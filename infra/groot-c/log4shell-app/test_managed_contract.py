#!/usr/bin/env python3
"""Offline regressions for refusing deployment drift; no Docker or Java execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("managed_contract", Path(__file__).with_name("managed_contract.py"))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class ContainerContract(unittest.TestCase):
    def setUp(self):
        self.root = Path("/opt/capstone-log4shell")
        self.image = "sha256:" + "a" * 64
        self.jar = "b" * 64
        self.cid = "c" * 64
        self.manifest = {"image": self.image, "bind_address": "10.200.10.20", "jar_sha256": self.jar}
        ports = {"8080/tcp": [{"HostIp": "10.200.10.20", "HostPort": "8080"}]}
        self.item = {
            "Id": self.cid, "Name": "/log4shell-lab", "Image": self.image,
            "State": {"Status": "running", "Running": True, "OOMKilled": False},
            "Config": {"Image": self.image, "User": "65532:65532", "Entrypoint": ["java"], "Cmd": ["-jar", "/app/spring-boot-application.jar"], "WorkingDir": "/app", "Healthcheck": {"Test": ["NONE"]},
                       "Env": [key + "=" + value for key, value in C.ENVIRONMENT.items()],
                       "Labels": {"com.docker.compose.project": C.PROJECT, "com.docker.compose.service": "app", "com.docker.compose.project.working_dir": str(self.root), "com.docker.compose.project.config_files": str(self.root / "compose.yaml"), "io.capstone.role": "log4shell-java", "io.capstone.jar-sha256": self.jar}},
            "HostConfig": {"NetworkMode": "bridge", "PortBindings": ports, "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0}, "ReadonlyRootfs": True, "Privileged": False, "CapAdd": None, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "PidsLimit": 128, "Memory": 536870912, "NanoCpus": 1000000000, "Devices": [], "DeviceRequests": None, "PidMode": "", "IpcMode": "private", "Tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"}, "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}}},
            "NetworkSettings": {"Networks": {"bridge": {}}, "Ports": ports},
            "Mounts": [{"Type": "bind", "Source": str(self.root / "artifacts" / (self.jar + ".jar")), "Destination": "/app/spring-boot-application.jar", "RW": False}],
        }

    def check(self, value=None, running=True):
        return C.check_container([value or self.item], self.root, self.manifest, self.cid, running)

    def test_expected_container(self):
        self.assertEqual(self.check()["container_id"], self.cid)

    def test_rejects_drift(self):
        changes = [
            ("Id", "d" * 64), ("Image", "sha256:" + "d" * 64),
            ("Config.Labels", {}), ("Config.User", "0:0"), ("Config.Entrypoint", None),
            ("Config.Env", ["JAVA_TOOL_OPTIONS=-Dlog4j2.formatMsgNoLookups=true"]),
            ("HostConfig.NetworkMode", "host"), ("HostConfig.ReadonlyRootfs", False),
            ("HostConfig.Privileged", True), ("HostConfig.CapAdd", ["SYS_ADMIN"]),
            ("HostConfig.PortBindings", {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}),
            ("HostConfig.Tmpfs", {}), ("Mounts", []),
        ]
        for path, value in changes:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.item)
                parts = path.split("."); parent = changed
                for part in parts[:-1]: parent = parent[part]
                parent[parts[-1]] = value
                with self.assertRaises(ValueError): self.check(changed)

    def test_stopped_container_can_be_checked_but_not_verified(self):
        self.item["State"].update(Status="exited", Running=False)
        self.item["NetworkSettings"]["Ports"] = {}
        self.check(running=False)
        with self.assertRaises(ValueError): self.check()

    def test_read_write_or_extra_mount_rejected(self):
        self.item["Mounts"][0]["RW"] = True
        with self.assertRaises(ValueError): self.check()
        self.item["Mounts"][0]["RW"] = False
        self.item["Mounts"].append({"Type": "bind", "Source": "/", "Destination": "/host", "RW": False})
        with self.assertRaises(ValueError): self.check()

    def test_private_bind_only(self):
        for valid in ("127.0.0.1", "10.200.10.20", "172.16.2.1", "192.168.1.2"):
            self.assertEqual(C.bind_address(valid), valid)
        for invalid in ("0.0.0.0", "8.8.8.8", "::1", "localhost", "169.254.1.2"):
            with self.assertRaises(ValueError): C.bind_address(invalid)

    def test_unexpected_environment_cannot_override_spring(self):
        self.item["Config"]["Env"].append('SPRING_APPLICATION_JSON={"logging.config":"/tmp/other.xml"}')
        with self.assertRaises(ValueError): self.check()

    def test_image_environment_is_preserved_and_checked(self):
        self.item["Config"]["Env"].append("PATH=/usr/bin:/bin")
        C.check_container([self.item], self.root, self.manifest, self.cid, True, ["PATH=/usr/bin:/bin"])
        with self.assertRaises(ValueError): self.check()

    def test_explicit_recovery_still_checks_the_complete_contract(self):
        self.item["Id"] = "d" * 64
        with self.assertRaises(ValueError): self.check()
        receipt = C.check_container([self.item], self.root, self.manifest, expected_id=None, running=True)
        self.assertEqual(receipt["container_id"], "d" * 64)
        self.item["Config"]["Labels"] = {}
        with self.assertRaises(ValueError):
            C.check_container([self.item], self.root, self.manifest, expected_id=None, running=True)


class PersistentFiles(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="log4shell-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / "artifacts").mkdir(mode=0o700)
        for name in C.SOURCES:
            (self.root / name).write_bytes((name + " fixture\n").encode())
            (self.root / name).chmod(0o750 if name == "manage.sh" else 0o644)
        self.jar_sha = C.digest(b"jar bytes fixture")
        self.artifact = self.root / "artifacts" / (self.jar_sha + ".jar")
        self.artifact.write_bytes(b"jar bytes fixture")
        self.artifact.chmod(0o644)
        C.install_manifest(self.root, self.root, "sha256:" + "a" * 64, "10.200.10.20", self.jar_sha)
        # The fixture may live beneath a shared OS temp directory. Production
        # still checks every owned parent; these tests target file drift itself.
        self.parents = mock.patch.object(C, "directory", return_value=None)
        self.parents.start()
        self.addCleanup(self.parents.stop)

    def check(self):
        return C.check_files(self.root, expected_uid=os.getuid())

    def test_complete_installation(self):
        self.assertEqual(self.check()["jar_sha256"], self.jar_sha)

    def test_artifact_removed(self):
        self.artifact.unlink()
        with self.assertRaises(OSError): self.check()

    def test_artifact_modified(self):
        self.artifact.write_bytes(b"changed bytes")
        with self.assertRaises(ValueError): self.check()

    def test_environment_modified(self):
        (self.root / "managed.env").write_text("LOG4SHELL_BIND_ADDRESS=0.0.0.0\n")
        with self.assertRaises(ValueError): self.check()

    def test_script_write_permissions_rejected(self):
        (self.root / "manage.sh").chmod(0o777)
        with self.assertRaises(ValueError): self.check()

    def test_symlink_artifact_rejected(self):
        target = self.root / "original.jar"
        self.artifact.rename(target)
        self.artifact.symlink_to(target)
        with self.assertRaises(ValueError): self.check()

    def test_hardlink_artifact_rejected(self):
        os.link(self.artifact, self.root / "other.jar")
        with self.assertRaises(ValueError): self.check()

    def test_missing_manifest_file_cannot_be_hidden(self):
        manifest = json.loads((self.root / "manifest.json").read_text())
        del manifest["files"]["manage.sh"]
        (self.root / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(ValueError): self.check()

    def test_runtime_receipt_uses_new_tempfile_after_interruption(self):
        (self.root / "runtime.json.new").write_text("old interrupted write")
        C.write_runtime(self.root, {"container_id": "c" * 64, "image": "sha256:" + "a" * 64})
        C.write_runtime(self.root, {"container_id": "d" * 64, "image": "sha256:" + "a" * 64})
        result = json.loads((self.root / "runtime.json").read_text())
        self.assertEqual(result["container_id"], "d" * 64)
        self.assertEqual((self.root / "runtime.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.root.glob(".runtime-*.tmp")), [])
        self.assertEqual((self.root / "runtime.json.new").read_text(), "old interrupted write")

    def test_runtime_write_failure_preserves_original_receipt(self):
        receipt = {"container_id": "c" * 64, "image": "sha256:" + "a" * 64}
        C.write_runtime(self.root, receipt)
        original = (self.root / "runtime.json").read_bytes()
        with mock.patch.object(Path, "replace", side_effect=OSError("simulated interruption")):
            with self.assertRaises(OSError): C.write_runtime(self.root, {**receipt, "container_id": "d" * 64})
        self.assertEqual((self.root / "runtime.json").read_bytes(), original)
        self.assertEqual(list(self.root.glob(".runtime-*.tmp")), [])


class ProjectInventory(unittest.TestCase):
    def test_real_shell_guard_rejects_renamed_or_extra_project_containers(self):
        source = Path(__file__).with_name("manage.sh").read_text()
        guard = re.search(r"^check_inventory\(\)\{\n.*?^\}", source, re.MULTILINE | re.DOTALL).group()
        script = ('set -euo pipefail\ncontainer_id(){ printf "%s" "$NAMED"; }\n'
                  'project_ids(){ printf "%s" "$PROJECTED"; }\ndie(){ exit 23; }\n' + guard + '\ncheck_inventory\n')
        named = "a" * 64
        extra = "b" * 64
        for current, project, expected in (("", "", 0), (named, named, 0), ("", named, 23),
                                            (named, "", 23), (named, named + "\n" + extra, 23),
                                            (named, extra, 23)):
            with self.subTest(current=current, project=project):
                result = subprocess.run(["bash", "-c", script], env={**os.environ, "NAMED": current, "PROJECTED": project}, capture_output=True)
                self.assertEqual(result.returncode, expected)

    def test_verify_inside_if_does_not_hide_contract_failure(self):
        source = Path(__file__).with_name("manage.sh").read_text()
        verify = re.search(r"^verify\(\)\{\n.*?^\}", source, re.MULTILINE | re.DOTALL).group()
        script = '''set -euo pipefail
ROOT=/opt/capstone-log4shell
CONTAINER=log4shell-lab
check_inventory(){ return 0; }
inspect_managed(){ printf '[]'; }
contract(){ if [[ $1 == container ]]; then return 23; elif [[ $3 == jar_sha256 ]]; then printf abc; else printf 127.0.0.1; fi; }
docker_local(){ printf 'abc  /app/spring-boot-application.jar'; }
python3(){ return 0; }
die(){ exit 92; }
''' + verify + '\nif verify; then exit 91; else exit 0; fi\n'
        result = subprocess.run(["bash", "-c", script], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_inventory_query_failure_is_not_an_empty_inventory(self):
        source = Path(__file__).with_name("manage.sh").read_text()
        guard = re.search(r"^check_inventory\(\)\{\n.*?^\}", source, re.MULTILINE | re.DOTALL).group()
        script = ('set -euo pipefail\ncontainer_id(){ return 23; }\nproject_ids(){ return 0; }\n'
                  'die(){ exit 92; }\n' + guard + '\nif check_inventory; then exit 91; else exit 0; fi\n')
        result = subprocess.run(["bash", "-c", script], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
