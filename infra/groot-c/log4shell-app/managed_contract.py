#!/usr/bin/env python3
"""Local file and Docker inspect contracts; never loads or executes a lab JAR."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

PROJECT = "capstone-log4shell"
NAME = "log4shell-lab"
SHA = re.compile(r"[a-f0-9]{64}\Z")
IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
SOURCES = ("compose.yaml", "manage.sh", "managed_contract.py", "validate_log4shell_jar.py", "verify_log4shell_app.py")
PRIVATE = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"))
ENVIRONMENT = {"SERVER_ADDRESS": "0.0.0.0", "SERVER_PORT": "8080", "SERVER_SERVLET_CONTEXT_PATH": "/log4shell",
               "LOGGING_CONFIG": "classpath:log4j2-spring.xml", "TZ": "Asia/Seoul",
               "JAVA_TOOL_OPTIONS": "-Xms64m -Xmx256m -Duser.timezone=Asia/Seoul"}


class ContractError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise ContractError(reason)


def bind_address(value):
    address = ipaddress.ip_address(value)
    require(address.version == 4 and str(address) == value and any(address in block for block in PRIVATE), "private_ipv4_bind_required")
    return value


def regular(path, mode=None, expected_uid=0):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == expected_uid, "unsafe_owned_file")
    require(stat.S_IMODE(info.st_mode) == mode if mode is not None else not (info.st_mode & 0o022), "unsafe_file_mode")
    return path.read_bytes()


def directory(path, expected_uid=0):
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == expected_uid and not info.st_mode & 0o022, "unsafe_owned_directory")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_manifest(root, expected_uid=0):
    directory(root, expected_uid)
    require(stat.S_IMODE(root.stat().st_mode) == 0o700, "managed_root_mode")
    manifest = json.loads(regular(root / "manifest.json", 0o600, expected_uid))
    require(set(manifest) == {"schema", "project", "container", "root", "image", "bind_address", "jar_sha256", "files"}, "manifest_fields")
    require(manifest["schema"] == 1 and manifest["project"] == PROJECT and manifest["container"] == NAME and manifest["root"] == str(root), "manifest_identity")
    require(isinstance(manifest["image"], str) and IMAGE.fullmatch(manifest["image"]), "image_id_required")
    require(isinstance(manifest["jar_sha256"], str) and SHA.fullmatch(manifest["jar_sha256"]), "jar_digest_required")
    bind_address(manifest["bind_address"])
    return manifest


def check_files(root, expected_uid=0):
    manifest = read_manifest(root, expected_uid)
    artifact = "artifacts/" + manifest["jar_sha256"] + ".jar"
    require(set(manifest["files"]) == set(SOURCES) | {"managed.env", artifact}, "manifest_file_set")
    directory(root / "artifacts", expected_uid)
    for name, expected in manifest["files"].items():
        require(isinstance(expected, str) and SHA.fullmatch(expected), "manifest_digest")
        mode = 0o600 if name == "managed.env" else 0o750 if name == "manage.sh" else 0o644
        require(digest(regular(root / name, mode, expected_uid)) == expected, "managed_file_changed")
    require(manifest["files"][artifact] == manifest["jar_sha256"], "artifact_digest_mismatch")
    wanted_env = ("LOG4SHELL_IMAGE=" + manifest["image"] + "\nLOG4SHELL_BIND_ADDRESS=" + manifest["bind_address"]
                  + "\nLOG4SHELL_JAR_SHA256=" + manifest["jar_sha256"] + "\n").encode()
    require((root / "managed.env").read_bytes() == wanted_env, "managed_environment_changed")
    return manifest


def install_manifest(stage, destination, image, address, jar_sha):
    require(IMAGE.fullmatch(image) and SHA.fullmatch(jar_sha), "installation_identity")
    bind_address(address)
    (stage / "managed.env").write_text("LOG4SHELL_IMAGE=" + image + "\nLOG4SHELL_BIND_ADDRESS=" + address
                                       + "\nLOG4SHELL_JAR_SHA256=" + jar_sha + "\n", encoding="ascii")
    (stage / "managed.env").chmod(0o600)
    names = SOURCES + ("managed.env", "artifacts/" + jar_sha + ".jar")
    manifest = {"schema": 1, "project": PROJECT, "container": NAME, "root": str(destination), "image": image,
                "bind_address": address, "jar_sha256": jar_sha, "files": {name: digest((stage / name).read_bytes()) for name in names}}
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (stage / "manifest.json").chmod(0o600)


def check_image(snapshot, image):
    require(len(snapshot) == 1, "ambiguous_image")
    item = snapshot[0]
    require(item["Id"] == image and item["Os"] == "linux" and item["Architecture"] == "amd64", "local_image_mismatch")


def check_container(snapshot, root, manifest, expected_id=None, running=False, image_environment=()):
    require(isinstance(snapshot, list) and len(snapshot) == 1, "ambiguous_container")
    item = snapshot[0]
    config, host = item["Config"], item["HostConfig"]
    labels = config.get("Labels") or {}
    require(item["Name"] == "/" + NAME and re.fullmatch(r"[a-f0-9]{64}", item["Id"]), "container_identity")
    if expected_id is not None:
        require(item["Id"] == expected_id, "container_id_changed")
    require(labels.get("com.docker.compose.project") == PROJECT and labels.get("com.docker.compose.service") == "app"
            and labels.get("com.docker.compose.project.working_dir") == str(root)
            and labels.get("com.docker.compose.project.config_files") == str(root / "compose.yaml")
            and labels.get("io.capstone.role") == "log4shell-java"
            and labels.get("io.capstone.jar-sha256") == manifest["jar_sha256"], "unmanaged_or_wrong_project_container")
    require(item["Image"] == manifest["image"] and config["Image"] == manifest["image"], "container_image_changed")
    require(config["User"] == "65532:65532" and config["Entrypoint"] == ["java"]
            and config["Cmd"] == ["-jar", "/app/spring-boot-application.jar"] and config["WorkingDir"] == "/app", "container_command_changed")
    require(config.get("Healthcheck", {}).get("Test") == ["NONE"], "container_healthcheck_changed")
    environment = {}
    for entry in config.get("Env") or []:
        key, separator, value = entry.partition("=")
        require(separator and key not in environment, "ambiguous_container_environment")
        environment[key] = value
    expected_environment = {}
    for entry in image_environment:
        key, separator, value = entry.partition("=")
        require(separator and key not in expected_environment, "ambiguous_image_environment")
        expected_environment[key] = value
    expected_environment.update(ENVIRONMENT)
    require(environment == expected_environment, "container_environment_changed")
    require(host["NetworkMode"] == "bridge" and set(item["NetworkSettings"]["Networks"]) == {"bridge"}, "container_network_changed")
    require(host.get("PortBindings") == {"8080/tcp": [{"HostIp": manifest["bind_address"], "HostPort": "8080"}]}, "container_port_changed")
    require(host["RestartPolicy"]["Name"] == "unless-stopped" and host["RestartPolicy"].get("MaximumRetryCount", 0) == 0, "restart_policy_changed")
    require(host["ReadonlyRootfs"] is True and host["Privileged"] is False and host.get("CapAdd") in (None, [])
            and host["CapDrop"] == ["ALL"] and host["SecurityOpt"] == ["no-new-privileges:true"], "container_privileges_changed")
    require(host["PidsLimit"] == 128 and host["Memory"] == 536870912 and host["NanoCpus"] == 1000000000, "container_limits_changed")
    require(host.get("Devices") in (None, []) and host.get("DeviceRequests") in (None, [])
            and host.get("PidMode", "") == "" and host.get("IpcMode") == "private", "container_host_access_changed")
    require(host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,noexec,size=64m,mode=1777"}, "container_tmpfs_changed")
    require(host["LogConfig"] == {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}}, "container_log_policy_changed")
    mounts = [{key: mount.get(key) for key in ("Type", "Source", "Destination", "RW")} for mount in item.get("Mounts", [])]
    require(mounts == [{"Type": "bind", "Source": str(root / "artifacts" / (manifest["jar_sha256"] + ".jar")),
                        "Destination": "/app/spring-boot-application.jar", "RW": False}], "container_mount_changed")
    if running:
        require(item["State"]["Running"] is True and item["State"].get("OOMKilled") is False, "container_not_running")
        require(item["NetworkSettings"].get("Ports") == host["PortBindings"], "active_port_binding_changed")
    return {"container_id": item["Id"], "image": item["Image"], "state": item["State"]["Status"]}


def write_runtime(root, receipt):
    path = root / "runtime.json"
    require(not path.is_symlink(), "unsafe_runtime_path")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".runtime-", suffix=".tmp", dir=str(root))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump({"schema": 1, "container_id": receipt["container_id"], "image": receipt["image"]}, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        directory_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    operation = sys.argv[1]
    if operation == "install-manifest":
        install_manifest(Path(sys.argv[2]), Path(sys.argv[3]), *sys.argv[4:7])
        return
    if operation == "image":
        check_image(json.load(sys.stdin), sys.argv[2])
        return
    root = Path(sys.argv[2])
    manifest = check_files(root)
    if operation == "files":
        print("managed_files_ok")
    elif operation == "field":
        require(sys.argv[3] in {"image", "bind_address", "jar_sha256"}, "unknown_manifest_field")
        print(manifest[sys.argv[3]])
    elif operation in {"container", "candidate", "record"}:
        snapshots = json.load(sys.stdin)
        require(isinstance(snapshots, list) and len(snapshots) == 2, "image_and_container_snapshot_required")
        images = [item for item in snapshots if item.get("Id") == manifest["image"]]
        check_image(images, manifest["image"])
        containers = [item for item in snapshots if "State" in item]
        expected = None
        if operation == "container":
            runtime = json.loads(regular(root / "runtime.json", 0o600))
            require(set(runtime) == {"schema", "container_id", "image"} and runtime["schema"] == 1
                    and runtime["image"] == manifest["image"], "runtime_identity")
            expected = runtime["container_id"]
        receipt = check_container(containers, root, manifest, expected, running=len(sys.argv) > 3 and sys.argv[3] == "running",
                                  image_environment=images[0]["Config"].get("Env") or [])
        if operation == "record":
            write_runtime(root, receipt)
        print(json.dumps(receipt, sort_keys=True))
    else:
        raise ValueError("unknown_operation")


if __name__ == "__main__":
    try:
        main()
    except ContractError as error:
        print("log4shell_management_contract_failed:" + str(error), file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, KeyError, OSError, IndexError, TypeError):
        print("log4shell_management_contract_failed", file=sys.stderr)
        raise SystemExit(1)
