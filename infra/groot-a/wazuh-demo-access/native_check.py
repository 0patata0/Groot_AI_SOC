#!/usr/bin/env python3
"""Read-only native Nginx checks on A; creates only isolated disposable fixtures."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
LABEL = "org.capstone.wazuh-demo.native-check"
CASES = (
    ("day_before", "192.168.15.7", "2026-10-18T23:59:59+00:00", 403),
    ("first_second", "192.168.15.7", "2026-10-19T00:00:00+00:00", 204),
    ("first_day_end", "192.168.15.7", "2026-10-19T23:59:59+00:00", 204),
    ("last_full_hour", "192.168.15.7", "2026-10-20T13:59:59+00:00", 204),
    ("partial_hour_start", "192.168.15.7", "2026-10-20T14:00:00+00:00", 204),
    ("last_allowed_second", "192.168.15.254", "2026-10-20T14:58:59+00:00", 204),
    ("expiry_second", "192.168.15.7", "2026-10-20T14:59:00+00:00", 403),
    ("expired_hour", "192.168.15.7", "2026-10-20T15:00:00+00:00", 403),
    ("following_day", "192.168.15.7", "2026-10-21T00:00:00+00:00", 403),
    ("other_timezone", "192.168.15.7", "2026-10-19T22:00:00+09:00", 403),
    ("malformed_time", "192.168.15.7", "invalid", 403),
    ("non_vpn_guard_unaffected", "192.168.16.7", "2026-10-21T00:00:00+00:00", 204),
)
HTTP_CHECK = r'''
import http.client, json, sys, time
cases = json.load(sys.stdin)
for attempt in range(100):
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=1)
    try:
        conn.request("GET", "/", headers={"X-Test-Remote": "192.168.15.7", "X-Test-Time": "invalid"})
        response = conn.getresponse(); response.read(); conn.close()
        break
    except OSError:
        conn.close(); time.sleep(0.1)
else:
    raise SystemExit("fixture_readiness_timeout")
results = []
for name, address, timestamp, expected in cases:
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=2)
    conn.request("GET", "/", headers={"X-Test-Remote": address, "X-Test-Time": timestamp})
    response = conn.getresponse(); status = response.status; response.read(); conn.close()
    results.append({"name": name, "address": address, "time": timestamp, "expected": expected, "actual": status})
print(json.dumps(results))
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def diagnostic(text, limit=4096):
    """Bound known fixture-process diagnostics; never read certificate contents."""
    clean = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    return {"text": clean[-limit:], "truncated": len(clean) > limit}


def syntax_projection(candidate):
    """Only fixture paths change; no mountpoint is created in the real TLS dir."""
    text = candidate.decode("utf-8")
    original_include = "include /etc/nginx/tls/wazuh-vpn-window.allow.conf;"
    if text.count(original_include) != 1:
        raise ValueError("candidate_include_count")
    text = text.replace(original_include, "include /candidate/wazuh-vpn-window.allow.conf;")
    text, count = re.subn(r"(\bssl_certificate(?:_key)?\s+)/etc/nginx/tls/", r"\1/fixture-tls/", text)
    if count != 12 or "/etc/nginx/tls/" in text:
        raise ValueError("candidate_certificate_path_count")
    return text.encode("utf-8")


def guard_fixture(renderer):
    guard = renderer.global_guard()
    if guard.count("$remote_addr") != 1 or guard.count("$time_iso8601") != 1:
        raise ValueError("guard_input_count")
    guard = guard.replace("$remote_addr", "$http_x_test_remote").replace("$time_iso8601", "$http_x_test_time")
    return ("worker_processes 1;\npid /tmp/nginx.pid;\nerror_log /dev/stderr notice;\n"
            "events { worker_connections 32; }\nhttp {\naccess_log off;\n" + guard +
            "server { listen 127.0.0.1:18080;\n"
            "if ($capstone_wazuh_demo_deny) { return 403; }\n"
            "location / { return 204; }\n}\n}\n").encode("utf-8")


def regular(path):
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
        raise ValueError("root_owned_non_writable_regular_file_required: " + str(path))


class Fixture:
    def __init__(self, docker, image):
        self.docker, self.image = docker, image
        self.token = uuid.uuid4().hex
        self.names = []

    def run(self, args, check=True, timeout=30, input_text=None):
        result = subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C"})
        if check and result.returncode:
            raise ValueError("command_failed: " + Path(args[0]).name + " exit=" + str(result.returncode))
        return result

    def dock(self, args, **kwargs):
        return self.run([self.docker, "--host", "unix:///var/run/docker.sock"] + args, **kwargs)

    def inspect(self, name):
        return json.loads(self.dock(["container", "inspect", name]).stdout)[0]

    def create(self, kind, mounts, user, config):
        name = "capstone-wazuh-check-" + self.token + "-" + kind
        self.names.append(name)  # Recover by our label even if create times out.
        args = ["container", "create", "--name", name, "--label", LABEL + "=" + self.token,
                "--pull=never", "--network=none", "--read-only", "--user", user,
                "--cap-drop=ALL", "--security-opt", "no-new-privileges=true",
                "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777",
                "--tmpfs", "/var/cache/nginx:rw,noexec,nosuid,size=16m,mode=1777",
                "--tmpfs", "/var/run:rw,noexec,nosuid,size=1m,mode=1777"]
        if kind == "syntax":
            # nginx -t prepares its private tmpfs cache directories for UID 101.
            # Production TLS/config mounts and the image remain read-only.
            args.append("--cap-add=CHOWN")
        for source, destination in mounts:
            if "," in str(source):
                raise ValueError("comma_in_mount_path")
            args.extend(["--mount", "type=bind,src=" + str(source) + ",dst=" + destination + ",readonly"])
        args.extend(["--entrypoint", "nginx", self.image] + config)
        self.dock(args)
        info = self.inspect(name)
        self.assert_owned(info)
        if info["HostConfig"]["NetworkMode"] != "none" or info["HostConfig"].get("PortBindings"):
            raise ValueError("fixture_network_isolation_mismatch")
        return name

    def assert_owned(self, info):
        if info["Image"] != self.image or info["Config"].get("Labels", {}).get(LABEL) != self.token:
            raise ValueError("fixture_identity_mismatch")

    def cleanup(self):
        failures = []
        for name in reversed(self.names):
            try:
                result = self.dock(["container", "inspect", name], check=False)
                if result.returncode:
                    if "No such object" in result.stderr or "No such container" in result.stderr:
                        continue
                    raise ValueError("cannot_inspect_owned_fixture")
                self.assert_owned(json.loads(result.stdout)[0])
                self.dock(["container", "rm", "--force", name])
                result = self.dock(["container", "inspect", name], check=False)
                if not result.returncode or not ("No such object" in result.stderr or "No such container" in result.stderr):
                    raise ValueError("fixture_removal_not_verified")
            except (ValueError, KeyError, OSError, subprocess.SubprocessError):
                failures.append(name)
        return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--tls-dir", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--docker", default="/usr/bin/docker")
    parser.add_argument("--nsenter", default="/usr/bin/nsenter")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("root_linux_required")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        raise ValueError("immutable_image_id_required")
    for path in (args.render, args.baseline, Path(args.docker), Path(args.nsenter)):
        regular(path)
        if not path.is_absolute():
            raise ValueError("absolute_paths_required")
    if not args.tls_dir.is_absolute() or not stat.S_ISDIR(args.tls_dir.lstat().st_mode):
        raise ValueError("real_absolute_tls_directory_required")
    spec = importlib.util.spec_from_file_location("wazuh_demo_renderer", args.render)
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    baseline = args.baseline.read_bytes()
    candidate, state = renderer.render(baseline)
    projected, fixture = syntax_projection(candidate), guard_fixture(renderer)
    runner = Fixture(args.docker, args.image)
    image = json.loads(runner.dock(["image", "inspect", args.image]).stdout)[0]
    if image["Id"] != args.image or image.get("Os") != "linux":
        raise ValueError("local_image_identity_mismatch")
    stage = Path(tempfile.mkdtemp(prefix="capstone-wazuh-native-", dir="/var/tmp"))
    report = {"schema": 1, "image": args.image, "baseline_sha256": digest(baseline),
              "candidate_sha256": digest(candidate), "syntax_projection_sha256": digest(projected),
              "guard_fixture_sha256": digest(fixture), "expires_utc": state["expires_utc"],
              "production_files_changed": False, "tls_copied": False,
              "fixture_only_header_substitution": True, "guard_tests_only_not_full_allowlist": True,
              "syntax_passed": False, "cases": [], "passed": False}
    error = None
    try:
        config_dir = stage / "config"
        config_dir.mkdir(mode=0o755)
        for name, contents in (("nginx.conf", projected), ("guard.conf", fixture),
                               ("wazuh-vpn-window.allow.conf", renderer.ACTIVE_INCLUDE)):
            target = config_dir / name
            target.write_bytes(contents)
            target.chmod(0o644)
        syntax = runner.create("syntax", [(config_dir, "/candidate"), (args.tls_dir, "/fixture-tls")],
                               "0:0", ["-t", "-c", "/candidate/nginx.conf"])
        result = runner.dock(["container", "start", "--attach", syntax], check=False)
        info = runner.inspect(syntax)
        report["syntax_diagnostics"] = {
            "docker_start_exit_code": result.returncode,
            "container_exit_code": info["State"]["ExitCode"],
            "container_running": info["State"]["Running"],
            "docker_state_error": diagnostic(info["State"].get("Error", "")),
            "stdout": diagnostic(result.stdout), "stderr": diagnostic(result.stderr),
        }
        if result.returncode or info["State"]["Running"] or info["State"]["ExitCode"] != 0:
            raise ValueError("nginx_syntax_check_failed")
        report["syntax_passed"] = True
        guard = runner.create("guard", [(config_dir, "/candidate")], "65532:65532",
                              ["-g", "daemon off;", "-c", "/candidate/guard.conf"])
        runner.dock(["container", "start", guard])
        info = runner.inspect(guard)
        if not info["State"]["Running"] or info["State"]["Pid"] <= 1:
            raise ValueError("guard_fixture_not_running")
        output = runner.run([args.nsenter, "--target", str(info["State"]["Pid"]), "--net", "--",
                             sys.executable, "-B", "-c", HTTP_CHECK], timeout=25,
                            input_text=json.dumps(CASES))
        report["cases"] = json.loads(output.stdout)
        if len(report["cases"]) != len(CASES) or any(item["actual"] != item["expected"] for item in report["cases"]):
            raise ValueError("guard_http_boundary_mismatch")
        if args.baseline.read_bytes() != baseline:
            raise ValueError("baseline_changed_during_check")
        report["passed"] = True
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as problem:
        error = str(problem)
    finally:
        leftovers = runner.cleanup()
        report["container_cleanup_verified"] = not leftovers
        if leftovers:
            report["leftover_owned_containers"] = leftovers
        if not leftovers:
            shutil.rmtree(stage)
        report["temporary_directory_removed"] = not stage.exists()
        if leftovers or stage.exists():
            error = "cleanup_incomplete" + (": " + error if error else "")
        if error:
            report["passed"], report["error"] = False, error
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"passed": False, "error": str(error)}))
        raise SystemExit(1)
