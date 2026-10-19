#!/usr/bin/python3
"""Close this one fixed VPN window; never reopen it or restore other configs."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path("/var/lib/capstone-wazuh-demo-access")
BASE = Path("/home/groot_a/capstone/chatproxy")
INCLUDE = BASE / "tls/wazuh-vpn-window.allow.conf"
CONTAINER_ID = "2c6923e7a66ebf55ef28f866cda77a3000f3ed26f7937198927cd73d5cd85403"
DOMAIN = "wazuh.grootlab.duckdns.org"
EXPIRES = "2026-10-20T14:59:00Z"
ACTIVE = ("# Fixed demonstration window; expires " + EXPIRES + "\nallow 192.168.15.0/24;\n").encode()
CLOSED = b"# Wazuh demonstration VPN window closed; no temporary addresses.\n"
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C", "TZ": "UTC"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def regular(path, mode):
    for parent in path.parents:
        require(not parent.is_symlink(), "symlink_parent")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == mode, "unsafe_fixed_file")
    return path.read_bytes()


def validate_state(state):
    expected = {"schema", "domain", "vpn_cidr", "expires_utc", "container", "container_id", "config", "include",
                "baseline_sha256", "active_config_sha256", "active_include_sha256", "closed_include_sha256"}
    require(set(state) == expected and state["schema"] == 1 and state["domain"] == DOMAIN
            and state["vpn_cidr"] == "192.168.15.0/24" and state["expires_utc"] == EXPIRES
            and state["container"] == "chatproxy" and state["container_id"] == CONTAINER_ID
            and state["config"] == str(BASE / "nginx.conf") and state["include"] == str(INCLUDE)
            and state["active_include_sha256"] == digest(ACTIVE) and state["closed_include_sha256"] == digest(CLOSED),
            "fixed_window_state_mismatch")


def close_include(path, content):
    require(content in (ACTIVE, CLOSED), "unexpected_include_content")
    if content == CLOSED:
        return
    descriptor, name = tempfile.mkstemp(prefix=".wazuh-window-close-", dir=str(path.parent))
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(CLOSED)
            output.flush()
            os.fchmod(output.fileno(), 0o644)
            os.fsync(output.fileno())
        os.replace(str(temporary), str(path))
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def command(arguments):
    result = subprocess.run(arguments, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=10, check=False)
    require(result.returncode == 0, "native_command_failed")
    return result.stdout


def validate_container(snapshot):
    require(len(snapshot) == 1, "ambiguous_proxy")
    item = snapshot[0]
    require(item["Id"] == CONTAINER_ID and item["Name"] == "/chatproxy"
            and item["State"]["Running"] is True, "proxy_identity_changed")
    mounts = {mount["Destination"]: mount for mount in item["Mounts"]}
    for target, source in (("/etc/nginx/nginx.conf", BASE / "nginx.conf"), ("/etc/nginx/tls", BASE / "tls")):
        mount = mounts.get(target, {})
        require(mount.get("Type") == "bind" and mount.get("Source") == str(source)
                and mount.get("RW") is False, "proxy_mount_changed")


def main():
    require(sys.argv[1:] in ([], ["close"], ["check"]), "usage_close_or_check")
    require(os.geteuid() == 0, "root_required")
    os.umask(0o077)
    info = ROOT.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_state_directory")
    state = json.loads(regular(ROOT / "state.json", 0o600))
    validate_state(state)
    lock = ROOT / "operation.lock"
    descriptor = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(descriptor)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600, "unsafe_lock")
    with os.fdopen(descriptor, "r+") as locked:
        fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        content = regular(INCLUDE, 0o644)
        require(content in (ACTIVE, CLOSED), "unexpected_include_content")
        if sys.argv[1:] == ["check"]:
            print(json.dumps({"expires_utc": EXPIRES, "include": "closed" if content == CLOSED else "active"}))
            return
        # Close on disk first. A failed reload must never restore the allow.
        # The already-loaded UTC guard independently denies new expired requests.
        close_include(INCLUDE, content)
        docker = shutil.which("docker", path=ENV["PATH"])
        require(docker is not None, "docker_missing")
        docker_command = [docker, "--host", "unix:///var/run/docker.sock"]
        snapshot = json.loads(command(docker_command + ["inspect", "--type", "container", CONTAINER_ID]))
        validate_container(snapshot)
        command(docker_command + ["exec", CONTAINER_ID, "nginx", "-t"])
        command(docker_command + ["exec", CONTAINER_ID, "nginx", "-s", "reload"])
        require(regular(INCLUDE, 0o644) == CLOSED, "include_did_not_close")
        print("wazuh_demo_include_closed_and_nginx_reload_signalled")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print("wazuh_demo_close_failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
