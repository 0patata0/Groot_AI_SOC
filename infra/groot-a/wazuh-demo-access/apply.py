#!/usr/bin/env python3
"""One-shot A deployment. Argument: root-owned stage containing the four sources."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import types

sys.dont_write_bytecode = True
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1"}
BASE = Path("/home/groot_a/capstone/chatproxy")
CONFIG = BASE / "nginx.conf"
TLS = BASE / "tls"
INCLUDE = TLS / "wazuh-vpn-window.allow.conf"
STATE_ROOT = Path("/var/lib/capstone-wazuh-demo-access")
CLOSE = Path("/usr/local/sbin/capstone-wazuh-demo-close")
UNIT_ROOT = Path("/etc/systemd/system")
SERVICE = "capstone-wazuh-demo-close.service"
TIMER = "capstone-wazuh-demo-close.timer"
BACKUP = Path("/var/backups/capstone-wazuh-demo/20261019")
CONTAINER = "2c6923e7a66ebf55ef28f866cda77a3000f3ed26f7937198927cd73d5cd85403"
BASE_SHA = "2790ab83df6c4e1b13ac00a277ea8158a16bb767c2c2b1e0a2c5f01b598b8424"
DOMAIN = "wazuh.grootlab.duckdns.org"
EXPIRY = dt.datetime(2026, 10, 20, 14, 59, tzinfo=dt.timezone.utc)
NEXT = "Tue 2026-10-20 14:59:00 UTC"
SOURCE_HASHES = {
    "render.py": "15fe4963f66bc76e70c68cc77170ac8baa06b2f084d333e64d897e1393d4903c",
    "close.py": "ffe3137008047c3183232fbd27fe8a8f9a57691b61a2e5bc08863c0ec189eb2b",
    SERVICE: "0436e65660669df0469b19ef4f71e7bee5818e3a26769f4e23215c1da95d8357",
    TIMER: "91ffe41e810c2cbd95739e88fdcccc342df9b479cf8a4093d06f594088a9c4e4",
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path):
    require(path.is_absolute(), "absolute_path_required")
    for item in (path,) + tuple(path.parents):
        require(not item.is_symlink(), "symlink_path_refused")


def regular(path, root=False):
    safe_path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular_single_link_required")
    if root:
        require(info.st_uid == 0 and not info.st_mode & 0o022, "root_source_required")
    return path.read_bytes()


def exclusive(path, data, mode):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())
    fsync_directory(path.parent)


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def command(label, arguments, timeout=25, allow_failure=False):
    result = subprocess.run(arguments, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if not allow_failure:
        require(result.returncode == 0, label + "_failed")
    return result


def now():
    return dt.datetime.now(dt.timezone.utc)


def no_existing(path):
    safe_path(path)
    require(not path.exists(), "existing_destination_refused")


def main():
    require(os.geteuid() == 0 and len(sys.argv) == 2, "usage_root_python_stage_directory")
    os.umask(0o077)
    stage = Path(os.path.abspath(sys.argv[1]))
    safe_path(stage)
    info = stage.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "unsafe_stage")
    sources = {name: regular(stage / name, root=True) for name in SOURCE_HASHES}
    require(all(digest(sources[name]) == expected for name, expected in SOURCE_HASHES.items()), "reviewed_sources_changed")
    render = types.ModuleType("reviewed_render")
    close = types.ModuleType("reviewed_close")
    exec(compile(sources["render.py"], str(stage / "render.py"), "exec"), render.__dict__)
    exec(compile(sources["close.py"], str(stage / "close.py"), "exec"), close.__dict__)
    require(now() < EXPIRY - dt.timedelta(minutes=5), "window_already_expiring")
    docker_path = shutil.which("docker", path=ENV["PATH"])
    require(docker_path is not None, "docker_missing")
    docker = [docker_path, "--host", "unix:///var/run/docker.sock"]

    def native(label, *args):
        return command(label, docker + ["exec", CONTAINER, *args]).stdout

    snapshot = json.loads(command("container_inspect", docker + ["inspect", "--type", "container", CONTAINER]).stdout)
    close.validate_container(snapshot)
    baseline = regular(CONFIG)
    require(digest(baseline) == BASE_SHA, "baseline_changed")
    require(native("inside_baseline_sha", "sha256sum", "/etc/nginx/nginx.conf").decode().split()[0] == BASE_SHA, "inside_baseline_changed")
    native("baseline_nginx_test", "nginx", "-t")
    container_time = native("container_utc", "date", "-Iseconds").decode().strip()
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", container_time), "container_not_utc")
    require(abs((dt.datetime.fromisoformat(container_time) - now()).total_seconds()) < 60, "container_clock_mismatch")
    cert = TLS / "chatduck.crt"
    cert_content = regular(cert)
    cert_meta = {str(path): (path.stat().st_dev, path.stat().st_ino, path.stat().st_size, path.stat().st_mtime_ns)
                 for path in (cert, TLS / "chatduck.key")}
    match = command("wildcard_checkhost", ["openssl", "x509", "-in", str(cert), "-noout", "-checkhost", DOMAIN]).stdout.decode().strip()
    require(match == "Hostname " + DOMAIN + " does match certificate", "certificate_hostname_did_not_match")
    remaining = int((EXPIRY - now()).total_seconds()) + 300
    command("certificate_window_validity", ["openssl", "x509", "-in", str(cert), "-noout", "-checkend", str(remaining)])
    trust = command("certificate_chain", ["openssl", "verify", "-CAfile", "/etc/ssl/certs/ca-certificates.crt", "-untrusted", str(cert), str(cert)]).stdout.decode().strip()
    require(trust == str(cert) + ": OK", "certificate_chain_unconfirmed")
    destinations = [STATE_ROOT, CLOSE, UNIT_ROOT / SERVICE, UNIT_ROOT / TIMER, INCLUDE,
                    UNIT_ROOT / "timers.target.wants" / TIMER, Path("/var/lib/systemd/timers/stamp-" + TIMER)]
    for destination in destinations:
        no_existing(destination)
    for unit in (SERVICE, TIMER):
        status = command("unit_absence", ["systemctl", "show", unit, "--property=LoadState", "--value"], allow_failure=True)
        require(status.stdout.decode().strip() == "not-found", "preexisting_systemd_unit")
    candidate, state = render.render(baseline)
    close.validate_state(state)
    safe_path(BACKUP)
    if not BACKUP.parent.exists():
        BACKUP.parent.mkdir(mode=0o700)
    parent_info = BACKUP.parent.stat()
    require(parent_info.st_uid == 0 and stat.S_IMODE(parent_info.st_mode) == 0o700, "unsafe_backup_parent")
    BACKUP.mkdir(mode=0o700)
    baseline_stat = CONFIG.stat()
    exclusive(BACKUP / "nginx.conf.before", baseline, 0o600)
    exclusive(BACKUP / "nginx.conf.candidate", candidate, 0o600)
    exclusive(BACKUP / "wazuh-vpn-window.active.conf", render.ACTIVE_INCLUDE, 0o600)
    exclusive(BACKUP / "wazuh-vpn-window.closed.conf", render.CLOSED_INCLUDE, 0o600)
    for name, content in sources.items():
        exclusive(BACKUP / name, content, 0o600)
    state_bytes = (json.dumps(state, sort_keys=True, indent=2) + "\n").encode()
    exclusive(BACKUP / "state.json", state_bytes, 0o600)
    exclusive(BACKUP / "baseline-stat.json", json.dumps({"dev": baseline_stat.st_dev, "inode": baseline_stat.st_ino,
              "uid": baseline_stat.st_uid, "gid": baseline_stat.st_gid, "mode": stat.S_IMODE(baseline_stat.st_mode)}).encode(), 0o600)
    descriptor = os.open(CONFIG, os.O_RDWR | os.O_NOFOLLOW)
    original_identity = (baseline_stat.st_dev, baseline_stat.st_ino)
    created = []
    touched_config = False
    timer_installed = False
    candidate_path = TLS / (".wazuh-window-candidate-" + secrets.token_hex(8) + ".conf")

    def replace_same_inode(content, expected_sha, arm=False):
        nonlocal touched_config
        descriptor_info = os.fstat(descriptor)
        path_info = CONFIG.stat()
        require((descriptor_info.st_dev, descriptor_info.st_ino) == original_identity == (path_info.st_dev, path_info.st_ino), "config_inode_changed")
        require(digest(CONFIG.read_bytes()) == expected_sha, "config_cas_changed")
        if arm:
            touched_config = True
        os.lseek(descriptor, 0, os.SEEK_SET)
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view):]
        os.ftruncate(descriptor, len(content))
        os.fsync(descriptor)

    def install(path, content, mode):
        exclusive(path, content, mode)
        created.append(path)

    try:
        STATE_ROOT.mkdir(mode=0o700)
        created.append(STATE_ROOT)
        install(STATE_ROOT / "state.json", state_bytes, 0o600)
        install(CLOSE, sources["close.py"], 0o500)
        install(UNIT_ROOT / SERVICE, sources[SERVICE], 0o644)
        install(UNIT_ROOT / TIMER, sources[TIMER], 0o644)
        timer_installed = True
        command("systemd_verify", ["systemd-analyze", "verify", str(UNIT_ROOT / SERVICE), str(UNIT_ROOT / TIMER)])
        calendar = command("systemd_calendar", ["systemd-analyze", "calendar", "2026-10-20 14:59:00 UTC"]).stdout.decode()
        require(any(line.strip() == "Next elapse: " + NEXT for line in calendar.splitlines()), "calendar_expiry_mismatch")
        command("daemon_reload", ["systemctl", "daemon-reload"])
        command("timer_enable", ["systemctl", "enable", "--now", TIMER])
        props = command("timer_properties", ["systemctl", "show", TIMER, "--property=ActiveState,SubState,NextElapseUSecRealtime"]).stdout.decode()
        timer = dict(line.split("=", 1) for line in props.splitlines() if "=" in line)
        require(timer == {"ActiveState": "active", "SubState": "waiting", "NextElapseUSecRealtime": NEXT}, "timer_not_waiting_for_exact_expiry")
        require(now() < EXPIRY - dt.timedelta(minutes=1), "window_expired_before_enable")
        install(INCLUDE, render.ACTIVE_INCLUDE, 0o644)
        install(candidate_path, candidate, 0o644)
        native("candidate_nginx_test", "nginx", "-t", "-c", "/etc/nginx/tls/" + candidate_path.name)
        close.validate_container(json.loads(command("container_recheck", docker + ["inspect", "--type", "container", CONTAINER]).stdout))
        replace_same_inode(candidate, BASE_SHA, arm=True)
        require(native("inside_candidate_sha", "sha256sum", "/etc/nginx/nginx.conf").decode().split()[0] == state["active_config_sha256"], "inside_candidate_changed")
        native("installed_nginx_test", "nginx", "-t")
        native("nginx_reload", "nginx", "-s", "reload")
        command("installed_close_check", [str(CLOSE), "check"])
        require(all((Path(path).stat().st_dev, Path(path).stat().st_ino, Path(path).stat().st_size, Path(path).stat().st_mtime_ns) == metadata
                    for path, metadata in cert_meta.items()), "certificate_file_changed")
        candidate_path.unlink()
        created.remove(candidate_path)
        fsync_directory(TLS)
        result = {"status": "installed_reload_signalled", "container_id": CONTAINER,
                  "baseline_sha256": BASE_SHA, "config_sha256": state["active_config_sha256"],
                  "include_sha256": state["active_include_sha256"], "state_sha256": digest(state_bytes),
                  "certificate_sha256": digest(cert_content), "config_inode": baseline_stat.st_ino,
                  "units": [SERVICE, TIMER], "next_elapse_utc": state["expires_utc"],
                  "container_time": container_time, "applied_utc": now().isoformat(), "http_login_test": "pending"}
        exclusive(BACKUP / "deployment-result.json", (json.dumps(result, sort_keys=True) + "\n").encode(), 0o600)
        print(json.dumps(result, sort_keys=True))
    except BaseException as error:
        rollback = []
        if timer_installed:
            for action in (["systemctl", "disable", "--now", TIMER], ["systemctl", "stop", SERVICE]):
                try:
                    command("rollback_stop", action)
                except BaseException:
                    rollback.append("timer_or_service_stop_failed")
        restored = not touched_config
        try:
            if INCLUDE in created and INCLUDE.exists():
                close.close_include(INCLUDE, INCLUDE.read_bytes())
            if touched_config:
                # A partial write also belongs to this transaction. The inode
                # check remains mandatory; never overwrite a replaced file.
                replace_same_inode(baseline, digest(CONFIG.read_bytes()))
                require(native("rollback_inside_sha", "sha256sum", "/etc/nginx/nginx.conf").decode().split()[0] == BASE_SHA, "rollback_inside_mismatch")
                native("rollback_nginx_test", "nginx", "-t")
                native("rollback_nginx_reload", "nginx", "-s", "reload")
                restored = True
        except BaseException:
            rollback.append("baseline_restore_or_reload_failed")
        if restored:
            for path in reversed(created):
                try:
                    if path == STATE_ROOT:
                        # The installed check/close helper alone may create it.
                        lock = path / "operation.lock"
                        if lock.exists():
                            lock.unlink()
                        path.rmdir()
                    else:
                        path.unlink(missing_ok=True)
                except BaseException:
                    rollback.append("created_file_cleanup_failed")
            if timer_installed:
                command("rollback_daemon_reload", ["systemctl", "daemon-reload"], allow_failure=True)
                command("rollback_reset_failed", ["systemctl", "reset-failed", SERVICE, TIMER], allow_failure=True)
                stamp = Path("/var/lib/systemd/timers/stamp-" + TIMER)
                if stamp.exists() and not stamp.is_symlink():
                    stamp.unlink()
        failure = {"status": "failed", "error": str(error) if isinstance(error, ValueError) else type(error).__name__,
                   "baseline_restored_and_reload_signalled": restored, "rollback_errors": rollback,
                   "backup": str(BACKUP), "failed_utc": now().isoformat()}
        exclusive(BACKUP / "deployment-failure.json", (json.dumps(failure, sort_keys=True) + "\n").encode(), 0o600)
        print(json.dumps(failure, sort_keys=True))
        raise SystemExit(1)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise InterruptedError("signal_" + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "preflight_failed", "error": str(error) if isinstance(error, ValueError) else type(error).__name__}, sort_keys=True))
        raise SystemExit(1)
