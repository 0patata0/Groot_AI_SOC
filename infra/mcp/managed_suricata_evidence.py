#!/usr/bin/env python3
"""Fixed-A managed evidence reader; no daemon, commands, writes or policy changes.

Only an ACTIVE current generation is admitted. Rotation/pending states defer;
older generations are deliberately not guessed from globs or legacy .1 files.
The existing containment validator remains the sole attack-policy decision.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

MID = "096e90b6243e438aa8a7b392be754732"
STATE = Path("/var/lib/capstone-raw-operations/suricata/state.json")
BASE = Path("/home/groot_a/capstone/secstack/logs/suricata")
LOCK = Path("/var/lib/capstone-automation/ansible/vector.lock")
PINS = {
    "vector_config_sha256": Path("/etc/capstone-vector/vector.toml"),
    "vector_env_sha256": Path("/etc/capstone-vector/vector.env"),
    "wazuh_config_sha256": Path("/var/ossec/etc/ossec.conf"),
}
MAX_BYTES = 16 * 1024 * 1024
MAX_LINE = 256 * 1024
MAX_ROWS = 32768
HEX = re.compile(r"[0-9a-f]{64}\Z")


class EvidenceUnavailable(ValueError):
    """Fixed diagnostic codes only; never include source bytes in errors."""


def need(condition, code):
    if not condition:
        raise EvidenceUnavailable(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def identity(s, content=False):
    answer = (s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink)
    return answer + (s.st_size, s.st_mtime_ns, s.st_ctime_ns) if content else answer


def directories(path, root_only=False):
    answer = []
    for part in (path, *path.parents):
        s = part.lstat()
        need(stat.S_ISDIR(s.st_mode), "directory_not_regular")
        if root_only:
            need(s.st_uid == 0 and not stat.S_IMODE(s.st_mode) & 0o022,
                 "untrusted_directory")
        answer.append((str(part), identity(s)))
    return answer


def read_fixed(path, limit, mode=None, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == owner and
             before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o002 and
             (mode is not None or not stat.S_IMODE(before.st_mode) & 0o020) and
             (mode is None or stat.S_IMODE(before.st_mode) == mode) and
             0 <= before.st_size <= limit, "fixed_file_metadata")
        data = os.read(fd, limit + 1)
        need(len(data) == before.st_size and
             identity(before, True) == identity(os.fstat(fd), True) ==
             identity(path.lstat(), True), "fixed_file_changed")
        return data, identity(before, True)
    finally:
        os.close(fd)


def uint(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def active_state(raw, boot):
    try:
        state = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError):
        raise EvidenceUnavailable("state_json_invalid") from None
    need(type(state) is dict and raw == canonical(state) and set(state) == {
        "schema_version", "policy", "engine", "machine_id", "boot_id", "revision",
        "phase", "current", "pending", "proof", "source_pins"}, "state_shape")
    need(type(state["schema_version"]) is int and state["schema_version"] == 1 and
         state["policy"] == "capstone-raw-operations-v1" and state["engine"] == "suricata" and
         state["machine_id"] == MID and state["boot_id"] == boot and
         uint(state["revision"], 2147483647), "state_identity")
    need(state["phase"] == "active" and state["pending"] is None and
         state["proof"] == {"old_closed": None, "publish_guard": None, "readers_drained": None},
         "managed_rotation_not_active")
    generation = state["current"]
    need(type(generation) is dict and set(generation) == {
        "basename", "number", "device", "inode", "writer_config_sha256"}, "generation_shape")
    need(uint(generation["number"], 4294967295) and
         uint(generation["device"], 9007199254740991) and
         uint(generation["inode"], 9007199254740991) and generation["inode"] > 0 and
         generation["basename"] == "generation-%010d.jsonl" % generation["number"],
         "generation_identity")
    pins = state["source_pins"]
    need(type(pins) is dict and set(pins) == {"container_id", "engine_config_sha256",
        "producer_format_sha256", *PINS} and
        all(isinstance(v, str) and HEX.fullmatch(v) for v in pins.values()), "pins_shape")
    need(generation["writer_config_sha256"] == pins["engine_config_sha256"], "generation_config_pin")
    return state


@contextlib.contextmanager
def shared_rotation_lock(path=LOCK):
    directories(path.parent, root_only=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and identity(s)[2:] == (0, 0, 0o600, 1), "rotation_lock_metadata")
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise EvidenceUnavailable("rotation_lock_busy") from None
        need(identity(path.lstat()) == identity(s), "rotation_lock_changed")
        yield
        need(identity(path.lstat()) == identity(s), "rotation_lock_changed")
    finally:
        os.close(fd)


def _events(state_path, base, pins, boot, *, root_uid=0, root_gid=0, sensor_uid=998, sensor_gid=998,
            trusted_state_ancestors=True):
    """Internal fixture API. Production entry supplies only constants above."""
    deadline = time.monotonic() + 5
    state_dirs = directories(state_path.parent, root_only=trusted_state_ancestors)
    need(state_path.parent.lstat().st_uid == root_uid and
         stat.S_IMODE(state_path.parent.lstat().st_mode) == 0o700, "state_parent_metadata")
    state_raw, state_meta = read_fixed(state_path, 16384, 0o600, root_uid)
    state = active_state(state_raw, boot)
    config_snapshot = {}
    for key, path in pins.items():
        mode = 0o660 if key == "wazuh_config_sha256" else 0o600
        data, meta = read_fixed(path, 1024 * 1024, mode, root_uid)
        need(hashlib.sha256(data).hexdigest() == state["source_pins"][key], "configuration_pin_changed")
        config_snapshot[key] = (data, meta)
    managed = base / "capstone-managed"
    raw_dirs = directories(managed)
    ms = managed.lstat()
    need(ms.st_uid == root_uid and ms.st_gid == root_gid and stat.S_IMODE(ms.st_mode) == 0o711, "managed_parent_metadata")
    need(not any(os.path.lexists(managed / name) for name in (".publish-link", ".audit-path.next")),
         "unfinished_publication")
    current = state["current"]
    paths = (managed / current["basename"], managed / "active.jsonl", base / "eve.json")
    handles = []
    try:
        for path in paths:
            handles.append(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK))
        baseline = [os.fstat(fd) for fd in handles]
        expected = (current["device"], current["inode"], sensor_uid, sensor_gid, 0o644, 3)
        need(all(stat.S_ISREG(s.st_mode) and identity(s) == expected for s in baseline), "managed_links_not_exact")
        end = baseline[0].st_size
        need(0 <= end <= 2147483648, "generation_size_bound")
        start = max(0, end - MAX_BYTES)
        data = os.pread(handles[0], end - start, start)
        need(len(data) == end - start, "snapshot_short_read")
        # Appends may continue; the fixed pre-stat byte range must stay exact.
        need(data == os.pread(handles[0], len(data), start), "snapshot_prefix_changed")
        for path, fd in zip(paths, handles):
            s = os.fstat(fd)
            need(identity(s) == expected == identity(path.lstat()) and s.st_size >= end,
                 "managed_links_changed")
        if start:
            split = data.find(b"\n")
            data = data[split + 1:] if split >= 0 else b""
        # A live partial final line cannot be treated as complete evidence.
        tail = data.rfind(b"\n")
        complete = data[:tail + 1] if tail >= 0 else b""
        lines = complete.split(b"\n")[:-1]
        need(len(lines) <= MAX_ROWS, "snapshot_record_budget")
        events = []
        for line in lines:
            need(time.monotonic() <= deadline, "evidence_scan_deadline")
            if len(line) > MAX_LINE:
                continue
            try:
                event = json.loads(line, object_pairs_hook=unique)
            except (ValueError, UnicodeDecodeError, RecursionError):
                continue
            if isinstance(event, dict):
                events.append(event)
        need(read_fixed(state_path, 16384, 0o600, root_uid) == (state_raw, state_meta), "state_changed")
        need(directories(state_path.parent, root_only=trusted_state_ancestors) == state_dirs and
             directories(managed) == raw_dirs, "directories_changed")
        for key, path in pins.items():
            mode = 0o660 if key == "wazuh_config_sha256" else 0o600
            need(read_fixed(path, 1024 * 1024, mode, root_uid) == config_snapshot[key], "configuration_changed")
        for path, fd in zip(paths, handles):
            s = os.fstat(fd)
            need(identity(s) == expected == identity(path.lstat()) and s.st_size >= end,
                 "managed_links_changed")
        need(not any(os.path.lexists(managed / name) for name in (".publish-link", ".audit-path.next")),
             "unfinished_publication")
        need(time.monotonic() <= deadline, "evidence_scan_deadline")
        return events, {"policy": "managed_active_current_generation_v1",
            "state_sha256": hashlib.sha256(state_raw).hexdigest(), "revision": state["revision"],
            "generation": current["number"], "device": current["device"], "inode": current["inode"],
            "link_count": 3, "snapshot_start": start, "snapshot_end": end,
            "complete_lines_bytes": len(complete), "complete_lines_sha256": hashlib.sha256(complete).hexdigest(),
            "older_generations_scanned": False, "delivery_acknowledged": False}
    finally:
        for fd in handles:
            os.close(fd)


def read_evidence(ip, now, validate):
    """Used inside the existing ContainmentService rule-change lock."""
    need(os.geteuid() == 0, "root_required")
    need(Path("/etc/machine-id").read_text().strip() == MID, "fixed_A_required")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    need(re.fullmatch(r"[0-9a-f]{32}", boot), "boot_id_invalid")
    with shared_rotation_lock():
        events, provenance = _events(STATE, BASE, PINS, boot)
        result = validate(events, ip, now)
        result["managed_source"] = provenance
        return result
