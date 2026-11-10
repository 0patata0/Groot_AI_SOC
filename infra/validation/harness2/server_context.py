#!/usr/bin/env python3
"""Capture actual read-only MCP discovery; never invoke a model or expose secrets."""
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import importlib.util
import sys

KST = ZoneInfo("Asia/Seoul")
STATE = Path("/var/lib/capstone-harness2")
DESTINATION = STATE / "context.json"
ENTRYPOINT = "/usr/local/sbin/capstone-ollama-trial"
CONFIG = Path("/etc/capstone-harness2/audit.json")
HASH_PATHS = (
    "/etc/capstone-ollama-trial/config.json",
    "/opt/capstone-ollama-trial/policy.py",
    "/opt/hermes-data/config.yaml",
    "/opt/hermes-data/management/config.yaml",
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def discovery_projection(value):
    if (not isinstance(value, dict) or value.get("status") != "discovered"
            or value.get("calls") != [] or value.get("model_calls") != []
            or type(value.get("protected_calls")) is not int or value["protected_calls"] != 0
            or type(value.get("chat_posts")) is not int or value["chat_posts"] != 0):
        raise ValueError("discovery_scope_invalid")
    model = value.get("model")
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,128}", model):
        raise ValueError("discovery_model_invalid")
    if value.get("access_mode") not in ("read-only", "hermes-parity"):
        raise ValueError("discovery_access_invalid")
    catalog = value.get("catalog")
    if not isinstance(catalog, list) or not 1 <= len(catalog) <= 256:
        raise ValueError("discovery_catalog_invalid")
    selected = []
    seen = set()
    for row in catalog:
        if not isinstance(row, dict) or set(row) != {"server", "name", "alias", "schema_sha256"}:
            raise ValueError("discovery_catalog_fields")
        if (not all(isinstance(row[k], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", row[k])
                    for k in ("server", "name", "alias"))
                or row["alias"] != "mcp__" + row["server"].replace("-", "_") + "__" + row["name"]
                or not isinstance(row["schema_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["schema_sha256"])
                or row["alias"] in seen):
            raise ValueError("discovery_catalog_identity")
        seen.add(row["alias"])
        selected.append(dict(row))
    selected.sort(key=lambda r: r["alias"])
    return {"model": model, "access_mode": value["access_mode"], "catalog": selected,
            "catalog_sha256": digest(json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()),
            "schema_observation": "actual tool names and input-schema hashes; full schemas not included",
            "model_observation": "configured model identity; inference availability not tested"}


def source_bytes(path, allowed_uids):
    """Read only fixed configured paths, with no link following or code execution.

    Original agent files may be service-owned. Their owner is recorded; they
    become root-owned data snapshots, never trusted executable audit modules.
    """
    path = Path(path)
    if not path.is_absolute() or any(p in (".", "..") for p in path.parts):
        raise ValueError("source_path_invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
            st = os.fstat(fd)
            if st.st_uid not in allowed_uids or st.st_mode & 0o022:
                raise ValueError("source_parent_unsafe")
        target = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        if not stat.S_ISREG(os.fstat(target).st_mode):
            os.close(target)
            raise ValueError("source_file_unsafe")
        with os.fdopen(target, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid not in allowed_uids or before.st_mode & 0o022
                    or before.st_size > 2 * 1024 * 1024):
                raise ValueError("source_file_unsafe")
            raw = stream.read(2 * 1024 * 1024 + 1)
            after = os.fstat(stream.fileno())
            identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_mode, x.st_uid)
            if identity(before) != identity(after) or len(raw) != after.st_size:
                raise ValueError("source_changed_during_read")
            return raw, {"uid": after.st_uid, "gid": after.st_gid,
                         "mode": oct(stat.S_IMODE(after.st_mode)), "size": len(raw)}
    finally:
        os.close(fd)


def service_uids():
    import pwd
    result = {0}
    for name in ("hermes", "capstone-hermes", "soc-ollama"):
        try: result.add(pwd.getpwnam(name).pw_uid)
        except KeyError: pass
    return result


def read_fixed_hash(path):
    # No credential-bearing configuration bytes are included in the report.
    return digest(source_bytes(path, service_uids())[0])


def configured_inputs():
    # The audit module/config are root-controlled installation outputs, never
    # model-selected imports or paths. Verify before importing the local module.
    module_path = Path(__file__).with_name("server_audit.py")
    raw, _ = source_bytes(module_path, {0})
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader("capstone_audit_context", loader=None))
    sys.modules[module.__name__] = module
    try:
        exec(compile(raw, str(module_path), "exec"), module.__dict__)
        cfg = module._validate_config(json.loads(source_bytes(CONFIG, {0})[0]))
    finally:
        sys.modules.pop(module.__name__, None)
    facts = cfg["collector_facts"]
    origins = facts.get("component_sources")
    hashes = facts.get("configuration_paths")
    if (not isinstance(origins, dict) or origins.keys() != cfg["component_paths"].keys()
            or not isinstance(hashes, list) or len(hashes) != 4
            or len(set(hashes)) != len(hashes)):
        raise ValueError("collector_mapping_invalid")
    for key, destination in cfg["component_paths"].items():
        if destination != str(STATE / "sources" / key):
            raise ValueError("collector_snapshot_invalid")
        if not isinstance(origins[key], str) or not origins[key].startswith("/opt/"):
            raise ValueError("collector_source_invalid")
    if any(not isinstance(p, str) or not p.startswith(("/opt/", "/etc/")) for p in hashes):
        raise ValueError("collector_hash_path_invalid")
    return cfg, origins, hashes


def snapshots(config, origins, now=None):
    observed = {}
    for key, path in sorted(origins.items()):
        record = {"path": path, "status": "unavailable"}
        try:
            raw, metadata = source_bytes(Path(path), service_uids())
            destination = Path(config["component_paths"][key])
            # Root owns the fixed storage hierarchy; no service may replace it.
            for parent in reversed(destination.parent.parents):
                if parent == STATE or STATE in parent.parents:
                    if not parent.exists(): parent.mkdir(mode=0o700)
                    if parent.is_symlink() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022:
                        raise ValueError("snapshot_parent_unsafe")
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            publish_bytes(raw, destination)
            record.update(status="observed", sha256=digest(raw), **metadata)
        except (ValueError, OSError):
            record["error_code"] = "source_snapshot_unavailable"
        record["observed_at_kst"] = (now or datetime.now(KST)).isoformat()
        observed[key] = record
    return observed


def collect(run=subprocess.run, now=None, *, hash_paths=HASH_PATHS, source_observations=None):
    result = {"schema": 1, "observed_at_kst": (now or datetime.now(KST)).isoformat(),
              "status": "unavailable", "model": None, "access_mode": None, "catalog": [],
              "catalog_sha256": None, "configuration_sha256": {}, "error_code": None,
              "model_calls": None, "tool_calls": None, "chat_posts": None, "protected_calls": None}
    try:
        for name in hash_paths:
            result["configuration_sha256"][name] = read_fixed_hash(Path(name))
        response = run([ENTRYPOINT], input=json.dumps({"discover_only": True, "question": "등록 도구 목록 확인"}),
                       text=True, capture_output=True, timeout=75,
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
                            "PYTHONDONTWRITEBYTECODE": "1"})
        if response.returncode != 0 or len(response.stdout.encode()) > 2 * 1024 * 1024:
            raise ValueError("discovery_execution_failed")
        result.update(discovery_projection(json.loads(response.stdout)), status="observed",
                      model_calls=0, tool_calls=0, chat_posts=0, protected_calls=0)
    except subprocess.TimeoutExpired:
        result["error_code"] = "discovery_timeout"
    except (OSError, ValueError, TypeError, KeyError):
        result["error_code"] = "discovery_unavailable"
    result["observed_at_kst"] = (now or datetime.now(KST)).isoformat()
    if source_observations is not None:
        result["source_observations"] = source_observations
    return result


def publish_bytes(raw, destination):
    parent = destination.parent
    if parent.is_symlink() or not parent.is_dir() or parent.stat().st_uid != os.geteuid():
        raise ValueError("context_directory_invalid")
    if parent.stat().st_mode & 0o022 or destination.is_symlink():
        raise ValueError("context_directory_writable")
    fd, tmp = tempfile.mkstemp(prefix=".context-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush(); os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, destination)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def publish(value, destination=DESTINATION):
    publish_bytes((json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode(), destination)


def main():
    import sys
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise SystemExit("fixed root collector required")
    try:
        config, origins, hashes = configured_inputs()
        source_observations = snapshots(config, origins)
        value = collect(hash_paths=hashes, source_observations=source_observations)
    except (ValueError, OSError, KeyError, TypeError):
        value = {"schema": 1, "status": "unavailable", "observed_at_kst": datetime.now(KST).isoformat(),
                 "error_code": "collector_configuration_unavailable"}
    publish(value)
    # An unavailable observation is recorded, never mislabeled as a successful
    # audit; transient remote failure need not create recurring systemd failures.
    print(json.dumps({k: value[k] for k in ("status", "observed_at_kst", "error_code")}))


if __name__ == "__main__":
    main()
