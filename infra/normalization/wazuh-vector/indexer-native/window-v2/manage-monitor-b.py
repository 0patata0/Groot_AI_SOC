#!/usr/bin/env python3
"""Root-only, pinned v1/v2 monitor manager; no service, MCP, arbitrary JSON or retry.

upgrade/rollback changes only inputs and triggers on the same owned monitor.
An acknowledged mutation is bound to an independent GET before local state moves.
An uncertain request leaves a pending receipt and requires operator reconciliation.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

LEGACY_HELPER_SHA = "0318e0ab4231b32de9624466b19bb07c6324ae6277311d5bf528460a774d6f80"
V1_SHA = "f0262be494e605edcb22fb32f71f4854014dd4f671b035803886a5b1036bafd1"
V2_SHA = "acc8ac9649cc8b974872a30cf4bcc8f2e52adf0caf56ed197e8b95066d657c7f"
ROOT = Path(__file__).absolute().parent
BACKUPS = Path("/var/backups")


def module(version):
    path = ROOT.parent / "deploy-monitor-b.py"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != LEGACY_HELPER_SHA:
        raise RuntimeError("legacy_helper_source_changed")
    result = types.ModuleType("monitor_" + version)
    result.__file__ = str(path)
    # Execute exactly the bytes verified above; no second import read or pycache.
    exec(compile(raw, str(path), "exec"), result.__dict__)
    if version == "v2":
        result.SOURCE_SHA = V2_SHA

        def canonical_aggs(aggs):
            result.require(isinstance(aggs, dict) and set(aggs) == {"observation"},
                           "unexpected_v2_aggregation")
            aggregate = aggs["observation"]
            result.require(isinstance(aggregate, dict) and set(aggregate) == {"scripted_metric"},
                           "unexpected_v2_metric")
            metric = copy.deepcopy(aggregate["scripted_metric"])
            scripts = {"init_script", "map_script", "combine_script", "reduce_script"}
            result.require(isinstance(metric, dict) and set(metric) <= scripts | {"params"}
                           and scripts <= set(metric), "unexpected_v2_metric_fields")
            metric.setdefault("params", {})
            result.require(isinstance(metric["params"], dict), "unexpected_v2_metric_params")
            for name in scripts:
                script = metric[name]
                result.require(isinstance(script, dict) and set(script) <= {"source", "lang", "params"}
                               and isinstance(script.get("source"), str), "unexpected_v2_script")
                script.setdefault("lang", "painless")
                script.setdefault("params", {})
                result.require(script["lang"] == "painless" and isinstance(script["params"], dict),
                               "unexpected_v2_script_language_or_params")
            return {"observation": {"scripted_metric": metric}}

        result.canonical_aggs = canonical_aggs
    return result


def sources():
    result = {}
    for version, expected, path in (("v1", V1_SHA, ROOT.parent / "monitor.json"),
                                    ("v2", V2_SHA, ROOT / "monitor.json")):
        api = module(version)
        raw = path.read_bytes()
        api.require(len(raw) < 65536 and hashlib.sha256(raw).hexdigest() == expected,
                    "candidate_source_sha_mismatch_" + version)
        candidate = api.strict_json(raw)
        api.validate_monitor(candidate, candidate, False)
        result[version] = (api, candidate)
    return result


def version_for(state, legacy):
    legacy.require(isinstance(state, dict), "monitor_not_managed")
    versions = {V1_SHA: "v1", V2_SHA: "v2"}
    legacy.require(state.get("candidate_sha256") in versions, "unknown_managed_source")
    legacy.require(state.get("phase") in {"enabled", "disabled"}, "previous_mutation_uncertain")
    return versions[state["candidate_sha256"]]


def unchanged_fields(before, after):
    # These are the only changed configuration fields; lifecycle timestamps are
    # server-owned. User/permissions/schema/schedule/identity stay byte-equivalent.
    ignored = {"inputs", "triggers", "last_update_time"}
    unchanged = {k: v for k, v in before.items() if k not in ignored} == {
        k: v for k, v in after.items() if k not in ignored}
    def trigger_metadata(monitor):
        rows = copy.deepcopy(monitor["triggers"])
        for row in rows:
            row.get("query_level_trigger", row).pop("condition", None)
        return rows
    return unchanged and trigger_metadata(before) == trigger_metadata(after)


def write_private(path, data):
    raw = json.dumps(data, sort_keys=True, ensure_ascii=True, allow_nan=False).encode() + b"\n"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return hashlib.sha256(raw).hexdigest()


def backup(before, state, from_version, to_version, legacy):
    legacy.protected(BACKUPS, directory=True)
    path = BACKUPS / ("capstone-indexer-window-" + str(time.time_ns()))
    path.mkdir(mode=0o700)
    hashes = {}
    for name, value in (("monitor-get.json", before), ("state.json", state)):
        hashes[name] = write_private(path / name, value)
    write_private(path / "manifest.json", {"from": from_version, "to": to_version,
                                           "sha256": hashes, "created_epoch_ms": time.time_ns() // 1000000})
    for directory in (path, path.parent):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return path


def migrate(operation, api, store, state, registry, backup_fn=backup):
    legacy = registry["v1"][0]
    current_version = version_for(state, legacy)
    wanted = "v2" if operation == "upgrade" else "v1"
    legacy.require(operation in {"upgrade", "rollback"}, "unknown_migration")
    current_module, current_candidate = registry[current_version]
    target, candidate = registry[wanted]
    before = current_module.get_owned(api, state, current_candidate)
    if current_version == wanted:
        return {"operation": operation, "changed": False, "version": wanted,
                "monitor_id": state["_id"], "actions": 0}
    body = copy.deepcopy(before["monitor"])
    body["inputs"] = copy.deepcopy(candidate["inputs"])
    for actual, wanted_trigger in zip(body["triggers"], candidate["triggers"]):
        actual.get("query_level_trigger", actual)["condition"] = copy.deepcopy(wanted_trigger["query_level_trigger"]["condition"])
    body.pop("last_update_time", None)
    target.validate_monitor(body, candidate, before["monitor"]["enabled"])
    legacy.require(unchanged_fields(before["monitor"], body), "unexpected_migration_change")
    backup_path = backup_fn(before, state, current_version, wanted, legacy)
    pending = {**state, "phase": operation + "_pending", "backup": str(backup_path),
               "target_candidate_sha256": target.SOURCE_SHA,
               "submitted_body_sha256": legacy.digest(body)}
    store.write(pending)
    path = legacy.API + "/" + state["_id"] + "?if_seq_no=" + str(state["_seq_no"]) + "&if_primary_term=" + str(state["_primary_term"])
    # Exactly one PUT. A timeout, 409 or bad reply is never automatically retried.
    _, updated = api("PUT", path, body)
    write_private(backup_path / "acknowledged-update.json", updated)
    record = target.saved_record(updated, candidate, before["monitor"]["enabled"])
    legacy.require(record["_id"] == state["_id"] and record["_seq_no"] > state["_seq_no"]
                   and record["_primary_term"] >= state["_primary_term"]
                   and unchanged_fields(before["monitor"], updated["monitor"]),
                   "migration_identity_revision_or_permissions_changed")
    store.write({**pending, "phase": operation + "_readback_pending", "acknowledged_revision": target.revision(updated)})
    legacy.require(target.exact_names(api) == [state["_id"]], "post_migration_name_not_unique")
    _, fetched = api("GET", legacy.API + "/" + state["_id"])
    write_private(backup_path / "readback.json", fetched)
    verified = target.saved_record(fetched, candidate, before["monitor"]["enabled"])
    for key in ("_id", "_seq_no", "_primary_term", "monitor_sha256", "config_sha256"):
        legacy.require(verified[key] == record[key], "migration_readback_changed")
    verified.update({"managed_version": wanted, "last_migration_backup": str(backup_path)})
    store.write(verified)
    return {"operation": operation, "changed": True, "version": wanted, "monitor_id": state["_id"],
            "enabled": before["monitor"]["enabled"], "actions": 0, "backup": str(backup_path),
            "before_revision": legacy.revision(before), "after_revision": target.revision(fetched),
            "server_config_sha256": verified["config_sha256"], "independent_readback": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inspect", "observe", "enable", "disable", "upgrade", "rollback"))
    args = parser.parse_args()
    if os.geteuid() != 0 or Path("/etc/machine-id").read_text().strip() != "1e143067c98a44ffba6eaa925dc038d7":
        raise RuntimeError("root_or_machine_identity_mismatch")
    for path in (ROOT, ROOT.parent, ROOT.parent / "deploy-monitor-b.py"):
        item = path.lstat()
        valid_kind = stat.S_ISREG(item.st_mode) if path.name == "deploy-monitor-b.py" else stat.S_ISDIR(item.st_mode)
        if not valid_kind or item.st_uid != 0 or item.st_mode & 0o022 or (stat.S_ISREG(item.st_mode) and item.st_nlink != 1):
            raise RuntimeError("unsafe_legacy_import_path")
    legacy = module("v1")
    legacy.require(os.geteuid() == 0 and Path("/etc/machine-id").read_text().strip() == legacy.MACHINE_ID,
                   "root_or_machine_identity_mismatch")
    os.umask(0o077)
    for path in (ROOT, ROOT.parent, legacy.STATE_DIR):
        legacy.protected(path, directory=True, private=path == legacy.STATE_DIR)
    for path in (ROOT / "manage-monitor-b.py", ROOT / "monitor.json", ROOT.parent / "monitor.json",
                 ROOT.parent / "deploy-monitor-b.py"):
        legacy.protected(path)
    registry = sources()
    state_path = legacy.STATE_DIR / "state.json"
    legacy.protected(state_path, private=True)
    legacy.require(state_path.stat().st_size <= legacy.MAX_RESPONSE, "state_too_large")
    lock = legacy.STATE_DIR / ".lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    try:
        legacy.protected(lock, private=True)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = legacy.strict_json(state_path.read_bytes())
        version = version_for(state, legacy)
        current, candidate = registry[version]
        store = current.StateStore(state_path)
        api = current.CurlAPI()
        if args.operation in {"upgrade", "rollback"}:
            result = migrate(args.operation, api, store, state, registry)
        else:
            result = current.operate(args.operation, api, store, candidate)
            result["version"] = version
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Fixed-code exceptions only; no HTTP body, cert, config or traceback.
        code = str(error) if type(error).__name__ == "Refused" else "operator_check_failed_no_automatic_retry"
        print(json.dumps({"ok": False, "error": code}))
        sys.exit(1)
