#!/usr/bin/python3 -IB
"""Root-only response executor. No sudo grant exposes this program directly.

The response MCP root wrapper owns the approval check. This helper accepts only
three fixed operations and uses the same live protection checks as containment.
It never flushes a set or refreshes an existing incident's temporary deadline.
"""
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time


def load(name, path):
    p = Path(path)
    for directory in p.parents:
        s = directory.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("unsafe_executor_directory")
    s = p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or s.st_mode & 0o022:
        raise ValueError("unsafe_executor")
    spec = importlib.util.spec_from_loader(name, importlib.machinery.SourceFileLoader(name, str(p)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def arguments(argv):
    if argv == ["list"]:
        return "list", None, None
    if len(argv) != 4 or argv[0] not in ("add", "del") or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,64}", argv[3]):
        raise ValueError("invalid_fixed_operation")
    if argv[0] == "del":
        if argv[2] != "-":
            raise ValueError("invalid_release")
        return "del", argv[1], None
    match = re.fullmatch(r"([1-9][0-9]{0,2})m", argv[2])
    if not match or not 1 <= int(match[1]) <= 120:
        raise ValueError("invalid_ttl")
    return "add", argv[1], int(match[1]) * 60


def release_owned_containment(engine, containment, backend, ip, before):
    """Called only after the existing Response MCP consumed unblock approval.

    Caller holds the rule-change lock followed by the shared firewall lock.
    Never treat a forged tag or another owner's entry as an owned incident.
    """
    match = re.fullmatch(r"contain:([0-9a-f]{32}):([1-9][0-9]{0,11})", str(before.get("comment", "")))
    if not match:
        raise ValueError("existing_block_not_response_owned")
    service = containment.ContainmentService(engine)
    record = service._load(match[1])
    if (record["ip"] != ip or record["owned_deadline"] != int(match[2]) or
            record["status"] not in ("pending", "kept") or not backend.owned(record, {"element": before})):
        raise ValueError("existing_containment_identity_changed")
    after = backend.release(record)
    if after.get("element") is not None:
        raise ValueError("release_readback_failed")
    record["status"] = "released"
    record["result"] = "released by existing Response MCP after separate operator unblock approval"
    record["after_observation_sha256"] = containment.digest(after)
    service._save(record)


def main(argv):
    if os.geteuid() != 0:
        raise ValueError("root_required")
    operation, ip, seconds = arguments(argv)
    executor = load("capstone_response_rules", "/usr/local/sbin/rule-change-executor")
    containment = load("capstone_response_containment", "/opt/rule-change/incident_containment.py")
    host, broker = executor._secure_config()
    if host != "a":
        raise ValueError("security_host_required")
    engine = executor.Engine(host, broker)
    backend = containment.NftBackend(engine)
    with engine.locked(), backend.locked():
        if operation == "list":
            value = backend._set("agent_block")
            print(json.dumps({"blocks": value.get("elem", [])}, sort_keys=True))
            return
        backend.check_protected(ip)
        before = backend.snapshot(ip)["element"]
        if operation == "del":
            if before and str(before.get("comment", "")).startswith("contain:"):
                release_owned_containment(engine, containment, backend, ip, before)
            elif before:
                if not str(before.get("comment", "")).startswith("response:"):
                    raise ValueError("existing_block_not_response_owned")
                engine.runner.call([containment.NFT, "delete", "element", "inet", "capstone_fw", "agent_block", "{", ip, "}"])
                if backend.snapshot(ip)["element"] is not None:
                    raise ValueError("release_readback_failed")
        else:
            if before:
                raise ValueError("existing_block_refresh_refused")
            tag = "response:" + secrets.token_hex(16) + ":" + str(int(time.time()) + seconds)
            engine.runner.call([containment.NFT, "create element inet capstone_fw agent_block { %s timeout %ds comment \"%s\" }" % (ip, seconds, tag)])
            if backend.snapshot(ip)["element"].get("comment") != tag:
                raise ValueError("ownership_readback_failed")
        print(json.dumps({"status": "applied", "operation": operation}, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as exc:
        code = str(exc) if isinstance(exc, ValueError) and re.fullmatch(r'[a-z_]{1,80}', str(exc)) else 'fixed_policy_or_execution_failure'
        print(json.dumps({'error':'response_operation_refused','reason_code':code}))
        raise SystemExit(3)
