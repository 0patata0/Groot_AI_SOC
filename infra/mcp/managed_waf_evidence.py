#!/usr/bin/env python3
"""Read trusted, current WAF denial evidence for the existing containment tool.

No commands, writes, caller paths or extra MCP. The common managed reader is
passed as verified code by incident_containment, never imported from cwd.
HTTP transactions are not represented as independent network flows.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time

STATE = Path("/var/lib/capstone-raw-operations/modsecurity/state.json")
BASE = Path("/home/groot_a/capstone/secstack/logs/modsec")
POLICY = Path("/etc/rule-change/waf-evidence.json")
KST = timezone(timedelta(hours=9))
UID = re.compile(r"v2:([0-9a-f]{64}):([0-9a-f]{32}):([0-9]{10,12}\.[0-9]{3}):(.+)\Z")
CONFIGS = (
    "/etc/modsecurity.d/modsecurity.conf", "/etc/modsecurity.d/setup.conf",
    "/etc/modsecurity.d/modsecurity-override.conf",
    "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf",
    "/etc/nginx/includes/proxy_backend.conf",
    "/etc/nginx/conf.d/zz-capstone-evidence.conf",
    "/etc/nginx/conf.d/zz-capstone-labs.conf",
)
ATTACK_TAGS = frozenset(("attack-sqli", "attack-xss", "attack-rce", "attack-rfi",
                         "attack-lfi", "attack-php", "attack-java", "attack-sess"))


class EvidenceUnavailable(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise EvidenceUnavailable(code)


class Pairs(list):
    pass


def structure(value, path=()):
    # ModSecurity legitimately repeats HTTP header names. Never consult header
    # values as identity evidence, and reject duplicates in every other object.
    if isinstance(value, Pairs):
        if path in (("transaction", "request", "headers"),
                    ("transaction", "response", "headers")):
            return None
        answer = {}
        for key, item in value:
            need(key not in answer, "duplicate_structure_key")
            answer[key] = structure(item, (*path, key))
        return answer
    if isinstance(value, list):
        return [structure(item, path) for item in value]
    return value


def parse_event(raw, binding):
    """Only compact denial facts leave this parser; no URI, body or headers."""
    tx = structure(json.loads(raw, object_pairs_hook=Pairs))["transaction"]
    match = UID.fullmatch(tx.get("unique_id", ""))
    need(match is not None and match[1] == binding, "producer_binding_invalid")
    epoch = float(match[3])
    iso = datetime.fromisoformat(match[4])
    need(iso.tzinfo is not None and 0 <= epoch - iso.timestamp() < 1, "producer_clock_invalid")
    stamp = datetime.strptime(tx["time_stamp"], "%a %b %d %H:%M:%S %Y").replace(tzinfo=iso.tzinfo)
    need(abs(stamp.timestamp() - epoch) <= 2, "audit_clock_invalid")
    need(tx.get("is_interrupted") is True and tx["response"].get("http_code") == 403 and
         type(tx["response"].get("http_code")) is int and
         tx["producer"].get("secrules_engine") == "Enabled", "not_waf_denial")
    source = str(ipaddress.IPv4Address(tx["client_ip"]))
    destination = str(ipaddress.IPv4Address(tx["host_ip"]))
    need(source == tx["client_ip"] and destination == tx["host_ip"] and
         type(tx["client_port"]) is int and 1 <= tx["client_port"] <= 65535 and
         type(tx["host_port"]) is int and 1 <= tx["host_port"] <= 65535, "endpoint_invalid")
    rules = set()
    for message in tx["messages"]:
        details = message["details"]
        rid, tags, severity = details.get("ruleId"), details.get("tags"), details.get("severity")
        # CRS anomaly totals (949110), protocol checks and scanner/policy noise
        # alone cannot authorize an IP ban. Require a concrete attack rule.
        if (isinstance(rid, str) and re.fullmatch(r"[0-9]{1,10}", rid) and
                isinstance(tags, list) and all(isinstance(t, str) for t in tags) and
                ATTACK_TAGS.intersection(tags) and str(severity) in ("0", "1", "2", "3", "4") and
                type(severity) in (str, int)):
            rules.add(int(rid))
    need(rules, "no_eligible_attack_rule")
    return {"timestamp": datetime.fromtimestamp(epoch, KST).isoformat(timespec="milliseconds"),
            "transaction_id": match[2], "src_ip": source, "dest_ip": destination,
            "dest_port": tx["host_port"], "rule_ids": sorted(rules), "http_status": 403}


def validated_evidence(events, ip, now, destination, port):
    rows = {}
    conflicts = set()
    for event in events:
        if event.get("src_ip") != ip or event.get("dest_ip") != destination or event.get("dest_port") not in (port if isinstance(port, (list, tuple)) else (port,)):
            continue
        seen = datetime.fromisoformat(event["timestamp"]).timestamp()
        if not now - 300 <= seen <= now + 2:
            continue
        tid = event["transaction_id"]
        if tid in rows and rows[tid] != event:
            conflicts.add(tid)
        rows[tid] = event
    need(rows and not conflicts, "no_unambiguous_recent_waf_attack")
    ordered = sorted(rows.values(), key=lambda r: (r["timestamp"], r["transaction_id"]))
    return {"sensor": "a:modsecurity", "window_seconds": 300, "independent_flows": 0,
            "http_transactions": len(rows), "events": ordered[-16:]}


def policy_snapshot(common):
    common["directories"](POLICY.parent, root_only=True)
    raw, meta = common["read_fixed"](POLICY, 16384, 0o600)
    policy = json.loads(raw, object_pairs_hook=common["unique"])
    need(set(policy) == {"schema_version", "container_id", "deployment_binding", "proxy_container_id", "proxy_config_sha256",
                         "destination_ip", "destination_ports", "config_sha256"} and
         type(policy["schema_version"]) is int and policy["schema_version"] == 1 and
         all(isinstance(policy[k], str) and common["HEX"].fullmatch(policy[k])
             for k in ("container_id", "deployment_binding", "proxy_container_id", "proxy_config_sha256")) and
         str(ipaddress.IPv4Address(policy["destination_ip"])) == policy["destination_ip"] and
         type(policy["destination_ports"]) is list and policy["destination_ports"] == [8080, 8443] and
         type(policy["config_sha256"]) is dict and set(policy["config_sha256"]) == set(CONFIGS) and
         all(isinstance(v, str) and common["HEX"].fullmatch(v) for v in policy["config_sha256"].values()),
         "waf_policy_invalid")
    return policy, raw, meta


def read_config(common, path):
    # The pinned CRS image generates two nginx files as 101:101/0664. Only
    # that sensor-owned group-write form is admitted; bytes still match the
    # operator's root-owned SHA manifest on both writer observations.
    s = path.lstat()
    mode = None
    if stat.S_IMODE(s.st_mode) == 0o664:
        need(s.st_uid == s.st_gid == 101, "config_group_writer_invalid")
        mode = 0o664
    return common["read_fixed"](path, 1024 * 1024, mode, owner=None)


def writer_snapshot(state, common, policy, proc=Path("/proc")):
    """Attest all pinned nginx writers and configuration, twice per snapshot."""
    deadline = time.monotonic() + 2
    need(state["source_pins"]["container_id"] == policy["container_id"], "waf_container_changed")
    pointer = ("SecAuditLog /var/log/modsecurity/capstone-managed/" + state["current"]["basename"] + "\n").encode()
    need(hashlib.sha256(pointer).hexdigest() == state["current"]["writer_config_sha256"], "waf_pointer_pin_invalid")
    data, _ = common["read_fixed"](BASE / "capstone-managed/audit-path.conf", 4096, 0o444)
    need(data == pointer, "waf_pointer_changed")
    candidates = []
    proxy = []
    entries = list(proc.iterdir())
    need(len(entries) <= 32768, "writer_process_budget")
    for path in entries:
        need(time.monotonic() <= deadline, "writer_scan_deadline")
        if not path.name.isdigit():
            continue
        try:
            if (path / "comm").read_text().strip() != "nginx":
                continue
            groups = [row.split(":", 2)[-1] for row in (path / "cgroup").read_text().splitlines()]
            if "/system.slice/docker-" + policy["proxy_container_id"] + ".scope" in groups:
                need(os.readlink(path / "exe") == "/usr/sbin/nginx", "proxy_executable_changed")
                raw, _ = read_config(common, path / "root/etc/nginx/nginx.conf")
                need(hashlib.sha256(raw).hexdigest() == policy["proxy_config_sha256"], "proxy_config_changed")
                fib = (path / "net/fib_trie").read_text()
                need(re.search(r"[|+]-- 172\.18\.0\.3\s*\n\s+/32 host LOCAL", fib), "proxy_endpoint_changed")
                before = (path / "stat").read_text().rsplit(")", 1)[1].split()
                need(len(before) >= 20 and before[0] not in ("Z", "X") and before[19].isdigit(), "proxy_not_live")
                proxy.append({"pid": int(path.name), "start_ticks": int(before[19])})
                continue
            if "/system.slice/docker-" + policy["container_id"] + ".scope" not in groups:
                continue
            need(os.readlink(path / "exe") == "/usr/sbin/nginx", "writer_executable_changed")
            before = (path / "stat").read_text().rsplit(")", 1)[1].split()
            status = dict(row.split(":", 1) for row in (path / "status").read_text().splitlines() if ":" in row)
            need(len(before) >= 20 and before[0] not in ("Z", "X") and before[19].isdigit() and
                 status.get("Uid", "").split() == ["101"] * 4 and
                 status.get("Gid", "").split() == ["101"] * 4, "waf_writer_identity_invalid")
            for name, expected in policy["config_sha256"].items():
                raw, _ = read_config(common, path / ("root" + name))
                need(hashlib.sha256(raw).hexdigest() == expected, "waf_config_changed")
            raw, _ = common["read_fixed"](path / "root/etc/modsecurity.d/modsecurity-override.conf", 65536, owner=None)
            need(hashlib.sha256(raw).hexdigest() == state["source_pins"]["engine_config_sha256"], "waf_engine_changed")
            raw, _ = common["read_fixed"](path / "root/etc/nginx/conf.d/zz-capstone-evidence.conf", 65536, owner=None)
            need(hashlib.sha256(raw).hexdigest() == state["source_pins"]["producer_format_sha256"] and
                 ("v2:" + policy["deployment_binding"] + ":$request_id:$msec:$time_iso8601").encode() in raw,
                 "waf_producer_changed")
            descriptors = list((path / "fd").iterdir())
            need(len(descriptors) <= 1024, "writer_descriptor_budget")
            matched = []
            for descriptor in descriptors:
                try:
                    s = descriptor.stat()
                    if (s.st_dev, s.st_ino) != (state["current"]["device"], state["current"]["inode"]):
                        continue
                    flags = re.search(r"^flags:\s*([0-7]+)$", (path / "fdinfo" / descriptor.name).read_text(), re.M)
                    need(flags is not None and int(flags[1], 8) & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR),
                         "writer_fd_not_writable")
                    matched.append(descriptor.name)
                except FileNotFoundError:
                    continue
            after = (path / "stat").read_text().rsplit(")", 1)[1].split()
            need(matched and after[19] == before[19] and after[0] not in ("Z", "X"), "writer_fd_unconfirmed")
            candidates.append({"pid": int(path.name), "start_ticks": int(before[19]), "fds": sorted(matched)})
        except (FileNotFoundError, ProcessLookupError):
            continue
    need(time.monotonic() <= deadline and 1 <= len(candidates) <= 16 and 1 <= len(proxy) <= 16,
         "waf_writer_or_proxy_unconfirmed")
    return {"waf": sorted(candidates, key=lambda row: row["pid"]), "proxy": sorted(proxy, key=lambda row: row["pid"])}


def read_evidence(ip, now, common):
    need(os.geteuid() == 0 and Path("/etc/machine-id").read_text().strip() == common["MID"], "fixed_A_root_required")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    need(re.fullmatch(r"[0-9a-f]{32}", boot), "boot_id_invalid")
    with common["shared_rotation_lock"]():
        policy, raw, meta = policy_snapshot(common)
        events, provenance = common["_events"](STATE, BASE, common["PINS"], boot,
            sensor_uid=101, sensor_gid=101, engine="modsecurity",
            writer_probe=lambda state: writer_snapshot(state, common, policy),
            parse_line=lambda line: parse_event(line, policy["deployment_binding"]))
        need(common["read_fixed"](POLICY, 16384, 0o600) == (raw, meta), "waf_policy_changed")
        result = validated_evidence(events, ip, now, policy["destination_ip"], policy["destination_ports"])
        provenance["policy_sha256"] = hashlib.sha256(raw).hexdigest()
        result["managed_source"] = provenance
        return result
