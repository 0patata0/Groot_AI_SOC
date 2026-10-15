#!/usr/bin/python3 -I
"""Stateless native Wazuh adapter. Existing containment owns every action.

No shell, arbitrary operation/argument/path, firewall command, sudo, approval
token, delete command or independent retry. Never print the alert or source IP.
"""
from datetime import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

MID = "096e90b6243e438aa8a7b392be754732"
HELPER = Path("/usr/local/sbin/rule-change-executor")
PROGRAM = "/var/ossec/active-response/bin/capstone-containment"
LOCATION = "/home/groot_a/capstone/secstack/logs/suricata/eve.json"
MAX_INPUT = 64 * 1024
PROTECTED = tuple(ipaddress.ip_network(x) for x in (
    "211.170.162.0/24", "168.126.63.1/32", "168.126.63.2/32", "8.8.8.8/32",
    "8.8.4.4/32", "1.1.1.1/32", "1.0.0.1/32", "9.9.9.9/32"))


class Refused(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def request(raw, now):
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_INPUT and raw.endswith(b"\n") and
         raw.count(b"\n") == 1 and b"\0" not in raw, "input_bounds")
    try:
        obj = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Refused("invalid_json") from None
    need(type(obj) is dict and set(obj) == {"version", "origin", "command", "parameters"} and
         type(obj["version"]) is int and obj["version"] == 1 and obj["command"] == "add", "add_only")
    origin, parameters = obj["origin"], obj["parameters"]
    need(type(origin) is dict and set(origin) == {"name", "module"} and
         origin["module"] == "wazuh-execd" and isinstance(origin["name"], str) and
         re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", origin["name"]), "native_origin")
    need(type(parameters) is dict and set(parameters) == {"extra_args", "alert", "program"} and
         parameters["extra_args"] == [] and parameters["program"] == PROGRAM, "fixed_program")
    alert = parameters["alert"]
    need(type(alert) is dict and type(alert.get("rule")) is dict and
         type(alert.get("agent")) is dict and type(alert.get("data")) is dict, "alert_shape")
    need(alert["agent"].get("id") == "001" and alert["rule"].get("id") == "100110" and
         type(alert["rule"].get("level")) is int and alert["rule"]["level"] == 9 and
         alert.get("location") == LOCATION, "fixed_agent_rule_location")
    value = alert.get("timestamp")
    try:
        need(isinstance(value, str) and len(value) <= 40, "timestamp_shape")
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        need(dt.tzinfo is not None and now - 300 <= dt.timestamp() <= now + 2, "stale_alert")
    except (ValueError, OverflowError):
        raise Refused("timestamp_invalid_or_stale") from None
    data = alert["data"]
    need(data.get("event_type") == "alert" and type(data.get("alert")) is dict and
         (data["alert"].get("severity") == "1" or
          (type(data["alert"].get("severity")) is int and data["alert"]["severity"] == 1)), "suricata_severity")
    source = data.get("src_ip")
    try:
        need(isinstance(source, str), "source_type")
        ip = ipaddress.IPv4Address(source)
    except (ValueError, ipaddress.AddressValueError):
        raise Refused("public_ipv4_required") from None
    need(str(ip) == source and ip.is_global and not ip.is_multicast and not ip.is_reserved and
         not any(ip in network for network in PROTECTED), "protected_or_nonpublic_source")
    # The alert is only a wake-up hint. The existing helper independently reads
    # fixed managed sensor bytes and applies its unchanged 3-flow policy.
    return {"operation": "contain-ip", "ip": source,
            "reason": "Wazuh native rule 100110 agent 001; independently verify fixed sensor evidence"}


def helper_metadata():
    for path in (HELPER.parent, *HELPER.parent.parents):
        s = path.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not stat.S_IMODE(s.st_mode) & 0o022,
             "helper_directory")
    s = HELPER.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
         not stat.S_IMODE(s.st_mode) & 0o022 and stat.S_IMODE(s.st_mode) & 0o100 and
         0 < s.st_size <= 256 * 1024, "helper_metadata")


def dispatch(payload):
    helper_metadata()
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    proc = subprocess.Popen([str(HELPER)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True,
                            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                 "LC_ALL": "C.UTF-8", "TZ": "Asia/Seoul", "PYTHONDONTWRITEBYTECODE": "1"})
    completed = False
    try:
        proc.stdin.write(data); proc.stdin.close()
        deadline = time.monotonic() + 360
        while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            need(time.monotonic() < deadline, "helper_timeout_outcome_unknown")
            time.sleep(0.05)
        # WNOWAIT has already observed the direct child exit. Mark before reap,
        # so a delivered signal cannot cause killpg of a reused leader PID.
        completed = True
        code = proc.wait(timeout=3)
        return {"status": "existing_helper_returned", "helper_exit_code": code,
                "automatic_retry": False, "native_delete_supported": False}, 0 if code == 0 else 75
    finally:
        if not completed:
            # The child has not been reaped: its PGID cannot be reassigned here.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass


def interrupted(_sig, _frame):
    raise Refused("interrupted_outcome_unknown")


def main():
    need(sys.platform == "linux" and os.geteuid() == 0 and len(sys.argv) == 1, "fixed_linux_root_cli")
    need(Path("/etc/machine-id").read_text().strip() == MID, "fixed_A_required")
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(3)
    raw = sys.stdin.buffer.readline(MAX_INPUT + 1)
    signal.alarm(0)
    payload = request(raw, time.time())
    result, code = dispatch(payload)
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Refused, OSError, ValueError, KeyError, TypeError) as exc:
        code = str(exc) if isinstance(exc, Refused) else type(exc).__name__
        print(json.dumps({"status": "refused_or_outcome_unknown", "reason": code, "automatic_retry": False}))
        sys.exit(75)
