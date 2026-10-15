#!/usr/bin/env python3
"""Groot_A: fixed B -> TPNS IPv4/TCP443 exception; default --check is read-only.

Install as /usr/local/sbin/capstone-push-egress.py with the matching timer.
Only CAPSTONE-PUSH and its exact DOCKER-USER jump are changed, atomically using
iptables-restore --noflush. DNS success grants at most one hour; failure never
extends the old kernel UTC deadline. Missing DNS/state starts DROP-only.
The jump precedes CAPSTONE-FWD/ESTABLISHED, so expiry blocks B's outbound packets
too, and a CAPSTONE-FWD rebuild cannot remove the independent jump.
Return packets retain the existing policy; conntrack sessions are not deleted.
DNS IPs can be shared by other HTTPS services: this is not hostname/process
enforcement. TLS hostname validation remains the Mattermost client's duty.
No packages, NAT, routes, global flush or other firewall chains are changed.
--remove deletes only our jump/chain; disable the timer and service drop-in first.
"""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

IPTABLES = "/usr/sbin/iptables"
RESTORE = "/usr/sbin/iptables-restore"
HOST = "push-test.mattermost.com"
CHAIN = "CAPSTONE-PUSH"
PARENT = "DOCKER-USER"
BASE_CHAIN = "CAPSTONE-FWD"
OWNER = "capstone-push-v1"
MAX_IPS = 16
MAX_STALE = 3600
LOCK = "/run/capstone-push-egress.lock"
JUMP = ("-s 10.200.10.10/32 -i ens160 -o ens192 -p tcp -m tcp --dport 443 "
        "-m comment --comment " + OWNER + " -j " + CHAIN)
DROP = "-A " + CHAIN + " -m comment --comment " + OWNER + " -j DROP"


class Failure(Exception):
    pass


def run(argv, data=None, timeout=10):
    try:
        result = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure("command failed or timed out: " + Path(argv[0]).name) from None
    if result.returncode:
        raise Failure("command rejected: " + Path(argv[0]).name)
    return result.stdout


def public_ip(value):
    address = ipaddress.IPv4Address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise Failure("DNS/owned chain contains a non-public IPv4 address")
    return str(address)


def resolve():
    code = ("import json,socket; print(json.dumps(sorted({r[4][0] for r in "
            "socket.getaddrinfo(" + repr(HOST) + ",443,socket.AF_INET,socket.SOCK_STREAM)})))")
    values = json.loads(run(["/usr/bin/python3", "-B", "-c", code], timeout=8))
    addresses = sorted({public_ip(value) for value in values})
    if not 1 <= len(addresses) <= MAX_IPS:
        raise Failure("DNS answer count is outside the fixed limit")
    return addresses


def arguments(tokens):
    fields, modules = {}, []
    if len(tokens) % 2:
        raise Failure("unexpected rule syntax in owned firewall scope")
    for key, value in zip(tokens[::2], tokens[1::2]):
        if key == "-m":
            modules.append(value)
        elif key in fields:
            raise Failure("duplicate option in owned firewall scope")
        else:
            fields[key] = ",".join(sorted(value.split(","))) if key == "--ctstate" else value
    return fields, sorted(modules)


def snapshot():
    lines = [shlex.split(line) for line in run([IPTABLES, "-w", "5", "-S"]).splitlines()]
    if (["-P", "FORWARD", "DROP"] not in lines or ["-N", PARENT] not in lines
            or ["-N", BASE_CHAIN] not in lines):
        raise Failure("expected FORWARD DROP / CAPSTONE-FWD policy is absent")
    if ["-A", PARENT, "-j", BASE_CHAIN] not in lines:
        raise Failure("existing DOCKER-USER -> CAPSTONE-FWD jump is absent")
    rules, jumps, unrelated = [], [], []
    exists = ["-N", CHAIN] in lines
    for tokens in lines:
        if tokens == ["-N", CHAIN]:
            continue
        if tokens[:2] == ["-A", CHAIN]:
            rules.append(tokens)
            continue
        targets_ours = any(tokens[i] in ("-j", "-g") and tokens[i + 1] == CHAIN
                           for i in range(len(tokens) - 1))
        if targets_ours:
            if tokens[:2] != ["-A", PARENT] or arguments(tokens[2:]) != arguments(shlex.split(JUMP)):
                raise Failure("unexpected reference to CAPSTONE-PUSH; refusing changes")
            jumps.append(tokens)
        else:
            unrelated.append(tokens)
    if len(jumps) > 1 or (jumps and not exists):
        raise Failure("duplicate or inconsistent owned jump")
    if exists:
        validate_rules(rules)
    return {"lines": lines, "rules": rules, "jumps": jumps, "unrelated": unrelated, "exists": exists}


def validate_rules(rules):
    if not rules or arguments(rules[-1][2:]) != arguments(shlex.split(DROP)[2:]):
        raise Failure("owned chain lacks its exact final DROP")
    if len(rules) > MAX_IPS + 1:
        raise Failure("owned chain exceeds the rule limit")
    seen, dates = set(), set()
    for tokens in rules[:-1]:
        fields, modules = arguments(tokens[2:])
        expected = {"-d", "-p", "--dport", "--ctstate", "--datestop", "--comment", "-j"}
        if (set(fields) != expected or modules != ["comment", "conntrack", "tcp", "time"]
                or fields["-p"] != "tcp" or fields["--dport"] != "443"
                or set(fields["--ctstate"].split(",")) != {"NEW", "ESTABLISHED"}
                or fields["--comment"] != OWNER or fields["-j"] != "ACCEPT"):
            raise Failure("unrecognized CAPSTONE-PUSH rule; refusing overwrite")
        destination = fields["-d"]
        if not destination.endswith("/32"):
            raise Failure("owned destination is not a single IPv4 host")
        address = public_ip(destination[:-3])
        if address in seen:
            raise Failure("duplicate owned destination")
        seen.add(address)
        expiry = datetime.strptime(fields["--datestop"], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        if expiry.timestamp() > time.time() + MAX_STALE + 30:
            raise Failure("owned rule deadline exceeds the maximum stale interval")
        dates.add(expiry)
    if len(dates) > 1:
        raise Failure("owned rules have inconsistent expiry times")


def fresh_rules(addresses):
    # xt_time uses UTC by default. Do not use --kerneltz even on this KST host.
    expiry = datetime.fromtimestamp(time.time() + MAX_STALE - 1, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    rules = [shlex.split("-A " + CHAIN + " -d " + address + "/32 -p tcp -m tcp --dport 443 "
                        "-m conntrack --ctstate NEW,ESTABLISHED -m time --datestop " + expiry
                        + " -m comment --comment " + OWNER + " -j ACCEPT") for address in addresses]
    return rules + [shlex.split(DROP)]


def transaction(before, rules, remove=False):
    lines = ["*filter"]
    if not remove:
        lines.extend((":" + CHAIN + " - [0:0]", "-F " + CHAIN))
        lines.extend(shlex.join(tokens) for tokens in rules)
    lines.extend(shlex.join(["-D"] + tokens[1:]) for tokens in before["jumps"])
    if remove:
        if before["exists"]:
            lines.extend(("-F " + CHAIN, "-X " + CHAIN))
    else:
        lines.append("-I " + PARENT + " 1 " + JUMP)
    return "\n".join(lines + ["COMMIT", ""])


def apply_and_verify(before, rules, remove):
    payload = transaction(before, rules, remove)
    run([RESTORE, "--wait", "5", "--noflush", "--test"], payload)
    if snapshot() != before:
        raise Failure("firewall changed during preparation; rerun instead of overwriting")
    run([RESTORE, "--wait", "5", "--noflush"], payload)
    after = snapshot()
    if after["unrelated"] != before["unrelated"]:
        raise Failure("unrelated filter rules changed concurrently; no global restore attempted")
    if remove:
        if after["exists"] or after["jumps"]:
            raise Failure("owned firewall removal read-back failed")
    else:
        parent_rules = [line for line in after["lines"] if line[:2] == ["-A", PARENT]]
        if not after["jumps"] or parent_rules[0] != after["jumps"][0]:
            raise Failure("owned jump is not ahead of ESTABLISHED")
        if [arguments(row[2:]) for row in after["rules"]] != [arguments(row[2:]) for row in rules]:
            raise Failure("owned firewall read-back does not match the atomic update")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="read-only policy/DNS/restore syntax check (default)")
    modes.add_argument("--apply", action="store_true", help="refresh the isolated exception; DNS failure never renews expiry")
    modes.add_argument("--remove", action="store_true", help="remove only our jump and chain; disable timer/drop-in first")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise Failure("run on Groot_A as root")
    if any(not os.access(path, os.X_OK) for path in (IPTABLES, RESTORE, "/usr/bin/python3")):
        raise Failure("existing iptables/iptables-restore/python3 are required")
    if "--datestop" not in run([IPTABLES, "-m", "time", "--help"]):
        raise Failure("xt_time support is required; no broader fallback is allowed")
    mutating = args.apply or args.remove
    lock = os.fdopen(os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600), "w") if mutating else nullcontext()
    with lock as stream:
        if mutating:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot()
        if args.remove:
            apply_and_verify(before, [], True)
            print("REMOVED: only the fixed B TCP443 jump and CAPSTONE-PUSH")
            return
        try:
            addresses = resolve()
            rules = fresh_rules(addresses)
            result = "DNS refreshed; " + str(len(addresses)) + " public IPv4 destinations; maximum stale 1 hour"
        except Exception as error:
            if not args.apply:
                raise Failure("DNS readiness failed: " + type(error).__name__) from None
            rules = before["rules"] if before["exists"] else [shlex.split(DROP)]
            result = "DNS failed; existing kernel deadline unchanged" if before["exists"] else "DNS failed; DROP-only policy installed"
        if args.apply:
            apply_and_verify(before, rules, False)
            print("APPLIED: " + result + "; unrelated filter rules unchanged")
        else:
            run([RESTORE, "--wait", "5", "--noflush", "--test"], transaction(before, rules))
            print("CHECK: " + result + "; syntax passed; firewall unchanged")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("ERROR: " + (str(error) if isinstance(error, Failure) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
