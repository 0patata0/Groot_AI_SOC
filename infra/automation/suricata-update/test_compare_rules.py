#!/usr/bin/env python3
"""Local pure oracle regressions; no installed updater, Docker or filesystem mutation."""
import json
from pathlib import Path
import sys

from compare_rules import active_map, compare, parser

ROOT = Path(__file__).resolve().parents[3]
worker = (ROOT / "infra/mcp/rule_change_executor.py").read_bytes()
local = (ROOT / "new_rule/GROOT_A_local.rules").read_bytes()
env = parser(worker)

# Reconstruct only the two public ET fixture originals from their approved
# overrides. This is a pure comparator test, not a vendor feed fixture.
vendor = []
for line, single in env["_suricata_lines"](local):
    rule = env["_suricata_rule"](line, single)
    sid, _ = env["_suricata_number"](rule, b"sid")
    if sid not in (2034802, 2034806):
        continue
    revision, rev = env["_suricata_number"](rule, b"rev")
    line = line[:rev[3]] + str(revision - 1).encode() + line[rev[4]:]
    line = line.replace(b"flowbits:isnotset,groot_llm_api; ", b"", 1)
    vendor.append(line)
et = b"\n".join(vendor) + b"\n"
combined = et + local
generated = b"\n".join(line for line, _ in env["_suricata_lines"](local)) + b"\n"


def same(output):
    assert compare(et, local, combined, output, worker)["active_rule_maps_equal"]


def different(output):
    assert not compare(et, local, combined, output, worker)["active_rule_maps_equal"]


def rejects(function):
    try:
        function()
    except (ValueError, UnicodeError):
        return
    raise AssertionError("expected refusal")


cases = [
    ("approved_pair_high_revision", lambda: same(generated)),
    ("comment_only_difference", lambda: same(b"# offline fixture\n" + generated)),
    ("header_spacing", lambda: same(generated.replace(b"alert tcp ", b"alert  tcp ", 1))),
    ("option_spacing", lambda: same(generated.replace(b"sid:1000000;", b"sid: 1000000 ;", 1))),
    ("missing_marker", lambda: different(b"\n".join(generated.splitlines()[1:]) + b"\n")),
    ("new_sid", lambda: different(generated + b'alert tcp any any -> any any (msg:"extra"; sid:1000099; rev:1;)\n')),
    ("changed_scope", lambda: different(generated.replace(b"192.168.16.230", b"192.168.16.231", 1))),
    ("changed_quoted_value", lambda: different(generated.replace(b"transport marker", b"transport  marker", 1))),
    ("missing_guard", lambda: different(generated.replace(b"flowbits:isnotset,groot_llm_api; ", b"", 1))),
    ("changed_revision", lambda: different(generated.replace(b"sid:1000000; rev:2;", b"sid:1000000; rev:3;", 1))),
    ("output_duplicate", lambda: rejects(lambda: same(generated + generated.splitlines()[0] + b"\n"))),
    ("non_rule_payload", lambda: rejects(lambda: same(generated + b"unknown text\n"))),
    ("bad_utf8", lambda: rejects(lambda: same(generated + b"# \xff\n"))),
    ("NUL", lambda: rejects(lambda: same(generated + b"\0"))),
    ("CRLF", lambda: rejects(lambda: same(generated.replace(b"\n", b"\r\n")))),
    ("different_worker", lambda: rejects(lambda: compare(et, local, combined, generated, worker + b"\n"))),
    ("concat_contract", lambda: rejects(lambda: compare(et, local, combined + b"\n", generated, worker))),
    ("equal_revision_ambiguity", lambda: rejects(lambda: active_map(vendor[0] + b"\n" + vendor[0] + b"\n", env, True))),
    ("ordinary_duplicate", lambda: rejects(lambda: active_map(generated + generated.splitlines()[0] + b"\n", env, True))),
    ("unterminated_continuation", lambda: rejects(lambda: same(generated + b"alert tcp \\"))),
]
failures = []
for name, test in cases:
    try:
        test()
    except Exception as error:
        failures.append({"case": name, "type": type(error).__name__})
print(json.dumps({"tests": len(cases), "passed": len(cases) - len(failures),
                  "failed": failures, "native_updater_executed": False,
                  "operating_files_accessed": False}, sort_keys=True))
sys.exit(bool(failures))
