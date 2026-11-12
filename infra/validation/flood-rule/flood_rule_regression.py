#!/usr/bin/env python3
"""Synthetic regression for the dedicated volumetric-flood Wazuh rule 100113.

No network transmission, training or alert injection. `generate` prints the
cases. `native` runs inside a Wazuh manager container (production for the
read-only 'before' baseline, or an isolated network-none copy for 'candidate')
using Wazuh's own pinned logtest client; every logtest session is removed.
stdin for `native`: {"engine": "before"|"candidate", "cases": [...]}.
"""
import json
import sys

LOCATION = "/home/groot_a/capstone/secstack/logs/suricata/eve.json"


def eve(sid, sev, src, dport=None, proto="ICMP", sig=None, cat="Attempted Denial of Service"):
    e = {"timestamp": "2026-11-13T00:00:00.000000+0000", "event_type": "alert", "src_ip": src,
         "dest_ip": "192.168.16.230", "proto": proto,
         "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1,
                   "signature": sig or ("GROOT-LOCAL flood test SID %d" % sid), "category": cat, "severity": sev}}
    if dport is not None:
        e.update(src_port=40001, dest_port=dport)
    return json.dumps(e, separators=(",", ":"))


ICMP = lambda src="192.168.16.233", sev=2: eve(1000090, sev, src)
SYN = lambda src="192.168.16.232": eve(1000091, 2, src, 80, "TCP")

MED = lambda src="192.168.16.233": eve(2034806, 2, src, 80, "TCP", cat="Potentially Bad Traffic")

# final: expected rule id of the LAST event; burst_at: 1-based positions that hit 100112;
# ids (optional): exact rule id per event. 100113 must be defined BEFORE 100112: Wazuh
# links the if_matched_group burst rule only to group members loaded ahead of it, and
# the first candidate (100113 appended after 100112) silenced the same-source burst.
CASES = [
    {"name": "flood_icmp_single", "logs": [ICMP()],
     "before": {"final": 100111, "burst_at": []}, "candidate": {"final": 100113, "burst_at": [], "level": 10}},
    {"name": "flood_syn_single", "logs": [SYN()],
     "before": {"final": 100111, "burst_at": []}, "candidate": {"final": 100113, "burst_at": [], "level": 10}},
    {"name": "medium_other_sid_unchanged", "logs": [eve(2034806, 2, "192.168.16.233", 80, "TCP", cat="Potentially Bad Traffic")],
     "before": {"final": 100111, "burst_at": []}, "candidate": {"final": 100111, "burst_at": []}},
    {"name": "high_other_sid_unchanged", "logs": [eve(2024792, 1, "192.168.16.233", 80, "TCP", cat="Attempted Administrator Privilege Gain")],
     "before": {"final": 100110, "burst_at": []}, "candidate": {"final": 100110, "burst_at": []}},
    {"name": "near_miss_sid_not_flood", "logs": [eve(1000092, 2, "192.168.16.233")],
     "before": {"final": 100111, "burst_at": []}, "candidate": {"final": 100111, "burst_at": []}},
    {"name": "flood_sid_with_severity1_goes_high", "logs": [ICMP(sev=1)],
     "before": {"final": 100110, "burst_at": []}, "candidate": {"final": 100110, "burst_at": []}},
    {"name": "same_source_flood_burst_still_100112", "logs": [ICMP()] * 8,
     "before": {"final": 100112, "burst_at": [8], "ids": [100111] * 7 + [100112]},
     "candidate": {"final": 100112, "burst_at": [8], "ids": [100113] * 7 + [100112]}},
    {"name": "mixed_same_source_flood_and_other_burst", "logs": [ICMP() if i % 2 else MED() for i in range(8)],
     "before": {"final": 100112, "burst_at": [8], "ids": [100111] * 7 + [100112]},
     "candidate": {"final": 100112, "burst_at": [8], "ids": [100111, 100113] * 3 + [100111, 100112]}},
    {"name": "two_sources_flood_no_per_source_burst",
     "logs": [ICMP("192.168.16.232" if i % 2 else "192.168.16.233") for i in range(8)],
     "before": {"final": 100111, "burst_at": []},
     "candidate": {"final": 100113, "burst_at": [], "ids": [100113] * 8}},
]

NATIVE_CODE = r'''
import json, sys, hashlib, importlib.util, socket
from pathlib import Path
socket.setdefaulttimeout(8)
p = Path('/var/ossec/framework/scripts/wazuh_logtest.py')
assert hashlib.sha256(p.read_bytes()).hexdigest() == '59fb8b25a9315f3007aaea3bd572a8e5098012ca12046617b9615ce367672414'
s = importlib.util.spec_from_file_location('flood_native', p)
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
req = json.loads(sys.stdin.read()); engine = req['engine']
out = []
for row in req['cases']:
    c = m.WazuhLogtest(location=LOCATION, log_format='syslog'); ids = []; levels = []; groups = []; mitre = []; removed = False
    try:
        for log in row['logs']:
            r = c.process_log(log, token=c.last_token)['output']; rule = r.get('rule') or {}
            ids.append(int(rule.get('id', 0))); levels.append(rule.get('level')); groups.append(rule.get('groups'))
            mitre.append(((rule.get('mitre') or {}).get('id')))
    finally:
        if c.last_token:
            removed = c.remove_session(c.last_token)
    exp = row[engine]
    burst = [i + 1 for i, v in enumerate(ids) if v == 100112]
    ok = (ids[-1] == exp['final'] and burst == exp['burst_at'] and ('level' not in exp or levels[-1] == exp['level'])
          and ('ids' not in exp or ids == exp['ids']))
    out.append({'name': row['name'], 'ids': ids, 'last_level': levels[-1], 'last_groups': groups[-1],
                'last_mitre': mitre[-1], 'burst_at': burst, 'pass': ok, 'session_removed': removed})
print(json.dumps({'engine': engine, 'cases': out, 'passed': sum(r['pass'] for r in out), 'count': len(out),
                  'alert_injection': False}))
'''.replace("LOCATION", repr(LOCATION))

if __name__ == "__main__":
    if sys.argv[1:] == ["generate"]:
        print(json.dumps(CASES))
    elif sys.argv[1:] == ["native"]:
        exec(compile(NATIVE_CODE, "<pinned-native-flood-regression>", "exec"))
    else:
        raise SystemExit("usage: flood_rule_regression.py generate|native")
