#!/usr/bin/python3
"""Execute the probe's exact jq filter against nine synthetic metadata cases."""
import copy
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit(64)
source = Path(sys.argv[1]).resolve()
original = source.read_bytes()
program = re.search(r"jq -sce --arg binding.*?\n(.*?)\n  ' \"\$PROBE/appended.jsonl\"", original.decode(), re.S).group(1)
epoch = int(datetime.datetime(2026, 10, 15, tzinfo=datetime.timezone.utc).timestamp() * 1000) + 123
binding = 'a' * 64
row = {'transaction': {'request': {'method': 'POST', 'uri': '/50x.html'}, 'response': {'http_code': 405},
       'client_ip': '127.0.0.1', 'client_port': 54321, 'host_ip': '127.0.0.1', 'host_port': 8080, 'messages': [],
       'unique_id': f'v2:{binding}:{"b" * 32}:{epoch // 1000}.123:2026-10-15T00:00:00+00:00'}}
cases = [('utc', [copy.deepcopy(row)], True)]
kst = copy.deepcopy(row)
kst['transaction']['unique_id'] = kst['transaction']['unique_id'].replace('T00:00:00+00:00', 'T09:00:00+09:00')
cases.append(('kst', [kst], True))
other = copy.deepcopy(row)
other['transaction']['client_port'] = 54322
cases.append(('natural_other_row', [other, copy.deepcopy(row)], True))
for name, mutate in [
    ('wrong_binding', lambda r: r['transaction'].__setitem__('unique_id', r['transaction']['unique_id'].replace(binding, 'c' * 64))),
    ('nonempty_messages', lambda r: r['transaction'].__setitem__('messages', [{}])),
    ('wrong_status', lambda r: r['transaction']['response'].__setitem__('http_code', 400)),
    ('clock_offset_mismatch', lambda r: r['transaction'].__setitem__('unique_id', r['transaction']['unique_id'].replace('+00:00', '+09:00'))),
    ('wrong_port', lambda r: r['transaction'].__setitem__('client_port', 54320)),
]:
    value = copy.deepcopy(row)
    mutate(value)
    cases.append((name, [value], False))
cases.append(('duplicate_matching_port', [row, row], False))
for name, rows, wanted in cases:
    result = subprocess.run(['/usr/bin/jq', '-sce', '--arg', 'binding', binding, '--argjson', 'port', '54321',
                             '--argjson', 'start', str(epoch - 200), '--argjson', 'end', str(epoch + 200), program],
                            input=''.join(json.dumps(x) + '\n' for x in rows).encode(), capture_output=True, timeout=5)
    assert (result.returncode == 0) == wanted, (name, result.returncode)
    if wanted:
        value = json.loads(result.stdout)
        assert value['matched_rows'] == 1 and value['total_appended_rows'] == len(rows) and value['iso_epoch_verified']
assert source.read_bytes() == original
print(json.dumps({'suite': 'benign_audit_actual_jq', 'passed': len(cases), 'production_access': False,
                  'source_sha256': hashlib.sha256(original).hexdigest()}))
