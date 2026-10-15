#!/usr/bin/python3
"""Private path substitution only; the first body Docker command is a stub."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if len(sys.argv) != 3:
    raise SystemExit(64)
source, temp_root = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
new = source.read_bytes()
begin, end = b'# BEGIN managed-raw legacy gate\n', b'# END managed-raw legacy gate\n'
assert new.count(begin) == new.count(end) == 1
prefix, rest = new.split(begin)
block, suffix = rest.split(end)
old = prefix + suffix
assert hashlib.sha256(old).hexdigest() == '5db09428171a3605f03b3b0681f2ef4637953ba91edf9b1abf0574ba974377fa'
assert b'set -euo pipefail\n' == prefix[-len(b'set -euo pipefail\n'):]
results = []
with tempfile.TemporaryDirectory(prefix='secstack-legacy-guard-', dir=temp_root) as raw:
    base = Path(raw)
    rawstate, rebind = base / 'raw-state', base / 'rebind'
    child = base / 'candidate.sh'
    child.write_bytes(new.replace(b'/var/lib/capstone-raw-operations', os.fsencode(rawstate)).replace(
        b'/var/backups/capstone-waf-recreation-20261015/rebind', os.fsencode(rebind)))
    stub = base / 'bash-env'
    stub.write_text("docker() { printf '%s\\n' PRIVATE_BODY_DOCKER_STUB >&2; return 97; }\n")
    cases = [('raw_regular', rawstate, 'file'), ('raw_dangling', rawstate, 'link'),
             ('rebind_directory', rebind, 'dir'), ('rebind_dangling', rebind, 'link'),
             ('absent_reaches_body_stub', None, None)]
    for name, target, kind in cases:
        if kind == 'file': target.write_text('fixture\n')
        elif kind == 'dir': target.mkdir()
        elif kind == 'link': target.symlink_to(base / 'missing')
        result = subprocess.run(['/bin/bash', str(child)], env={
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'BASH_ENV': str(stub)},
            capture_output=True, timeout=5)
        body = b'PRIVATE_BODY_DOCKER_STUB' in result.stderr
        assert (result.returncode == 78 and not body) if target else (result.returncode == 1 and body)
        results.append({'case': name, 'exit': result.returncode, 'body_stub_reached': body})
        if kind == 'dir': target.rmdir()
        elif target: target.unlink()
assert source.read_bytes() == new
print(json.dumps({'suite': 'secstack_legacy_guard', 'passed': len(results), 'cases': results,
                  'original_body_byte_identical': True, 'production_access': False,
                  'private_fixture_removed': True, 'before_sha256': hashlib.sha256(old).hexdigest(),
                  'after_sha256': hashlib.sha256(new).hexdigest()}))
