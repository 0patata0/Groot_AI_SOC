#!/usr/bin/env python3
"""Reuse all pinned collection profiles with bootstrap/CLI completion cases."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('limits_replay', HERE / 'reproduce_limits.py')
replay = importlib.util.module_from_spec(spec); spec.loader.exec_module(replay)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--comparison', type=Path, required=True)
    p.add_argument('--environment', choices=('mac', 'hermes'), required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    root, comparison, out = args.root.resolve(), args.comparison.resolve(), args.output.resolve()
    frozen = json.loads((HERE / 'limits-manifest.json').read_text())
    base = json.loads((HERE / 'collection-manifest.json').read_text())
    original = json.loads((HERE / 'manifest.json').read_text())
    assert replay.collection.sha(HERE / 'collection-manifest.json') == frozen['collection_manifest_sha256']
    for name, digest in frozen['tools_sha256'].items():
        assert replay.collection.sha(HERE / name) == digest, name
    expected = (frozen['candidate_tree_file_count'], frozen['candidate_tree_sha256'])
    assert replay.collection.identity(root) == expected
    for name, value in original['comparison_sources'].items():
        assert replay.collection.sha(comparison / name) == value['comparison_sha256']
    profiles = json.loads((HERE / 'regressions.json').read_text())['groups']
    profiles.append({'group': 'native-collection', 'mac_tests': base['new_tests'], 'hermes_tests': base['new_tests']})
    assert len(profiles) == len({v['group'] for v in profiles}) == 28
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(root) and not out.is_relative_to(HERE.parents[2])
    out.mkdir(mode=0o700)
    rows = []
    for profile in profiles:
        label = profile['group']; start = time.monotonic()
        command = [sys.executable, '-B', str(HERE / 'run_collection_regressions.py'), '--root', str(root),
                   '--comparison', str(comparison), '--environment', args.environment, '--job', label]
        proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
                              env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        assert len(proc.stdout.encode()) <= 2097152 and len(proc.stderr.encode()) <= 2097152
        (out / (label + '.stdout')).write_text(proc.stdout); (out / (label + '.stderr')).write_text(proc.stderr)
        count = re.search(r'Ran ([0-9]+) tests?', proc.stderr); skips = re.search(r'skipped=([0-9]+)', proc.stderr)
        tests = int(count[1]) if count else None; skipped = int(skips[1]) if skips else 0
        target = profile[args.environment + '_tests'] + frozen['additional_tests_by_group'].get(label, 0)
        allowed = 6 if args.environment == 'mac' and label == 'root' else 0
        passed = proc.returncode == 0 and tests == target and skipped <= allowed
        rows.append({'group': label, 'rc': proc.returncode, 'tests': tests, 'expected_tests': target,
                     'skipped': skipped, 'passed': passed, 'seconds': round(time.monotonic() - start, 3)})
        print(json.dumps(rows[-1]), flush=True)
        if not passed: break
    complete = len(rows) == len(profiles) and all(x['passed'] for x in rows)
    assert replay.collection.identity(root) == expected
    report = {'environment': args.environment, 'complete': complete, 'groups': rows,
              'tests': sum(x['tests'] or 0 for x in rows), 'skipped': sum(x['skipped'] for x in rows),
              'model_calls': 0, 'operating_changes': 0, 'scope': 'Frozen source regressions, not independent SOC incidents or operating acceptance'}
    (out / 'results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    raise SystemExit(0 if complete else 1)


if __name__ == '__main__':
    main()
