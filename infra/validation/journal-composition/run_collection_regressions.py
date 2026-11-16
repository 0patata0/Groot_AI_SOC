#!/usr/bin/env python3
"""Run the unchanged composition profiles plus collection-specific fixtures."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import runpy
import socket
import subprocess
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixed_collection_replay', HERE / 'reproduce_collection.py')
replay = importlib.util.module_from_spec(spec); spec.loader.exec_module(replay)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--comparison', type=Path, required=True)
    parser.add_argument('--environment', choices=('mac', 'hermes'), required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--job', help=argparse.SUPPRESS)
    args = parser.parse_args()
    root, comparison = args.root.resolve(), args.comparison.resolve()
    frozen = json.loads((HERE / 'collection-manifest.json').read_text())
    original = json.loads((HERE / 'manifest.json').read_text())
    assert replay.sha(HERE / 'manifest.json') == frozen['composition_manifest_sha256']
    for name, digest in frozen['tests_sha256'].items():
        assert replay.sha(HERE / name) == digest, name
    for name in ('regressions.json', 'run_regressions.py'):
        assert replay.sha(HERE / name) == original['tests_sha256'][name], name
    profiles = json.loads((HERE / 'regressions.json').read_text())['groups']
    profiles.append({'group': 'native-collection', 'mac_tests': frozen['new_tests'], 'hermes_tests': frozen['new_tests']})
    assert len({p['group'] for p in profiles}) == len(profiles) == 28
    if args.job:
        selected = [p for p in profiles if p['group'] == args.job]
        assert len(selected) == 1
        old_spec = importlib.util.spec_from_file_location('fixed_composition_regressions', HERE / 'run_regressions.py')
        old = importlib.util.module_from_spec(old_spec); old_spec.loader.exec_module(old)
        if args.job != 'native-collection':
            old.child(args, selected[0])
            return
        old.environment(root, comparison)
        os.environ['SOC_JOURNAL_COLLECTION_ROOT'] = str(root)
        def deny(*unused, **kwargs):
            raise AssertionError('isolated_regression_socket_connect_denied')
        socket.socket.connect = deny; socket.socket.connect_ex = deny; socket.create_connection = deny
        sys.argv = [str(HERE / 'test_collection.py')]
        runpy.run_path(str(HERE / 'test_collection.py'), run_name='__main__')
        return
    expected_identity = (frozen['candidate_tree_file_count'], frozen['candidate_tree_sha256'])
    assert replay.identity(root) == expected_identity
    for name, info in original['comparison_sources'].items():
        assert replay.sha(comparison / name) == info['comparison_sha256'], name
    assert args.output is not None
    out = args.output.resolve()
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(root) and not out.is_relative_to(HERE.parents[2])
    out.mkdir(mode=0o700); rows = []
    for profile in profiles:
        label = profile['group']; start = time.monotonic()
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--root', str(root), '--comparison', str(comparison), '--environment', args.environment, '--job', label]
        proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        assert len(proc.stdout.encode()) <= 2097152 and len(proc.stderr.encode()) <= 2097152
        (out / (label + '.stdout')).write_text(proc.stdout); (out / (label + '.stderr')).write_text(proc.stderr)
        count = re.search(r'Ran ([0-9]+) tests?', proc.stderr); skips = re.search(r'skipped=([0-9]+)', proc.stderr)
        tests = int(count[1]) if count else None; skipped = int(skips[1]) if skips else 0
        allowed = 6 if args.environment == 'mac' and label == 'root' else 0
        passed = proc.returncode == 0 and tests == profile[args.environment + '_tests'] and skipped <= allowed
        rows.append({'group': label, 'rc': proc.returncode, 'tests': tests, 'skipped': skipped, 'passed': passed, 'seconds': round(time.monotonic() - start, 3)})
        print(json.dumps(rows[-1]), flush=True)
        if not passed:
            break
    complete = len(rows) == len(profiles) and all(r['passed'] for r in rows)
    assert replay.identity(root) == expected_identity
    report = {'environment': args.environment, 'complete': complete, 'groups': rows, 'tests': sum(r['tests'] or 0 for r in rows), 'skipped': sum(r['skipped'] for r in rows), 'model_calls': 0, 'operating_changes': 0, 'scope': 'Frozen-source regression executions, not independent SOC incidents or operating acceptance'}
    (out / 'results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    raise SystemExit(0 if complete else 1)


if __name__ == '__main__':
    main()
