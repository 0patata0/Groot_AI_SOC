#!/usr/bin/env python3
"""Replay the complete current application campaign on an immutable source copy.

Use existing Python/dependencies only. This invokes the prior27 profile
commands and the five current identity/controller/preparation profiles. Six
profiles retain their parent suites through the declared contract adapter.
Python socket connections are denied in each child. This is not live model,
MCP, deployment, latency or independent incident-quality acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(root):
    files = {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), 'source_symlink'
        if path.is_file():
            files[str(path.relative_to(root))] = sha(path.read_bytes())
        else:
            assert path.is_dir(), 'source_file_kind'
    return files


def profiles(environment):
    rows = json.loads((HERE / 'regressions.json').read_text())['groups']
    assert len(rows) == 27
    replacements = json.loads((HERE / 'current-application-contracts.json').read_text())['groups']
    for row in rows:
        if row['group'] in replacements:
            row['command'] = {'kind': 'script', 'origin': 'artifact', 'path': 'test_current_application.py'}
        if row['group'] in ('common-new', 'root'):
            row['mac_tests'] += 1
            row['hermes_tests'] += 1
        # The immutable parent27 census predates added cases already in
        # the current source. Their counts are fixed here, not inferred as a
        # passing result after execution.
        counts = {'sdk': 107, 'workflow': 14, 'sdk-flow': 68, 'installation': 38,
                  'common-service-mac': 65 if environment == 'mac' else 152,
                  'new-factual': 31, 'diagnostic-core': 51}
        if row['group'] in counts:
            row[environment + '_tests'] = counts[row['group']]
    rows += [
        {'group': 'current-native-identity', 'cwd': 'infra/hermes',
         'command': {'kind': 'unittest', 'arguments': ['test_native_service_identity']}, 'mac_tests': 7, 'hermes_tests': 7},
        {'group': 'current-sdk-identity', 'cwd': 'infra/ollama-trial',
         'command': {'kind': 'unittest', 'arguments': ['test_service_identity_scope', 'test_service_current_scope', 'test_service_report_provenance']},
         'mac_tests': 55, 'hermes_tests': 55},
        {'group': 'current-controller', 'cwd': 'infra/hermes',
         'command': {'kind': 'unittest', 'arguments': ['test_soc_management_controller', 'test_controller_busy', 'test_peer_text_schema', 'test_review_execution_control']},
         'mac_tests': 139, 'hermes_tests': 139},
        {'group': 'deployment-gate-binding', 'cwd': 'deployment',
         'command': {'kind': 'unittest', 'arguments': ['tests.test_soc_management']}, 'mac_tests': 49, 'hermes_tests': 49},
        {'group': 'payload-producer', 'cwd': '.',
         'command': {'kind': 'script', 'origin': 'root', 'path': 'infra/validation/journal-composition/test_prepare_payload.py'},
         'mac_tests': 6, 'hermes_tests': 6},
    ]
    assert len(rows) == len({row['group'] for row in rows}) == 32
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--comparison', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--environment', choices=('mac', 'hermes'), required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--job', help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.root.resolve();comparison = args.comparison.resolve()
    manifest = json.loads(args.source_manifest.read_text())
    assert manifest['schema'] == 1 and re.fullmatch('[0-9a-f]{40}', manifest['source_commit'])
    rows = profiles(args.environment)
    if args.job:
        selected = [row for row in rows if row['group'] == args.job]
        assert len(selected) == 1
        os.environ['SOC_CURRENT_REPLAY_GROUP'] = args.job
        spec = importlib.util.spec_from_file_location('operating_profile_child', HERE / 'run_regressions.py')
        helper = importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        helper.child(args, selected[0])
        raise AssertionError('profile_did_not_terminate')
    assert args.output is not None
    assert identity(root) == manifest['files'], 'source_manifest_changed'
    for name, expected in manifest['comparison_sources_sha256'].items():
        path = comparison / name
        assert not path.is_symlink() and sha(path.read_bytes()) == expected, 'comparison_source_changed'
    out = args.output.resolve()
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(root), 'output_scope'
    out.mkdir(mode=0o700)
    results = []
    for profile in rows:
        label = profile['group'];started = time.monotonic()
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--root', str(root),
                   '--comparison', str(comparison), '--source-manifest', str(args.source_manifest.resolve()),
                   '--environment', args.environment, '--job', label]
        try:
            process = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=90,
                                     env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            stdout, stderr, rc = process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, rc = exc.stdout or b'', exc.stderr or b'', 124
        assert len(stdout) <= 2097152 and len(stderr) <= 2097152, 'profile_output_bound'
        (out / (label + '.stdout')).write_bytes(stdout)
        (out / (label + '.stderr')).write_bytes(stderr)
        text = stderr.decode(errors='replace')
        count = re.search(r'Ran ([0-9]+) tests?', text);skip = re.search(r'skipped=([0-9]+)', text)
        tests = int(count[1]) if count else None;skipped = int(skip[1]) if skip else 0
        allowed = {'root': 6, 'current-controller': 4}.get(label, 0) if args.environment == 'mac' else 0
        row = {'group': label, 'rc': rc, 'tests': tests, 'expected_tests': profile[args.environment + '_tests'],
               'skipped': skipped, 'allowed_dependency_skips': allowed,
               'passed': rc == 0 and tests == profile[args.environment + '_tests'] and skipped <= allowed,
               'seconds': round(time.monotonic() - started, 3)}
        results.append(row)
        (out / 'progress.json').write_text(json.dumps({'state': 'running', 'groups': results}, indent=2) + '\n')
        print(json.dumps(row), flush=True)
    assert identity(root) == manifest['files'], 'source_changed_during_replay'
    report = {'schema': 1, 'environment': args.environment, 'groups': results,
              'complete': all(row['passed'] for row in results),
              'tests': sum(row['tests'] or 0 for row in results), 'skipped': sum(row['skipped'] for row in results),
              'source_manifest_sha256': sha(args.source_manifest.read_bytes()),
              'runner_sha256': sha(Path(__file__).read_bytes()),
              'contract_adapter_sha256': sha((HERE / 'test_current_application.py').read_bytes()),
              'contract_registry_sha256': sha((HERE / 'current-application-contracts.json').read_bytes()),
              'candidate_sources_unchanged': True, 'socket_connections_denied': True,
              'operating_changes': 0, 'model_calls': 0, 'live_MCP_calls': 0,
              'scope': '32 current-source regression profiles with immutable parent assertions and explicit current-contract replacements; not live operating or model-quality acceptance'}
    (out / 'results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'groups'}), flush=True)
    raise SystemExit(0 if report['complete'] else 1)


if __name__ == '__main__':
    main()
