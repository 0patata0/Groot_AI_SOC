#!/usr/bin/env python3
"""Exercise the production native rollback block against synthetic files only.

No Docker, container, systemd, network, package or real Hermes data access.
Ansible itself runs only in `run`; `prepare` validates the isolated test plan.
The command shim is an explicit test double, not an engine/recreation test.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / 'roles/hermes_guard/tasks/main.yml'
CHECKS = ROOT.parents[1] / 'hermes/hermes_guard_checks.py'
IDENTITY = 'a' * 64
FILES = ('plugins/platforms/mattermost/adapter.py', 'gateway/run_turn.py',
         'capstone_korean_output_guard.py')
IMAGE = 'sha256:2fd023efbb8d3d2b0ce1a73d028b07370cff34f567cfe0e999553e8c327ea283'
NAMES = (
    'Require the reviewed image, command and persistent data mount',
    'Reject any unknown source pair or core',
    'Recheck source and configuration before entering mutation block',
    'Reject concurrent source or configuration changes before mutation',
    'Recheck freshness immediately before stop',
    'Recheck name binding before touching the saved container',
    'Reject concurrent replacement',
    'Deploy candidate with native rollback',
)
CASES = (
    'success', 'missing_core_success', 'unknown_image', 'unknown_source',
    'source_changed', 'busy', 'container_changed', 'copy_failure',
    'copied_hash_mismatch', 'database_drift', 'runtime_failure',
    'missing_core_runtime_failure', 'started_database_progress',
    'started_config_drift', 'rollback_hash_mismatch', 'first_stop_failure',
)
PREFLIGHT_FAILURES = {'unknown_image', 'unknown_source', 'source_changed',
                      'busy', 'container_changed'}
STOPPED_FAILURES = {'database_drift', 'started_config_drift',
                    'rollback_hash_mismatch', 'first_stop_failure'}


def require(value, code):
    if not value:
        raise ValueError(code)


def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def helper():
    spec = importlib.util.spec_from_file_location('fixture_guard_checks', CHECKS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def production_tasks():
    tasks = json.loads(ROLE.read_text())
    selected = [task for task in tasks if task.get('name') in NAMES]
    require(tuple(task['name'] for task in selected) == NAMES, 'task_boundary_changed')
    require(selected[-1].get('block') and selected[-1].get('rescue'), 'rollback_missing')
    return copy.deepcopy(selected)


def confine(path, root):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), 'unsafe_fixture_path')
    resolved = path.resolve()
    require(resolved.is_relative_to(root.resolve()), 'fixture_path_escape')
    return resolved


def rewrite_tasks(tasks, root):
    """Replace external command effects, preserving native decisions and rescue."""
    for task in tasks:
        action = [key for key in task if key.startswith('ansible.builtin.')]
        if 'block' in task:
            require(not action, 'unexpected_block_action')
            rewrite_tasks(task['block'], root)
            rewrite_tasks(task.get('rescue', []), root)
            continue
        require(len(action) == 1, 'unexpected_action')
        name = action[0]
        require(name in {'ansible.builtin.command', 'ansible.builtin.copy',
                         'ansible.builtin.stat', 'ansible.builtin.assert',
                         'ansible.builtin.set_fact', 'ansible.builtin.fail'},
                'unexpected_module')
        if name == 'ansible.builtin.command':
            command = task[name]
            require(set(command) <= {'argv', 'stdin', 'stdin_add_newline'}, 'unexpected_command')
            args = command['argv']
            if args[0] == '/usr/local/bin/docker':
                operation = ['docker', *args[1:]]
                require(args[1] in {'inspect', 'exec', 'cp', 'stop', 'start'}, 'unexpected_docker_operation')
            else:
                require(args[:3] == ['/usr/bin/python3', '-B',
                        '{{ capstone_guard_source_dir }}/hermes_guard_checks.py'], 'unexpected_executable')
                require(len(args) == 4 and args[3] in {'idle', 'snapshot'}, 'unexpected_helper')
                operation = ['helper', args[3]]
            task[name] = {'argv': [sys.executable, '-B', str(Path(__file__).resolve()),
                                  'shim', str(root), *operation]}
            # Only the retry delay is shortened; original until/retries remain.
            if 'delay' in task:
                task['delay'] = 0
        elif name in {'ansible.builtin.copy', 'ansible.builtin.stat'}:
            target = task[name].get('dest', task[name].get('path', ''))
            require(target in {
                '{{ guard_stage.path }}/protected.json',
                '{{ guard_stage.path }}/verify-{{ item | basename }}',
                '{{ guard_stage.path }}/rollback-{{ item | basename }}',
                '{{ guard_stage.path }}/rollback-core.py',
            }, 'unsafe_native_file_target')
            require('src' not in task[name] and 'remote_src' not in task[name], 'unexpected_native_copy')
    return tasks


def prepare(root, case):
    require(case in CASES, 'unknown_case')
    root.mkdir(mode=0o700)
    stage = root / 'stage'
    data = root / 'data'
    tree = root / 'container'
    for p in (stage, data, tree, root / 'tmp'):
        p.mkdir(mode=0o700)
    for name in FILES:
        for base, tag in ((stage / 'original', 'original'),
                          (stage / 'candidate', 'candidate'), (tree, 'original')):
            p = base / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(f'# synthetic {tag}: {name}\n')
    missing = case.startswith('missing_core')
    if missing:
        (tree / FILES[2]).unlink()
        (stage / 'original' / FILES[2]).unlink()
    for name in ('config.yaml', '.env', 'SOUL.md', 'cron/jobs.json'):
        p = data / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('synthetic-only\n')
    with sqlite3.connect(data / 'state.db') as db:
        db.execute('CREATE TABLE session_turn_leases(expires_at REAL)')
        db.execute('CREATE TABLE fixture_progress(value TEXT)')
    dump(data / 'gateway_state.json', {'gateway_state': 'running', 'active_agents':
         1 if case == 'busy' else 0, 'active_work': [], 'updated_at': time.time()})
    checks = helper()
    files = {name: checks.metadata(tree / name, optional=name == FILES[2]) for name in FILES}
    current = {'files': files, 'config': checks.metadata(data / 'config.yaml')}
    source_pairs = [[files[name]['sha256'] for name in FILES[:2]]]
    desired = {name: digest(stage / 'candidate' / name) for name in FILES}
    core_sha = files[FILES[2]].get('sha256', desired[FILES[2]])
    probe = json.dumps(current, sort_keys=True)
    if case == 'unknown_source':
        current = copy.deepcopy(current)
        current['files'][FILES[0]]['sha256'] = 'f' * 64
    container = {'Id': IDENTITY, 'Image': IMAGE, 'State': {'Running': True, 'OOMKilled': False},
                 'Config': {'User': 'root', 'Entrypoint': ['/opt/hermes/docker/entrypoint-dispatch.sh'],
                            'Cmd': ['gateway', 'run']}, 'Mounts': [
                 {'Destination': '/opt/data', 'Source': '/opt/hermes-data', 'Type': 'bind',
                  'RW': True, 'Propagation': 'rprivate'}]}
    if case == 'unknown_image':
        container['Image'] = 'sha256:' + '0' * 64
    state = {'case': case, 'running': True, 'stops': 0, 'starts': 0, 'calls': [],
             'candidate_copies': 0, 'snapshot_calls': 0, 'runtime_calls': 0,
             'missing_core': missing, 'probe': probe}
    dump(root / 'state.json', state)
    dump(root / 'baseline.json', {'protected': checks.snapshot(data), 'files': files})
    tasks = rewrite_tasks(production_tasks(), root)
    variables = {'guard_container': container, 'guard_current': current, 'guard_desired': desired,
                 'capstone_guard_source_pairs': source_pairs, 'capstone_guard_core_sha256': core_sha,
                 'guard_probe': {'stdout': probe}, 'guard_needs_code': True,
                 'guard_stage': {'path': str(stage)}, 'guard_uid': '995:986'}
    play = [{'name': f'Isolated synthetic guard fixture: {case}', 'hosts': 'localhost',
             'connection': 'local', 'gather_facts': False,
             'vars': variables, 'tasks': tasks}]
    dump(root / 'play.json', play)
    return root / 'play.json'


def fixture_copy(root, state, src, dest):
    def translate(value):
        prefix = IDENTITY + ':/opt/hermes/'
        if value.startswith(prefix):
            relative = value[len(prefix):]
            require(relative in FILES, 'unknown_container_file')
            return root / 'container' / relative
        path = confine(value, root / 'stage')
        require(path != root / 'stage', 'invalid_stage_file')
        return path
    source, target = translate(src), translate(dest)
    require(source.is_file() and not source.is_symlink(), 'missing_fixture_file')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    candidate_write = str(source).startswith(str(root / 'stage/candidate') + '/')
    original_write = str(source).startswith(str(root / 'stage/original') + '/')
    case = state['case']
    if candidate_write:
        state['candidate_copies'] += 1
        if state['candidate_copies'] == 1 and case in {'copy_failure', 'rollback_hash_mismatch'}:
            return 1
        if state['candidate_copies'] == 3 and case == 'database_drift':
            with sqlite3.connect(root / 'data/state.db') as db:
                db.execute("INSERT INTO fixture_progress VALUES ('unexpected-before-start')")
    if case == 'copied_hash_mismatch' and target.name == 'verify-adapter.py':
        target.write_text('synthetic wrong copy-back\n')
    if case == 'rollback_hash_mismatch' and original_write and target.name == 'adapter.py':
        target.write_text('synthetic corrupted rollback\n')
    return 0


def shim(root, args):
    root = root.resolve()
    require(root.is_dir() and not root.is_symlink(), 'invalid_fixture_root')
    state_path = root / 'state.json'
    state = json.loads(state_path.read_text())
    case = state['case']
    operation = args[0]
    rc, result = 0, None
    if operation == 'helper':
        require(len(args) == 2 and args[1] in {'snapshot', 'idle'}, 'invalid_helper_operation')
        state['calls'].append('helper:' + args[1])
        if args[1] == 'snapshot':
            state['snapshot_calls'] += 1
            result = helper().snapshot(root / 'data')
        else:
            # Real idle helper checks synthetic SQLite and timestamp files only.
            try:
                result = helper().idle(root / 'data')
            except ValueError:
                rc = 1
    else:
        require(operation == 'docker' and len(args) > 1, 'invalid_fixture_operation')
        command = args[1:]
        state['calls'].append('docker:' + command[0])
        if command[0] == 'inspect':
            require(command == ['inspect', '--format', '{{.Id}}', 'hermes'], 'unknown_inspect')
            result = ('b' * 64 if case == 'container_changed' else IDENTITY)
        elif command[0] == 'stop':
            require(command == ['stop', '-t', '30', IDENTITY], 'unknown_stop')
            state['stops'] += 1
            state['running'] = False
            if case == 'first_stop_failure' and state['stops'] == 1:
                rc = 1
        elif command[0] == 'start':
            require(command == ['start', IDENTITY], 'unknown_start')
            state['starts'] += 1
            state['running'] = True
            if state['starts'] == 1 and case == 'started_database_progress':
                with sqlite3.connect(root / 'data/state.db') as db:
                    db.execute("INSERT INTO fixture_progress VALUES ('synthetic-normal-progress')")
            if state['starts'] == 1 and case == 'started_config_drift':
                (root / 'data/config.yaml').write_text('synthetic configuration drift\n')
        elif command[0] == 'cp':
            require(len(command) == 3, 'unknown_copy')
            rc = fixture_copy(root, state, command[1], command[2])
        else:
            require(command[0] == 'exec' and IDENTITY in command, 'unknown_exec')
            inner = command[command.index(IDENTITY) + 1:]
            require(state['running'], 'exec_while_stopped')
            if inner == ['rm', '-f', '--', '/opt/hermes/capstone_korean_output_guard.py']:
                (root / 'container' / FILES[2]).unlink(missing_ok=True)
            elif len(inner) == 4 and inner[:3] == ['python3', '-B', '-c']:
                if 'm.container()' in inner[3]:
                    result = state['probe'] + (' ' if case == 'source_changed' else '')
                elif 'guard_runtime_verify.py' in inner[3]:
                    state['runtime_calls'] += 1
                    rc = int(case in {'runtime_failure', 'missing_core_runtime_failure',
                                      'started_database_progress', 'started_config_drift'})
                    result = {'synthetic_transport_ok': not bool(rc)}
                else:
                    raise ValueError('unknown_python_exec')
            else:
                raise ValueError('unknown_exec_arguments')
    dump(state_path, state)
    if result is not None:
        print(result if isinstance(result, str) else json.dumps(result, sort_keys=True))
    return rc


def verify(root, returncode):
    state = json.loads((root / 'state.json').read_text())
    baseline = json.loads((root / 'baseline.json').read_text())
    case = state['case']
    success = case in {'success', 'missing_core_success'}
    require((returncode == 0) == success, 'unexpected_ansible_exit')
    require(state['running'] == (case not in STOPPED_FAILURES), 'unexpected_running_state')
    if case in PREFLIGHT_FAILURES:
        require(state['stops'] == state['starts'] == state['candidate_copies'] == 0,
                'preflight_mutated_fixture')
    elif case in STOPPED_FAILURES:
        expected_starts = 1 if case == 'started_config_drift' else 0
        require(state['starts'] == expected_starts, 'unsafe_restart')
    elif success:
        require(state['stops'] == state['starts'] == 1, 'unexpected_success_lifecycle')
    else:
        require(state['stops'] == 2 and state['starts'] >= 1, 'rollback_lifecycle_missing')
    actual_protected = helper().snapshot(root / 'data')
    expected_drift = {'database_drift': {'state.db'}, 'started_database_progress': {'state.db'},
                      'started_config_drift': {'config.yaml'}}.get(case, set())
    changed = {k for k in baseline['protected'] if baseline['protected'][k] != actual_protected[k]}
    require(changed == expected_drift, 'protected_preservation_mismatch')
    for name in FILES:
        actual = root / 'container' / name
        if not success and case != 'rollback_hash_mismatch':
            if not baseline['files'][name]['exists']:
                require(not actual.exists(), 'unused_core_not_removed')
            else:
                require(digest(actual) == baseline['files'][name]['sha256'], 'original_not_restored')
        elif success:
            require(digest(actual) == digest(root / 'stage/candidate' / name), 'candidate_not_installed')
    if case == 'started_database_progress':
        with sqlite3.connect(root / 'data/state.db') as db:
            require(db.execute('SELECT count(*) FROM fixture_progress').fetchone()[0] == 1,
                    'new_database_progress_lost')
    return {'case': case, 'passed': True, 'native_exit': returncode,
            'fixture_stops': state['stops'], 'fixture_starts': state['starts'],
            'fixture_running': state['running'], 'protected_changed': sorted(changed)}


def run(prepare_only=False, chosen=None):
    require(CHECKS.is_file(), 'checks_source_missing')
    results = []
    controller = Path('/opt/capstone-automation/venv/bin/ansible-playbook')
    if not prepare_only:
        require(controller.is_file(), 'native_controller_missing')
    with tempfile.TemporaryDirectory(prefix='hermes-native-fixture-') as temporary:
        suite = Path(temporary)
        config = suite / 'ansible.cfg'
        config.write_text('[defaults]\nretry_files_enabled=False\nstdout_callback=default\n'
                          'interpreter_python=/usr/bin/python3\nlocalhost_warning=False\n'
                          'deprecation_warnings=False\n[connection]\npipelining=True\n')
        for case in chosen or CASES:
            root = suite / case
            play = prepare(root, case)
            if prepare_only:
                results.append({'case': case, 'plan_checked': True})
                continue
            env = {k: v for k, v in os.environ.items() if not k.startswith('ANSIBLE_')}
            env.update(ANSIBLE_CONFIG=str(config), ANSIBLE_LOCAL_TEMP=str(root / 'tmp'),
                       ANSIBLE_REMOTE_TEMP=str(root / 'tmp'), ANSIBLE_NOCOLOR='1',
                       PYTHONDONTWRITEBYTECODE='1')
            completed = subprocess.run([str(controller), '-i', 'localhost,', str(play)],
                                       cwd=suite, env=env, capture_output=True, timeout=180)
            try:
                results.append(verify(root, completed.returncode))
            except ValueError as exc:
                # These logs contain synthetic files only and disappear with the suite.
                # Emit task names and safe classification; no actual data was loaded.
                result = {'case': case, 'passed': False, 'error': str(exc),
                          'native_exit': completed.returncode}
                results.append(result)
                print(json.dumps(result), file=sys.stderr, flush=True)
            else:
                print(json.dumps({'case': case, 'passed': True}), file=sys.stderr, flush=True)
    report = {'production_task_sha256': digest(ROLE), 'fixture_source_sha256': digest(Path(__file__)),
              'helper_source_sha256': digest(CHECKS), 'mode': 'prepare' if prepare_only else 'native_fixture',
              'real_docker_calls': 0, 'real_hermes_changes': 0, 'real_chat_posts': 0,
              'production_task_names': list(NAMES), 'cases': results,
              'limitations': ['synthetic command effects, not a real container recreation',
                              'dependency installation and timer scheduling not exercised',
                              'controller termination and power loss not exercised']}
    print(json.dumps(report, sort_keys=True))
    return int(any(row.get('passed') is False for row in results))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'run', 'shim'))
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.operation == 'shim':
            require(len(args.arguments) >= 2, 'invalid_shim_arguments')
            return shim(Path(args.arguments[0]), args.arguments[1:])
        require(all(case in CASES for case in args.arguments), 'unknown_case')
        return run(args.operation == 'prepare', args.arguments or None)
    except Exception as exc:
        # Exception bodies may include arbitrary native output; do not print them.
        print(json.dumps({'error': 'fixture_failed', 'kind': type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
