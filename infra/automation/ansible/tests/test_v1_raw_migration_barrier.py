#!/usr/bin/env python3
"""Check the actual legacy Ansible guards; --native uses existing Linux Ansible.

The private native playbook contains only the extracted stat/assert guards and
a synthetic sentinel copy. It never runs the Vector/storage deployment roles.
No package installation, services, Docker, raw logs or operating markers.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FILES = (ROOT / 'vector-storage-a.yml', ROOT / 'roles/vector_shadow/tasks/main.yml')
PATHS = ('/var/lib/capstone-raw-operations', '/var/lib/capstone-raw-migration',
         '/var/backups/capstone-raw-operations-initial-20261014/migration.json')
REGISTER = 'capstone_v1_raw_barriers'
ANSIBLE = '/opt/capstone-automation/venv/bin/ansible-playbook'


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def guards():
    result = []
    for path in FILES:
        raw = path.read_bytes()
        doc = json.loads(raw)
        tasks = doc[0]['tasks'] if path.name == 'vector-storage-a.yml' else doc
        positions = [i for i, task in enumerate(tasks) if task.get('register') == REGISTER]
        require(positions == [1], 'barrier_not_immediately_after_host_guard')
        pair = tasks[1:3]
        probe, refusal = pair
        require(probe['ansible.builtin.stat'] == {'path': '{{ item }}', 'follow': False,
                'get_checksum': False, 'get_mime': False, 'get_attributes': False}, 'probe_must_not_read_contents')
        require(tuple(probe['loop']) == PATHS, 'fixed_barrier_paths_changed')
        require(refusal['loop'] == '{{ capstone_v1_raw_barriers.results }}', 'assert_result_binding_changed')
        require(refusal['ansible.builtin.assert']['that'] == [
                'item.stat.exists is defined', 'not item.stat.exists',
                'not (item.stat.islnk | default(false))'], 'fail_closed_assertions_changed')
        require(all(t.get('tags') == ['always'] and 'when' not in t and
                    not t.get('ignore_errors', False) for t in pair), 'barrier_may_be_skipped')
        require('ansible.builtin.assert' in tasks[0], 'mutation_before_barrier')
        # Preparation files alone must not become a deployment lockout.
        require(all(not p.endswith('/plan.json') and not p.endswith('/prepare-intent.json') for p in PATHS),
                'prepare_only_must_remain_allowed')
        result.append((path, pair, digest(raw)))
    first = copy.deepcopy(result[0][1]); second = copy.deepcopy(result[1][1])
    for tasks in (first, second):
        for task in tasks:
            task.pop('name')
    require(first == second, 'role_and_storage_guards_diverged')
    role = json.loads(FILES[1].read_bytes())
    schema_guard = next(t for t in role if t['name'] == 'Require fixed WAF metadata contract')
    require("(capstone_waf_binding.schema | default('')) == 'waf-producer-deployment-1'" in
            schema_guard['ansible.builtin.assert']['that'], 'existing_v1_schema_guard_removed')
    return result


def metadata(path):
    info = path.lstat()
    value = [info.st_dev, info.st_ino, info.st_uid, info.st_gid,
             stat.S_IMODE(info.st_mode), info.st_nlink]
    if path.is_symlink():
        value.append(os.readlink(path))
    elif path.is_file():
        value.append(digest(path.read_bytes()))
    return value


def native(source):
    require(os.geteuid() == 0 and sys.platform == 'linux', 'native_requires_private_linux_root')
    require(Path(ANSIBLE).is_file(), 'existing_ansible_required')
    stage = Path(tempfile.mkdtemp(prefix='capstone-v1-barrier-test.', dir='/var/tmp'))
    os.chmod(stage, 0o700)
    plays, expected, preserved = [], [], {}
    scenarios = ('absent', 'prepare_only', 'state_directory', 'state_file', 'state_symlink',
                 'migration_directory', 'migration_bad_marker', 'migration_symlink',
                 'ledger_file', 'ledger_directory', 'ledger_symlink', 'check_absent', 'check_barrier')
    case_count = 0
    try:
        for source_index, (_, pair, _) in enumerate(source):
            for scenario in scenarios:
                case_count += 1
                case = stage / ('case-%02d-%s' % (source_index, scenario))
                case.mkdir(mode=0o700)
                backup = case / 'backup'; backup.mkdir(mode=0o700)
                state_path, migration, ledger = case / 'state', case / 'migration', backup / 'migration.json'
                if scenario == 'prepare_only':
                    (backup / 'plan.json').write_text('{"phase":"prepared"}\n')
                    (backup / 'prepare-intent.json').write_text('{"operating_mutations":false}\n')
                elif scenario == 'state_directory':
                    state_path.mkdir(mode=0o700)
                elif scenario == 'state_file':
                    state_path.write_text('invalid synthetic state\n'); state_path.chmod(0o000)
                elif scenario == 'state_symlink':
                    state_path.symlink_to(case / 'missing')
                elif scenario in ('migration_directory', 'migration_bad_marker', 'check_barrier'):
                    migration.mkdir(mode=0o700)
                    if scenario == 'migration_bad_marker':
                        (migration / 'start-barrier.json').write_text('not JSON\n')
                        (migration / 'start-barrier.json').chmod(0o666)
                elif scenario == 'migration_symlink':
                    migration.symlink_to(case / 'missing')
                elif scenario == 'ledger_file':
                    ledger.write_text('not JSON\n'); os.chown(ledger, 1000, 1000)
                elif scenario == 'ledger_directory':
                    ledger.mkdir(mode=0o700)
                elif scenario == 'ledger_symlink':
                    ledger.symlink_to(case / 'missing')
                allowed = scenario in ('absent', 'prepare_only', 'check_absent')
                check_mode = scenario.startswith('check_')
                sentinel = case / 'sentinel'
                tasks = copy.deepcopy(pair)
                require(tasks[0]['loop'] == list(PATHS), 'native_rewrite_source_contract_changed')
                # Exactly three literal fixture paths change; the production
                # modules, flags, assertions, register and tags remain exact.
                tasks[0]['loop'] = [str(state_path), str(migration), str(ledger)]
                mutation = {'name': 'Synthetic mutation reached only after both guards',
                            'ansible.builtin.copy': {'content': 'guard passed\n', 'dest': str(sentinel), 'mode': '0600'}}
                plays.append({'name': '%02d-%s' % (source_index, scenario), 'hosts': 'all', 'gather_facts': False,
                              'check_mode': check_mode,
                              'vars': {'ansible_python_interpreter': '/usr/bin/python3'}, 'tasks': [
                    {'ansible.builtin.set_fact': {'barrier_rejected': False}},
                    {'block': tasks + [mutation], 'rescue': [
                        {'ansible.builtin.assert': {'that': [
                            'ansible_failed_task.name == ' + json.dumps(tasks[1]['name'])]}},
                        {'ansible.builtin.set_fact': {'barrier_rejected': True}}]},
                    {'ansible.builtin.assert': {'that': ['barrier_rejected == ' + ('false' if allowed else 'true')]}}]})
                expected.append((sentinel, allowed and not check_mode))
                for path in case.rglob('*'):
                    preserved[str(path)] = metadata(path)
        config = stage / 'ansible.cfg'
        config.write_text('[defaults]\nretry_files_enabled = False\n'
                          'local_tmp = %s\nremote_tmp = %s\n' % (stage / 'local-tmp', stage / 'remote-tmp'))
        playbook = stage / 'test.json'
        playbook.write_text(json.dumps(plays, indent=2) + '\n')
        command = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=5s', '180s', ANSIBLE,
                   '-i', 'localhost,', '-c', 'local', str(playbook)]
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8',
                       'PYTHONDONTWRITEBYTECODE': '1', 'ANSIBLE_CONFIG': str(config),
                       'ANSIBLE_NOCOLOR': '1'}
        log = stage / 'ansible.log'
        with log.open('wb') as output:
            completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                       env=environment, timeout=190)
        require(completed.returncode == 0, 'native_ansible_fixture_failed')
        require(log.stat().st_size <= 4194304, 'native_fixture_output_limit')
        for sentinel, should_exist in expected:
            require(sentinel.exists() == should_exist, 'unexpected_sentinel_mutation')
            if should_exist:
                require(sentinel.read_bytes() == b'guard passed\n', 'sentinel_bytes_changed')
        require(all(metadata(Path(path)) == original for path, original in preserved.items()), 'fixture_barrier_changed')
        require(all(digest(path.read_bytes()) == checksum for path, _, checksum in source), 'source_changed')
        result = {'status': 'passed', 'native_cases': case_count, 'entrypoints': 2,
                  'unchanged_extracted_guard_tasks': True, 'rewritten_fixture_paths_per_entrypoint': 3,
                  'legacy_without_barriers_allowed': True, 'prepare_only_allowed': True,
                  'malformed_or_symlink_barriers_rejected': True, 'check_mode_enforced': True,
                  'rejected_cases_reached_mutation': 0, 'barrier_files_unchanged': True,
                  'operating_roles_executed': False, 'operating_changes': False,
                  'source_sha256': {str(path.relative_to(ROOT)): checksum for path, _, checksum in source}}
    finally:
        require(re.fullmatch(r'/var/tmp/capstone-v1-barrier-test\.[A-Za-z0-9_-]+', str(stage)) and
                stage.is_dir() and not stage.is_symlink() and stage.stat().st_uid == 0, 'unsafe_fixture_cleanup')
        shutil.rmtree(stage)
    result['fixture_removed'] = not stage.exists()
    return result


def main():
    require(sys.argv[1:] in ([], ['--static'], ['--native']), 'invalid_mode')
    source = guards()
    if sys.argv[1:] == ['--native']:
        return native(source)
    return {'status': 'passed', 'static_entrypoints': len(source), 'barrier_paths': len(PATHS),
            'before_first_mutation': True, 'check_mode_tasks_supported': True,
            'existing_v1_schema_guard_preserved': True, 'native_executed': False,
            'source_sha256': {str(path.relative_to(ROOT)): checksum for path, _, checksum in source}}


if __name__ == '__main__':
    try:
        print(json.dumps(main(), sort_keys=True))
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'failed', 'reason': str(error) if isinstance(error, RuntimeError)
                          else 'fixture_execution_failed', 'operating_changes': False}))
        sys.exit(1)
