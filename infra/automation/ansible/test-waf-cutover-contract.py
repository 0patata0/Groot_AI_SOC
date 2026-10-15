#!/usr/bin/env python3
"""Exercise captured cutover functions/predicates with synthetic metadata only.

No Docker/systemctl commands, runtime files, SSH, or source modifications. The
systemctl token inside the captured unit parser resolves to a fixed shell stub.
This does not test actual lifecycle ordering, locks, EOF gates, or publication.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def run(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=5)
    if len(result.stdout) > 8192 or len(result.stderr) > 8192:
        raise ValueError('fixture_output_limit')
    return result


def function(source, name):
    match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', source,
                      flags=re.M | re.S)
    if not match:
        raise ValueError('source_function_missing')
    return match.group(0)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(64)
    path = Path(sys.argv[1])
    raw = path.read_bytes()
    if len(raw) > 131072:
        raise ValueError('source_size_limit')
    source = raw.decode('utf-8')
    unit = function(source, 'wrc_unit')
    writer = function(source, 'wrc_new_writer')
    matches = re.findall(
        r'jq -e --slurpfile expected "\$WRC_BASE/candidate-create/candidate-inspect.json" '
        r'\\\n\s*\x27(.*?)\x27 >/dev/null', writer, flags=re.S)
    if len(matches) != 1:
        raise ValueError('profile_predicate_not_exactly_one')
    program = matches[0]
    results = []

    active = {
        'ActiveState': 'active', 'SubState': 'running',
        'InvocationID': '1' * 32, 'MainPID': '1234',
        'Result': 'success', 'ExecMainStatus': '0',
        'ExecMainStartTimestampMonotonic': '123456789',
    }
    inactive = dict(active, ActiveState='inactive', SubState='dead',
                    InvocationID='', MainPID='0')

    def lines(value):
        return ''.join(k + '=' + v + '\n' for k, v in value.items())

    cases = [('active_exact', lines(active), active),
             ('inactive_empty_invocation', lines(inactive), inactive),
             ('reordered_fields', lines(dict(reversed(list(active.items())))), active),
             ('missing_field', lines({k: v for k, v in active.items() if k != 'Result'}), None),
             ('duplicate_field', lines(active) + 'Result=success\n', None),
             ('unknown_field', lines({k: v for k, v in active.items() if k != 'Result'}) + 'Other=success\n', None),
             ('extra_equal_separator', lines(active).replace('Result=success', 'Result=success=extra'), None),
             ('empty_input', '', None)]
    # Only this reviewed function is evaluated. The native executable called by
    # its body is jq; systemctl always resolves to this in-process fixture stub.
    shell = ("set -uo pipefail\n" + unit + "\n"
             "systemctl() { [[ $# == 4 && $1 == show && $2 == capstone-vector.service "
             "&& $3 == -p ]] || return 97; printf '%s' \"$WRC_SYNTHETIC_UNIT\"; }\n"
             "WRC_SYNTHETIC_UNIT=$1\nwrc_unit capstone-vector.service\n")
    for name, value, expected in cases:
        observed = run(['/bin/bash', '-c', shell, 'unit-fixture', value])
        canonical = (json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n').encode()
        exact_canonical = observed.stdout == canonical if expected is not None else None
        good = (observed.returncode == 0 and json.loads(observed.stdout) == expected
                and exact_canonical
                if expected is not None else observed.returncode != 0)
        results.append({'case': 'unit_' + name, 'passed': good,
                        'exit_code': observed.returncode,
                        'canonical_bytes_exact': exact_canonical})

    expected = {
        'Config': {'User': 'nginx', 'Env': ['SYNTHETIC=1'],
                   'Entrypoint': ['/fixed-entrypoint'], 'Cmd': ['nginx']},
        'HostConfig': {'OomKillDisable': False, 'Privileged': False,
                       'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                       'Binds': ['synthetic-bind-' + str(i) for i in range(5)]},
        'Mounts': [{'Type': 'bind', 'Source': '/source/' + str(i),
                    'Destination': '/target/' + str(i), 'RW': i == 0,
                    'Propagation': 'rprivate'} for i in range(5)],
        'RestartCount': 0,
    }
    defaults = ['BlkioDeviceReadBps', 'BlkioDeviceReadIOps',
                'BlkioDeviceWriteBps', 'BlkioDeviceWriteIOps',
                'BlkioWeightDevice', 'Devices', 'DnsOptions', 'DnsSearch']
    for key in defaults:
        expected['HostConfig'][key] = None
    actual = copy.deepcopy(expected)
    actual['HostConfig']['OomKillDisable'] = None
    for key in defaults:
        actual['HostConfig'][key] = []
    profile_cases = [('started_null', copy.deepcopy(actual), copy.deepcopy(expected), True),
                     ('still_false', copy.deepcopy(expected), copy.deepcopy(expected), True)]
    changed = copy.deepcopy(actual)
    changed['Mounts'].reverse()
    profile_cases.append(('mount_order_only', changed, copy.deepcopy(expected), True))
    changes = [
        ('oom_true', lambda x: x['HostConfig'].update(OomKillDisable=True)),
        ('oom_numeric_zero', lambda x: x['HostConfig'].update(OomKillDisable=0)),
        ('oom_missing', lambda x: x['HostConfig'].pop('OomKillDisable')),
        ('privileged_changed', lambda x: x['HostConfig'].update(Privileged=True)),
        ('restart_policy_changed', lambda x: x['HostConfig']['RestartPolicy'].update(Name='always')),
        ('config_changed', lambda x: x['Config'].update(User='root')),
        ('mount_source_changed', lambda x: x['Mounts'][1].update(Source='/unexpected')),
        ('mount_target_changed', lambda x: x['Mounts'][1].update(Destination='/unexpected')),
        ('mount_rw_changed', lambda x: x['Mounts'][1].update(RW=True)),
        ('mount_missing', lambda x: x['Mounts'].pop()),
        ('mount_duplicate', lambda x: x['Mounts'].append(copy.deepcopy(x['Mounts'][0]))),
        ('restart_count_changed', lambda x: x.update(RestartCount=1)),
    ]
    for name, mutate in changes:
        changed = copy.deepcopy(actual)
        mutate(changed)
        profile_cases.append((name, changed, copy.deepcopy(expected), False))
    before_null = copy.deepcopy(expected)
    before_null['HostConfig']['OomKillDisable'] = None
    profile_cases.append(('created_null_forbidden', copy.deepcopy(actual), before_null, False))
    created_empty = copy.deepcopy(expected)
    for key in defaults:
        created_empty['HostConfig'][key] = []
    profile_cases.append(('all_empty_defaults', copy.deepcopy(actual), created_empty, True))
    started_null_defaults = copy.deepcopy(actual)
    for key in defaults:
        started_null_defaults['HostConfig'][key] = None
    profile_cases.append(('empty_to_null_defaults', started_null_defaults,
                          copy.deepcopy(created_empty), True))
    for key in defaults:
        changed = copy.deepcopy(actual)
        changed['HostConfig'][key] = ['unreviewed']
        profile_cases.append(('nonempty_' + key, changed, copy.deepcopy(expected), False))
        changed = copy.deepcopy(actual)
        del changed['HostConfig'][key]
        profile_cases.append(('missing_' + key, changed, copy.deepcopy(expected), False))
    for name, after, before, accepted in profile_cases:
        observed = run(['/usr/bin/jq', '-n', '-e', '--argjson', 'expected',
                        json.dumps([[before]]), '--argjson', 'actual',
                        json.dumps([after]), '$actual | (' + program + ')'])
        results.append({'case': 'profile_' + name,
                        'passed': observed.returncode == (0 if accepted else 1),
                        'exit_code': observed.returncode})
    unchanged = path.read_bytes() == raw
    passed = all(x['passed'] for x in results) and unchanged
    print(json.dumps({'schema_version': 1, 'status': 'passed' if passed else 'failed',
                      'source_sha256': hashlib.sha256(raw).hexdigest(),
                      'cases': results, 'passed': sum(x['passed'] for x in results),
                      'failed': sum(not x['passed'] for x in results),
                      'source_unchanged': unchanged, 'runtime_access': False,
                      'docker_calls': 0, 'systemctl_calls': 0, 'files_written': 0},
                     sort_keys=True))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
