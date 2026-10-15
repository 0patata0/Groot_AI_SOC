#!/usr/bin/env python3
"""Private pure native-jq fixtures. No Docker, Ansible, runtime path, or writes."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit(64)
    raw = Path(sys.argv[1]).read_bytes()
    assert len(raw) < 131072
    source_sha = hashlib.sha256(raw).hexdigest()
    assert source_sha == 'b9796bb01608ce42650edb3581de11f1b024051efd76f1ab2191c4384bb296cc'
    play = json.loads(raw)[0]
    assert play['vars']['prepare'] == '/var/backups/capstone-waf-recreation-20261015/prepare-persistence-attempt2'
    assert play['vars']['compose_lf'] == '\n'
    assert play['vars']['compose_cr'] == '\r'
    condition = next(t for t in play['tasks'] if t['name'] ==
                     'Require one existing Imperva bind line and no new source names')
    assert condition['ansible.builtin.assert']['that'][:3] == [
        '(old_compose.split(imperva_line + compose_lf) | length) == 2',
        'old_compose.endswith(compose_lf)', 'compose_cr not in old_compose']
    publication = next(t for t in play['tasks'] if t['name'] ==
                       'Add exactly two mount lines after the existing Imperva bind')
    assert publication['ansible.builtin.copy']['content'] == (
        '{{ old_compose | replace(imperva_line + compose_lf, imperva_line + compose_lf + '
        'producer_line + compose_lf + template_line + compose_lf) }}')
    task = next(t for t in play['tasks'] if t['name'] ==
                'Require only two new read-only WAF binds and preserve every other rendered field')
    argv = task['ansible.builtin.command']['argv']
    assert argv[:3] == ['/usr/bin/jq', '-n', '-e']
    program = argv[-1]
    base = {'name': 'secstack', 'services': {
        'waf': {'image': 'fixed', 'environment': {'MODSEC_RULE_ENGINE': 'DetectionOnly'},
                'ports': [{'published': '80', 'target': 8080}],
                'volumes': [{'type': 'bind', 'source': x, 'target': '/' + x}
                            for x in ['logs', 'groot', 'imperva']]},
        'suricata': {'image': 'other-fixed'}},
        'networks': {'waf-net': {'driver': 'bridge'}}}
    candidate = copy.deepcopy(base)
    candidate['services']['waf']['volumes'] += [
        dict(type='bind', source='/etc/capstone-waf/zz-capstone-evidence-v2.conf',
             target='/etc/nginx/conf.d/zz-capstone-evidence.conf', read_only=True, bind={}),
        dict(type='bind', source='/etc/capstone-waf/modsecurity-override-v2.conf.template',
             target='/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template',
             read_only=True, bind={})]
    cases = [('exact_two', copy.deepcopy(candidate), copy.deepcopy(base), True)]
    item = copy.deepcopy(candidate)
    item['services']['waf']['volumes'][3]['bind'] = {'create_host_path': True}
    cases.append(('compose_default_bind', item, copy.deepcopy(base), True))
    changes = [
        ('image', lambda x: x['services']['waf'].update(image='changed')),
        ('port', lambda x: x['services']['waf']['ports'][0].update(published='81')),
        ('env', lambda x: x['services']['waf']['environment'].update(MODSEC_RULE_ENGINE='On')),
        ('other_service', lambda x: x['services']['suricata'].update(image='changed')),
        ('old_bind', lambda x: x['services']['waf']['volumes'][1].update(source='changed')),
        ('new_rw', lambda x: x['services']['waf']['volumes'][3].update(read_only=False)),
        ('bind_extra', lambda x: x['services']['waf']['volumes'][3].update(consistency='cached')),
        ('extra_volume', lambda x: x['services']['waf']['volumes'].append({})),
        ('wrong_target', lambda x: x['services']['waf']['volumes'][4].update(target='/wrong')),
        ('network', lambda x: x['networks'].update(extra={}))]
    for name, mutate in changes:
        item = copy.deepcopy(candidate)
        mutate(item)
        cases.append((name, item, copy.deepcopy(base), False))
    cases.append(('live_baseline_drift', copy.deepcopy(candidate), {}, False))
    results = []
    for name, item, current, expected in cases:
        result = subprocess.run(['/usr/bin/jq', '-n', '-e',
            '--argjson', 'old', json.dumps([base]),
            '--argjson', 'now', json.dumps([current]),
            '--argjson', 'new', json.dumps([item]), program],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        assert len(result.stdout) < 128 and len(result.stderr) < 4096
        assert result.returncode == (0 if expected else 1), name
        results.append({'case': name, 'expected_accepted': expected,
                        'observed_exit': result.returncode, 'passed': True})
    assert len(results) == 13
    print(json.dumps({'schema_version': 1, 'status': 'passed',
        'source_sha256': source_sha, 'literal_data_and_attempt2_contract': True,
        'native_jq_cases': 13, 'cases': results,
        'production_paths_accessed': False, 'docker_calls': 0, 'files_written': 0},
        sort_keys=True))


if __name__ == '__main__':
    main()
