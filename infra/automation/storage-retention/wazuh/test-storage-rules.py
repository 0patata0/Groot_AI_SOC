#!/usr/bin/env python3
"""Pure route/shape fixtures; --native invokes existing manager logtest only.

No rule install, restart, logger, operating input append or external request.
Native validation is separate from actual A/B journal receipt and indexing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
RULES = HERE / 'capstone_storage_rules.xml'
DECODERS = HERE / 'capstone_storage_decoders.xml'
IDS = {str(n) for n in range(100310, 100314)}
LOCATIONS = {'a': '(groot-sec) any->journald', 'b': '/var/ossec/logs/capstone-storage-b.log'}
MACHINES = {'a': '096e90b6243e438aa8a7b392be754732', 'b': '1e143067c98a44ffba6eaa925dc038d7'}
EXPECTED = {'ok': ('100310', 0), 'warning': ('100311', 5),
            'critical': ('100312', 10), 'unavailable': ('100313', 5)}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def event(host='a', status='ok'):
    value = {'schema_version': 1, 'policy': 'capstone-storage-retention-v1',
             'machine_id': MACHINES[host], 'host': host, 'observed_at_utc': '2026-10-15T00:00:00Z',
             'status': status, 'reason': {'ok': 'healthy', 'warning': 'capacity_warning',
                 'critical': 'capacity_critical', 'unavailable': 'scan_unavailable'}[status],
             'scan_status': 'unavailable' if status == 'unavailable' else 'complete',
             'used_percent': {'ok': 40, 'warning': 80, 'critical': 90, 'unavailable': None}[status],
             'available_bytes': 10737418240, 'raw_bytes': 1024, 'backup_bytes': 2048,
             'history_bytes': 4096, 'raw_archive_review_due_count': 0, 'backup_review_due_count': 0,
             'retention_days': 30 if host == 'a' else 90,
             'automatic_deletion': False, 'checkpoint_changed': False}
    assert len(value) == 18
    return value


def fixtures():
    rows = []
    def add(name, payload, want, host='a', program='capstone-storage', location=None, pid=True):
        rows.append({'name': name, 'payload': payload, 'expected': want, 'program': program,
                     'location': location or LOCATIONS[host], 'pid': pid})
    for host in MACHINES:
        for status in EXPECTED:
            add(host + '_' + status, canonical(event(host, status)), EXPECTED[status], host)
        value = event(host, 'critical'); value.update(scan_status='unavailable', raw_bytes=None)
        add(host + '_known_critical_with_unknown', canonical(value), EXPECTED['critical'], host)
        value = event(host, 'unavailable'); value.update(used_percent=80, raw_bytes=None)
        add(host + '_warning_plus_unknown', canonical(value), EXPECTED['unavailable'], host)
        add(host + '_logger_without_pid', canonical(event(host, 'critical')), EXPECTED['critical'], host, pid=False)
    value = event('b', 'unavailable')
    for key in ('used_percent', 'available_bytes', 'raw_bytes', 'backup_bytes', 'history_bytes',
                'raw_archive_review_due_count', 'backup_review_due_count'): value[key] = None
    add('all_measurements_unknown', canonical(value), EXPECTED['unavailable'], 'b')
    valid = canonical(event('a', 'critical'))
    for name, program, location in (
        ('wrong_program', 'unrelated', LOCATIONS['a']),
        ('program_suffix', 'capstone-storage-other', LOCATIONS['a']),
        ('wrong_agent', 'capstone-storage', '(other-agent) any->journald'),
        ('bare_journald', 'capstone-storage', 'journald'),
        ('unrelated_file', 'capstone-storage', '/var/log/unrelated.log'),
        ('b_path_suffix', 'capstone-storage', LOCATIONS['b'] + '.old')):
        add(name, valid, None, program=program, location=location)
    for key, bad in (('schema_version', '1'), ('schema_version', True), ('policy', 'other'),
                     ('automatic_deletion', True), ('automatic_deletion', 'false'),
                     ('checkpoint_changed', True), ('checkpoint_changed', 0),
                     ('used_percent', -1), ('used_percent', 101), ('used_percent', 90.5),
                     ('raw_bytes', '1024'), ('backup_bytes', -1), ('history_bytes', {}),
                     ('backup_review_due_count', True), ('raw_archive_review_due_count', []),
                     ('machine_id', MACHINES['b']), ('host', 'b'), ('retention_days', 90),
                     ('observed_at_utc', '2026-10-15T09:00:00+09:00'),
                     ('status', 'critical-extra'), ('reason', 'capacity_warning'),
                     ('scan_status', 'other')):
        value = event('a', 'critical'); value[key] = bad
        add('invalid_' + key + '_' + type(bad).__name__, canonical(value), None)
    for status in ('ok', 'warning'):
        value = event('a', status); value['scan_status'] = 'unavailable'
        add(status + '_unknown_not_healthy', canonical(value), None)
    value = event('a', 'critical'); value['raw_bytes'] = None
    add('complete_with_null_refused', canonical(value), None)
    for key in ('host', 'status', 'used_percent', 'checkpoint_changed', 'policy'):
        value = event('a', 'critical'); del value[key]
        add('missing_' + key, canonical(value), None)
    value = event('a', 'critical'); value['extra_payload'] = 'synthetic-only'
    add('extra_key', canonical(value), None)
    add('trailing_payload', valid + ' trailing', None)
    add('concatenated_json', valid + valid, None)
    add('duplicate_key', valid.replace('"schema_version":1', '"schema_version":1,"schema_version":1'), None)
    add('noncanonical_spacing', json.dumps(event('a', 'critical'), sort_keys=True), None)
    return rows


def static_contract(rows):
    decoder = ET.fromstring(DECODERS.read_bytes())
    assert decoder.tag == 'decoder' and decoder.attrib == {'name': 'capstone_storage_json'}
    assert decoder.findtext('program_name') == '^capstone-storage$'
    assert decoder.findtext('prematch') == r'^\{' and decoder.findtext('plugin_decoder') == 'JSON_Decoder'
    raw = RULES.read_bytes()
    assert b'any->journald' in raw and b'&gt;' not in raw  # native OS_XML literal bytes
    root = ET.fromstring(raw); rules = {r.attrib['id']: r for r in root.findall('rule')}
    assert set(rules) == IDS
    base = rules['100310']
    assert base.attrib == {'id': '100310', 'level': '0'}
    assert base.findtext('decoded_as') == 'capstone_storage_json'
    assert [x.text for x in base.findall('options')] == ['no_log']
    assert not any(root.iter('active-response')) and not any(root.iter('command'))
    pattern = re.compile(base.findtext('match').replace(r'\z', r'\Z'))
    for row in rows:
        route = (re.fullmatch(base.findtext('program_name'), row['program']) is not None and
                 re.fullmatch(base.findtext('location'), row['location']) is not None)
        shape = pattern.fullmatch(row['payload']) is not None
        if row['expected'] is None:
            assert not route or not shape, row['name']
            continue
        assert route and shape, row['name']
        value = json.loads(row['payload']); matched = []
        for sid, rule in rules.items():
            if sid == '100310': continue
            assert rule.findtext('if_sid') == '100310' and 'ignore' not in rule.attrib
            assert not any(x.attrib.get('name') == 'status' for x in rule.findall('field'))
            assert [x.text for x in rule.findall('options')] == ['no_email_alert', 'no_full_log']
            if (re.search(rule.findtext('match'), row['payload']) is not None and
                    all(re.fullmatch(x.text, str(value.get(x.attrib['name'], ''))) for x in rule.findall('field'))):
                matched.append((sid, int(rule.attrib['level'])))
        assert len(matched) <= 1, (row['name'], 'overlapping severity leaves')
        assert (matched[0] if matched else ('100310', 0)) == row['expected'], row['name']
    fragment = ET.fromstring((HERE / 'manager-localfile.xml').read_bytes())
    assert fragment.findtext('location') == LOCATIONS['b'] and fragment.findtext('log_format') == 'syslog'
    assert fragment.findtext('only-future-events') == 'yes'
    return len(rows)


def native(rows, manager):
    assert re.fullmatch('[0-9a-f]{64}', manager), 'full fixed manager CID required'
    assert sys.platform == 'linux', 'existing Linux B host required'
    passed = 0
    for row in rows:
        pid = '[12345]' if row['pid'] else ''
        line = 'Oct 15 09:00:00 synthetic-host ' + row['program'] + pid + ': ' + row['payload'] + '\n'
        argv = ['/usr/local/bin/docker', 'exec', '-i', manager, '/var/ossec/bin/wazuh-logtest', '-l', row['location']]
        try:
            result = subprocess.run(argv, input=line.encode(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=20, check=False)
        except subprocess.TimeoutExpired:
            print(canonical({'status': 'failed', 'case': row['name'], 'reason': 'native_timeout'}))
            return False, passed
        raw = result.stdout
        if len(raw) > 65536:
            print(canonical({'status': 'failed', 'case': row['name'], 'reason': 'native_output_limit'}))
            return False, passed
        text = raw.decode('utf-8', errors='replace')
        ids = re.findall(r"^\s*id: '([0-9]+)'", text, re.M)
        levels = re.findall(r"^\s*level: '([0-9]+)'", text, re.M)
        clean = result.returncode == 0 and re.search(r'(?:ERROR|CRITICAL):', text) is None
        if row['expected'] is None:
            good = clean and not (set(ids) & IDS)
        else:
            sid, level = row['expected']
            good = clean and ids == [sid] and levels == [str(level)] and "name: 'capstone_storage_json'" in text
        if not good:
            # Supplied input is this synthetic fixture only. Keep diagnostics on B.
            sys.stderr.buffer.write(raw); sys.stderr.buffer.flush()
            print(canonical({'status': 'failed', 'case': row['name'], 'expected': row['expected'],
                'actual_ids': ids, 'actual_levels': levels, 'exit_code': result.returncode,
                'diagnostic_sha256': hashlib.sha256(raw).hexdigest(), 'new_operating_input': 0}))
            return False, passed
        passed += 1
        print(canonical({'status': 'passed', 'case': row['name'], 'expected': row['expected']}))
    return True, passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true'); parser.add_argument('--manager', default='')
    args = parser.parse_args()
    rows = fixtures(); count = static_contract(rows)
    ok, passed = native(rows, args.manager) if args.native else (True, 0)
    print(canonical({'schema_version': 1, 'status': 'passed' if ok else 'failed', 'static_cases': count,
        'native_cases_passed': passed, 'native_executed': args.native,
        'rules_sha256': hashlib.sha256(RULES.read_bytes()).hexdigest(),
        'decoders_sha256': hashlib.sha256(DECODERS.read_bytes()).hexdigest(),
        'new_operating_input': 0, 'rules_installed': False, 'actual_b_host_journal_received': False,
        'capacity_thresholds_recomputed_by_rules': False, 'exactly_once_alert_delivery_claimed': False}))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
