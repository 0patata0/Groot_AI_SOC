"""Build attributed AIT evidence groups for review, never training dialogues.

Read only the six historical training environments. Preserve every matching
phase at shared boundaries, count rejected records, and keep raw alert objects.
Phase windows, detector descriptions and signature IDs are not incident gold.
Only Python's standard library is required; no archive is extracted to disk.
"""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
from pathlib import Path
import zipfile

KST = timezone(timedelta(hours=9))
TRAIN = ('fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck')
EXPECTED_SPLIT = {'train': list(TRAIN), 'val': ['wheeler'], 'holdout': ['wilson']}
OFFICIAL_MD5 = {'archive': '43db6b1f0996e0024befd617706c50e9',
                'labels': '60ff33796c77fd2136c4d1a4bc841bd9'}
OUTSIDE = 'outside_published_phase_windows'


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_hashes(path):
    hashes = {name: hashlib.new(name) for name in ('md5', 'sha256')}
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            for digest in hashes.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in hashes.items()}


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError('Timestamp is not text')
    value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('Timestamp lacks an explicit timezone')
    return value


def verify_split(split):
    if set(split) != set(EXPECTED_SPLIT):
        raise ValueError('Historical split keys changed')
    for key, expected in EXPECTED_SPLIT.items():
        if not isinstance(split[key], list) or sorted(split[key]) != sorted(expected):
            raise ValueError('Historical environment split changed: ' + key)


def read_phases(data):
    rows = defaultdict(list)
    text = data.decode('utf-8')
    raw_lines = data.splitlines(keepends=True)
    for number, row in enumerate(csv.DictReader(io.StringIO(text)), 2):
        start, end = float(row['start']), float(row['end'])
        if not (0 < start < end) or row['scenario'] not in (*TRAIN, 'wheeler', 'wilson'):
            raise ValueError('Invalid phase interval/environment')
        entry = {'phase': row['attack'], 'start_epoch': start, 'end_epoch': end,
                 'source_line': number, 'source_line_sha256': sha(raw_lines[number-1]),
                 'start_kst': datetime.fromtimestamp(start, KST).isoformat(),
                 'end_kst': datetime.fromtimestamp(end, KST).isoformat()}
        rows[row['scenario']].append(entry)
    for env in (*TRAIN, 'wheeler', 'wilson'):
        phases = rows[env]
        if not phases or len({p['phase'] for p in phases}) != len(phases):
            raise ValueError('Missing or duplicate phase names: ' + env)
    return rows


def matching_phases(epoch, phases):
    # Endpoints are retained inclusively. A shared boundary is explicitly
    # ambiguous rather than silently assigned to the first CSV row.
    return [p['phase'] for p in phases if p['start_epoch'] <= epoch <= p['end_epoch']]


def origin(record):
    rule = record.get('rule') or {}
    return 'suricata_via_wazuh' if 'suricata' in rule.get('groups', []) else 'wazuh'


def projection(record, env, member, number, line, phases):
    observed = parse_time(record.get('@timestamp'))
    matches = matching_phases(observed.timestamp(), phases)
    data = record.get('data') or {}
    rule = record.get('rule') or {}
    detector = data.get('alert') or {}
    return {
        'evidence_id': f'{env}:{member}:{number}',
        'source_member': member, 'source_line': number,
        'source_line_sha256': sha(line), 'source_alert_id': record.get('id'),
        'origin': origin(record), 'timestamp_source': record['@timestamp'],
        'timestamp_kst': observed.astimezone(KST).isoformat(),
        'provider_phase_matches': matches,
        'phase_boundary_or_overlap': len(matches) > 1,
        'agent': record.get('agent'),
        'wazuh_rule': {k: rule.get(k) for k in ('id', 'level', 'description', 'groups')},
        'suricata_alert': {k: detector.get(k) for k in ('signature_id', 'severity', 'signature', 'action')}
            if origin(record) == 'suricata_via_wazuh' else None,
        'network_fields': {k: data[k] for k in ('src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto') if k in data},
        'maliciousness_ground_truth': 'not_provided_per_alert',
        'raw_alert': record,
    }


def choose_samples(pool, count):
    # Round-robin across sensor/agent strata, with a deterministic representative
    # per rule. This is a review sample; source counts remain in the report.
    strata = defaultdict(list)
    for (sensor, agent, _rule), item in pool.items():
        strata[(sensor, agent)].append(item)
    for items in strata.values():
        items.sort(key=lambda item: item['source_line_sha256'])
    result = []
    keys = sorted(strata)
    while keys and len(result) < count:
        next_keys = []
        for key in keys:
            if len(result) >= count:
                break
            result.append(strata[key].pop(0))
            if strata[key]:
                next_keys.append(key)
        keys = next_keys
    return sorted(result, key=lambda item: (item['timestamp_kst'], item['evidence_id']))


def scan_member(stream, env, member, phases, samples):
    pools = {p['phase']: {} for p in phases}
    pools[OUTSIDE] = {}
    counts = Counter()
    phase_counts = Counter()
    origin_counts = Counter()
    rejected = []
    member_sha = hashlib.sha256()
    for number, line in enumerate(stream, 1):
        member_sha.update(line)
        counts['lines'] += 1
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError('Alert is not an object')
            item = projection(record, env, member, number, line, phases)
        except (ValueError, TypeError, AttributeError, KeyError, OverflowError) as error:
            counts['rejected'] += 1
            if len(rejected) < 20:
                rejected.append({'source_line': number, 'sha256': sha(line),
                                 'reason': type(error).__name__ + ': ' + str(error)[:160]})
            continue
        counts['parsed'] += 1
        if item['source_alert_id'] is None:
            counts['missing_alert_id'] += 1
        if item['phase_boundary_or_overlap']:
            counts['multiple_phase_matches'] += 1
        origin_counts[item['origin']] += 1
        matches = item['provider_phase_matches'] or [OUTSIDE]
        for name in matches:
            phase_counts[name] += 1
            key = (item['origin'], canonical(item['agent']), canonical(item['wazuh_rule']['id']))
            old = pools[name].get(key)
            if old is None or item['source_line_sha256'] < old['source_line_sha256']:
                pools[name][key] = item
    groups = []
    for name, pool in pools.items():
        selected = choose_samples(pool, samples)
        groups.append({'id': f'ait-ads-evidence:{env}:{name}', 'environment': env,
                       'split': 'historical_train_only', 'phase_context': name,
                       'provider_phase': next((p for p in phases if p['phase'] == name), None),
                       'source_matching_records': phase_counts[name],
                       'selected_records': len(selected), 'selection_is_complete': len(selected) == phase_counts[name],
                       'evidence': selected,
                       'scope': 'Co-temporal source observations, not a proven causal chain or independent incident.',
                       'labels': {'incident_verdict': None, 'approved_action': None, 'maliciousness': None}})
    return groups, {'member': member, 'member_sha256': member_sha.hexdigest(),
                    'counts': dict(counts), 'origins': dict(origin_counts),
                    'phase_memberships': dict(phase_counts), 'rejected_examples': rejected,
                    'source_lines_conserved': counts['lines'] == counts['parsed'] + counts['rejected']}


def build(archive_path, labels_path, split_path, output, samples=12, expected_md5=None):
    if output.exists():
        raise ValueError('Use a new immutable output directory')
    if not 1 <= samples <= 100:
        raise ValueError('Sample count must be between 1 and 100')
    for source in (archive_path, labels_path, split_path):
        if source.is_symlink() or not source.is_file():
            raise ValueError('Unsafe or missing source')
    split = json.loads(split_path.read_text())
    verify_split(split)
    digests = {'archive': file_hashes(archive_path), 'labels': file_hashes(labels_path)}
    for name, expected in (expected_md5 or OFFICIAL_MD5).items():
        if digests[name]['md5'] != expected:
            raise ValueError('Pinned provider content mismatch: ' + name)
    phases = read_phases(labels_path.read_bytes())
    groups, reports = [], []
    with zipfile.ZipFile(archive_path) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())):
            raise ValueError('Ambiguous duplicate ZIP member names')
        for env in TRAIN:
            member = env + '_wazuh.json'
            with archive.open(member) as stream:
                selected, report = scan_member(stream, env, member, phases[env], samples)
            # Reading each member to EOF also checks ZIP CRC, including rejected lines.
            report['zip_crc_checked_to_eof'] = True
            groups.extend(selected)
            reports.append(report)
            print(canonical({'environment_done': env, **report['counts']}), flush=True)
    payload = ''.join(canonical(group) + '\n' for group in groups).encode('utf-8')
    errors = sum(r['counts'].get('rejected', 0) for r in reports)
    selected_ids = {item['evidence_id'] for group in groups for item in group['evidence']}
    report = {
        'schema': 1, 'created_at_kst': datetime.now(KST).isoformat(),
        'status': 'blocked_source_errors' if errors else 'evidence_prepared_pending_context_and_answer_review',
        'source': {'doi': '10.5281/zenodo.8263181', 'license': 'CC-BY-4.0', 'digests': digests,
                   'paper_doi': '10.1145/3675741.3675748', 'split_sha256': sha(split_path.read_bytes())},
        'historical_split': split, 'read_environment_members': [r['member'] for r in reports],
        'validation_test_members_read': False,
        'sample_cap_per_group': samples, 'groups': len(groups), 'independent_environments': len(TRAIN),
        'nonempty_groups': sum(bool(g['evidence']) for g in groups),
        'selected_record_occurrences': sum(g['selected_records'] for g in groups),
        'selected_unique_records': len(selected_ids), 'rejected_records': errors,
        'groups_sha256': sha(payload), 'members': reports,
        'new_training_dialogues': 0, 'expert_review': False, 'training_started': False,
        'limits': [
            'Historical training environments may overlap earlier training records; no novelty or new holdout claim.',
            'Selection is bounded by rule/sensor/agent diversity; excluded observations are counted, not certified benign.',
            'Phase membership is time context only; outside a phase does not mean benign.',
            'Shared endpoints retain all matching phases; group counts can exceed unique record counts.',
            'Wazuh rule.id/level and Suricata signature_id/severity are separate identifiers and scales.',
            'No raw LDS host-log label linkage, incident adjudication, MCP trajectory or response gold yet.',
            'Provider source reputation and byte identity do not certify labels or model quality.',
        ],
    }
    output.mkdir(parents=True)
    (output / 'evidence-groups.jsonl').write_bytes(payload)
    (output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--split', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=12)
    args = parser.parse_args()
    report = build(args.archive, args.labels, args.split, args.output, args.samples)
    print(canonical({key: report[key] for key in ('status', 'groups', 'nonempty_groups',
        'selected_unique_records', 'rejected_records', 'new_training_dialogues')}))
    if report['rejected_records']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
