"""Inspect pinned Linux-APT CSVs; emit evidence coordinates, never SFT/gold.

Only bounded files are read into memory. No log text, commands, credentials,
host/user identifiers or network addresses are copied into the projection.
Record coordinates/hash permit later authorized source review. Source rule
annotations and SCA references are not independently adjudicated attack labels.
"""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import ssl
import urllib.request

KST = timezone(timedelta(hours=9))
TIME_KEYS = ('_source.@timestamp', '_source.timestamp')
MONTHS = dict(zip('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), range(1, 13)))
KIBANA = re.compile(r'([A-Z][a-z]{2}) (\d{1,2}), (\d{4}) @ (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?')
TECHNIQUE = re.compile(r'T\d{4}(?:\.\d{3})?')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def source_time(row):
    """Never infer an offset from country, filename, event ID or predecoder."""
    values = []
    for key in TIME_KEYS:
        value = row.get(key, '').strip()
        if not value:
            continue
        try:
            match = KIBANA.fullmatch(value)
            if match:
                mon, day, year, hh, mm, ss, fraction = match.groups()
                parsed = datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm),
                                  int(ss), int((fraction or '').ljust(6, '0')))
            else:
                parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (ValueError, KeyError):
            return {'status': 'unparsed', 'timestamp_kst': None}
        values.append(parsed)
    if not values:
        return {'status': 'missing', 'timestamp_kst': None}
    aware = [v.tzinfo is not None and v.utcoffset() is not None for v in values]
    if any(aware) and not all(aware):
        return {'status': 'mixed_timezone_evidence', 'timestamp_kst': None}
    if any(v != values[0] for v in values[1:]):
        return {'status': 'conflicting_fields', 'timestamp_kst': None}
    if not all(aware):
        return {'status': 'timezone_unknown', 'timestamp_kst': None,
                'source_wall_time': values[0].isoformat()}
    return {'status': 'explicit_offset', 'timestamp_kst': values[0].astimezone(KST).isoformat()}


def rule_annotations(row):
    raw = row.get('_source.rule.mitre.id', '').strip()
    if not raw:
        labels = []
    else:
        try:
            labels = json.loads(raw)
        except json.JSONDecodeError:
            labels = None
    valid = (isinstance(labels, list) and all(isinstance(x, str) and
             TECHNIQUE.fullmatch(x) for x in labels))
    sca = any(v.strip() for k, v in row.items() if 'sca.check.compliance.mitre_' in k)
    return {'status': 'parsed' if valid else 'invalid_format',
            'rule_technique_ids': sorted(set(labels)) if valid else [],
            'sca_mitre_references_present': sca,
            'maliciousness': 'not_adjudicated', 'attack_success': 'not_adjudicated',
            'basis': 'detector_rule_annotation_not_independent_gold'}


def safe_code(value):
    """Only structural codes, not arbitrary source prose, enter the output."""
    value = value.strip()
    return value if re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', value) else None


class RecordingLines:
    def __init__(self, text):
        self.stream = io.StringIO(text, newline='')
        self.pending = []

    def __iter__(self):
        return self

    def __next__(self):
        line = next(self.stream)
        self.pending.append(line)
        return line

    def take(self):
        value = ''.join(self.pending).encode('utf-8')
        self.pending.clear()
        return value


class CorpusReview:
    def __init__(self, max_groups=512, per_group=2):
        if max_groups < 1 or per_group < 1:
            raise ValueError('Sample limits must be positive')
        self.max_groups, self.per_group = max_groups, per_group
        self.counts = Counter()
        self.times, self.techniques, self.rules = Counter(), Counter(), Counter()
        self.identity_hashes = {}
        self.record_hashes = set()
        self.samples = defaultdict(list)
        self.files = []

    def inspect(self, data, entry):
        if len(data) != entry['bytes'] or hashlib.md5(data).hexdigest() != entry['md5']:
            raise ValueError('Source byte count or MD5 mismatch: ' + canonical({
                'file': entry['name'], 'expected_bytes': entry['bytes'],
                'received_bytes': len(data), 'expected_md5': entry['md5'],
                'received_md5': hashlib.md5(data).hexdigest(), 'received_sha256': sha(data)}))
        if any(f['name'] == entry['name'] for f in self.files):
            raise ValueError('Source file repeated')
        text = data.decode('utf-8-sig')
        lines = RecordingLines(text)
        reader = csv.reader(lines, strict=True)
        header = next(reader)
        lines.take()
        if not header or len(set(header)) != len(header) or any(not x for x in header):
            raise ValueError('Empty or duplicate CSV header')
        if not {'_source.full_log', '_source.rule.id'}.issubset(header):
            raise ValueError('Required observation columns missing')
        file_sha, count, previous_line = sha(data), 0, reader.line_num
        for number, values in enumerate(reader, 1):
            raw = lines.take()
            start_line, end_line = previous_line + 1, reader.line_num
            previous_line = end_line
            if not values:
                self.counts['blank_records'] += 1
                continue
            if len(values) != len(header):
                raise ValueError('CSV width mismatch: ' + entry['name'] + ':' + str(number))
            row = dict(zip(header, values))
            count += 1
            self.counts['rows'] += 1
            normalized = {k: v for k, v in row.items() if v.strip()}
            record_sha = sha(canonical(normalized).encode())
            duplicate = record_sha in self.record_hashes
            self.record_hashes.add(record_sha)
            self.counts['duplicate_normalized_records'] += duplicate
            index, identity = row.get('_index', '').strip(), row.get('_id', '').strip()
            if index and identity:
                identity_sha = sha(canonical([index, identity]).encode())
                previous = self.identity_hashes.setdefault(identity_sha, record_sha)
                self.counts['conflicting_document_id_records'] += previous != record_sha
            else:
                self.counts['missing_document_identity'] += 1
            when, annotations = source_time(row), rule_annotations(row)
            self.times[when['status']] += 1
            self.techniques.update(annotations['rule_technique_ids'])
            self.counts['rule_annotated_rows'] += bool(annotations['rule_technique_ids'])
            self.counts['invalid_annotation_rows'] += annotations['status'] != 'parsed'
            self.counts['sca_mitre_reference_rows'] += annotations['sca_mitre_references_present']
            self.counts['raw_log_missing'] += not bool(row['_source.full_log'].strip())
            decoder = safe_code(row.get('_source.decoder.name', ''))
            rule_id = safe_code(row['_source.rule.id'])
            self.rules[rule_id or 'unknown'] += 1
            group = canonical([decoder, rule_id, annotations['rule_technique_ids'],
                               annotations['sca_mitre_references_present'], when['status']])
            if duplicate:
                continue
            if group not in self.samples and len(self.samples) >= self.max_groups:
                self.counts['sampling_group_limit_rows'] += 1
                continue
            projection = {
                'source': {'file': entry['name'], 'url': entry['url'], 'file_sha256': file_sha,
                           'csv_record_number': number, 'physical_start_line': start_line,
                           'physical_end_line': end_line, 'csv_record_bytes_sha256': sha(raw),
                           'normalized_record_sha256': record_sha},
                'time': when, 'detector_annotations': annotations,
                'observation': {'decoder_name': decoder, 'rule_id': rule_id,
                                'rule_level': safe_code(row.get('_source.rule.level', '')),
                                'syscheck_event': safe_code(row.get('_source.syscheck.event', '')),
                                'audit_type': safe_code(row.get('_source.data.audit.type', '')),
                                'full_log_sha256': sha(row['_source.full_log'].encode()),
                                'full_log_copied': False},
                'review_status': 'coordinates_only_requires_original_event_review',
                'training_admitted': False,
            }
            chosen = self.samples[group]
            chosen.append(projection)
            chosen.sort(key=lambda x: x['source']['normalized_record_sha256'])
            del chosen[self.per_group:]
        result = {'name': entry['name'], 'url': entry['url'], 'bytes': len(data),
                  'provider_md5_verified': True, 'sha256': file_sha, 'rows': count,
                  'columns': len(header)}
        self.files.append(result)
        return result

    def result(self, spec_sha):
        samples = [x for key in sorted(self.samples) for x in self.samples[key]]
        return {'schema': 1, 'spec_sha256': spec_sha, 'counts': dict(self.counts),
                'files': self.files, 'time_status_counts': dict(self.times),
                'rule_technique_counts': dict(self.techniques), 'rule_counts': dict(self.rules),
                'unique_normalized_records': len(self.record_hashes),
                'unique_document_identities': len(self.identity_hashes),
                'sample_groups': len(self.samples), 'sample_records': len(samples),
                'samples': samples, 'training_examples_generated': 0,
                'independent_incident_gold_generated': 0}


def write_checkpoint(folder, review, spec_sha, code_sha):
    """Commit only fully verified files; a failed next file is never resumed."""
    state = {'spec_sha256': spec_sha, 'code_sha256': code_sha,
             'counts': dict(review.counts), 'times': dict(review.times),
             'techniques': dict(review.techniques), 'rules': dict(review.rules),
             'identity_hashes': review.identity_hashes,
             'record_hashes': sorted(review.record_hashes),
             'samples': dict(review.samples), 'files': review.files,
             'max_groups': review.max_groups, 'per_group': review.per_group}
    envelope = {'state': state, 'sha256': sha(canonical(state).encode())}
    temporary = folder / 'checkpoint.tmp'
    temporary.write_text(canonical(envelope) + '\n', encoding='utf-8')
    temporary.replace(folder / 'checkpoint.json')


def read_checkpoint(folder, spec, spec_sha, code_sha):
    envelope = json.loads((folder / 'checkpoint.json').read_text())
    state = envelope['state']
    if sha(canonical(state).encode()) != envelope['sha256']:
        raise ValueError('Checkpoint content hash mismatch')
    if state['spec_sha256'] != spec_sha or state['code_sha256'] != code_sha:
        raise ValueError('Checkpoint belongs to different source spec or code')
    expected = {x['name']: x for x in spec['files']}
    if len({x['name'] for x in state['files']}) != len(state['files']):
        raise ValueError('Checkpoint repeats source files')
    for checked in state['files']:
        entry = expected.get(checked['name'])
        if (entry is None or checked['url'] != entry['url'] or
                checked['bytes'] != entry['bytes'] or not checked['provider_md5_verified']):
            raise ValueError('Checkpoint source differs from manifest')
    if state['counts'].get('rows', 0) != sum(x['rows'] for x in state['files']):
        raise ValueError('Checkpoint row total mismatch')
    review = CorpusReview(state['max_groups'], state['per_group'])
    for name in ('counts', 'times', 'techniques', 'rules'):
        setattr(review, name, Counter(state[name]))
    review.identity_hashes = state['identity_hashes']
    review.record_hashes = set(state['record_hashes'])
    review.samples = defaultdict(list, state['samples'])
    review.files = state['files']
    return review


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--resume', action='store_true',
                        help='Resume only a checkpoint matching this exact spec and code')
    args = parser.parse_args()
    spec_raw = args.spec.read_bytes()
    spec = json.loads(spec_raw)
    if args.output.exists() and not args.resume:
        parser.error('Output already exists; use explicit resume for a matching partial run')
    if args.resume and (not (args.output / 'checkpoint.json').exists() or
                        (args.output / 'review.json').exists()):
        parser.error('No resumable partial review, or review already completed')
    if len({x['name'] for x in spec['files']}) != len(spec['files']):
        parser.error('Duplicate file manifest entries')
    if sum(x['bytes'] for x in spec['files']) > spec['max_total_bytes']:
        parser.error('Total exceeds pinned byte budget')
    for entry in spec['files']:
        if not (entry['url'].startswith('https://zenodo.org/api/records/10685642/files/')
                and Path(entry['name']).name == entry['name']
                and entry['bytes'] <= spec['max_file_bytes']):
            parser.error('Manifest source or size outside pinned scope')
    ca = Path('/etc/ssl/cert.pem')
    context = ssl.create_default_context(cafile=str(ca) if ca.is_file() else None)
    spec_sha, code_sha = sha(spec_raw), sha(Path(__file__).read_bytes())
    review = read_checkpoint(args.output, spec, spec_sha, code_sha) if args.resume else CorpusReview()
    args.output.mkdir(parents=True, exist_ok=args.resume)
    write_checkpoint(args.output, review, spec_sha, code_sha)
    checked_names = {x['name'] for x in review.files}
    for entry in spec['files']:
        if entry['name'] in checked_names:
            continue
        try:
            request = urllib.request.Request(entry['url'], headers={'User-Agent': 'SOC-source-review'})
            with urllib.request.urlopen(request, context=context, timeout=30) as response:
                data = response.read(entry['bytes'] + 1)
            checked = review.inspect(data, entry)
            del data
        except Exception as exc:
            failure = {'at_kst': datetime.now(KST).isoformat(), 'file': entry['name'],
                       'error': type(exc).__name__ + ': ' + str(exc),
                       'completed': False, 'last_checkpoint_excludes_failed_file': True}
            stamp = datetime.now(KST).strftime('%Y%m%dT%H%M%S%f')
            (args.output / ('failure-' + stamp + '.json')).write_text(canonical(failure) + '\n')
            raise
        write_checkpoint(args.output, review, spec_sha, code_sha)
        print(json.dumps({'at_kst': datetime.now(KST).isoformat(), 'checked': checked}), flush=True)
    result = review.result(sha(spec_raw))
    samples = result.pop('samples')
    (args.output / 'evidence_coordinates.jsonl').write_text(
        ''.join(canonical(x) + '\n' for x in samples), encoding='utf-8')
    result['completed_at_kst'] = datetime.now(KST).isoformat()
    result['source_family'] = spec['source_family']
    result['code_sha256'] = code_sha
    result['partition'] = spec['review_partition']
    result['evidence_coordinates_sha256'] = sha((args.output / 'evidence_coordinates.jsonl').read_bytes())
    (args.output / 'review.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    (args.output / 'NOTICE').write_text(
        'Linux-APT-Dataset-2024 by Sohaib Karim, DOI 10.5281/zenodo.10685642.\n'
        'Source license: CC BY 4.0, https://creativecommons.org/licenses/by/4.0/\n'
        'Related paper: Karim et al., Data in Brief 54 (2024), 110290, DOI 10.1016/j.dib.2024.110290.\n'
        'Project transformation: structural codes, source coordinates/hashes and rule annotations; '
        'original log text omitted. No institution-endorsed QA, attack gold or training examples.\n'
        'Offset-free timestamps remain unresolved; rule MITRE tags/SCA are not proof of attack.\n')
    (args.output / 'checkpoint.json').unlink()
    print(json.dumps({'completed': True, 'rows': result['counts']['rows'],
                      'sample_records': len(samples), 'output': str(args.output)}), flush=True)


if __name__ == '__main__':
    main()
