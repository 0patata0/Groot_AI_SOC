#!/usr/bin/env python3
"""Stream pinned GUIDE v2 train data and retain deterministic incident groups.

This collects review evidence, not model inputs, answers, or training examples.
Only a verified EOF can establish coverage within the released training file.
"""
import argparse
import base64
from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import time
import urllib.request

KST = timezone(timedelta(hours=9))
BASE = 'https://www.kaggle.com/api/v1/datasets/download/Microsoft/microsoft-security-incident-prediction/'
TRAIN_URL = BASE + 'GUIDE_Train.csv?datasetVersionNumber=2'
RANK_URL = BASE + 'GUIDE_Test_Queue_Rankings.csv?datasetVersionNumber=2'
TRAIN_BYTES = 2425409087
PREFIX_BYTES = 1048576
PREFIX_SHA = '6923227d705e137f9d494ef996e13f3bfe836eeff443c331a428d449842a4026'
RANK_BYTES = 136325
RANK_SHA = 'e4ea9308f45821128a3cd446ab19e6559edfc50709e72034ce957b6f0e2e65d6'
SEED = 'groot-guide-v2-20261031'
COLUMNS = ('Id OrgId IncidentId AlertId Timestamp DetectorId AlertTitle Category '
           'MitreTechniques IncidentGrade ActionGrouped ActionGranular EntityType '
           'EvidenceRole DeviceId Sha256 IpAddress Url AccountSid AccountUpn '
           'AccountObjectId AccountName DeviceName NetworkMessageId EmailClusterId '
           'RegistryKey RegistryValueName RegistryValueData ApplicationId ApplicationName '
           'OAuthApplicationId ThreatFamily FileName FolderPath ResourceIdName ResourceType '
           'Roles OSFamily OSVersion AntispamDirection SuspicionLevel LastVerdict '
           'CountryCode State City').split()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def now():
    return datetime.now(KST).isoformat()


def atomic_json(path, data):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    tmp.replace(path)


def reserved_organizations(data):
    if len(data) != RANK_BYTES or sha(data) != RANK_SHA:
        raise ValueError('Ranking version/hash mismatch')
    reader = csv.DictReader(io.StringIO(data.decode('utf-8')))
    if reader.fieldnames != ['OrgId', 'IncidentId', 'QueueRank']:
        raise ValueError('Unexpected actual ranking schema')
    groups, pairs = {}, set()
    for row in reader:
        if None in row or not all(v and v.isdecimal() for v in row.values()):
            raise ValueError('Malformed ranking row')
        key = (row['OrgId'], row['IncidentId'])
        if key in pairs:
            raise ValueError('Duplicate ranking incident')
        pairs.add(key)
        groups.setdefault(row['OrgId'], []).append(int(row['QueueRank']))
    if len(pairs) != 9980 or len(groups) != 499 or any(
            sorted(ranks) != list(range(1, 21)) for ranks in groups.values()):
        raise ValueError('Ranking coverage mismatch')
    return set(groups)


def selected_key(org, incident, reserved, modulus=64):
    if not org.isdecimal() or not incident.isdecimal() or modulus < 1:
        raise ValueError('Invalid incident key/selection modulus')
    if org in reserved:
        return False
    digest = hashlib.sha256((SEED + '\0' + org + '\0' + incident).encode()).digest()
    return int.from_bytes(digest[:8], 'big') % modulus == 0


class VerifiedReader(io.RawIOBase):
    def __init__(self, source, expected, prefix_sha, *, prefix_bytes=PREFIX_BYTES,
                 deadline=None):
        self.source, self.expected = source, expected
        self.prefix_expected, self.prefix_bytes = prefix_sha, prefix_bytes
        self.deadline = deadline
        self.bytes_read = 0
        self.digest, self.prefix, self.md5 = hashlib.sha256(), hashlib.sha256(), hashlib.md5()
        self.complete = False

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise TimeoutError('Explicit acquisition deadline reached')
        block = self.source.read(min(len(buffer), self.expected - self.bytes_read + 1))
        if not block:
            if self.bytes_read != self.expected or self.prefix.hexdigest() != self.prefix_expected:
                raise ValueError('Source truncated or prefix changed')
            self.complete = True
            return 0
        remaining = max(0, self.prefix_bytes - self.bytes_read)
        self.prefix.update(block[:remaining])
        self.digest.update(block)
        self.md5.update(block)
        self.bytes_read += len(block)
        if self.bytes_read > self.expected:
            raise ValueError('Source exceeds pinned length')
        if self.bytes_read >= self.prefix_bytes and self.prefix.hexdigest() != self.prefix_expected:
            raise ValueError('Source prefix changed')
        buffer[:len(block)] = block
        return len(block)


def scan(stream, destination, reserved, *, modulus=64, output_limit=256*1024*1024,
         progress=None):
    """Retain every row of each selected key, including late and duplicate rows."""
    reader = csv.reader(stream, strict=True)
    if next(reader, None) != COLUMNS:
        raise ValueError('Unexpected GUIDE train columns')
    rows = kept = output_bytes = duplicates = 0
    grades, actions, groups, seen = Counter(), Counter(), {}, set()
    for values in reader:
        rows += 1
        if len(values) != len(COLUMNS):
            raise ValueError('Malformed CSV width at record ' + str(rows))
        record = dict(zip(COLUMNS, values))
        org, incident = record['OrgId'], record['IncidentId']
        grades[record['IncidentGrade']] += 1
        actions[record['ActionGrouped']] += 1
        if selected_key(org, incident, reserved, modulus):
            canonical = json.dumps(record, sort_keys=True, ensure_ascii=False,
                                   separators=(',', ':')).encode()
            digest = sha(canonical)
            duplicates += digest in seen
            seen.add(digest)
            item = {'record_ordinal': rows, 'csv_end_line': reader.line_num,
                    'parsed_record_sha256': digest, 'record': record}
            line = (json.dumps(item, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
            output_bytes += len(line)
            if output_bytes > output_limit:
                raise ValueError('Selected evidence exceeds explicit output limit')
            destination.write(line)
            kept += 1
            group = groups.setdefault((org, incident), {'rows': 0, 'grades': Counter(),
                                      'actions': Counter(), 'granular_actions': Counter()})
            group['rows'] += 1
            group['grades'][record['IncidentGrade']] += 1
            group['actions'][record['ActionGrouped']] += 1
            group['granular_actions'][record['ActionGranular']] += 1
        if progress and rows % 10000 == 0:
            progress({'source_records': rows, 'selected_records': kept,
                      'selected_incidents': len(groups), 'selected_bytes': output_bytes})
    summaries = [{'org_id': k[0], 'incident_id': k[1], **g,
                  'conflicting_nonempty_grades': len(set(g['grades']) - {''}) > 1}
                 for k, g in sorted(groups.items())]
    return {'source_records': rows, 'selected_records': kept,
            'selected_incidents': len(groups), 'selected_bytes': output_bytes,
            'selected_duplicate_records_preserved': duplicates,
            'source_grade_row_counts': grades, 'source_action_row_counts': actions,
            'groups': summaries, 'iterator_exhausted': True,
            'transport_eof_must_be_verified_separately': True}


def request(url, limit=None):
    headers = {'User-Agent': 'Groot-SOC-source-review/1.0', 'Accept-Encoding': 'identity'}
    if limit:
        headers['Range'] = 'bytes=0-' + str(limit-1)
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=900)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 1800:
        parser.error('Use an explicit 30..1800 second acquisition limit')
    os.umask(0o077)
    args.output.mkdir(parents=False, exist_ok=False)
    started = time.monotonic()
    state = {'started_at_kst': now(), 'status': 'running', 'training_examples_generated': 0,
             'source_url': TRAIN_URL, 'selection_seed': SEED, 'selection_modulus': 64,
             'source_file': 'GUIDE_Train.csv', 'source_version': 2,
             'original_test_file_read': False, 'raw_full_file_saved': False,
             'selection_uses_labels': False, 'ranked_organizations_excluded': True}
    def interrupted(signum, frame):
        raise TimeoutError('Acquisition interrupted or deadline reached')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(args.seconds)
    atomic_json(args.output/'progress.json', state)
    try:
        with request(RANK_URL, RANK_BYTES) as response:
            ranks = response.read(RANK_BYTES+1)
        reserved = reserved_organizations(ranks)
        (args.output/'rankings.csv').write_bytes(ranks)
        state['reserved_organizations'] = len(reserved)
        with request(TRAIN_URL) as response:
            if response.status != 200 or int(response.headers.get('Content-Length', '0')) != TRAIN_BYTES:
                raise ValueError('Expected full v2 train response with pinned byte length')
            state['transport_headers'] = {k: response.headers.get(k) for k in
                                          ('ETag', 'Last-Modified', 'Content-Length', 'x-goog-hash')}
            source = VerifiedReader(response, TRAIN_BYTES, PREFIX_SHA,
                                    deadline=started+args.seconds)
            def progress(counts):
                atomic_json(args.output/'progress.json', {**state, **counts,
                    'source_bytes_read': source.bytes_read, 'checked_at_kst': now()})
            with (args.output/'selected.partial.jsonl').open('wb') as dest:
                text = io.TextIOWrapper(io.BufferedReader(source, buffer_size=1024*1024),
                                        encoding='utf-8', newline='')
                result = scan(text, dest, reserved, progress=progress)
                dest.flush()
                os.fsync(dest.fileno())
            if not source.complete:
                raise ValueError('No verified transport EOF')
            provider_md5 = [p.strip()[4:] for p in response.headers.get('x-goog-hash','').split(',')
                            if p.strip().startswith('md5=')]
            if provider_md5 and provider_md5 != [base64.b64encode(source.md5.digest()).decode()]:
                raise ValueError('Provider MD5 does not match the complete stream')
            state.update(result, source_sha256=source.digest.hexdigest(),
                         source_md5=source.md5.hexdigest(), provider_md5_verified=bool(provider_md5),
                         source_bytes_read=source.bytes_read, source_eof_verified=True,
                         coverage='All released train rows for selected keys; not complete real-world incidents.',
                         selected_sha256=sha((args.output/'selected.partial.jsonl').read_bytes()))
        (args.output/'selected.partial.jsonl').replace(args.output/'selected.jsonl')
        state['status'] = 'collected_for_review'
    except BaseException as exc:
        state.update(status='failed', error=type(exc).__name__+': '+str(exc),
                     source_eof_verified=False)
        raise
    finally:
        signal.alarm(0)
        state['finished_at_kst'] = now()
        state['elapsed_seconds'] = round(time.monotonic()-started, 3)
        atomic_json(args.output/'manifest.json', state)
        atomic_json(args.output/'progress.json', {k: v for k, v in state.items() if k != 'groups'})


if __name__ == '__main__':
    main()
