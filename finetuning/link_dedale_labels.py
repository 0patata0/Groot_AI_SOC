"""Link provider-selected DEDALE events to exact original JSON records.

No label inference, training split, raw command export, or network access.
The caller must separately verify archive/member integrity and consume EOF.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json

KST = timezone(timedelta(hours=9))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def parse(line):
    row = json.loads(line, object_pairs_hook=no_duplicates,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    if not isinstance(row, dict):
        raise ValueError('Expected JSON object')
    return row


def fingerprint(row):
    return sha(json.dumps(row, ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'), allow_nan=False).encode())


def observed_time(row):
    value = row.get('@timestamp')
    if not isinstance(value, str):
        raise ValueError('Missing event timestamp')
    at = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValueError('Timestamp has no explicit timezone')
    return at


def identity(row):
    host = row.get('host')
    if not isinstance(host, dict) or not isinstance(host.get('name'), str) or not host['name']:
        raise ValueError('Missing host identity')
    observed_time(row)
    return row['@timestamp'], host['name']


def index_labels(lines, *, member, max_line_bytes=4*1024*1024):
    """Keep hashes/coordinates only; do not copy message or command contents."""
    result, digest, offset = {}, hashlib.sha256(), 0
    for number, line in enumerate(lines, 1):
        if len(line) > max_line_bytes:
            raise ValueError('Label line exceeds limit')
        row = parse(line); key = identity(row); item = fingerprint(row)
        if item in result:
            raise ValueError('Duplicate provider label record')
        result[item] = {'member': member, 'line': number, 'byte_offset': offset,
                        'raw_line_sha256': sha(line), 'identity': key,
                        'timestamp_source': row['@timestamp'],
                        'timestamp_kst': observed_time(row).astimezone(KST).isoformat()}
        digest.update(line); offset += len(line)
    return result, {'member': member, 'records': len(result), 'bytes': offset,
                    'sha256': digest.hexdigest()}


def validate_subset(class1, combined):
    if not set(class1) <= set(combined):
        raise ValueError('Class 1 is not a subset of combined provider labels')
    return {'class_1': len(class1), 'class_1_and_2': len(combined),
            'class_2_only': len(set(combined) - set(class1))}


def bounded_lines(stream, *, max_line_bytes=4*1024*1024, max_bytes=4*1024**3):
    """Require full stream EOF; never silently cut an over-budget member."""
    if max_line_bytes < 1 or max_bytes < 1:
        raise ValueError('Invalid byte limit')
    total = 0
    while True:
        line = stream.readline(max_line_bytes + 1)
        if not line:
            return
        total += len(line)
        if len(line) > max_line_bytes or total > max_bytes:
            raise ValueError('Raw decompression/line budget exceeded')
        yield line


def scan_raw_member(lines, *, labels, class1, member, start, end,
                    on_match=None, progress=None):
    """Exact full-object match; same host/time with different content is not a match.

    Explicit [start,end) selects reviewed labels, not a claimed file boundary.
    Other raw events are unlabelled in this view, never automatically benign.
    """
    start = observed_time({'@timestamp': start}); end = observed_time({'@timestamp': end})
    if start >= end:
        raise ValueError('Invalid review interval')
    validate_subset(class1, labels)
    target = {h: x for h, x in labels.items()
              if start <= observed_time({'@timestamp': x['timestamp_source']}) < end}
    wanted = defaultdict(set)
    for h, x in target.items():
        wanted[x['identity']].add(h)
    counts = Counter({'rows': 0, 'invalid_identity_or_time': 0, 'out_of_window': 0,
                      'same_identity_different_content': 0, 'matched_rows': 0,
                      'time_regressions': 0})
    matched = Counter(); digest = hashlib.sha256(); offset = 0
    first = last = previous = None
    for number, line in enumerate(lines, 1):
        row = parse(line); counts['rows'] += 1; digest.update(line)
        try:
            key = identity(row); at = observed_time(row)
        except (ValueError, TypeError, OverflowError):
            counts['invalid_identity_or_time'] += 1
            offset += len(line)
            continue
        if previous is not None and at < previous:
            counts['time_regressions'] += 1
        previous = at
        first = at if first is None or at < first else first
        last = at if last is None or at > last else last
        if not start <= at < end:
            counts['out_of_window'] += 1
        if key in wanted:
            h = fingerprint(row)
            if h in wanted[key]:
                matched[h] += 1; counts['matched_rows'] += 1
                if on_match:
                    proof = dict(target[h]); proof.pop('identity')
                    on_match({'raw_member': member, 'raw_line': number,
                              'raw_byte_offset': offset, 'raw_line_sha256': sha(line),
                              'canonical_event_sha256': h,
                              'label': proof, 'provider_class_1': h in class1,
                              'provider_class_2_only': h not in class1})
            else:
                counts['same_identity_different_content'] += 1
        offset += len(line)
        if progress and number % 100000 == 0:
            progress(dict(counts))
    return {'raw_member': member, 'counts': dict(counts), 'bytes': offset,
            'sha256': digest.hexdigest(), 'iterator_exhausted': True,
            'expected_label_records': len(target), 'matched_unique_records': len(matched),
            'missing_label_hashes': sorted(set(target)-set(matched)),
            'duplicate_matches': sum(n-1 for n in matched.values()),
            'matched_class_1': sum(h in class1 for h in matched),
            'matched_class_2_only': sum(h not in class1 for h in matched),
            'min_observed_kst': first.astimezone(KST).isoformat() if first else None,
            'max_observed_kst': last.astimezone(KST).isoformat() if last else None,
            'unmatched_rows_are_not_benign_labels': True,
            'training_admitted': 0,
            'integrity_scope': 'Caller must verify archive/member CRC and compression EOF separately.'}
