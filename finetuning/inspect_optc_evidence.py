"""Inspect a bounded OpTC gzip prefix without inventing incident labels.

The caller supplies bytes from offset zero plus the provider file size. No
network, training, or executable log content is used here. Partial input is
explicitly distinguished from a verified complete gzip stream.
"""
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
import zlib

KST = timezone(timedelta(hours=9))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def observed_time(record):
    values = []
    for key in ('timestamp', 'timestamp_ms'):
        if key not in record:
            continue
        value = record[key]
        if key == 'timestamp' and isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError('Timestamp has no explicit timezone')
        elif type(value) in (int, float) and 10**12 <= value < 10**13:
            # Documented epoch milliseconds; never infer seconds or a local zone.
            parsed = datetime.fromtimestamp(value / 1000, timezone.utc)
        else:
            raise ValueError('Unsupported timestamp representation')
        values.append(parsed)
    if not values:
        raise ValueError('Missing timestamp')
    if any(abs((v - values[0]).total_seconds()) > 0.001 for v in values[1:]):
        raise ValueError('Conflicting timestamp fields')
    return values[0]


def host_key(value):
    return value.split('.', 1)[0].casefold() if isinstance(value, str) else None


def scan_records(lines, *, source_id, target_host, start, end, progress=None,
                 max_line_bytes=4*1024*1024):
    """Scan an entire iterator with bounded samples, keeping out-of-order events.

    start/end are an explicitly supplied review hypothesis, not provider gold.
    Integrity/EOF is the transport caller's responsibility. The result alone
    never certifies that the original file was read in full.
    """
    start, end = observed_time({'timestamp': start}), observed_time({'timestamp': end})
    if start >= end or not target_host or not source_id:
        raise ValueError('Invalid source, host or review interval')
    counts = Counter({'lines': 0, 'parsed': 0, 'rejected': 0, 'unknown_time': 0,
                      'target_host': 0, 'target_window': 0, 'time_regressions': 0})
    hosts, kinds, selected_groups, matches = [Counter() for _ in range(4)]
    samples, selected_coordinates = [], set()
    digest = hashlib.sha256()
    offset, previous, first, last = 0, None, None, None
    markers = ('runme.bat', 'powershell.exe', 'lsass.exe', 'windir', '\\currentversion\\debug')
    for number, line in enumerate(lines, 1):
        if len(line) > max_line_bytes:
            raise ValueError('Line size exceeds explicit limit')
        digest.update(line); counts['lines'] += 1
        try:
            record = json.loads(line)
            if not isinstance(record, dict):raise ValueError('Not an object')
        except (ValueError, UnicodeError):
            counts['rejected'] += 1; offset += len(line); continue
        counts['parsed'] += 1
        hosts[host_key(record.get('hostname')) or '<missing>'] += 1
        try: at = observed_time(record)
        except (ValueError, OSError, OverflowError):
            at = None; counts['unknown_time'] += 1
        if at is not None:
            if previous is not None and at < previous:counts['time_regressions'] += 1
            previous = at
            first = at if first is None or at < first else first
            last = at if last is None or at > last else last
        if host_key(record.get('hostname')) == host_key(target_host):
            counts['target_host'] += 1
            if at is not None and start <= at <= end:
                counts['target_window'] += 1
                kind = str(record.get('object', '<missing>'))+':'+str(record.get('action', '<missing>'))
                kinds[kind] += 1
                props = record.get('properties')
                props = props if isinstance(props, dict) else {}
                # Search the actual strings, not JSON-escaped path separators.
                values = '\n'.join(str(v) for v in props.values()).casefold()
                found = [marker for marker in markers if marker in values]
                pid_match = str(record.get('pid')) in ('5452', '2952')
                c2_match = props.get('dest_ip') == '132.197.158.98'
                groups = ['object:'+kind] + ['artifact:'+m for m in found]
                if pid_match:groups.append('reported_pid')
                if c2_match:groups.append('reported_c2_ip')
                matches.update(groups)
                eligible = [g for g in groups if selected_groups[g] < (12 if g.startswith('reported_') else 4)]
                if eligible and number not in selected_coordinates:
                    selected_coordinates.add(number); selected_groups.update(eligible)
                    samples.append({'source_id': source_id, 'line': number,
                                    'uncompressed_byte_offset': offset, 'raw_line_sha256': sha(line),
                                    'event_id': record.get('id'), 'actor_id': record.get('actorID'),
                                    'object_id': record.get('objectID'), 'object_action': kind,
                                    'timestamp_source': record.get('timestamp'),
                                    'timestamp_kst': at.astimezone(KST).isoformat(),
                                    'hostname': record.get('hostname'), 'pid': record.get('pid'),
                                    'ppid': record.get('ppid'), 'property_keys': sorted(props),
                                    'image_basename': str(props.get('image_path','')).replace('\\','/').rsplit('/',1)[-1][:128],
                                    'observed_reference_matches': groups[1:],
                                    'match_is_not_success_or_maliciousness_label': True,
                                    'selection_groups': eligible})
        offset += len(line)
        if progress is not None and number % 10000 == 0:
            progress(dict(counts), samples)
    if progress is not None:progress(dict(counts), samples)
    assert counts['lines'] == counts['parsed'] + counts['rejected']
    return {'source_id': source_id, 'counts': dict(counts), 'host_counts': dict(hosts),
            'review_interval_hypothesis': {'start': start.isoformat(), 'end': end.isoformat(),
                'provider_report_timezone_confirmed': False},
            'target_object_action_counts': dict(kinds), 'reference_match_counts': dict(matches),
            'metadata_samples': samples, 'decompressed_bytes': offset,
            'decompressed_sha256': digest.hexdigest(), 'iterator_exhausted': True,
            'source_file_completeness_requires_transport_verification': True,
            'min_observed_kst': first.astimezone(KST).isoformat() if first else None,
            'max_observed_kst': last.astimezone(KST).isoformat() if last else None,
            'training_examples_generated': 0, 'incident_labels_generated': 0}


def inspect_prefix(data, *, source_id, expected_file_bytes, target_host,
                   max_output_bytes=64 * 1024 * 1024, sample_limit=16):
    if not isinstance(data, bytes) or not data or len(data) > expected_file_bytes:
        raise ValueError('Invalid prefix or provider file size')
    if not source_id or not target_host or sample_limit < 1 or max_output_bytes < 1:
        raise ValueError('Invalid inspection limits or source identity')
    decoder = zlib.decompressobj(31)
    raw = decoder.decompress(data, max_output_bytes + 1)
    if len(raw) > max_output_bytes or decoder.unconsumed_tail:
        raise ValueError('Decompressed output limit reached; do not report a silent cutoff')
    if decoder.unused_data:
        raise ValueError('Multiple gzip members or trailing data require explicit handling')
    whole = len(data) == expected_file_bytes
    if whole and not decoder.eof:
        raise ValueError('Provider-size input ends before gzip integrity trailer')
    if decoder.eof and not whole:
        raise ValueError('Gzip ends before provider size; remainder not inspected')
    lines = raw.splitlines(keepends=True)
    tail = b''
    if lines and not lines[-1].endswith(b'\n') and not whole:
        tail = lines.pop()
    counts = Counter({'complete_lines': 0, 'parsed_objects': 0, 'rejected_lines': 0,
                      'unknown_timestamp': 0, 'missing_event_id': 0,
                      'duplicate_event_id': 0, 'target_host_records': 0})
    hosts, objects, target_objects, properties, representations = [Counter() for _ in range(5)]
    seen, sample_types, samples, rejected = set(), set(), [], []
    first = last = target_first = target_last = None
    offset = 0
    for number, line in enumerate(lines, 1):
        counts['complete_lines'] += 1
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError('Expected JSON object')
        except (ValueError, UnicodeError):
            counts['rejected_lines'] += 1
            if len(rejected) < sample_limit:
                rejected.append({'line': number, 'sha256': sha(line)})
            offset += len(line)
            continue
        counts['parsed_objects'] += 1
        host = host_key(record.get('hostname'))
        hosts[host or '<missing>'] += 1
        kind = str(record.get('object', '<missing>')) + ':' + str(record.get('action', '<missing>'))
        objects[kind] += 1
        for key in ('timestamp', 'timestamp_ms'):
            if key in record:
                representations[key + ':' + type(record[key]).__name__] += 1
        props = record.get('properties')
        if isinstance(props, dict):
            properties.update(props.keys())
        event_id = record.get('id')
        if not isinstance(event_id, str) or not event_id:
            counts['missing_event_id'] += 1
        elif event_id in seen:
            counts['duplicate_event_id'] += 1
        else:
            seen.add(event_id)
        try:
            observed = observed_time(record)
        except (ValueError, OverflowError, OSError):
            observed = None
            counts['unknown_timestamp'] += 1
        if observed is not None:
            first = observed if first is None or observed < first else first
            last = observed if last is None or observed > last else last
        if host == host_key(target_host):
            counts['target_host_records'] += 1
            target_objects[kind] += 1
            if observed is not None:
                target_first = observed if target_first is None or observed < target_first else target_first
                target_last = observed if target_last is None or observed > target_last else target_last
            if kind not in sample_types and len(samples) < sample_limit:
                sample_types.add(kind)
                # Do not copy arbitrary commands, URLs, credentials or payloads.
                samples.append({'source_id': source_id, 'line': number,
                                'uncompressed_byte_offset': offset, 'raw_line_sha256': sha(line),
                                'event_id': event_id, 'actor_id': record.get('actorID'),
                                'object_id': record.get('objectID'), 'object_action': kind,
                                'hostname': record.get('hostname'),
                                'timestamp_source': record.get('timestamp'),
                                'timestamp_ms_source': record.get('timestamp_ms'),
                                'timestamp_kst': observed.astimezone(KST).isoformat() if observed else None,
                                'pid': record.get('pid'), 'ppid': record.get('ppid'),
                                'property_keys': sorted(props) if isinstance(props, dict) else [],
                                'maliciousness': 'not_adjudicated', 'report_event_link': None})
        offset += len(line)
    assert counts['complete_lines'] == counts['parsed_objects'] + counts['rejected_lines']
    interval = lambda start, end: None if start is None else {
        'min_source': start.isoformat(), 'max_source': end.isoformat(),
        'min_kst': start.astimezone(KST).isoformat(), 'max_kst': end.astimezone(KST).isoformat()}
    return {'source_id': source_id, 'expected_file_bytes': expected_file_bytes,
            'compressed_prefix_bytes': len(data), 'compressed_prefix_sha256': sha(data),
            'decompressed_prefix_bytes': len(raw), 'decompressed_prefix_sha256': sha(raw),
            'whole_file_read': whole, 'gzip_integrity_verified': whole and decoder.eof,
            'coverage': 'whole_file' if whole else 'prefix_only',
            'partial_tail_bytes': len(tail), 'partial_tail_sha256': sha(tail) if tail else None,
            'counts': dict(counts), 'host_counts': dict(hosts), 'object_action_counts': dict(objects),
            'timestamp_representations': dict(representations), 'property_key_counts': dict(properties),
            'observed_time_range': interval(first, last), 'target_host': target_host,
            'target_time_range': interval(target_first, target_last),
            'target_object_action_counts': dict(target_objects), 'metadata_samples': samples,
            'rejected_line_samples': rejected, 'line_accounting_conserved': True,
            'incident_labels_generated': 0, 'training_examples_generated': 0}
