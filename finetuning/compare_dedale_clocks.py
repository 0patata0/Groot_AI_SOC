"""Compare DEDALE alert exports against timezone-explicit source syslog events.

This validates a candidate epoch-millisecond representation through event
content and multiplicity, not numeric width. It does not link attack incidents.
Source archive integrity and exhaustive iteration are the caller's responsibility.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

from link_dedale_labels import parse

CLOCKS = ('@timestamp', 'timestamp', 'timestamp8601')
ISO = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})')
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
KST = timezone(timedelta(hours=9))


def epoch_microseconds(value):
    if not isinstance(value, str) or not ISO.fullmatch(value):
        raise ValueError('Explicit ISO timestamp/offset required; no unit or zone guessing')
    delta = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc) - EPOCH
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds)


def normalized_event(row, *, representation):
    if row.get('program') != 'suricata':
        raise ValueError('Not a Suricata event')
    result = dict(row)
    if representation == 'source-iso':
        times = [epoch_microseconds(row.get(k)) for k in CLOCKS]
        if times[1] != times[2] or any(t // 1000 != times[0] // 1000 for t in times):
            raise ValueError('Source clock fields disagree beyond millisecond precision')
        for name, value in zip(CLOCKS, times):
            result[name] = value // 1000
    elif representation == 'export-integer':
        times = [row.get(k) for k in CLOCKS]
        if any(type(v) is not int for v in times) or len(set(times)) != 1:
            raise ValueError('Export must have three equal integer clock fields')
    else:
        raise ValueError('Unknown representation')
    # These are the only non-time field types normalized between the two exports.
    for name in ('@version', 'pid'):
        value = row.get(name)
        if isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]*', value):
            result[name] = int(value)
        elif type(value) is not int or value < 0:
            raise ValueError('Unexpected version/pid representation')
    return result


def event_key(row, *, representation):
    data = normalized_event(row, representation=representation)
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode()).digest()


def index_exports(lines):
    index = Counter(); digest = hashlib.sha256(); count = size = 0
    for line in lines:
        index[event_key(parse(line), representation='export-integer')] += 1
        count += 1; size += len(line); digest.update(line)
    return index, {'rows': count, 'unique_normalized_events': len(index),
                   'duplicate_instances': count - len(index),
                   'duplicate_scope': 'Normalized export only; not proof of duplicate precise source events.',
                   'bytes': size,
                   'sha256': digest.hexdigest()}


def compare_source(lines, remaining, *, source, sample_limit=2):
    counts = Counter({'rows': 0, 'suricata': 0, 'matched': 0, 'not_in_export_or_excess': 0})
    digest = hashlib.sha256(); md5 = hashlib.md5(); size = 0; samples = []
    for number, line in enumerate(lines, 1):
        row = parse(line); counts['rows'] += 1; digest.update(line); md5.update(line)
        if row.get('program') == 'suricata':
            counts['suricata'] += 1
            key = event_key(row, representation='source-iso')
            if remaining.get(key, 0) > 0:
                remaining[key] -= 1; counts['matched'] += 1
                if remaining[key] == 0:
                    del remaining[key]
                if len(samples) < sample_limit:
                    us = epoch_microseconds(row['@timestamp'])
                    samples.append({'source': source, 'line': number, 'byte_offset': size,
                                    'raw_line_sha256': hashlib.sha256(line).hexdigest(),
                                    'normalized_event_sha256': key.hex(),
                                    'source_timestamps': {k: row[k] for k in CLOCKS},
                                    'epoch_ms': us // 1000,
                                    'timestamp_kst': (EPOCH + timedelta(microseconds=us)).astimezone(KST).isoformat()})
            else:
                counts['not_in_export_or_excess'] += 1
        size += len(line)
    return {'source': source, 'counts': dict(counts), 'bytes': size,
            'sha256': digest.hexdigest(), 'md5': md5.hexdigest(), 'samples': samples,
            'iterator_exhausted': True}


def main():
    """Reproduce the full comparison using explicitly supplied, pinned archives."""
    import argparse
    import bz2
    import io
    from pathlib import Path
    import zipfile
    from link_dedale_labels import bounded_lines

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alerts-zip', type=Path, required=True)
    parser.add_argument('--syslog-zip', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output already exists; preserve previous evidence')
    expected_archives = {
        'alerts': (args.alerts_zip, 24596811, '4a5140ca94d5f73649dc3743a9806e255ffde21bb3669e93f1953337cf539128'),
        'syslog': (args.syslog_zip, 125537856, 'd7b94d9c6df0dbe22ac31ccc0898471d05d4bc5bc290dc4c224c757c1c373ea7'),
    }
    report = {'started_at_kst': datetime.now(KST).isoformat(), 'status': 'running',
              'archives': {}, 'members': []}
    # Reserve only a fresh evidence file. Input data is never modified or extracted.
    with args.output.open('x', encoding='utf-8') as destination:
        json.dump(report, destination)
    def save():
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    try:
        for name, (path, size, expected_sha) in expected_archives.items():
            if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
                raise ValueError('Missing, unsafe or unexpected '+name+' archive')
            sha = hashlib.sha256(); md5 = hashlib.md5()
            with path.open('rb') as source:
                for chunk in iter(lambda: source.read(1024*1024), b''):
                    sha.update(chunk); md5.update(chunk)
            if sha.hexdigest() != expected_sha:
                raise ValueError('Pinned SHA mismatch: '+name)
            report['archives'][name] = {'bytes': size, 'sha256': sha.hexdigest(), 'md5': md5.hexdigest()}
        with zipfile.ZipFile(args.alerts_zip) as archive, archive.open('suricata_alerts.jsonl') as source:
            remaining, report['export'] = index_exports(bounded_lines(source, max_bytes=1024**3))
        totals = Counter(); raw_bytes = 0
        with zipfile.ZipFile(args.syslog_zip) as archive:
            checksum_lines = archive.read('daily_syslog/syslog_md5sum.sig').decode().splitlines()
            expected = {}
            for line in checksum_lines:
                digest, name = line.split(); name = name.removeprefix('./')
                if name in expected or not re.fullmatch('[0-9a-f]{32}', digest):
                    raise ValueError('Invalid checksum manifest')
                expected[name] = digest
            names = sorted(n for n in archive.namelist() if n.endswith('.jsonl.bz2'))
            if len(names) != 672 or {Path(n).name.removesuffix('.bz2') for n in names} != set(expected):
                raise ValueError('Unexpected source member set')
            for number, name in enumerate(names, 1):
                compressed = archive.read(name)  # Full member read verifies ZIP CRC.
                with bz2.BZ2File(io.BytesIO(compressed), 'rb') as source:
                    item = compare_source(bounded_lines(source, max_bytes=512*1024*1024),
                                          remaining, source=name, sample_limit=1)
                if item['md5'] != expected[Path(name).name.removesuffix('.bz2')]:
                    raise ValueError('Source JSONL MD5 mismatch')
                item['provided_raw_md5_verified'] = True
                item['zip_member_crc_verified'] = True
                report['members'].append(item); totals.update(item['counts']); raw_bytes += item['bytes']
                if raw_bytes > 16*1024**3:
                    raise ValueError('Decoded byte budget exceeded')
                if number % 96 == 0:
                    report['counts'] = dict(totals); save()
                    print(json.dumps({'members': number, 'matched': totals['matched'],
                                      'at_kst': datetime.now(KST).isoformat()}), flush=True)
        report.update({'status': 'complete', 'completed_at_kst': datetime.now(KST).isoformat(),
                       'counts': dict(totals), 'source_decoded_bytes': raw_bytes,
                       'remaining_export_instances': sum(remaining.values()),
                       'representation_verified': not remaining and totals['not_in_export_or_excess'] == 0,
                       'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
        save()
        print(json.dumps({k: v for k, v in report.items() if k != 'members'}), flush=True)
    except Exception as error:
        report.update({'status': 'failed', 'error': type(error).__name__+': '+str(error)})
        save()
        raise


if __name__ == '__main__':
    main()
