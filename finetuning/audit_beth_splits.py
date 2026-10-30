"""Audit pinned BETH process CSVs without extracting logs or admitting training data.

Full-feature equality and equality after a shared-column projection are reported
separately. Neither establishes episode independence or correctness of labels.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import io
import itertools
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import zipfile

BASE = {'timestamp', 'processId', 'parentProcessId', 'userId', 'processName',
        'hostName', 'eventId', 'eventName', 'argsNum', 'returnValue', 'args'}
EXTRA = {'threadId', 'mountNamespace', 'stackAddresses'}
LABELS = {'sus', 'evil'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


class Meter(io.RawIOBase):
    def __init__(self, source, limit):
        self.source, self.limit = source, limit
        self.size = 0
        self.digest = hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.source.read(len(buffer))
        self.size += len(data)
        require(self.size <= self.limit, 'Raw byte limit exceeded')
        self.digest.update(data)
        buffer[:len(data)] = data
        return len(data)


@contextmanager
def csv_stream(path, item):
    # ZIP member is streamed; paths from an archive are never extracted.
    if item['format'] == 'zip':
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            require(len(infos) == 1 and infos[0].filename == item['member'],
                    'Unexpected ZIP members')
            require(infos[0].file_size == item['raw_bytes'], 'ZIP size mismatch')
            require(infos[0].CRC == item['provider_crc32'], 'ZIP CRC metadata mismatch')
            with z.open(infos[0]) as f:
                meter = Meter(f, item['raw_bytes'])
                with io.TextIOWrapper(io.BufferedReader(meter), encoding='utf-8', newline='') as text:
                    yield csv_reader(text), meter
    else:
        require(item['format'] == 'csv', 'Unsupported container format')
        with path.open('rb') as f:
            meter = Meter(f, item['raw_bytes'])
            with io.TextIOWrapper(io.BufferedReader(meter), encoding='utf-8', newline='') as text:
                yield csv_reader(text), meter


def csv_reader(text):
    import csv
    return csv.reader(text, strict=True)


def header(reader):
    columns = next(reader, [])
    require(len(columns) == len(set(columns)), 'Duplicate CSV columns')
    require(set(columns) in (BASE | LABELS, BASE | EXTRA | LABELS),
            'Unexpected BETH process schema')
    return columns


def signature(row, columns):
    # Exact strings, including empty and "0", remain distinct. Labels excluded.
    data = json.dumps([[k, row[k]] for k in columns], ensure_ascii=False,
                      separators=(',', ':')).encode()
    return hashlib.sha256(data).digest()


def audit(manifest, directory, scratch):
    require(manifest.get('schema') == 1 and manifest.get('source') == 'BETH'
            and manifest.get('version') == 3, 'Unsupported manifest')
    items = manifest['files']
    parts = [x['partition'] for x in items]
    require(2 <= len(items) <= 4 and len(parts) == len(set(parts)), 'Invalid partitions')
    require(set(parts) <= {'train', 'validation', 'test', 'reference'}, 'Unknown partition')
    directory = Path(directory).resolve()
    paths, schemas = {}, {}
    for item in items:
        name = item['file']
        require(isinstance(name, str) and name == Path(name).name, 'Invalid file name')
        path = (directory / name).resolve()
        require(path.parent == directory and path.is_file(), 'Input outside directory')
        require(re.fullmatch('[a-f0-9]{64}', item['download_sha256']), 'Missing pinned SHA')
        require(path.stat().st_size == item['download_bytes'] and
                sha_file(path) == item['download_sha256'], 'Download hash/size mismatch')
        require(isinstance(item['raw_bytes'], int) and 0 < item['raw_bytes'] <= 512*1024*1024,
                'Invalid raw size')
        with csv_stream(path, item) as (reader, _):
            schemas[item['partition']] = header(reader)
        paths[item['partition']] = path
    shared = sorted(set.intersection(*(set(v) - LABELS for v in schemas.values())))
    reports = {}
    with tempfile.TemporaryDirectory(prefix='beth-digests-', dir=scratch) as work:
        db = sqlite3.connect(str(Path(work) / 'observations.sqlite3'))
        try:
            db.execute('PRAGMA journal_mode=OFF')  # Disposable scratch DB only.
            db.execute('PRAGMA synchronous=OFF')
            db.execute('CREATE TABLE obs(mode TEXT, digest BLOB, part TEXT, n INTEGER, mask INTEGER, '
                       'PRIMARY KEY(mode,digest,part)) WITHOUT ROWID')
            insert = ('INSERT INTO obs VALUES(?,?,?,?,?) ON CONFLICT(mode,digest,part) '
                      'DO UPDATE SET n=n+excluded.n,mask=mask|excluded.mask')
            for item in items:
                part = item['partition']
                labels, hosts, empty = Counter(), Counter(), Counter()
                ranges, batch, rows = {}, [], 0
                with csv_stream(paths[part], item) as (reader, meter):
                    columns = header(reader)
                    features = sorted(set(columns) - LABELS)
                    for values in reader:
                        require(len(values) == len(columns), 'CSV row width mismatch')
                        row = dict(zip(columns, values))
                        require(row['sus'] in ('0', '1') and row['evil'] in ('0', '1'),
                                'Nonbinary label')
                        t = Decimal(row['timestamp'])
                        require(t.is_finite() and t >= 0, 'Invalid uptime')
                        require(row['hostName'] != '', 'Missing host identity')
                        rows += 1
                        labels[row['sus'] + row['evil']] += 1
                        hosts[row['hostName']] += 1
                        empty.update(k for k, v in row.items() if v == '')
                        bounds = ranges.setdefault(row['hostName'], [t, t])
                        bounds[0], bounds[1] = min(bounds[0], t), max(bounds[1], t)
                        mask = 1 << (2 * int(row['sus']) + int(row['evil']))
                        for mode, fields in [('full_features', features), ('shared_projection', shared)]:
                            batch.append((mode, signature(row, fields), part, 1, mask))
                        if len(batch) >= 4096:
                            db.executemany(insert, batch)
                            batch.clear()
                    require(rows > 0 and meter.size == item['raw_bytes'], 'Empty or incomplete CSV')
                    raw_sha = meter.digest.hexdigest()
                if batch:
                    db.executemany(insert, batch)
                db.commit()
                reports[part] = {'rows': rows, 'columns': columns, 'feature_columns': features,
                                 'projection_omits': sorted(set(features) - set(shared)),
                                 'label_pairs_sus_evil': dict(labels), 'hosts': dict(hosts),
                                 'empty_fields': dict(empty), 'raw_bytes': meter.size,
                                 'raw_sha256': raw_sha, 'container_sha256': item['download_sha256'],
                                 'zip_crc_checked_on_full_read': item['format'] == 'zip',
                                 'uptime_ranges_by_host': {h: [str(v) for v in b] for h,b in ranges.items()}}
                print(json.dumps({'partition': part, 'rows_verified': rows}), flush=True)
            pairs = []
            for a, b in itertools.combinations(parts, 2):
                pair = {'partitions': [a, b], 'shared_host_names': sorted(set(reports[a]['hosts']) &
                                                                           set(reports[b]['hosts']))}
                for mode in ('full_features', 'shared_projection'):
                    n, left, right, matched, conflicting = db.execute(
                        'SELECT count(*),coalesce(sum(a.n),0),coalesce(sum(b.n),0),'
                        'coalesce(sum(min(a.n,b.n)),0),'
                        'coalesce(sum((a.mask|b.mask) NOT IN (1,2,4,8)),0) '
                        'FROM obs a JOIN obs b ON a.mode=b.mode AND a.digest=b.digest '
                        'WHERE a.part=? AND b.part=? AND a.mode=?', (a,b,mode)).fetchone()
                    pair[mode] = dict(zip(('unique_shared_signatures','left_rows','right_rows',
                                          'matched_multiplicity','conflicting_label_signatures'),
                                         (n,left,right,matched,conflicting)))
                pairs.append(pair)
            for part in parts:
                reports[part]['within_file'] = {}
                for mode in ('full_features','shared_projection'):
                    n, repeats, conflicts = db.execute(
                        'SELECT count(*),coalesce(sum(n-1),0),coalesce(sum(mask NOT IN (1,2,4,8)),0) '
                        'FROM obs WHERE part=? AND mode=?', (part,mode)).fetchone()
                    reports[part]['within_file'][mode] = {'unique_signatures':n,
                        'repeated_rows_beyond_first':repeats,'conflicting_label_signatures':conflicts}
        finally:
            db.close()
    return {'schema':1, 'checked_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(),
            'source':'BETH v3', 'shared_feature_columns':shared, 'files':reports, 'pairs':pairs,
            'training_admitted':0, 'model_calls':0,
            'scope':'Exact strings after CSV parsing; SHA256 signatures, not semantic/event identity proof.',
            'limits':['Shared projection can collapse observations when fields are absent; never call it full-row equality.',
                      'Labels are excluded from fingerprints and remain provider annotations, not certified truth.',
                      'Host names and uptime do not identify capture sessions without boot/capture provenance.',
                      'No timestamp conversion, label repair, deduplication, repartition or training occurs.',
                      'Statistically reviewed official test data is not automatically a new independent final test.']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','directory','scratch','output'):
        p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error('Output already exists')
    report = audit(json.loads(args.manifest.read_text()), args.directory, args.scratch)
    report['manifest_sha256'] = sha_file(args.manifest)
    with args.output.open('x') as f:
        json.dump(report,f,ensure_ascii=False,indent=2)
        f.write('\n')


if __name__ == '__main__':
    main()
