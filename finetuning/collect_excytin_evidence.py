"""Read selected CSV members of the pinned ExCyTIn ZIP over HTTP Range.

Do not download the whole archive, execute SQL, or install its environment.
Partial reads cannot verify the archive's full SHA256: record this limitation.
"""
import argparse
import csv
import io
import json
from pathlib import Path
import ssl
import stat
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile
from collect_defensive_sources import now, sha, safe_path, write

REVISION = '8bc9ce1f97f8a6880c815dfba76d88651ddb761a'
URL = f'https://huggingface.co/datasets/anandmudgerikar/excytin-bench/resolve/{REVISION}/data.zip'
SIZE = 280428179
ARCHIVE_SHA = '6b2a2247f5b25132a8ad716641438c42dc30e38b57ba764f97f22626e7be5f31'
BUDGET = 32 * 1024 * 1024
MEMBER_LIMIT = 16 * 1024 * 1024
TABLES = {'SecurityAlert', 'SecurityIncident', 'AlertEvidence', 'AlertInfo'}
METADATA = {
    'excytin-card-pinned.md': (f'https://huggingface.co/datasets/anandmudgerikar/excytin-bench/resolve/{REVISION}/README.md',
                               '44fb9ab9c369127ff4c78136e183635ba99691a74fc5b6724a7423e32ca05f89'),
    'excytin_transparency': (f'https://huggingface.co/datasets/anandmudgerikar/excytin-bench/resolve/{REVISION}/TRANSPARENCY_DOC.md',
                            '9dc28468f2add3ab4462a50d482dfa543ef01ba102bfb982b024d53d932c007d'),
    'CDLA-Permissive-2.0.txt': ('https://raw.githubusercontent.com/Community-Data-License-Agreements/Releases/main/CDLA-Permissive-2.0.txt',
                                '4531a67d443284d93ffed0803df5b10634aff21c3d77e381f2d48af01d875868')
}


def verify_metadata(data, expected_sha):
    if len(data)>65536 or sha(data)!=expected_sha: raise ValueError('Metadata/license digest differs')


def collect_metadata(root):
    root=Path(root).resolve()
    if not root.name.startswith('data-'): raise ValueError('Use ignored data-* folder')
    dest=root/'metadata';dest.mkdir(parents=True,exist_ok=True)
    context=ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').exists() else None)
    receipts=[]
    for name,(url,digest) in METADATA.items():
        p=dest/name
        if p.is_symlink(): raise ValueError('Unsafe metadata destination')
        if p.exists(): data=p.read_bytes()
        else:
            with urlopen(Request(url,headers={'User-Agent':'Groot-SOC-source-review/1.0'}),context=context,timeout=30) as response:
                if urlsplit(response.url).scheme!='https' or urlsplit(response.url).hostname not in ('huggingface.co','raw.githubusercontent.com'):
                    raise ValueError('Unexpected metadata redirect')
                data=response.read(65537)
        verify_metadata(data,digest)
        if not p.exists(): p.write_bytes(data)
        receipts.append({'path':name,'url':url,'bytes':len(data),'sha256':digest})
    write(dest/'required-metadata-receipt.json',receipts)
    return {'metadata_verified':len(receipts)}


def csv_records(data):
    # Provider SQL LOAD DATA specifies U+2756 delimiter and double-quote enclosure.
    # Never infer ordinary comma CSV: JSON cells and embedded newlines would corrupt it.
    reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig')), delimiter='❖', strict=True)
    headers = reader.fieldnames
    if not headers or len(headers) < 2 or len(headers) != len(set(headers)):
        raise ValueError('Unexpected or duplicate evidence headers')
    result = []
    while True:
        start_line = reader.line_num + 1
        try: row = next(reader)
        except StopIteration: break
        if None in row or any(v is None for v in row.values()):
            raise ValueError('Evidence column count mismatch')
        result.append((start_line, row))
    return result


def validate_range(status, header, start, end, size):
    if status != 206 or header != f'bytes {start}-{end}/{size}':
        raise ValueError('Server did not return the exact requested byte range')


class RemoteZip(io.RawIOBase):
    def __init__(self, url=URL, size=SIZE, budget=BUDGET):
        self.url, self.size, self.pos, self.bytes, self.budget = url, size, 0, 0, budget
        self.context = ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').exists() else None)
        self.receipts = []

    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self.pos

    def seek(self, offset, whence=0):
        target = offset if whence == 0 else self.pos + offset if whence == 1 else self.size + offset if whence == 2 else -1
        if not 0 <= target <= self.size:
            raise ValueError('Invalid ZIP seek')
        self.pos = target
        return target

    def read(self, n=-1):
        n = self.size - self.pos if n < 0 else min(n, self.size - self.pos)
        if n == 0: return b''
        if n > MEMBER_LIMIT or self.bytes + n > self.budget:
            raise ValueError('Selective download budget exceeded')
        start, end = self.pos, self.pos+n-1
        request = Request(self.url, headers={'User-Agent': 'Groot-SOC-source-review/1.0',
                          'Range': f'bytes={start}-{end}', 'Accept-Encoding': 'identity'})
        with urlopen(request, context=self.context, timeout=30) as response:
            host = urlsplit(response.url).hostname or ''
            if urlsplit(response.url).scheme != 'https' or not (host == 'huggingface.co' or host.endswith('.huggingface.co') or host.endswith('.xethub.hf.co') or host.endswith('.cdn.hf.co')):
                raise ValueError('Unexpected archive redirect')
            validate_range(response.status, response.headers.get('Content-Range'), start, end, self.size)
            data = response.read(n+1)
        if len(data) != n:
            raise ValueError('Range length mismatch')
        self.pos += n; self.bytes += n
        self.receipts.append({'start': start, 'end': end, 'bytes': n, 'sha256': sha(data)})
        return data


def member_record(item):
    name = item.filename.removesuffix('/')
    safe_path(name)
    if stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1:
        raise ValueError('Symlink/encrypted member not allowed')
    return {'path': item.filename, 'bytes': item.file_size, 'compressed_bytes': item.compress_size,
            'crc32': f'{item.CRC:08x}', 'header_offset': item.header_offset,
            'compression': item.compress_type}


def selected(name):
    p = Path(name)
    return p.suffix == '.csv' and p.stem in TABLES


def run(root, phase):
    root = Path(root).resolve()
    if not root.name.startswith('data-'): raise ValueError('Use an ignored data-* folder')
    if phase == 'metadata': return collect_metadata(root)
    if phase == 'collect': collect_metadata(root)
    target = root/'excytin-evidence'; target.mkdir(parents=True, exist_ok=True)
    reader = RemoteZip()
    with zipfile.ZipFile(reader) as archive:
        members = archive.infolist()
        if len(members) > 5000 or len({x.filename for x in members}) != len(members):
            raise ValueError('Invalid or excessive ZIP directory')
        listing = [member_record(x) for x in members]
        chosen = [x for x in members if selected(x.filename)]
        write(target/'index.json', {'url': URL, 'revision': REVISION, 'archive_bytes': SIZE,
                                   'declared_archive_sha256': ARCHIVE_SHA, 'archive_sha256_verified': False,
                                   'members': listing, 'selected': [member_record(x) for x in chosen]})
        results = []
        if phase == 'collect':
            if sum(x.compress_size for x in chosen) > BUDGET - reader.bytes:
                raise ValueError('Selected members exceed transfer budget')
            if sum(x.file_size for x in chosen) > 64*1024*1024 or any(x.file_size > MEMBER_LIMIT for x in chosen):
                raise ValueError('Selected members exceed extraction budget')
            for item in chosen:
                data = archive.read(item)  # CRC32 checked by zipfile; no extractall.
                if len(data) != item.file_size: raise ValueError('Member size mismatch')
                rows = csv_records(data)
                dest = target/'raw'/str(safe_path(item.filename))
                if dest.is_symlink() or not dest.resolve().is_relative_to((target/'raw').resolve()):
                    raise ValueError('Unsafe destination')
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.exists() and dest.read_bytes() != data: raise ValueError('Existing evidence differs')
                dest.write_bytes(data)
                if sha(dest.read_bytes()) != sha(data): raise ValueError('Stored member changed')
                results.append({**member_record(item), 'sha256': sha(data), 'rows': len(rows),
                                'crc32_verified': True, 'training_admitted': False})
                print(json.dumps({'member': item.filename, 'rows': len(rows), 'bytes': len(data)}), flush=True)
    receipt = {'at_kst': now(), 'phase': phase, 'url': URL, 'revision': REVISION,
               'declared_archive_sha256': ARCHIVE_SHA, 'archive_sha256_verified': False,
               'integrity_scope': 'Exact HTTPS ranges from pinned revision plus ZIP CRC32 and local SHA256; whole archive not fetched or hash-verified',
               'transferred_bytes': reader.bytes, 'range_receipts': reader.receipts,
               'files': results, 'source_instructions_executed': False, 'training_admitted': 0}
    write(target/(phase+'-receipt.json'), receipt)
    return {'phase': phase, 'archive_members': len(listing), 'selected_members': len(chosen),
            'selected_compressed_bytes': sum(x.compress_size for x in chosen),
            'selected_uncompressed_bytes': sum(x.file_size for x in chosen),
            'transferred_bytes': reader.bytes, 'files': len(results)}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--phase', choices=('index', 'collect', 'metadata'), required=True)
    a = p.parse_args()
    print(json.dumps(run(a.root, a.phase)))
