#!/usr/bin/env python3
"""Verify a bounded, pinned packet bundle and extract PCAP/PDF members only.

No packet transmission, payload-object extraction, software installation or
malware execution. Run as the Kali user, in a fresh, private experiment folder.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import zipfile

MAX_MEMBER = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAGICS = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
          b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def relative(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name:
        raise ValueError('unsafe member path')
    return p


def unpack(root, archive, expected_sha):
    if digest(archive) != expected_sha:
        raise ValueError('transport archive SHA mismatch')
    stage = root / 'imported'
    stage.mkdir(mode=0o700, exist_ok=False)
    with tarfile.open(archive, 'r:gz') as src:
        members = src.getmembers()
        names = [str(relative(m.name)) for m in members]
        if (len(names) != len(set(names)) or len(names) > 100 or
                sum(m.size for m in members) > MAX_TOTAL or
                any(not m.isfile() or m.size > MAX_MEMBER for m in members)):
            raise ValueError('unexpected transport members')
        for m, name in zip(members, names):
            p = stage / name
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with p.open('xb') as dst, src.extractfile(m) as f:
                shutil.copyfileobj(f, dst, 1024 * 1024)
            p.chmod(0o600)
    manifest = json.loads((stage / 'download-manifest.json').read_text())
    allowed = {'download-manifest.json', 'catalog.json'}
    for item in manifest['files']:
        name = str(relative(item['relative_path']))
        allowed.add(name)
        p = stage / name
        if (item['rc'] != 0 or not item['expected_size_match'] or
                p.stat().st_size != item['bytes'] or digest(p) != item['sha256']):
            raise ValueError('download manifest mismatch')
    if set(names) != allowed:
        raise ValueError('transport member allowlist mismatch')
    if digest(stage / 'catalog.json') != manifest['catalog_sha256']:
        raise ValueError('catalog SHA mismatch')
    return stage, manifest


def extract(root, catalog, manifest):
    captures, evidence, excluded = [], [], []
    cases = {c['id']: c for c in catalog['cases']}
    for item in manifest['files']:
        if item['kind'] not in ('capture', 'answers'):
            continue
        source = root / item['relative_path']
        case = cases[item['case']]
        generated = []
        if source.suffix == '.zip':
            with zipfile.ZipFile(source) as z:
                seen = set()
                for member in z.infolist():
                    name = relative(member.filename)
                    mode = member.external_attr >> 16
                    if stat.S_ISLNK(mode) or member.file_size > MAX_MEMBER:
                        raise ValueError('unsafe ZIP member')
                    wanted = (name.suffix.lower() in ('.pcap', '.pcapng', '.cap')
                              if item['kind'] == 'capture' else name.suffix.lower() == '.pdf')
                    if not wanted or member.is_dir():
                        excluded.append({'case': case['id'], 'member': member.filename,
                                         'reason': 'not an allowed packet/PDF member'})
                        continue
                    if name.name in seen:
                        raise ValueError('duplicate ZIP output name')
                    seen.add(name.name)
                    output = source.parent / name.name
                    with output.open('xb') as dst:
                        result = subprocess.run(
                            ['unzip', '-P', 'infected_' + case['archive_date'], '-p',
                             str(source), member.filename], stdout=dst, stderr=subprocess.PIPE,
                            timeout=75)
                    if result.returncode or output.stat().st_size != member.file_size:
                        raise ValueError('ZIP extraction/size verification failed')
                    output.chmod(0o600)
                    generated.append(output)
                if not generated:
                    raise ValueError('archive has no allowed member')
        elif source.suffix == '.gz':
            output = source.with_suffix('')
            with gzip.open(source, 'rb') as src, output.open('xb') as dst:
                count = 0
                for chunk in iter(lambda: src.read(1024 * 1024), b''):
                    count += len(chunk)
                    if count > MAX_MEMBER:
                        raise ValueError('gzip output exceeds limit')
                    dst.write(chunk)
            output.chmod(0o600)
            generated = [output]
        else:
            generated = [source]
        for p in generated:
            packet = item['kind'] == 'capture'
            with p.open('rb') as f:
                magic = f.read(5)
            if (packet and magic[:4] not in MAGICS) or (not packet and magic != b'%PDF-'):
                raise ValueError('unexpected file signature')
            row = {'case': case['id'], 'path': str(p.relative_to(root)),
                   'bytes': p.stat().st_size, 'sha256': digest(p)}
            (captures if packet else evidence).append(row)
    return {'captures': captures, 'answer_pdfs': evidence, 'excluded': excluded}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', required=True)
    p.add_argument('--bundle', required=True)
    p.add_argument('--sha256', required=True)
    args = p.parse_args()
    os.umask(0o077)
    root, archive = Path(args.root).resolve(), Path(args.bundle).resolve()
    assert root.is_dir() and archive.parent == root and not archive.is_symlink()
    stage, manifest = unpack(root, archive, args.sha256)
    result = extract(stage, json.loads((stage / 'catalog.json').read_text()), manifest)
    result.update(schema=1, transport_sha256=args.sha256,
                  files_verified=len(manifest['files']), root=str(stage))
    with (root / 'import-result.json').open('x') as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
