"""Lossless dataset archives: explicit members, hashes, and safe fresh extraction.

No shell extraction, links, devices, traversal, duplicate or unexpected members.
This module does not grant training eligibility or alter existing archives.
"""
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

MANIFEST = 'archive_manifest.json'
MAX_TOTAL = 16 * 1024**3
MAX_MEMBERS = 50000


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()


def safe_name(name):
    p = PurePosixPath(name)
    if not isinstance(name,str) or not name or p.is_absolute() or '..' in p.parts or \
            str(p) != name or '\\' in name or '\x00' in name or name.endswith('/'):
        raise ValueError('unsafe archive path')
    return name


def build(output, files, kind):
    output = Path(output)
    if kind not in ('original','cleaned'): raise ValueError('unregistered archive kind')
    if output.exists(): raise ValueError('refuse overwrite; stage and verify first')
    if not files or len(files)>MAX_MEMBERS: raise ValueError('invalid member count')
    records=[]
    for name,path in sorted(files.items()):
        safe_name(name)
        if name == MANIFEST: raise ValueError('reserved manifest name')
        path=Path(path)
        if path.is_symlink() or not path.is_file(): raise ValueError('regular files only')
        stat=path.stat()
        records.append({'path':name,'bytes':stat.st_size,'sha256':digest(path),
                        'original_mode':stat.st_mode & 0o777,'original_mtime_ns':stat.st_mtime_ns})
    if sum(r['bytes'] for r in records)>MAX_TOTAL: raise ValueError('archive size budget exceeded')
    manifest={'schema':'groot-lossless-dataset-v1','kind':kind,'members':records,
              'training_eligible':False,'training_input_allowlist':[]}
    blob=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    with output.open('xb') as target, gzip.GzipFile(filename='',fileobj=target,mode='wb',mtime=0,compresslevel=6) as zipped, \
            tarfile.open(fileobj=zipped,mode='w',format=tarfile.PAX_FORMAT) as tar:
        info=tarfile.TarInfo(MANIFEST);info.size=len(blob);info.mode=0o600;tar.addfile(info,io.BytesIO(blob))
        for record in records:
            info=tarfile.TarInfo(record['path']);info.size=record['bytes'];info.mode=0o600
            with Path(files[record['path']]).open('rb') as source: tar.addfile(info,source)
    output.chmod(0o600)
    return {'kind':kind,'bytes':output.stat().st_size,'sha256':digest(output),
            'manifest_sha256':hashlib.sha256(blob).hexdigest(),
            'members':[MANIFEST]+[r['path'] for r in records],
            'uncompressed_bytes':sum(r['bytes'] for r in records),'files':len(records)}


def verify_extract(archive, receipt, destination):
    archive=Path(archive);destination=Path(destination)
    if destination.exists() or destination.is_symlink(): raise ValueError('fresh extraction directory required')
    if digest(archive)!=receipt['sha256']: raise ValueError('archive hash mismatch')
    allowed=receipt['members']
    if len(allowed)!=len(set(allowed)) or len(allowed)>MAX_MEMBERS+1: raise ValueError('invalid allowlist')
    with tarfile.open(archive,'r:gz') as tar:
        members=tar.getmembers(); names=[m.name for m in members]
        if len(names)!=len(set(names)) or set(names)!=set(allowed): raise ValueError('unexpected or duplicate members')
        if sum(m.size for m in members)>MAX_TOTAL+4*1024**2: raise ValueError('extraction size budget exceeded')
        for m in members:
            safe_name(m.name)
            if not m.isfile() or m.issym() or m.islnk() or m.size<0: raise ValueError('unsafe member type')
        member=tar.getmember(MANIFEST)
        if member.size>4*1024**2: raise ValueError('manifest too large')
        blob=tar.extractfile(member).read()
        if hashlib.sha256(blob).hexdigest()!=receipt['manifest_sha256']: raise ValueError('manifest hash mismatch')
        manifest=json.loads(blob)
        if manifest['schema']!='groot-lossless-dataset-v1' or manifest['kind']!=receipt['kind']:
            raise ValueError('unexpected manifest schema/kind')
        records={r['path']:r for r in manifest['members']}
        if len(records)!=len(manifest['members']) or set(records)!=(set(allowed)-{MANIFEST}):
            raise ValueError('manifest members mismatch')
        for m in members:
            if m.name!=MANIFEST and m.size!=records[m.name]['bytes']: raise ValueError('member size mismatch')
        destination.mkdir(parents=True,exist_ok=False,mode=0o700)
        for m in members:
            target=destination/m.name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            # Destination is new and controlled. Do not use tar.extract/extractall.
            with tar.extractfile(m) as source, target.open('xb') as out:
                for chunk in iter(lambda:source.read(1024*1024),b''): out.write(chunk)
            target.chmod(0o600)
            expected=receipt['manifest_sha256'] if m.name==MANIFEST else records[m.name]['sha256']
            if target.stat().st_size!=m.size or digest(target)!=expected: raise ValueError('restored member mismatch')
    return {'verified_files':len(members),'archive_sha256':receipt['sha256'],
            'training_eligible':False,'training_started':False}
