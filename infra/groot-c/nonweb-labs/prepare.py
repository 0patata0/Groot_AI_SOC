#!/usr/bin/env python3
"""Acquire official inputs or verify them into a network-free image context.

acquire is HTTPS acquisition, NOT signature approval. prepare requires gpgv and
an independently trusted Ubuntu keyring SHA. Neither installs host packages.
"""
import argparse
import base64
import concurrent.futures
import functools
import gzip
import hashlib
import io
import json
import lzma
import os
import posixpath
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import urllib.request

BASE=Path(__file__).resolve().parent
HEX=re.compile(r'[0-9a-f]{64}\Z')


def need(value,code):
    if not value:raise ValueError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def encode(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def read(path,limit=256*1024*1024):
    p=Path(path);s=p.lstat()
    need(p.is_file() and not p.is_symlink() and s.st_nlink==1 and s.st_size<=limit,'unsafe_input_file')
    raw=p.read_bytes();need(len(raw)==s.st_size,'input_changed');return raw


def control(raw):
    out={};key=None
    for line in raw.splitlines():
        if line.startswith((' ','\t')):
            need(key is not None,'control_continuation');out[key]+='\n'+line.strip()
        elif line:
            key,sep,value=line.partition(':');need(sep and key not in out,'duplicate_control_field');out[key]=value.strip()
    return out


def unpack_xz(raw):
    result=bytearray();streams=0
    while raw:
        streams+=1;need(streams<=1024,'xz_stream_limit')
        dec=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=128*1024*1024)
        result.extend(dec.decompress(raw,max_length=512*1024*1024-len(result)+1))
        need(dec.eof and len(result)<=512*1024*1024,'xz_output_limit')
        rest=dec.unused_data;raw=rest.lstrip(b'\0');need((len(rest)-len(raw))%4==0,'xz_padding')
    return bytes(result)


def compare_part(a,b):
    def order(c):return -1 if c=='~' else 0 if not c else ord(c) if c.isalpha() else ord(c)+256
    while a or b:
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            x=a[0] if a and not a[0].isdigit() else '';y=b[0] if b and not b[0].isdigit() else ''
            if order(x)!=order(y):return 1 if order(x)>order(y) else -1
            if x:a=a[1:]
            if y:b=b[1:]
        x=re.match('[0-9]*',a).group();y=re.match('[0-9]*',b).group();a=a[len(x):];b=b[len(y):]
        x=x.lstrip('0');y=y.lstrip('0')
        if len(x)!=len(y):return 1 if len(x)>len(y) else -1
        if x!=y:return 1 if x>y else -1
    return 0


def version_compare(a,b):
    def split(v):
        epoch,sep,rest=v.partition(':')
        if not sep:epoch,rest='0',v
        upstream,sep,revision=rest.rpartition('-')
        return int(epoch),upstream if sep else rest,revision if sep else '0'
    x,y=split(a),split(b)
    if x[0]!=y[0]:return 1 if x[0]>y[0] else -1
    return compare_part(x[1],y[1]) or compare_part(x[2],y[2])


def satisfies(version,op,wanted):
    if not op:return True
    n=version_compare(version,wanted)
    return {'=':n==0,'>=':n>=0,'<=':n<=0,'>>':n>0,'<<':n<0}[op]


def parse_dependency(text):
    m=re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)(?::(?:any|native|amd64))?(?:\s*\((>=|<=|=|>>|<<)\s*([^()\s]+)\))?',text.strip())
    need(m is not None,'unsupported_dependency_expression')
    return m.groups()


def indexes(root,source,releases=None):
    records={};proof=[]
    for suite in source['ubuntu_suites']:
        origin='https://security.ubuntu.com/ubuntu/' if suite=='focal-security' else 'https://archive.ubuntu.com/ubuntu/'
        for component in source['ubuntu_components']:
            name=suite+'-'+component+'-Packages.xz';raw=read(root/name,64*1024*1024)
            if releases is not None:
                release=control(releases[suite]);need(release.get('Origin')=='Ubuntu' and release.get('Suite')==suite and release.get('Codename')=='focal','release_identity')
                path=component+'/binary-amd64/Packages.xz'
                rows=[x.split() for x in release.get('SHA256','').splitlines() if len(x.split())==3 and x.split()[2]==path]
                need(len(rows)==1 and rows[0][:2]==[sha(raw),str(len(raw))],'signed_index_hash')
                proof.append({'suite':suite,'component':component,'packages_sha256':sha(raw),'release_date':release.get('Date')})
            for part in unpack_xz(raw).decode().split('\n\n'):
                if not part.strip():continue
                row=control(part)
                if row.get('Architecture') not in ('amd64','all'):continue
                need(re.fullmatch(r'pool/[a-zA-Z0-9+_./%~-]+\.deb',row.get('Filename','')) and '..' not in row['Filename'] and
                     HEX.fullmatch(row.get('SHA256','')) and row.get('Size','').isdigit(),'package_record_invalid')
                row['OriginURL']=origin;key=(row['Package'],row['Version'])
                if key in records:need(records[key]['SHA256']==row['SHA256'],'package_hash_conflict')
                records[key]=row
    return records,proof


def resolve(records,names,pinned=None):
    pinned=pinned or {};by_name={};provides={}
    for row in records.values():
        by_name.setdefault(row['Package'],[]).append(row)
        for value in row.get('Provides','').split(','):
            if value.strip():
                name,op,version=parse_dependency(value);provides.setdefault(name,[]).append((row,version if op=='=' else None))
    for rows in by_name.values():rows.sort(key=functools.cmp_to_key(lambda a,b:version_compare(a['Version'],b['Version'])),reverse=True)
    selected={};pending=[x for x in names]
    while pending:
        expr=pending.pop(0);chosen=None
        for alternative in expr.split('|'):
            name,op,wanted=parse_dependency(alternative)
            candidates=[(x,x['Version']) for x in by_name.get(name,[])]+provides.get(name,[])
            for row,provided_version in candidates:
                actual=row['Package']
                if actual in pinned and row['Version']!=pinned[actual]:continue
                if op and (provided_version is None or not satisfies(provided_version,op,wanted)):continue
                if actual in selected and selected[actual]['Version']!=row['Version']:continue
                chosen=row;break
            if chosen:break
        need(chosen is not None,'unsatisfied_dependency_'+expr)
        name=chosen['Package']
        if name in selected:continue
        selected[name]=chosen;need(len(selected)<=512,'dependency_closure_limit')
        for field in ('Pre-Depends','Depends'):
            pending += [x.strip() for x in chosen.get(field,'').split(',') if x.strip()]
    return [selected[k] for k in sorted(selected)]


def groups(records,source):
    fixed={x:source['redis']['package_version'] for x in ('redis-server','redis-tools')}
    return {'redis':resolve(records,source['redis']['packages'],fixed),
            'samba-build':resolve(records,source['samba']['build_packages']),
            'samba-runtime':resolve(records,source['samba']['runtime_packages'])}


def fetch(url,limit):
    need(url.startswith(('https://archive.ubuntu.com/ubuntu/','https://security.ubuntu.com/ubuntu/','https://download.samba.org/pub/samba/')),'download_origin')
    context=ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').exists() else None)
    with urllib.request.urlopen(url,context=context,timeout=90) as response:
        need(response.url.startswith(url.rsplit('/',1)[0]+'/'),'download_redirect')
        raw=response.read(limit+1);need(len(raw)<=limit,'download_size_limit');return raw


def acquire(args,source):
    need(not args.output.exists(),'new_output_required');args.output.mkdir(mode=0o700)
    for suite in source['ubuntu_suites']:
        origin='https://security.ubuntu.com/ubuntu/' if suite=='focal-security' else 'https://archive.ubuntu.com/ubuntu/'
        name=suite+'-InRelease'
        raw=read(args.metadata_from/name,8*1024*1024) if args.metadata_from else fetch(origin+'dists/'+suite+'/InRelease',8*1024*1024)
        (args.output/name).write_bytes(raw)
        for component in source['ubuntu_components']:
            name=suite+'-'+component+'-Packages.xz'
            raw=read(args.metadata_from/name,64*1024*1024) if args.metadata_from else fetch(origin+'dists/'+suite+'/'+component+'/binary-amd64/Packages.xz',64*1024*1024)
            (args.output/name).write_bytes(raw)
    records,_=indexes(args.output,source);closure=groups(records,source)
    unique={r['Filename']:r for rows in closure.values() for r in rows}
    need(sum(int(r['Size']) for r in unique.values())<=1024*1024*1024,'download_total_limit')
    (args.output/'debs').mkdir(mode=0o700)
    def one(row):
        raw=fetch(row['OriginURL']+row['Filename'],int(row['Size']))
        need(len(raw)==int(row['Size']) and sha(raw)==row['SHA256'],'download_deb_hash')
        (args.output/'debs'/Path(row['Filename']).name).write_bytes(raw)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(one,unique.values()))
    for name,meta in source['samba']['artifacts'].items():
        raw=fetch(meta['url'],meta['size']);need(len(raw)==meta['size'] and sha(raw)==meta['sha256'],'samba_artifact_pin')
        (args.output/name).write_bytes(raw)
    evidence={'schema':1,'source_sha256':sha(read(BASE/'sources.json')),'groups':closure,
              'signature_verified':False,'status':'acquired_pending_native_signature_verification'}
    (args.output/'acquisition.json').write_bytes(encode(evidence))
    return {'status':evidence['status'],'deb_count':len(unique),'deb_bytes':sum(int(r['Size']) for r in unique.values()),'output':str(args.output)}


def verify_signature(gpgv,keyring,signature,data=None):
    if keyring.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n'):
        # The exact official historical key file is pinned before this call.
        block=keyring.split(b'\n\n',1)[1].split(b'-----END PGP PUBLIC KEY BLOCK-----',1)[0]
        keyring=base64.b64decode(b''.join(x for x in block.splitlines() if x and not x.startswith(b'=')),validate=True)
    with tempfile.TemporaryDirectory(prefix='nonweb-signature-') as temp:
        root=Path(temp);(root/'keyring.gpg').write_bytes(keyring);(root/'signed').write_bytes(signature)
        command=[gpgv,'--homedir',str(root),'--keyring',str(root/'keyring.gpg'),'--status-fd','1']
        if data is None:command+=['--output',str(root/'plain'),str(root/'signed')]
        else:(root/'data').write_bytes(data);command += [str(root/'signed'),str(root/'data')]
        p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40)
        need(p.returncode==0 and len(p.stdout)<=65536 and b'[GNUPG:] VALIDSIG ' in p.stdout,'signature_invalid')
        return ((root/'plain').read_bytes() if data is None else None),p.stdout.decode()


def prepare(args,source):
    gpgv=shutil.which('gpgv');need(gpgv is not None,'gpgv_required_no_install_attempted')
    key=read(args.keyring,8*1024*1024);need(HEX.fullmatch(args.keyring_sha256) and sha(key)==args.keyring_sha256,'ubuntu_keyring_pin')
    releases={}
    for suite in source['ubuntu_suites']:
        plain,_=verify_signature(gpgv,key,read(args.assets/(suite+'-InRelease'),8*1024*1024));releases[suite]=plain.decode()
    records,proof=indexes(args.assets,source,releases);closure=groups(records,source)
    recorded=json.loads(read(args.assets/'acquisition.json'))
    need(recorded['source_sha256']==sha(read(BASE/'sources.json')) and recorded['groups']==closure,'acquisition_manifest_changed')
    payloads={}
    for rows in closure.values():
        for row in rows:
            name=Path(row['Filename']).name;raw=read(args.assets/'debs'/name)
            need(len(raw)==int(row['Size']) and sha(raw)==row['SHA256'],'verified_deb_hash');payloads[name]=raw
    samba={}
    for name,meta in source['samba']['artifacts'].items():
        raw=read(args.assets/name);need(len(raw)==meta['size'] and sha(raw)==meta['sha256'],'samba_artifact_pin');samba[name]=raw
    with gzip.GzipFile(fileobj=io.BytesIO(samba['samba-4.6.3.tar.gz'])) as stream:tar=stream.read(256*1024*1024+1)
    need(len(tar)<=256*1024*1024 and sha(tar)==source['samba']['uncompressed_tar_sha256'],'samba_tar_pin')
    _,status=verify_signature(gpgv,samba['samba-pubkey_6F33915B6568B7EA.asc'],samba['samba-4.6.3.tar.asc'],tar)
    valid=[x.split() for x in status.splitlines() if x.startswith('[GNUPG:] VALIDSIG ')]
    need(len(valid)==1 and valid[0][-1] in source['samba']['distribution_primary_fingerprints'],'samba_signer_pin')
    with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
        for item in archive:
            p=Path(item.name)
            need(not p.is_absolute() and '..' not in p.parts and p.parts[0]=='samba-4.6.3' and
                 not item.isdev() and not item.isfifo(),'samba_tar_path')
            if item.issym() or item.islnk():
                target=posixpath.normpath(posixpath.join(posixpath.dirname(item.name),item.linkname) if item.issym() else item.linkname)
                need(not item.linkname.startswith('/') and target.startswith('samba-4.6.3/'),'samba_tar_link')
    need(not args.output.exists(),'new_output_required');args.output.mkdir(mode=0o700)
    evidence={'schema':1,'source_sha256':sha(read(BASE/'sources.json')),'base_image':source['base_image'],
              'ubuntu_keyring_sha256':sha(key),'signed_indexes':proof,'packages':closure,
              'samba_artifacts':source['samba']['artifacts'],'samba_signature_verified':True,
              'samba_signer':valid[0][-1],'ubuntu_signatures_verified':True,
              'historical_package_authenticity_only':True,'attack_tested':False,'images_built':False}
    for lab in ('redis','samba'):
        dest=args.output/lab;dest.mkdir();(dest/'debs').mkdir()
        selected=closure['redis' if lab=='redis' else 'samba-build']
        for row in selected:
            name=Path(row['Filename']).name;(dest/'debs'/name).write_bytes(payloads[name])
        if lab=='samba':
            (dest/'runtime-debs').mkdir()
            for row in closure['samba-runtime']:
                name=Path(row['Filename']).name;(dest/'runtime-debs'/name).write_bytes(payloads[name])
            (dest/'samba-4.6.3.tar').write_bytes(tar)
        for name in ('Dockerfile','start.sh','verify.sh','redis.conf' if lab=='redis' else 'smb.conf'):
            (dest/name).write_bytes(read(BASE/lab/name))
        for name in ('terminal-session.sh','terminal-close.sh','terminal-lib.sh'):(dest/name).write_bytes(read(BASE/name))
        (dest/'provenance.json').write_bytes(encode(evidence))
        sums=[]
        for path in sorted(dest.rglob('*')):
            if path.is_file():sums.append(sha(read(path))+'  '+str(path.relative_to(dest)))
        (dest/'SHA256SUMS').write_text('\n'.join(sums)+'\n')
    (args.output/'provenance.json').write_bytes(encode(evidence))
    return {'status':'signature_verified_contexts_prepared','output':str(args.output),'images_built':False,'attack_tested':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('acquire');a.add_argument('--output',type=Path,required=True);a.add_argument('--metadata-from',type=Path)
    b=sub.add_parser('prepare')
    for name in ('assets','keyring','output'):b.add_argument('--'+name,type=Path,required=True)
    b.add_argument('--keyring-sha256',required=True)
    args=p.parse_args()
    try:
        source=json.loads(read(BASE/'sources.json'));result=globals()[args.command](args,source);print(json.dumps(result,sort_keys=True))
    except Exception as e:
        print(json.dumps({'status':'refused','reason':str(e) if isinstance(e,ValueError) else type(e).__name__,'images_built':False}));return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
