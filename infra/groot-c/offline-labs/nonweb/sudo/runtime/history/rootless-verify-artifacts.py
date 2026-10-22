import base64, datetime, email.utils, gzip, hashlib, io, json, lzma, re, subprocess, tarfile, tempfile
from pathlib import Path

ARCHIVE=Path('/var/tmp/capstone-lab-expansion-20261022/rootless-artifacts.tar')
EXPECTED='58a0822afa28f429ff3906648db5ca798ae1d21514386ed7121dde766bd8f0e9'
KEYRING=Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
KEYRING_SHA='80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31'
DOCKER_KEY='9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
def sha(b): return hashlib.sha256(b).hexdigest()
def require(value,code):
    if not value: raise RuntimeError(code)
def control(text):
    data={}; key=None
    for line in text.splitlines():
        if line.startswith((' ','\t')):
            require(key is not None,'control_continuation'); data[key]+='\n'+line.strip()
        elif line:
            key,separator,value=line.partition(':'); require(separator and key not in data,'control_field'); data[key]=value.strip()
    return data
def docker_key(armor):
    lines=armor.decode().splitlines(); require(lines[0]=='-----BEGIN PGP PUBLIC KEY BLOCK-----','key_armor')
    body=''.join(x for x in lines[1:] if x and not x.startswith(('Version:','Comment:','=','-----')))
    binary=base64.b64decode(body,validate=True); off=0; primaries=[]
    while off<len(binary):
        tag=binary[off]; off+=1; require(tag&128,'key_packet')
        if tag&64:
            tag &=63; size=binary[off]; off+=1
            if size==255: size=int.from_bytes(binary[off:off+4],'big'); off+=4
            elif 192<=size<224: size=((size-192)<<8)+binary[off]+192; off+=1
            else: require(size<192,'partial_key_packet')
        else:
            kind=tag&3; tag=(tag>>2)&15; require(kind!=3,'indefinite_key_packet')
            count=(1,2,4)[kind]; size=int.from_bytes(binary[off:off+count],'big'); off+=count
        packet=binary[off:off+size]; off+=size; require(len(packet)==size,'truncated_key')
        if tag==6:
            require(packet[0]==4 and size<65536,'key_version')
            primaries.append(hashlib.sha1(b'\x99'+size.to_bytes(2,'big')+packet).hexdigest().upper())
    require(primaries==[DOCKER_KEY],'docker_key_fingerprint')
    return binary

packed=ARCHIVE.read_bytes(); require(sha(packed)==EXPECTED,'transfer_sha')
files={}
with tarfile.open(fileobj=io.BytesIO(packed),mode='r:') as tar:
    for entry in tar.getmembers():
        require(entry.isfile() and re.fullmatch(r'[A-Za-z0-9_.+~-]+',entry.name) and entry.name not in files and entry.size<32*1024*1024,'tar_member')
        files[entry.name]=tar.extractfile(entry).read()
manifest=json.loads(files['acquisition.json'])
require(set(files)=={'acquisition.json'}|{x['name'] for x in manifest['sources']},'manifest_files')
for item in manifest['sources']:
    require(sha(files[item['name']])==item['sha256'] and len(files[item['name']])==item['size'],'source_sha')
keyring=KEYRING.read_bytes(); require(sha(keyring)==KEYRING_SHA,'ubuntu_keyring_sha')
results={}
with tempfile.TemporaryDirectory(prefix='capstone-rootless-verify-',dir='/var/tmp') as name:
    work=Path(name)
    (work/'ubuntu.gpg').write_bytes(keyring); (work/'docker.gpg').write_bytes(docker_key(files['docker.asc']))
    for repo,origin,suite,index,compression in [('ubuntu','Ubuntu','noble-updates','main/binary-amd64/Packages.xz','xz'),('docker','Docker','noble','stable/binary-amd64/Packages.gz','gz')]:
        (work/(repo+'.InRelease')).write_bytes(files[repo+'.InRelease'])
        output=work/(repo+'.Release')
        result=subprocess.run(['/usr/bin/gpgv','--homedir',name,'--keyring',str(work/(repo+'.gpg')),'--status-fd','1','--output',str(output),str(work/(repo+'.InRelease'))],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
        require(result.returncode==0 and '[GNUPG:] VALIDSIG ' in result.stdout,'signature_'+repo)
        release=control(output.read_text()); require(release['Origin']==origin and release['Suite']==suite
            and (release.get('Codename')=='noble' if repo=='ubuntu' else release.get('Codename','noble')=='noble'),'release_identity')
        now=datetime.datetime.now(datetime.timezone.utc); date=email.utils.parsedate_to_datetime(release['Date'])
        require(datetime.timedelta(hours=-1)<=now-date<=datetime.timedelta(days=14),'release_freshness')
        if 'Valid-Until' in release: require(now<email.utils.parsedate_to_datetime(release['Valid-Until']),'release_expired')
        hashes=[line.split() for line in release['SHA256'].splitlines() if len(line.split())==3 and line.split()[2]==index]
        require(len(hashes)==1,'signed_index_unique')
        data=files[repo+'.Packages.'+compression]
        require(hashes[0][:2]==[sha(data),str(len(data))],'signed_index_sha')
        plain=lzma.decompress(data,memlimit=128*1024*1024) if compression=='xz' else gzip.decompress(data)
        require(len(plain)<128*1024*1024,'index_size')
        entries=[control(p) for p in plain.decode().split('\n\n') if p.strip()]
        chosen=[]
        for expected in manifest['packages']:
            if (expected['Package']=='docker-ce-rootless-extras') != (repo=='docker'): continue
            found=[p for p in entries if all(p.get(k)==expected[k] for k in ('Package','Version','Architecture','Filename','SHA256','Size'))]
            require(len(found)==1,'signed_package_unique')
            blob=files[Path(expected['Filename']).name]
            require(sha(blob)==expected['SHA256'] and str(len(blob))==expected['Size'],'package_sha')
            chosen.append(expected)
        results[repo]={'signature_verified':True,'release_date':release['Date'],'packages':chosen}
    extras=next(x for x in manifest['packages'] if x['Package']=='docker-ce-rootless-extras')
    deb=work/'extras.deb'; deb.write_bytes(files[Path(extras['Filename']).name])
    result=subprocess.run(['/usr/bin/dpkg-deb','--fsys-tarfile',str(deb)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    require(result.returncode==0,'extras_read')
    binaries={}
    with tarfile.open(fileobj=io.BytesIO(result.stdout),mode='r:') as tar:
        for member in tar.getmembers():
            if member.name in ('./usr/bin/rootlesskit','./usr/bin/dockerd-rootless.sh','./usr/bin/dockerd-rootless-setuptool.sh'):
                require(member.isfile(),'extras_binary_type'); blob=tar.extractfile(member).read()
                binaries[Path(member.name).name]={'sha256':sha(blob),'size':len(blob)}
    require(set(binaries)=={'rootlesskit','dockerd-rootless.sh','dockerd-rootless-setuptool.sh'},'extras_binary_set')
results.update({'schema':1,'archive_sha256':EXPECTED,'docker_primary_key':DOCKER_KEY,'binaries':binaries,'installed':False})
print(json.dumps(results,sort_keys=True))
