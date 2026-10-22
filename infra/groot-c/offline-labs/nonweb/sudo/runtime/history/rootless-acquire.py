import base64, gzip, hashlib, json, lzma, re, ssl, urllib.request
from pathlib import Path

DEST=Path(__file__).with_name('rootless-artifacts')
DEST.mkdir(mode=0o700,exist_ok=True)
SSL=ssl.create_default_context(cafile='/etc/ssl/cert.pem')
records=[]
def get(url,name,limit=32*1024*1024):
    path=DEST/name
    if path.exists() and name!='ubuntu.Packages.xz':
        data=path.read_bytes()
    else:
        request=urllib.request.Request(url,headers={'User-Agent':'capstone-rootless-provenance/1'})
        with urllib.request.urlopen(request,timeout=60,context=SSL) as response:
            if response.geturl().split('/')[2] != url.split('/')[2]: raise RuntimeError('cross_host_redirect')
            data=response.read(limit+1)
    if len(data)>limit: raise RuntimeError('download_limit')
    path.write_bytes(data)
    records.append({'name':name,'url':url,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    return data
def control(text):
    fields={}; key=None
    for line in text.splitlines():
        if line.startswith((' ','\t')):
            fields[key]+='\n'+line.strip()
        elif line:
            key,separator,value=line.partition(':')
            if not separator or key in fields: raise RuntimeError('duplicate_control_field')
            fields[key]=value.strip()
    return fields
def select(plain,package,version=None):
    entries=[control(p) for p in plain.decode().split('\n\n') if p.strip()]
    selected=[p for p in entries if p.get('Package')==package and p.get('Architecture')=='amd64'
              and (version is None or p.get('Version')==version)]
    if len(selected)!=1: raise RuntimeError('exact_package_selection_failed:'+package+':'+str(len(selected)))
    return selected[0]

ubuntu='https://archive.ubuntu.com/ubuntu/'
release=get(ubuntu+'dists/noble-updates/InRelease','ubuntu.InRelease').decode()
index=[line.split()[0] for line in release.splitlines() if re.fullmatch(r' [a-f0-9]{64}\s+\d+\s+main/binary-amd64/Packages.xz',line)]
if len(index)!=1: raise RuntimeError('ubuntu_index_digest')
packed=get(ubuntu+'dists/noble-updates/main/binary-amd64/by-hash/SHA256/'+index[0],'ubuntu.Packages.xz')
if hashlib.sha256(packed).hexdigest()!=index[0]: raise RuntimeError('ubuntu_index_digest_mismatch')
plain=lzma.decompress(packed,memlimit=128*1024*1024)
if len(plain)>128*1024*1024: raise RuntimeError('metadata_output_limit')
selected=[]
for name in ('uidmap','libsubid4'):
    entry=select(plain,name)
    filename=entry['Filename']
    if not re.fullmatch(r'pool/main/s/shadow/[A-Za-z0-9_.+~-]+\.deb',filename): raise RuntimeError('ubuntu_path')
    data=get(ubuntu+filename,Path(filename).name,4*1024*1024)
    if str(len(data))!=entry['Size'] or hashlib.sha256(data).hexdigest()!=entry['SHA256']: raise RuntimeError('deb_hash')
    selected.append({k:entry[k] for k in ('Package','Version','Architecture','Filename','Size','SHA256','Depends')})
if selected[0]['Version']!=selected[1]['Version']: raise RuntimeError('shadow_version_mismatch')

docker='https://download.docker.com/linux/ubuntu/'
get(docker+'gpg','docker.asc',64*1024)
get(docker+'dists/noble/InRelease','docker.InRelease')
packed=get(docker+'dists/noble/stable/binary-amd64/Packages.gz','docker.Packages.gz')
plain=gzip.decompress(packed)
entry=select(plain,'docker-ce-rootless-extras','5:29.8.1-1~ubuntu.24.04~noble')
filename=entry['Filename']
if not re.fullmatch(r'dists/noble/pool/stable/amd64/docker-ce-rootless-extras_29\.8\.1-1~ubuntu\.24\.04~noble_amd64\.deb',filename): raise RuntimeError('docker_path')
data=get(docker+filename,Path(filename).name,32*1024*1024)
if str(len(data))!=entry['Size'] or hashlib.sha256(data).hexdigest()!=entry['SHA256']: raise RuntimeError('docker_deb_hash')
selected.append({k:entry[k] for k in ('Package','Version','Architecture','Filename','Size','SHA256','Depends')})
manifest={'schema':1,'sources':records,'packages':selected,'signature_verified':False,
          'next':'C gpgv verification required before extracting or installing'}
(DEST/'acquisition.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
print(json.dumps(manifest,sort_keys=True))
