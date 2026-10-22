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

import os, pwd, grp, shutil, stat, time

USER='capstone-sudo'; UID=1991; GID=1991
RUNTIME_HOME=Path('/var/lib/capstone-sudo-runtime')
BIN=Path('/opt/capstone-sudo-rootless/29.8.1/bin')
EVIDENCE=Path('/var/lib/capstone-offline-labs/rootless-runtime-20261022')
APPARMOR=Path('/etc/apparmor.d/opt.capstone-sudo-rootless.29.8.1.bin.rootlesskit')
DROPIN=Path('/etc/systemd/system/user@1991.service.d')
CONF=Path('/etc/capstone-sudo-lab')
IMAGE='sha256:3a7816fe014c0a9e33b36b869dcd65b0e9662cb51f78271254b396502dd53ab7'
HOST_SUDO='install ok installed|1.8.31-1ubuntu1'
ROOTFUL_UNIT_SHA='fc3f399c2451c6da5ea536d9dfaf4f188b8f8e6f21aa791fd47763c849380c7d'
BASE_ENV={'PATH':'/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive','PYTHONDONTWRITEBYTECODE':'1'}
def run(args,timeout=40):
    p=subprocess.run(list(map(str,args)),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout,env=BASE_ENV)
    require(p.returncode==0,'command_failed:'+str(args[0])+':'+str(p.returncode))
    return p.stdout.strip()
def pkg(name):
    p=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${Status}|${Version}',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    return p.stdout.strip() if p.returncode==0 else None
def rootpath(path):
    for p in (path,)+tuple(path.parents):
        s=p.lstat(); require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'unsafe_root_directory')
def write(path,data,mode=0o644,owner=0,group=0):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f: f.write(data.encode() if isinstance(data,str) else data); f.flush(); os.fsync(f.fileno())
    os.chown(path,owner,group)
def user_run(args,timeout=40):
    return run(['/usr/sbin/runuser','-u',USER,'--','/usr/bin/env','-i',
                'PATH=/opt/capstone-sudo-rootless/29.8.1/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'HOME='+str(RUNTIME_HOME),'XDG_RUNTIME_DIR=/run/user/1991','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus',
                'LANG=C','LC_ALL=C','PYTHONDONTWRITEBYTECODE=1']+args,timeout)
require(os.geteuid()==0,'root_install_required')
require(pkg('sudo')==HOST_SUDO and sha(Path('/etc/systemd/system/docker.service').read_bytes())==ROOTFUL_UNIT_SHA,'protected_baseline_changed')
require(run(['/usr/bin/dpkg','--audit'])=='','preexisting_dpkg_audit')
for item in ('uidmap','libsubid4'): require(pkg(item) is None,'package_already_present')
for lookup,key in ((pwd.getpwuid,UID),(pwd.getpwnam,USER),(grp.getgrgid,GID),(grp.getgrnam,USER)):
    try: lookup(key)
    except KeyError: pass
    else: raise RuntimeError('dedicated_identity_already_present')
for path in (RUNTIME_HOME,BIN.parent,CONF,APPARMOR,DROPIN,EVIDENCE): require(not path.exists() and not path.is_symlink(),'install_path_exists')
for parent in ('/opt','/var/lib','/etc','/etc/apparmor.d','/etc/systemd/system','/var/lib/capstone-offline-labs'): rootpath(Path(parent))
subids={}
for name in ('subuid','subgid'):
    p=Path('/etc')/name; data=p.read_bytes(); subids[name]=data
    for line in data.decode().splitlines():
        if not line or line.startswith('#'): continue
        who,start,count=line.split(':'); start,count=int(start),int(count)
        require(who!=USER and max(start,231072)>=min(start+count,296608),'subid_range_conflict')
before_sysctl={p:Path('/proc/sys/'+p.replace('.','/')).read_text() for p in ('kernel.unprivileged_userns_clone','kernel.apparmor_restrict_unprivileged_userns')}
before_containers=json.loads(run(['/usr/local/bin/docker','container','ls','--all','--format','json']).replace('\n',',').join(('[',']')))
EVIDENCE.mkdir(mode=0o700)
artifacts=EVIDENCE/'artifacts'; artifacts.mkdir(mode=0o700)
for name,data in files.items(): write(artifacts/name,data,0o600)
write(EVIDENCE/'verification.json',json.dumps(results,sort_keys=True,indent=2)+'\n',0o600)
write(EVIDENCE/'baseline.json',json.dumps({'host_sudo':HOST_SUDO,'rootful_unit_sha':ROOTFUL_UNIT_SHA,'sysctl':before_sysctl,'containers':before_containers},sort_keys=True,indent=2)+'\n',0o600)
for name,data in subids.items(): write(EVIDENCE/(name+'.before'),data,0o600)
run(['/usr/bin/dpkg','-i',artifacts/'libsubid4_4.13+dfsg1-4ubuntu3.2_amd64.deb',artifacts/'uidmap_4.13+dfsg1-4ubuntu3.2_amd64.deb'],120)
require(pkg('sudo')==HOST_SUDO,'host_sudo_changed')
run(['/usr/sbin/groupadd','--gid',str(GID),USER])
run(['/usr/sbin/useradd','--system','--uid',str(UID),'--gid',str(GID),'--create-home','--home-dir',str(RUNTIME_HOME),'--shell','/usr/sbin/nologin','--no-log-init',USER])
os.chmod(RUNTIME_HOME,0o700)
for name,data in subids.items():
    p=Path('/etc')/name; require(p.read_bytes()==data,'unexpected_subid_mutation')
    with p.open('ab') as f:
        if data and not data.endswith(b'\n'): f.write(b'\n')
        f.write((USER+':231072:65536\n').encode()); f.flush(); os.fsync(f.fileno())
BIN.mkdir(mode=0o755,parents=True)
with tempfile.TemporaryDirectory(prefix='capstone-rootless-extract-',dir='/var/tmp') as tmp:
    extra=next(p for p in manifest['packages'] if p['Package']=='docker-ce-rootless-extras')
    deb=artifacts/Path(extra['Filename']).name
    result=subprocess.run(['/usr/bin/dpkg-deb','--fsys-tarfile',str(deb)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    require(result.returncode==0,'extras_tar_read')
    with tarfile.open(fileobj=io.BytesIO(result.stdout),mode='r:') as tar:
        for member in tar.getmembers():
            if member.name in ('./usr/bin/rootlesskit','./usr/bin/dockerd-rootless.sh','./usr/bin/dockerd-rootless-setuptool.sh'):
                blob=tar.extractfile(member).read(); name=Path(member.name).name
                require(sha(blob)==binaries[name]['sha256'],'binary_sha_changed'); write(BIN/name,blob,0o755)
require('3.1.0' in run([BIN/'rootlesskit','--version']),'rootlesskit_version')
write(APPARMOR,'abi <abi/4.0>,\ninclude <tunables/global>\n"'+str(BIN/'rootlesskit')+'" flags=(unconfined) {\n  userns,\n}\n')
run(['/usr/sbin/apparmor_parser','-r',APPARMOR])
DROPIN.mkdir(mode=0o755); write(DROPIN/'capstone-sudo.conf','[Service]\nDelegate=cpu memory pids\n')
CONF.mkdir(mode=0o755)
write(CONF/'config.json',json.dumps({'schema':1,'operator_uid':UID,'image_id':IMAGE,
 'deb_sha256':'de4106cd19a5b9f8acac9e0ab5f40f218d3ac321cc58143e051baab064a5fb36',
 'preparation_sha256':'8c69d341e14798ec161d093031f0ae54473d7d089166c3eedba6bbda0ce042ff'},sort_keys=True,indent=2)+'\n')
write(CONF/'daemon.json',json.dumps({'hosts':['unix:///run/user/1991/docker.sock'],'data-root':str(RUNTIME_HOME/'docker'),
 'exec-root':'/run/user/1991/docker-exec','pidfile':'/run/user/1991/docker.pid','bridge':'none','iptables':False,
 'ip6tables':False,'ip-forward':False,'ip-masq':False,'userland-proxy':False,'storage-driver':'vfs',
 'exec-opts':['native.cgroupdriver=systemd'],'log-driver':'json-file','log-opts':{'max-size':'1m','max-file':'2'}},sort_keys=True,indent=2)+'\n')
unitdir=RUNTIME_HOME/'.config/systemd/user'; unitdir.mkdir(mode=0o700,parents=True)
for p in (RUNTIME_HOME/'.config',RUNTIME_HOME/'.config/systemd',unitdir): os.chown(p,UID,GID); os.chmod(p,0o700)
write(unitdir/'capstone-sudo-docker.service','''[Unit]
Description=Capstone isolated sudo lab rootless Docker
After=dbus.socket
[Service]
Type=notify
NotifyAccess=all
Environment=PATH=/opt/capstone-sudo-rootless/29.8.1/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=DOCKERD=/usr/local/bin/dockerd
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=none
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=none
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=false
ExecStart=/opt/capstone-sudo-rootless/29.8.1/bin/dockerd-rootless.sh --config-file=/etc/capstone-sudo-lab/daemon.json
Restart=on-failure
RestartSec=5
TimeoutStartSec=90
TimeoutStopSec=30
KillMode=mixed
Delegate=cpu memory pids
UMask=0077
LimitNOFILE=65536
TasksMax=256
MemoryMax=768M
MemorySwapMax=0
CPUQuota=100%
[Install]
WantedBy=default.target
''',0o644)
run(['/usr/bin/systemctl','daemon-reload'])
run(['/usr/bin/loginctl','enable-linger',USER])
run(['/usr/bin/systemctl','start','user@1991.service'])
user_run(['/usr/bin/systemctl','--user','daemon-reload'])
user_run(['/usr/bin/systemctl','--user','enable','--now','capstone-sudo-docker.service'],120)
info=json.loads(user_run(['/usr/local/bin/docker','--host','unix:///run/user/1991/docker.sock','info','--format','{{json .}}']))
require('name=rootless' in info['SecurityOptions'] and 'name=seccomp,profile=builtin' in info['SecurityOptions'],'rootless_security')
require(info['CgroupDriver']=='systemd' and str(info['CgroupVersion'])=='2','cgroup_driver')
require(info['Driver']=='vfs','dedicated_storage')
require(pkg('sudo')==HOST_SUDO and sha(Path('/etc/systemd/system/docker.service').read_bytes())==ROOTFUL_UNIT_SHA,'protected_state_changed')
require(all(Path('/proc/sys/'+k.replace('.','/')).read_text()==v for k,v in before_sysctl.items()),'global_sysctl_changed')
result={'schema':1,'installed':True,'operator_uid':UID,'operator_gid':GID,'subid_start':231072,'subid_count':65536,
 'daemon_version':info['ServerVersion'],'rootlesskit_version':run([BIN/'rootlesskit','--version']),
 'storage_driver':info['Driver'],'security':info['SecurityOptions'],'cgroup_driver':info['CgroupDriver'],
 'host_sudo_unchanged':True,'rootful_unit_unchanged':True,'global_sysctl_unchanged':True,
 'packages':{x:pkg(x) for x in ('uidmap','libsubid4')},'environment_ready':False,'attack_tested':False}
write(EVIDENCE/'installed.json',json.dumps(result,sort_keys=True,indent=2)+'\n',0o600)
print(json.dumps(result,sort_keys=True))
