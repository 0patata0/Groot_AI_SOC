import hashlib,json,os,pwd,stat,time
from pathlib import Path
B=Path('/var/lib/capstone-offline-labs/build-sudo-20261022');E=Path('/var/lib/capstone-offline-labs/rootless-runtime-20261022');S=Path('/opt/capstone-offline-labs/nonweb/sudo');O=Path('/var/lib/capstone-offline-labs/offline-sudo-20261022');STAGE=Path('/var/tmp/capstone-lab-expansion-20261022')
def digest(p):
 d=hashlib.sha256()
 with p.open('rb') as f:
  for data in iter(lambda:f.read(1048576),b''): d.update(data)
 return d.hexdigest()
def regular(p, owner=0):
 m=p.lstat();assert stat.S_ISREG(m.st_mode) and m.st_uid==owner and m.st_nlink==1 and not m.st_mode&0o022
 for parent in p.parents:
  if parent==Path('/var/tmp'):break
  st=parent.lstat();assert stat.S_ISDIR(st.st_mode) and st.st_uid in ({0,1000} if p.parent==STAGE else {0}) and not st.st_mode&0o022
 return m
sets={B/'assets':{'InRelease','Packages.xz','download-provenance.json','sudo.deb','ubuntu-20.04-oci.tar'},B/'context':{'Dockerfile','check.sh','preparation.json','source.json','sudo.deb'},E/'artifacts':{'acquisition.json','docker-ce-rootless-extras_29.8.1-1~ubuntu.24.04~noble_amd64.deb','docker.InRelease','docker.Packages.gz','docker.asc','libsubid4_4.13+dfsg1-4ubuntu3.2_amd64.deb','ubuntu.InRelease','ubuntu.Packages.xz','uidmap_4.13+dfsg1-4ubuntu3.2_amd64.deb'}}
files=[]
for directory,names in sets.items():
 assert {p.name for p in directory.iterdir()}==names
 for p in directory.iterdir():regular(p);files.append(p)
staged={'rootless-artifacts.tar':'58a0822afa28f429ff3906648db5ca798ae1d21514386ed7121dde766bd8f0e9','rootless-cli.tar':'065d725da275f39971110bac76f1006cc2fbde206c7d25d2362ac215b5341b97','rootless-publisher.tar':'bc3eef8912320869a14647777e9cb10c89107339a692e4ab20a776ca5a6f130c','rootless-final-source.tar':'2f4f32f4d97e445b854ccf82a18bde8eeefbf80d7a4cf9800e4b8fc561fbc650'}
for name,sha in staged.items():
 p=STAGE/name;assert STAGE.lstat().st_uid==1000 and stat.S_IMODE(STAGE.lstat().st_mode)==0o700;regular(p,1000);assert digest(p)==sha;files.append(p)
assert digest(B/'context/preparation.json')=='8c69d341e14798ec161d093031f0ae54473d7d089166c3eedba6bbda0ce042ff'
for name in ('Dockerfile','check.sh','source.json'):assert digest(B/'context'/name)==digest(B/'source'/name)
archive=O/'sudo-1.8.31-1ubuntu1-amd64.tar';archive_sha=digest(archive);assert archive_sha=='db6a201143ad6372d24c91fed6e04f58206abad535941d39e6f5ad2ac79c5389'
preserved=[]
for src,dest in ((B/'context/preparation.json',B/'preparation.json'),(B/'assets/download-provenance.json',B/'download-provenance.json'),(E/'artifacts/acquisition.json',E/'acquisition.json')):
 assert not dest.exists() and not dest.is_symlink()
 fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(src.read_bytes());f.flush();os.fsync(f.fileno())
 assert digest(src)==digest(dest);preserved.append({'path':str(dest),'sha256':digest(dest)})
deleted=[{'path':str(p),'sha256':digest(p),'size':p.stat().st_size} for p in sorted(files)]
for p in files:p.unlink()
for directory in sets:directory.rmdir()
assert all(not Path(x['path']).exists() for x in deleted) and all(not p.exists() for p in sets)
assert digest(archive)==archive_sha and (O/'images.json').is_file() and (O/'SHA256SUMS').is_file()
assert STAGE.is_dir() and (B/'source').is_dir() and (B/'build-result.json').is_file() and S.is_dir()
assert pwd.getpwnam('capstone-sudo').pw_uid==1991 and Path('/var/lib/capstone-sudo-runtime/docker').is_dir()
receipt=json.loads(Path('/var/lib/capstone-offline-labs/nonweb-status.json').read_text());assert receipt['labs']=={'CVE-2021-3156':{'status':'ready'}} and receipt['checked_at']<=time.time()<receipt['expires_at']
result={'schema':1,'checked_at':int(time.time()),'deleted_files':deleted,'deleted_directories':[str(p) for p in sets],'removed_bytes':sum(x['size'] for x in deleted),'preserved_metadata':preserved,'operational_archive':{'path':str(archive),'sha256':archive_sha,'unchanged':True},'runtime_data_account_source_preserved':True,'shared_stage_directory_preserved':True,'mac_cleanup_owner':'root-agent','receipt':receipt}
body=json.dumps(result,sort_keys=True,indent=2)+'\n'
for target in (E/'cleanup-20261023.json',S/'runtime/cleanup-20261023.json'):
 assert not target.exists();target.write_text(body);target.chmod(0o600 if target.parent==E else 0o644)
print(json.dumps(result,sort_keys=True))
