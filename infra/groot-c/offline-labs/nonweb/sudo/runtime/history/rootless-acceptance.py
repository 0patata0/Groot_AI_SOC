import hashlib,json,os,subprocess,tarfile,time
from pathlib import Path
EVIDENCE=Path('/var/lib/capstone-offline-labs/rootless-runtime-20261022')
OFFLINE=Path('/var/lib/capstone-offline-labs/offline-sudo-20261022')
SOURCE=Path('/opt/capstone-offline-labs/nonweb/sudo')
MANIFEST_ID='sha256:3a7816fe014c0a9e33b36b869dcd65b0e9662cb51f78271254b396502dd53ab7'
CONFIG_ID='sha256:90fd1384894d26e34c2364b0ff8fb8bdb92a3e9ebc3df5dee29a61b68bfcab2a'
PREFIX=['/usr/sbin/runuser','-u','capstone-sudo','--','/usr/bin/env','-i',
 'PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME=/var/lib/capstone-sudo-runtime',
 'XDG_RUNTIME_DIR=/run/user/1991','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus','LANG=C','LC_ALL=C','PYTHONDONTWRITEBYTECODE=1']
DOCKER=PREFIX+['/usr/local/bin/docker','--host','unix:///run/user/1991/docker.sock']
def sha(data): return hashlib.sha256(data).hexdigest()
def file_sha(path):
 d=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): d.update(b)
 return d.hexdigest()
def write(path,data,replace=False):
 target=path.with_name(path.name+'.new') if replace else path
 fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f: f.write(data); f.flush(); os.fsync(f.fileno())
 if replace: os.replace(target,path)
def run(args):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=40)
 assert p.returncode==0,'inspect_failed'
 return p.stdout
images=json.loads((OFFLINE/'images.json').read_text()); archive=OFFLINE/images['images'][0]['archive']
assert file_sha(archive)==images['images'][0]['sha256']
with tarfile.open(archive,'r:') as tar:
 index=json.load(tar.extractfile('index.json'))
 assert len(index['manifests'])==1 and index['manifests'][0]['digest']==MANIFEST_ID
 raw=tar.extractfile('blobs/sha256/'+MANIFEST_ID[7:]).read(); assert 'sha256:'+sha(raw)==MANIFEST_ID
 manifest=json.loads(raw); assert manifest['config']['digest']==CONFIG_ID
 raw=tar.extractfile('blobs/sha256/'+CONFIG_ID[7:]).read(); assert 'sha256:'+sha(raw)==CONFIG_ID
 config=json.loads(raw); assert config['architecture']=='amd64' and config['os']=='linux'
 for layer in manifest['layers']:
  d=hashlib.sha256(); size=0
  with tar.extractfile('blobs/sha256/'+layer['digest'][7:]) as f:
   for b in iter(lambda:f.read(1024*1024),b''): d.update(b); size+=len(b)
  assert 'sha256:'+d.hexdigest()==layer['digest'] and size==layer['size']
loaded=json.loads(run(DOCKER+['image','inspect',CONFIG_ID]))[0]
assert loaded['Id']==CONFIG_ID and loaded['RootFS']['Layers']==config['rootfs']['diff_ids']
cfg=Path('/etc/capstone-sudo-lab/config.json'); current=json.loads(cfg.read_text())
assert current['image_id']==MANIFEST_ID
write(EVIDENCE/'config-before-runtime-id.json',cfg.read_text())
current['image_id']=CONFIG_ID
write(cfg,json.dumps(current,sort_keys=True,indent=2)+'\n',True); os.chmod(cfg,0o644)
identity={'schema':1,'source_oci_manifest_id':MANIFEST_ID,'runtime_config_id':CONFIG_ID,
 'archive_sha256':file_sha(archive),'all_oci_layer_digests_verified':True,'rootfs_diff_ids_match':True}
write(EVIDENCE/'image-identity.json',json.dumps(identity,sort_keys=True,indent=2)+'\n')
write(EVIDENCE/'offline-images-initial.json',(OFFLINE/'images.json').read_text())
images['images'][0].update(runtime_image_id=CONFIG_ID,source_oci_manifest_id=MANIFEST_ID)
write(OFFLINE/'images.json',json.dumps(images,sort_keys=True,indent=2)+'\n',True)
write(OFFLINE/'SHA256SUMS',file_sha(archive)+'  '+archive.name+'\n'+file_sha(OFFLINE/'images.json')+'  images.json\n',True)
results={'schema':1,'native_regression_tests':20,'native_regression_passed':True,'image_identity':identity,'checks':[]}
for action in ('check','up','verify','stop','up','verify'):
 p=subprocess.run(PREFIX+['/usr/bin/python3','-B',str(SOURCE/'lab.py'),action],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=80)
 data=json.loads(p.stdout); results['checks'].append({'action':action,'rc':p.returncode,'result':data})
 print(json.dumps({'action':action,'rc':p.returncode,'result':data},sort_keys=True),flush=True)
 if p.returncode:
  write(EVIDENCE/'native-checks.json',json.dumps(results,sort_keys=True,indent=2)+'\n')
  raise SystemExit(1)
ids={x['result']['container_id'] for x in results['checks'] if x['result'].get('container_id')}
assert len(ids)==1
results.update(same_container_id=True,attack_tested=False,host_scenario_verified=False)
write(EVIDENCE/'native-checks.json',json.dumps(results,sort_keys=True,indent=2)+'\n')
print(json.dumps({'completed':True,'container_id':ids.pop(),'image_identity':identity},sort_keys=True))
