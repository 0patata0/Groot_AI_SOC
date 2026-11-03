import gzip,hashlib,io,json,os,pwd,re,subprocess,tarfile
from pathlib import Path
root=Path('/home/groot_a/.local/state/capstone-pcap-tool-20261103');root.mkdir(mode=0o700,parents=True,exist_ok=False)
uid=pwd.getpwnam('groot_a').pw_uid;gid=pwd.getpwnam('groot_a').pw_gid
info=json.loads(subprocess.check_output(['docker','inspect','suricata']))[0];assert info['Image']=='sha256:d4fd70f7955f1f9d5c8f54d0b91dd22e359bebce6fba5423d1182f33ae0d59ff'
ldd=subprocess.check_output(['docker','exec','suricata','ldd','/usr/bin/suricata'],text=True)
paths=['usr/bin/suricata']+sorted(set(re.findall(r'(/lib64/[^ \n]+)',ldd)))
paths=[x.lstrip('/') for x in paths]
raw=subprocess.check_output(['docker','exec','suricata','tar','-chf','-','-C','/']+paths,timeout=35)
out=root/'portable-suricata.tar.gz';members=[]
with tarfile.open(out,'w:gz',compresslevel=3) as dst:
 with tarfile.open(fileobj=io.BytesIO(raw)) as src:
  for m in src:
   assert m.isfile() and not m.name.startswith('/') and '..' not in Path(m.name).parts
   data=src.extractfile(m).read();dst.addfile(m,io.BytesIO(data));members.append({'path':m.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 for name,path in [('rules/all.rules',Path('/home/groot_a/capstone/suricata/ruleset/all.rules')),('rules/local.rules',Path('/home/groot_a/capstone/suricata/ruleset/GROOT_A_local.rules'))]:
  data=path.read_bytes();m=tarfile.TarInfo(name);m.size=len(data);m.mode=0o444;dst.addfile(m,io.BytesIO(data));members.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
 for name in ['classification.config','reference.config']:
  data=subprocess.check_output(['docker','exec','suricata','cat','/etc/suricata/'+name]);m=tarfile.TarInfo('etc/'+name);m.size=len(data);m.mode=0o444;dst.addfile(m,io.BytesIO(data));members.append({'path':m.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
report={'image':info['Image'],'purpose':'standalone unprivileged offline PCAP reader on Kali232, no service installation','members':members,'sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'bytes':out.stat().st_size}
(root/'manifest.json').write_text(json.dumps(report,indent=2))
for p in [root,*root.iterdir()]:os.chown(p,uid,gid);p.chmod(0o700 if p.is_dir() else 0o600)
print(json.dumps(report))
