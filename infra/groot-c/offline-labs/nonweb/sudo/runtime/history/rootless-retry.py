import hashlib,io,json,os,subprocess,tarfile,time
from pathlib import Path
E=Path('/var/lib/capstone-offline-labs/rootless-runtime-20261022'); S=Path('/opt/capstone-offline-labs/nonweb/sudo')
A=Path('/var/tmp/capstone-lab-expansion-20261022/rootless-cli.tar')
assert hashlib.sha256(A.read_bytes()).hexdigest()=='065d725da275f39971110bac76f1006cc2fbde206c7d25d2362ac215b5341b97'
with tarfile.open(fileobj=io.BytesIO(A.read_bytes()),mode='r:') as t:
 assert {m.name for m in t.getmembers()}=={'lab.py','test_sudo_lab.py','publish.py'}
 for m in t.getmembers():
  assert m.isfile(); p=S/m.name; assert not p.is_symlink() and (not p.exists() or p.stat().st_uid==0)
  b=p.read_bytes() if p.exists() else b''; backup=E/(m.name+'.'+hashlib.sha256(b).hexdigest()+'.before')
  if not backup.exists(): backup.write_bytes(b); backup.chmod(0o600)
  n=p.with_name(p.name+'.new'); assert not n.exists(); n.write_bytes(t.extractfile(m).read()); n.chmod(0o755 if m.name=='lab.py' else 0o644); os.replace(n,p)
p=subprocess.run(['/usr/bin/python3','-B','-m','unittest','discover','-s',str(S),'-p','test_sudo_lab.py'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=40)
assert p.returncode==0,'native_regression_failed'
P=['/usr/sbin/runuser','-u','capstone-sudo','--','/usr/bin/env','-i','PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
 'HOME=/var/lib/capstone-sudo-runtime','XDG_RUNTIME_DIR=/run/user/1991','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus','LANG=C','LC_ALL=C','PYTHONDONTWRITEBYTECODE=1']
results={'schema':1,'native_regression_tests':26,'native_regression_passed':True,'checks':[]}
if (E/'native-checks.json').exists(): os.rename(E/'native-checks.json',E/('native-checks-before-'+str(time.time_ns())+'.json'))
for action in ('check','up','verify','up','stop','up','verify'):
 p=subprocess.run(P+['/usr/bin/python3','-B',str(S/'lab.py'),action],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=80)
 data=json.loads(p.stdout); results['checks'].append({'action':action,'rc':p.returncode,'result':data})
 print(json.dumps({'action':action,'rc':p.returncode,'result':data},sort_keys=True),flush=True)
 if p.returncode: break
ids={x['result']['container_id'] for x in results['checks'] if x['result'].get('container_id')}
results['stop_up_recreates']=len(ids)>1
results['complete']=len(results['checks'])==7 and all(x['rc']==0 for x in results['checks'])
(E/'native-checks.json').write_text(json.dumps(results,sort_keys=True,indent=2)+'\n'); (E/'native-checks.json').chmod(0o600)
raise SystemExit(0 if results['complete'] else 1)
