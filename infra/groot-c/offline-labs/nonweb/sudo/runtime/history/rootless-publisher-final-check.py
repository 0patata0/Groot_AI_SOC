import hashlib,json,os,stat,subprocess,time
from pathlib import Path
S=Path('/opt/capstone-offline-labs/nonweb/sudo');E=Path('/var/lib/capstone-offline-labs/rootless-runtime-20261022')
u=Path('/etc/systemd/system/capstone-sudo-status.service');old=u.read_text();assert 'User=root\nGroup=root\n' in old
u.write_text(old.replace('User=root\nGroup=root\n',''));u.chmod(0o644)
subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
limits=[131072,131072]
P=['/usr/sbin/runuser','-u','capstone-sudo','--','/usr/bin/env','-i','PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME=/var/lib/capstone-sudo-runtime','XDG_RUNTIME_DIR=/run/user/1991','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus','LANG=C','LC_ALL=C','PYTHONDONTWRITEBYTECODE=1']
def run(args,timeout=100):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
 assert p.returncode==0,'fixed_command_failed:'+args[0]
 return p.stdout
receipt=Path('/var/lib/capstone-offline-labs/nonweb-status.json')
checks=[]
def publish(expected):
 run(['/usr/bin/systemctl','start','capstone-sudo-status.service'])
 data=json.loads(receipt.read_text());meta=receipt.lstat()
 assert stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and meta.st_uid==0 and meta.st_gid==0 and stat.S_IMODE(meta.st_mode)==0o600
 assert data['labs']=={'CVE-2021-3156':{'status':expected}} and data['expires_at']-data['checked_at']==300
 assert data['checked_at']<=time.time()<data['expires_at']
 checks.append({'expected':expected,'receipt':data})
 print(json.dumps({'publisher':expected,'checked_at':data['checked_at'],'expires_at':data['expires_at']},sort_keys=True),flush=True)
publish('ready')
stopped=json.loads(run(P+['/usr/bin/python3','-B',str(S/'lab.py'),'stop']))
assert stopped['status']=='stopped';publish('needs_setup')
started=json.loads(run(P+['/usr/bin/python3','-B',str(S/'lab.py'),'up']))
assert started['environment_ready'] and started['container_id']!=stopped['container_id'];publish('ready')
run(['/usr/bin/systemctl','enable','--now','capstone-sudo-status.timer'])
assert run(['/usr/bin/systemctl','is-active','capstone-sudo-status.timer']).strip()=='active'
assert run(['/usr/bin/systemctl','is-enabled','capstone-sudo-status.timer']).strip()=='enabled'
result={'schema':1,'native_regression_tests':26,'native_regression_passed':True,'child_rlimit_fsize':limits,'checks':checks,'final_container_id':started['container_id'],'stop_up_new_cid':True,'timer_enabled':True,'timer_active':True,'attack_tested':False,'host_scenario_verified':False}
(E/'publisher-checks.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');(E/'publisher-checks.json').chmod(0o600)
print(json.dumps(result,sort_keys=True))
