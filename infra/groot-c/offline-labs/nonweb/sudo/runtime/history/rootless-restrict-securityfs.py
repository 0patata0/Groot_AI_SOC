import hashlib,json,os,subprocess,time
from pathlib import Path
E=Path('/var/lib/capstone-offline-labs/rootless-runtime-20261022')
D=Path('/etc/systemd/system/user@1991.service.d/capstone-sudo.conf')
old=D.read_bytes(); assert old==b'[Service]\nDelegate=cpu memory pids\n'
assert D.stat().st_uid==0 and not D.is_symlink()
before=Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns').read_text()
unitsha=hashlib.sha256(Path('/etc/systemd/system/docker.service').read_bytes()).hexdigest()
assert unitsha=='fc3f399c2451c6da5ea536d9dfaf4f188b8f8e6f21aa791fd47763c849380c7d'
host_security=Path('/sys/kernel/security/apparmor').is_dir()
assert host_security
baseline={'host_securityfs_visible':host_security,'rootful_unit_sha':unitsha,'sysctl':before}
(E/'securityfs-view-before.json').write_text(json.dumps(baseline,sort_keys=True)+'\n')
(E/'securityfs-view-before.json').chmod(0o600)
new=old+b'InaccessiblePaths=/sys/kernel/security\n'
tmp=D.with_name(D.name+'.new'); assert not tmp.exists(); tmp.write_bytes(new); tmp.chmod(0o644);os.replace(tmp,D)
for command in (['/usr/bin/systemctl','daemon-reload'],['/usr/bin/systemctl','restart','user@1991.service']):
 p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
 assert p.returncode==0,'user_service_restart_failed'
P=['/usr/sbin/runuser','-u','capstone-sudo','--','/usr/bin/env','-i','PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME=/var/lib/capstone-sudo-runtime','XDG_RUNTIME_DIR=/run/user/1991','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus']
for i in range(30):
 p=subprocess.run(P+['/usr/local/bin/docker','--host','unix:///run/user/1991/docker.sock','info','--format','{{json .}}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
 if p.returncode==0: break
 time.sleep(.5)
assert p.returncode==0,'rootless_restart_failed'
info=json.loads(p.stdout)
assert 'name=rootless' in info['SecurityOptions'] and 'name=seccomp,profile=builtin' in info['SecurityOptions']
assert Path('/sys/kernel/security/apparmor').is_dir() and Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns').read_text()==before
assert hashlib.sha256(Path('/etc/systemd/system/docker.service').read_bytes()).hexdigest()==unitsha
p=subprocess.run(['/usr/bin/systemctl','show','user@1991.service','-p','MainPID','--value'],stdout=subprocess.PIPE,text=True,check=True)
pid=int(p.stdout)
seen=Path('/proc')/str(pid)/'root/sys/kernel/security/apparmor'
assert not seen.exists(),'securityfs_not_hidden_in_dedicated_service'
result={'schema':1,'dedicated_user_service_securityfs_hidden':True,'host_securityfs_visible':True,'host_apparmor_sysctl_unchanged':True,'rootful_unit_unchanged':True,'security_options':info['SecurityOptions'],'daemon_version':info['ServerVersion'],'checked_at':int(time.time())}
(E/'securityfs-view.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');(E/'securityfs-view.json').chmod(0o600)
print(json.dumps(result,sort_keys=True))
