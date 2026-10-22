import hashlib,json,pwd,stat,subprocess,time
from pathlib import Path
E=Path('/var/lib/capstone-offline-labs/rootless-runtime-20261022');O=Path('/var/lib/capstone-offline-labs/offline-sudo-20261022')
def run(args):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20);assert p.returncode==0;return p.stdout.strip()
def file_sha(p):
 d=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''): d.update(b)
 return d.hexdigest()
baseline=json.loads((E/'baseline.json').read_text())
sudo=run(['/usr/bin/dpkg-query','-W','-f=${Status}|${Version}','sudo']);assert sudo==baseline['host_sudo']
rootful=file_sha(Path('/etc/systemd/system/docker.service'));assert rootful==baseline['rootful_unit_sha']
assert all(Path('/proc/sys/'+k.replace('.','/')).read_text()==v for k,v in baseline['sysctl'].items())
receipt=Path('/var/lib/capstone-offline-labs/nonweb-status.json');r=json.loads(receipt.read_text());m=receipt.stat()
assert r['labs']=={'CVE-2021-3156':{'status':'ready'}} and r['checked_at']<=time.time()<r['expires_at']
assert m.st_uid==0 and m.st_gid==0 and stat.S_IMODE(m.st_mode)==0o600 and m.st_nlink==1
images=json.loads((O/'images.json').read_text());item=images['images'][0]
assert file_sha(O/item['archive'])==item['sha256']
paths={'rootless_unit':'/var/lib/capstone-sudo-runtime/.config/systemd/user/capstone-sudo-docker.service','rootless_dropin':'/etc/systemd/system/user@1991.service.d/capstone-sudo.conf','rootless_apparmor':'/etc/apparmor.d/opt.capstone-sudo-rootless.29.8.1.bin.rootlesskit','daemon_config':'/etc/capstone-sudo-lab/daemon.json','lab_config':'/etc/capstone-sudo-lab/config.json','publisher_unit':'/etc/systemd/system/capstone-sudo-status.service','publisher_timer':'/etc/systemd/system/capstone-sudo-status.timer'}
result={'schema':1,'checked_at':int(time.time()),'scope':'environment_only','attack_tested':False,'host_scenario_verified':False,
 'host_sudo_unchanged':True,'host_sudo_revision':sudo,'rootful_unit_unchanged':True,'global_sysctl_unchanged':True,
 'host_securityfs_visible':Path('/sys/kernel/security/apparmor').is_dir(),'installation':json.loads((E/'installed.json').read_text()),
 'signature_verification':json.loads((E/'verification.json').read_text()),'image_identity':json.loads((E/'image-identity.json').read_text()),
 'archive':item,'native_checks':json.loads((E/'native-checks.json').read_text()),'publisher_checks':json.loads((E/'publisher-checks.json').read_text()),
 'securityfs_view':json.loads((E/'securityfs-view.json').read_text()),'current_receipt':r,'timer_active':run(['/usr/bin/systemctl','is-active','capstone-sudo-status.timer'])=='active','timer_enabled':run(['/usr/bin/systemctl','is-enabled','capstone-sudo-status.timer'])=='enabled',
 'configuration_sha256':{k:{'path':v,'sha256':file_sha(Path(v))} for k,v in paths.items()}}
(E/'final-evidence.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');(E/'final-evidence.json').chmod(0o600)
print(json.dumps(result,sort_keys=True))
