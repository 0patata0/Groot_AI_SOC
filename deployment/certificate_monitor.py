#!/usr/bin/env python3
"""Fresh-host certificate observers for the existing lab and internal chat TLS.

Called only by deploy.sh. Reuses the reviewed fixed observer's probe; it does
not renew certificates, read private keys, change proxies, or adopt live hosts.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

BASE='infra/groot-a/certificate-monitor/'
PINS={
    'monitor.sh':'ecc817ceb6dd8d6b24b3ab3087e9642631bea796fb2e3a4e18f81836091b77d8',
    'capstone_certificate_rules.xml':'40dc486283cd5dc9e5aaf57bc79ed78be233528c44375914ea2620d31dc1df2d',
    'capstone_certificate_decoders.xml':'3a7d37d2ce9979da70b196b17adcfed9f33285bb604979c2e7416b7a3c5d281c',
}
EXECUTABLE=Path('/usr/local/sbin/capstone-cert-monitor')
STATE=Path('/var/lib/capstone-cert-monitor')
INSTALL_STATE=Path('/var/lib/capstone-certificate-bootstrap')
UNIT=Path('/etc/systemd/system/capstone-cert-monitor.service')
TIMER=Path('/etc/systemd/system/capstone-cert-monitor.timer')
OLD_DOMAIN='chat.grootlab.duckdns.org'
OLD_MID='096e90b6243e438aa8a7b392be754732'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','TZ':'UTC',
     'PYTHONDONTWRITEBYTECODE':'1','OPENSSL_CONF':'/etc/ssl/openssl.cnf'}

class Refused(ValueError):pass

def need(ok,message):
    if not ok:raise Refused(message)

def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()

def site_specs(environ):
    """Two existing TLS services; neither is an arbitrary probe destination."""
    need(environ.get('CAPSTONE_ROOT','/opt/capstone')=='/opt/capstone','fixed_bootstrap_root_required')
    hosts={k:str(ipaddress.IPv4Address(environ[k])) for k in ('SECURITY_HOST','SIEM_HOST','SERVICE_HOST')}
    need(len(set(hosts.values()))==3 and all(not (ipaddress.ip_address(v).is_loopback or
         ipaddress.ip_address(v).is_multicast or ipaddress.ip_address(v).is_unspecified) for v in hosts.values()),'distinct_usable_hosts_required')
    origin=environ['LAB_PUBLIC_ORIGIN'];url=urlsplit(origin)
    domain=url.hostname or ''
    need(url.scheme=='https' and not url.username and not url.password and url.path in ('','/') and
         not url.query and not url.fragment and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',domain) and
         all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in domain.split('.')) and
         '.' in domain and domain!='capstone-siem.internal','lab_dns_origin_required')
    try:ipaddress.ip_address(domain)
    except ValueError:pass
    else:raise Refused('lab_dns_origin_required')
    port=int(environ['LAB_HTTPS_PORT'])
    need(1<=port<=65535 and (url.port or 443)==port,'lab_origin_port_mismatch')
    net=ipaddress.IPv4Network(environ['LAB_PROXY_SUBNET'],strict=True)
    need(net.is_private and net.prefixlen==29,'fixed_lab_proxy_29_required')
    # validate_lab_site.py assigns gateway .1, WAF .2 and edge .3.
    edge=str(list(net.hosts())[2])
    need(all(ipaddress.ip_address(v) not in net for v in hosts.values()),'host_overlaps_proxy_network')
    return {
      'security':{'domain':domain,'host':hosts['SECURITY_HOST'],'connect':edge+':8443',
          'address':edge,'certificate':'/opt/capstone/security/tls/lab.crt',
          'private_key':'/opt/capstone/security/tls/lab.key','sensor':'capstone-security',
          'scope':'A lab-edge TLS leaf; public DNS/port/HTTP availability separate'},
      'siem':{'domain':'capstone-siem.internal','host':hosts['SIEM_HOST'],
          'connect':hosts['SIEM_HOST']+':8444','address':hosts['SIEM_HOST'],
          'certificate':'/etc/capstone-internal-tls/server.crt',
          'private_key':'/etc/capstone-internal-tls/server.key','sensor':'capstone-siem-host',
          'scope':'B internal chat TLS8444 leaf; broker8445/HTTP/LLM availability separate'}
    }

def templates(source,reader=None):
    reader=reader or (lambda p:trusted_read(p,65536))
    result={name:reader(Path(source)/BASE/name) for name in PINS}
    for name,raw in result.items():need(sha(raw)==PINS[name],'reviewed_template_changed:'+name)
    return result

def monitor(raw,spec,machine_id):
    need(sha(raw)==PINS['monitor.sh'] and re.fullmatch('[0-9a-f]{32}',machine_id),'monitor_template_or_machine_id')
    text=raw.decode()
    replacements={
      OLD_DOMAIN:spec['domain'],
      '/home/groot_a/capstone/chatproxy/tls/chatduck.crt':spec['certificate'],
      OLD_MID:machine_id,'172.18.0.3:8443':spec['connect'],
      '== 0:0:644:1':'== 0:0:444:1',
    }
    for before,after in replacements.items():
        need(before in text,'monitor_substitution_boundary')
        text=text.replace(before,after)
    need(OLD_MID not in text and '/home/groot_a/' not in text and '172.18.0.3' not in text,'legacy_monitor_pin_retained')
    return text.encode()

def service(spec):
    return f'''[Unit]
Description=Observe the installed {spec['sensor']} TLS certificate
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart={EXECUTABLE} run
StandardOutput=null
StandardError=journal
TimeoutStartSec=30s
TimeoutStopSec=1s
SuccessExitStatus=2 75
StateDirectory=capstone-cert-monitor
StateDirectoryMode=0700
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={STATE}
InaccessiblePaths=-{spec['private_key']}
RestrictAddressFamilies=AF_INET AF_UNIX
IPAddressDeny=any
IPAddressAllow=127.0.0.1/32
IPAddressAllow={spec['address']}/32
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
'''.encode()

def timer():
    return b'''[Unit]
Description=Daily Korea-time installed TLS certificate observation
[Timer]
OnCalendar=*-*-* 09:00:00 Asia/Seoul
Persistent=true
AccuracySec=1min
Unit=capstone-cert-monitor.service
[Install]
WantedBy=timers.target
'''

def rules(raw,specs):
    need(sha(raw)==PINS['capstone_certificate_rules.xml'],'reviewed_rules_changed')
    groups=[]
    for index,role in enumerate(('security','siem')):
        spec=specs[role];text=raw.decode()
        text=text.replace(r'chat\.grootlab\.duckdns\.org',re.escape(spec['domain']))
        text=text.replace(OLD_DOMAIN,spec['domain']).replace('groot-sec',spec['sensor'])
        text=text.replace('capstone_certificate_health,','capstone_certificate_health,'+role+',')
        def shift(match):return match[1]+str(int(match[2])+6*index)+match[3]
        text=re.sub(r'(id=")([0-9]+)(")|(<if_sid>)([0-9]+)(</if_sid>)',
            lambda m:shift(m) if m[1] else m[4]+str(int(m[5])+6*index)+m[6],text)
        ET.fromstring(text);groups.append(text)
    result='\n'.join(groups).encode()
    tree=ET.fromstring(b'<root>'+result+b'</root>')
    need(len(tree.findall('.//rule'))==12,'portable_rule_count')
    return result

def trusted_read(path,limit=1048576):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts,'absolute_trusted_path_required')
    source=Path(os.environ.get('CAPSTONE_SOURCE','/nonexistent'))
    staged=bool(re.fullmatch('/var/tmp/capstone-bootstrap-[0-9a-f]{24}/source',str(source))) and path.is_relative_to(source)
    for parent in reversed(path.parents):
        s=parent.lstat();sticky=staged and parent==Path('/var/tmp') and stat.S_IMODE(s.st_mode)==0o1777
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and (sticky or not s.st_mode&0o022),'untrusted_parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022 and 0<s.st_size<=limit,'untrusted_file')
        raw=os.read(fd,limit+1);after=os.fstat(fd)
        need(len(raw)==s.st_size and len(raw)<=limit and (s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns,s.st_size)==
             (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns,after.st_size),'file_changed_while_reading')
        return raw
    finally:os.close(fd)

def directory(path,create=False):
    path=Path(path)
    if create:path.mkdir(mode=0o700)
    for parent in (path,*path.parents):
        s=parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'untrusted_directory')

def write_new(path,raw,mode):
    directory(path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);stream.write(raw);stream.flush();os.fsync(stream.fileno())
    except Exception:
        # A partial new installation is retained for review, never adopted.
        raise

def run(argv,timeout=35):
    p=subprocess.run(argv,capture_output=True,env=ENV,timeout=timeout)
    need(p.returncode==0,'certificate_command_failed:'+Path(argv[0]).name)
    return p.stdout

def profile(role,environ,source):
    spec=site_specs(environ)[role]
    mid=trusted_read(Path('/etc/machine-id'),128).decode().strip()
    need(re.fullmatch('[0-9a-f]{32}',mid),'machine_id_required')
    inputs=templates(source)
    payload={EXECUTABLE:monitor(inputs['monitor.sh'],spec,mid),UNIT:service(spec),TIMER:timer()}
    value={'schema':1,'role':role,'spec':spec,'machine_id':mid,'templates':dict(PINS),
        'installer_sha256':sha(trusted_read(Path(__file__).resolve())),
        'files':{str(p):{'sha256':sha(raw),'mode':0o500 if p==EXECUTABLE else 0o644} for p,raw in payload.items()}}
    value['profile_sha256']=sha(canonical(value))
    return value,payload

def fresh_guard(role,require_installed_role):
    need(os.geteuid()==0,'root_required')
    for path in ('/home/groot_a/capstone','/home/groot_b/capstone','/opt/suricata'):
        need(not Path(path).exists() and not Path(path).is_symlink(),'legacy_host_not_adopted')
    role_file=Path('/opt/capstone/role')
    if require_installed_role or role_file.exists():
        need(trusted_read(role_file,64).decode().strip()==role,'fresh_role_identity_required')

def verify(value,probe=True):
    receipt=json.loads(trusted_read(INSTALL_STATE/'receipt.json',65536))
    need(receipt.get('phase')=='complete' and receipt.get('profile')==value,'certificate_installation_receipt_drift')
    for name,record in value['files'].items():
        path=Path(name);need(sha(trusted_read(path))==record['sha256'] and stat.S_IMODE(path.stat().st_mode)==record['mode'],'certificate_installation_file_drift')
    run(['/usr/bin/systemctl','is-enabled',TIMER.name]);run(['/usr/bin/systemctl','is-active',TIMER.name])
    actual=json.loads(run([str(EXECUTABLE),'check'])) if probe else None
    if probe:need(actual['domain']==value['spec']['domain'] and actual['probe_status']=='verified','installed_certificate_probe_failed')
    return {'status':'verified','role':value['role'],'profile_sha256':value['profile_sha256'],
        'certificate':actual,'private_key_read':False,'automatic_renewal':False,'scope':value['spec']['scope']}

def install(value,payload):
    if INSTALL_STATE.exists():return verify(value)
    for path in (EXECUTABLE,UNIT,TIMER,STATE):need(not path.exists() and not path.is_symlink(),'unowned_certificate_destination')
    cert=Path(value['spec']['certificate']);raw=trusted_read(cert,65536)
    need(b'PRIVATE KEY' not in raw and cert.stat().st_gid==0 and stat.S_IMODE(cert.stat().st_mode)==0o444,'readonly_public_certificate_required')
    directory(INSTALL_STATE,True)
    write_new(INSTALL_STATE/'installation-start.json',canonical({'phase':'installing','profile':value}),0o600)
    for path,raw in payload.items():write_new(path,raw,value['files'][str(path)]['mode'])
    run(['/usr/bin/systemctl','daemon-reload'])
    run(['/usr/bin/systemctl','start',UNIT.name])
    event=json.loads(trusted_read(STATE/'status.json',65536))
    stamp=event.get('observed_at_utc','')
    import datetime
    observed=datetime.datetime.fromisoformat(stamp.replace('Z','+00:00')).timestamp()
    need(-2<=time.time()-observed<=35 and event.get('domain')==value['spec']['domain'] and
         event.get('probe_status')=='verified','initial_certificate_observation_failed')
    run(['/usr/bin/systemctl','enable','--now',TIMER.name])
    write_new(INSTALL_STATE/'receipt.json',canonical({'phase':'complete','profile':value}),0o600)
    return verify(value)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('check','install','verify'))
    p.add_argument('--role',choices=('security','siem'),required=True)
    args=p.parse_args();fresh_guard(args.role,args.action!='check')
    source=Path(os.environ['CAPSTONE_SOURCE']);value,payload=profile(args.role,os.environ,source)
    if args.action=='check':
        if INSTALL_STATE.exists():verify(value,probe=False)
        else:
            for path in (EXECUTABLE,UNIT,TIMER,STATE):need(not path.exists() and not path.is_symlink(),'unowned_certificate_destination')
        result={'status':'prerequisites_checked','role':args.role,'profile_sha256':value['profile_sha256'],
            'actual_tls_probe':False,'private_key_read':False}
    else:result=install(value,payload) if args.action=='install' else verify(value)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (Refused,OSError,KeyError,ValueError,subprocess.SubprocessError):
        print('certificate-bootstrap: refused; inspect prerequisites, receipt and journal',file=sys.stderr);sys.exit(1)
