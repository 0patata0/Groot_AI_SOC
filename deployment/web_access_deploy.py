"""Fixed C web-evidence reader/publisher installed after diagnostic identity.

Internal to deploy.sh. This creates no general sudo, shell, Docker or caller
chosen file access. Existing B diagnostic public identity is reused; its private
key never leaves B. Existing diagnostic reader protocol remains unchanged.
"""
import ast
import grp
import os
from pathlib import Path
import pwd
import sys

import soc_management as common

CODE=Path('/opt/capstone-web-evidence')
STATE=Path('/var/lib/capstone-web-evidence')
RECEIPT=STATE/'installation.json'
ACCOUNT='capstone-web-evidence'
GROUP='capstone-diagnostics'
SERVICE='capstone-web-evidence.service'
TIMER='capstone-web-evidence.timer'
SSHD=Path('/etc/ssh/sshd_config.d/64-capstone-web-evidence.conf')
SOURCES=('web_evidence.py','read-web-evidence.py')
need=common.need


def unit_documents():
    service=('''[Unit]
Description=Publish bounded sanitized C web evidence
After=apache2.service
[Service]
Type=oneshot
User=root
Group=capstone-diagnostics
SupplementaryGroups=wazuh
Environment=LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -IB /opt/capstone-web-evidence/web_evidence.py --collect
UMask=0027
StateDirectory=capstone-web-evidence
StateDirectoryMode=0750
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/capstone-web-evidence
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
KillMode=control-group
TimeoutStartSec=30
TimeoutStopSec=5
CPUQuota=20%
MemoryMax=96M
TasksMax=16
''')
    timer=('''[Unit]
Description=Refresh bounded C web evidence
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s
Unit=capstone-web-evidence.service
[Install]
WantedBy=timers.target
''')
    return {SERVICE:service.encode(),TIMER:timer.encode()}


def source_bundle(s):
    values={name:common.read(s['source']/'infra/mcp'/name,131072) for name in SOURCES}
    values['web_access_deploy.py']=common.read(s['source']/'deployment/web_access_deploy.py',131072)
    for raw in values.values():ast.parse(raw)
    return values


def launcher():
    return b'''#!/bin/sh
set -eu
[ "$#" -eq 0 ] && [ -z "${SSH_ORIGINAL_COMMAND:-}" ] || exit 2
exec /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C LC_ALL=C \\
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -IB /opt/capstone-web-evidence/read-web-evidence.py
'''


def ssh_configuration():
    return ('''Match User capstone-web-evidence
    ForceCommand /opt/capstone-web-evidence/read
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    DisableForwarding yes
    PermitTTY no
    X11Forwarding no
    PermitUserRC no
''').encode()


def record(path):
    raw=common.read(path,4*1024*1024);meta=Path(path).lstat()
    return {'sha256':common.digest(raw),'mode':meta.st_mode&0o777,'gid':meta.st_gid}


def verify(s, public):
    public=common.public_key(public.encode());saved=common.parse(common.read(RECEIPT,262144))
    need(saved['hosts']==s['hosts'] and saved['reader_public_key']==public
         and saved['source_sha256']=={k:common.digest(v) for k,v in source_bundle(s).items()},'web_installation_profile_changed')
    for path,wanted in saved['files'].items():need(record(path)==wanted,'web_installed_file_changed')
    user=pwd.getpwnam(ACCOUNT);need(user.pw_uid!=0 and user.pw_gid==grp.getgrnam(GROUP).gr_gid
        and user.pw_dir==str(STATE/'reader') and user.pw_shell=='/bin/dash','web_reader_identity_changed')
    common.run(['/usr/sbin/sshd','-t'])
    effective=common.run(['/usr/sbin/sshd','-T','-C','user='+ACCOUNT+',host=web-reader,addr='+s['hosts']['SIEM_HOST']]).decode()
    policy=dict(line.split(' ',1) for line in effective.splitlines() if ' ' in line)
    expected={'forcecommand':str(CODE/'read'),'pubkeyauthentication':'yes','authenticationmethods':'publickey',
              'passwordauthentication':'no','kbdinteractiveauthentication':'no','disableforwarding':'yes',
              'permittty':'no','x11forwarding':'no','permituserrc':'no','permituserenvironment':'no'}
    need(all(policy.get(k)==v for k,v in expected.items()),'web_ssh_effective_policy_changed')
    common.run(['/usr/bin/systemctl','is-active',TIMER]);common.run(['/usr/bin/systemctl','is-enabled',TIMER])
    return {'schema':1,'status':'ready','source':'c_apache_access_snapshot','new_sudo_rules':0,'new_private_key_exported':False}


def install_service(s, public):
    need(sys.platform=='linux' and os.geteuid()==0,'Linux_root_required')
    public=common.public_key(public.encode());bundle=source_bundle(s);gid=grp.getgrnam(GROUP).gr_gid
    if RECEIPT.exists():return verify(s,public)
    for path in (CODE,STATE,SSHD,*[Path('/etc/systemd/system')/n for n in unit_documents()]):
        need(not os.path.lexists(path),'unmanaged_web_namespace_exists')
    try:pwd.getpwnam(ACCOUNT)
    except KeyError:pass
    else:raise common.Refused('unmanaged_web_reader_exists')
    common.mkdir(CODE,0o755);common.mkdir(STATE,0o750,0,gid)
    common.write(STATE/'intent.json',common.canonical({'hosts':s['hosts'],'reader_public_key':public}))
    common.run(['/usr/sbin/useradd','--system','--gid',GROUP,'--no-create-home','--home-dir',str(STATE/'reader'),'--shell','/bin/dash',ACCOUNT])
    common.run(['/usr/sbin/usermod','--password','*',ACCOUNT])
    common.mkdir(STATE/'reader',0o750,0,gid);common.mkdir(STATE/'reader/.ssh',0o750,0,gid)
    common.write(CODE/'web_evidence.py',bundle['web_evidence.py'],0o644)
    common.write(CODE/'read-web-evidence.py',bundle['read-web-evidence.py'],0o550,0,gid)
    common.write(CODE/'read',launcher(),0o550,0,gid)
    keys=STATE/'reader/.ssh/authorized_keys'
    common.write(keys,('from="'+s['hosts']['SIEM_HOST']+'",restrict,command="'+str(CODE/'read')+'" '+public+'\n').encode(),0o640,0,gid)
    common.write(SSHD,ssh_configuration(),0o644)
    for name,raw in unit_documents().items():common.write(Path('/etc/systemd/system')/name,raw,0o644)
    common.run(['/usr/sbin/sshd','-t']);common.run(['/usr/bin/systemctl','daemon-reload'])
    common.run(['/usr/bin/systemctl','start',SERVICE],timeout=40)
    common.run(['/usr/bin/systemctl','enable','--now',TIMER]);common.run(['/usr/bin/systemctl','reload','ssh'])
    paths=[CODE/name for name in SOURCES]+[CODE/'read',keys,SSHD]+[Path('/etc/systemd/system')/n for n in unit_documents()]
    common.write(RECEIPT,common.canonical({'schema':1,'hosts':s['hosts'],'reader_public_key':public,
        'source_sha256':{k:common.digest(v) for k,v in bundle.items()},'files':{str(p):record(p) for p in paths}}))
    return verify(s,public)
