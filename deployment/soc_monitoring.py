#!/usr/bin/env python3
"""Root bootstrap for fixed runtime observations and A's durable notifier.

Fresh deployment is called only by deploy.sh. Existing GROOT migration uses
--existing-groot and updates only the diagnostic/observer namespace, with backups.
No package installation, security-rule change or LLM privilege grant occurs.
"""
import argparse
import ast
from datetime import datetime, timedelta, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import shlex
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit
import soc_diagnostics as diag
import soc_management as common

ETC=Path('/etc/capstone-diagnostics')
CODE=diag.CODE
STATE=diag.STATE
SOURCES=('runtime_health.py','soc_monitor.py','pipeline_probe.py')
CANARY='infra/normalization/wazuh-vector/'
need=common.need


def write(path,data,mode=0o600,uid=0,gid=0):
    path=Path(path);common.trusted_directory(path.parent)
    if path.exists() or path.is_symlink(): common.read(path)
    fd,name=tempfile.mkstemp(prefix='.monitor-install-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);os.fchown(stream.fileno(),uid,gid)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if os.path.exists(name): os.unlink(name)


def files(s):
    result={CODE/name:common.read(s['source']/'infra/mcp'/name) for name in SOURCES}
    for scenario in ('canary-repeat','canary-cross','canary-repeat-duplicate','canary-historical'):
        result[CODE/'canary'/(scenario+'.jsonl')]=common.read(s['source']/(CANARY+'fixtures/correlation/'+scenario+'.jsonl'))
    result[CODE/'canary/canary-validation.jq']=common.read(s['source']/(CANARY+'history-replay-b/canary-validation.jq'))
    for path,raw in result.items():
        if path.suffix=='.py': ast.parse(raw)
    return result


def units(role):
    actions=('observe',) if role=='security' else ('model','ingestion') if role=='siem' else ()
    docs={}
    for action in actions:
        name='capstone-soc-'+action
        writes=str(STATE)+(' /var/log/capstone-vector/canary' if action=='observe' else '')
        docs[name+'.service']=(
            '[Unit]\nDescription=Fixed SOC health '+action+'\nAfter=network-online.target\n'
            '[Service]\nType=oneshot\nUser=root\nUMask=0077\n'
            'ExecStart=/usr/bin/python3 -IB '+str(CODE)+'/soc_monitor.py '+action+'\n'
            'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            'ProtectKernelTunables=yes\nProtectControlGroups=yes\n'
            'ReadWritePaths='+writes+'\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
            'TimeoutStartSec=50\nTimeoutStopSec=5\nKillMode=control-group\n').encode()
        docs[name+'.timer']=(
            '[Unit]\nDescription=Periodic SOC '+action+'\n[Timer]\nOnBootSec=45s\n'
            'OnUnitInactiveSec='+('180' if action=='model' else '60')+'s\nAccuracySec=5s\n'
            '[Install]\nWantedBy=timers.target\n').encode()
    return docs


def configure(s,role,layout):
    need(layout in ('fresh','groot'),'monitor_layout')
    need((CODE/'system_diagnostics.py').is_file() and (STATE/'snapshot.json').is_file(),'diagnostics_required')
    if layout=='fresh': need((STATE/'installation/active.json').is_file(),'fresh_diagnostic_receipt_required')
    if layout=='fresh': need(common.read('/opt/capstone/role').decode().strip()==role,'host_role_mismatch')
    home='/opt/hermes-data' if layout=='groot' else '/opt/capstone/siem/capstone-hermes'
    cfg={'schema':1,'role':role,'layout':layout,'llm_url':'','model':'','mattermost_url':'','hermes_home':home,'ollama_enabled':False}
    if role=='siem':
        if Path('/etc/capstone-ollama-trial/config.json').exists():
            c=common.parse(common.read('/etc/capstone-ollama-trial/config.json'))
            cfg.update(llm_url=c['base_url'].removesuffix('/v1').rstrip('/'),model=c['model'],ollama_enabled=Path('/etc/capstone-ollama-trial/chat.json').exists())
        else:
            cfg.update(llm_url=os.environ['LLM_BASE_URL'].removesuffix('/v1').rstrip('/'),model=os.environ['LLM_MODEL'])
        cfg['mattermost_url']='http://'+s['hosts']['SIEM_HOST']+':8065'
    stamp=datetime.now(timezone(timedelta(hours=9))).strftime('%Y%m%d-%H%M%S-%f')
    backup=Path('/var/backups')/('capstone-monitoring-'+stamp)
    common.mkdir(backup)
    common.mkdir(ETC,0o700);common.mkdir(CODE/'canary',0o755)
    payload=files(s)
    payload[CODE/'system_diagnostics.py']=common.read(s['source']/'infra/mcp/system_diagnostics.py')
    payload[ETC/'runtime.json']=common.canonical(cfg)
    payload.update({Path('/etc/systemd/system')/n:b for n,b in diag.unit_documents(role).items()})
    payload.update({Path('/etc/systemd/system')/n:b for n,b in units(role).items()})
    if role=='siem': payload[Path('/opt/mcp/system-diagnostics-mcp.py')]=common.read(s['source']/'infra/mcp/system-diagnostics-mcp.py')
    if role=='siem':
        # Root's bounded probe cannot use the MCP group's 0640 SSH key and
        # NoNewPrivileges prevents changing identity on hardened hosts.
        # Keep a root-only copy of the same snapshot-only identity. The
        # remote authorization and model/MCP access do not change.
        payload[ETC/'ingestion_ed25519']=common.read('/etc/mcp/system-diagnostics/id_ed25519',16384)
    records={}
    for index,(path,raw) in enumerate(payload.items()):
        mode=0o600 if path in (ETC/'runtime.json',ETC/'ingestion_ed25519') else 0o644
        uid=gid=0
        if path.exists():
            meta=path.lstat();need(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and meta.st_nlink==1 and not meta.st_mode&0o022,'monitor_existing_file_unsafe')
            shutil.copy2(path,backup/str(index));records[str(path)]={'backup':str(index),'mode':stat.S_IMODE(meta.st_mode),'gid':meta.st_gid}
            if path.parent==Path('/opt/mcp'): mode=stat.S_IMODE(meta.st_mode);gid=meta.st_gid
        write(path,raw,mode,uid,gid)
    write(backup/'manifest.json',common.canonical(records))
    # Preserve the previous installation receipt; update only files replaced
    # above so fresh verifier can still detect unrelated drift.
    receipt=STATE/'installation/active.json'
    if receipt.exists():
        saved=common.parse(common.read(receipt,secret=True))
        write(backup/'diagnostics-active.json',common.canonical(saved))
        for path in payload:
            if str(path) in saved['files']: saved['files'][str(path)]=diag.installed_record(path)
        write(receipt,common.canonical(saved))
    write(STATE/'monitor-installation.json',common.canonical({'schema':1,'role':role,'layout':layout,'backup':str(backup),
        'files':{str(p):diag.installed_record(p) for p in payload}}))
    common.run(['/usr/bin/systemctl','daemon-reload'])
    common.run(['/usr/bin/systemctl','start',diag.SERVICE],timeout=100)
    if role=='siem':
        for name in units(role):
            if name.endswith('.timer'): common.run(['/usr/bin/systemctl','enable','--now',name])
    return {'status':'configured','role':role,'backup':str(backup)}


def prepare(s):
    common.mkdir(ETC,0o700)
    key=ETC/'observer_ed25519'
    if not key.exists(): common.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','capstone-A-observer-readonly','-f',str(key)])
    need(stat.S_IMODE(key.stat().st_mode)==0o600 and key.stat().st_uid==0,'observer_key_permissions')
    return {'schema':1,'source':s['hosts']['SECURITY_HOST'],'key':common.public_key(common.read(str(key)+'.pub'))}


def authorize(s,role,value):
    need(role in ('siem','service') and set(value)=={'schema','source','key'} and value['schema']==1 and value['source']==s['hosts']['SECURITY_HOST'],'observer_public_identity')
    public=common.public_key(value['key'].encode());gid=grp.getgrnam(diag.GROUP).gr_gid
    try: user=pwd.getpwnam(diag.ACCOUNT)
    except KeyError:
        need(role=='siem','existing_C_reader_required')
        common.run(['/usr/sbin/useradd','--system','--gid',diag.GROUP,'--no-create-home','--home-dir',str(diag.READER_HOME),'--shell','/bin/dash',diag.ACCOUNT])
        common.run(['/usr/sbin/usermod','--password','*',diag.ACCOUNT]);user=pwd.getpwnam(diag.ACCOUNT)
    need(user.pw_dir==str(diag.READER_HOME) and user.pw_shell=='/bin/dash' and user.pw_gid==gid,'reader_identity')
    common.mkdir(diag.READER_HOME,0o750,0,gid);common.mkdir(diag.READER_HOME/'.ssh',0o750,0,gid)
    write(CODE/'read-system-diagnostics.py',common.read(s['source']/'infra/mcp/read-system-diagnostics.py'),0o550,0,gid)
    write(CODE/'read-snapshot',diag.reader_launcher(),0o550,0,gid)
    keyfile=diag.READER_HOME/'.ssh/authorized_keys'
    old=common.read(keyfile).decode() if keyfile.exists() else ''
    line='from="'+value['source']+'",restrict,command="'+str(CODE/'read-snapshot')+'" '+public+'\n'
    if line not in old.splitlines(keepends=True): write(keyfile,(old+line).encode(),0o640,0,gid)
    write('/etc/ssh/sshd_config.d/63-capstone-diagnostics.conf',diag.reader_ssh_configuration(),0o644)
    common.run(['/usr/sbin/sshd','-t']);common.run(['/usr/bin/systemctl','reload','ssh'])
    # The existing B key is preserved; only this exact additional forced-read
    # identity is accounted for in the earlier diagnostic receipt.
    receipt=STATE/'installation/active.json'
    if receipt.exists():
        saved=common.parse(common.read(receipt,secret=True))
        if str(keyfile) in saved['files']: saved['files'][str(keyfile)]=diag.installed_record(keyfile)
        write(receipt,common.canonical(saved))
    return {'schema':1,'host':diag.ROLE_HOST[role],'address':s['hosts'][diag.HOST_ENV[role]],
        'host_key':common.public_key(common.read('/etc/ssh/ssh_host_ed25519_key.pub'))}


def trust(s,values):
    need(isinstance(values,list) and len(values)==2 and {v['host'] for v in values}=={'b','c'},'observer_host_set')
    lines=[]
    for v in values:
        expected=s['hosts']['SIEM_HOST' if v['host']=='b' else 'SERVICE_HOST']
        need(set(v)=={'schema','host','address','host_key'} and v['schema']==1 and v['address']==expected,'observer_host_identity')
        name=expected if s['ssh_port']==22 else '['+expected+']:'+str(s['ssh_port'])
        lines.append(name+' '+common.public_key(v['host_key'].encode()))
    write(ETC/'observer_known_hosts',('\n'.join(lines)+'\n').encode())
    return {'status':'trusted','hosts':['b','c']}


def export_webhook():
    raw=common.read('/etc/capstone-management/controller.env',secret=True).decode()
    values=[x.split('=',1)[1] for x in raw.splitlines() if x.startswith('MM_WEBHOOK=')]
    need(len(values)==1,'one_existing_webhook_required')
    decoded=shlex.split(values[0],posix=True)
    need(len(decoded)==1,'one_existing_webhook_required')
    hook=urlsplit(decoded[0])
    need(re.fullmatch(r'/hooks/[a-z0-9]{26}',hook.path) and not hook.query and not hook.fragment,'observer_webhook')
    # A cannot necessarily reach B's locally restricted :8065. Use the
    # already configured Mattermost HTTPS ingress, preserving the same hook.
    cfg=common.parse(common.read(ETC/'runtime.json'))
    binary='/usr/local/bin/docker' if cfg['layout']=='groot' else '/usr/bin/docker'
    name='mm-app' if cfg['layout']=='groot' else 'capstone-mattermost'
    environment=common.parse(common.run([binary,'inspect','--format','{{json .Config.Env}}',name]))
    sites=[x.split('=',1)[1] for x in environment if x.startswith('MM_SERVICESETTINGS_SITEURL=')]
    need(len(sites)==1,'one_mattermost_site_required');site=sites[0]
    u=urlsplit(site)
    need(u.scheme=='https' and u.hostname and not u.username and not u.password
         and u.path in ('','/') and not u.query and not u.fragment,'observer_https_ingress_required')
    return {'schema':1,'webhook':site.rstrip('/')+hook.path}


def activate(s,value):
    need(set(value)=={'schema','webhook'} and value['schema']==1,'observer_secret_stream')
    u=urlsplit(value['webhook'])
    need(u.scheme in ('http','https') and u.hostname and not u.username and not u.password and u.path.startswith('/hooks/') and not u.query and not u.fragment,'observer_webhook')
    write(ETC/'monitor.json',common.canonical({'schema':1,'hosts':{'b':s['hosts']['SIEM_HOST'],'c':s['hosts']['SERVICE_HOST']},'ssh_port':s['ssh_port'],'webhook':value['webhook']}))
    common.run(['/usr/bin/systemctl','enable','--now','capstone-soc-observe.timer'])
    common.run(['/usr/bin/systemctl','start','capstone-soc-observe.service'],timeout=60)
    return {'status':'active','out_of_band':False}


def verify(role):
    saved=common.parse(common.read(STATE/'monitor-installation.json',secret=True))
    need(saved['role']==role,'monitor_receipt_role')
    for path,record in saved['files'].items(): need(diag.installed_record(path)==record,'monitor_file_drift')
    for name in units(role):
        if name.endswith('.timer'):
            common.run(['/usr/bin/systemctl','is-active',name]);common.run(['/usr/bin/systemctl','is-enabled',name])
    need(common.parse(common.read(STATE/'snapshot.json'))['schema']==2,'runtime_snapshot_required')
    return {'status':'verified','role':role,'probe_results_require_live_review':True,'attack_e2e':False}


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('configure','prepare','authorize','trust','export','activate','verify'))
    p.add_argument('--role',required=True,choices=tuple(diag.ROLE_HOST));p.add_argument('--existing-groot',action='store_true')
    args=p.parse_args();need(os.geteuid()==0,'root_required');os.umask(0o077);s=diag.settings()
    if args.action=='configure': result=configure(s,args.role,'groot' if args.existing_groot else 'fresh')
    elif args.action=='prepare': need(args.role=='security','A_required');result=prepare(s)
    elif args.action=='authorize': result=authorize(s,args.role,common.parse(sys.stdin.buffer.read(8193)))
    elif args.action=='trust': need(args.role=='security','A_required');result=trust(s,common.parse(sys.stdin.buffer.read(16385)))
    elif args.action=='export': need(args.role=='siem','B_required');result=export_webhook()
    elif args.action=='activate': need(args.role=='security','A_required');result=activate(s,common.parse(sys.stdin.buffer.read(8193)))
    else: result=verify(args.role)
    sys.stdout.buffer.write(common.canonical(result))


if __name__=='__main__':
    try: main()
    except Exception:
        print('{"status":"failed","reason":"monitor_installation_refused"}',file=sys.stderr)
        raise SystemExit(78)
