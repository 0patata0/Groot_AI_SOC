"""Fixed thirteen-row canary, isolated from packet traffic and response rules."""
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
import grp
from pathlib import Path
import re
import stat
import time
import uuid
import xml.etree.ElementTree as ET

CANARY = Path('/var/log/capstone-vector/canary/normalized.jsonl')
CODE = Path('/opt/capstone-diagnostics/canary')
STATE = Path('/var/lib/capstone-diagnostics')
RULE_SHA256 = '9f76264a8038c5c377b4c24a53ab2e3acc0eaf3fce7632df07f921cabdd26995'


def safe_manager(d, cfg):
    h=d.runtime_library();name=h.CONTAINERS[cfg['layout']]['b:wazuh-manager']
    prefix=[h.docker_binary(cfg),'exec',name]
    raw=h.command(d.bounded_command,prefix+['cat','/var/ossec/etc/rules/capstone_vector_rules.xml'])
    d.need(hashlib.sha256(raw.encode()).hexdigest()==RULE_SHA256,'canary_rule_drift')
    root=ET.fromstring('<root>'+h.command(d.bounded_command,prefix+['cat','/var/ossec/etc/ossec.conf'])+'</root>')
    # Fail closed if any enabled response/integration could match the level-3
    # synthetic rules. The established containment rule is unrelated 100110.
    for item in list(root.iter('active-response'))+list(root.iter('integration')):
        if item.findtext('disabled','no')=='yes': continue
        ids={x.strip() for x in item.findtext('rules_id',item.findtext('rule_id','')).split(',') if x.strip()}
        d.need(all(re.fullmatch('[0-9]{1,7}',i) for i in ids) and not ids & {'100290','100291','100292','100293','100294'},'canary_response_scope_unsafe')
        level=item.findtext('level','')
        groups=item.findtext('rules_group',item.findtext('group',''))
        d.need(not groups and ((ids and not ids & {'100290','100291','100292','100293','100294'}) or (level.isdigit() and int(level)>3)), 'canary_response_scope_unsafe')
        d.need(not (level and (not level.isdigit() or int(level)<=3)), 'canary_response_scope_unsafe')
    return True


def canary_directory(d):
    """Pin every path component without following symlinks.

    Ubuntu's /var/log may be root:syslog 0775. Only that specific parent
    accepts the system logging group; all descendants remain root-only.
    The pinned descriptor prevents a parent rename from redirecting writes.
    """
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    path=Path('/')
    try:
        for part in CANARY.parent.parts[1:]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=next_fd;path=path/part;meta=os.fstat(fd)
            logging_parent=(path==Path('/var/log') and meta.st_gid==grp.getgrnam('syslog').gr_gid)
            d.need(meta.st_uid==0 and not meta.st_mode&0o002 and
                   (not meta.st_mode&0o020 or logging_parent),'canary_directory_permissions')
        return fd
    except BaseException:
        os.close(fd);raise


def write_canary(d, atomic, now, allowed, verified_run=None):
    if not allowed: return
    fd=canary_directory(d)
    try:
        _write_canary(d,atomic,now,verified_run,Path('/proc/self/fd')/str(fd)/CANARY.name)
    finally: os.close(fd)


def _write_canary(d, atomic, now, verified_run, path):
    receipt=STATE/'canary-input.json'
    old={}
    if receipt.exists():
        old=d.parsed(d.root_file(receipt,4096))
        if 0<=now-old['checked_at']<900: return
    d.runtime_library().read_file(path,10485760)
    d.need(stat.S_IMODE(path.stat().st_mode)==0o600,'canary_permissions')
    before=path.stat();identity=(before.st_dev,before.st_ino)
    if old.get('success') is True and 'append_end' in old:
        d.need(before.st_size==old['append_end'],'canary_unowned_append_requires_review')
    if before.st_size>=8388608:
        rotate(d,atomic,now,old,verified_run,path)
        return  # Wait for the agent to open the replacement before appending.
    d.need(before.st_size<10450000,'canary_capacity')
    rc,_=d.bounded_command(['/usr/bin/systemctl','is-active','--quiet','wazuh-agent.service'],1024,3)
    d.need(rc==0,'canary_agent_inactive')
    opened=0
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            if proc.joinpath('comm').read_text().strip()!='wazuh-logcollec': continue
            for fd in proc.joinpath('fd').iterdir():
                try:
                    m=fd.stat();opened+=int((m.st_dev,m.st_ino)==identity)
                except OSError: pass
        except OSError: pass
    d.need(opened==1,'canary_input_not_open')
    rid=uuid.uuid4().hex;stamp=datetime.fromtimestamp(now,timezone(timedelta(hours=9))).isoformat();records=[]
    for scenario in ('canary-repeat','canary-cross','canary-repeat-duplicate','canary-historical'):
        for line in d.root_file(CODE/(scenario+'.jsonl'),32768).splitlines():
            row=d.parsed(line);n=row['capstone_norm'];v=row['capstone_validation']
            v.update(run_id=rid,scenario=scenario)
            n.update(correlation_key=hashlib.sha256((rid+':'+scenario).encode()).hexdigest(),observed_at_kst=stamp)
            if n['correlation_time_class']=='fresh': n['event_time_kst']=stamp
            records.append(d.encode(row))
    d.need(len(records)==13 and len(b''.join(records))<=32768,'canary_fixture_shape')
    raw=b''.join(records);fd=os.open(path,os.O_RDWR|os.O_APPEND|os.O_NOFOLLOW)
    with os.fdopen(fd,'r+b',buffering=0) as stream:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);m=os.fstat(fd)
        d.need((m.st_dev,m.st_ino)==identity and m.st_size==before.st_size,'canary_identity')
        # Reserve the run before append. A crash/partial write is not retried
        # with another ID until the next interval; incomplete runs stay failed.
        atomic(receipt,{'schema':1,'checked_at':now,'run_id':rid,'success':False,'rows':13})
        stream.write(b''.join(records[:6]));os.fsync(fd);time.sleep(3)
        d.need((path.stat().st_dev,path.stat().st_ino)==identity,'canary_identity')
        stream.write(b''.join(records[6:]));os.fsync(fd)
        stream.seek(before.st_size);copied=stream.read(len(raw)+1)
        d.need(copied==raw,'canary_append_readback')
    atomic(receipt,{'schema':1,'checked_at':now,'run_id':rid,'success':True,'rows':13,'append_end':before.st_size+len(raw),'sha256':hashlib.sha256(raw).hexdigest()})


def rotate(d,atomic,now,receipt,verified_run,path):
    """Rotate only fully acknowledged bytes; keep pre-existing history forever.

    Unacknowledged input and unexpected append activity refuse rotation. No
    agent restart or copytruncate is used. Old descriptors remain readable.
    """
    d.need(receipt.get('success') is True and receipt.get('run_id')==verified_run,'canary_rotation_requires_receipt')
    marker=STATE/'canary-rotation.json';history=d.parsed(d.root_file(marker,32768)) if marker.exists() else {'schema':1,'archives':[]}
    directory=path.parent/'archive';directory.mkdir(mode=0o700,exist_ok=True)
    meta=directory.lstat()
    d.need(stat.S_ISDIR(meta.st_mode) and meta.st_uid==0 and not meta.st_mode&0o077,'canary_archive_directory')
    with os.fdopen(os.open(path,os.O_RDWR|os.O_NOFOLLOW),'r+b',buffering=0) as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB);meta=os.fstat(stream.fileno())
        d.need(meta.st_size==receipt.get('append_end') and meta.st_ino==path.stat().st_ino,'canary_rotation_identity')
        prefix='initial-' if not marker.exists() else 'monitor-'
        name=prefix+str(now)+'-'+verified_run+'.jsonl';destination=directory/name
        d.need(not destination.exists(),'canary_archive_collision')
        os.rename(path,destination)
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.fsync(fd);os.close(fd)
        history['archives'].append({'name':name,'at':now,'initial':prefix=='initial-'})
        # The initial archive may contain earlier manual test evidence and is
        # never deleted. Later archives contain only this writer's own input.
        retained=[]
        for row in history['archives']:
            archived=directory/row['name']
            d.need(re.fullmatch(r'(?:initial|monitor)-[0-9]+-[0-9a-f]{32}\.jsonl',row['name']),'canary_archive_name')
            if not row['initial'] and now-row['at']>90*86400:
                d.runtime_library().read_file(archived,10485760);archived.unlink()
            else: retained.append(row)
        history['archives']=retained;atomic(marker,history)
        atomic(STATE/'canary-input.json',{**receipt,'append_end':0})


def jq(d, raw, expression, rid):
    repeat=hashlib.sha256((rid+':canary-repeat').encode()).hexdigest()
    cross=hashlib.sha256((rid+':canary-cross').encode()).hexdigest()
    d.root_file(CODE/'canary-validation.jq',32768)
    rc,out=d.bounded_command(['/usr/bin/jq','-ce','-L',str(CODE),'--arg','rid',rid,'--arg','repeat_key',repeat,
        '--arg','cross_key',cross,'include "canary-validation"; '+expression],65536,5,input_data=raw)
    d.need(rc==0,'canary_evidence_mismatch');return d.parsed(out)


def verify(d, atomic):
    h=d.runtime_library();cfg=h.load_config('siem');now=int(time.time())
    result={'schema':1,'checked_at':now,'success':False,'canary_allowed':False,'run_id':'none','input_at':0}
    try:
        result['canary_allowed']=safe_manager(d,cfg)
        # Same fixed snapshot-only identity, stored root-only for this root
        # service. Do not relax SSH file checks or NoNewPrivileges.
        import types
        path=Path('/opt/mcp/system-diagnostics-mcp.py');module=types.ModuleType('fixed_canary_router');module.__file__=str(path)
        exec(compile(d.root_file(path,131072),str(path),'exec'),module.__dict__);module._library=d
        routes=module.route_config()
        key=Path('/etc/capstone-diagnostics/ingestion_ed25519');d.root_file(key,16384,0o600)
        module.IDENTITY=key
        snapshot=module.remote_snapshot('a',routes)
        m=snapshot.get('runtime',{}).get('a:collection',{}).get('metrics',{})
        rid=m.get('canary_run_id','');at=m.get('canary_input_at',0)
        d.need(isinstance(rid,str) and re.fullmatch('[0-9a-f]{32}',rid) and type(at) is int and 0<=now-at<=1200 and m.get('canary_input_verified') is True,'canary_input_stale')
        result.update(run_id=rid,input_at=at)
        previous=STATE/'ingestion-probe.json'
        if previous.exists():
            old=d.parsed(d.root_file(previous,4096))
            if old.get('success') is True and old.get('run_id')==rid:
                # Preserve the actual verification time, not a pretend fresh
                # delivery observation on each poll.
                return
        manager=h.CONTAINERS[cfg['layout']]['b:wazuh-manager'];indexer=h.CONTAINERS[cfg['layout']]['b:wazuh-indexer']
        rc,raw=d.bounded_command([h.docker_binary(cfg),'exec',manager,'tail','-n','10000','/var/ossec/logs/alerts/alerts.json'],16777216,10)
        d.need(rc==0,'canary_manager_unavailable')
        selected=[d.parsed(line) for line in raw.splitlines() if rid.encode() in line]
        m=jq(d,d.encode(selected),'canary_manager($rid; $repeat_key; $cross_key)',rid)
        query={'size':20,'timeout':'5s','track_total_hits':True,'query':{'term':{'data.capstone_validation.run_id':rid}}}
        cert='/usr/share/wazuh-indexer/config/certs/'
        rc,raw=d.bounded_command([h.docker_binary(cfg),'exec','-i',indexer,'curl','--disable','--silent','--fail',
            '--max-time','10','--max-filesize','1048576','--cacert',cert+'root-ca.pem','--cert',cert+'admin.pem',
            '--key',cert+'admin-key.pem','-H','Content-Type: application/json','-X','POST','--data-binary','@-',
            'https://wazuh.indexer:9200/wazuh-alerts-*/_search?allow_partial_search_results=false'],1048576,12,input_data=d.encode(query))
        d.need(rc==0,'canary_indexer_unavailable')
        i=jq(d,raw,'canary_indexer($rid; $repeat_key; $cross_key)',rid)
        d.need(m==i,'canary_tuple_mismatch')
        result.update(success=True,manager_matches=2,indexer_matches=2,exact_tuples_match=True)
    except (ValueError,OSError,KeyError,TypeError,ET.ParseError) as exc:
        result['reason']=str(exc) if isinstance(exc,ValueError) and re.fullmatch('[a-z_]{1,80}',str(exc)) else 'canary_probe_failed'
    atomic(STATE/'ingestion-probe.json',result)
