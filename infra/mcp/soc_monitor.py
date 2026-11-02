#!/usr/bin/env python3
"""Independent root health observer and bounded probes; never security response.

Fixed endpoints only. The A outbox survives B/Mattermost outages. Failed sends
are retried at least once; an HTTP acknowledgement lost in transit may duplicate
the same event ID. No outage is silently discarded to meet a queue cap.
"""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import tempfile
import time
import types
from urllib.parse import urlsplit

CODE = Path('/opt/capstone-diagnostics')
STATE = Path('/var/lib/capstone-diagnostics')
ETC = Path('/etc/capstone-diagnostics')
KST = timezone(timedelta(hours=9))
PROBE_REASONS = frozenset(('response_ok', 'request_timeout', 'connection_failure',
    'network_failure', 'http_failure', 'protocol_failure', 'invalid_response', 'legacy_unknown'))


def core():
    path = CODE / 'system_diagnostics.py'
    for parent in (path.parent, *path.parent.parents):
        m = parent.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022: raise ValueError('unsafe_code')
    m = path.lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_nlink != 1 or m.st_mode & 0o022: raise ValueError('unsafe_code')
    module = types.ModuleType('fixed_diagnostics');module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def pipeline(d):
    path=CODE/'pipeline_probe.py';module=types.ModuleType('fixed_pipeline_probe');module.__file__=str(path)
    exec(compile(d.root_file(path,65536),str(path),'exec'),module.__dict__)
    return module


def atomic(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.monitor-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchmod(stream.fileno(), 0o600);json.dump(value, stream, sort_keys=True)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def transport(d, host, cfg):
    d.need(host in ('a','b','c') and host in cfg['hosts'], 'monitor_host')
    for name in ('observer_ed25519','observer_known_hosts'): d.root_file(ETC / name, 32768, 0o600)
    argv = ['/usr/bin/ssh','-F','/dev/null','-T','-p',str(cfg['ssh_port']),
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','ControlMaster=no','-o','ControlPath=none',
        '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no',
        '-o','ConnectTimeout=4','-o','ConnectionAttempts=1',
        '-o','UserKnownHostsFile='+str(ETC/'observer_known_hosts'),'-i',str(ETC/'observer_ed25519'),
        'capstone-diagnostics@'+cfg['hosts'][host]]
    rc, raw = d.bounded_command(argv, d.MAX_SNAPSHOT, 10)
    d.need(rc == 0, 'snapshot_transport_unavailable')
    return d.validate_snapshot(d.parsed(raw), host)


def signals(d, snapshots):
    rows = {}
    for role, host in d.ROLE_HOST.items():
        snap = snapshots.get(host)
        rows[host+':snapshot'] = 'ok' if snap else 'unavailable'
        if not snap: continue
        for target, row in snap.get('runtime',{}).items():
            metrics=row.get('metrics',{})
            age=metrics.get('input_age_seconds')
            if target=='b:ingestion' and metrics.get('probe_succeeded') is False and type(age) in (int,float) and 0<=age<=180:
                continue
            rows[target] = row['status']
        if 'runtime' not in snap: rows[host+':runtime'] = 'unavailable'
        for target, row in snap['units'].items():
            p = row['properties']
            # These legacy entries are deliberately not installed on B.
            if target in ('b:vector','b:wazuh-agent') and p['LoadState']=='not-found': continue
            ok = row['status']=='observed' and p['LoadState']=='loaded' and p['Result'] in (None,'success') and (
                p['ActiveState']=='active' or p['Type']=='oneshot' and p['Result']=='success')
            rows[target] = 'ok' if ok else 'unavailable' if row['status']=='unavailable' else 'degraded'
    return rows


def database(path):
    if path.exists():
        m=path.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=os.geteuid() or m.st_mode&0o077 or m.st_nlink!=1:
            raise ValueError('unsafe_monitor_database')
    db=sqlite3.connect(path, timeout=5)
    os.chmod(path,0o600)
    db.execute('pragma journal_mode=WAL');db.execute('pragma synchronous=FULL')
    db.execute('create table if not exists health (target text primary key,status text,first_seen integer,streak integer,announced text)')
    db.execute('create table if not exists outbox (id integer primary key autoincrement,target text,status text,started integer,observed integer,delivered integer,attempts integer not null default 0)')
    # Additive migration preserves delivered/pending event IDs and supports
    # restoring the previous executable without rewriting notification history.
    if 'reason' not in {row[1] for row in db.execute('pragma table_info(outbox)')}:
        db.execute('alter table outbox add column reason text')
    db.execute('create table if not exists samples (target text primary key,sample_key text)')
    db.execute('create table if not exists episodes (target text primary key,started integer)')
    db.commit();return db


def probe_samples(snapshots):
    """A cached model result is one trial, not one trial per collector tick.

    Stale/missing evidence and live transport failures deliberately keep the
    ordinary observer cadence: a stopped probe must not suppress an outage.
    """
    row=(snapshots.get('b') or {}).get('runtime',{}).get('b:llm',{})
    metrics=row.get('metrics',{});rid=metrics.get('probe_run_id')
    codes=row.get('codes',[])
    if (row.get('status') not in ('ok','degraded') or
            any(code!='model_request_failed' for code in codes) or
            not isinstance(rid,str) or not re.fullmatch('[0-9a-f]{32}',rid)):
        return {},{}
    reason=metrics.get('probe_result_reason','legacy_unknown')
    return {'b:llm':rid},{'b:llm':reason if isinstance(reason,str) and reason in PROBE_REASONS else 'legacy_unknown'}


def record(db, rows, now, sample_keys=None, reasons=None):
    sample_keys=sample_keys or {};reasons=reasons or {}
    with db:
        for target, status in sorted(rows.items()):
            key=sample_keys.get(target)
            prior=None
            if key is not None:
                if not isinstance(key,str) or not re.fullmatch('[0-9a-f]{32}',key):
                    raise ValueError('invalid_probe_identity')
                key=status+':'+key
                prior=db.execute('select sample_key from samples where target=?',(target,)).fetchone()
                if prior and prior[0]==key: continue
                db.execute('insert or replace into samples values(?,?)',(target,key))
            else:
                # A live transport/staleness failure breaks a cached success
                # streak. Its later recovery must be counted afresh.
                db.execute('delete from samples where target=?',(target,))
            old=db.execute('select status,first_seen,streak,announced from health where target=?',(target,)).fetchone()
            first=now if not old or old[0]!=status else old[1]
            streak=1 if not old or old[0]!=status else old[2]+1
            if key is not None and prior is None: streak=1
            announced=old[3] if old else 'ok'
            if old and announced not in ('ok','not_installed'):
                db.execute('insert or ignore into episodes values(?,?)',(target,old[1]))
            else:
                # A rollback may have closed the incident using the old
                # executable; do not reuse its episode for a later failure.
                db.execute('delete from episodes where target=?',(target,))
            healthy=status in ('ok','not_installed')
            recovery_required=2 if target=='b:llm' and key is not None else 1
            if status!=announced and ((healthy and announced not in ('ok','not_installed') and streak>=recovery_required) or (not healthy and streak>=2)):
                # Recovery carries the original outage first-seen time.
                episode=db.execute('select started from episodes where target=?',(target,)).fetchone()
                started=episode[0] if healthy and episode else old[1] if healthy and old else first
                reason=reasons.get(target)
                if not isinstance(reason,str) or reason not in PROBE_REASONS: reason=None
                if healthy and recovery_required==2: reason='independent_probe_recovery'
                db.execute('insert into outbox(target,status,started,observed,reason) values(?,?,?,?,?)',(target,status,started,now,reason))
                if healthy: db.execute('delete from episodes where target=?',(target,))
                else: db.execute('insert or ignore into episodes values(?,?)',(target,first))
                announced=status
            db.execute('insert or replace into health values(?,?,?,?,?)',(target,status,first,streak,announced))
        # Pending outages are retained without expiration. Only old delivered
        # notification history is pruned, while current state remains durable.
        db.execute('delete from outbox where delivered is not null and delivered<?',(now-90*86400,))


def webhook_send(url, text):
    u=urlsplit(url)
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.query or u.fragment or not re.fullmatch(r'/hooks/[a-z0-9]{26}',u.path):
        raise ValueError('invalid_monitor_webhook')
    cls=http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection
    connection=cls(u.hostname,u.port,timeout=6)
    try:
        connection.request('POST',u.path,json.dumps({'text':text,'props':{'disable_mentions':True}}),{'Content-Type':'application/json'})
        response=connection.getresponse();body=response.read(1025)
        if response.status!=200 or body.strip()!=b'ok': raise ValueError('notification_not_acknowledged')
    finally: connection.close()


def deliver(db, url, now, sender=webhook_send):
    rows=db.execute('select id,target,status,started,observed,reason from outbox where delivered is null order by id limit 10').fetchall()
    if not rows: return 0
    lines=['[SOC 독립 감시 · A 서버] 장애 기록/복구 알림 (KST)']
    labels={'request_timeout':'35초 내 추론 응답 없음(서버 중단 여부 미확정)',
        'connection_failure':'추론 연결 실패', 'network_failure':'추론 전송 실패',
        'http_failure':'추론 API 오류 응답', 'protocol_failure':'추론 통신 응답 오류',
        'invalid_response':'추론 결과 형식/모델 불일치', 'legacy_unknown':'과거 진단의 상세 원인 미기록',
        'independent_probe_recovery':'서로 다른 소량 추론 진단 2회 성공'}
    for identifier,target,status,started,observed,reason in rows:
        state='복구' if status in ('ok','not_installed') else '이상·미확인'
        if target=='b:llm': state='추론 진단 정상 재확인' if status=='ok' else '추론 진단 이상·미확인'
        lines.append(f'- #{identifier} `{target}` {state} ({status}) · 발생 {datetime.fromtimestamp(started,KST).isoformat()} · 확인 {datetime.fromtimestamp(observed,KST).isoformat()}')
        if reason in labels: lines.append('  원인/근거: '+labels[reason])
    lines.append('지연 전송될 수 있습니다. 보안 사고 정상 판정이나 자동 조치를 수행한 알림이 아닙니다.')
    ids=[row[0] for row in rows]
    with db: db.executemany('update outbox set attempts=attempts+1 where id=?',[(i,) for i in ids])
    sender(url,'\n'.join(lines))
    with db: db.executemany('update outbox set delivered=? where id=?',[(now,i) for i in ids])
    return len(rows)


def observer(d,cfg):
    from concurrent.futures import ThreadPoolExecutor
    def get(host):
        try: return host, d.read_snapshot('a') if host=='a' else transport(d,host,cfg)
        except (ValueError,OSError,KeyError,TypeError): return host,None
    with ThreadPoolExecutor(max_workers=3) as pool: snapshots=dict(pool.map(get,('a','b','c')))
    now=int(time.time());db=database(STATE/'monitor.sqlite3')
    try:
        keys,reasons=probe_samples(snapshots)
        record(db,signals(d,snapshots),now,keys,reasons)
        try:
            b=snapshots.get('b') or {}
            allowed=b.get('runtime',{}).get('b:ingestion',{}).get('metrics',{}).get('canary_allowed') is True
            verified=b.get('runtime',{}).get('b:ingestion',{}).get('metrics',{}).get('verified_run_id')
            pipeline(d).write_canary(d,atomic,now,allowed,verified)
        except (ValueError,OSError):
            record(db,{'a:canary-writer':'unavailable'},now)
        else:
            record(db,{'a:canary-writer':'ok' if allowed else 'unavailable'},now)
        delivery_ok=True
        try: deliver(db,cfg['webhook'],now)
        except (ValueError,OSError,http.client.HTTPException): delivery_ok=False
        pending=db.execute('select count(*) from outbox where delivered is null').fetchone()[0]
        atomic(STATE/'observer.json',{'schema':1,'checked_at':now,'delivery_ok':delivery_ok,'pending_notifications':pending,
            'hosts':{h:s is not None for h,s in snapshots.items()},'out_of_band_notification':False})
    finally: db.close()


def model_probe(d):
    h=d.runtime_library();cfg=h.load_config('siem');now=int(time.time())
    backend=hashlib.sha256(json.dumps([cfg['llm_url'],cfg['model']]).encode()).hexdigest()
    previous=STATE/'model-probe.json'
    old={}
    if previous.exists():
        old=d.parsed(d.root_file(previous,4096))
        if old.get('backend_sha256')==backend and 0<=now-old['checked_at']<180: return
    start=time.monotonic();ok=False;reason='invalid_response';http_status=None
    try:
        response=h.request_json(cfg['llm_url'],'/api/generate',timeout=35,body={
            'model':cfg['model'],'prompt':'Reply OK.','stream':False,'think':False,'keep_alive':'10m',
            'options':{'num_predict':4,'temperature':0}})
        ok=response.get('done') is True and response.get('model')==cfg['model'] and isinstance(response.get('response'),str) and bool(response['response'].strip())
        if ok: reason='response_ok'
    except TimeoutError: reason='request_timeout'
    except ConnectionError: reason='connection_failure'
    except OSError: reason='network_failure'
    except http.client.HTTPException: reason='protocol_failure'
    except (ValueError,AttributeError) as exc:
        status=getattr(exc,'status_code',None)
        if type(status) is int and 100<=status<=599: reason='http_failure';http_status=status
    result={'schema':1,'run_id':secrets.token_hex(16),'checked_at':now,'completed_at':int(time.time()),
        'success':ok,'reason':reason,'backend_sha256':backend,'elapsed_ms':round((time.monotonic()-start)*1000),
        'scope':'bounded_inference_only_no_tool_or_security_judgement'}
    if http_status is not None: result['http_status']=http_status
    if not ok:
        result['last_failure']={k:result[k] for k in ('run_id','checked_at','completed_at','reason','elapsed_ms')}
    elif old.get('backend_sha256')==backend and isinstance(old.get('last_failure'),dict):
        failure=old['last_failure']
        if (isinstance(failure.get('run_id'),str) and re.fullmatch('[0-9a-f]{32}',failure['run_id'])
                and failure.get('reason') in PROBE_REASONS-{'response_ok'}
                and all(type(failure.get(k)) is int and 0<=failure[k]<=2**63 for k in ('checked_at','completed_at','elapsed_ms'))):
            result['last_failure']={k:failure[k] for k in ('run_id','checked_at','completed_at','reason','elapsed_ms')}
    atomic(previous,result)
    # Fixed fields only: never persist model text, exception strings, URLs or
    # credentials. Every actual trial has a durable system journal entry.
    print(json.dumps({'event':'model_probe_result','run_id':result['run_id'],'success':ok,
        'reason':reason,'elapsed_ms':result['elapsed_ms'],'http_status':http_status,
        'started_at_kst':datetime.fromtimestamp(now,KST).isoformat(),
        'completed_at_kst':datetime.fromtimestamp(result['completed_at'],KST).isoformat()}))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=('observe','model','ingestion'))
    args=parser.parse_args()
    if os.getuid()!=0 or os.geteuid()!=0: raise ValueError('root_required')
    os.umask(0o077);d=core()
    with open(STATE/('monitor-'+args.action+'.lock'),'a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='model': model_probe(d)
        elif args.action=='ingestion': pipeline(d).verify(d,atomic)
        else:
            cfg=d.parsed(d.root_file(ETC/'monitor.json',8192,0o600))
            d.need(set(cfg)=={'schema','hosts','ssh_port','webhook'} and cfg['schema']==1 and set(cfg['hosts'])=={'b','c'},'monitor_configuration')
            for value in cfg['hosts'].values(): d.runtime_library().endpoint('http://'+value)
            d.need(type(cfg['ssh_port']) is int and 1<=cfg['ssh_port']<=65535,'monitor_port')
            observer(d,cfg)
    print(json.dumps({'status':'completed','action':args.action,'at_kst':datetime.now(KST).isoformat()}))


if __name__=='__main__':
    try: main()
    except Exception:
        print('{"status":"unavailable","reason":"health_observer_failed"}')
        raise SystemExit(1)
