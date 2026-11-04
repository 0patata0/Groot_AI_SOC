#!/usr/bin/env python3
"""Operator-only, exact-profile rollout of enforced public web inspection.

Not an MCP tool: no model-selected file, shell, Docker action or service is
accepted. Preserve sources/permissions and independent recovery on each host.
"""
import argparse
import ast
import base64
from datetime import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import time
import uuid
from zoneinfo import ZoneInfo

STATE = Path('/var/lib/capstone-web-security')
BASE = 'infra/groot-c/offline-labs/'
FILES = {
 'a': {BASE+'nginx-log4shell-server.conf': '/home/groot_a/capstone/chatproxy/nginx.conf',
       BASE+'REQUEST-900-CAPSTONE-LABS.conf': '/etc/capstone-offline-labs-waf/REQUEST-900-CAPSTONE-LABS.conf',
       BASE+'waf-log4shell-server.conf': '/etc/capstone-offline-labs-waf/waf-log4shell-server.conf'},
 'c': {BASE+n: '/opt/capstone-offline-labs/'+n for n in (
       'app.py','practice_mode.py','challenge.py','static/app.js','static/index.html',
       'REQUEST-900-CAPSTONE-LABS.conf','waf-log4shell-server.conf','nginx-log4shell-server.conf','scripts/bootstrap.py')},
}
CONTAINER_FILES = {
 '/etc/capstone-offline-labs-waf/REQUEST-900-CAPSTONE-LABS.conf': '/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-LABS.conf',
 '/etc/capstone-offline-labs-waf/waf-log4shell-server.conf': '/etc/nginx/conf.d/zz-capstone-labs.conf',
}


def sha(value): return hashlib.sha256(value).hexdigest()
def clock(): return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def run(args, value=None):
    p=subprocess.run(args,input=value,capture_output=True,text=True,timeout=25)
    if p.returncode: raise RuntimeError(json.dumps({'command':args[:4],'rc':p.returncode,'error':p.stderr[-1300:]}))
    return p.stdout


def trusted(path):
    for item in (path,*path.parents):
        s=item.lstat()
        if not (stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)) or s.st_uid or s.st_mode & 0o022:
            raise ValueError('untrusted_web_policy_path')
    return path


def source_fd(path,flags=os.O_RDONLY):
    if str(path) not in {name for role in FILES.values() for name in role.values()}:
        raise ValueError('fixed_web_source_required')
    # Resolve every directory relative to a pinned fd, refusing intermediate
    # symlinks too. The existing A bind source lives below its named user's home.
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    current=Path('/')
    try:
        for part in path.parts[1:-1]:
            current=current/part
            new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=new;s=os.fstat(fd)
            owners={0}
            named=None
            if current==Path('/home/groot_a') or Path('/home/groot_a') in current.parents:
                named=pwd.getpwnam('groot_a');owners.add(named.pw_uid)
            existing_group_directory=(named is not None and current in (
                Path('/home/groot_a/capstone'),Path('/home/groot_a/capstone/chatproxy'))
                and s.st_uid==named.pw_uid and s.st_gid==named.pw_gid)
            if s.st_uid not in owners or s.st_mode&0o002 or (s.st_mode&0o020 and not existing_group_directory):
                raise ValueError('unsafe_web_source_directory')
        out=os.open(path.name,flags|os.O_NOFOLLOW,dir_fd=fd)
        s=os.fstat(out)
        if s.st_uid or s.st_nlink!=1 or not stat.S_ISREG(s.st_mode) or s.st_mode&0o022:
            os.close(out);raise ValueError('root_owned_single_web_source_required')
        return out
    finally:os.close(fd)


def file_info(path):
    with os.fdopen(source_fd(path),'rb') as f:
        b=f.read();s=os.fstat(f.fileno())
    return {'sha256':sha(b),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'content':base64.b64encode(b).decode()}


def same(actual,expected):
    return all(actual[k]==expected[k] for k in ('sha256','uid','gid','mode'))


def write(path,data,meta,expected):
    # Preserve the inode because A's Nginx configuration is a file bind mount.
    with os.fdopen(source_fd(path,os.O_RDWR),'r+b') as out:
        s=os.fstat(out.fileno());current={'sha256':sha(out.read()),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
        if not same(current,expected):raise ValueError('web_source_changed_before_write')
        out.seek(0);out.write(data);out.truncate();out.flush();os.fsync(out.fileno())
        os.fchown(out.fileno(),meta['uid'],meta['gid']);os.fchmod(out.fileno(),meta['mode'])


def proxy_candidate(original, template):
    marker='server_name log4shell.grootlab.duckdns.org;'
    if original.count(marker)!=1 or template.count(marker)!=1:raise ValueError('unique_log4shell_vhost_required')
    start=original.rfind('    server {',0,original.index(marker))
    end=original.index('\n    }',original.index(marker))+len('\n    }')
    if start<0:raise ValueError('log4shell_vhost_boundary')
    candidate=template[template.index('    server {'):].rstrip()
    if 'proxy_pass http://10.200.10.20:80/_offline-labs/;' in candidate:
        raise ValueError('public_UI_WAF_bypass_refused')
    if candidate.count('proxy_set_header X-Capstone-Lab-Mode enforce;')!=4:
        raise ValueError('all_web_routes_must_enforce')
    return original[:start]+candidate+original[end:]


def identities():
    out={}
    for name in ('waf','chatproxy'):
        x=json.loads(run(['docker','inspect',name]))[0]
        if not x['State']['Running']:raise ValueError('existing_web_container_not_running')
        out[name]={'id':x['Id'],'image':x['Image'],'started_at':x['State']['StartedAt']}
    return out


def container_sources():
    return {dst:sha(run(['docker','exec','waf','cat',dst]).encode()) for dst in CONTAINER_FILES.values()}


def artifact(path):
    if not isinstance(path,Path):raise ValueError('prepared_web_directory_required')
    if path.parent!=STATE or not re.fullmatch(r'change-[0-9a-f]{16}',path.name):raise ValueError('web_recovery_scope')
    m=json.loads(trusted(path/'manifest.json').read_text())
    digest=m.pop('plan_sha256')
    if sha(json.dumps(m,sort_keys=True,separators=(',',':')).encode())!=digest:raise ValueError('web_manifest_digest')
    m['plan_sha256']=digest
    if m['role'] not in FILES or set(m['files'])!=set(FILES[m['role']].values()):raise ValueError('web_file_allowlist')
    if sha(trusted(path/'recovery.py').read_bytes())!=m['controller_sha256'] or sha(Path(__file__).read_bytes())!=m['controller_sha256']:
        raise ValueError('approved_web_controller_changed')
    return m


def prepare(role,source):
    addresses=run(['ip','-j','-4','addr'])
    if ('192.168.16.230' if role=='a' else '10.200.10.20') not in addresses:
        raise ValueError('existing_reviewed_A_or_C_required')
    STATE.mkdir(mode=0o700,parents=True,exist_ok=True);trusted(STATE)
    path=STATE/('change-'+uuid.uuid4().hex[:16]);path.mkdir(mode=0o700)
    m={'schema':1,'role':role,'created_at_kst':clock(),'controller_sha256':sha(Path(__file__).read_bytes()),'files':{},'containers':identities() if role=='a' else {},
       'unit':'capstone-web-recover-'+path.name.removeprefix('change-')}
    for relative,name in FILES[role].items():
        target=Path(name);before=file_info(target);after=(source/relative).read_bytes()
        if role=='a' and name.endswith('/nginx.conf'):
            after=proxy_candidate(target.read_text(),after.decode()).encode()
        if name.endswith('.py'):ast.parse(after)
        if name.endswith('REQUEST-900-CAPSTONE-LABS.conf') and b'ctl:ruleEngine=DetectionOnly' in after:
            raise ValueError('WAF_exemption_refused')
        desired=dict(before,sha256=sha(after),content=base64.b64encode(after).decode())
        m['files'][name]={'before':before,'after':desired}
    if role=='a':
        m['container_sources']=container_sources()
        for src,dst in CONTAINER_FILES.items():
            if m['container_sources'][dst]!=m['files'][src]['before']['sha256']:raise ValueError('waf_host_container_source_drift')
        candidate=path/'proxy.after';candidate.write_bytes(base64.b64decode(m['files']['/home/groot_a/capstone/chatproxy/nginx.conf']['after']['content']));candidate.chmod(0o644)
        dest='/tmp/capstone-web-'+path.name+'.conf'
        run(['docker','cp',str(candidate),'chatproxy:'+dest])
        try:run(['docker','exec','chatproxy','nginx','-t','-c',dest])
        finally:run(['docker','exec','chatproxy','rm','-f',dest])
    m['plan_sha256']=sha(json.dumps(m,sort_keys=True,separators=(',',':')).encode())
    (path/'manifest.json').write_text(json.dumps(m,sort_keys=True));(path/'manifest.json').chmod(0o600)
    (path/'recovery.py').write_bytes(Path(__file__).read_bytes());(path/'recovery.py').chmod(0o600)
    return {'status':'prepared_not_applied','directory':str(path),'plan_sha256':m['plan_sha256'],
            'files':{name:{side:row[side]['sha256'] for side in ('before','after')} for name,row in m['files'].items()}}


def validate_files(m,side=None):
    for name,row in m['files'].items():
        current=file_info(Path(name));allowed=[row[side]] if side else [row['before'],row['after']]
        if not any(same(current,expected) for expected in allowed):raise ValueError('web_source_drift:'+name)
    if m['role']=='a':
        if identities()!=m['containers']:raise ValueError('web_container_identity_changed')
        actual=container_sources()
        for src,dst in CONTAINER_FILES.items():
            allowed=[m['files'][src][side]['sha256']] if side else [m['files'][src][k]['sha256'] for k in ('before','after')]
            if actual[dst] not in allowed:raise ValueError('waf_container_source_drift')


def set_sources(m,side):
    for name,row in m['files'].items():
        desired=row[side]
        current=file_info(Path(name))
        if not same(current,desired):write(Path(name),base64.b64decode(desired['content']),desired,current)
    if m['role']=='a':
        current=container_sources()
        for src,dst in CONTAINER_FILES.items():
            row=m['files'][src][side]
            if current[dst]!=row['sha256']:
                run(['docker','exec','--user','0','-i','waf','sh','-c','cat > '+dst],base64.b64decode(row['content']).decode())


def activate(m):
    if m['role']=='a':
        for name in ('waf','chatproxy'):run(['docker','exec',name,'nginx','-t'])
        for name in ('waf','chatproxy'):run(['docker','exec',name,'nginx','-s','reload'])
    else:
        run(['systemctl','restart','capstone-offline-labs.service'])
        deadline=time.monotonic()+12
        while True:
            try:
                conn=http.client.HTTPConnection('127.0.0.1',18090,timeout=2)
                conn.request('GET','/api/session',headers={'Host':'127.0.0.1:18090'});response=conn.getresponse();value=json.loads(response.read());conn.close()
                if response.status==200 and value.get('mode')=='enforce':break
            except (OSError,ValueError,http.client.HTTPException):pass
            if time.monotonic()>deadline:raise RuntimeError('web_api_not_ready')
            time.sleep(.15)


def verify(path):
    m=artifact(path);validate_files(m,'after')
    if m['role']=='a':
        for name in ('waf','chatproxy'):run(['docker','exec',name,'nginx','-t'])
    else:
        run(['systemctl','is-active','--quiet','capstone-offline-labs.service'])
        conn=http.client.HTTPConnection('127.0.0.1',18090,timeout=2)
        try:
            conn.request('GET','/api/session',headers={'Host':'127.0.0.1:18090'});response=conn.getresponse();value=json.loads(response.read())
        finally:conn.close()
        if response.status!=200 or value!={'mode':'enforce','expires_at':None,'admin_authenticated':False,'admin_expires_at':None}:
            raise ValueError('new_web_administrator_contract_not_live')
    return {'status':'verified','observed_at_kst':clock(),'plan_sha256':m['plan_sha256']}


def recover(path,manual=False):
    m=artifact(path)
    if (path/'confirmed.json').exists() and not manual:return {'status':'confirmed_recovery_noop'}
    validate_files(m)
    if all(same(file_info(Path(n)),r['before']) for n,r in m['files'].items()):
        if m['role']!='a' or container_sources()==m['container_sources']:return {'status':'already_original'}
    set_sources(m,'before');activate(m);validate_files(m,'before')
    return {'status':'restored_original','observed_at_kst':clock()}


def apply(path,approved):
    m=artifact(path)
    if approved!=m['plan_sha256']:raise ValueError('exact_prepared_plan_approval_required')
    validate_files(m,'before')
    run(['systemd-run','--unit='+m['unit'],'--on-active=15m','--timer-property=AccuracySec=1s',
         '/usr/bin/python3','-I','-B',str(path/'recovery.py'),'recover','--directory',str(path)])
    run(['systemctl','is-active','--quiet',m['unit']+'.timer'])
    try:
        set_sources(m,'after');activate(m);result=verify(path)
    except BaseException:
        recover(path);raise
    result.update(status='applied_awaiting_external_verification',directory=str(path),timer=m['unit']+'.timer')
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('prepare','apply','verify','confirm','recover','rollback'))
    p.add_argument('--role',choices=('a','c'));p.add_argument('--source-root',type=Path)
    p.add_argument('--directory',type=Path);p.add_argument('--approved-plan-sha256')
    args=p.parse_args()
    if os.geteuid()!=0:raise ValueError('root_operator_required')
    fd=os.open('/run/lock/capstone-web-security.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if info.st_uid or info.st_nlink!=1 or not stat.S_ISREG(info.st_mode) or info.st_mode&0o022:raise ValueError('unsafe_web_policy_lock')
        fcntl.flock(fd,fcntl.LOCK_EX)
        if args.action=='prepare':
            if not args.role or not args.source_root:raise ValueError('role_and_source_required')
            result=prepare(args.role,args.source_root)
        elif args.action=='apply':result=apply(args.directory,args.approved_plan_sha256)
        elif args.action in ('recover','rollback'):result=recover(args.directory,manual=args.action=='rollback')
        else:
            result=verify(args.directory)
            if args.action=='confirm':
                m=artifact(args.directory);out=args.directory/'confirmed.json';out.write_text(json.dumps(result));out.chmod(0o600)
                run(['systemctl','stop',m['unit']+'.timer']);result['status']='confirmed'
    finally:os.close(fd)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
