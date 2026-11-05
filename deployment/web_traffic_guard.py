#!/usr/bin/env python3
"""Reviewed WAF HTTP guards/management redirect; root maintenance only."""
import argparse, base64, hashlib, json, os, re, subprocess, sys, tempfile, time
from pathlib import Path
HOST = Path('/etc/capstone-offline-labs-waf/waf-log4shell-server.conf')
DEST = '/etc/nginx/conf.d/zz-capstone-labs.conf'
POLICY = Path('/etc/rule-change/waf-evidence.json')
STATE = Path('/var/lib/capstone-web-traffic')

def run(args, data=None, timeout=25):
    p = subprocess.run(args, input=data, capture_output=True, timeout=timeout,
        env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})
    if p.returncode: raise RuntimeError('command failed: '+args[0]+': '+p.stderr.decode(errors='replace')[-800:])
    return p.stdout

def sha(data): return hashlib.sha256(data).hexdigest()
def need(ok, reason):
    if not ok: raise RuntimeError(reason)

def trusted(p):
    for q in [*reversed(p.parents),p]:
        if q.exists() or q.is_symlink():
            s=q.lstat();need(not q.is_symlink() and s.st_uid==0 and not s.st_mode&0o022,'untrusted path')
    return p

def write(p, raw, mode=0o600):
    trusted(p);fd,tmp=tempfile.mkstemp(dir=p.parent,prefix='.guard-')
    try:
        with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def identity():
    r=json.loads(run(['docker','inspect','waf']))[0]
    need(r['State']['Running'],'WAF stopped')
    return {k:r['State'][k] for k in ('Pid','StartedAt')}|{'id':r['Id'],'image':r['Image']}

def read_container(cid):return run(['docker','exec','--user','0',cid,'cat',DEST])
def replace_container(cid, raw, scratch):
    f=scratch/'container-candidate.conf';write(f,raw,0o644)
    run(['docker','cp',str(f),cid+':'+DEST]);run(['docker','exec','--user','0',cid,'chmod','0644',DEST])

def rollback(directory,manual=False):
    trusted(directory);need(directory.parent==STATE and re.fullmatch(r'run-[0-9]+',directory.name),'recovery directory')
    if (directory/'confirmed').exists() and not manual:return {'state':'confirmed_noop'}
    doc=json.loads(trusted(directory/'state.json').read_text());need(identity()==doc['identity'],'WAF identity drift')
    for p in (HOST,POLICY):need(sha(trusted(p).read_bytes()) in [doc[str(p)+'_before_sha'],doc[str(p)+'_after_sha']],'concurrent file edit')
    need(sha(read_container(doc['identity']['id'])) in (doc['container_before_sha'],doc['container_after_sha']),'container config drift')
    replace_container(doc['identity']['id'],base64.b64decode(doc['container_before']),directory)
    for p in (HOST,POLICY):write(p,base64.b64decode(doc[str(p)+'_before']),doc[str(p)+'_mode'])
    run(['docker','exec','waf','nginx','-t']);run(['docker','exec','waf','nginx','-s','reload'])
    return {'state':'rolled_back','container_preserved':identity()==doc['identity']}

def apply(source,expected):
    raw=trusted(source).read_bytes();need(0<len(raw)<65536,'candidate size')
    need(b'limit_req_status 429;' in raw and b'server_name wazuh.groot.lab wazuh.grootlab.duckdns.org;' in raw,'required guard missing')
    before=identity();cid=before['id'];original=read_container(cid)
    need(sha(original)==expected and sha(trusted(HOST).read_bytes())==expected,'exact old config mismatch')
    # These files live in the writable layer, never an unreviewed mounted path.
    mounts=json.loads(run(['docker','inspect','--format','{{json .Mounts}}','waf']))
    need(not any(DEST==m['Destination'] or DEST.startswith(m['Destination'].rstrip('/')+'/') for m in mounts),'mounted configuration requires separate inode-safe plan')
    policy=json.loads(trusted(POLICY).read_text());need(policy['config_sha256'][DEST]==expected,'evidence policy drift')
    after_policy=dict(policy,config_sha256={**policy['config_sha256'],DEST:sha(raw)})
    encoded_policy=(json.dumps(after_policy,sort_keys=True,separators=(',',':'))+'\n').encode()
    directory=STATE/('run-'+str(time.time_ns()));directory.mkdir(mode=0o700)
    doc={'identity':before,'container_before':base64.b64encode(original).decode(),'container_before_sha':sha(original),'container_after_sha':sha(raw)}
    for p,new in ((HOST,raw),(POLICY,encoded_policy)):
        old=trusted(p).read_bytes();doc.update({str(p)+'_before':base64.b64encode(old).decode(),str(p)+'_before_sha':sha(old),str(p)+'_after_sha':sha(new),str(p)+'_mode':p.stat().st_mode&0o777})
    write(directory/'state.json',json.dumps(doc).encode());write(directory/'recovery.py',Path(__file__).read_bytes())
    timer='capstone-web-traffic-'+directory.name
    run(['systemd-run','--quiet','--unit='+timer,'--on-active=15min','/usr/bin/python3','-IB',str(directory/'recovery.py'),'rollback','--directory',str(directory)])
    try:
        write(HOST,raw,doc[str(HOST)+'_mode']);replace_container(cid,raw,directory)
        run(['docker','exec','waf','nginx','-t']);run(['docker','exec','waf','nginx','-s','reload'])
        run(['/usr/bin/python3','-IB','/opt/rule-change/configure_waf_evidence.py'])
        need(sha(POLICY.read_bytes())==sha(encoded_policy) and identity()==before,'enrollment/readback mismatch')
        return {'state':'awaiting_confirmation','directory':str(directory),'timer':timer+'.timer','sha256':sha(raw),'container_preserved':True,'evidence_reenrolled':True}
    except BaseException:
        rollback(directory);raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('apply','confirm','rollback'));p.add_argument('--source',type=Path);p.add_argument('--expected-sha256');p.add_argument('--directory',type=Path);p.add_argument('--manual',action='store_true');a=p.parse_args()
    need(os.geteuid()==0,'root maintenance only');trusted(STATE);STATE.mkdir(mode=0o700,exist_ok=True)
    if a.action=='apply':result=apply(a.source,a.expected_sha256)
    elif a.action=='rollback':result=rollback(a.directory,a.manual)
    else:
        d=a.directory;trusted(d);need(d.parent==STATE and re.fullmatch(r'run-[0-9]+',d.name),'confirmation directory');doc=json.loads((d/'state.json').read_text())
        need(identity()==doc['identity'] and sha(read_container(doc['identity']['id']))==doc['container_after_sha'],'confirmation config drift')
        for q in (HOST,POLICY):need(sha(trusted(q).read_bytes())==doc[str(q)+'_after_sha'],'confirmation source drift')
        write(d/'confirmed',b'confirmed\n');run(['systemctl','stop','capstone-web-traffic-'+d.name+'.timer']);result={'state':'confirmed'}
    print(json.dumps(result))

if __name__=='__main__':
    try:main()
    except (RuntimeError,OSError,ValueError,subprocess.SubprocessError) as e:print(str(e),file=sys.stderr);sys.exit(1)
