#!/usr/bin/env python3
"""Move only A's three reviewed NAT rules into existing ip nat base chains.

Docker rules, host filtering and timed containment are left in place. All
iptables writes use its native restore path; no native sets are added to a
Docker compatibility table. Root maintenance only, entered through deploy.sh.
"""
import argparse,base64,copy,fcntl,hashlib,ipaddress,json,os,re,shlex,stat,subprocess,tempfile,time
from pathlib import Path
from datetime import datetime,timezone,timedelta
CODE=Path('/usr/local/libexec/capstone-firewall-nat.py')
LOADER=Path('/usr/local/sbin/capstone-nat.sh')
UNIT=Path('/etc/systemd/system/capstone-nat.service')
STATE=Path('/var/lib/capstone-basic-nat')
CHAINS=('nat_prerouting','nat_postrouting')
PREFIX='capstone-basic-nat-'
DEFAULT={'schema': 1, 'external_interface': 'ens192', 'internal_interface': 'ens160', 'internal_network': '10.200.10.0/24', 'management_source': '192.168.16.231/32', 'forwards': [{'external_port': 10443, 'address': '10.200.10.10', 'port': 443}]}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def checked(value):
    if type(value) is not dict or set(value) != set(DEFAULT) or value['schema'] != 1:
        raise ValueError('nat_configuration_fields')
    value = copy.deepcopy(value)
    for key in ('external_interface', 'internal_interface'):
        if type(value[key]) is not str or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value[key]):
            raise ValueError('nat_interface')
    if value['external_interface'] == value['internal_interface']:
        raise ValueError('nat_distinct_interfaces_required')
    for key in ('internal_network', 'management_source'):
        network = ipaddress.IPv4Network(value[key], strict=True)
        if str(network) != value[key] or not network.prefixlen or network.is_multicast:
            raise ValueError('nat_source_network')
    forwards = value['forwards']
    if type(forwards) is not list or not 1 <= len(forwards) <= 16:
        raise ValueError('nat_forward_count')
    seen = set()
    for row in forwards:
        if type(row) is not dict or set(row) != {'external_port', 'address', 'port'}:
            raise ValueError('nat_forward_fields')
        address = ipaddress.IPv4Address(row['address'])
        if str(address) != row['address'] or address not in ipaddress.IPv4Network(value['internal_network']):
            raise ValueError('nat_forward_address')
        for key in ('external_port', 'port'):
            if type(row[key]) is not int or not 1 <= row[key] <= 65535:
                raise ValueError('nat_forward_port')
        if row['external_port'] in seen:
            raise ValueError('nat_duplicate_forward')
        seen.add(row['external_port'])
    return value

def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}

def prefix(network):
    net = ipaddress.IPv4Network(network)
    return str(net.network_address) if net.prefixlen == 32 else {
        'prefix': {'addr': str(net.network_address), 'len': net.prefixlen}}

def rules(c, merged):
    c = checked(c)
    result = []
    def add(table, chain, expr):
        if merged:
            expr = [match({'meta': {'key': 'nfproto'}}, 'ipv4')] + copy.deepcopy(expr)
            for item in expr:
                if 'dnat' in item:
                    item['dnat']['family'] = 'ip'
        result.append({'family': 'inet' if merged else 'ip',
                       'table': 'capstone_fw' if merged else table,
                       'chain': 'nat_' + chain if merged else chain, 'expr': expr})
    add('capstone_gw', 'postrouting', [
        match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, prefix(c['internal_network'])),
        match({'meta': {'key': 'oifname'}}, c['external_interface']), {'masquerade': None}])
    for row in c['forwards']:
        add('capstone_fwd', 'prerouting', [
            match({'meta': {'key': 'iifname'}}, c['external_interface']),
            match({'payload': {'protocol': 'ip', 'field': 'saddr'}}, prefix(c['management_source'])),
            match({'payload': {'protocol': 'tcp', 'field': 'dport'}}, row['external_port']),
            {'dnat': {'addr': row['address'], 'port': row['port']}}])
    add('capstone_fwd', 'postrouting', [
        match({'meta': {'key': 'oifname'}}, c['internal_interface']),
        match({'ct': {'key': 'status'}}, 'dnat', 'in'), {'masquerade': None}])
    return result

def definitions(c, merged):
    result = []
    if merged:
        pairs = [('capstone_fw', 'nat_prerouting', 'prerouting', -100),
                 ('capstone_fw', 'nat_postrouting', 'postrouting', 100)]
    else:
        for name in ('capstone_gw', 'capstone_fwd'):
            result.append({'table': {'family': 'ip', 'name': name}})
        pairs = [('capstone_gw', 'postrouting', 'postrouting', 100),
                 ('capstone_fwd', 'prerouting', 'prerouting', -100),
                 ('capstone_fwd', 'postrouting', 'postrouting', 100)]
    for table, name, hook, priority in pairs:
        result.append({'chain': {'family': 'inet' if merged else 'ip', 'table': table,
                                'name': name, 'type': 'nat', 'hook': hook,
                                'prio': priority, 'policy': 'accept'}})
    result += [{'rule': rule} for rule in rules(c, merged)]
    return result

def owned(kind, obj):
    if obj.get('family') == 'ip':
        return (obj.get('name') if kind == 'table' else obj.get('table')) in ('capstone_gw', 'capstone_fwd')
    return (obj.get('family') == 'inet' and obj.get('table') == 'capstone_fw' and
            (obj.get('name') if kind != 'rule' else obj.get('chain')) in CHAINS)

def objects(snapshot):
    if type(snapshot) is not dict or type(snapshot.get('nftables')) is not list:
        raise ValueError('native_nft_JSON_required')
    for row in snapshot['nftables']:
        if type(row) is not dict or len(row) != 1:
            raise ValueError('nft_object_shape')
        kind, obj = next(iter(row.items()))
        if type(obj) is not dict:
            raise ValueError('nft_object_value')
        yield kind, obj

def view(snapshot):
    """Canonical owned objects; rule order within each chain is significant."""
    out, seen = [], set()
    for kind, obj in objects(snapshot):
        if not owned(kind, obj):
            continue
        if kind not in ('table', 'chain', 'rule'):
            raise ValueError('unexpected_owned_nat_object')
        clean = {k: copy.deepcopy(v) for k, v in obj.items() if k not in ('handle', 'index')}
        if kind == 'rule':
            # nft omits an explicit nfproto guard when an IPv4 saddr match
            # already proves it. Keep it significant on the reply masquerade
            # rule, which otherwise has only interface/conntrack conditions.
            ipv4_saddr = any(item.get('match', {}).get('left') == {
                'payload': {'protocol': 'ip', 'field': 'saddr'}} and
                item.get('match', {}).get('op') == '==' for item in clean.get('expr', []))
            if ipv4_saddr:
                guard = match({'meta': {'key': 'nfproto'}}, 'ipv4')
                clean['expr'] = [item for item in clean['expr'] if item != guard]
        if kind != 'rule':
            key = (kind, clean['family'], clean.get('table'), clean.get('name'))
            if key in seen:
                raise ValueError('duplicate_nat_object')
            seen.add(key)
        out.append({kind: clean})
    # Stable sort preserves the order of the rules within a chain.
    return sorted(out, key=lambda row: (next(iter(row.values()))['family'],
        next(iter(row.values())).get('table', next(iter(row.values())).get('name')),
        next(iter(row)), next(iter(row.values())).get('chain', next(iter(row.values())).get('name'))))

def trusted(path):
    path = Path(path)
    for item in (path, *path.parents):
        s = item.lstat()
        if not stat.S_ISREG(s.st_mode) and not stat.S_ISDIR(s.st_mode):
            raise ValueError('unsafe_nat_path')
        if s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('untrusted_nat_path')
    return path

def atomic(path, raw, mode=0o644):
    path = Path(path); trusted(path.parent)
    if path.exists() or path.is_symlink():
        trusted(path)
    fd, name = tempfile.mkstemp(prefix='.nat-policy-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode); os.fchown(f.fileno(), 0, 0)
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(name): os.unlink(name)

def file_state(path):
    if not path.exists() and not path.is_symlink():
        return None
    trusted(path); raw = path.read_bytes(); s = path.stat()
    return {'sha256': sha(raw), 'mode': stat.S_IMODE(s.st_mode), 'uid': s.st_uid,
            'gid': s.st_gid, 'bytes_b64': base64.b64encode(raw).decode()}

def same_file(actual, expected):
    if actual is None or expected is None:
        return actual is expected
    return all(actual[k] == expected[k] for k in ('sha256', 'mode', 'uid', 'gid'))


def run(args, data=None):
    p=subprocess.run(args,input=data,text=True,capture_output=True,timeout=25)
    if p.returncode:
        raise RuntimeError(json.dumps({'program':Path(args[0]).name,'rc':p.returncode,'stderr':p.stderr[:1000]}))
    return p.stdout


def native():
    return json.loads(run(['nft','-j','list','ruleset']))


def specs(c):
    c=checked(c)
    rows=[]
    for i,f in enumerate(c['forwards']):
        rows.append(['-A','PREROUTING','-i',c['external_interface'],'-s',c['management_source'],
          '-p','tcp','-m','tcp','--dport',str(f['external_port']),'-m','comment','--comment',PREFIX+'dnat-'+str(i),
          '-j','DNAT','--to-destination',f['address']+':'+str(f['port'])])
    rows.append(['-A','POSTROUTING','-s',c['internal_network'],'-o',c['external_interface'],
                 '-m','comment','--comment',PREFIX+'egress','-j','MASQUERADE'])
    rows.append(['-A','POSTROUTING','-o',c['internal_interface'],'-m','conntrack','--ctstate','DNAT',
                 '-m','comment','--comment',PREFIX+'reply','-j','MASQUERADE'])
    return rows


def normalized(tokens):
    if tokens[:1]!=['-A'] or len(tokens)<4 or (len(tokens)-2)%2:
        raise ValueError('nat_rule_shape')
    fields={};modules=[]
    for k,v in zip(tokens[2::2],tokens[3::2]):
        if k=='-m':modules.append(v)
        elif k in fields:raise ValueError('duplicate_nat_option')
        else:fields[k]=v
    return tokens[1],sorted(fields.items()),sorted(modules)


def ipt_snapshot(c):
    lines=[shlex.split(x) for x in run(['iptables','-w','5','-t','nat','-S']).splitlines()]
    owned_rows=[];foreign=[];counts={};positions=[]
    for row in lines:
        comments=[row[i+1] for i,x in enumerate(row[:-1]) if x=='--comment']
        is_owned=any(x.startswith(PREFIX) for x in comments)
        if row[:1]==['-A']:
            index=counts.get(row[1],0);counts[row[1]]=index+1
            if is_owned:positions.append((row[1],index))
        (owned_rows if is_owned else foreign).append(row)
    expected=sorted(normalized(x) for x in specs(c))
    if owned_rows and sorted(normalized(x) for x in owned_rows)!=expected:
        raise ValueError('owned_basic_nat_drift')
    return {'owned':owned_rows,'foreign':foreign,'positions':positions,'counts':counts}


def outside(value,ipt):
    def clean(v):
        if isinstance(v,list):return [clean(x) for x in v]
        if isinstance(v,dict):return {k:clean(x) for k,x in v.items() if k not in ('packets','bytes','expires','elem')}
        return v
    # libnftables represents xt_comment opaquely. Match the validated iptables
    # rule positions to the native order, and require identical chain counts.
    counts={};result=[]
    for k,o in objects(value):
        if k=='rule' and o.get('family')=='ip' and o.get('table')=='nat':
            chain=o['chain'];index=counts.get(chain,0);counts[chain]=index+1
            if (chain,index) in ipt['positions']:continue
        if k!='metainfo' and not owned(k,o):result.append(clean({k:o}))
    if counts!=ipt['counts']:raise ValueError('iptables_native_order_or_count_mismatch')
    return result


def state(value,c,ipt):
    observed=view(value)
    legacy=view({'nftables':definitions(c,False)})
    if observed and observed!=legacy:raise ValueError('legacy_nat_drift')
    return 'mixed' if observed and ipt['owned'] else 'legacy' if observed else 'basic' if ipt['owned'] else 'absent'


def restore_text(rows,delete=False):
    return '*nat\n'+'\n'.join(shlex.join(['-D',*r[1:]] if delete else r) for r in rows)+'\nCOMMIT\n'


def apply(c,dry=False):
    before=native();ipt=ipt_snapshot(c);mode=state(before,c,ipt)
    if not any(k=='table' and o.get('family')=='inet' and o.get('name')=='capstone_fw' for k,o in objects(before)):
        raise ValueError('existing_host_firewall_required')
    if not any(k=='table' and o.get('family')=='ip' and o.get('name')=='nat' for k,o in objects(before)):
        raise ValueError('existing_docker_nat_table_required')
    bases={o.get('name') for k,o in objects(before) if k=='chain' and o.get('family')=='ip' and o.get('table')=='nat'}
    if not {'PREROUTING','POSTROUTING'}<=bases:raise ValueError('existing_nat_base_chains_required')
    if mode=='basic':return {'changed':False,'state':'basic','rules':len(specs(c))}
    if not ipt['owned']:run(['iptables-restore','--wait','5','--noflush','--test'],restore_text(specs(c)))
    deletion={'nftables':[{'delete':{'table':{'family':'ip','name':n}}} for n in ('capstone_gw','capstone_fwd')]}
    if mode in ('legacy','mixed'):run(['nft','--check','--json','-f','-'],json.dumps(deletion))
    if dry:return {'changed':False,'state':mode,'syntax_checked':True,'rules':len(specs(c))}
    if not ipt['owned']:run(['iptables-restore','--wait','5','--noflush'],restore_text(specs(c)))
    if mode in ('legacy','mixed'):run(['nft','--json','-f','-'],json.dumps(deletion))
    after=native();new=ipt_snapshot(c)
    if state(after,c,new)!='basic' or outside(before,ipt)!=outside(after,new) or new['foreign']!=ipt['foreign']:
        raise RuntimeError(json.dumps({'error':'basic_nat_verification_failed','state':state(after,c,new),
          'foreign_nft_equal':outside(before,ipt)==outside(after,new),'foreign_iptables_equal':new['foreign']==ipt['foreign']}))
    return {'changed':True,'state':'basic','rules':len(specs(c)),'unrelated_policy_and_handles_preserved':True}


def undo(c):
    before=native();ipt=ipt_snapshot(c);mode=state(before,c,ipt)
    if mode in ('basic','absent'):
        raw=json.dumps({'nftables':[{'add':x} for x in definitions(c,False)]})
        run(['nft','--check','--json','-f','-'],raw);run(['nft','--json','-f','-'],raw)
    if ipt['owned']:
        text=restore_text(ipt['owned'],True)
        run(['iptables-restore','--wait','5','--noflush','--test'],text)
        run(['iptables-restore','--wait','5','--noflush'],text)
    after=native();new=ipt_snapshot(c)
    if state(after,c,new)!='legacy' or outside(before,ipt)!=outside(after,new) or new['foreign']!=ipt['foreign']:
        raise RuntimeError('basic_nat_rollback_verification_failed')
    return {'state':'legacy','unrelated_policy_and_handles_preserved':True}


def recovery(path,manual=False):
    p=Path(path);trusted(p)
    if p.parent!=STATE or not re.fullmatch(r'migration-[0-9]+',p.name):raise ValueError('recovery_scope')
    if (p/'confirmed.json').exists() and not manual:return {'state':'confirmed_noop'}
    m=json.loads(trusted(p/'manifest.json').read_text())
    if set(m['files'])!={str(x) for x in (CODE,LOADER,UNIT)}:raise ValueError('recovery_file_scope')
    for n,v in m['files'].items():
        if not any(same_file(file_state(Path(n)),x) for x in (v['before'],v['after'])):raise ValueError('concurrent_file_drift')
    result=undo(m['config'])
    for n,v in m['files'].items():
        old=v['before'];q=Path(n)
        if old:atomic(q,base64.b64decode(old['bytes_b64']),old['mode']);os.chown(q,old['uid'],old['gid'])
        elif q.exists():q.unlink()
    run(['systemctl','daemon-reload']);atomic(p/'restored.json',json.dumps(result).encode(),0o600)
    run(['systemctl','stop',m['timer']+'.timer']);return result


def install(c,loader_source,unit_source,expected_loader_sha):
    if state(native(),c,ipt_snapshot(c))!='legacy':raise ValueError('exact_legacy_state_required')
    if sha(trusted(LOADER).read_bytes())!=expected_loader_sha:raise ValueError('live_loader_sha_changed')
    if CODE.exists():raise ValueError('existing_helper_not_adopted')
    apply(c,True);loader=trusted(loader_source).read_bytes();unit=trusted(unit_source).read_bytes()
    if str(CODE).encode() not in loader:raise ValueError('loader_helper_binding')
    run(['bash','-n'],loader.decode())
    STATE.mkdir(mode=0o700,exist_ok=True);trusted(STATE)
    p=STATE/('migration-'+str(time.time_ns()));p.mkdir(mode=0o700)
    timer='capstone-basic-nat-'+p.name
    payload={CODE:Path(__file__).read_bytes(),LOADER:loader,UNIT:unit}
    m={'config':c,'timer':timer,'files':{str(q):{'before':file_state(q),'after':{'sha256':sha(raw),'uid':0,'gid':0,'mode':0o755 if q==LOADER else 0o644}} for q,raw in payload.items()}}
    atomic(p/'manifest.json',json.dumps(m).encode(),0o600);atomic(p/'recovery.py',Path(__file__).read_bytes(),0o600)
    run(['systemd-run','--unit='+timer,'--on-active=15m','/usr/bin/python3','-I','-B',str(p/'recovery.py'),'rollback','--recovery-directory',str(p)])
    try:
        for q,raw in payload.items():atomic(q,raw,0o755 if q==LOADER else 0o644)
        result=apply(c);run(['systemctl','daemon-reload'])
        atomic(p/'applied.json',json.dumps(result).encode(),0o600)
        return {**result,'recovery_directory':str(p),'timer':timer+'.timer','confirmation_required':True}
    except BaseException:
        recovery(p);raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('print','check','apply','verify','undo','install','confirm','rollback'))
    for k in ('external_interface','internal_interface','internal_network','management_source'):
        p.add_argument('--'+k.replace('_','-'),default=DEFAULT[k])
    p.add_argument('--forward',action='append');p.add_argument('--loader-source',type=Path);p.add_argument('--unit-source',type=Path)
    p.add_argument('--expected-loader-sha');p.add_argument('--recovery-directory');p.add_argument('--manual',action='store_true')
    a=p.parse_args();c=copy.deepcopy(DEFAULT)
    for k in ('external_interface','internal_interface','internal_network','management_source'):c[k]=getattr(a,k)
    if a.forward:c['forwards']=[dict(zip(('external_port','address','port'),(int(x.split(':')[0]),x.split(':')[1],int(x.split(':')[2])))) for x in a.forward]
    c=checked(c)
    if a.action=='print':result={'iptables_restore':restore_text(specs(c)),'config':c}
    else:
        if os.geteuid()!=0:raise ValueError('root_required')
        fd=os.open('/run/lock/capstone-basic-nat.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            if os.fstat(fd).st_uid or not stat.S_ISREG(os.fstat(fd).st_mode):raise ValueError('unsafe_lock')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if a.action in ('apply','check'):result=apply(c,a.action=='check')
            elif a.action=='undo':result=undo(c)
            elif a.action=='verify':
                if state(native(),c,ipt_snapshot(c))!='basic':raise ValueError('basic_nat_not_active')
                result={'state':'basic','verified':True}
            elif a.action=='install':result=install(c,a.loader_source,a.unit_source,a.expected_loader_sha)
            elif a.action=='rollback':result=recovery(a.recovery_directory,a.manual)
            else:
                q=Path(a.recovery_directory);m=json.loads(trusted(q/'manifest.json').read_text())
                if q.parent!=STATE or state(native(),m['config'],ipt_snapshot(m['config']))!='basic':raise ValueError('confirm_policy')
                for n,v in m['files'].items():
                    if not same_file(file_state(Path(n)),v['after']):raise ValueError('confirm_source')
                atomic(q/'confirmed.json',json.dumps({'confirmed_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat()}).encode(),0o600)
                run(['systemctl','stop',m['timer']+'.timer']);result={'state':'confirmed'}
        finally:os.close(fd)
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
