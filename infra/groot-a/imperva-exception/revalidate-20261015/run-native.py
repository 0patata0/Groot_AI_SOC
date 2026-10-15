#!/usr/bin/env python3
"""One-shot exact-policy comparison in a new loopback-only network namespace.

No operational requests, signals, reloads, configuration changes or new containers.
Raw synthetic audit/config/log evidence remains in the operator's root-only output.
"""
import argparse
import fcntl
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types

HERE = Path(__file__).resolve().parent
OLD = HERE.parent / 'test-native.py'
SAFE = HERE.parents[2] / 'normalization/vector/waf-rotation/run-probe-a.py'
PINS = {OLD: '64ac65da6ab011a438f7791da9c93b6b46fe140c9b506be1303af3aefcbf48d7',
        SAFE: 'ae12559a4641e596c647bc009a7f0d68906e2890d8201d18fca75537e324f7fe'}
CID = '6c72d5a5b8229fc3b6e010c9d046d97ac5c13437cae045c72a330fe0d6d82f81'
IMAGE = 'sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650'
DOCKER = '/usr/local/bin/docker'
MID = '096e90b6243e438aa8a7b392be754732'
ROOT = '/etc/modsecurity.d'
CRS = ROOT + '/owasp-crs'
EXCEPTION = CRS + '/rules/REQUEST-900-CAPSTONE-SCANNER.conf'
EXCEPTION_SHA = 'd95e75f39d082053543b04de10d538154da4ce8b25e9333014b3b2d858b65f8d'
FIXED = {ROOT+'/setup.conf': '5e8dd2dab4517701be865f68467df491f54805d331cdff0dd3092a30f5022876',
         ROOT+'/modsecurity.conf': 'a0dc08ae01c58b68e54a881a039359dc09008e50c101a2c4d4b01823b5a5e178',
         ROOT+'/modsecurity-override.conf': '814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb',
         EXCEPTION: EXCEPTION_SHA}
POINTER = 'Include /var/log/modsecurity/capstone-managed/audit-path.conf'
ADDRESSES = ['211.170.162.9', '211.170.162.8', '172.18.0.2', '172.18.0.3']
LOCKS = ['/var/lib/rule-change/.lock', '/var/lib/capstone-automation/ansible/vector.lock']


def load(path):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[path]:
        raise RuntimeError('dependency_sha_mismatch')
    module = types.ModuleType('private_' + path.stem.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


old, safe = load(OLD), load(SAFE)
need, sha = safe.need, safe.sha


def write(path, raw, mode=0o400, uid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode); os.fchown(f.fileno(), uid, uid)
        f.write(raw); f.flush(); os.fsync(f.fileno())


def read_container(path):
    need(path in FIXED or path == ROOT+'/unicode.mapping' or
         re.fullmatch(re.escape(CRS)+r'/(?:crs-setup\.conf|(?:rules|plugins)/[A-Za-z0-9_.-]+)', path),
         'container_read_not_allowed')
    return safe.run([DOCKER, 'exec', CID, 'cat', '--', path], tag='public_config_read')


def sources():
    # Resolve the image's CRS alias inside the fixed container, never on host.
    raw = safe.run([DOCKER, 'exec', CID, 'find', '-L', CRS, '-maxdepth', '2',
                    '-type', 'f', '-print'], tag='public_crs_inventory')
    names = raw.decode().splitlines()
    selected = sorted(p for p in names if re.fullmatch(re.escape(CRS)+
        r'/(?:crs-setup\.conf|(?:rules|plugins)/[A-Za-z0-9_.-]+\.(?:conf|data))', p))
    need(len(selected) == len(set(selected)) and 20 <= len(selected) <= 256, 'crs_inventory_bounds')
    result = {p: read_container(p) for p in sorted(set(selected) | set(FIXED) | {ROOT+'/unicode.mapping'})}
    need(sum(map(len, result.values())) <= 16*1024*1024, 'public_config_total_bound')
    need(all(sha(result[p]) == digest for p, digest in FIXED.items()), 'fixed_public_policy_changed')
    return result


def isolated_config(material, private, candidate):
    """Expand exact setup order into one private rules file, retaining rule bytes.

    Only the managed audit pointer Include and output-storage directives are
    removed. Baseline additionally omits exactly the installed 900 file.
    """
    used = []
    def expand(path, stack=()):
        need(path not in stack and len(stack) < 8 and path in material, 'include_graph_not_supported')
        used.append(path)
        if path == EXCEPTION and not candidate:
            return ''
        content = material[path].decode()
        if path == ROOT+'/modsecurity-override.conf':
            need(content.splitlines().count(POINTER) == 1, 'managed_pointer_include_changed')
            content = '\n'.join(line for line in content.splitlines() if line != POINTER)+'\n'
        lines = []
        for line in content.splitlines(keepends=True):
            match = re.fullmatch(r'\s*Include\s+(\S+)\s*\n?', line)
            if match:
                pattern = match[1]
                need(pattern.startswith(ROOT+'/') and '..' not in pattern, 'include_outside_public_config')
                matches = sorted(p for p in material if fnmatch.fnmatchcase(p, pattern))
                need(bool(matches) or '*' in pattern and pattern.startswith(CRS+'/plugins/'), 'include_missing')
                lines.extend(expand(p, (*stack, path)) for p in matches)
            else:
                need(not re.match(r'\s*Include', line), 'include_syntax_not_supported')
                lines.append(line)
        return ''.join(lines)
    text = expand(ROOT+'/setup.conf')
    need(used.count(EXCEPTION) == 1 and used.count(ROOT+'/modsecurity-override.conf') == 1,
         'exception_or_override_include_count')
    # All destinations are private before even nginx -t runs as UID101.
    text = re.sub(r'^\s*Sec(?:AuditEngine|AuditLog\w*|DebugLog\w*|TmpDir|DataDir|UploadDir)\s+.*$',
                  '', text, flags=re.M)
    need(re.search(r'^SecRuleEngine DetectionOnly$', text, re.M), 'detection_only_required')
    active='\n'.join(line for line in text.splitlines() if not re.match(r'^\s*#',line))
    need('/var/log/modsecurity' not in active and not re.search(r'^\s*Include', active, re.M),
         'operating_output_reference_remaining')
    text += f'\nSecAuditEngine On\nSecAuditLogType Serial\nSecAuditLogFormat JSON\nSecAuditLogParts ABIJDEFHZ\nSecAuditLog {private}/run/audit.json\n'
    text += f'SecAuditLogStorageDir {private}/run\nSecDebugLog {private}/run/debug.log\nSecDebugLogLevel 0\n'
    for key in ('TmpDir', 'DataDir', 'UploadDir'):
        text += f'Sec{key} {private}/run\n'
    return text.encode(), used


def network():
    links = json.loads(safe.run(['ip', '-j', 'link'], tag='private_link_inventory'))
    need([r['ifname'] for r in links] == ['lo'], 'nonloopback_interface')
    routes = json.loads(safe.run(['ip', '-j', 'route', 'show', 'table', 'all'], tag='private_route_inventory'))
    need(all(r.get('dev') == 'lo' and r.get('type') in (None, 'local', 'broadcast', 'unicast')
             and r.get('dst') != 'default' for r in routes), 'external_or_default_route')
    routes6 = json.loads(safe.run(['ip', '-j', '-6', 'route', 'show', 'table', 'all'], tag='private_route6_inventory'))
    need(all(r.get('dev') == 'lo' and r.get('dst') != 'default' for r in routes6), 'external_ipv6_route')
    addrs = json.loads(safe.run(['ip', '-j', 'address', 'show'], tag='private_address_inventory'))
    v4 = sorted(x['local'] for row in addrs for x in row['addr_info'] if x['family'] == 'inet')
    need(v4 == sorted(ADDRESSES + ['127.0.0.1']), 'private_ipv4_set')
    return {'netns': os.readlink('/proc/self/ns/net'), 'interfaces': ['lo'],
            'ipv4_addresses': v4, 'routes': routes, 'routes6': routes6, 'external_interfaces': 0, 'default_routes': 0}


def operational():
    projection='{"Id":{{json .Id}},"Image":{{json .Image}},"State":{"Pid":{{json .State.Pid}},"Running":{{json .State.Running}},"StartedAt":{{json .State.StartedAt}},"Health":{"Status":{{json .State.Health.Status}}}},"Mounts":{{json .Mounts}}}'
    row = json.loads(safe.run([DOCKER, 'inspect', '--format', projection, CID], tag='fixed_container_inspect'))
    need(row['Id'] == CID and row['Image'] == IMAGE and row['State']['Running']
         and row['State']['Health']['Status'] == 'healthy', 'operating_waf_changed')
    pid = row['State']['Pid']
    mounts=[m for m in row['Mounts'] if m['Destination']==EXCEPTION]
    need(len(mounts)==1 and mounts[0]['Type']=='bind' and mounts[0]['RW'] is False and
         mounts[0]['Source']=='/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf','exception_readonly_mount_changed')
    host_exception=Path(mounts[0]['Source']); value=host_exception.lstat()
    need(stat.S_ISREG(value.st_mode) and (value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode),value.st_nlink)==(0,0,0o444,1)
         and sha(safe.bounded(host_exception))==EXCEPTION_SHA,'host_exception_pin')
    vector = int(safe.run(['systemctl', 'show', 'capstone-vector.service', '-p', 'MainPID', '--value']))
    pids = list(Path('/var/ossec/var/run').glob('wazuh-logcollector-*.pid'))
    need(len(pids) == 1, 'wazuh_pid_count')
    host = ['/etc/capstone-vector/vector.toml', '/etc/capstone-vector/vector.env',
            '/etc/capstone-vector/waf-binding.json', '/var/ossec/etc/ossec.conf',
            '/var/lib/capstone-raw-operations/suricata/state.json',
            '/var/lib/capstone-raw-operations/modsecurity/state.json']
    return {'id': CID, 'image': IMAGE, 'waf': safe.stable_info(pid), 'started_at': row['State']['StartedAt'],
            'netns': os.readlink(f'/proc/{pid}/ns/net'), 'vector': safe.stable_info(vector),
            'wazuh': safe.stable_info(int(pids[0].read_text())),
            'host_sha256': {p: sha(safe.bounded(Path(p))) for p in host}}


def oracle(rows):
    original = {r['name']: r for r in rows if r['phase'] == 'baseline'}
    revised = {r['name']: r for r in rows if r['phase'] == 'candidate'}
    names = {c['name'] for c in old.cases()}
    need(len(rows) == 42 and set(original) == set(revised) == names, 'case_set_mismatch')
    for name in names:
        a, b = original[name], revised[name]
        need(b['target_rule'] in a['rule_ids'], 'baseline_target_missing')
        if b['mode'] == 'must_remain':
            need(b['rule_ids'] == a['rule_ids'], 'negative_detection_changed')
        else:
            need(b['target_rule'] not in b['rule_ids'], 'exception_not_effective')
        if b['mode'] == 'xss':
            need({10300, 949110}.issubset(b['rule_ids']) and
                 set(b['rule_ids']) == set(a['rule_ids']) - {b['target_rule']}, 'xss_control_changed')
        if b['mode'] == 'exception':
            need(b['rule_ids'] == [], 'normal_probe_unexpected_rule')
    return {'paired_cases': 21, 'native_requests': 42, 'positive': 2, 'negative': 17,
            'xss_controls': 2, 'exact_original_exception_sha256': EXCEPTION_SHA}


class Probe:
    def __init__(self, output):
        self.output = output; self.work = None; self.process = self.master = None
        self.identities = {}; self.result = {'status': 'running', 'phase': 'preflight', 'cases': []}
        self.netns = os.readlink('/proc/self/ns/net'); self.save()

    def save(self):
        safe.atomic(self.output/'result.json', self.result)
        safe.atomic(self.output/'runtime-processes.json', {'fixture_netns': self.netns,
            'rows': [{'kind': 'private_nginx', 'pid': i.pid, 'start_ticks': i.start, 'netns': i.netns}
                     for i in self.identities.values() if i.live()]})

    def track(self):
        # The direct child remains ours and unreaped until stop(). Include its
        # children even if constructing the first pidfd identity failed.
        if self.process is not None and safe.proc_info(self.process.pid):
            for pid in safe.descendants(self.process.pid):
                if pid not in self.identities:
                    info=safe.proc_info(pid)
                    if info is not None and info['state']!='Z':
                        self.identities[pid] = safe.Identity(pid, netns=self.netns)
        self.save()

    def stop(self):
        if self.process is None:
            return
        self.track()
        if self.master is None:self.master=self.identities.get(self.process.pid)
        forced = False
        if self.master is not None and self.master.live(): self.master.send(signal.SIGQUIT)
        elif self.process.returncode is None: self.process.terminate() # unreaped direct child only
        try: self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            forced = True
            for identity in self.identities.values():
                if identity.live(): identity.send(signal.SIGKILL)
            self.process.kill(); self.process.wait(timeout=3)
        deadline = time.monotonic()+3
        while any(i.live() for i in self.identities.values()) and time.monotonic()<deadline: time.sleep(.05)
        need(not any(i.live() for i in self.identities.values()), 'private_writer_remains')
        self.result.setdefault('stops', []).append({'returncode': self.process.returncode, 'forced': forced})
        self.process = None; self.master = None
        need(not forced, 'private_writer_forced_cleanup')

    def execute(self):
        self.before = operational()
        need(self.netns != os.readlink('/proc/1/ns/net') and self.netns != self.before['netns'], 'netns_not_private')
        safe.run(['ip','link','set','lo','up'])
        for address in ADDRESSES: safe.run(['ip','address','add',address+'/32','dev','lo'])
        self.result['network_before'] = network()
        material = sources(); self.result['source_sha256'] = {p: sha(b) for p,b in material.items()}
        init = self.before['waf']['pid']; container_root = Path('/proc')/str(init)/'root'
        need(not (container_root/'tmp').is_symlink(), 'container_tmp_symlink')
        self.work = Path(tempfile.mkdtemp(prefix='capstone-imperva-revalidate.', dir=container_root/'tmp'))
        self.work_identity=safe.devino(self.work)
        os.chmod(self.work,0o711); cp='/tmp/'+self.work.name
        self.result['private_container_path']=cp; self.result['phase']='native_comparison'; self.save()
        for mode in ('baseline','candidate'):
            stage=self.work/mode; stage.mkdir(mode=0o711); os.chmod(stage,0o711)
            (stage/'run').mkdir(mode=0o700); os.chown(stage/'run',101,101)
            (stage/'html').mkdir(mode=0o755); os.chmod(stage/'html',0o755)
            write(stage/'html/index.html',b'private native fixture\n',0o444)
            p=cp+'/'+mode
            config, used=isolated_config(material,p,mode=='candidate')
            write(stage/'setup.conf',config,0o444)
            write(stage/'unicode.mapping',material[ROOT+'/unicode.mapping'],0o444)
            for path, raw in material.items():
                if path.endswith('.data'):
                    destination=stage/Path(path).name
                    need(not destination.exists(), 'duplicate_data_basename'); write(destination,raw,0o444)
            nginx=f'''load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
worker_processes 1;
pid {p}/run/nginx.pid;
error_log {p}/run/error.log warn;
events {{ worker_connections 32; }}
http {{
 access_log off;
 client_body_temp_path {p}/run;
 proxy_temp_path {p}/run;
 fastcgi_temp_path {p}/run;
 uwsgi_temp_path {p}/run;
 scgi_temp_path {p}/run;
 modsecurity on;
 modsecurity_rules_file {p}/setup.conf;
 server {{ listen 172.18.0.2:8080; listen 172.18.0.3:8080; listen 172.18.0.2:8081;
 server_name _; root {p}/html; location / {{ }} }}
}}
'''
            write(stage/'nginx.conf',nginx.encode(),0o444)
            argv=['nsenter','--target',str(init),'--mount','--root','--wd=/',
                  '--setgid=101','--setuid=101','--','/usr/sbin/nginx','-e',p+'/run/initial.log','-c',p+'/nginx.conf']
            safe.run(argv+['-t'],tag='native_test_'+mode)
            with (stage/'process.log').open('wb') as log:
                self.process=subprocess.Popen(argv+['-g','daemon off;'],stdout=log,stderr=log,start_new_session=True)
                try:
                    # Direct child is retained before any fallible identity lookup.
                    self.master=safe.Identity(self.process.pid,netns=self.netns)
                    self.identities[self.master.pid]=self.master; self.save()
                    deadline=time.monotonic()+8
                    while time.monotonic()<deadline:
                        need(self.process.poll() is None,'native_writer_start_failed')
                        if safe.private_pid_ready(stage/'run/nginx.pid',self.process.pid) and len(safe.descendants(self.process.pid))>=2: break
                        time.sleep(.025)
                    else: raise safe.Refused('native_writer_start_timeout')
                    self.track()
                    for identity in self.identities.values():
                        if not identity.live(): continue
                        status=Path(f'/proc/{identity.pid}/status').read_text()
                        for kind in ('Uid','Gid'):
                            match=re.search(r'^'+kind+r':\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$',status,re.M)
                            need(match and set(map(int,match.groups()))=={101},'private_writer_uid_gid')
                        groups=re.search(r'^Groups:[ \t]*([^\n]*)$',status,re.M)
                        need(groups is not None and set(map(int,groups[1].split())).issubset({101}),
                             'private_writer_supplementary_groups')
                    need(network()==self.result['network_before'],'private_network_changed_before_requests')
                    for number,case in enumerate(old.cases(),1):
                        code=old.request(case)
                        event=old.wait_audit(stage/'run/audit.json',number)['transaction']
                        need(event['client_ip']==case['source'] and event['host_ip']==case['destination'] and int(event['host_port'])==case['port'],'native_tuple_mismatch')
                        ids=sorted({int(m['details']['ruleId']) for m in event.get('messages',[])})
                        self.result['cases'].append({'phase':mode,'name':case['name'],'http_status':code,
                            'target_rule':case['target'],'mode':case['mode'],'rule_ids':ids}); self.save()
                finally: self.stop()
            self.result.setdefault('arms',{})[mode]={'setup_sha256':sha(config),'included_files':used,'writer_uid_gid':101}
        self.result['verification']=oracle(self.result['cases'])
        self.result['network_after']=network()
        need(self.result['network_after']==self.result['network_before'],'private_network_changed')
        need(operational()==self.before,'operational_identity_changed')
        need({p:sha(b) for p,b in sources().items()}==self.result['source_sha256'],'public_sources_changed')
        self.result.update(status='passed',phase='verified',operating_services_and_sources_unchanged=True,
                           natural_scan_verified=False,production_requests=0,operating_signals=0)

    def cleanup(self):
        errors=[]
        try: self.stop()
        except BaseException as e: errors.append(type(e).__name__)
        if self.work is not None:
            try:
                need(not any(i.live() for i in self.identities.values()),'private_writer_remains')
                need(safe.stable_info(self.before['waf']['pid'])==self.before['waf'] and
                     not self.work.is_symlink() and safe.devino(self.work)==self.work_identity,
                     'private_cleanup_root_identity_changed')
                evidence=self.output/'evidence'; evidence.mkdir(mode=0o700)
                for path in sorted(self.work.rglob('*')):
                    relative=path.relative_to(self.work); target=evidence/relative
                    need(not path.is_symlink(),'private_evidence_symlink')
                    if path.is_dir(): target.mkdir(mode=0o700)
                    else:
                        raw=safe.bounded(path); write(target,raw)
                        need(sha(safe.bounded(target))==sha(raw),'preserved_evidence_sha_mismatch')
                for directory in sorted((p for p in evidence.rglob('*') if p.is_dir()),reverse=True):
                    safe.sync_dir(directory)
                safe.sync_dir(evidence)
                safe.sync_dir(self.output)
                need(safe.stable_info(self.before['waf']['pid'])==self.before['waf'] and
                     not self.work.is_symlink() and safe.devino(self.work)==self.work_identity,
                     'private_cleanup_root_identity_changed')
                shutil.rmtree(self.work)
            except BaseException as e: errors.append(type(e).__name__)
        self.result['cleanup']={'errors':errors,'private_runtime_removed':self.work is None or not self.work.exists(),
            'known_private_writers_remaining':sum(i.live() for i in self.identities.values())}
        if errors:self.result['status']='failed'
        for identity in self.identities.values(): identity.close()
        self.save()


def inner(output):
    safe.COMMAND_DIAGNOSTICS=output/'command-diagnostics'
    def interrupted(_sig,_frame):raise safe.Refused('supervisor_requested_cleanup')
    signal.signal(signal.SIGTERM,interrupted)
    probe=Probe(output)
    try: probe.execute()
    except BaseException as error:
        probe.result.update(status='failed',failure_code=str(error) if isinstance(error,safe.Refused) else 'native_probe_failure',
                            failure_type=type(error).__name__,failure_frames=safe.failure_frames(error))
    finally: probe.cleanup()
    return 0 if probe.result['status']=='passed' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--inside',action='store_true',help=argparse.SUPPRESS)
    args=parser.parse_args(); output=args.output
    need(os.geteuid()==0 and Path('/etc/machine-id').read_text().strip()==MID,'fixed_root_host_required')
    need(re.fullmatch(r'/var/tmp/capstone-imperva-revalidate-20261015/run-[A-Za-z0-9_-]{1,48}',str(output)),'output_scope')
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if args.inside:return inner(output)
    parent=output.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and parent.st_mode&0o077==0 and not output.parent.is_symlink(),'private_output_parent')
    locks=[]
    for name in LOCKS:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW); value=os.fstat(fd)
        need(stat.S_ISREG(value.st_mode) and (value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode),value.st_nlink)==(0,0,0o600,1),'lock_metadata')
        fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB); locks.append(fd)
    output.mkdir(mode=0o700)
    source=output/'source'; source.mkdir(mode=0o700)
    for name,path in [('run-native.py',Path(__file__)),('test-native.py',OLD),('run-probe-a.py',SAFE)]:write(source/name,path.read_bytes())
    host_ns=os.readlink('/proc/self/ns/net')
    def host_network():
        return {kind:json.loads(safe.run(['ip','-j',*args],tag='host_network_read')) for kind,args in
                [('links',['link']),('addresses',['address','show']),('routes',['route','show','table','all']),
                 ('routes6',['-6','route','show','table','all'])]}
    host_before=host_network()
    def limit():resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024*1024,8*1024*1024))
    with (output/'supervisor.log').open('wb') as log:
        child=subprocess.Popen(['unshare','--net','--',sys.executable,'-B',str(Path(__file__).resolve()),'--inside','--output',str(output)],
                               stdout=log,stderr=log,start_new_session=True,preexec_fn=limit)
        identity=safe.Identity(child.pid)
        try:
            try:child.wait(timeout=240)
            except subprocess.TimeoutExpired:
                if identity.live():identity.send(signal.SIGTERM)
                try:child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    safe.emergency_cleanup(output,identity); child.wait(timeout=5)
                    raise safe.Refused('timeout_private_files_preserved')
        finally:identity.close()
    need(os.readlink('/proc/self/ns/net')==host_ns,'operator_network_changed')
    need(host_network()==host_before,'host_network_inventory_changed')
    write(output/'network-operator-proof.json',safe.encode({'host_namespace':host_ns,'host_network_before_after_equal':True,
          'before':host_before,'scope':'read_only_operator_interface_address_route_metadata'}))
    result=json.loads(safe.bounded(output/'result.json'))
    for fd in locks:os.close(fd)
    print(json.dumps({key:result.get(key) for key in ('status','phase','failure_code','failure_type','verification','cleanup')}))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'failed','failure_type':type(error).__name__,
            'failure_code':str(error) if isinstance(error,safe.Refused) else 'supervisor_failure'}))
        raise SystemExit(1)
