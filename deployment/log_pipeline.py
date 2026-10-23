#!/usr/bin/env python3
"""Fresh-host adapter for the reviewed Vector/Wazuh observation pipeline.

No network downloads, existing-host adoption, checkpoint edits, raw deletion,
automatic retries, arbitrary commands, or new LLM privileges. The CLI is an
administrator bootstrap helper, not a service or an MCP tool.
"""
import argparse
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

MID = '096e90b6243e438aa8a7b392be754732'
OLD_LOG = '/home/groot_a/capstone/secstack/logs'
OLD_BINDING = '3ae6308be37c1ab82ce62720e2b516c4c27190a9e043afe913b76bdf1da10637'
ROOT = Path('/opt/capstone')
CFG = Path('/etc/capstone-vector')
RAW = Path('/var/lib/capstone-raw-operations')
RUNTIME = Path('/usr/local/lib/capstone-raw-operations')
SENSOR = 'capstone-security'
MONITOR_NAME = 'capstone-portable-evidence-observation-v2'
API = '/_plugins/_alerting/monitors'
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LC_ALL': 'C', 'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1', 'HOME': '/root'}
V = 'infra/normalization/vector/'
W = 'infra/normalization/wazuh-vector/'
FILES = {
    V+'raw-operations/coordinator-writer-intent-fix.sh': str(RUNTIME/'coordinator.sh'),
    **{V+'raw-operations/'+n: str(RUNTIME/n) for n in ('state-lib.sh','state.jq',
       'checkpoint-gates.sh','checkpoint-gates.jq','writer-gates.sh','guard.sh','line-length-lib-v2.sh')},
    V+'raw-operations/capstone-raw-operations': '/usr/local/sbin/capstone-raw-operations',
    V+'raw-operations/raw-line-scan-v2.sh': '/usr/local/sbin/capstone-vector-raw-lines',
    V+'raw-operations/migration-start-guard.sh': '/usr/local/lib/capstone-raw-migration/migration-start-guard.sh',
    V+'raw-operations/vector-v2.toml': str(CFG/'vector.toml'),
    V+'raw-operations/vector-start-guard.conf': '/etc/systemd/system/capstone-vector.service.d/50-capstone-raw.conf',
    V+'raw-operations/wazuh-start-guard.conf': '/etc/systemd/system/wazuh-agent.service.d/50-capstone-raw.conf',
    V+'raw-operations/capstone-raw-operations@.service': '/etc/systemd/system/capstone-raw-operations@.service',
    V+'raw-operations/capstone-raw-operations@.timer': '/etc/systemd/system/capstone-raw-operations@.timer',
    V+'raw-operations/timer-stagger/suricata.conf': '/etc/systemd/system/capstone-raw-operations@suricata.timer.d/stagger.conf',
    V+'raw-operations/timer-stagger/modsecurity.conf': '/etc/systemd/system/capstone-raw-operations@modsecurity.timer.d/stagger.conf',
    V+'raw-operations/timer-stagger/maintenance.conf': '/etc/systemd/system/capstone-vector-maintenance.timer.d/stagger.conf',
    V+'capstone-vector.service': '/etc/systemd/system/capstone-vector.service',
    V+'capstone-vector-maintenance.service': '/etc/systemd/system/capstone-vector-maintenance.service',
    V+'capstone-vector-maintenance.timer': '/etc/systemd/system/capstone-vector-maintenance.timer',
    V+'capstone-vector-maintenance-raw-guard.sh': '/usr/local/sbin/capstone-vector-maintenance',
    V+'logrotate.conf': str(CFG/'logrotate.conf'),
    V+'collection-health.jq': str(CFG/'collection-health.jq'),
    V+'collection/line-length/raw-line-status.jq': str(CFG/'raw-line-status.jq'),
    V+'collection/line-length/line-length-lib.sh': str(CFG/'line-length-lib.sh'),
    **{V+'transforms/'+n: str(CFG/'transforms'/n) for n in ('suricata.vrl','nftables.vrl',
       'waf_json_guard.vrl','correlation.vrl')},
    V+'waf-producer-v2/audit-context.vrl': str(CFG/'transforms/waf_audit_context.vrl'),
}
HISTORY = ('auto-worker.sh','auto-lib.sh','state.jq')
HISTORY_LIB = ('history-lib.sh','history-run.sh','continuation-lib.sh','continue-run.sh','validate-records.jq')
for _n in HISTORY:
    FILES[V+'history-auto/'+_n] = '/usr/local/lib/capstone-vector-history-auto/'+_n
for _n in HISTORY_LIB:
    FILES[V+'history/'+_n] = '/usr/local/lib/capstone-vector-history-auto/history/'+_n
FILES.update({V+'history-auto/run-a.sh': '/usr/local/sbin/capstone-vector-history-auto',
              **{V+'history-auto/'+n: '/etc/systemd/system/'+n for n in
                 ('capstone-vector-history-auto.service','capstone-vector-history-auto.timer')}})
EXTRA = (V+'raw-operations/zz-capstone-evidence-v2.conf', V+'raw-operations/suricata-entrypoint-managed.sh',
         W+'capstone_vector_rules.xml', W+'agent-localfile.xml', W+'indexer-native/window-v2/monitor.json',
         W+'indexer-native/deploy-monitor-b.py',
         'infra/groot-a/logrotate-capstone-secstack', 'deployment/log_pipeline.py')
LOGTESTS = ('test-installed-manager.sh','test-correlation-manager.sh','test-health-manager.sh','test-evidence-manager.sh')
FIXTURES = ('positive-suricata','positive-nftables','positive-modsecurity','wrong-schema','wrong-pipeline','wrong-source')
TIMERS = ('capstone-raw-operations@suricata.timer','capstone-raw-operations@modsecurity.timer',
          'capstone-vector-maintenance.timer','capstone-vector-history-auto.timer','capstone-security-auxiliary.timer')


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def parse(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            need(k not in result, 'duplicate_json_key')
            result[k] = v
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite_json')))
    except (ValueError, UnicodeError, RecursionError) as e:
        raise Refused('invalid_json') from e


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def trusted_directory(path, info, native_agent=False):
    if not stat.S_ISDIR(info.st_mode):return False
    if info.st_uid==0 and not info.st_mode&0o022:return True
    if native_agent and str(path) in ('/var/ossec','/var/ossec/etc'):
        import grp
        if info.st_uid==0 and info.st_gid==grp.getgrnam('wazuh').gr_gid and stat.S_IMODE(info.st_mode)==0o770:
            return True
    # Only these two existing writer bind roots may be owned by their writer.
    # The managed child and every config/state file remain root-owned.
    writers={str(ROOT/'security/logs/suricata'):998,str(ROOT/'security/logs/modsecurity'):101}
    uid=writers.get(str(path))
    return uid is not None and info.st_uid==info.st_gid==uid and stat.S_IMODE(info.st_mode)==0o755


def read(path, limit=4*1024*1024, private=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    for parent in path.parents:
        s = parent.lstat()
        stage = (str(parent) == '/var/tmp' and stat.S_IMODE(s.st_mode) == 0o1777 and
                 re.match(r'^/var/tmp/capstone-bootstrap-[a-f0-9]{24}/source/', str(path)))
        need((stage and stat.S_ISDIR(s.st_mode) and s.st_uid==0) or
             trusted_directory(parent,s,str(path)=='/var/ossec/etc/ossec.conf'),'unsafe_parent')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        # Wazuh's native root:wazuh 0660 configuration is an explicit package
        # contract. No other group-writable source/config file is accepted.
        native_agent = str(path)=='/var/ossec/etc/ossec.conf' and stat.S_IMODE(before.st_mode)==0o660
        if native_agent:
            import grp
            native_agent = before.st_gid==grp.getgrnam('wazuh').gr_gid
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and (native_agent or not before.st_mode & 0o022) and before.st_size <= limit, 'unsafe_file')
        if private:
            need(before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o600, 'private_file_required')
        raw = bytearray()
        while len(raw) <= limit:
            part = os.read(fd, min(65536, limit+1-len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(fd)
        need(len(raw) <= limit and (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
             (after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns), 'file_changed')
        return bytes(raw)
    finally:
        os.close(fd)


def mkdir(path, mode=0o700, native_agent=False):
    path = Path(path)
    if not path.exists():
        mkdir(path.parent, 0o755)
        path.mkdir(mode=mode)
        os.chmod(path, mode)
    s = path.lstat()
    need(trusted_directory(path,s,native_agent),'unsafe_directory')


def write(path, raw, mode=0o600, replace=False):
    path = Path(path)
    mkdir(path.parent,native_agent=str(path)=='/var/ossec/etc/ossec.conf')
    if path.exists() or path.is_symlink():
        need(replace, 'destination_exists')
        read(path)
    fd, temporary = tempfile.mkstemp(prefix='.log-pipeline-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchown(f.fileno(), 0, 0)
            os.fchmod(f.fileno(), mode)
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path, follow_symlinks=False)
            os.unlink(temporary)
        d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def run(args, data=None, timeout=45, limit=4*1024*1024, ok=(0,), environ=None, cwd=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit+4096, limit+4096))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                           stdout=out, stderr=err, env=ENV if environ is None else environ,
                           cwd=cwd, preexec_fn=limits,start_new_session=True)
        try:
            p.communicate(data,timeout=timeout)
        except BaseException:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.wait()
            raise
        need(p.returncode in ok, 'native_command_failed')
        out.seek(0)
        raw = out.read(limit+1)
        need(len(raw) <= limit, 'native_output_limit')
        return raw


def source_files(source, trusted=True):
    reader = read if trusted else lambda p: Path(p).read_bytes()
    names=set(FILES)|set(EXTRA)|{W+'tests/'+n for n in LOGTESTS}|{W+'fixtures/'+n+'.jsonl' for n in FIXTURES}
    result={name:reader(Path(source)/name) for name in sorted(names)}
    for lane in ('correlation','evidence'):
        expected=W+'fixtures/'+lane+'/expected.tsv';result[expected]=reader(Path(source)/expected)
        rows=fixture_rows(result[expected])
        for fixture,_,_ in rows:
            name=W+'fixtures/'+lane+'/'+fixture+'.jsonl';result[name]=reader(Path(source)/name)
    return result


def fixture_rows(raw):
    rows=[]
    for line in raw.decode().splitlines():
        if not line or line.startswith('#'):continue
        row=line.split('|')
        need(len(row)==3 and re.fullmatch('[a-z0-9_-]+',row[0]) and
             row[1] in ('ready','canary','evidence','other-agent','bare','unrelated') and
             (row[2] in ('','reject') or re.fullmatch('[0-9]+(?: [0-9]+)*',row[2])), 'native_fixture_manifest_invalid')
        rows.append(row)
    need(1<=len(rows)<=128 and len({r[0] for r in rows})==len(rows),'native_fixture_manifest_invalid')
    return rows


def operation_lock(role, mutation):
    """No lock-file creation for read-only calls; exclusive on mutations."""
    path=Path('/run')/('capstone-log-pipeline-'+role+'.lock')
    parent=path.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode&0o002,'unsafe_lock_parent')
    if not mutation and not path.exists():
        return None
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|(os.O_CREAT if mutation else 0),0o600)
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and
             stat.S_IMODE(s.st_mode)==0o600,'unsafe_operation_lock')
        fcntl.flock(fd,(fcntl.LOCK_EX if mutation else fcntl.LOCK_SH)|fcntl.LOCK_NB)
        return fd
    except Exception:
        os.close(fd)
        raise


def fingerprint(files):
    hashes = {k: sha(v) for k, v in files.items()}
    return {'schema': 1, 'source_sha256': sha(canonical(hashes)), 'files': hashes}


def settings(role, environ=None):
    e = dict(os.environ if environ is None else environ)
    need(role in ('security','siem'), 'invalid_role')
    need(e.get('ROLE_DIR', str(ROOT/role)) == str(ROOT/role), 'fixed_role_path_required')
    hosts = {}
    for key in ('SECURITY_HOST','SIEM_HOST','SERVICE_HOST'):
        try:
            addr = ipaddress.IPv4Address(e[key])
        except (KeyError, ValueError) as exc:
            raise Refused('invalid_host_address') from exc
        need(not addr.is_unspecified and not addr.is_multicast and not addr.is_loopback, 'invalid_host_address')
        hosts[key] = str(addr)
    need(len(set(hosts.values())) == 3, 'distinct_hosts_required')
    supplied = e.get('LOG_PROTECTED_IPS', ','.join(hosts.values())).split(',')
    need(1 <= len(supplied) <= 32, 'protected_address_limit')
    try:
        protected = sorted({str(ipaddress.ip_address(x)) for x in supplied})
    except ValueError as exc:
        raise Refused('invalid_protected_address') from exc
    need(set(hosts.values()) <= set(protected), 'management_hosts_must_be_protected')
    profile=sha(canonical({'role':role,'hosts':hosts,'protected_ips':protected}))
    return {'schema':1,'role':role,'profile':profile,'hosts':hosts,'protected_ips':protected,
            'role_dir':str(ROOT/role),'sensor':SENSOR}


def text_render(raw, config):
    text = raw.decode('utf-8')
    text = text.replace(MID, config['machine_id']).replace(OLD_LOG+'/modsec', str(ROOT/'security/logs/modsecurity'))
    text = text.replace(OLD_LOG+'/suricata', str(ROOT/'security/logs/suricata'))
    text = text.replace('/usr/local/bin/docker', config['docker']).replace('/usr/local/bin/vector', config['vector'])
    text = text.replace('groot-sec', SENSOR).replace(OLD_BINDING, config['binding'])
    text = text.replace('["211.170.162.110", "211.170.162.111"]', json.dumps(config['protected_ips']))
    text = text.replace('value == "211.170.162.110" || value == "211.170.162.111"',
                        'includes('+json.dumps(config['protected_ips'])+', value)')
    need(OLD_LOG not in text and MID not in text and '211.170.162.11' not in text, 'untranslated_site_pin')
    return text.encode()


def rule_config(raw, config):
    # These four negative lookaheads are the independent evidence-lane check;
    # changing only the VRL protected_asset flag would leave old host IPs here.
    marker=rb'(?!211\.170\.162\.(?:110|111)\z)'
    need(raw.count(marker)==4,'evidence_protected_rule_boundary')
    replacement=('(?!(?:'+'|'.join(re.escape(x) for x in config['protected_ips'])+r')\z)').encode()
    result=text_render(raw.replace(marker,replacement),config)
    need(rb'211\.170\.162' not in result,'untranslated_rule_protection')
    ET.fromstring(b'<root>'+result+b'</root>')
    return result


def native_logtest_files(files,config,cid):
    need(re.fullmatch('[0-9a-f]{64}',cid),'native_manager_identity_invalid')
    result={}
    for name,raw in files.items():
        if not name.startswith((W+'tests/',W+'fixtures/')):continue
        raw=raw.replace(b'211.170.162.110',config['hosts']['SECURITY_HOST'].encode())
        raw=raw.replace(b'211.170.162.111',config['hosts']['SIEM_HOST'].encode())
        raw=text_render(raw,config).replace(b'single-node-wazuh.manager-1',cid.encode())
        if name.startswith(W+'fixtures/evidence/') and name.endswith('.jsonl') and not name.rsplit('/',1)[-1].startswith('protected-'):
            # Documentation-range VM addresses must not turn an unrelated
            # positive fixture into a protected-address negative test.
            records=[]
            for line in raw.splitlines():
                obj=parse(line);norm=obj.get('capstone_norm',{})
                for field in ('source_ip','destination_ip'):
                    value=norm.get(field)
                    if isinstance(value,str) and value in config['protected_ips']:
                        network='192.0.2.0/24' if ipaddress.ip_address(value).version==4 else '2001:db8:ffff::/120'
                        norm[field]=next(str(x) for x in ipaddress.ip_network(network).hosts() if str(x) not in config['protected_ips'])
                records.append(canonical(obj))
            raw=b''.join(records)
        if name.startswith(W+'tests/'):
            # Explicit rootful socket: no inherited Docker context or daemon.
            raw=raw.replace(b'"$docker" exec',b'"$docker" --host unix:///var/run/docker.sock exec')
        result[name[len(W):]]=raw
    return result


def auxiliary_policy(raw,config):
    body=raw[raw.index(b'/home/groot_a/'):]
    header=(OLD_LOG+'/suricata/*.json\n'+OLD_LOG+'/suricata/*.log\n'+OLD_LOG+'/modsec/*.log {').encode()
    need(body.count(header)==1,'auxiliary_policy_boundary')
    paths=[str(ROOT/'security/logs'/p) for p in ('suricata/fast.log','suricata/stats.log',
           'suricata/suricata.log','modsecurity/capstone-access.log')]
    result=body.replace(header,('\n'.join(paths)+' {').encode(),1)
    need(all(x not in result for x in (b'*',b'eve.json',b'audit.log',b'generation-')),'raw_copytruncate_forbidden')
    return text_render(result,config)


def bind(source, target):
    return {'type':'bind','source':str(source),'target':target,'read_only':True,'bind':{'create_host_path':False}}


def add_mount(service, source, target):
    existing = service.setdefault('volumes', [])
    targets = [v.get('target') if isinstance(v,dict) else v.split(':')[1] for v in existing]
    need(target not in targets, 'mount_target_conflict')
    existing.append(bind(source, target))


def security_compose(compose, role):
    result = copy.deepcopy(compose)
    waf, suri = result['services']['waf'], result['services']['suricata']
    need(waf['container_name']=='capstone-security-waf' and suri['container_name']=='capstone-security-suricata', 'writer_name_changed')
    add_mount(suri, role/'log-pipeline/suricata.yaml', '/etc/suricata/suricata.yaml')
    add_mount(suri, role/'log-pipeline/suricata-entrypoint.sh', '/capstone-entrypoint.sh')
    # The reviewed entrypoint otherwise chowns mounted config recursively. Use
    # native fixed UID execution and explicit config, preserving cap/host IDS.
    suri['entrypoint']=['/bin/bash','/capstone-entrypoint.sh']
    suri.setdefault('environment',{}).update({'PUID':'998','PGID':'998'})
    suri['command']=['-c','/etc/suricata/suricata.yaml']+suri['command']
    add_mount(waf, role/'log-pipeline/waf-producer.conf', '/etc/nginx/conf.d/zz-capstone-evidence.conf')
    # The image renders this template at startup. Mounting its generated
    # destination read-only would make the image's envsubst step fail.
    add_mount(waf, role/'log-pipeline/waf-override.conf',
              '/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template')
    return result


def suricata_config(raw):
    need(b'\r' not in raw and b'\0' not in raw, 'yaml_framing')
    pattern=rb'(?m)^(\s*filename:[ \t]*)eve\.json([ \t]*(?:#[^\n]*)?)$'
    need(len(re.findall(pattern,raw))==1,'eve_filename_ambiguous')
    return re.sub(pattern,rb'\1capstone-managed/active.jsonl\2',raw)


def render_runtime(files, config):
    result = {dest: text_render(files[src],config) for src,dest in FILES.items()}
    # Keep logical writer names (suricata/waf) in all gate output; translate only
    # the Docker argument. This preserves executable and source type checks.
    p=str(RUNTIME/'writer-gates.sh'); body=result[p].decode()
    old='output=$(/usr/local/bin/docker "$@"'
    old=old.replace('/usr/local/bin/docker',config['docker'])
    replacement=('local -a mapped=(); local arg\n    for arg in "$@"; do\n'
                 '      case "$arg" in suricata) arg=capstone-security-suricata;; waf) arg=capstone-security-waf;; esac\n'
                 '      mapped+=("$arg")\n    done\n    output=$('+config['docker']+' --host unix:///var/run/docker.sock "${mapped[@]}"')
    need(body.count(old)==1,'writer_docker_adapter_boundary'); result[p]=body.replace(old,replacement).encode()
    # Only the first attested gen0 may be re-read from the beginning during
    # the bounded first-start grant. Existing malformed CP and every later
    # generation still use the native gate. Never fabricate a checkpoint.
    p=str(RUNTIME/'coordinator.sh'); body=result[p].decode()
    old=('        cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" >/dev/null ||\n'
         '            { ro_refuse existing_native_cursor_unsafe; return 2; }\n'
         '        cg_vector_current "$RO_CP" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" >/dev/null ||\n'
         '            { ro_refuse vector_current_cursor_unavailable; return 2; }')
    new=('        result=$(cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO") ||\n'
         '            { lp_initial_replay wazuh "$result" || { ro_refuse existing_native_cursor_unsafe; return 2; }; }\n'
         '        result=$(cg_vector_current "$RO_CP" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO") ||\n'
         '            { lp_initial_replay vector "$result" || { ro_refuse vector_current_cursor_unavailable; return 2; }; }')
    need(body.count(old)==1,'fresh_guard_boundary');body=body.replace(old,new,1)
    body += '\n'+EMPTY_INITIAL_GUARD
    # coordinator's main dispatch precedes appended definitions: insert helper
    # before the first function, keeping runtime source imports conventional.
    body=body.replace('\n'+EMPTY_INITIAL_GUARD,'')
    body=body.replace('ro_refuse() {',EMPTY_INITIAL_GUARD+'\nro_refuse() {',1)
    for command,count in (('exec',2),('kill',1)):
        needle=config['docker']+' '+command+' '
        need(body.count(needle)==count,'coordinator_docker_endpoint_boundary')
        body=body.replace(needle,config['docker']+' --host unix:///var/run/docker.sock '+command+' ')
    result[p]=body.encode()
    hist='/usr/local/lib/capstone-vector-history-auto/'
    names=[*HISTORY,*('history/'+n for n in HISTORY_LIB)]
    result[hist+'runtime.sha256']=''.join(sha(result[hist+n])+'  '+n+'\n' for n in names).encode()
    result[str(CFG/'auxiliary-logrotate.conf')]=auxiliary_policy(files['infra/groot-a/logrotate-capstone-secstack'],config)
    result['/etc/systemd/system/capstone-security-auxiliary.service']=b'''[Unit]
Description=Rotate only Suricata auxiliary logs and WAF access log
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/sbin/logrotate --state /var/lib/capstone-vector-maintenance/auxiliary-logrotate.status /etc/capstone-vector/auxiliary-logrotate.conf
TimeoutStartSec=120
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/capstone/security/logs /var/lib/capstone-vector-maintenance
'''
    result['/etc/systemd/system/capstone-security-auxiliary.timer']=b'''[Unit]
Description=Daily auxiliary security log retention
[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=300
[Install]
WantedBy=timers.target
'''
    return result


def runtime_mode(path):
    if path in (str(CFG/n) for n in ('vector.toml','vector.env','raw-line-binding.json')):return 0o600
    return 0o644 if '/etc/systemd/' in path else 0o500 if '/sbin/' in path else 0o400


EMPTY_INITIAL_GUARD = r'''lp_initial_replay() {
    local reader=$1 reason=$2 cp=/var/ossec/queue/logcollector/file_status.json
    local grant=/var/lib/capstone-raw-operations/bootstrap-reader.json phase size
    [[ -f $grant && ! -L $grant && $(/usr/bin/stat -c %u:%g:%a:%h "$grant") == 0:0:600:1 &&
       $(/usr/bin/stat -c %s "$grant") -le 4096 ]] || return 1
    [[ $RO_PHASE == active && $(/usr/bin/jq -r '.revision,.current.number' <<< "$RO_STATE") == $'0\n0' &&
       ${RO_CURRENT##*/} == generation-0000000000.jsonl ]] || return 1
    size=$(/usr/bin/stat -c %s "$RO_CURRENT") || return 1
    (( size<=2147483648 )) || return 1
    phase=$(/usr/bin/jq -er --arg engine "$RO_ENGINE" --arg dev "$RO_OLD_DEV" --arg ino "$RO_OLD_INO" \
      --argjson now "$(date +%s)" --argjson size "$size" '
      select(.schema==1 and .engines[$engine].device==($dev|tonumber) and .engines[$engine].inode==($ino|tonumber) and
       ((.phase=="pending" and .expires_at>$now) or (.phase=="sealed" and $size==0)))|.phase' "$grant") || return 1
    if [[ $reader == vector ]]; then
        [[ ! -L $RO_CP && ! -L $RO_CP/checkpoints.json && ! -L $RO_CP/checkpoints.new.json ]] || return 1
        if [[ ! -e $RO_CP/checkpoints.json && ! -e $RO_CP/checkpoints.new.json ]]; then return 0; fi
        [[ $(/usr/bin/jq -r .reason <<< "$reason") == vector_checkpoint_match_missing ]] || return 1
    elif [[ $reader == wazuh ]]; then
        [[ ! -L $cp ]] || return 1
        [[ -e $cp ]] || return 0
        [[ -f $cp && $(/usr/bin/stat -c %u:%h "$cp") == 0:1 && $(/usr/bin/stat -c %s "$cp") -le 65535 ]] || return 1
        /usr/bin/jq -nce --stream --arg mode stream_guard --arg logical '' --argjson device 0 --argjson inode 0 \
          -f "$RO_LIBRARY/checkpoint-gates.jq" "$cp" >/dev/null || return 1
        /usr/bin/jq -se --arg p "$RO_ALIAS" 'length==1 and (.[0]|type=="object" and (.files|type=="array") and
          all(.files[];type=="object" and (.path|type=="string")) and all(.files[];.path!=$p))' "$cp" >/dev/null || return 1
    else return 1
    fi
    return 0
}'''

NATIVE_INITIAL_PROBE = r'''set -euo pipefail
source /usr/local/lib/capstone-raw-operations/coordinator.sh
ro_runtime
for engine in suricata modsecurity; do
 ro_engine "$engine"; ro_load; ro_validate
 [[ $(stat -c %s "$RO_CURRENT") == 0 ]] && continue
 cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" >/dev/null
 cg_vector_current "$RO_CP" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" >/dev/null
done
'''


def agent_configuration(raw, localfiles):
    need(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'agent_xml_declaration')
    root=ET.fromstring(b'<config>'+raw+b'</config>')
    paths=[n.text for n in root.findall('.//localfile/location')]
    additions=ET.fromstring(b'<config>'+localfiles+b'</config>')
    for node in additions.findall('.//localfile/location'):
        need(node.text not in paths,'normalized_localfile_already_present')
    # Storage health is an existing JSON-formatted command emitted by the
    # maintenance wrapper's logger; retain journal/syslog agent defaults.
    result=raw.rstrip()+b'\n'+localfiles+b'\n'
    ET.fromstring(b'<config>'+result+b'</config>')
    return result


def monitor_candidate(raw, agent_id, protected):
    need(re.fullmatch('[0-9]{3,8}',agent_id),'invalid_security_agent_id')
    value=parse(raw); value['name']=MONITOR_NAME
    def visit(node):
        if isinstance(node,dict):
            return {k:(agent_id if k=='agent.id' and v=='001' else SENSOR if k=='data.capstone_norm.sensor' and v=='groot-sec' else visit(v)) for k,v in node.items()}
        if isinstance(node,list):
            if node==['211.170.162.110','211.170.162.111']:
                return protected
            return [visit(v) for v in node]
        return node
    value=visit(value)
    need(value['enabled'] is False and value['schedule']=={'period':{'interval':1,'unit':'MINUTES'}},'monitor_schedule_changed')
    need(all(t['query_level_trigger']['actions']==[] for t in value['triggers']),'monitor_actions_forbidden')
    need('groot-sec' not in json.dumps(value) and '211.170.162.11' not in json.dumps(value),'untranslated_monitor_pin')
    return value


def config_environment(config, waf_cid, producer):
    need(re.fullmatch('[0-9a-f]{64}',waf_cid),'invalid_waf_id')
    pairs={'CAPSTONE_SENSOR':SENSOR,'SURICATA_EVE_PATH':str(ROOT/'security/logs/suricata/eve.json'),
           'WAF_AUDIT_PATH':str(ROOT/'security/logs/modsecurity/audit.log'),
           'WAF_ACCESS_PATH':str(ROOT/'security/logs/modsecurity/capstone-access.log'),
           'WAF_INSTANCE_ID':waf_cid,'WAF_CONFIG_SHA256':sha(producer),'WAF_DEPLOYMENT_BINDING':config['binding']}
    return ''.join(k+'='+v+'\n' for k,v in pairs.items()).encode()


def state_initial(config, engine, meta, pins, writer_hash, boot_id):
    need(engine in ('suricata','modsecurity') and re.fullmatch('[0-9a-f]{32}',boot_id),'invalid_raw_identity')
    need(set(pins)=={'container_id','engine_config_sha256','producer_format_sha256','vector_config_sha256','vector_env_sha256','wazuh_config_sha256'}
         and all(re.fullmatch('[0-9a-f]{64}',x) for x in pins.values()),'invalid_source_pins')
    return {'schema_version':1,'policy':'capstone-raw-operations-v1','machine_id':config['machine_id'],
            'boot_id':boot_id,'engine':engine,'revision':0,'phase':'active','source_pins':pins,
            'current':{'number':0,'basename':'generation-0000000000.jsonl','device':meta.st_dev,
                       'inode':meta.st_ino,'writer_config_sha256':writer_hash},'pending':None,
            'proof':{'old_closed':None,'readers_drained':None,'publish_guard':None}}


class Bootstrap:
    def __init__(self, role):
        self.config=settings(role); self.role=role; self.root=ROOT/role
        self.base=self.root/'log-pipeline'; self.receipt=self.base/'receipt.json'
        self.source=Path(os.environ['CAPSTONE_SOURCE'])
        self.files=source_files(self.source); self.fp=fingerprint(self.files)
        self.config['machine_id']=read('/etc/machine-id',128).decode().strip()
        need(re.fullmatch('[0-9a-f]{32}',self.config['machine_id']),'machine_id_invalid')
        self.config['docker']=self.binary('docker',('/usr/bin/docker','/usr/local/bin/docker'))
        self.config['vector']=self.binary('vector',('/usr/bin/vector','/usr/local/bin/vector')) if role=='security' else '/usr/bin/vector'
        self.config['binding']=sha(canonical({'machine':self.config['machine_id'],'profile':self.config['profile']}))
        self.config['sources']=self.fp['source_sha256']; self.config_hash=sha(canonical(self.config))

    @staticmethod
    def binary(name, choices):
        for choice in choices:
            if Path(choice).is_file() and not Path(choice).is_symlink():
                read(choice,128*1024*1024)
                need(os.access(choice,os.X_OK),'binary_not_executable')
                return choice
        raise Refused('required_binary_missing_'+name)

    def docker(self, args, **kwargs):
        return run([self.config['docker'],'--host','unix:///var/run/docker.sock',*args],**kwargs)

    def current(self):
        data=parse(read(self.receipt, private=True))
        need(data.get('schema')==1 and data.get('config_sha256')==self.config_hash and data.get('sources')==self.fp,'installation_profile_changed')
        return data

    def save(self, data):
        write(self.receipt,canonical(data),replace=self.receipt.exists())

    def record(self, phase, **extra):
        self.save({'schema':1,'config_sha256':self.config_hash,'config':self.config,'sources':self.fp,
                   'phase':phase,'role':self.role,**extra})

    def inspect(self,name):
        values=parse(self.docker(['inspect',name])); need(len(values)==1,'container_not_unique')
        obj=values[0]
        need(re.fullmatch('[0-9a-f]{64}',obj['Id']) and obj['State']['Running'] is True,'container_not_running')
        need(obj['Config']['Labels'].get('com.docker.compose.project')=='capstone-'+self.role,'foreign_container')
        return obj

    def check(self):
        if self.receipt.exists():
            data=self.current(); need(data['phase'] in ('prepared','rules_active','complete'),'partial_install_requires_review')
            for path,digest in data['files'].items():
                need(sha(read(path))==digest,'prepared_file_changed')
            return {'status':'prerequisites_checked','phase':data['phase'],'mutations':0,'source_sha256':self.fp['source_sha256']}
        if self.role=='security':
            need(re.match(rb'vector 0\.59\.0(?:\s|$)',run([self.config['vector'],'--version'])),'vector_0_59_0_required')
            for name in ('jq','logrotate','systemctl','timeout','flock','journalctl','logger','find','stat','sha256sum','sha1sum'):
                path=shutil.which(name,path=ENV['PATH']); need(path,'required_tool_missing_'+name)
            for path in (CFG,RAW,RUNTIME,Path('/var/lib/capstone-vector'),Path('/var/log/capstone-vector'),
                         Path('/var/lib/capstone-raw-migration'),Path('/var/lib/capstone-vector-history-auto')):
                need(not path.exists() and not path.is_symlink(),'existing_pipeline_not_adopted')
            self.binary('logrotate',('/usr/sbin/logrotate',))
            for dest in render_runtime(self.files,self.config):
                need(not Path(dest).exists() and not Path(dest).is_symlink(),'pipeline_destination_exists')
        need(not self.base.exists() and not self.base.is_symlink(),'partial_install_requires_review')
        return {'status':'prerequisites_checked','mutations':0,'source_sha256':self.fp['source_sha256']}

    def export_image_config(self,image):
        need(re.fullmatch('sha256:[0-9a-f]{64}',image),'pinned_image_required')
        cid=self.docker(['create','--pull','never','--network','none','--read-only',
                         '--label','io.capstone.pipeline.config-extract='+self.config_hash,
                         '--entrypoint','/bin/true',image]).decode().strip()
        need(re.fullmatch('[0-9a-f]{64}',cid),'config_extract_identity')
        self.record('config_extract_pending',temporary_container_id=cid)
        try:
            # docker cp is read-only toward the stopped image filesystem.
            archive=self.docker(['cp',cid+':/etc/suricata.dist/suricata.yaml','-'],limit=8*1024*1024)
            import io, tarfile
            with tarfile.open(fileobj=io.BytesIO(archive)) as t:
                members=t.getmembers(); need(len(members)==1 and members[0].isfile() and members[0].size<2*1024*1024,'image_config_archive_invalid')
                result=t.extractfile(members[0]).read()
        finally:
            obj=parse(self.docker(['inspect',cid]))[0]
            need(obj['Id']==cid and obj['State']['Running'] is False and
                 obj['Config']['Labels'].get('io.capstone.pipeline.config-extract')==self.config_hash,'config_extract_ownership_changed')
            self.docker(['rm',cid])
        return result

    def prepare(self):
        if self.receipt.exists():
            need(self.current()['phase']=='complete','partial_install_requires_review')
            return self.verify()
        self.check(); mkdir(self.base); self.record('preparing')
        if self.role=='siem':
            compose_path=self.root/'compose.core.json'; compose=parse(read(compose_path))
            rule=rule_config(self.files[W+'capstone_vector_rules.xml'],self.config)
            write(self.base/'capstone_vector_rules.xml',rule,0o444)
            manager=compose['services']['wazuh.manager']
            add_mount(manager,self.base/'capstone_vector_rules.xml','/wazuh-config-mount/etc/rules/capstone_vector_rules.xml')
            options=self.root/'wazuh/capstone-internal-options.conf'; old=read(options)
            need(not re.search(rb'(?m)^analysisd\.(event_threads|rule_matching_threads)=',old),'analysis_threads_already_configured')
            need(b'analysisd.decoder_order_size=1024' in old,'decoder_1024_required')
            write(options,old.rstrip()+b'\nanalysisd.event_threads=1\nanalysisd.rule_matching_threads=1\n',0o444,True)
            write(compose_path,canonical(compose),0o600,True)
            outputs={str(self.base/'capstone_vector_rules.xml'):sha(rule),str(options):sha(read(options))}
        else:
            compose_path=self.root/'compose.json'; compose=parse(read(compose_path))
            source_config=self.export_image_config(compose['services']['suricata']['image'])
            outputs={}
            producer=text_render(self.files[V+'raw-operations/zz-capstone-evidence-v2.conf'],self.config)
            # Preserve the reviewed image setup but do not chown a read-only bind.
            entry=text_render(self.files[V+'raw-operations/suricata-entrypoint-managed.sh'],self.config)
            need(entry.count(b'chown -R suricata:suricata /etc/suricata\n')==1,'entrypoint_adapter_boundary')
            entry=entry.replace(b'chown -R suricata:suricata /etc/suricata\n',b'# config is a root-owned read-only bootstrap bind\n')
            for name,raw,mode in [('suricata.yaml',suricata_config(source_config),0o444),
                                  ('suricata-entrypoint.sh',entry,0o555),('waf-producer.conf',producer,0o444),
                                  ('waf-override.conf',b'Include /var/log/modsecurity/capstone-managed/audit-path.conf\n',0o444)]:
                path=self.base/name; write(path,raw,mode); outputs[str(path)]=sha(raw)
            initial={}
            for engine,folder,uid,alias in [('suricata','suricata',998,'eve.json'),('modsecurity','modsecurity',101,'audit.log')]:
                log=self.root/'logs'/folder; managed=log/'capstone-managed'
                need(not managed.exists() and not (log/alias).exists(),'raw_log_already_present')
                mkdir(managed,0o711)
                raw=managed/'generation-0000000000.jsonl'; write(raw,b'',0o644); os.chown(raw,uid,uid)
                initial[engine]={'device':raw.stat().st_dev,'inode':raw.stat().st_ino,'initial_bytes':0}
                os.link(raw,log/alias,follow_symlinks=False)
                if engine=='suricata':
                    os.link(raw,managed/'active.jsonl',follow_symlinks=False)
                else:
                    pointer=b'SecAuditLog /var/log/modsecurity/capstone-managed/generation-0000000000.jsonl\n'
                    write(managed/'audit-path.conf',pointer,0o444)
                    # The bounded line-health reader requires the reviewed
                    # producer's auxiliary access log to be 101:101 / 0640.
                    write(log/'capstone-access.log',b'',0o640);os.chown(log/'capstone-access.log',101,101)
            write(compose_path,canonical(security_compose(compose,self.root)),0o444,True)
            manifest_path=self.root/'manifest.json'
            manifest=parse(read(manifest_path)); need('compose.json' in manifest['files'],'base_compose_manifest_missing')
            manifest['files']['compose.json']=sha(read(compose_path))
            write(manifest_path,canonical(manifest),0o600,True)
        self.record('prepared',files=outputs,initial_generations=initial if self.role=='security' else {})
        return {'status':'prepared','role':self.role,'source_sha256':self.fp['source_sha256']}

    def activate(self):
        data=self.current()
        if data['phase']=='complete':
            return self.verify()
        need(data['phase']=='prepared','partial_install_requires_review')
        for p,digest in data['files'].items():
            need(sha(read(p))==digest,'prepared_file_changed')
        self.record('activation_pending',files=data['files'],initial_generations=data.get('initial_generations',{}))
        if self.role=='siem':
            manager=self.inspect('capstone-wazuh-manager')
            version=self.docker(['exec',manager['Id'],'/var/ossec/bin/wazuh-control','info'])
            need(b'v4.14.8' in version,'wazuh_4_14_8_required')
            self.docker(['exec',manager['Id'],'/var/ossec/bin/wazuh-analysisd','-t'])
            mounted=self.docker(['exec',manager['Id'],'cat','/var/ossec/etc/rules/capstone_vector_rules.xml'])
            need(sha(mounted)==data['files'][str(self.base/'capstone_vector_rules.xml')],'manager_rule_copy_mismatch')
            native={}
            for name,raw in native_logtest_files(self.files,self.config,manager['Id']).items():
                target=self.base/'native-logtest'/name;write(target,raw,0o400);data['files'][str(target)]=sha(raw)
            for script in LOGTESTS:
                result=run(['/bin/sh',str(self.base/'native-logtest/tests'/script)],timeout=180,limit=65536).decode()
                lines=result.splitlines()
                need(lines and all(x.startswith('PASS ') for x in lines),'native_logtest_output_invalid')
                native[script]={'pass_lines':len(lines),'stdout_sha256':sha(result.encode())}
            self.record('rules_active',files=data['files'],manager_id=manager['Id'],native_logtest=native)
            return {'status':'rules_active','monitor_pending_security_enrollment':True,'actions':0,'native_logtest':native}
        writers={name:self.inspect('capstone-security-'+name) for name in ('suricata','waf')}
        need(b'8.0.6' in self.docker(['exec',writers['suricata']['Id'],'/usr/bin/suricata','--build-info']),'suricata_8_0_6_required')
        conf=Path('/var/ossec/etc/ossec.conf'); previous=read(conf); info=conf.stat()
        write(self.base/'ossec.conf.before',previous)
        updated=agent_configuration(previous,self.files[W+'agent-localfile.xml'])
        run(['/usr/bin/systemctl','stop','wazuh-agent'],timeout=90)
        write(conf,updated,stat.S_IMODE(info.st_mode),True); os.chown(conf,0,info.st_gid)
        run(['/var/ossec/bin/wazuh-agentd','-t']); run(['/var/ossec/bin/wazuh-logcollector','-t'])
        output=render_runtime(self.files,self.config)
        environment=config_environment(self.config,writers['waf']['Id'],read(self.base/'waf-producer.conf'))
        output[str(CFG/'vector.env')]=environment
        output[str(CFG/'raw-line-binding.json')]=canonical({'schema_version':1,'policy':'periodic-snapshot-tail-v1',
                'vector_config_sha256':sha(output[str(CFG/'vector.toml')]),'vector_env_sha256':sha(environment)})
        for path in ('/var/lib/capstone-vector','/var/log/capstone-vector','/var/lib/capstone-vector-maintenance',
                     '/var/lib/capstone-vector-history-auto','/var/lib/capstone-raw-migration',str(RAW)):
            mkdir(path)
        for name in ('jobs','store'):
            mkdir(Path('/var/lib/capstone-vector-history-auto')/name)
        write('/var/lib/capstone-vector-history-auto/.lock',b'')
        for lane,name in [('ready','normalized.jsonl'),('evidence','normalized.jsonl'),('quarantine','quarantine.jsonl'),
                          ('telemetry','health.jsonl'),('canary','normalized.jsonl')]:
            directory=Path('/var/log/capstone-vector')/lane; mkdir(directory); write(directory/name,b'')
        mkdir('/var/lib/capstone-automation/ansible')
        lock=Path('/var/lib/capstone-automation/ansible/vector.lock')
        if not lock.exists():
            write(lock,b'')
        else:
            read(lock)
        for path,raw in output.items():
            mode=runtime_mode(path)
            write(path,raw,mode); data['files'][path]=sha(raw)
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-','')
        for engine,folder,writer in [('suricata','suricata','suricata'),('modsecurity','modsecurity','waf')]:
            directory=RAW/engine
            for d in (directory,directory/'history',directory/'staging'): mkdir(d)
            engine_path='/etc/suricata/suricata.yaml' if engine=='suricata' else '/etc/modsecurity.d/modsecurity-override.conf'
            format_path=engine_path if engine=='suricata' else '/etc/nginx/conf.d/zz-capstone-evidence.conf'
            engine_sha=sha(self.docker(['exec',writers[writer]['Id'],'cat',engine_path]))
            format_sha=sha(self.docker(['exec',writers[writer]['Id'],'cat',format_path]))
            managed=self.root/'logs'/folder/'capstone-managed'; raw=managed/'generation-0000000000.jsonl'
            original=data['initial_generations'][engine]
            need((raw.lstat().st_dev,raw.lstat().st_ino)==(original['device'],original['inode']) and
                 original['initial_bytes']==0,'initial_generation_identity_changed')
            pins={'container_id':writers[writer]['Id'],'engine_config_sha256':engine_sha,'producer_format_sha256':format_sha,
                  'vector_config_sha256':sha(output[str(CFG/'vector.toml')]),'vector_env_sha256':sha(environment),
                  'wazuh_config_sha256':sha(updated)}
            writer_sha=engine_sha if engine=='suricata' else sha(read(managed/'audit-path.conf'))
            write(directory/'state.json',canonical(state_initial(self.config,engine,raw.stat(),pins,writer_sha,boot)))
        grant={'schema':1,'phase':'pending','expires_at':int(time.time())+600,'engines':data['initial_generations']}
        write(RAW/'bootstrap-reader.json',canonical(grant))
        barrier={'schema_version':1,'policy':'capstone-raw-migration-start-v1','machine_id':self.config['machine_id'],
                 'phase':'released','plan_sha256':self.config_hash,'armed_boot_id':boot,'armed_ledger_sha256':self.config_hash,
                 'release':{'boot_id':boot,'ledger_sha256':self.config_hash,'runtime_guard_sha256':sha(output[str(RUNTIME/'guard.sh')]),
                 'suricata_state_sha256':sha(read(RAW/'suricata/state.json')),'modsecurity_state_sha256':sha(read(RAW/'modsecurity/state.json')),
                 'readers_verified':['vector','wazuh']}}
        # The migration record is a bootstrap guard binding, not a delivery ACK.
        # Verify both read-only guards before publishing its released record.
        for reader in ('vector','wazuh'):
            run(['/bin/bash',str(RUNTIME/'guard.sh'),reader],timeout=120)
        write('/var/lib/capstone-raw-migration/start-barrier.json',canonical(barrier))
        vector_env={**ENV,'VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION':'true'}
        vector_env.update(dict(line.split('=',1) for line in environment.decode().splitlines()))
        # Native validation uses no running input and cannot emit source records.
        run([self.config['vector'],'validate','--no-environment',str(CFG/'vector.toml')],
            environ=vector_env,cwd=CFG,timeout=45)
        run(['/usr/bin/systemctl','daemon-reload'])
        run(['/usr/bin/systemctl','enable','--now','wazuh-agent','capstone-vector.service'],timeout=180)
        deadline=time.monotonic()+180
        for attempt in range(24):
            try:
                run(['/bin/bash','--noprofile','--norc','-c',NATIVE_INITIAL_PROBE],timeout=125)
                break
            except Refused:
                need(attempt<23 and time.monotonic()<deadline,'initial_native_checkpoint_deadline')
                time.sleep(5)
        grant['phase']='sealed'; write(RAW/'bootstrap-reader.json',canonical(grant),replace=True)
        run(['/usr/bin/systemctl','enable','--now',*TIMERS],timeout=90)
        data['files'][str(conf)]=sha(updated)
        self.record('activation_verifying',files=data['files'],writers={k:v['Id'] for k,v in writers.items()},
                    delivery_acknowledged=False,actual_attack_tested=False)
        result=self.verify(phase='activation_verifying')
        data=self.current();data['phase']='complete';self.save(data)
        return result

    def verify_base(self):
        data=self.current()
        need(data['phase'] in ('prepared','complete'),'pipeline_base_not_prepared')
        for path,digest in data['files'].items():
            need(sha(read(path))==digest,'prepared_file_changed')
        if self.role=='siem':
            return {'status':'base_verified','role':self.role}
        compose=parse(read(self.root/'compose.json'))
        for service in ('suricata','waf'):
            expected=compose['services'][service]
            observed=self.inspect('capstone-security-'+service)
            image=parse(self.docker(['image','inspect',expected['image']]))[0]
            compare_container(observed,expected,image,compose,'capstone-security')
        for folder,uid,alias in [('suricata',998,'eve.json'),('modsecurity',101,'audit.log')]:
            base=self.root/'logs'/folder; managed=base/'capstone-managed'
            need(managed.lstat().st_uid==0 and stat.S_IMODE(managed.lstat().st_mode)==0o711,'managed_raw_directory_changed')
            if data['phase']=='prepared':
                current=managed/'generation-0000000000.jsonl'; info=current.lstat()
                need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_gid==uid and
                     stat.S_IMODE(info.st_mode)==0o644 and info.st_nlink==(3 if folder=='suricata' else 2),'initial_raw_metadata_changed')
                paths=[base/alias]+([managed/'active.jsonl'] if folder=='suricata' else [])
                for p in paths:
                    other=p.lstat(); need(stat.S_ISREG(other.st_mode) and (info.st_dev,info.st_ino)==(other.st_dev,other.st_ino),'raw_alias_changed')
        return {'status':'base_verified','role':self.role,'pipeline_active':data['phase']=='complete'}

    def monitor(self):
        need(self.role=='siem','monitor_requires_siem')
        state=self.current()
        if state['phase']=='complete':
            return self.verify()
        need(state['phase']=='rules_active','monitor_previous_operation_uncertain')
        manager=self.inspect('capstone-wazuh-manager')
        listing=self.docker(['exec',manager['Id'],'/var/ossec/bin/agent_control','-l']).decode()
        matches=re.findall(r'ID:\s*([0-9]{3,8}), Name: capstone-security, IP: [^,\n]+, Active',listing)
        need(len(matches)==1,'security_agent_not_uniquely_active')
        candidate=monitor_candidate(self.files[W+'indexer-native/window-v2/monitor.json'],matches[0],self.config['protected_ips'])
        client=Indexer(self.root,self.config['hosts']['SIEM_HOST'])
        version=client('GET','/')['version']['number']; need(version=='2.19.6','opensearch_2_19_6_required')
        need(not exact_monitor_ids(client),'existing_monitor_not_adopted')
        audit={'manager_id':state['manager_id'],'native_logtest':state['native_logtest']}
        # An uncertain create cannot be retried or adopted by name.
        self.record('monitor_create_pending',files=state['files'],candidate_sha256=sha(canonical(candidate)),**audit)
        response=client('POST',API,candidate,statuses=(200,201)); mid=response.get('_id','')
        need(re.fullmatch('[A-Za-z0-9_-]{1,128}',mid),'invalid_monitor_id')
        fetched=client('GET',API+'/'+mid); compare_monitor(fetched['monitor'],candidate,False,self.files[W+'indexer-native/deploy-monitor-b.py'])
        need(type(fetched.get('_seq_no')) is int and type(fetched.get('_primary_term')) is int,'monitor_revision_missing')
        self.record('monitor_enable_pending',files=state['files'],monitor_id=mid,candidate=candidate,**audit)
        enabled=copy.deepcopy(candidate); enabled['enabled']=True
        enabled['enabled_time']=int(time.time()*1000)
        client('PUT',API+'/'+mid+'?if_seq_no='+str(fetched['_seq_no'])+'&if_primary_term='+str(fetched['_primary_term']),enabled)
        fetched=client('GET',API+'/'+mid); compare_monitor(fetched['monitor'],candidate,True,self.files[W+'indexer-native/deploy-monitor-b.py'])
        self.record('monitor_verifying',files=state['files'],monitor_id=mid,candidate=candidate,security_agent_id=matches[0],actions=0,**audit)
        result=self.verify(phase='monitor_verifying')
        data=self.current();data['phase']='complete';self.save(data)
        return result

    def verify(self,phase='complete'):
        data=self.current(); need(data['phase']==phase,'pipeline_not_complete')
        for path,expected in data['files'].items():
            need(sha(read(path))==expected,'installed_file_changed')
        if self.role=='siem':
            manager=self.inspect('capstone-wazuh-manager')
            need(manager['Id']==data['manager_id'],'manager_recreation_requires_review')
            self.docker(['exec',manager['Id'],'/var/ossec/bin/wazuh-analysisd','-t'])
            client=Indexer(self.root,self.config['hosts']['SIEM_HOST'])
            need(exact_monitor_ids(client)==[data['monitor_id']],'managed_monitor_name_identity_changed')
            compare_monitor(client('GET',API+'/'+data['monitor_id'])['monitor'],data['candidate'],True,
                            self.files[W+'indexer-native/deploy-monitor-b.py'])
        else:
            for name in ('vector.toml','vector.env','raw-line-binding.json'):
                need(stat.S_IMODE((CFG/name).stat().st_mode)==0o600,'vector_native_file_mode_changed')
            for writer,cid in data['writers'].items():
                need(self.inspect('capstone-security-'+writer)['Id']==cid,'writer_recreation_requires_rebind')
            for reader in ('vector','wazuh'):
                run(['/bin/bash',str(RUNTIME/'guard.sh'),reader],timeout=120)
            for unit in ('capstone-vector.service','wazuh-agent',*TIMERS):
                run(['/usr/bin/systemctl','is-active','--quiet',unit])
                run(['/usr/bin/systemctl','is-enabled','--quiet',unit])
            grant=parse(read(RAW/'bootstrap-reader.json',private=True))
            need(grant.get('phase')=='sealed','initial_replay_not_sealed')
        return {'status':'verified','role':self.role,'source_sha256':self.fp['source_sha256'],
                'vector_version':'0.59.0','wazuh_version':'4.14.8','indexer_version':'2.19.6',
                'remote_event_ack_verified':False,'actual_attack_tested':False,'host_reboot_tested':False,
                'observation_actions':0,'history_transfer_installed':False}


def exact_monitor_ids(client):
    status,result=client('POST',API+'/_search',{'size':100,'track_total_hits':True,
        'query':{'match':{'monitor.name':MONITOR_NAME}}},statuses=(200,404),with_status=True)
    if status==404:
        error=result.get('error',{});need(isinstance(error,dict),'unexpected_monitor_search_404')
        causes=[error]+error.get('root_cause',[]);wrapped=error.get('caused_by',{})
        exact=(error.get('type')=='alerting_exception' and isinstance(wrapped,dict) and
               wrapped.get('type')=='exception' and wrapped.get('reason')=='org.opensearch.index.IndexNotFoundException: no such index [.opendistro-alerting-config]')
        need(exact or any(x.get('type')=='index_not_found_exception' and x.get('index')=='.opendistro-alerting-config' for x in causes),
             'unexpected_monitor_search_404')
        return []
    need(result.get('timed_out') is False,'monitor_search_timed_out')
    shards=result.get('_shards',{})
    need(type(shards.get('total')) is int and shards['total']>0 and shards.get('failed')==0 and
         shards.get('successful')==shards['total'],'monitor_search_partial')
    hits=result.get('hits',{});total=hits.get('total');rows=hits.get('hits')
    if isinstance(total,dict):
        need(total.get('relation')=='eq','monitor_search_inexact');total=total.get('value')
    need(type(total) is int and 0<=total<=100 and isinstance(rows,list) and len(rows)==total,'monitor_search_overflow')
    found=[]
    for row in rows:
        source=row.get('_source',{});source=source.get('monitor',source)
        if source.get('name')==MONITOR_NAME:
            mid=row.get('_id','');need(re.fullmatch('[A-Za-z0-9_-]{1,128}',mid),'monitor_id_invalid');found.append(mid)
    need(len(found)<=1,'duplicate_exact_monitor_names')
    return found


def compare_monitor(actual,candidate,enabled,validator_raw):
    """Reuse ONLY pure, reviewed native-query canonicalizers, not its CLI.

    OpenSearch expands bool/term defaults and scripts on readback. A bytewise
    JSON comparison would reject the unchanged stored monitor. All selected
    definitions and the v2 scripted metric adapter remain hash-bound sources.
    """
    import ast
    names={'keys_only','unboost','canonical_clause','canonical_search','validate_monitor'}
    tree=ast.parse(validator_raw)
    defs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    need(len(defs)==len(names),'monitor_validator_source_boundary')
    def v2_aggs(aggs):
        need(isinstance(aggs,dict) and set(aggs)=={'observation'},'unexpected_v2_aggregation')
        need(set(aggs['observation'])=={'scripted_metric'},'unexpected_v2_metric')
        metric=copy.deepcopy(aggs['observation']['scripted_metric'])
        scripts={'init_script','map_script','combine_script','reduce_script'}
        need(scripts<=set(metric)<=scripts|{'params'},'unexpected_v2_metric_fields')
        metric.setdefault('params',{})
        for name in scripts:
            script=metric[name]
            need(isinstance(script,dict) and set(script)<={'source','lang','params'} and isinstance(script.get('source'),str),'unexpected_v2_script')
            script.setdefault('lang','painless'); script.setdefault('params',{})
            need(script['lang']=='painless' and isinstance(script['params'],dict),'unexpected_v2_script_language')
        return {'observation':{'scripted_metric':metric}}
    namespace={'copy':copy,'require':need,'canonical_aggs':v2_aggs}
    exec(compile(ast.Module(body=defs,type_ignores=[]),'<reviewed-monitor-canonicalizers>','exec'),namespace)
    need(isinstance(actual,dict) and set(actual)<=set(candidate)|{'last_update_time','enabled_time','user','schema_version','ui_metadata'},'monitor_response_fields')
    namespace['validate_monitor'](actual,candidate,enabled)


def compare_container(actual, expected, image, compose, project):
    need(actual['Image']==expected['image'],'writer_image_changed')
    config=actual['Config']; defaults=image['Config']
    need(config.get('Cmd')==expected.get('command',defaults.get('Cmd')) and
         config.get('Entrypoint')==expected.get('entrypoint',defaults.get('Entrypoint')),'writer_command_changed')
    want={}
    for mount in expected.get('volumes',[]):
        if isinstance(mount,str):
            fields=mount.split(':'); need(len(fields) in (2,3),'invalid_compose_mount')
            source,target=fields[:2]; ro=len(fields)==3 and fields[2]=='ro'
            kind='bind' if source.startswith('/') else 'volume'
        else:
            source,target,kind=mount['source'],mount['target'],mount['type']; ro=mount.get('read_only',False)
        need(target not in want and kind in ('bind','volume'),'duplicate_or_unsupported_mount')
        if kind=='volume':
            spec=compose.get('volumes',{}).get(source,{})
            source=spec.get('name',project+'_'+source)
        want[target]=(kind,source,not ro)
    got={}
    for mount in actual.get('Mounts',[]):
        target=mount['Destination']; need(target not in got,'duplicate_live_mount')
        got[target]=(mount['Type'],mount['Source'] if mount['Type']=='bind' else mount.get('Name'),mount['RW'])
    need(got==want,'writer_mounts_changed')
    baseline={x.split('=',1)[0]:x.split('=',1)[1] for x in defaults.get('Env',[])}
    baseline.update(expected.get('environment',{}))
    live={x.split('=',1)[0]:x.split('=',1)[1] for x in config.get('Env',[])}
    need(live==baseline,'writer_environment_changed')


class Indexer:
    def __init__(self, role, host):
        self.base='https://'+str(ipaddress.IPv4Address(host))+':9200'
        cert=role/'tls'
        for name in ('root-ca.pem','admin.pem','admin-key.pem'):
            read(cert/name,65536)
        self.context=ssl.create_default_context(cafile=str(cert/'root-ca.pem'))
        self.context.load_cert_chain(str(cert/'admin.pem'),str(cert/'admin-key.pem'))
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
                         urllib.request.HTTPSHandler(context=self.context),NoRedirect())

    def __call__(self,method,path,body=None,statuses=(200,),with_status=False):
        need(method in ('GET','POST','PUT') and (path=='/' or path==API or path==API+'/_search' or
             re.fullmatch(re.escape(API)+r'/[A-Za-z0-9_-]{1,128}(?:\?if_seq_no=[0-9]+&if_primary_term=[0-9]+)?',path)), 'api_scope_rejected')
        req=urllib.request.Request(self.base+path,data=None if body is None else canonical(body),method=method,
                                   headers={'Content-Type':'application/json','Accept':'application/json'})
        try:
            with self.opener.open(req,timeout=35) as response:
                need(response.status in statuses,'indexer_http_status')
                status=response.status
                raw=response.read(2*1024*1024+1); need(len(raw)<=2*1024*1024,'indexer_response_limit')
        except urllib.error.HTTPError as e:
            need(e.code in statuses,'indexer_http_status')
            with e:
                status=e.code;raw=e.read(2*1024*1024+1)
                need(len(raw)<=2*1024*1024,'indexer_response_limit')
        except (urllib.error.URLError,TimeoutError) as e:
            raise Refused('indexer_request_failed_or_uncertain') from e
        value=parse(raw)
        return (status,value) if with_status else value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise Refused('indexer_redirect_forbidden')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('fingerprint','check','prepare','activate','monitor','verify','verify-base'))
    parser.add_argument('role',choices=('security','siem'),nargs='?',default='security')
    args=parser.parse_args()
    try:
        if args.operation=='fingerprint':
            source=Path(os.environ.get('CAPSTONE_SOURCE',Path(__file__).resolve().parents[1]))
            result=fingerprint(source_files(source,trusted=False))
        else:
            need(os.geteuid()==0 and os.uname().sysname=='Linux','root_linux_required')
            lock=operation_lock(args.role,args.operation in ('prepare','activate','monitor'))
            try:
                result=getattr(Bootstrap(args.role),args.operation.replace('-','_'))()
            finally:
                if lock is not None:os.close(lock)
        print(json.dumps(result,sort_keys=True))
    except Exception as e:
        print(json.dumps({'status':'refused','reason':str(e) if isinstance(e,Refused) else type(e).__name__},sort_keys=True))
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
