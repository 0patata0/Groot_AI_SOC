#!/usr/bin/env python3
"""One-shot synthetic native analysisd diagnostic; never a service or deployer.

Runs only on the fixed B host. All native binaries/rules are copied; no live
queue, agent DB, manager configuration or credentials enter the private root.
Only metadata is printed. Private native logs remain in the task directory.
"""
import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import stat
import struct
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

MACHINE = '1e143067c98a44ffba6eaa925dc038d7'
TASK = Path('/var/tmp/capstone-correlation-20261014')
DOCKER = '/usr/local/bin/docker'
LOCATION = '(groot-sec) any->/var/log/capstone-vector/canary/normalized.jsonl'
SCENARIOS = ('canary-repeat', 'canary-cross', 'canary-repeat-duplicate', 'canary-historical')


def require(value, code):
    if not value:
        raise RuntimeError(code)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native(args):
    return subprocess.run(args, check=True, capture_output=True, timeout=20).stdout


def identity(path):
    v = path.stat()
    return [v.st_dev, v.st_ino]


def proc_start(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


def production():
    v = json.loads(native([DOCKER, 'inspect', 'single-node-wazuh.manager-1']))[0]
    root = Path('/proc') / str(v['State']['Pid']) / 'root/var/ossec'
    pids = [int(row.split()[0]) for row in native([DOCKER, 'top', v['Id'], '-eo', 'pid,comm']).decode().splitlines()[1:]
            if len(row.split()) == 2 and row.split()[1] == 'wazuh-analysisd']
    require(len(pids) == 1, 'production_analysisd_identity')
    return root, {'cid': v['Id'], 'init_pid': v['State']['Pid'], 'started_at': v['State']['StartedAt'],
                  'analysisd_pid': pids[0], 'analysisd_start': proc_start(pids[0]),
                  'root': identity(root), 'queue': identity(root / 'queue/sockets/queue'),
                  'host_identity_files':{str(q):{'devino':identity(q),'sha256':digest(q),'uid':q.stat().st_uid,'gid':q.stat().st_gid,'mode':stat.S_IMODE(q.stat().st_mode)} for q in (Path('/etc/group'),Path('/etc/passwd'))},
                  'hashes': {p: digest(root/p) for p in ('bin/wazuh-analysisd', 'etc/ossec.conf',
                       'etc/rules/local_rules.xml', 'etc/rules/capstone_vector_rules.xml')}}


def protected_dir(path, create=False):
    if create:
        path.mkdir(mode=0o700)
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700,
            'private_directory_metadata')


def copy_tree(source, target):
    # Trusted installed assets only. Dereference into independent regular copies.
    if source.is_dir():
        shutil.copytree(source, target, symlinks=False)
        for p in target.rglob('*'):
            require(p.is_dir() or p.is_file(), 'unexpected_asset_type')
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o700 if source.name.startswith('wazuh-') else 0o600)


def prepare(prefix, original, profile):
    protected_dir(prefix, create=True)
    for rel in ('bin/wazuh-analysisd', 'lib/libwazuhext.so', 'ruleset/decoders', 'ruleset/rules',
                'etc/decoders', 'etc/rules', 'etc/lists', 'etc/internal_options.conf'):
        if (original/rel).exists():
            (prefix/rel).parent.mkdir(parents=True, exist_ok=True)
            copy_tree(original/rel, prefix/rel)
    for rel in ('logs/alerts', 'logs/archives', 'logs/firewall', 'stats', 'queue/fts',
                'queue/diff', 'queue/db', 'queue/alerts', 'queue/sockets', 'queue/rids',
                'var/run', 'var/multigroups', 'var/db', 'etc/shared', 'tmp'):
        (prefix/rel).mkdir(mode=0o700, parents=True, exist_ok=True)
    source_config = ET.fromstring('<root>' + (original/'etc/ossec.conf').read_text() + '</root>')
    rulesets = source_config.findall('ossec_config/ruleset')
    require(len(rulesets) == 1, 'single_ruleset_required')
    # All references must remain relative to the copied prefix.
    for node in rulesets[0]:
        value = (node.text or '').strip()
        if node.tag in ('decoder_dir', 'rule_dir', 'decoder_include', 'rule_include', 'list'):
            require(value and not value.startswith('/') and '..' not in Path(value).parts, 'unsafe_ruleset_reference')
    ruleset = ET.tostring(rulesets[0], encoding='unicode')
    config = ('<ossec_config><global><jsonout_output>yes</jsonout_output><alerts_log>no</alerts_log>'
              '<logall>no</logall><logall_json>yes</logall_json><email_notification>no</email_notification>'
              '</global><alerts><log_alert_level>3</log_alert_level></alerts>' + ruleset +
              '<rule_test><enabled>yes</enabled><threads>1</threads><max_sessions>128</max_sessions>'
              '<session_timeout>15m</session_timeout></rule_test></ossec_config>\n')
    (prefix/'etc/ossec.conf').write_text(config)
    local = (original/'etc/local_internal_options.conf').read_text() if (original/'etc/local_internal_options.conf').exists() else ''
    overrides = {'analysisd.debug': '0'}
    if profile in ('single', 'decode-single'):
        overrides['analysisd.event_threads'] = '1'
    if profile in ('single', 'rules-single'):
        overrides['analysisd.rule_matching_threads'] = '1'
    local = '\n'.join(line for line in local.splitlines() if line.strip().split('=', 1)[0] not in overrides)
    local += '\n' + '\n'.join(k+'='+v for k, v in overrides.items()) + '\n'
    (prefix/'etc/local_internal_options.conf').write_text(local)
    (prefix/'etc/passwd').write_text('root:x:0:0:root:/:/bin/false\nwazuh:x:59999:59999:isolated fixture:/:/bin/false\n')
    (prefix/'etc/group').write_text('root:x:0:\nwazuh:x:59999:\n')
    if Path('/etc/localtime').exists():
        shutil.copyfile('/etc/localtime', prefix/'etc/localtime')
    return {'config_sha256': digest(prefix/'etc/ossec.conf'), 'local_options_sha256': digest(prefix/'etc/local_internal_options.conf'),
            'binary_sha256': digest(prefix/'bin/wazuh-analysisd'), 'rules_sha256': digest(prefix/'etc/rules/capstone_vector_rules.xml')}


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (128*1024*1024, 128*1024*1024))
    resource.setrlimit(resource.RLIMIT_AS, (4*1024**3, 4*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (240, 240))


def launch(prefix, run_dir):
    script = ('set -eu; /usr/bin/mount --make-rprivate /; '
              'test "$(readlink /proc/self/ns/mnt)" != "$1"; '
              'test "$(readlink /proc/self/ns/net)" != "$2"; '
              '/usr/bin/mount --bind "$3/etc/group" /etc/group; /usr/bin/mount -o remount,bind,ro /etc/group; '
              '/usr/bin/mount --bind "$3/etc/passwd" /etc/passwd; /usr/bin/mount -o remount,bind,ro /etc/passwd; '
              'export LD_LIBRARY_PATH="$3/lib"; cd "$3"; '
              'exec "$3/bin/wazuh-analysisd" -f -u root -g root -D "$3" -c etc/ossec.conf')
    stderr = (run_dir/'native-stderr.log').open('wb')
    p = subprocess.Popen(['/usr/bin/unshare', '--mount', '--net', '/bin/bash', '-c', script, 'analysisd-isolated',
                          os.readlink('/proc/self/ns/mnt'), os.readlink('/proc/self/ns/net'), str(prefix)],
                         cwd=prefix, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'KST-9'},
                         stdin=subprocess.DEVNULL, stdout=stderr, stderr=stderr,
                         start_new_session=True, preexec_fn=limits)
    stderr.close()
    return p, proc_start(p.pid)


def stop(p, start):
    # Only this direct child; unreaped Popen owns PID until wait, preventing reuse.
    if p.poll() is None:
        require(proc_start(p.pid) == start, 'child_identity_changed')
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            require(proc_start(p.pid) == start, 'child_identity_changed')
            p.kill()
            p.wait(timeout=5)
    require(not Path(f'/proc/{p.pid}').exists(), 'child_cleanup_unverified')


def wait_ready(p, prefix, production_pid):
    end = time.monotonic()+40
    while time.monotonic() < end:
        require(p.poll() is None, 'native_startup_exited')
        if ((prefix/'queue/sockets/logtest').is_socket() and (prefix/'queue/sockets/queue').is_socket()
                and (prefix/'var/run/wazuh-analysisd.state').is_file()):
            require(identity(Path(f'/proc/{p.pid}/root')) == identity(prefix), 'native_root_not_private')
            require(identity(Path(f'/proc/{p.pid}/cwd')) == identity(prefix), 'native_cwd_not_private')
            fd_inventory = [{'fd':fd.name,'target':os.readlink(fd),'devino':identity(fd),'mode':fd.stat().st_mode,'rdev':fd.stat().st_rdev,
                             'flags':[line.split(':',1)[1].strip() for line in (Path(f'/proc/{p.pid}/fdinfo')/fd.name).read_text().splitlines() if line.startswith('flags:')]}
                            for fd in Path(f'/proc/{p.pid}/fd').iterdir()]
            (prefix.parent/'fd-inventory.json').write_text(json.dumps(fd_inventory,indent=2)+'\n')
            targets = [row['target'] for row in fd_inventory]
            for row in fd_inventory:
                target=row['target']
                known = target == '/dev/null' or target.startswith(str(prefix.parent)+'/') or target.startswith(('socket:', 'anon_inode:', 'pipe:'))
                random_read = (target == '/dev/urandom' and stat.S_ISCHR(row['mode']) and row['rdev']==Path('/dev/urandom').stat().st_rdev
                               and len(row['flags'])==1 and int(row['flags'][0],8)&os.O_ACCMODE==os.O_RDONLY)
                require(known or random_read,'unexpected_native_fd')
            production_sockets=set()
            for fd in Path(f'/proc/{production_pid}/fd').iterdir():
                try:
                    v=fd.stat()
                except FileNotFoundError:
                    continue
                if stat.S_ISSOCK(v.st_mode):
                    production_sockets.add(v.st_ino)
            require(not production_sockets.intersection(row['devino'][1] for row in fd_inventory if stat.S_ISSOCK(row['mode'])),'production_socket_shared')
            require(os.readlink(f'/proc/{p.pid}/ns/mnt') != os.readlink('/proc/self/ns/mnt') and os.readlink(f'/proc/{p.pid}/ns/net') != os.readlink('/proc/self/ns/net'), 'native_namespaces_not_private')
            return {'pid': p.pid, 'open_file_paths_private_or_device_allowlist':True, 'production_socket_inodes_disjoint':True, 'start_ticks': proc_start(p.pid),
                    'threads': len(list(Path(f'/proc/{p.pid}/task').iterdir())),
                    'root_private': True, 'mount_namespace_private': os.readlink(f'/proc/{p.pid}/ns/mnt') != os.readlink('/proc/self/ns/mnt'),
                    'network_namespace_private': os.readlink(f'/proc/{p.pid}/ns/net') != os.readlink('/proc/self/ns/net')}
        time.sleep(.1)
    raise RuntimeError('native_ready_timeout')


def fixtures(source, run_id, identities, order):
    records = []
    stamp = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat()
    for scenario in SCENARIOS:
        rows = [json.loads(x) for x in (source/(scenario+'.jsonl')).read_text().splitlines()]
        if scenario == 'canary-cross' and order == 'reverse':
            rows.reverse()
        for seq, row in enumerate(rows):
            row['capstone_validation'].update(run_id=run_id, scenario=scenario, delivery_seq=len(records)+1)
            norm = row['capstone_norm']
            norm['correlation_key'] = hashlib.sha256((run_id+':'+scenario).encode()).hexdigest()
            norm['observed_at_kst'] = stamp
            if norm['correlation_time_class'] == 'fresh':
                norm['event_time_kst'] = stamp
            if identities == 'fresh':
                logical = 0 if scenario == 'canary-repeat-duplicate' else seq
                eid = hashlib.sha256(f'{run_id}:{scenario}:{norm["source"]}:{logical}'.encode()).hexdigest()
                norm['event_id'] = eid
                norm['correlation_dedupe_key'] = eid
            records.append(row)
    require(len(records) == 13, 'fixture_count')
    return records


def request(sockpath, body):
    wire = json.dumps(body, separators=(',', ':')).encode()
    def read_n(sock, n):
        data = b''
        while len(data) < n:
            piece = sock.recv(n-len(data))
            require(piece, 'logtest_early_eof')
            data += piece
        return data
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(sockpath))
        sock.sendall(struct.pack('<I', len(wire))+wire)
        size = struct.unpack('<I', read_n(sock, 4))[0]
        require(0 < size <= 1024*1024, 'logtest_response_bound')
        response = json.loads(read_n(sock, size))
    require(response.get('error') == 0 and response.get('data', {}).get('codemsg', -1) >= 0, 'logtest_response_rejected')
    return response['data']


def logtest(prefix, rows, agent):
    token = None
    ids = []
    try:
        for row in rows:
            params = {'event': json.dumps(row, separators=(',', ':')), 'log_format': 'syslog', 'location': f'[{agent}] '+LOCATION}
            if token:
                params['token'] = token
            response = request(prefix/'queue/sockets/logtest', {'command': 'log_processing', 'parameters': params})
            token = response['token']
            out = response.get('output', {})
            ids.append(str(out.get('rule', {}).get('id', '')))
        return ids
    finally:
        if token:
            request(prefix/'queue/sockets/logtest', {'command': 'remove_session', 'parameters': {'token': token}})


def json_rows(path):
    if not path.exists():
        return []
    require(path.stat().st_size < 64*1024*1024, 'native_log_bound')
    data = path.read_bytes()
    return [json.loads(x) for x in data.split(b'\n')[:-1] if x]


def case(prefix, run_dir, source, identities, order, pacing, number, agent='000', use_logtest=True):
    run_id = uuid.uuid4().hex
    rows = fixtures(source, run_id, identities, order)
    expected = ['100291']*4+['100293']+(['100292','100291'] if order == 'reverse' else ['100291','100294'])+['100291']*5+['']
    ids = None
    if use_logtest:
        ids = logtest(prefix, rows, agent)
        (run_dir/f'case-{number}-logtest.json').write_text(json.dumps({'run_id':run_id,'actual':ids,'expected':expected})+'\n')
        require(ids == expected, 'exact_logtest_rule_assertion')
    wire_rows = [(f'1:[{agent}] '+LOCATION+':'+json.dumps(row, separators=(',', ':'))).encode()+b'\0' for row in rows]
    require(all(len(x) < 6000 for x in wire_rows), 'synthetic_datagram_bound')
    receipt = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect(str(prefix/'queue/sockets/queue'))
        for seq, wire in enumerate(wire_rows, 1):
            if pacing == 'cross-gap' and seq == 7:
                time.sleep(3)
            if pacing == 'each' and seq > 1:
                time.sleep(.1)
            require(sock.send(wire) == len(wire), 'datagram_send_incomplete')
            receipt.append({'delivery_seq': seq, 'bytes': len(wire), 'sha256': hashlib.sha256(wire).hexdigest(), 'sent_monotonic_ns': time.monotonic_ns()})
    (run_dir/f'case-{number}-send-receipts.json').write_text(json.dumps(receipt, indent=2)+'\n')
    deadline = time.monotonic()+12
    archived = []
    while time.monotonic() < deadline:
        archived = [x for x in json_rows(prefix/'logs/archives/archives.json') if x.get('data', {}).get('capstone_validation', {}).get('run_id') == run_id]
        if len(archived) >= 13:
            break
        time.sleep(.1)
    require(len(archived) == 13, 'archive_exact_count')
    delivery = [int(x['data']['capstone_validation']['delivery_seq']) for x in archived]
    require(sorted(delivery) == list(range(1,14)), 'archive_exact_identities')
    require(all(x.get('agent',{}).get('id')==agent and x.get('location') in (LOCATION, LOCATION.split('->',1)[1]) for x in archived),'archive_agent_location_identity')
    for event in archived:
        seq = int(event['data']['capstone_validation']['delivery_seq'])
        require(event['full_log'] == json.dumps(rows[seq-1], separators=(',', ':')), 'archive_full_payload_identity')
    archive_leaf_counts = dict(collections.Counter(str(x.get('rule', {}).get('id','')) for x in archived
                                                  if str(x.get('rule', {}).get('id','')) in ('100293','100294')))
    alert_wait_started = time.monotonic()
    deadline = alert_wait_started + 10
    counts = {}
    while time.monotonic() < deadline:
        alerts = [x for x in json_rows(prefix/'logs/alerts/alerts.json') if x.get('data', {}).get('capstone_validation', {}).get('run_id') == run_id]
        counts = dict(collections.Counter(str(x['rule']['id']) for x in alerts))
        require(set(counts) <= {'100293', '100294'}, 'unexpected_private_alert_rule')
        if counts == archive_leaf_counts:
            break
        time.sleep(.1)
    expected_counts = {'100293': 1} if order == 'reverse' else {'100293':1, '100294':1}
    return {'run_id':run_id, 'profile_number':number, 'identities':identities, 'order':order, 'pacing':pacing,
            'agent_id':agent, 'input_rows':13, 'sent_rows':len(receipt), 'archive_rows':len(archived),
            'archive_delivery_order':delivery, 'archive_exact_payloads':True, 'logtest_executed':use_logtest, 'logtest_rule_ids':ids,
            'archive_rule_ids':[str(x.get('rule', {}).get('id','')) for x in archived],
            'archive_leaf_delivery_sequences':[{'rule_id':str(x.get('rule',{}).get('id','')),'delivery_seq':int(x['data']['capstone_validation']['delivery_seq'])} for x in archived if str(x.get('rule',{}).get('id','')) in ('100293','100294')],
            'archive_leaf_counts':archive_leaf_counts, 'alert_rule_counts':counts, 'alert_writer_drained':counts == archive_leaf_counts,
            'alert_writer_wait_seconds':round(time.monotonic()-alert_wait_started,3),
            'expected_alert_rule_counts':expected_counts, 'analysis_matches_sequential_expectation': archive_leaf_counts == expected_counts,
            'alerts_match_sequential_expectation': counts == expected_counts,
            'socket_send_is_analysis_ack':False, 'archive_order_is_receive_order':False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('smoke', 'matrix', 'native-only'), required=True)
    args = parser.parse_args()
    require(os.geteuid()==0 and Path('/etc/machine-id').read_text().strip()==MACHINE, 'wrong_host_or_user')
    protected_dir(TASK)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    original, before = production()
    source = Path(__file__).resolve().parent.parent/'fixtures/correlation'
    require(source.is_dir(), 'fixture_source_missing')
    trial = TASK/('analysisd-'+uuid.uuid4().hex[:10])
    protected_dir(trial, create=True)
    source_bytes=Path(__file__).read_bytes()
    (trial/'runner-source.py').write_bytes(source_bytes)
    source_sha=hashlib.sha256(source_bytes).hexdigest()
    (trial/'source.sha256').write_text(source_sha+'\n')
    result = {'kind':'private_native_analysisd_correlation_diagnosis', 'mode':args.mode,
              'production_before':before, 'arms':[], 'operational_input_written':False, 'native_children_cleaned':False,
              'agent000_is_not_agent001_transport_equivalence':True, 'fixture_directory':str(trial)}
    error = None
    try:
        profiles = ('auto',) if args.mode=='smoke' else (('auto','single') if args.mode=='native-only' else ('auto','decode-single','rules-single','single'))
        for profile in profiles:
            arm = trial/profile
            protected_dir(arm, create=True)
            prefix = arm/'root'
            hashes = prepare(prefix, original, profile)
            p = None
            try:
                result['native_children_cleaned'] = False
                p, start = launch(prefix, arm)
                runtime = wait_ready(p,prefix,before['analysisd_pid'])
                result['native_children_cleaned'] = False
                cases=[]
                result['arms'].append({'profile':profile,'hashes':hashes,'runtime':runtime,'cases':cases})
                matrix = [('reused','forward','cross-gap')] if args.mode=='smoke' else [
                    (identities,order,pacing) for identities in ('reused','fresh')
                    for order in ('forward','reverse') for pacing in ('burst','cross-gap','each')]
                if args.mode=='native-only':
                    matrix=[(identities,'forward','burst') for identities in ('reused','fresh') for _ in range(10)]
                for n,(identities,order,pacing) in enumerate(matrix):
                    result['current_case']={'profile':profile,'number':n,'identities':identities,'order':order,'pacing':pacing}
                    (trial/'partial-result.json').write_text(json.dumps(result,indent=2)+'\n')
                    cases.append(case(prefix, arm, source, identities, order, pacing, n, use_logtest=args.mode!='native-only'))
                    (trial/'partial-result.json').write_text(json.dumps(result,indent=2)+'\n')
                    done=cases[-1]
                    print(json.dumps({'kind':'case_progress','profile':profile,'case':n,'identities':identities,'order':order,'pacing':pacing,
                          'archive_leaf_counts':done['archive_leaf_counts'],'alert_rule_counts':done['alert_rule_counts'],
                          'writer_drained':done['alert_writer_drained'],'expected_match':done['analysis_matches_sequential_expectation']}),flush=True)
                    require(p.poll() is None,'native_process_exited')
            finally:
                if p:
                    stop(p,start)
                result['native_children_cleaned'] = True
    except Exception as exc:
        error = str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
        result['error'] = error
        result['private_diagnostics'] = {}
        for candidate in trial.glob('*/native-stderr.log'):
            result['private_diagnostics'][str(candidate.relative_to(trial))] = candidate.read_text(errors='replace').splitlines()[-20:]
        for candidate in trial.glob('*/root/logs/ossec.log'):
            result['private_diagnostics'][str(candidate.relative_to(trial))] = candidate.read_text(errors='replace').splitlines()[-20:]
        for candidate in trial.glob('*/case-*-logtest.json'):
            result['private_diagnostics'][str(candidate.relative_to(trial))] = json.loads(candidate.read_text())
        for candidate in trial.glob('*/fd-inventory.json'):
            result['private_diagnostics'][str(candidate.relative_to(trial))] = json.loads(candidate.read_text())
    finally:
        _, after = production()
        result['production_unchanged'] = before == after
        result['checked_at_kst'] = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat()
        result['source_sha256'] = source_sha
        result['result_path'] = str(trial/'result.json')
        (trial/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
    require(before == after,'production_identity_changed')
    require(not error,'isolated_trial_failed')


if __name__ == '__main__':
    main()
