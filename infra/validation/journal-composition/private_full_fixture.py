"""Build a bounded, owned-root input from live SHA metadata and pinned code.

Operating source bytes are copied only on the same server into the disposable
test input. Operating configuration, keys, chat databases and journals are not
copied. The cache, consumers, initial provenance and approval are test fixtures.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

HERE = Path(__file__).resolve().parent
KST = timezone(timedelta(hours=9))
GROUP = 50123
MCP = 50124


def load(name):
    spec = importlib.util.spec_from_file_location('full_fixture_' + name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(root, target, data, mode=0o600):
    path = root / target.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    need(not path.is_symlink() and (not path.exists() or path.is_file()), 'fixture_file_collision')
    path.write_bytes(data)
    path.chmod(mode)
    return path


def baseline(role, target, inputs):
    observed = inputs['live_metadata'][role][target]
    if not observed['exists']:
        return None
    known = inputs['known_before'][role].get(target)
    if known is not None:
        raw = base64.b64decode(known, validate=True)
    else:
        # The input contract restricts this fallback to B's exact source set.
        files = load('release_files.py')
        need(role == 'b' and target in files.TARGETS['b'], 'no_unlisted_operating_source_read')
        path = Path(target)
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 2 * 1024 * 1024,
             'unsafe_operating_source')
        raw = path.read_bytes()
        after = path.lstat()
        fields = lambda item: (item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        need(fields(before) == fields(after), 'operating_source_changed_during_read')
    need(digest(raw) == observed['sha256'], 'operating_source_metadata_changed')
    return raw


def receipt_after(raw, target, before, after, changes):
    value = json.loads(raw)
    # These are integrity/provenance records, not runtime credential files.
    def no_credentials(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if re.search(r'(?i)(?:^|_)(?:password|passwd|token|secret|private_key|api_key)(?:$|_)', str(key)):
                    # A typed attestation (for example, no private-key export)
                    # contains no credential material. Strings/collections under
                    # credential-shaped keys remain forbidden at every depth.
                    need(child is None or type(child) is bool, 'credential_field_in_source_receipt')
                no_credentials(child)
        elif isinstance(item, list):
            for child in item:
                no_credentials(child)
    no_credentials(value)
    field = 'sources' if 'ollama' in target else 'files'
    need(isinstance(value[field], dict), 'integrity_receipt_shape')
    prefix = '/opt/capstone-ollama-trial/' if field == 'sources' else '/opt/capstone-review-chat/'
    for name, payload in after.items():
        if not name.startswith(prefix):
            continue
        key = Path(name).name if field == 'sources' else name
        if key not in value[field]:
            continue
        original = value[field][key]
        need(isinstance(original,str) and re.fullmatch('[0-9a-f]{64}',original), 'integrity_receipt_digest')
        actual = digest(before[name])
        replacement = digest(payload)
        changes.append({'receipt':target,'entry':key,'previous_receipt_sha256':original,
                        'observed_source_sha256':actual,'after_sha256':replacement,
                        'preexisting_receipt_drift':original != actual})
        value[field][key] = replacement
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def cache(root, role):
    path = root / 'var/lib/capstone-diagnostics/journal-history.sqlite3'
    path.parent.mkdir(parents=True, exist_ok=True)
    need(not path.exists(), 'fixture_cache_collision')
    db = sqlite3.connect(path)
    try:
        db.executescript('''CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE events(id TEXT PRIMARY KEY,at_us INTEGER NOT NULL,unit TEXT NOT NULL,error TEXT NOT NULL);
            CREATE INDEX event_window ON events(unit,at_us,id);
            CREATE TABLE windows(since_us INTEGER NOT NULL,until_us INTEGER NOT NULL,truncated INTEGER NOT NULL,
                PRIMARY KEY(since_us,until_us));''')
        now = int(datetime.now(KST).timestamp() * 1000000)
        db.executemany('INSERT INTO metadata VALUES(?,?)', [('schema','1'),('host',role),
            ('observed_at_us',str(now)),('retained_since_us',str(now-3600*1000000))])
        db.execute('INSERT INTO events VALUES(?,?,?,?)', (digest(('fixture-'+role).encode()),now-1000000,
            'capstone-owned-fixture.service','{"kind":"journal_error"}'))
        db.execute('INSERT INTO windows VALUES(?,?,?)',(now-3600*1000000,now,0))
        db.commit()
    finally:
        db.close()
    path.chmod(0o640)
    return path


def populate(root, role, source, output, pinmap, inputs, release_id, backend):
    backend.populate(root, role, source, output, pinmap)
    for name in ('coordinator-manifest.json','witness-manifest.json'):
        put(root,'/opt/pid1-proof/code/'+name,(source/name).read_bytes())
    probe_unit = root / 'etc/systemd/system/capstone-proof.service'
    probe_text = probe_unit.read_text()
    need(probe_text.count('TimeoutStartSec=30s') == 1, 'test_probe_timeout_shape')
    probe_unit.write_text(probe_text.replace('TimeoutStartSec=30s', 'TimeoutStartSec=250s'))
    manager=root/'etc/systemd/system.conf'
    manager_text=manager.read_text()
    need('DefaultStandardOutput=null\nDefaultStandardError=null\n' in manager_text,
         'private_manager_logging_shape')
    manager.write_text(manager_text.replace('DefaultStandardOutput=null\nDefaultStandardError=null\n',
                                           'DefaultStandardOutput=journal\nDefaultStandardError=journal\n'))
    # A real journal daemon owns only this root's fresh /run/log and sockets.
    # The foundation's masks and all operating journal mounts stay untouched.
    put(root,'/etc/systemd/journald.conf',
        b'[Journal]\nStorage=volatile\nRuntimeMaxUse=4M\nRuntimeMaxFileSize=1M\nForwardToKMsg=no\nForwardToConsole=no\n',0o644)
    put(root,'/etc/systemd/system/capstone-private-journal.service',
        b'[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\n'
        b'ExecStart=/usr/lib/systemd/systemd-journald\nKillMode=control-group\n'
        b'MemoryMax=64M\nTasksMax=16\nTimeoutStopSec=5s\n'
        b'StandardOutput=file:/proof/journal-daemon.stdout\n'
        b'StandardError=file:/proof/journal-daemon.stderr\n',0o644)
    # A real, root-only system bus in this disposable root. Manager.RefUnit
    # tracks a live bus sender; a private manager socket alone cannot supply it.
    put(root,'/etc/dbus-1/capstone-private.conf',
        b'<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" '
        b'"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
        b'<busconfig><type>system</type><listen>systemd:</listen><auth>EXTERNAL</auth>'
        b'<policy user="root"><allow own="*"/><allow send_destination="*"/>'
        b'<allow receive_sender="*"/></policy></busconfig>\n',0o644)
    put(root,'/etc/systemd/system/dbus.socket',
        b'[Unit]\nDefaultDependencies=no\nBefore=dbus.service\n'
        b'[Socket]\nListenStream=/run/dbus/system_bus_socket\nSocketMode=0600\n'
        b'DirectoryMode=0755\nService=dbus.service\n',0o644)
    put(root,'/etc/systemd/system/dbus.service',
        b'[Unit]\nDefaultDependencies=no\nRequires=dbus.socket\nAfter=dbus.socket\n'
        b'[Service]\nType=simple\n'
        b'ExecStart=/usr/bin/dbus-daemon --nofork --nopidfile --systemd-activation '
        b'--config-file=/etc/dbus-1/capstone-private.conf --address=systemd:\n'
        b'MemoryMax=32M\nTasksMax=8\nTimeoutStartSec=10s\nTimeoutStopSec=5s\n'
        b'StandardOutput=file:/proof/dbus.stdout\nStandardError=file:/proof/dbus.stderr\n',0o644)
    for suffix,condition in (('executed',b''),('skipped',b'ConditionPathExists=/run/capstone-reference-missing\n')):
        put(root,'/etc/systemd/system/capstone-reference-'+suffix+'.service',
            b'[Unit]\nDefaultDependencies=no\n'+condition+
            b'[Service]\nType=oneshot\nExecStart=/usr/bin/true\n'
            b'PrivateNetwork=yes\nNoNewPrivileges=yes\nMemoryMax=16M\nTasksMax=4\nTimeoutStartSec=5s\n',0o644)
    files = load('release_files.py')
    plans = load('release_plan.py')
    readers = load('release_reader.py')
    launcher = load('release_mcp_launcher.py')
    before = {target:baseline(role,target,inputs) for target in files.TARGETS[role]}
    after = {target:base64.b64decode(raw,validate=True) for target,raw in inputs['after'][role].items()}
    changes = []
    if role == 'b':
        for target in ('/etc/capstone-ollama-trial/receipt.json','/etc/capstone-review-chat/receipt.json'):
            after[target] = receipt_after(before[target],target,before,after,changes)
    rows = []
    for target in sorted(files.TARGETS[role] - files.BARRIERS[role]):
        observed = inputs['live_metadata'][role][target]
        rows.append({'target':target,'before_sha256':digest(before[target]) if before[target] is not None else None,
                     'after_sha256':digest(after[target]),'uid':observed.get('uid',0),
                     'gid':observed.get('gid',0),'mode':observed.get('mode',0o644)})
    contract = files.contract.source_contract(role,release_id,rows)
    after[files.READER] = readers.build(before[files.READER],digest(before[files.READER]),
        host=role,release_id=release_id,source_contract_sha256=contract)
    rows.append({'target':files.READER,'before_sha256':digest(before[files.READER]),
                 'after_sha256':digest(after[files.READER]),'uid':0,'gid':GROUP,'mode':0o550})
    if role == 'b':
        after[files.MCP_LAUNCHER] = launcher.build(before[files.MCP_LAUNCHER],digest(before[files.MCP_LAUNCHER]))
        observed = inputs['live_metadata'][role][files.MCP_LAUNCHER]
        rows.append({'target':files.MCP_LAUNCHER,'before_sha256':digest(before[files.MCP_LAUNCHER]),
                     'after_sha256':digest(after[files.MCP_LAUNCHER]),'uid':0,'gid':MCP,'mode':0o750})
    need(set(before) == set(after) == files.TARGETS[role], 'full_source_footprint')
    for target, raw in before.items():
        path = root / target.lstrip('/')
        if raw is None:
            path.unlink(missing_ok=True)
        else:
            row = next(row for row in rows if row['target'] == target)
            put(root,target,raw,row['mode'])
    # Unchanged collector dependencies and original shell launcher, from Git
    # bytes matching the fresh live metadata. No operating config is imported.
    dependency_owners = {}
    diagnostic_gid = inputs['live_metadata'][role][files.READER]['gid']
    need(type(diagnostic_gid) is int and 0 < diagnostic_gid < 65534, 'observed_diagnostic_group_required')
    for target in ('/opt/capstone-diagnostics/runtime_health.py','/opt/capstone-diagnostics/host_inventory.py',
                   '/opt/capstone-diagnostics/read-snapshot','/etc/systemd/system/capstone-journal-reader.service',
                   '/etc/systemd/system/capstone-system-diagnostics.timer'):
        observed = inputs['live_metadata'][role][target]
        need(observed['uid'] == 0, 'collector_dependency_root_owner')
        put(root,target,baseline(role,target,inputs),observed['mode'])
        dependency_owners[target.lstrip('/')] = {'uid':0,
            'gid':GROUP if observed['gid'] == diagnostic_gid else observed['gid']}
    config_path = root / 'etc/ssh/sshd_config'
    config = config_path.read_text()
    need(config.count('ForceCommand /usr/bin/python3 -IB /opt/pid1-proof/ssh_reply.py') == 1, 'forced_reader_fixture_shape')
    config_path.write_text(config.replace('ForceCommand /usr/bin/python3 -IB /opt/pid1-proof/ssh_reply.py',
                                         'ForceCommand /opt/capstone-diagnostics/read-snapshot'))
    # Native consumer names stay exact. Tests use idle oneshots and two chat
    # sleepers rather than starting operating agents or sending chat messages.
    services = load('release_services.py')
    for name in services.catalog(role)['consumer_services']:
        content = ('[Unit]\nDefaultDependencies=no\n[Service]\nKillMode=control-group\nTimeoutStopSec=5s\n')
        if name in ('capstone-ollama-chat.service','capstone-review-chat.service'):
            content += 'Type=simple\nExecStart=/usr/bin/sleep infinity\n'
        else:
            content += 'Type=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n'
        put(root,'/etc/systemd/system/'+name,content.encode(),0o644)
    cache_path = cache(root,role)
    desired = {**dependency_owners,
               **{str(path.relative_to(root)):{'uid':0,'gid':GROUP} for path in [cache_path]}}
    if role in ('a','b'):
        if role == 'a':
            directory = '/etc/capstone-diagnostics/'
            private = directory+'observer_ed25519'
            known = directory+'observer_known_hosts'
            route = directory+'monitor.json'
            mode = 0o600
        else:
            private = '/etc/mcp/system-diagnostics/id_ed25519'
            known = '/etc/mcp/system-diagnostics/known_hosts'
            route = '/etc/mcp/system-diagnostics.json'
            mode = 0o640
        put(root,private,(root/'etc/ssh/client_ed25519').read_bytes(),mode)
        put(root,known,(root/'etc/ssh/known_hosts').read_bytes(),mode)
        put(root,route,json.dumps({'schema':1,'hosts':{h:backend.ADDRESSES[h]for h in 'abc'if h!=role},
                                   'ssh_port':44222},sort_keys=True).encode(),mode)
        if role == 'b':
            for target in (private,known,route):
                desired[target.lstrip('/')] = {'uid':0,'gid':MCP}
    for target in plans.PROTECTED[role]:
        path = root / target.lstrip('/')
        if path.exists():
            continue
        if plans.optional_protected(role,target):
            continue
        payload = b'{"schema":1,"origin":"owned-native-fixture-only"}\n' if target.endswith('.json') else b'owned fixture only\n'
        put(root,target,payload,0o600)
    if role == 'b' and not (root / plans.ACTIVE_PROTECTED.lstrip('/')).exists():
        put(root,plans.OPTIONAL_PROTECTED,b'{"schema":1,"origin":"owned-native-fixture-prepared-only"}\n',0o600)
    storage = '/var/lib/capstone-journal-release/'+release_id+'/'+role
    for directory in (storage,storage+'/candidates',storage+'/backups',storage+'/cache',
                      '/var/lib/capstone-journal-release'):
        path = root / directory.lstrip('/')
        path.mkdir(parents=True,exist_ok=True);path.chmod(0o700)
    (root/'var/lib/capstone-journal-release'/release_id).chmod(0o700)
    for name in plans.HELPERS:
        put(root,storage+'/'+name,(source/name).read_bytes(),0o600)
    for raw in after.values():
        put(root,storage+'/candidates/'+digest(raw)+'.data',raw,0o600)
    if role == 'b':
        for name in ('/var/lib/capstone-review-chat/queue.sqlite','/var/lib/capstone-ollama-trial/chat/queue.sqlite'):
            path = root / name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True)
            db = sqlite3.connect(path);db.execute('CREATE TABLE jobs(status TEXT)');db.commit();db.close();path.chmod(0o640)
        path = root/'opt/hermes-data/state.db';db=sqlite3.connect(path)
        db.execute('CREATE TABLE session_turn_leases(expires_at REAL)');db.commit();db.close();path.chmod(0o600)
        put(root,'/opt/hermes-data/gateway_state.json',json.dumps({'active_agents':0,'active_work':[],
            'updated_at':datetime.now(KST).isoformat()}).encode(),0o600)
    # All helper ReadWritePaths must exist before systemd adds its sandbox.
    for path in ['/var/lib/capstone-diagnostics','/opt/capstone-diagnostics','/etc/systemd/system'] + (
        ['/opt/capstone-management','/opt/capstone-ollama-trial','/opt/capstone-review-chat',
         '/opt/hermes-data/management-code','/opt/hermes-data/plugins/groot-query-completion',
         '/opt/mcp','/etc/capstone-ollama-trial','/etc/capstone-review-chat','/etc/mcp/system-diagnostics'] if role=='b' else []):
        (root/path.lstrip('/')).mkdir(parents=True,exist_ok=True)
    for row in rows:
        desired[row['target'].lstrip('/')]={'uid':row['uid'],'gid':row['gid']}
    ready = {'schema':1,'host':role,'release_id':release_id,'rows':sorted(rows,key=lambda row:row['target']),
             'diagnostic_gid':GROUP,'reader_uid':GROUP,'mcp_uid':MCP if role=='b'else None,
             'machine_sha256':digest((root/'etc/machine-id').read_bytes()),
             'previous_current_sha256':None,'receipt_changes':changes,
             'cache_origin':'synthetic fixed-schema native integration input; not operating A/B/C records'}
    protected = {}
    for target in plans.PROTECTED[role]:
        path = root/target.lstrip('/')
        if not path.exists():
            protected[target]=None
        else:
            item=path.stat();owner=desired.get(target.lstrip('/'),{'uid':item.st_uid,'gid':item.st_gid})
            protected[target]={'sha256':digest(path.read_bytes()),**owner,'mode':stat.S_IMODE(item.st_mode)}
    ready['protected']=protected
    (output/'node-input.json').write_text(json.dumps(ready,sort_keys=True))
    # Capture only the pre-mount private file layout. The child mounts its own
    # user-namespace-owned tmpfs and can preserve the real source UID/GID.
    layout=[]
    for path in sorted(root.rglob('*'),key=lambda path:(len(path.relative_to(root).parts),str(path))):
        relative=path.relative_to(root).as_posix();item=path.lstat()
        if path.is_symlink():
            layout.append({'path':relative,'kind':'link','target':os.readlink(path)})
        elif path.is_dir():
            layout.append({'path':relative,'kind':'directory','mode':stat.S_IMODE(item.st_mode)})
        else:
            need(stat.S_ISREG(item.st_mode) and item.st_nlink==1,'private_layout_regular_files_only')
            owner=desired.get(relative,{'uid':item.st_uid,'gid':item.st_gid})
            layout.append({'path':relative,'kind':'file','mode':stat.S_IMODE(item.st_mode),
                           'sha256':digest(path.read_bytes()),**owner})
    (output/'root-layout.json').write_text(json.dumps(layout,sort_keys=True))
