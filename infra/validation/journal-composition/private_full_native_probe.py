"""Per-role bounded controller for the fixed root entry in an owned PID1."""
import ast
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
import pwd
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import types

OUT=Path('/proof')
CODE=Path('/opt/pid1-proof/code')
ROLE=Path('/etc/capstone-proof-role').read_text().strip()
NODE=json.loads((OUT/'node-input.json').read_text())
RELEASE=NODE['release_id']
STORE=Path('/var/lib/capstone-journal-release')/RELEASE/ROLE
RUNTIME=STORE/'release_runtime.py'
KST=timezone(timedelta(hours=9))
ENV={'PATH':'/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin','LANG':'C','LC_ALL':'C',
     'PYTHONDONTWRITEBYTECODE':'1','SYSTEMD_PAGER':'','SYSTEMD_COLORS':'0'}


def need(value,reason):
    if not value:
        raise RuntimeError(reason)


def unprivileged_regressions():
    """Exercise the frozen profiles without the controller's root identity."""
    need(ROLE=='b' and Path('/proc/self/uid_map').read_text().split()==['0','0','65536'],
         'owned_regression_scope')
    manifest=json.loads((CODE/'coordinator-manifest.json').read_text())
    witness=json.loads((CODE/'witness-manifest.json').read_text())
    expected={**witness['source_sha256'],**manifest['dependencies_sha256'],**manifest['source_sha256']}
    root=Path(tempfile.mkdtemp(prefix='capstone-native-regressions-',dir='/tmp'))
    root.chmod(0o755)
    code=root/'code';code.mkdir(mode=0o755)
    work=root/'work';work.mkdir(mode=0o700);os.chown(work,50123,50123)
    process=None
    try:
        for name in (*expected,'coordinator-manifest.json','witness-manifest.json'):
            need(Path(name).name==name and not(CODE/name).is_symlink(),'regression_source_scope')
            raw=(CODE/name).read_bytes()
            if name in expected:
                need(hashlib.sha256(raw).hexdigest()==expected[name],'regression_source_changed')
            target=code/name;target.write_bytes(raw);target.chmod(0o444)
        code.chmod(0o555)
        script=code/'run_coordinator_regressions.py';output=work/'results'
        wrapper=('import json,os,runpy,sys; '
                 'assert os.getuid()==os.geteuid()==os.getgid()==os.getegid()==50123 and os.getgroups()==[]; '
                 'print(json.dumps({"uid":os.getuid(),"euid":os.geteuid(),"gid":os.getgid(),'
                 '"egid":os.getegid(),"supplementary_groups":os.getgroups()}),flush=True); '
                 'sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name="__main__")')
        process=subprocess.Popen(['/usr/bin/python3','-I','-B','-c',wrapper,str(script),
            '--output',str(output),'--jobs','2'],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(work),env=ENV,
            user=50123,group=50123,extra_groups=[],start_new_session=True)
        timed_out=False;started=time.monotonic()
        try:
            stdout,stderr=process.communicate(timeout=210)
        except subprocess.TimeoutExpired:
            timed_out=True
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            stdout,stderr=process.communicate(timeout=3)
        need(len(stdout)<=65536 and len(stderr)<=8192,'regression_output_bound')
        lines=stdout.decode().splitlines()
        identity=json.loads(lines[0]) if lines else None
        result=json.loads((output/'results.json').read_text()) if (output/'results.json').is_file() else None
        evidence={'returncode':process.returncode,'identity':identity,'timed_out':timed_out,
                  'elapsed_seconds':time.monotonic()-started,
                  'stdout':stdout.decode(),'stderr':stderr.decode(),'result':result}
        if timed_out or process.returncode!=0:
            evidence['profile_log_tails']={path.name:path.read_bytes()[-8192:].decode(errors='replace')
                                          for path in sorted(output.glob('*.log'))}
        report['linux_regression_evidence']=evidence
        save('regression-evidence.json',evidence)
        need(not timed_out,'unprivileged_linux_regression_deadline')
        need(process.returncode==0 and identity=={'uid':50123,'euid':50123,'gid':50123,'egid':50123,
             'supplementary_groups':[]} and isinstance(result,dict) and result.get('complete')is True
             and result.get('platform')=='linux' and result.get('tests')==sum(manifest['regressions'].values())
             and result.get('skipped')==0 and result.get('source_unchanged')is True,
             'unprivileged_linux_regressions_failed')
        return {'returncode':0,'identity':identity,'result':result,'isolated_network':True}
    finally:
        if process is not None and process.poll()is None:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=3)
        if process is not None:
            for stream in (process.stdout,process.stderr):stream.close()
        shutil.rmtree(root)


def save(name,value):
    destination=OUT/name
    temporary=OUT/(name+'.tmp')
    temporary.write_text(json.dumps(value,sort_keys=True))
    os.replace(temporary,destination)


class PrivateConsole:
    """Drain this root's real console without retaining unbounded boot output."""

    def __init__(self):
        self.master,self.slave=os.openpty()
        self.path=Path('/dev/console')
        need(not self.path.exists() and not self.path.is_symlink(),'owned_console_collision')
        self.path.symlink_to(os.ttyname(self.slave))
        self.tail=bytearray()
        self.pending=bytearray()
        self.failures=[]
        self.stop=threading.Event()
        self.worker=threading.Thread(target=self.drain,daemon=True)
        self.worker.start()

    def drain(self):
        while not self.stop.is_set():
            readable,_,_=select.select([self.master],[],[],.1)
            if readable:
                try:
                    raw=os.read(self.master,4096)
                except OSError:
                    break
                if not raw:
                    break
                self.tail.extend(raw)
                del self.tail[:-32768]
                self.pending.extend(raw)
                while b'\n' in self.pending:
                    line,_,remaining=self.pending.partition(b'\n')
                    self.pending=bytearray(remaining)
                    message=line.decode(errors='replace').strip()
                    if re.search(r'(?i)seccomp|syscall|system call|failed at step|failed to apply|failed to set up',message):
                        self.failures.append(message[:2048])
                        del self.failures[:-32]
                del self.pending[:-8192]

    def close(self):
        self.stop.set()
        self.worker.join(timeout=.3)
        need(not self.worker.is_alive(),'owned_console_reader_stop')
        for descriptor in (self.master,self.slave):
            os.close(descriptor)
        return self.snapshot()

    def snapshot(self):
        return {'tail':bytes(self.tail).decode(errors='replace'),
                'filter_setup_failures':list(self.failures)}


def load(name):
    spec=importlib.util.spec_from_file_location('full_probe_'+name[:-3],CODE/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def command(args,raw=None,timeout=30):
    result=subprocess.run(args,input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=ENV,timeout=timeout)
    need(len(result.stdout)<=131072 and len(result.stderr)<=8192,'native_entry_output_bound')
    value=json.loads(result.stdout) if result.stdout.strip() else None
    return {'returncode':result.returncode,'reply':value,'stderr':result.stderr.decode(errors='replace')[:2048]}


def collection_observation():
    need(ROLE in ('a','b','c')and Path('/proc/self/uid_map').read_text().split()==['0','0','65536'],
         'owned_collection_observation_scope')
    fields=('Id','LoadState','ActiveState','SubState','FragmentPath','DropInPaths','Result','ConditionResult',
            'ExecMainStartTimestampMonotonic','ExecMainStatus','ExecStart','Conditions')
    observed={}
    for name in ('capstone-journal-reader.service','capstone-system-diagnostics.service',
                 'capstone-diagnostic-history-backfill.service'):
        result=subprocess.run(['/usr/bin/systemctl','show',name,'--no-pager','--property='+','.join(fields)],
                              capture_output=True,env=ENV,timeout=3)
        need(len(result.stdout)<=16384 and len(result.stderr)<=2048,'owned_collection_observation_bound')
        observed[name]={'returncode':result.returncode,
                       'properties':dict(line.split('=',1)for line in result.stdout.decode().splitlines()),
                       'stderr':result.stderr.decode(errors='replace')}
    return observed


_reference_services=load('release_services.py')


class CollectionReference(_reference_services._UnitReference):
    """Use the same pin implementation, confined to two owned test units."""
    def __init__(self,name):
        need(name in ('capstone-reference-executed.service','capstone-reference-skipped.service')
             and Path('/proc/self/uid_map').read_text().split()==['0','0','65536'],
             'owned_collection_reference_scope')
        super().__init__(name)


def collection_reference_diagnostic():
    """Preserve result identity while retaining a real live D-Bus client."""
    fields=('Id','LoadState','Type','RemainAfterExit','ConditionResult','Result',
            'ExecMainStartTimestampMonotonic','ExecMainStatus','MainPID','ActiveState')
    def probe(name):
        result=subprocess.run(['/usr/bin/systemctl','show',name,'--property='+','.join(fields)],
                              capture_output=True,env=ENV,timeout=3)
        need(result.returncode==0 and len(result.stdout)<8192,'owned_reference_probe')
        return dict(line.split('=',1)for line in result.stdout.decode().splitlines())
    records={}
    for suffix in ('executed','skipped'):
        name='capstone-reference-'+suffix+'.service'
        with CollectionReference(name):
            before=probe(name)
            result=subprocess.run(['/usr/bin/systemctl','start',name],capture_output=True,env=ENV,timeout=5)
            need(result.returncode==0,'owned_reference_start')
            after=probe(name)
            need(after['Type']=='oneshot'and after['RemainAfterExit']=='no','owned_reference_unit_type')
            start=int(after['ExecMainStartTimestampMonotonic'])
            if suffix=='executed':
                need(after['ConditionResult']=='yes'and after['Result']=='success'
                     and after['ExecMainStatus']=='0'and start>int(before['ExecMainStartTimestampMonotonic']),
                     'owned_referenced_execution_not_retained')
            else:
                need(after['ConditionResult']=='no'and start==int(before['ExecMainStartTimestampMonotonic']),
                     'owned_skipped_unit_falsely_executed')
            retained=[]
            for _ in range(3):
                time.sleep(.05);observation=probe(name)
                need(observation==after,'owned_referenced_properties_changed')
                retained.append(observation)
        released=probe(name)
        records[suffix]={'before':before,'after':after,'retained':retained,
                         'after_unref':released,'reference_connection_closed':True}
    return {'returncode':0,'reference_diagnostics':records,'operating_sources_modified':False}


def native(operation,proofs=None,deadline=None):
    args=['/usr/bin/python3','-I','-B',str(RUNTIME),'--host',ROLE,'--release-id',RELEASE,
          '--plan-sha256',PLAN_SHA,'--operation',operation]
    if deadline:
        args+=['--deadline-kst',deadline]
    raw=None if proofs is None else json.dumps(proofs,sort_keys=True,separators=(',',':')).encode()
    before=collection_observation()if operation=='verify'else None
    result=command(args,raw=raw,timeout=45)
    if before is not None:
        result['collection_observation']={'before':before,'after':collection_observation()}
        if result['returncode']!=0:
            journal=subprocess.run(['/usr/bin/journalctl','--no-pager','-n','30','-o','cat',
                '-u','capstone-journal-reader.service','-u','capstone-system-diagnostics.service',
                '-u','capstone-diagnostic-history-backfill.service'],capture_output=True,env=ENV,timeout=3)
            need(len(journal.stderr)<=2048,'owned_collection_journal_bound')
            result['collection_observation']['journal']={'returncode':journal.returncode,
                'stdout':journal.stdout.decode(errors='replace')[-8192:],
                'stderr':journal.stderr.decode(errors='replace')}
    return result


def peer_readonly_diagnostics():
    """Observe only this synthetic root; never replace the fixed peers gate."""
    need(ROLE in ('a','b') and Path('/proc/self/uid_map').read_text().split()==['0','0','65536'],
         'owned_peer_diagnostic_scope')
    config=Path('/etc/capstone-diagnostics/monitor.json'if ROLE=='a'else'/etc/mcp/system-diagnostics.json')
    cfg=json.loads(config.read_text())
    key='/etc/capstone-diagnostics/observer_ed25519'if ROLE=='a'else'/etc/mcp/system-diagnostics/id_ed25519'
    known='/etc/capstone-diagnostics/observer_known_hosts'if ROLE=='a'else'/etc/mcp/system-diagnostics/known_hosts'
    identity=None if ROLE=='a'else pwd.getpwnam('mcp')
    options={}if identity is None else{'user':identity.pw_uid,'group':identity.pw_gid,
              'extra_groups':os.getgrouplist(identity.pw_name,identity.pw_gid)}
    observations={}
    for host,address in sorted(cfg['hosts'].items()):
        need(host in 'abc' and address=='198.18.0.'+str(11+'abc'.index(host))and cfg['ssh_port']==44222,
             'only_owned_peer_addresses')
        argv=['/usr/bin/ssh','-F','/dev/null','-T','-p',str(cfg['ssh_port']),'-o','BatchMode=yes',
              '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
              '-o','ControlMaster=no','-o','ControlPath=none','-o','ForwardAgent=no',
              '-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','ConnectTimeout=4',
              '-o','ConnectionAttempts=1','-o','UserKnownHostsFile='+known,'-i',key,
              'capstone-diagnostics@'+address]
        raw=json.dumps({'release_status':{'schema':1,'host':host,'release_id':RELEASE}},
                       sort_keys=True,separators=(',',':')).encode()
        try:
            observed=subprocess.run(argv,input=raw,capture_output=True,cwd='/',env=ENV,timeout=6,**options)
            need(len(observed.stdout)<=65536 and len(observed.stderr)<=4096,'owned_peer_diagnostic_bound')
            observations[host]={'returncode':observed.returncode,'stdout':observed.stdout.decode(errors='replace'),
                                'stderr':observed.stderr.decode(errors='replace')}
        except subprocess.TimeoutExpired:
            observations[host]={'status':'observation_timeout','not_terminal_inference':True}
    # Import the unchanged prepared relay as the real reader UID and call its
    # read-only local client to expose an otherwise intentionally hidden error.
    diagnostic=r'''import json,runpy,sys
query=json.loads(sys.stdin.buffer.read())
try:
 relay=runpy.run_path('/opt/capstone-diagnostics/read-system-diagnostics.py',run_name='owned_readonly_diagnostic')
 value=relay['_client'](query)
 print(json.dumps({'status':'observed','host':value['host'],'generation':value['generation'],'phase':value['phase']}))
except Exception as error:
 print(json.dumps({'status':'unavailable','reason':type(error).__name__+':'+str(error)[:256]}))
'''
    reader=pwd.getpwnam('capstone-diagnostics')
    local=subprocess.run(['/usr/bin/python3','-I','-B','-c',diagnostic],
        input=json.dumps({'schema':1,'host':ROLE,'release_id':RELEASE}).encode(),capture_output=True,
        cwd='/',env=ENV,timeout=4,user=reader.pw_uid,group=reader.pw_gid,
        extra_groups=os.getgrouplist(reader.pw_name,reader.pw_gid))
    need(len(local.stdout)<=4096 and len(local.stderr)<=2048,'owned_local_relay_diagnostic_bound')
    observations['local_relay']={'returncode':local.returncode,'stdout':local.stdout.decode(errors='replace'),
                                'stderr':local.stderr.decode(errors='replace')}
    journal=subprocess.run(['/usr/bin/journalctl','--no-pager','-n','40','-o','cat',
                             '-u','capstone-private-ssh.service'],capture_output=True,env=ENV,timeout=3)
    observations['owned_ssh_journal']={'returncode':journal.returncode,
                                     'stdout':journal.stdout.decode(errors='replace')[-6000:]}
    return observations


def backend_functions():
    # Reuse unchanged test-library definitions only. Its top-level standalone
    # probe is not executed, and no operating helper is rewritten or mocked.
    raw=(CODE/'private_backend_probe.py').read_bytes()
    expected=json.loads((CODE/'full-input.json').read_text())['backend_probe_sha256']
    need(hashlib.sha256(raw).hexdigest()==expected,'pinned_backend_probe_changed')
    tree=ast.parse(raw);selected=[]
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='report' for t in node.targets):
            break
        selected.append(node)
    module=types.ModuleType('pinned_backend_functions')
    exec(compile(ast.Module(body=selected,type_ignores=[]),'pinned-backend-functions','exec'),module.__dict__)
    return module


def immutable(name,value):
    raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    fd=os.open(STORE/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def assert_sources(which):
    source=load('release_files.py')
    files=source.FileSet(ROLE,RELEASE,NODE['rows'],NODE['diagnostic_gid'])
    if which=='before':
        # Temporary reader/MCP barriers intentionally stay until final cleanup.
        for row in files.rows:
            if row['target'] in source.BARRIERS[ROLE]:
                continue
            raw,_=files.read_target(row)
            need((hashlib.sha256(raw).hexdigest()if raw is not None else None)==row['before_sha256'],
                 'baseline_source_not_restored')
    else:
        files.check('after_sha256')
    return {'source_generation':which,'core_files_verified':len(files.rows)-len(source.BARRIERS[ROLE])}


def assert_restored_cache():
    # Legacy collection may legitimately advance the database after resume.
    # Bind the verified restoration to its durable operation receipt instead
    # of demanding that those subsequent observations be erased again.
    cache_module=load('cache_transaction.py')
    cache=cache_module.Cache(ROLE,NODE['diagnostic_gid'],STORE/'cache')
    baseline,before=cache.saved('before')
    current,_,observed=cache.inspect(cache.path,live=True)
    state=json.loads((STORE/'state.json').read_bytes())
    facts=state['facts']
    need(state['phase']=='rolled_back' and state['pending'] is None and
         all(facts.get(key) is True for key in ('source_restored','cache_restored','baseline_services_resumed')),
         'restored_source_cache_resume_checkpoint_required')
    receipt_hash=facts['rollback_receipt_sha256']
    receipts=[]
    for path in STORE.glob('operation-*.json'):
        value=json.loads(path.read_bytes())
        if hashlib.sha256(cache_module.canonical(value)).hexdigest()==receipt_hash:
            receipts.append(value)
    need(len(receipts)==1,'rollback_operation_receipt_required')
    receipt=receipts[0]
    need(receipt['host']==ROLE and receipt['release_id']==RELEASE and receipt['plan_sha256']==PLAN_SHA
         and receipt['operation']=='rollback' and receipt['isolated_filesystem'] is False,
         'rollback_operation_receipt_binding')
    proof=receipt['evidence']['cache']
    need(receipt['evidence']['sources_before'] is True and proof['baseline_sha256']==before['sha256']
         and before['sha256']==hashlib.sha256(baseline).hexdigest(),
         'rollback_cache_baseline_receipt_mismatch')
    need(observed['metadata'].get('source_filter_policy') is None,'resumed_cache_must_remain_legacy')
    if proof['post_preserved']:
        _,post=cache.saved('after')
        need(post['sha256']==proof['post_sha256'],'post_cache_preservation_receipt_mismatch')
    if proof['changed']:
        need(json.loads((STORE/'cache/restored.json').read_bytes())==proof,
             'actual_cache_restore_receipt_required')
    return {'cache_restoration_checkpoint_verified':True,'baseline_cache_sha256':before['sha256'],
            'rollback_receipt_sha256':receipt_hash,'candidate_cache_preserved':proof['post_preserved'],
            'current_cache_sha256':observed['sha256'],
            'current_cache_equals_baseline':hashlib.sha256(current).hexdigest()==before['sha256'],
            'current_source_filter_policy':None}


report={'schema':1,'role':ROLE,'scope':'owned_native_root_source_cache_integration',
        'operating_deployment':False,'actual_host_reboot':False,'actual_MCP_or_bot_acceptance':False,
        'steps':[]}
PLAN_SHA=None
console=None
try:
    need(os.getuid()==os.geteuid()==0 and ROLE in ('a','b','c') and NODE['host']==ROLE,'owned_role_identity')
    need(Path('/proc/self/uid_map').read_text().split()==['0','0','65536'],'private_user_namespace')
    need(Path('/proc/1/comm').read_text().strip()=='systemd','actual_PID1')
    need(not(os.statvfs('/').f_flag&os.ST_NOEXEC),'executable_user_owned_root')
    need(not Path('/root/.ssh').exists(),'no_operating_private_keys')
    libc=ctypes.CDLL(None,use_errno=True)
    libc.personality.argtypes=[ctypes.c_ulong]
    libc.personality.restype=ctypes.c_int
    ctypes.set_errno(0)
    query=libc.personality(0xffffffff)
    report['inherited_personality_query']={'returncode':query,'errno':ctypes.get_errno()}
    need(query==0 and ctypes.get_errno()==0,'native_personality_read_only_query')
    ctypes.set_errno(0)
    change=libc.personality(8)
    report['inherited_personality_change']={'returncode':change,'errno':ctypes.get_errno()}
    need(change==-1 and ctypes.get_errno()==1,'outer_personality_change_must_remain_denied')
    console=PrivateConsole()
    journal_started=subprocess.run(['/usr/bin/systemctl','start','capstone-private-journal.service'],
                                   capture_output=True,env=ENV,timeout=10)
    need(journal_started.returncode==0,'owned_journal_daemon_start')
    bus_started=subprocess.run(['/usr/bin/systemctl','start','dbus.socket','dbus.service'],
                               capture_output=True,env=ENV,timeout=10)
    need(bus_started.returncode==0,'owned_system_bus_start')
    bus_end=time.monotonic()+8
    while True:
        try:
            with CollectionReference('capstone-reference-executed.service'):
                pass
            break
        except (_reference_services.Refused,RuntimeError,OSError)as error:
            report['system_bus_readiness_last_error']={'type':type(error).__name__,'reason':str(error)[:160]}
            need(time.monotonic()<bus_end,'owned_manager_system_bus_not_ready')
            time.sleep(.1)
    journal_end=time.monotonic()+3
    while not Path('/run/systemd/journal/socket').is_socket():
        need(time.monotonic()<journal_end,'owned_journal_socket_required')
        time.sleep(.03)
    for setting in [('log-target','console'),('log-level','info')]:
        logging=subprocess.run(['/usr/bin/systemctl',*setting],capture_output=True,env=ENV,timeout=5)
        need(logging.returncode==0,'owned_manager_logging_setup')
    functions=backend_functions()
    started=subprocess.run(['/usr/bin/systemctl','start','capstone-private-ssh.service'],capture_output=True,env=ENV,timeout=10)
    need(started.returncode==0,'private_SSH_server_start')
    container=None
    if ROLE=='b':
        container,busybox_sha=functions.docker_container()
        report['private_Docker_image_binary_sha256']=busybox_sha
    # Start real pre-change collector code and the original shell/reader.
    for name in ['capstone-journal-reader.service','capstone-system-diagnostics.service',
                 'capstone-system-diagnostics.timer']+(
        ['capstone-soc-observe.service','capstone-soc-observe.timer'] if ROLE=='a' else
        ['capstone-management.service','capstone-management.timer','capstone-ollama-chat.service','capstone-review-chat.service'] if ROLE=='b' else []):
        result=subprocess.run(['/usr/bin/systemctl','start',name],capture_output=True,env=ENV,timeout=25)
        need(result.returncode==0,'baseline_unit_start_'+name)
    backend=load('release_services.py').Native(ROLE,container)
    end=time.monotonic()+8
    while True:
        snapshot=backend.snapshot()
        report['baseline_native_snapshot']=snapshot
        reader=snapshot['capstone-journal-reader.service']
        if (not any(row['ActiveState'] in ('activating','deactivating') for row in snapshot.values())
            and reader['ActiveState']=='active' and reader['SubState']=='running'
            and int(reader['MainPID'])>1 and reader['ExecMainStatus']=='0'):
            break
        need(time.monotonic()<end,'baseline_native_units_not_stable')
        time.sleep(.1)
    sandbox=subprocess.run(['/usr/bin/systemctl','show','capstone-journal-reader.service',
        '--property=LockPersonality,Personality,NoNewPrivileges,PrivateNetwork,ProtectSystem'],
        capture_output=True,env=ENV,timeout=5)
    values=dict(line.split('=',1)for line in sandbox.stdout.decode().splitlines())
    need(sandbox.returncode==0 and values.get('LockPersonality')=='yes' and
         values.get('NoNewPrivileges')=='yes' and values.get('PrivateNetwork')=='yes' and
         values.get('ProtectSystem')=='strict',
         'private_reader_original_sandbox_loaded')
    report['loaded_reader_sandbox']=values
    report['baseline_sources']=assert_sources('before')
    ready={key:value for key,value in NODE.items() if key not in ('receipt_changes','cache_origin')}
    ready['container']=container
    ready['namespaces']={name:os.readlink('/proc/self/ns/'+name)for name in ('user','mnt','pid','net','uts','ipc','cgroup')}
    save('ready.json',ready)
    finish=False
    for sequence in range(1,40):
        instruction=OUT/('control-%02d.json'%sequence)
        end=time.monotonic()+240
        while not instruction.exists():
            need(time.monotonic()<end,'owned_controller_instruction_deadline')
            time.sleep(.03)
        request=json.loads(instruction.read_text())
        operation=request['operation']
        need(operation in {'install_plan','initialize','prepare','arm','quiesce','backup','apply','apply_partial',
             'verify','confirm','resume','rollback','status','peers','assert_restored','assert_candidate',
             'completion_denied','peers_denied','collection_reference','regressions','finish'},'fixed_test_operation')
        if operation=='install_plan':
            plans=load('release_plan.py');plan=plans.Plan(request['plan'])
            need(plan.value['hosts'][ROLE]['rows']==NODE['rows'] and plan.sha256==request['plan_sha256'],
                 'exact_private_plan_binding')
            for name,expected in plan.value['helpers'].items():
                need(hashlib.sha256((STORE/name).read_bytes()).hexdigest()==expected,'operator_helper_changed')
            PLAN_SHA=plan.sha256
            immutable('plan.json',plan.value);immutable('bundle.json',plan.bundle())
            immutable('approval.json',request['approval'])
            result={'returncode':0,'plan_sha256':PLAN_SHA,'synthetic_approval_only':True}
        elif operation=='apply_partial':
            trace_input={'runtime':str(RUNTIME),'role':ROLE,'release_id':RELEASE,
                         'plan_sha256':PLAN_SHA,'rows':NODE['rows'],'proofs':request['proofs']}
            traced=command(['/usr/bin/python3','-I','-B',str(CODE/'private_apply_crash.py')],
                           raw=json.dumps(trace_input,sort_keys=True).encode(),timeout=60)
            report['apply_trace']=traced
            save('progress.json',report)
            need(traced['returncode']==0,'owned_apply_trace_failed_'+
                 str(traced['reply'].get('reason')if isinstance(traced['reply'],dict)else traced['stderr'])[-256:])
            result={'returncode':0,'interruption':traced['reply']}
        elif operation in ('assert_restored','assert_candidate'):
            result={'returncode':0,**assert_sources('before'if operation=='assert_restored'else'after')}
            if operation=='assert_restored':
                result.update(assert_restored_cache())
        elif operation=='completion_denied':
            result=native('completion_prepare',request['proofs'])
            need(result['returncode']!=0 and result['reply']['reason']=='operator_acceptance_required',
                 'missing_actual_acceptance_must_not_complete')
            result['expected_denial']=True
        elif operation=='peers_denied':
            need(ROLE=='c','peer_denial_only_on_c')
            result=native('peers')
            need(result['returncode']!=0 and result['reply']['reason']=='peer_transport_not_installed_on_c',
                 'c_must_not_gain_peer_client')
            result['expected_denial']=True
        elif operation=='collection_reference':
            result=collection_reference_diagnostic()
        elif operation=='regressions':
            result=unprivileged_regressions()
        elif operation=='finish':
            finish=True;result={'returncode':0}
        else:
            if ROLE=='b' and operation=='quiesce':
                Path('/opt/hermes-data/gateway_state.json').write_text(json.dumps({'active_agents':0,'active_work':[],
                    'updated_at':datetime.now(KST).isoformat()}))
            result=native(operation,request.get('proofs'),request.get('deadline_kst'))
        if operation=='peers' and result['returncode']!=0:
            try:
                report['peer_failure_diagnostics']=peer_readonly_diagnostics()
            except Exception as diagnosis_error:
                report['peer_failure_diagnostics']={'unavailable':type(diagnosis_error).__name__+':'+str(diagnosis_error)[:256]}
        report['steps'].append({'sequence':sequence,'operation':operation,**result})
        if console is not None:
            report['owned_manager_console_snapshot']=console.snapshot()
        save('progress.json',report)
        save('reply-%02d.json'%sequence,result)
        if finish:
            break
    need(finish,'test_finish_required')
    report.update(status='verified',private_pid1=True,namespaces=ready['namespaces'],
                  machine_id_sha256=NODE['machine_sha256'],default_native_backend=True,
                  production_root_entry_in_owned_namespace=True,cache_origin=NODE['cache_origin'])
except BaseException as error:
    report.update(status='failed',reason=type(error).__name__+':'+str(error)[:512])
    try:
        failure_log=subprocess.run(['/usr/bin/journalctl','--no-pager','-n','80','-o','cat'],
                                   capture_output=True,env=ENV,timeout=3)
        report['owned_failure_journal']={'returncode':failure_log.returncode,
            'stdout':failure_log.stdout.decode(errors='replace')[-16000:],
            'stderr':failure_log.stderr.decode(errors='replace')[-1024:]}
    except (OSError,subprocess.TimeoutExpired) as diagnosis_error:
        report['owned_failure_journal']={'unavailable':type(diagnosis_error).__name__}
finally:
    if console is not None:
        try:
            report['owned_manager_console']=console.close()
        except Exception as collection_error:
            report.update(status='failed',reason='owned_console_collection_'+
                          type(collection_error).__name__+':'+str(collection_error)[:256])
save('report.json',report)
raise SystemExit(0 if report['status']=='verified'else 1)
