#!/usr/bin/env python3
"""Opt-in fixed-root coordinator integration in three disposable PID1 roots.

Start and collect are separate so observation timeouts never cause a restart.
All source writes, approvals, helpers, source/cache recovery and consumers are
inside owned roots. Operating keys/configuration/agents are not installed.
"""
import argparse
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import time
import uuid

HERE=Path(__file__).resolve().parent


def module(name):
    spec=importlib.util.spec_from_file_location('full_native_'+name[:-3],HERE/name)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


backend=module('validate_private_backends.py')
base=backend.base
# The reused ownership verifier binds the current orchestrator, as in the
# existing backend wrapper; the pinned foundation file itself stays intact.
base.__file__=__file__
fixture=module('private_full_fixture.py')
KST=timezone(timedelta(hours=9))
EXTRA=('validate_private_backends.py','private_full_fixture.py','private_apply_crash.py',
       'private_full_native_probe.py','validate_full_native.py','full-input.json')


def pins():
    values=backend.extended_pins()
    for name in EXTRA:
        values[name]=base.sha((HERE/name).read_bytes())
    return values


def atomic(path,value):
    raw=json.dumps(value,sort_keys=True).encode()
    temporary=path.with_name(path.name+'.tmp')
    base.new_file(temporary,raw)
    os.replace(temporary,path)


def lock_native_personality():
    """Keep a native-only execution domain while allowing its read-only query.

    systemd255 LockPersonality also denies personality(0xffffffff), preventing
    a nested manager from installing the same lock on unchanged service units.
    This outer test-only filter denies every nonnative personality change;
    unlike the stock outer filter, the kernel's read-only query stays usable.
    The operating units and all inner LockPersonality directives stay intact.
    """
    base.require(os.uname().machine=='x86_64','native_personality_filter_architecture')
    libc=ctypes.CDLL(None,use_errno=True)
    libc.personality.argtypes=[ctypes.c_ulong]
    libc.personality.restype=ctypes.c_int
    base.require(libc.personality(0xffffffff)==0,'native_personality_required')
    seccomp=ctypes.CDLL('libseccomp.so.2')
    seccomp.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype=ctypes.c_int
    syscall=seccomp.seccomp_syscall_resolve_name(b'personality')
    base.require(syscall==135,'native_personality_syscall_number')
    class Filter(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),
                  ('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    # seccomp_data: arch at4, syscall at0, low32 of argument0 at16. Linux's
    # personality syscall consumes unsigned int; high32 cannot change its ABI.
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
          (0x20,0,0,0),(0x45,0,1,0x40000000),(0x06,0,0,0x80000000),
          (0x15,0,4,syscall),(0x20,0,0,16),
          (0x15,2,0,0),(0x15,1,0,0xffffffff),(0x06,0,0,0x00050001),
          (0x06,0,0,0x7fff0000)]
    instructions=(Filter*len(rows))(*(Filter(*row)for row in rows))
    program=Program(len(rows),instructions)
    base.require(libc.prctl(39,0,0,0,0)==1,'outer_no_new_privileges_required')
    base.require(libc.prctl(22,2,ctypes.byref(program),0,0)==0,
                 'native_personality_filter_install_'+str(ctypes.get_errno()))
    ctypes.set_errno(0);query=libc.personality(0xffffffff);query_errno=ctypes.get_errno()
    ctypes.set_errno(0);change=libc.personality(8);change_errno=ctypes.get_errno()
    base.require(query==0 and query_errno==0 and change==-1 and change_errno==1,
                 'personality_query_and_change_boundaries')
    child=os.fork()
    if child==0:
        # This disposable child attempts only an invalid-fd x32 read. Disable
        # core dumping first; the native-only filter must kill it with SIGSYS.
        if libc.prctl(4,0,0,0,0)!=0:
            os._exit(96)
        libc.syscall(ctypes.c_long(0x40000000),ctypes.c_long(-1),0,0)
        os._exit(97)
    _,status=os.waitpid(child,0)
    base.require(os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGSYS,
                 'personality_filter_x32_bypass_must_be_denied')
    return {'native_architecture':'x86_64','native_personality':0,'compat_and_x32_ABIs_denied':True,
            'read_only_query':{'returncode':query,'errno':query_errno},
            'nonnative_change':{'returncode':change,'errno':change_errno},
            'x32_probe_signal':signal.SIGSYS,'x32_probe_core_dump_disabled':True,
            'filter_sha256':base.sha(ctypes.string_at(ctypes.addressof(instructions),
                                                    ctypes.sizeof(instructions))),
            'unchanged_inner_units':True,'operating_host_policy_modified':False}


def boundaries(unit):
    names=('LoadState','ActiveState','MainPID','ControlGroup','MemoryMax','MemorySwapMax','TasksMax',
           'RuntimeMaxUSec','Delegate','DelegateSubgroup','PrivateNetwork','PrivateMounts','NoNewPrivileges',
           'ProtectSystem','ReadWritePaths','KillMode','MemoryPeak','LockPersonality')
    result=base.command(['/usr/bin/systemctl','show',unit,'--property='+','.join(names)],check=False)
    return dict(line.split('=',1)for line in result.stdout.decode().splitlines())


def retryable_status_observation(reply):
    """A changing read is pending evidence, never a successful operation."""
    value=reply.get('reply')
    if not isinstance(value,dict) or type(value.get('schema'))is not int or value['schema']!=1\
            or value.get('completion_verified')is not False:
        return False
    return (reply.get('returncode')==1 and value.get('status')=='unavailable' and
            value.get('reason')=='control_observation_changed')or(
            reply.get('returncode')==75 and value.get('status')=='deferred' and
            value.get('reason')in ('host_operation_busy','operation_busy'))


def start(case):
    base.require(os.getuid()==os.geteuid()==0 and os.sys.platform=='linux','linux_root_required')
    base.require(Path('/run/systemd/system').is_dir(),'host_system_manager_required')
    pinmap=pins()
    root=Path('/run')/('capstone-pid1-'+uuid.uuid4().hex[:12])
    root.mkdir(mode=0o700)
    unit=root.name+'.service'
    owner={'workspace':str(root),'unit':unit,'validator_sha256':base.sha(Path(__file__).read_bytes()),
           'parent_namespaces':base.namespaces(),'pid':os.getpid(),'case':case,'release_id':uuid.uuid4().hex,
           'input_source':str(HERE),'input_pins':pinmap,'schema':1}
    base.new_file(root/'owner.json',json.dumps(owner).encode())
    for name in (*pinmap,'coordinator-manifest.json','witness-manifest.json'):
        base.new_file(root/'code'/name,(HERE/name).read_bytes())
    (root/'roots').mkdir(mode=0o700)
    absent=base.command(['/usr/bin/systemctl','show',unit,'--property=LoadState'],check=False)
    base.require(absent.stdout.strip()==b'LoadState=not-found','owned_unit_name_collision')
    args=['/usr/bin/systemd-run','--quiet','--unit='+unit,'--service-type=exec',
          '--property=Delegate=yes','--property=DelegateSubgroup=supervisor',
          '--property=MemoryAccounting=yes','--property=MemoryMax=1G','--property=MemorySwapMax=0',
          '--property=TasksAccounting=yes','--property=TasksMax=384','--property=CPUQuota=100%',
          '--property=RuntimeMaxSec='+('300s'if case=='bootstrap'else'180s'),
          '--property=TimeoutStopSec=8s','--property=KillMode=control-group',
          '--property=PrivateNetwork=yes','--property=PrivateMounts=yes','--property=PrivateTmp=yes',
          '--property=PrivateDevices=yes','--property=NoNewPrivileges=yes','--property=ProtectSystem=strict',
          '--property=ReadWritePaths='+str(root),'--property=ProtectHome=yes',
          '--property=ProtectKernelTunables=yes','--property=ProtectKernelModules=yes','--property=ProtectClock=yes',
          '--property=LockPersonality=no','--property=StandardOutput=file:'+str(root/'outer.log'),
          '--property=StandardError=inherit','/usr/bin/python3','-I','-B',str(root/'code/validate_full_native.py'),
          '--supervisor',str(root)]
    try:
        base.command(args)
    except Exception:
        # Lost start responses leave an explicit, collectable owned handle.
        print(json.dumps({'workspace':str(root),'unit':unit,'start_outcome':'unknown','collect_required':True}))
        raise
    state=boundaries(unit)
    base.require(state['MemoryMax']==str(1024**3) and state['TasksMax']=='384' and
                 state['RuntimeMaxUSec']==('5min'if case=='bootstrap'else'3min') and state['Delegate']=='yes' and
                 state['DelegateSubgroup']=='supervisor' and state['PrivateNetwork']=='yes' and
                 state['PrivateMounts']=='yes' and state['NoNewPrivileges']=='yes' and
                 state['ProtectSystem']=='strict' and state['ReadWritePaths']==str(root) and
                 state['LockPersonality']=='no','loaded_owned_boundaries')
    atomic(root/'outer-loaded.json',state)
    print(json.dumps({'status':'started','workspace':str(root),'unit':unit,'case':case,
                      'RuntimeMaxSec':300 if case=='bootstrap'else 180,'observed':state},sort_keys=True))
    return 0


def own(root):
    path,owner=base.own_root(root)
    base.require(owner['schema']==1 and owner['case'] in
                 ('bootstrap','partial','deadline','confirmed','complete-candidate','complete-baseline'),
                 'owned_full_test_identity')
    base.require(owner['validator_sha256']==base.sha((path/'code/validate_full_native.py').read_bytes()),'owned_validator_changed')
    return path,owner


def mount_user_root(root,view,output):
    # Runs after the own child enters its mapped user namespace. Its writable
    # tmpfs superblock belongs to that namespace; host filesystem permissions
    # and inherited masked kernel/executable mounts are retained separately.
    layout=json.loads((output/'root-layout.json').read_text())
    base.mount('tmpfs',root,fs='tmpfs',flags=base.MS_NOSUID|base.MS_NODEV,data='mode=755,size=96m')
    for item in layout:
        target=root/item['path']
        if item['kind']=='directory':
            target.mkdir(exist_ok=True);target.chmod(item['mode'])
        elif item['kind']=='link':
            target.symlink_to(item['target'])
        else:
            raw=(view/item['path']).read_bytes()
            base.require(base.sha(raw)==item['sha256'],'private_root_materialization_changed')
            base.new_file(target,raw,item['mode'])
            os.chown(target,item['uid'],item['gid'])
    for relative in ('usr/bin','usr/sbin','usr/lib','usr/lib64','usr/local/bin','proc','sys','dev','proof'):
        source=view/relative
        target=root/relative
        if source.is_symlink() or not source.exists():
            continue
        base.mount(source,target,flags=base.MS_BIND|base.MS_REC)
    base.mount('tmpfs',root/'run',fs='tmpfs',flags=base.MS_NOSUID|base.MS_NODEV,data='mode=755,size=24m')
    base.mount('tmpfs',root/'tmp',fs='tmpfs',flags=base.MS_NOSUID|base.MS_NODEV,data='mode=1777,size=8m')
    base.new_file(output/'root-userfs.json',json.dumps({'user_namespace_owned_tmpfs':True,
        'executable_private_root':not bool(os.statvfs(root).f_flag&os.ST_NOEXEC),
        'inherited_kernel_and_binary_mounts_preserved':True}).encode())


def child_manager(root,output,cgroup,ready,ack):
    original_unshare=base.unshare
    entered=False
    materialized=False
    view=root.with_name(root.name+'-inherited')
    view.mkdir()
    def owned_unshare(flags):
        nonlocal entered,materialized
        if flags==base.NEWUSER:
            # Preserve the already-created, masked proc/sys/dev/binary views.
            base.mount(root,view,flags=base.MS_BIND|base.MS_REC)
            original_unshare(flags);entered=True
        else:
            original_unshare(flags)
            if entered and flags&base.NEWNS and not materialized:
                mount_user_root(root,view,output);materialized=True
    base.unshare=owned_unshare
    backend.child_manager(root,output,cgroup,ready,ack)


def supervisor(root):
    root,owner=own(root)
    current=Path('/proc/self/cgroup').read_text().strip()
    base.require(current.endswith('/'+owner['unit']+'/supervisor'),'owned_supervisor_cgroup')
    base.require(base.namespaces()['net']!=owner['parent_namespaces']['net'] and
                 base.namespaces()['mnt']!=owner['parent_namespaces']['mnt'],'private_outer_namespaces_required')
    personality_filter=lock_native_personality()
    atomic(root/'outer-personality-filter.json',personality_filter)
    delegated=(Path('/sys/fs/cgroup')/current[4:].lstrip('/')).parent
    base.require(not (delegated/'cgroup.procs').read_text().strip(),'empty_delegated_parent')
    (delegated/'cgroup.subtree_control').write_text('+cpu +memory +pids')
    interfaces=json.loads(base.command(['/usr/sbin/ip','-j','link']).stdout)
    base.require({item['ifname']for item in interfaces}=={'lo'},'no_external_interfaces')
    base.command(['/usr/sbin/ip','link','set','lo','up'])
    for address in (backend.ADDRESSES['a'],backend.ADDRESSES['c']):
        base.command(['/usr/sbin/ip','address','add',address+'/32','dev','lo'])
    pinmap=pins()
    inputs=json.loads((HERE/'full-input.json').read_text())
    base.PROBE=(HERE/'private_full_native_probe.py').read_text()
    children={};sequence={role:0 for role in 'abc'}
    result={'schema':1,'case':owner['case'],'scope':'full_fixed_root_in_owned_PID1_namespaces',
            'operating_deployment':False,'actual_host_reboot':False,'actual_MCP_or_bot_acceptance':False,
            'operator_helper_source_changes':0,'roles':{},'steps':[],'release_id':owner['release_id']}
    result['outer_personality_filter']=personality_filter
    helper=None
    def wait(paths,seconds=35):
        end=time.monotonic()+seconds
        while not all(path.exists()for path in paths):
            for role,item in children.items():
                failure=item['output']/'report.json'
                if failure.exists():
                    report=json.loads(failure.read_text())
                    if report.get('status')=='failed':
                        raise RuntimeError('private_role_'+role+'_'+report['reason'])
                boot=item['output']/'boot-error.json'
                if boot.exists():
                    raise RuntimeError('private_boot_'+role+'_'+boot.read_text()[:256])
            base.require(time.monotonic()<end,'owned_observation_deadline')
            time.sleep(.03)
    def rpc(operation,roles='abc',proofs=None,**extra):
        paths=[]
        for role in roles:
            sequence[role]+=1
            atomic(children[role]['output']/('control-%02d.json'%sequence[role]),
                   {'operation':operation,**({'proofs':proofs}if proofs is not None else {}),**extra})
            paths.append(children[role]['output']/('reply-%02d.json'%sequence[role]))
        wait(paths,220 if operation=='regressions'else 60 if operation=='apply_partial'else 35)
        replies={role:json.loads(path.read_text())for role,path in zip(roles,paths)}
        if operation=='status':
            for reply in replies.values():
                reply['observation_retry_required']=retryable_status_observation(reply)
        result['steps'].append({'operation':operation,'roles':list(roles),'replies':replies})
        for role,reply in replies.items():
            base.require(reply['returncode']==0 or reply.get('expected_denial') or
                         operation=='status' and reply['observation_retry_required'],
                         'fixed_entry_'+role+'_'+operation+'_'+str(reply.get('reply',{}))[:160])
        return replies
    try:
        log=(root/'network-controller.log').open('xb')
        helper=subprocess.Popen(['/usr/bin/python3','-I','-B',__file__,'--network-controller',str(root)],
            stdin=subprocess.DEVNULL,stdout=log,stderr=log,env=base.ENV)
        log.close()
        for role in 'abc':
            output=root/'outputs'/role;output.mkdir(parents=True,mode=0o700)
            base.new_file(output/'parent.json',json.dumps(owner['parent_namespaces']).encode())
            role_root=root/'roots'/role
            fixture.populate(role_root,role,HERE,output,pinmap,inputs,owner['release_id'],backend)
            cgroup=delegated/('role-'+role);cgroup.mkdir()
            rr,rw=os.pipe();ar,aw=os.pipe()
            child=os.fork()
            if child==0:
                os.close(rr);os.close(aw)
                child_manager(role_root,output,cgroup,rw,ar)
            children[role]={'pid':child,'cgroup':cgroup,'output':output}
            os.close(rw);os.close(ar)
            raw=os.read(rr,32);os.close(rr)
            base.require(re.fullmatch(rb'[0-9]{1,10}\n',raw),'owned_mapping_ready')
            pid=int(raw)
            base.require(Path('/proc/'+str(pid)+'/cgroup').read_text().strip().endswith('/'+owner['unit']+'/role-'+role),
                         'mapping_child_owned_cgroup')
            for name in ('uid_map','gid_map'):
                Path('/proc/'+str(pid)+'/'+name).write_text('0 0 65536\n')
            os.write(aw,b'1');os.close(aw)
        wait([item['output']/'ready.json'for item in children.values()],40)
        ready={role:json.loads(item['output'].joinpath('ready.json').read_text())for role,item in children.items()}
        fields=('rows','machine_sha256','diagnostic_gid','reader_uid','mcp_uid','container','protected','previous_current_sha256')
        plans=fixture.load('release_plan.py')
        source=fixture.load('release_files.py')
        value={'schema':1,'release_id':owner['release_id'],'source_commit':inputs['source_commit'],
               'hosts':{role:{key:ready[role][key]for key in fields}for role in 'abc'},
               'helpers':{name:base.sha((HERE/name).read_bytes())for name in plans.HELPERS},
               'cohort':{'schema':1,'release_id':owner['release_id'],
                         'hosts':{role:[row for row in ready[role]['rows']if row['target']not in source.BARRIERS[role]]for role in 'abc'}}}
        plan=plans.Plan(value)
        now=datetime.now(KST)
        approval={'schema':1,'release_id':owner['release_id'],'plan_sha256':plan.sha256,
                  'bundle_sha256':plans.digest(plan.bundle()),'decision':'approved',
                  'approved_at_kst':(now-timedelta(seconds=1)).isoformat(),
                  'expires_at_kst':(now+timedelta(minutes=5)).isoformat(),'reference':'owned-native-integration-only'}
        rpc('install_plan',plan=value,plan_sha256=plan.sha256,approval=approval)
        deadline=now+timedelta(seconds=75 if owner['case']=='deadline'else 150)
        rpc('initialize',deadline_kst=deadline.isoformat())
        rpc('prepare')
        proofs=rpc('peers',roles='a')['a']['reply']['result']
        result['authenticated_initial_source_proofs']=proofs
        b_proofs=rpc('peers',roles='b')['b']['reply']['result']
        base.require(set(proofs)==set(b_proofs)==set('abc') and
                     all(proofs[host]['source_contract_sha256']==b_proofs[host]['source_contract_sha256']
                         for host in 'abc'),'four_authenticated_peer_routes_source_binding')
        result['authenticated_B_source_proofs']=b_proofs
        result['C_peer_client_denied']=rpc('peers_denied',roles='c')['c']['expected_denial']
        if owner['case']=='bootstrap':
            rpc('collection_reference')
            rpc('regressions',roles='b')
        if owner['case']!='bootstrap':
            rpc('arm',proofs=proofs)
            rpc('quiesce')
            rpc('backup')
            proofs=rpc('peers',roles='a')['a']['reply']['result']
            if owner['case']in ('partial','complete-baseline'):
                rpc('apply_partial',proofs=proofs)
            else:
                rpc('apply',proofs=proofs)
                rpc('verify')
            if owner['case']in ('confirmed','complete-candidate'):
                for role in 'acb':
                    proofs=rpc('peers',roles='a')['a']['reply']['result']
                    rpc('confirm',roles=role,proofs=proofs)
                for role in 'acb':
                    proofs=rpc('peers',roles='a')['a']['reply']['result']
                    rpc('resume',roles=role,proofs=proofs)
                rpc('assert_candidate')
                proofs=rpc('peers',roles='a')['a']['reply']['result']
                rpc('completion_denied',proofs=proofs)
            else:
                end=time.monotonic()+100
                while True:
                    statuses=rpc('status')
                    phases=[row['reply']['result']['source']['phase'] if row['returncode']==0 else 'observation_pending'
                            for row in statuses.values()]
                    if phases==['rolled_back']*3:
                        break
                    base.require(time.monotonic()<end,'independent_recovery_deadline')
                    time.sleep(2)
                proofs=rpc('peers',roles='a')['a']['reply']['result']
                for role in 'acb':
                    rpc('resume',roles=role,proofs=proofs)
                rpc('assert_restored')
            if owner['case']in ('complete-candidate','complete-baseline'):
                # Explicitly synthetic attestations in disposable roots. The
                # same root CLI performs every protected completion mutation.
                rpc('acceptance_fixture')
                proofs=rpc('peers',roles='a')['a']['reply']['result']
                rpc('completion_prepare',proofs=proofs)
                prepared=rpc('completion_status')
                rpc('cleanup_decide',proofs={h:r['reply']['result']for h,r in prepared.items()})
                decided=rpc('completion_status')
                rpc('cleanup_authorize',proofs={h:r['reply']['result']for h,r in decided.items()})
                rpc('cleanup')
                rpc('current')
                rpc('current_pointer_denied')
                rpc('cleanup')
                rpc('assert_completed')
        rpc('finish')
        wait([item['output']/'report.json'for item in children.values()],5)
        result['roles']={role:json.loads(item['output'].joinpath('report.json').read_text())for role,item in children.items()}
        base.require(all(row['status']=='verified'for row in result['roles'].values()),'all_roles_verified')
        result['status']='verified'
    except BaseException as error:
        result.update(status='failed',reason=type(error).__name__+':'+str(error)[:512])
    finally:
        # Preserve complete per-role evidence even when initialization fails
        # before the supervisor reaches its normal report collection step.
        for role,item in children.items():
            report_path=item['output']/'report.json'
            if report_path.is_file():
                result['roles'][role]=json.loads(report_path.read_text())
            else:
                progress=item['output']/'progress.json'
                if progress.is_file():
                    result['roles'][role]={**json.loads(progress.read_text()),
                                           'status':'interrupted_by_supervisor',
                                           'evidence_kind':'last durable progress; not completed role proof'}
        for item in children.values():
            kill=item['cgroup']/'cgroup.kill'
            if kill.exists():
                kill.write_text('1')
        if helper is not None:
            if helper.poll()is None:
                helper.terminate()
            helper.wait(timeout=3)
            result['network_controller_returncode']=helper.returncode
        end=time.monotonic()+5
        while any('populated 1'in(item['cgroup']/'cgroup.events').read_text()for item in children.values()):
            base.require(time.monotonic()<end,'owned_children_still_live');time.sleep(.02)
        result['role_cgroups_empty']=all('populated 0'in(item['cgroup']/'cgroup.events').read_text()for item in children.values())
        result['outer_memory_peak_bytes']=int((delegated/'memory.peak').read_text())
        result['outer_pids_peak']=int((delegated/'pids.peak').read_text())
        result['outer_memory_events']=dict(line.split()for line in(delegated/'memory.events').read_text().splitlines())
        result['diagnostics']={}
        for path in sorted((root/'outputs').glob('*/*')):
            if path.name in ('report.json','probe.stderr','systemd.log','boot-error.json','dbus.stdout','dbus.stderr'):
                result['diagnostics'][path.relative_to(root).as_posix()]=path.read_text(errors='replace')[-6000:]
        if (root/'network-controller.log').exists():
            result['diagnostics']['network-controller.log']=(root/'network-controller.log').read_text(errors='replace')[-2000:]
        atomic(root/'supervisor-report.json',result)
    return 0 if result.get('status')=='verified'else 1


def collect(root):
    root,owner=own(root)
    state=boundaries(owner['unit'])
    if state.get('ActiveState')in ('active','activating','deactivating')or state.get('MainPID','0')!='0':
        print(json.dumps({'status':'running','workspace':str(root),'unit':owner['unit'],'observed':state},sort_keys=True))
        return 0
    base.require(state.get('ControlGroup','')=='','owned_cgroup_not_empty')
    report=root/'supervisor-report.json'
    value=json.loads(report.read_text())if report.exists()else {'status':'failed','reason':'terminal_without_report',
        'outer_log':(root/'outer.log').read_text(errors='replace')[-6000:]if(root/'outer.log').exists()else''}
    value['observed_outer_final']=state
    value['workspace']=str(root);value['unit']=owner['unit']
    value['outer_loaded_boundaries']=json.loads((root/'outer-loaded.json').read_text())
    value['input_source']=owner['input_source']
    value['input_source_sha_unchanged']=all(base.sha((Path(owner['input_source'])/name).read_bytes())==expected
        for name,expected in owner['input_pins'].items())
    mounts=[line.split()[4]for line in Path('/proc/self/mountinfo').read_text().splitlines()
            if line.split()[4]==str(root)or line.split()[4].startswith(str(root)+'/')]
    base.require(not mounts,'owned_mounts_remain_in_host_namespace')
    base.require(base.namespaces()==owner['parent_namespaces'],'host_namespaces_changed')
    value['host_namespaces_unchanged']=True
    inventory={path.relative_to(root).as_posix():base.sha(path.read_bytes())for path in root.rglob('*')
               if path.is_file()and not path.is_symlink()}
    value['removed_owned_files_sha256']=inventory
    shutil.rmtree(root)
    value['workspace_removed']=not root.exists()
    base.command(['/usr/bin/systemctl','reset-failed',owner['unit']],check=False)
    print(json.dumps(value,sort_keys=True))
    return 0 if value.get('status')=='verified'else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--start-owned',action='store_true')
    mode.add_argument('--collect-owned',type=Path)
    mode.add_argument('--supervisor',type=Path,help=argparse.SUPPRESS)
    mode.add_argument('--network-controller',type=Path,help=argparse.SUPPRESS)
    parser.add_argument('--case',choices=('bootstrap','partial','deadline','confirmed',
                                        'complete-candidate','complete-baseline'))
    args=parser.parse_args()
    base.require(bool(args.case)==args.start_owned,'case_only_for_start')
    if args.start_owned:
        return start(args.case)
    if args.collect_owned:
        return collect(args.collect_owned)
    if args.network_controller:
        return backend.network_controller(args.network_controller)
    return supervisor(args.supervisor)


if __name__=='__main__':
    raise SystemExit(main())
