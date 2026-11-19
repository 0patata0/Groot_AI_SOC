#!/usr/bin/env python3
"""Opt-in three private PID-1 managers, without any production service changes.

This is the native isolation foundation for the full coordinator integration.
It does NOT claim Lifecycle.recover, peer SSH, Docker lifecycle, host reboot,
operating deployment, or MCP/bot acceptance. No injected native backend is used.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LANG': 'C', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1',
       'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'}
NS = ('user', 'mnt', 'pid', 'net', 'uts', 'ipc', 'cgroup')
LIBC = ctypes.CDLL(None, use_errno=True)
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE, MS_SHARED = 32, 4096, 16384, 1 << 18, 1 << 20
NEWUSER, NEWNS, NEWCGROUP = 0x10000000, 0x00020000, 0x02000000
NEWUTS, NEWIPC, NEWPID = 0x04000000, 0x08000000, 0x20000000


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def new_file(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def command(argv, *, timeout=10, check=True):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=timeout)
    require(len(result.stdout) <= 65536 and len(result.stderr) <= 8192, 'command_output_bound')
    if check:
        require(result.returncode == 0, 'command_failed_' + Path(argv[0]).name + '_' +
                result.stderr.decode(errors='replace')[:180])
    return result


def mount(source, target, fs=None, flags=0, data=None):
    def encoded(value):
        return None if value is None else os.fsencode(value)
    result = LIBC.mount(encoded(source), encoded(target), encoded(fs), ctypes.c_ulong(flags), encoded(data))
    if result:
        raise OSError(ctypes.get_errno(), 'private_mount_' + str(target))


def unshare(flags):
    if LIBC.unshare(flags):
        raise OSError(ctypes.get_errno(), 'private_unshare')


def namespaces(pid='self'):
    return {name: os.readlink('/proc/' + str(pid) + '/ns/' + name) for name in NS}


def pins():
    manifest_raw = (HERE / 'coordinator-manifest.json').read_bytes()
    manifest = json.loads(manifest_raw)
    witness_raw = (HERE / 'witness-manifest.json').read_bytes()
    require(sha(witness_raw) == manifest['witness_manifest_sha256'], 'witness_manifest_changed')
    witness = json.loads(witness_raw)
    values = {**witness['source_sha256'], **manifest['dependencies_sha256'], **manifest['source_sha256']}
    require(len(values) == 42 and all(sha((HERE / name).read_bytes()) == digest
                                     for name, digest in values.items()), 'candidate_pins_changed')
    return values


def own_root(value):
    path = Path(value)
    require(path.parent == Path('/run') and re.fullmatch('capstone-pid1-[0-9a-f]{12}', path.name), 'workspace_scope')
    item = path.lstat()
    require(stat.S_ISDIR(item.st_mode) and item.st_uid == item.st_gid == 0 and
            stat.S_IMODE(item.st_mode) == 0o700, 'workspace_metadata')
    marker = json.loads((path / 'owner.json').read_text())
    require(marker['workspace'] == str(path) and marker['unit'] == path.name + '.service' and
            marker['validator_sha256'] == sha(Path(__file__).read_bytes()), 'workspace_identity')
    return path, marker


PROBE = r'''
import ctypes,hashlib,importlib.util,json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/');out=pathlib.Path('/proof');role=pathlib.Path('/etc/capstone-proof-role').read_text().strip()
def need(v,r):
    if not v:raise RuntimeError(r)
def run(args,check=True):
    p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12,
      env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','PYTHONDONTWRITEBYTECODE':'1'})
    need(len(p.stdout)<65536 and len(p.stderr)<8192,'output_bound')
    if check:need(p.returncode==0,'command_failed_'+p.stderr.decode(errors='replace')[:128])
    return p
def properties(unit):
    p=run(['/usr/bin/systemctl','show',unit,'--property=Id,ActiveState,SubState,MainPID,Result,ExecMainStatus,MemoryMax,TasksMax,FragmentPath'])
    return dict(line.split('=',1)for line in p.stdout.decode().splitlines())
try:
    before=json.loads((out/'parent.json').read_text())
    names={k:os.readlink('/proc/self/ns/'+k)for k in ('user','mnt','pid','net','uts','ipc','cgroup')}
    need(all(names[k]!=before[k]for k in names),'namespace_separation')
    need(pathlib.Path('/proc/1/comm').read_text().strip()=='systemd','real_systemd_pid1')
    need(os.getuid()==os.geteuid()==0,'inner_root')
    need(pathlib.Path('/proc/self/uid_map').read_text().split()==['0','0','65536'],'uid_map')
    need(pathlib.Path('/proc/self/gid_map').read_text().split()==['0','0','65536'],'gid_map')
    need(set(p.name for p in pathlib.Path('/sys/class/net').iterdir())=={'lo'},'private_loopback_only')
    need(pathlib.Path('/proc/1/cgroup').read_text().strip()=='0::/init.scope','private_cgroup_root')
    # The inherited read-only bind cannot be made writable by inner root.
    libc=ctypes.CDLL(None,use_errno=True)
    rc=libc.mount(None,b'/usr/lib',None,ctypes.c_ulong(32|4096),None)
    remount_errno=ctypes.get_errno()
    need(rc==-1 and remount_errno in (1,13),'readonly_usr_lock')
    need(not pathlib.Path('/root/.ssh').exists() and not pathlib.Path('/etc/mcp').exists(),'no_host_credentials')
    p=run(['/usr/bin/systemctl','start','capstone-proof-sandbox.service'])
    sandbox=properties('capstone-proof-sandbox.service')
    need(sandbox['Result']=='success'and sandbox['ExecMainStatus']=='0','native_sandbox_service')
    need(sandbox['MemoryMax']==str(64*1024*1024)and sandbox['TasksMax']=='8','native_resources')
    p=run(['/usr/bin/systemctl','start','capstone-proof-tick.timer'])
    end=time.monotonic()+12
    while not (out/'timer-fired.json').exists():
        need(time.monotonic()<end,'timer_deadline');time.sleep(.1)
    fired=json.loads((out/'timer-fired.json').read_text())
    need(fired['pid']!=os.getpid(),'independent_timer_process')
    code=pathlib.Path('/opt/pid1-proof/code')
    manifest=json.loads((out/'pins.json').read_text())
    need(all(hashlib.sha256((code/name).read_bytes()).hexdigest()==digest for name,digest in manifest.items()),'unchanged_42_sources')
    # Default Native runs real systemctl in this role's filesystem and PID 1.
    spec=importlib.util.spec_from_file_location('private_native',code/'release_services.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    native=mod.Native('c',None)
    need(native.fixture is False and native.runner is None and str(native.root)=='/','default_native_boundary')
    snapshot=native.snapshot();native.collection_resources(release_dropins=False)
    report={'schema':1,'status':'verified','role':role,'private_pid1':True,'actual_systemd':True,
      'default_native_backend':True,'native_C_collection_units':len(snapshot),'source_pins_verified':len(manifest),
      'namespaces':names,'systemd_pid1':1,'probe_pid':os.getpid(),'sandbox':sandbox,'timer':fired,
      'python_version':sys.version.split()[0],
      'systemd_version':run(['/usr/bin/systemctl','--version']).stdout.decode().splitlines()[0],
      'machine_id_sha256':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest(),
      'visible_interfaces':['lo'],'pid1_cgroup':pathlib.Path('/proc/1/cgroup').read_text().strip(),
      'read_only_usr_remount_errno':remount_errno,'production_root_entry':False,'lifecycle_recover':False,
      'peer_SSH':False,'docker_lifecycle':False,'actual_host_reboot':False,'operating_deployment':False}
except Exception as e:
    report={'schema':1,'status':'failed','role':role,'reason':type(e).__name__+':'+str(e)[:256]}
tmp=out/'report.tmp';tmp.write_text(json.dumps(report,sort_keys=True));os.replace(tmp,out/'report.json')
raise SystemExit(0 if report['status']=='verified'else 1)
'''


def populate(root, role, source, output, pinmap):
    root.mkdir(mode=0o755)
    for name in ('etc/systemd/system', 'etc/ssh', 'var/lib', 'run', 'tmp', 'proc', 'sys', 'dev/pts',
                 'dev/shm', 'usr/bin', 'usr/sbin', 'usr/lib', 'usr/share/zoneinfo', 'opt/pid1-proof/code',
                 'proof', 'oldroot'):
        (root / name).mkdir(parents=True, exist_ok=True)
    for name, target in (('bin', 'usr/bin'), ('sbin', 'usr/sbin'), ('lib', 'usr/lib'), ('lib64', 'usr/lib64')):
        (root / name).symlink_to(target)
    if Path('/usr/lib64').is_symlink():
        (root / 'usr/lib64').symlink_to(os.readlink('/usr/lib64'))
    elif Path('/usr/lib64').is_dir():
        (root / 'usr/lib64').mkdir()
    new_file(root / 'etc/machine-id', (uuid.uuid4().hex + '\n').encode(), 0o444)
    new_file(root / 'etc/hostname', ('capstone-proof-' + role + '\n').encode(), 0o644)
    new_file(root / 'etc/capstone-proof-role', (role + '\n').encode(), 0o644)
    new_file(root / 'etc/passwd', b'root:x:0:0:root:/root:/bin/sh\ncapstone-diagnostics:x:50123:50123:fixture:/nonexistent:/bin/false\nmcp:x:50124:50124:fixture:/nonexistent:/bin/false\n', 0o644)
    new_file(root / 'etc/group', b'root:x:0:\ncapstone-diagnostics:x:50123:mcp\nmcp:x:50124:\nnogroup:x:65534:\n', 0o644)
    new_file(root / 'etc/nsswitch.conf', b'passwd: files\ngroup: files\nshadow: files\nhosts: files\n', 0o644)
    new_file(root / 'etc/hosts', b'127.0.0.1 localhost\n', 0o644)
    new_file(root / 'etc/os-release', b'ID=capstone-proof\nNAME="Private coordinator fixture"\n', 0o644)
    new_file(root / 'etc/systemd/system.conf', b'[Manager]\nDefaultStandardOutput=null\nDefaultStandardError=null\nDefaultTimeoutStopSec=5s\nLogLevel=warning\n', 0o644)
    for name, digest in pinmap.items():
        raw = (source / name).read_bytes()
        require(sha(raw) == digest, 'source_copy_changed')
        new_file(root / 'opt/pid1-proof/code' / name, raw)
    new_file(root / 'opt/pid1-proof/probe.py', PROBE.encode(), 0o644)
    new_file(root / 'opt/pid1-proof/tick.py', b'import json,os,pathlib,time\np=pathlib.Path("/proof/timer-fired.json");p.write_text(json.dumps({"pid":os.getpid(),"monotonic_ns":time.monotonic_ns()}))\n', 0o644)
    units = root / 'etc/systemd/system'
    new_file(units / 'capstone-proof.target', b'[Unit]\nDescription=Private coordinator integration foundation\nDefaultDependencies=no\nRequires=capstone-proof.service\nAfter=capstone-proof.service\n', 0o644)
    (units / 'default.target').symlink_to('capstone-proof.target')
    for name in ('systemd-journald.service', 'systemd-journald.socket', 'systemd-journald-dev-log.socket',
                 'systemd-journald-audit.socket', 'systemd-udevd.service', 'systemd-logind.service',
                 'systemd-tmpfiles-setup.service', 'systemd-sysctl.service'):
        (units / name).symlink_to('/dev/null')
    new_file(units / 'capstone-proof.service', b'[Unit]\nDefaultDependencies=no\nBefore=capstone-proof.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 -IB /opt/pid1-proof/probe.py\nTimeoutStartSec=30s\nStandardOutput=file:/proof/probe.stdout\nStandardError=file:/proof/probe.stderr\n', 0o644)
    new_file(units / 'capstone-proof-sandbox.service', b'[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\nUser=root\nGroup=capstone-diagnostics\nNoNewPrivileges=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\nProtectKernelTunables=yes\nProtectControlGroups=yes\nProtectClock=yes\nRestrictAddressFamilies=AF_UNIX\nMemoryAccounting=yes\nMemoryMax=64M\nTasksAccounting=yes\nTasksMax=8\nTimeoutStartSec=10s\n', 0o644)
    new_file(units / 'capstone-proof-tick.service', b'[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -IB /opt/pid1-proof/tick.py\n', 0o644)
    new_file(units / 'capstone-proof-tick.timer', b'[Unit]\nDefaultDependencies=no\n[Timer]\nOnActiveSec=1s\nAccuracySec=100ms\nUnit=capstone-proof-tick.service\n', 0o644)
    # Real default-root Native validates this unchanged C catalog in each manager.
    new_file(units / 'capstone-journal-reader.service', b'[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\nMemoryAccounting=yes\nMemoryMax=128M\nTasksAccounting=yes\nTasksMax=8\nLimitNOFILE=1024\nKillMode=control-group\nTimeoutStopSec=5s\n', 0o644)
    for name, timeout in (('capstone-system-diagnostics.service', '85s'), ('capstone-diagnostic-history-backfill.service', '150s')):
        new_file(units / name, ('[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\nMemoryAccounting=yes\nMemoryHigh=192M\nMemoryMax=256M\nMemorySwapMax=0\nTasksAccounting=yes\nTasksMax=64\nLimitNOFILE=1024\nKillMode=control-group\nTimeoutStartSec=' + timeout + '\nTimeoutStopSec=5s\n').encode(), 0o644)
    new_file(units / 'capstone-system-diagnostics.service.d/30-inventory-netlink.conf', b'[Service]\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n', 0o644)
    new_file(units / 'capstone-system-diagnostics.timer', b'[Unit]\nDefaultDependencies=no\n[Timer]\nOnActiveSec=1h\nUnit=capstone-system-diagnostics.service\n', 0o644)
    new_file(output / 'pins.json', json.dumps(pinmap).encode())


def child_manager(root, output, cgroup, ready, acknowledge):
    try:
        # All changes below occur only in this own child's mount namespace.
        (cgroup / 'cgroup.procs').write_text(str(os.getpid()))
        unshare(NEWNS)
        mount(None, '/', flags=MS_PRIVATE | MS_REC)
        mount(root, root, flags=MS_BIND)
        for name in ('bin', 'sbin', 'lib', 'lib64'):
            origin = Path('/usr') / name
            destination = root / 'usr' / name
            if origin.is_dir() and not destination.is_symlink():
                mount(origin, destination, flags=MS_BIND)
                mount(None, destination, flags=MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID)
        mount('/usr/share/zoneinfo', root / 'usr/share/zoneinfo', flags=MS_BIND)
        mount(None, root / 'usr/share/zoneinfo', flags=MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
        mount('sysfs', root / 'sys', fs='sysfs', flags=MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)
        mount('tmpfs', root / 'dev', fs='tmpfs', flags=MS_NOSUID, data='mode=755,size=4m')
        for name in ('null', 'zero', 'full', 'random', 'urandom', 'tty'):
            target = root / 'dev' / name
            target.touch()
            mount('/dev/' + name, target, flags=MS_BIND)
        for name in ('pts', 'shm'):
            (root / 'dev' / name).mkdir()
        (root / 'dev/ptmx').symlink_to('pts/ptmx')
        (root / 'dev/fd').symlink_to('/proc/self/fd')
        for num, name in enumerate(('stdin', 'stdout', 'stderr')):
            (root / 'dev' / name).symlink_to('/proc/self/fd/' + str(num))
        mount('tmpfs', root / 'run', fs='tmpfs', flags=MS_NOSUID | MS_NODEV, data='mode=755,size=24m')
        mount('tmpfs', root / 'tmp', fs='tmpfs', flags=MS_NOSUID | MS_NODEV, data='mode=1777,size=8m')
        mount(output, root / 'proof', flags=MS_BIND)
        unshare(NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWPID)
        pid = os.fork()
        if pid:
            # The outside-PID wrapper must not occupy the delegated root when
            # PID 1 enables controllers. Lifetime is owned by the outer cgroup.
            os._exit(0)
        end = time.monotonic() + 3
        while len((cgroup / 'cgroup.procs').read_text().split()) != 1:
            require(time.monotonic() < end, 'outside_pid_wrapper_remained')
            time.sleep(.01)
        host_pid = int(os.readlink('/proc/self'))
        # The manager prepares the new PID namespace's procfs before lowering
        # privilege. A less privileged mount namespace must retain the outer
        # service's procfs restrictions instead of mounting a fresh unmasked one.
        mount('proc', root / 'proc', fs='proc', flags=MS_NOSUID | MS_NODEV | MS_NOEXEC)
        for name in ('sys', 'fs', 'irq', 'bus'):
            path = root / 'proc' / name
            if path.is_dir():
                mount(path, path, flags=MS_BIND)
                mount(None, path, flags=MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)
        for name in ('kcore', 'keys', 'timer_list', 'sysrq-trigger', 'kmsg'):
            path = root / 'proc' / name
            if path.exists():
                mount('/dev/null', path, flags=MS_BIND)
        mount('cgroup2', root / 'sys/fs/cgroup', fs='cgroup2', flags=MS_NOSUID | MS_NODEV | MS_NOEXEC)
        mount('devpts', root / 'dev/pts', fs='devpts', flags=MS_NOSUID | MS_NOEXEC, data='newinstance,ptmxmode=0666,mode=0620')
        mount('tmpfs', root / 'dev/shm', fs='tmpfs', flags=MS_NOSUID | MS_NODEV, data='mode=1777,size=8m')
        require(LIBC.sethostname(b'capstone-private-pid1', 21) == 0, 'private_hostname')
        unshare(NEWUSER)
        os.write(ready, (str(host_pid) + '\n').encode())
        os.close(ready)
        require(os.read(acknowledge, 1) == b'1', 'mapping_parent_ack')
        os.close(acknowledge)
        unshare(NEWNS)
        os.chroot(root)
        os.chdir('/')
        output = Path('/proof')
        mount(None, '/', flags=MS_SHARED | MS_REC)
        descriptor = os.open('/proof/systemd.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.dup2(descriptor, 1)
        os.dup2(descriptor, 2)
        os.close(descriptor)
        os.closerange(3, 65536)
        environment = {**ENV, 'container': 'capstone', 'SYSTEMD_LOG_TARGET': 'console',
                       'SYSTEMD_LOG_LEVEL': 'warning', 'SYSTEMD_COLORS': '0'}
        os.execve('/usr/lib/systemd/systemd', ['/usr/lib/systemd/systemd', '--system', '--unit=capstone-proof.target'], environment)
    except BaseException as error:
        try:
            new_file(output / 'boot-error.json', json.dumps({'error': type(error).__name__, 'reason': str(error)[:256]}).encode())
        except BaseException:
            pass
        os._exit(1)


def supervisor(workspace):
    root, owner = own_root(workspace)
    pinmap = pins()
    own_cg = Path('/proc/self/cgroup').read_text().strip()
    require(own_cg.startswith('0::/') and own_cg.endswith('/' + owner['unit'] + '/supervisor'), 'delegated_supervisor_cgroup')
    group = Path('/sys/fs/cgroup') / own_cg[4:].lstrip('/')
    delegated = group.parent
    require(delegated.name == owner['unit'] and not (delegated / 'cgroup.procs').read_text().strip(), 'empty_delegated_parent')
    available = set((delegated / 'cgroup.controllers').read_text().split())
    require({'cpu', 'memory', 'pids'} <= available, 'required_controllers_delegated')
    (delegated / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
    host_ns = owner['parent_namespaces']
    private_net = namespaces()['net']
    require(private_net != host_ns['net'], 'outer_private_network')
    interfaces = command(['/usr/sbin/ip', '-j', 'link']).stdout
    require({x['ifname'] for x in json.loads(interfaces)} == {'lo'}, 'outer_network_has_foreign_interface')
    command(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'])
    children = {}
    report = {'schema': 1, 'scope': 'three_private_PID1_managers_and_default_native_C_catalog',
              'production_unit_changes': 0, 'production_source_cache_changes': 0,
              'package_installations': 0, 'operating_deployment': False, 'lifecycle_recover': False,
              'actual_host_reboot': False, 'peer_SSH': False, 'docker_lifecycle': False,
              'private_net': private_net, 'candidate_pins_verified': len(pinmap), 'roles': {}}
    try:
        for role in 'abc':
            output = root / 'outputs' / role
            output.mkdir(parents=True, mode=0o700)
            new_file(output / 'parent.json', json.dumps(host_ns).encode())
            role_root = root / 'roots' / role
            populate(role_root, role, HERE, output, pinmap)
            cgroup = delegated / ('role-' + role)
            cgroup.mkdir()
            ready_r, ready_w = os.pipe()
            ack_r, ack_w = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(ready_r)
                os.close(ack_w)
                child_manager(role_root, output, cgroup, ready_w, ack_r)
            children[role] = {'pid': child, 'cgroup': cgroup, 'output': output}
            os.close(ready_w)
            os.close(ack_r)
            ready = os.read(ready_r, 32)
            os.close(ready_r)
            require(re.fullmatch(rb'[0-9]{1,10}\n', ready), 'private_manager_mapping_not_ready_' + role)
            inner_pid = int(ready)
            require(Path('/proc/' + str(inner_pid) + '/cgroup').read_text().strip().endswith('/' + owner['unit'] + '/role-' + role),
                    'mapping_child_not_in_owned_cgroup')
            children[role]['host_pid1'] = inner_pid
            for name in ('uid_map', 'gid_map'):
                Path('/proc/' + str(inner_pid) + '/' + name).write_text('0 0 65536\n')
            os.write(ack_w, b'1')
            os.close(ack_w)
        end = time.monotonic() + 45
        while len(report['roles']) != 3:
            for role, item in children.items():
                result = item['output'] / 'report.json'
                error = item['output'] / 'boot-error.json'
                if result.exists():
                    report['roles'][role] = json.loads(result.read_text())
                if error.exists():
                    raise RuntimeError('private_boot_failed_' + role + '_' + error.read_text()[:256])
                if not result.exists() and 'populated 0' in (item['cgroup'] / 'cgroup.events').read_text():
                    raise RuntimeError('private_pid1_terminal_before_report_' + role)
            require(time.monotonic() < end, 'private_managers_observation_deadline')
            time.sleep(.1)
        require(all(x['status'] == 'verified' for x in report['roles'].values()), 'private_role_probe_failed')
        unique_user = {x['namespaces']['user'] for x in report['roles'].values()}
        unique_pid = {x['namespaces']['pid'] for x in report['roles'].values()}
        unique_mnt = {x['namespaces']['mnt'] for x in report['roles'].values()}
        machine_ids = {x['machine_id_sha256'] for x in report['roles'].values()}
        require(len(unique_user) == len(unique_pid) == len(unique_mnt) == len(machine_ids) == 3, 'roles_must_have_distinct_namespaces')
        report['status'] = 'verified'
    except Exception as error:
        report.update(status='failed', reason=type(error).__name__ + ':' + str(error)[:512])
    finally:
        for item in children.values():
            kill = item['cgroup'] / 'cgroup.kill'
            if kill.exists():
                kill.write_text('1')
        for item in children.values():
            try:
                os.waitpid(item['pid'], 0)
            except ChildProcessError:
                pass
        end = time.monotonic() + 5
        while any('populated 1' in (item['cgroup'] / 'cgroup.events').read_text() for item in children.values()):
            require(time.monotonic() < end, 'private_children_termination_deadline')
            time.sleep(.02)
        report['role_cgroups_populated_after_kill'] = {
            role: 'populated 0' not in (item['cgroup'] / 'cgroup.events').read_text()
            for role, item in children.items()}
        require(not any(report['role_cgroups_populated_after_kill'].values()), 'private_children_remained')
        report['outer_memory_peak_bytes'] = int((delegated / 'memory.peak').read_text())
        report['outer_memory_events'] = dict(line.split() for line in (delegated / 'memory.events').read_text().splitlines())
        report['outer_pids_peak'] = int((delegated / 'pids.peak').read_text())
        new_file(root / 'supervisor-report.json', json.dumps(report, sort_keys=True).encode())
    return 0 if report['status'] == 'verified' else 1


def run_owned():
    require(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0, 'linux_root_required')
    require(Path('/run/systemd/system').is_dir(), 'host_system_manager_required')
    pinmap = pins()
    root = Path(tempfile.mkdtemp(prefix='capstone-pid1-', dir='/run'))
    # tempfile suffix is platform-dependent; the explicit UUID is the only accepted name.
    desired = Path('/run') / ('capstone-pid1-' + uuid.uuid4().hex[:12])
    os.rename(root, desired)
    root = desired
    os.chmod(root, 0o700)
    unit = root.name + '.service'
    owner = {'workspace': str(root), 'unit': unit, 'validator_sha256': sha(Path(__file__).read_bytes()),
             'parent_namespaces': namespaces(), 'pid': os.getpid()}
    new_file(root / 'owner.json', json.dumps(owner).encode())
    for name in (*pinmap, 'coordinator-manifest.json', 'witness-manifest.json', Path(__file__).name):
        new_file(root / 'code' / name, (HERE / name).read_bytes())
    (root / 'roots').mkdir(mode=0o700)
    reports = {}
    start_attempted = False
    try:
        absent = command(['/usr/bin/systemctl', 'show', unit, '--property=LoadState'], check=False)
        require(absent.stdout.decode().strip() == 'LoadState=not-found', 'owned_unit_name_collision')
        args = ['/usr/bin/systemd-run', '--quiet', '--unit=' + unit, '--service-type=exec',
                '--property=Delegate=yes', '--property=DelegateSubgroup=supervisor',
                '--property=MemoryAccounting=yes', '--property=MemoryMax=512M', '--property=MemorySwapMax=0',
                '--property=TasksAccounting=yes', '--property=TasksMax=256', '--property=CPUQuota=100%',
                '--property=RuntimeMaxSec=75s', '--property=TimeoutStopSec=5s', '--property=KillMode=control-group',
                '--property=PrivateNetwork=yes', '--property=PrivateTmp=yes', '--property=PrivateDevices=yes',
                '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict',
                '--property=ReadWritePaths=' + str(root), '--property=ProtectHome=yes',
                '--property=ProtectKernelTunables=yes', '--property=ProtectKernelModules=yes',
                '--property=ProtectClock=yes', '--property=LockPersonality=yes',
                '--property=StandardOutput=file:' + str(root / 'outer.log'), '--property=StandardError=inherit',
                '/usr/bin/python3', '-I', '-B', str(root / 'code' / Path(__file__).name),
                '--supervisor', str(root)]
        start_attempted = True
        command(args)
        boundary_keys = ('LoadState', 'Transient', 'MemoryMax', 'MemorySwapMax', 'TasksMax',
                         'CPUQuotaPerSecUSec', 'RuntimeMaxUSec', 'Delegate', 'DelegateSubgroup',
                         'PrivateNetwork', 'PrivateDevices', 'NoNewPrivileges', 'ProtectSystem',
                         'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectClock',
                         'ReadWritePaths', 'KillMode', 'TimeoutStopUSec')
        boundary_raw = command(['/usr/bin/systemctl', 'show', unit, '--property=' + ','.join(boundary_keys)]).stdout
        boundaries = dict(line.split('=', 1) for line in boundary_raw.decode().splitlines())
        require(boundaries['LoadState'] == 'loaded' and boundaries['Transient'] == 'yes' and
                boundaries['MemoryMax'] == str(512 * 1024 * 1024) and boundaries['MemorySwapMax'] == '0' and
                boundaries['TasksMax'] == '256' and boundaries['RuntimeMaxUSec'] == '1min 15s' and
                boundaries['Delegate'] == 'yes' and boundaries['DelegateSubgroup'] == 'supervisor' and
                all(boundaries[k] == 'yes' for k in ('PrivateNetwork', 'PrivateDevices', 'NoNewPrivileges',
                    'ProtectKernelTunables', 'ProtectKernelModules', 'ProtectClock')) and
                boundaries['ProtectSystem'] == 'strict' and boundaries['ReadWritePaths'] == str(root) and
                boundaries['KillMode'] == 'control-group', 'outer_loaded_boundary_mismatch')
        end = time.monotonic() + 65
        while not (root / 'supervisor-report.json').exists():
            require(time.monotonic() < end, 'host_supervisor_observation_deadline')
            state = command(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,SubState,ExecMainStatus']).stdout.decode()
            if 'ActiveState=failed' in state or 'ActiveState=inactive' in state:
                raise RuntimeError('host_supervisor_terminal_before_report_' + state.replace('\n', '_'))
            time.sleep(.2)
        reports = json.loads((root / 'supervisor-report.json').read_text())
        reports['outer_loaded_boundaries'] = boundaries
    except Exception as error:
        reports.update(schema=1, status='failed', reason=type(error).__name__ + ':' + str(error)[:512])
    finally:
        if start_attempted:
            # A lost/failed start response is not proof that no service started.
            reports['owned_termination_requested'] = True
            command(['/usr/bin/systemctl', 'stop', unit], timeout=12, check=False)
            state = command(['/usr/bin/systemctl', 'show', unit,
                             '--property=LoadState,ActiveState,SubState,Result,MainPID,ExecMainStatus,ControlGroup'], check=False)
            reports['outer_final_state'] = state.stdout.decode()
            final = dict(line.split('=', 1) for line in state.stdout.decode().splitlines())
            require(final.get('ActiveState') in ('inactive', 'failed') and final.get('MainPID', '0') == '0' and
                    final.get('ControlGroup', '') == '', 'owned_supervisor_still_live_workspace_preserved')
            command(['/usr/bin/systemctl', 'reset-failed', unit], check=False)
        reports['workspace'] = str(root)
        reports['unit'] = unit
        reports['diagnostics'] = {}
        for path in sorted(root.glob('outputs/*/*')):
            if path.name in ('systemd.log', 'boot-error.json', 'report.json', 'probe.stderr'):
                raw = path.read_bytes()
                reports['diagnostics'][str(path.relative_to(root))] = raw.decode(errors='replace')[-6000:]
        if (root / 'outer.log').exists():
            reports['diagnostics']['outer.log'] = (root / 'outer.log').read_text(errors='replace')[-8000:]
        # Do not recurse through any mount; refusal leaves an owned, identified path.
        mounted = [line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()
                   if line.split()[4] == str(root) or line.split()[4].startswith(str(root) + '/')]
        require(not mounted, 'owned_mounts_remained_in_host_namespace')
        cleanup_files = {str(path.relative_to(root)): sha(path.read_bytes()) for path in root.rglob('*') if path.is_file() and not path.is_symlink()}
        reports['removed_owned_file_count'] = len(cleanup_files)
        reports['removed_owned_files_sha256'] = cleanup_files
        shutil.rmtree(root)
        reports['workspace_removed'] = not root.exists()
        require(namespaces() == owner['parent_namespaces'], 'host_namespaces_changed')
        reports['host_namespaces_unchanged'] = True
        reports['candidate_pins_verified_after'] = len(pins())
    print(json.dumps(reports, sort_keys=True))
    return 0 if reports.get('status') == 'verified' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-owned-units', action='store_true')
    parser.add_argument('--supervisor', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    require(args.run_owned_units != bool(args.supervisor), 'explicit_one_operation_required')
    return supervisor(args.supervisor) if args.supervisor else run_owned()


if __name__ == '__main__':
    raise SystemExit(main())
