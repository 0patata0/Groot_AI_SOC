"""Runs only inside one test-owned PID namespace; never on an operating host."""
from datetime import datetime
from zoneinfo import ZoneInfo
import hashlib
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

OUT = Path('/proof')
ROLE = Path('/etc/capstone-proof-role').read_text().strip()
ENV = {'PATH': '/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin', 'LANG': 'C',
       'PYTHONDONTWRITEBYTECODE': '1', 'DOCKER_CONFIG': '/nonexistent',
       'DOCKER_HOST': 'unix:///var/run/docker.sock', 'SYSTEMD_PAGER': ''}


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def run(args, *, data=None, timeout=12, check=True, identity=None):
    options = {} if identity is None else {'user': identity, 'group': identity, 'extra_groups': []}
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=timeout, **options)
    need(len(result.stdout) < 65536 and len(result.stderr) < 16384, 'output_bound')
    if check:
        need(result.returncode == 0, 'command_failed_' + Path(args[0]).name + '_' + result.stderr.decode(errors='replace')[:300])
    return result


def properties(unit):
    raw = run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,MainPID,Result,ExecMainStatus']).stdout
    return dict(line.split('=', 1) for line in raw.decode().splitlines())


def ssh_command(role, known='/etc/ssh/known_hosts'):
    address = '198.18.0.' + str(11 + 'abc'.index(role))
    return ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', '44222',
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'PermitLocalCommand=no', '-o', 'ConnectTimeout=2',
            '-o', 'ConnectionAttempts=1', '-o', 'UserKnownHostsFile=' + known,
            '-i', '/etc/ssh/client_ed25519', 'capstone-diagnostics@' + address]


def ssh_peer(role):
    args = ssh_command(role)
    end = time.monotonic() + 8
    while True:
        result = run(args, timeout=4, check=False, identity=50124 if ROLE == 'b' else None)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            need(value['role'] == role and value['uid'] == 50123 and value['pid'] > 1, 'peer_identity')
            return value
        need(time.monotonic() < end, 'peer_SSH_unavailable_' + role + '_' + result.stderr.decode(errors='replace')[:180])
        time.sleep(.15)


def docker_container():
    need(not Path('/var/run/docker.sock').exists(), 'foreign_socket_present')
    run(['/usr/bin/systemctl', 'start', 'docker.service'])
    end = time.monotonic() + 15
    while True:
        result = run(['/usr/local/bin/docker', 'info', '--format', '{{.DockerRootDir}}'], check=False)
        if result.returncode == 0:
            need(result.stdout.strip() == b'/var/lib/docker', 'private_docker_root')
            break
        need(time.monotonic() < end, 'private_docker_not_ready')
        need(properties('docker.service')['ActiveState'] == 'active', 'private_docker_terminal')
        time.sleep(.15)
    # Existing static busybox is the only image content. No host image store,
    # registry, cache, credentials, or operating container is reused.
    binary = Path('/usr/bin/busybox').read_bytes()
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as stream:
        info = tarfile.TarInfo('busybox')
        info.mode = 0o755
        info.size = len(binary)
        stream.addfile(info, io.BytesIO(binary))
    image = run(['/usr/local/bin/docker', 'import', '-', 'capstone-private-proof:owned'], data=archive.getvalue()).stdout.decode().strip()
    cid = run(['/usr/local/bin/docker', 'run', '-d', '--name', 'capstone-private-owned',
               '--network', 'host', '--restart', 'unless-stopped', '--memory', '64m', '--pids-limit', '16',
               '--pid', 'host',
               '--mount', 'type=bind,src=/proc,dst=/proc,readonly',
               '--mount', 'type=bind,src=/sys,dst=/sys,readonly',
               '--mount', 'type=bind,src=/usr/bin/busybox,dst=/busybox,readonly',
               '--security-opt', 'apparmor=unconfined', '--entrypoint', '/busybox', image, 'sleep', '300'], timeout=15).stdout.decode().strip()
    return {'id': cid, 'image': image, 'restart': 'unless-stopped', 'running': True}, hashlib.sha256(binary).hexdigest()


report = {'schema': 1, 'role': ROLE, 'at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
          'lifecycle_recover': False, 'production_root_entry': False,
          'actual_host_reboot': False, 'operating_deployment': False}
try:
    need(os.getuid() == os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd', 'private_PID1_required')
    need(Path('/proc/self/uid_map').read_text().split() == ['0', '0', '65536'], 'private_user_mapping')
    need(not Path('/root/.ssh').exists() and not Path('/etc/mcp').exists(), 'no_operating_credentials')
    libc = ctypes.CDLL(None, use_errno=True)
    remount = libc.mount(None, b'/usr/local/bin', None, ctypes.c_ulong(32 | 4096), None)
    report['readonly_local_bin_remount_errno'] = ctypes.get_errno()
    need(remount == -1 and report['readonly_local_bin_remount_errno'] in (1, 13), 'readonly_extra_binaries_locked')
    run(['/usr/bin/systemctl', 'start', 'capstone-private-ssh.service'])
    report['ssh_server'] = properties('capstone-private-ssh.service')
    need(report['ssh_server']['ActiveState'] == 'active', 'SSH_server_not_active')
    if ROLE in ('a', 'b'):
        report['peers'] = {role: ssh_peer(role) for role in 'abc' if role != ROLE}
        report['peer_ssh_verified'] = len(report['peers']) == 2
        report['ssh_client_uid'] = 50124 if ROLE == 'b' else 0
        if ROLE == 'a':
            rejected = run(ssh_command('b', '/etc/ssh/wrong_known_hosts'), timeout=4, check=False)
            need(rejected.returncode != 0 and not rejected.stdout and
                 b'Host key verification failed' in rejected.stderr, 'wrong_host_key_must_be_denied')
            report['wrong_host_key_denied'] = True
    else:
        # C owns no client key; its server is exercised by both peer clients.
        report['peer_ssh_verified'] = True
        report['peer_client_key_present'] = Path('/etc/ssh/client_ed25519').exists()
        need(not report['peer_client_key_present'], 'C_client_key_not_required')
    container = None
    if ROLE == 'b':
        container, report['busybox_sha256'] = docker_container()
        report['container_isolation_fixture'] = {
            'pid_namespace': 'shares only this private B-role PID namespace',
            'network_namespace': 'shares only the user-owned private B network connected to the test-private outer network',
            'proc_sys': 'read-only binds of this private root with inherited masks retained',
            'operating_host_namespace_or_socket_shared': False,
            'privileged_container': False,
            'entrypoint': 'read-only existing /usr/bin/busybox; copied image bytes remain in the owned workspace',
        }
        report['image_workspace_noexec'] = bool(os.statvfs('/var/lib/docker').f_flag & os.ST_NOEXEC)
    spec = importlib.util.spec_from_file_location('actual_private_native', '/opt/pid1-proof/code/release_services.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    native = module.Native(ROLE, container)
    need(native.fixture is False and native.runner is None and str(native.root) == '/', 'default_native_required')
    snapshot = native.snapshot()
    native.collection_resources(release_dropins=False)
    report['native_catalog_units'] = len(snapshot)
    report['default_native_backend'] = True
    if ROLE == 'b':
        report['container_baseline'] = native.require_original_container()
        pid = report['container_baseline']['pid']
        configuration = run(['/usr/local/bin/docker', 'inspect', '--format',
            '{"memory":{{json .HostConfig.Memory}},"pids":{{json .HostConfig.PidsLimit}},"privileged":{{json .HostConfig.Privileged}},"pid_mode":{{json .HostConfig.PidMode}},"network":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}}}', container['id']])
        configuration = json.loads(configuration.stdout)
        need(configuration['memory'] == 64 * 1024 * 1024 and configuration['pids'] == 16
             and configuration['privileged'] is False and configuration['pid_mode'] == 'host'
             and configuration['network'] == 'host', 'container_fixture_limits')
        mounted = {row['Destination']: row for row in configuration['mounts']}
        need(set(mounted) == {'/proc', '/sys', '/busybox'} and all(row['RW'] is False for row in mounted.values()),
             'only_readonly_fixture_mounts')
        status = dict(line.split(':', 1) for line in Path('/proc/' + str(pid) + '/status').read_text().splitlines() if ':' in line)
        need(status['NoNewPrivs'].strip() == '1', 'inherited_no_new_privileges')
        observed_namespaces = {name: os.readlink('/proc/' + str(pid) + '/ns/' + name) for name in ('user', 'pid', 'net', 'mnt')}
        need(all(observed_namespaces[name] == os.readlink('/proc/self/ns/' + name) for name in ('user', 'pid', 'net'))
             and observed_namespaces['mnt'] != os.readlink('/proc/self/ns/mnt'), 'container_private_namespace_boundary')
        report['container_loaded_limits_and_mounts'] = configuration
        report['container_no_new_privileges'] = True
        report['container_namespaces'] = observed_namespaces
        native.stop_container()
        stopped = native.docker()
        need(stopped['running'] is False and stopped['pid'] == 0 and stopped['restart']['Name'] == 'no', 'native_Docker_stop')
        native.resume_container()
        report['container_resumed'] = native.require_original_container()
        need(report['container_resumed']['pid'] != pid, 'resumed_container_must_have_new_process')
        report['docker_native_stop_resume_verified'] = True
        report['container_stopped'] = stopped
    report.update(status='verified', private_pid1=True, actual_systemd=True,
                  systemd_pid1=1, probe_pid=os.getpid(),
                  namespaces={name: os.readlink('/proc/self/ns/' + name) for name in ('user','mnt','pid','net','uts','ipc','cgroup')},
                  machine_id_sha256=hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest())
except Exception as error:
    report.update(status='failed', reason=type(error).__name__ + ':' + str(error)[:512])
temporary = OUT / 'report.tmp'
temporary.write_text(json.dumps(report, sort_keys=True))
os.replace(temporary, OUT / 'report.json')
raise SystemExit(0 if report['status'] == 'verified' else 1)
