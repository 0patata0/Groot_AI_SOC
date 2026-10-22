#!/usr/bin/env python3
"""Operator CLI for a separate rootless runtime; no arbitrary command interface."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import subprocess
import sys
import time

NAME = 'capstone-sudo-cve-2021-3156'
CVE = 'CVE-2021-3156'
VERSION = '1.8.31-1ubuntu1'
BASE_DIGEST = 'sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a'
LABEL = 'io.capstone.sudo-lab'
HASH = re.compile(r'[a-f0-9]{64}\Z')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
ENV = ['LC_ALL=C', 'HOME=/tmp', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']
TMPFS = {'/tmp': 'rw,nosuid,nodev,size=64m,mode=1777',
         '/run': 'rw,nosuid,nodev,noexec,size=8m,mode=0755'}
CAPS = ['SETGID', 'SETUID']
MEMORY = 268435456
DOCKER_PATHS = (Path('/usr/local/bin/docker'), Path('/usr/bin/docker'))


class Rejected(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate_json_key')
        value[key] = item
    return value


def read_json(path, owner, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'r') as handle:
        meta = os.fstat(handle.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_uid == owner
                and not meta.st_mode & (0o077 if private else 0o022)
                and meta.st_size <= 16384, 'unsafe_json_file')
        return json.load(handle, object_pairs_hook=unique)


def trusted_parents(path, owners):
    require(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    for item in (path,) + tuple(path.parents):
        info = item.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in owners
                and not info.st_mode & 0o022, 'unsafe_parent_directory')


def docker_binary():
    # Never resolve Docker through operator-controlled PATH or a symlink.
    for path in DOCKER_PATHS:
        try:
            meta = path.lstat()
        except FileNotFoundError:
            continue
        trusted_parents(path.parent, {0})
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                and not meta.st_mode & 0o022 and bool(meta.st_mode & 0o111)
                and os.access(path, os.X_OK), 'unsafe_docker_binary')
        return str(path)
    raise Rejected('trusted_docker_binary_missing')


def config_at(path, uid):
    trusted_parents(path.parent, {0})
    config = read_json(path, 0)
    require(set(config) == {'schema', 'operator_uid', 'image_id', 'deb_sha256', 'preparation_sha256'},
            'config_fields_mismatch')
    require(type(config['schema']) is int and config['schema'] == 1
            and type(config['operator_uid']) is int and uid > 0 and config['operator_uid'] == uid,
            'nonroot_operator_required')
    require(isinstance(config['image_id'], str) and IMAGE.fullmatch(config['image_id']), 'pinned_image_required')
    for key in ('deb_sha256', 'preparation_sha256'):
        require(isinstance(config[key], str) and HASH.fullmatch(config[key]), 'verified_artifact_hash_required')
    return config


def daemon_contract(info, resources=True):
    options = info.get('SecurityOptions', [])
    require(any(item == 'name=rootless' for item in options), 'rootless_daemon_required')
    require('name=seccomp,profile=builtin' in options, 'builtin_seccomp_required')
    require(not resources or (str(info.get('CgroupVersion')) == '2' and info.get('CgroupDriver') == 'systemd'),
            'rootless_cgroup_v2_systemd_required')
    require(info.get('OSType') == 'linux' and info.get('Architecture') in ('x86_64', 'amd64'),
            'linux_amd64_daemon_required')


def expected_labels(config):
    return {LABEL: '1', LABEL + '.package-version': VERSION, LABEL + '.base': BASE_DIGEST,
            LABEL + '.deb-sha256': config['deb_sha256'],
            LABEL + '.preparation-sha256': config['preparation_sha256']}


def image_contract(image, config):
    require(image.get('Id') == config['image_id'] and image.get('Os') == 'linux'
            and image.get('Architecture') == 'amd64', 'image_identity_mismatch')
    conf = image.get('Config', {})
    require(not conf.get('Volumes') and not conf.get('OnBuild'), 'image_mount_or_build_hook_refused')
    require(conf.get('User') == '1000:1000' and conf.get('Entrypoint') == ['/usr/bin/sleep']
            and conf.get('Cmd') == ['infinity'] and conf.get('WorkingDir') == '/tmp'
            and sorted(conf.get('Env', [])) == sorted(ENV), 'image_process_contract_mismatch')
    require(all(conf.get('Labels', {}).get(k) == v for k, v in expected_labels(config).items()),
            'image_provenance_mismatch')


def create_args(config):
    args = ['container', 'create', '--pull=never', '--name', NAME, '--network=none',
            '--user=1000:1000', '--read-only', '--cap-drop=ALL', '--cap-add=SETUID', '--cap-add=SETGID',
            '--security-opt=no-new-privileges=false', '--security-opt=apparmor=unconfined',
            '--ipc=private', '--cgroupns=private',
            '--memory=' + str(MEMORY), '--memory-swap=' + str(MEMORY), '--cpus=0.5',
            '--pids-limit=64', '--restart=no', '--no-healthcheck', '--stop-timeout=5',
            '--log-driver=json-file', '--log-opt=max-size=1m', '--log-opt=max-file=2',
            '--entrypoint=/usr/bin/sleep', '--workdir=/tmp']
    for key, value in sorted(TMPFS.items()):
        args += ['--tmpfs', key + ':' + value]
    for value in ENV:
        args += ['--env', value]
    for key, value in sorted(expected_labels(config).items()):
        args += ['--label', key + '=' + value]
    return args + [config['image_id'], 'infinity']


def container_contract(info, config, cid):
    require(info.get('Id') == cid and info.get('Name') == '/' + NAME
            and info.get('Image') == config['image_id'], 'container_identity_conflict')
    conf, host = info.get('Config', {}), info.get('HostConfig', {})
    require(conf.get('User') == '1000:1000' and conf.get('Entrypoint') == ['/usr/bin/sleep']
            and conf.get('Cmd') == ['infinity'] and conf.get('WorkingDir') == '/tmp'
            and sorted(conf.get('Env', [])) == sorted(ENV) and not conf.get('Volumes')
            and conf.get('Healthcheck') == {'Test': ['NONE']}, 'container_process_changed')
    require(all(conf.get('Labels', {}).get(k) == v for k, v in expected_labels(config).items()),
            'container_labels_changed')
    expected = {'ReadonlyRootfs': True, 'Privileged': False, 'PublishAllPorts': False,
                'NetworkMode': 'none', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                'Memory': MEMORY, 'MemorySwap': MEMORY, 'NanoCpus': 500000000, 'PidsLimit': 64}
    require(all(host.get(key) == value for key, value in expected.items()), 'container_isolation_changed')
    security_options = host.get('SecurityOpt')
    require(host.get('CapDrop') == ['ALL'] and sorted(host.get('CapAdd') or [])
            in (CAPS, ['CAP_SETGID', 'CAP_SETUID'])
            and isinstance(security_options, list) and len(security_options) == 2
            and set(security_options) in ({'no-new-privileges=false', 'apparmor=unconfined'},
                                         {'no-new-privileges:false', 'apparmor=unconfined'})
            and info.get('AppArmorProfile') in ('', 'unconfined'),
            'container_security_options_changed')
    require(host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0}
            and host.get('Tmpfs') == TMPFS, 'container_lifecycle_changed')
    require(host.get('PidMode', '') == '' and host.get('UsernsMode', '') == '', 'host_namespace_refused')
    for key in ('Binds', 'Mounts', 'Devices', 'DeviceRequests', 'VolumesFrom', 'Links', 'ExtraHosts',
                'PortBindings', 'Sysctls'):
        require(not host.get(key), 'host_resource_or_port_refused')
    require(all(item.get('Type') == 'tmpfs' and item.get('Destination') in TMPFS
                for item in info.get('Mounts', [])), 'non_tmpfs_mount_refused')
    require(set(info.get('NetworkSettings', {}).get('Networks', {})) <= {'none'}, 'network_attachment_refused')
    require(host.get('LogConfig') == {'Type': 'json-file', 'Config': {'max-size': '1m', 'max-file': '2'}},
            'log_limit_changed')


def zero_mapping(value):
    rows = [tuple(map(int, line.split())) for line in value.splitlines() if line.strip()]
    require(rows and all(len(row) == 3 and row[0] >= 0 and row[1] > 0 and row[2] > 0
                        and row[0] + row[2] <= 4294967295 and row[1] + row[2] <= 4294967295
                        for row in rows), 'invalid_or_host_root_uid_map')
    for column in (0, 1):
        ordered = sorted((row[column], row[column] + row[2]) for row in rows)
        require(all(left[1] <= right[0] for left, right in zip(ordered, ordered[1:])), 'overlapping_uid_map')
    selected = [outside for inside, outside, length in rows if inside == 0]
    require(len(selected) == 1 and selected[0] > 0, 'container_root_maps_to_host_root')
    return selected[0]


def cgroup_contract(path):
    require(int((path / 'memory.max').read_text().strip()) == MEMORY, 'memory_limit_not_enforced')
    require(int((path / 'memory.swap.max').read_text().strip()) == 0, 'swap_limit_not_enforced')
    require(int((path / 'pids.max').read_text().strip()) == 64, 'pid_limit_not_enforced')
    quota, period = map(int, (path / 'cpu.max').read_text().split())
    require(quota > 0 and period > 0 and quota * 2 == period, 'cpu_limit_not_enforced')


def running_isolation(info, config):
    """Read from the host's /proc view, not a map reported inside the container."""
    require(Path('/proc/self/uid_map').read_text().split() == ['0', '0', '4294967295'],
            'initial_host_user_namespace_required')
    require(Path('/proc/self/gid_map').read_text().split() == ['0', '0', '4294967295'],
            'initial_host_group_namespace_required')
    cid, reported_pid = info['Id'], info.get('State', {}).get('Pid')
    require(type(reported_pid) is int and reported_pid > 0, 'running_pid_missing')
    # Rootless daemon PID numbers may differ from host PID numbers. Bind the
    # candidate to the full CID cgroup and its namespace PID before reading maps.
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            group = proc.joinpath('cgroup').read_text()
            paths = [line[3:] for line in group.splitlines() if line.startswith('0::')]
            if len(paths) != 1 or Path(paths[0]).name != 'docker-' + cid + '.scope':
                continue
            status = dict(line.split(':', 1) for line in proc.joinpath('status').read_text().splitlines() if ':' in line)
            namespace_pids = list(map(int, status.get('NSpid', '0').split()))
            if reported_pid not in namespace_pids or namespace_pids[-1] != 1:
                continue
            before = proc.joinpath('stat').read_text().split(') ', 1)[1].split()[19]
            require(proc.joinpath('cmdline').read_bytes() == b'/usr/bin/sleep\x00infinity\x00', 'container_pid_command_mismatch')
            root_uid = zero_mapping(proc.joinpath('uid_map').read_text())
            root_gid = zero_mapping(proc.joinpath('gid_map').read_text())
            require(root_uid == config['operator_uid']
                    and root_gid == pwd.getpwuid(config['operator_uid']).pw_gid,
                    'container_root_mapping_operator_mismatch')
            # These maps are read from the initial host namespace. A map that
            # excludes host ID zero proves separation without ptrace-protected
            # /proc/PID/ns/user readlink access to the subordinate-UID process.
            require(status.get('NoNewPrivs', '').strip() == '0', 'setuid_blocked_by_no_new_privileges')
            require(status.get('Seccomp', '').strip() == '2', 'seccomp_filter_not_enforced')
            require(int(status.get('CapBnd', '0'), 16) == 0xc0, 'capability_bound_changed')
            require(all(int(item) > 0 for item in status['Uid'].split()), 'host_uid_zero_refused')
            require(all(int(item) > 0 for item in status['Gid'].split()), 'host_gid_zero_refused')
            require(len(paths) == 1 and paths[0].startswith('/') and '..' not in Path(paths[0]).parts,
                    'invalid_cgroup_path')
            cgroup_contract(Path('/sys/fs/cgroup') / paths[0].lstrip('/'))
            require(proc.joinpath('stat').read_text().split(') ', 1)[1].split()[19] == before,
                    'process_changed_during_verification')
            return {'host_uid_for_container_root': root_uid, 'host_gid_for_container_root': root_gid,
                    'mapping_verification': 'initial-host-proc-uid-gid-maps',
                    'seccomp_mode': 2, 'capability_bounding_set': '00000000000000c0'}
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    raise Rejected('host_uid_mapping_or_cgroup_not_observable')


class Docker:
    def __init__(self, uid):
        self.uid = uid
        self.binary = docker_binary()
        path = Path('/run/user') / str(uid)
        trusted_parents(path, {0, uid})
        require(path.stat().st_uid == uid and stat.S_IMODE(path.stat().st_mode) == 0o700,
                'private_runtime_directory_required')
        meta = path.joinpath('docker.sock').lstat()
        require(stat.S_ISSOCK(meta.st_mode) and meta.st_uid == uid and not meta.st_mode & 0o007,
                'owned_rootless_socket_required')
        self.socket = 'unix://' + str(path / 'docker.sock')

    def run(self, args):
        result = subprocess.run([self.binary, '--host', self.socket] + args,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=40, text=True,
                                env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'DOCKER_CONFIG': '/nonexistent',
                                     'LANG': 'C', 'LC_ALL': 'C'})
        require(result.returncode == 0, 'docker_operation_failed')
        return result.stdout.strip()

    def inspect(self, kind, identifier):
        items = json.loads(self.run([kind, 'inspect', identifier]))
        require(isinstance(items, list) and len(items) == 1, 'invalid_docker_inspect')
        return items[0]


class Lab:
    def __init__(self, config, docker, state):
        self.config, self.docker, self.state = config, docker, state
        self.receipt = state / 'runtime.json'

    def inventory(self):
        listed = self.docker.run(['container', 'ls', '-aq', '--no-trunc', '--filter', 'name=^/' + NAME + '$']).splitlines()
        require(len(listed) <= 1, 'duplicate_container_name')
        if not self.receipt.exists():
            require(not listed, 'unmanaged_container_conflict')
            return None
        receipt = read_json(self.receipt, os.geteuid(), private=True)
        require(set(receipt) == {'schema', 'container_id', 'image_id'} and receipt['schema'] == 1
                and isinstance(receipt['container_id'], str) and HASH.fullmatch(receipt['container_id'])
                and receipt['image_id'] == self.config['image_id'], 'invalid_runtime_receipt')
        require(listed == [receipt['container_id']], 'receipt_container_conflict')
        info = self.docker.inspect('container', receipt['container_id'])
        container_contract(info, self.config, receipt['container_id'])
        return info

    def register(self, cid):
        require(HASH.fullmatch(cid), 'invalid_created_container_id')
        fd = os.open(self.receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'schema': 1, 'container_id': cid, 'image_id': self.config['image_id']}, stream)
            stream.flush()
            os.fsync(stream.fileno())

    def retire_stopped(self, info):
        # Docker 29.8.1 clears the rootless AppArmorProfile on first start, then
        # falls back to docker-default when that stopped container is started.
        # This stateless lab recreates only its exactly receipted, stopped CID.
        cid = info['Id']
        container_contract(info, self.config, cid)
        state = info.get('State', {})
        require(state.get('Running') is False and state.get('Pid') == 0
                and state.get('Status') in ('created', 'exited')
                and not any(state.get(k) for k in ('Paused', 'Restarting', 'Dead')),
                'stopped_container_required_for_recreate')
        previous = read_json(self.receipt, os.geteuid(), private=True)
        require(previous == {'schema': 1, 'container_id': cid, 'image_id': self.config['image_id']},
                'receipt_changed_before_recreate')
        history = self.state / ('retired-' + cid + '.json')
        descriptor = os.open(history, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(dict(previous, retired_at=int(time.time()), reason='stateless_stopped_recreate'), stream)
            stream.flush()
            os.fsync(stream.fileno())
        # No --force: Docker itself refuses a concurrent transition to running.
        self.docker.run(['container', 'rm', cid])
        self.receipt.unlink()

    def run(self, action):
        daemon_contract(json.loads(self.docker.run(['info', '--format', '{{json .}}'])), resources=action != 'stop')
        if action != 'stop':
            image_contract(self.docker.inspect('image', self.config['image_id']), self.config)
        info = self.inventory()
        result = {'schema': 1, 'cve_id': CVE, 'checked_at': int(time.time()), 'image_id': self.config['image_id'],
                  'image_present': None if action == 'stop' else True, 'package_version': VERSION, 'package_verified': False,
                  'isolation_verified': False, 'environment_ready': False,
                  'verification': 'inventory_only', 'attack_tested': False, 'host_scenario_verified': False}
        if action == 'check':
            result['verification'] = 'configuration_only'
        elif action == 'up':
            if info is not None and not info.get('State', {}).get('Running'):
                self.retire_stopped(info)
                info = None
            if info is None:
                cid = self.docker.run(create_args(self.config))
                # A failed receipt write leaves an unclaimed stopped container;
                # future operations refuse adoption instead of guessing ownership.
                self.register(cid)
                info = self.inventory()
            if not info.get('State', {}).get('Running'):
                started_cid = info['Id']
                try:
                    self.docker.run(['container', 'start', started_cid])
                    info = self.inventory()
                except Exception:
                    self.docker.run(['container', 'stop', '--time', '5', started_cid])
                    raise
        elif action == 'stop' and info is not None:
            self.docker.run(['container', 'stop', '--time', '5', info['Id']])
            info = self.inventory()
        if action in ('up', 'verify'):
            require(info is not None and info.get('State', {}).get('Running'), 'lab_not_running')
            try:
                isolation = running_isolation(info, self.config)
                check = json.loads(self.docker.run(['container', 'exec', '--user', '1000:1000', info['Id'], '/lab/check.sh']))
                require(check == {'schema': 1, 'package': 'sudo', 'version': VERSION, 'architecture': 'amd64',
                                  'setuid_binary': True, 'attack_tested': False}, 'package_probe_mismatch')
                # Verify again after the fresh package probe, including kernel limits.
                require(running_isolation(self.inventory(), self.config) == isolation,
                        'isolation_changed_during_probe')
            except Exception:
                if action == 'up':
                    self.docker.run(['container', 'stop', '--time', '5', info['Id']])
                raise
            result.update(package_verified=True, isolation_verified=True,
                          environment_ready=True, verification='environment_only', isolation=isolation)
        result['status'] = 'not_created' if info is None else ('running' if info.get('State', {}).get('Running') else 'stopped')
        result['container_id'] = info['Id'] if info is not None else None
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'up', 'status', 'verify', 'stop'])
    parser.add_argument('--config', type=Path, default=Path('/etc/capstone-sudo-lab/config.json'))
    args = parser.parse_args()
    try:
        uid = os.geteuid()
        require(uid != 0 and os.getuid() == uid and platform.system() == 'Linux'
                and platform.machine() in ('x86_64', 'amd64'), 'nonroot_linux_amd64_required')
        config = config_at(args.config, uid)
        docker = Docker(uid)
        home = Path(pwd.getpwuid(uid).pw_dir)
        trusted_parents(home, {0, uid})
        state = home / '.local/state/capstone-sudo-lab'
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        trusted_parents(state, {0, uid})
        require(state.stat().st_uid == uid and stat.S_IMODE(state.stat().st_mode) == 0o700, 'private_state_required')
        fd = os.open(state / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'r+') as lock:
            meta = os.fstat(lock.fileno())
            require(meta.st_uid == uid and meta.st_nlink == 1 and stat.S_ISREG(meta.st_mode)
                    and stat.S_IMODE(meta.st_mode) == 0o600, 'unsafe_lock_file')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(Lab(config, docker, state).run(args.action), sort_keys=True))
    except (Rejected, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'schema': 1, 'cve_id': CVE, 'checked_at': int(time.time()), 'status': 'needs_setup',
                          'environment_ready': False, 'attack_tested': False, 'host_scenario_verified': False,
                          'error': str(error) if isinstance(error, Rejected) else 'verification_unavailable'}, sort_keys=True))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
