#!/usr/bin/env python3
"""Opt-in real SSH and Docker backends inside the existing private PID-1 roots.

Reuses the pinned isolation implementation, without changing operator helpers
or injecting a Native runner. All keys, daemons, roots, images and containers
are disposable test-owned objects. This is a prerequisite for the full native
coordinator recovery test, not an operating deployment or Lifecycle proof.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
BASE_SHA256 = '65935aaf67e456db739193064087acb994742bef77a79e44f1d79119e073ecb8'
BASE = HERE / 'validate_private_pid1.py'
assert hashlib.sha256(BASE.read_bytes()).hexdigest() == BASE_SHA256
spec = importlib.util.spec_from_file_location('private_pid1_foundation', BASE)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
original_pins = base.pins
original_populate = base.populate
original_child_manager = base.child_manager
original_supervisor = base.supervisor
ADDRESSES = {role: '198.18.0.' + str(11 + index) for index, role in enumerate('abc')}


def extended_pins():
    values = original_pins()
    values['validate_private_pid1.py'] = BASE_SHA256
    values['private_backend_probe.py'] = base.sha((HERE / 'private_backend_probe.py').read_bytes())
    return values


def owned_key(directory, name):
    destination = directory / name
    base.command(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(destination)])
    return destination


def test_keys(workspace):
    directory = workspace / 'test-keys'
    if not directory.exists():
        directory.mkdir(mode=0o700)
        for name in ('client-a', 'client-b', 'host-a', 'host-b', 'host-c'):
            owned_key(directory, name)
    return directory


def populate(root, role, source, output, pinmap):
    original_populate(root, role, source, output, pinmap)
    (root / 'var/run').symlink_to('../run')
    # The isolation engine only supplies root/usr from explicitly read-only
    # binds. These extra existing binaries are bound by the own-child wrapper.
    (root / 'usr/local/bin').mkdir(parents=True)
    keys = test_keys(root.parents[1])
    account = (root / 'etc/passwd').read_bytes()
    account = account.replace(b'fixture:/nonexistent:/bin/false', b'fixture:/nonexistent:/bin/sh')
    (root / 'etc/passwd').write_bytes(account + b'sshd:x:50125:50125:sshd:/run/sshd:/bin/false\n')
    (root / 'etc/group').write_bytes((root / 'etc/group').read_bytes() + b'sshd:x:50125:\ndocker:x:50126:\n')
    # Public-key authentication only. An unguessable, invalid password hash
    # avoids a locked-account special case; no login password is generated.
    shadow = 'capstone-diagnostics:' + os.urandom(32).hex() + ':20000:0:99999:7:::\n'
    base.new_file(root / 'etc/shadow', shadow.encode(), 0o600)
    base.new_file(root / 'etc/ssh/host_ed25519', (keys / ('host-' + role)).read_bytes(), 0o600)
    accepted = b''.join((keys / ('client-' + name + '.pub')).read_bytes() for name in ('a', 'b'))
    base.new_file(root / 'etc/ssh/authorized_keys', accepted, 0o644)
    known = b''.join(
        ('[' + ADDRESSES[name] + ']:44222 ').encode() +
        (keys / ('host-' + name + '.pub')).read_bytes()
        for name in 'abc')
    if role in ('a', 'b'):
        base.new_file(root / 'etc/ssh/client_ed25519', (keys / ('client-' + role)).read_bytes(), 0o600)
        base.new_file(root / 'etc/ssh/known_hosts', known, 0o600)
        if role == 'b':
            for name in ('client_ed25519', 'known_hosts'):
                os.chown(root / 'etc/ssh' / name, 0, 50124)
                os.chmod(root / 'etc/ssh' / name, 0o640)
    if role == 'a':
        wrong = ('[' + ADDRESSES['b'] + ']:44222 ').encode() + (keys / 'host-c.pub').read_bytes()
        base.new_file(root / 'etc/ssh/wrong_known_hosts', wrong, 0o600)
    base.new_file(root / 'opt/pid1-proof/ssh_reply.py', b'import hashlib,json,os,pathlib\nassert not os.environ.get("SSH_ORIGINAL_COMMAND", "")\nprint(json.dumps({"schema":1,"role":pathlib.Path("/etc/capstone-proof-role").read_text().strip(),"uid":os.getuid(),"pid":os.getpid(),"machine_sha256":hashlib.sha256(pathlib.Path("/etc/machine-id").read_bytes()).hexdigest()}))\n', 0o644)
    config = ('Port 44222\nListenAddress ' + ADDRESSES[role] + '\n'
              'HostKey /etc/ssh/host_ed25519\nPidFile /run/sshd.pid\n'
              'UsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
              'PermitEmptyPasswords no\nPermitRootLogin no\nPubkeyAuthentication yes\n'
              'AuthorizedKeysFile /etc/ssh/authorized_keys\nAllowUsers capstone-diagnostics\n'
              'StrictModes yes\nDisableForwarding yes\nPermitTTY no\n'
              'ForceCommand /usr/bin/python3 -IB /opt/pid1-proof/ssh_reply.py\n'
              'LogLevel ERROR\n')
    base.new_file(root / 'etc/ssh/sshd_config', config.encode(), 0o600)
    unit = ('[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\n'
            'ExecStartPre=/usr/bin/mkdir -p /run/sshd\n'
            'ExecStart=/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config\n'
            'KillMode=control-group\nTimeoutStopSec=5s\n'
            'MemoryMax=64M\nTasksMax=32\nNoNewPrivileges=yes\n')
    base.new_file(root / 'etc/systemd/system/capstone-private-ssh.service', unit.encode(), 0o644)
    service_spec = importlib.util.spec_from_file_location('private_catalog', source / 'release_services.py')
    services = importlib.util.module_from_spec(service_spec)
    service_spec.loader.exec_module(services)
    groups = services.catalog(role)
    for name in (*groups['consumer_services'], *groups['consumer_timers']):
        if name.endswith('.timer'):
            content = '[Unit]\nDefaultDependencies=no\n[Timer]\nOnActiveSec=1h\nUnit=' + name[:-6] + '.service\n'
        else:
            content = '[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\nKillMode=control-group\nTimeoutStopSec=5s\n'
        base.new_file(root / 'etc/systemd/system' / name, content.encode(), 0o644)
    if role == 'b':
        base.new_file(root / 'etc/systemd/system/capstone-management.service.d/10-timeout.conf', b'[Service]\nTimeoutStartSec=330s\n', 0o644)
        for name in ('var/lib/docker', 'var/lib/docker-exec'):
            (root / name).mkdir(parents=True, mode=0o700)
        docker_unit = ('[Unit]\nDefaultDependencies=no\n[Service]\nType=simple\nDelegate=yes\n'
                      'ExecStart=/usr/local/bin/dockerd --data-root=/var/lib/docker --exec-root=/var/lib/docker-exec '
                      '--pidfile=/run/docker.pid --host=unix:///var/run/docker.sock --storage-driver=vfs '
                      '--bridge=none --iptables=false --ip6tables=false --ip-forward=false --ip-masq=false '
                      '--userland-proxy=false --exec-opt native.cgroupdriver=cgroupfs\n'
                      'KillMode=control-group\nTimeoutStopSec=5s\n'
                      'MemoryMax=256M\nTasksMax=128\n'
                      'StandardOutput=file:/proof/docker.stdout\nStandardError=file:/proof/docker.stderr\n')
        base.new_file(root / 'etc/systemd/system/docker.service', docker_unit.encode(), 0o644)


def child_manager(root, output, cgroup, ready, acknowledge):
    # The foundation first self-binds the owned root without MS_REC. Add this
    # read-only bind after that step so it is retained by the restricted root.
    # This hook exists only in the already-forked test child; operator/native
    # methods and command dispatch remain untouched.
    original_mount = base.mount
    def child_mount(source, target, fs=None, flags=0, data=None):
        original_mount(source, target, fs=fs, flags=flags, data=data)
        if source == root and target == root and flags == base.MS_BIND:
            original_mount('/usr/local/bin', root / 'usr/local/bin', flags=base.MS_BIND)
            original_mount(None, root / 'usr/local/bin', flags=base.MS_BIND | base.MS_REMOUNT | base.MS_RDONLY | base.MS_NOSUID)
    base.mount = child_mount
    if (root / 'etc/capstone-proof-role').read_text().strip() == 'b':
        original_unshare = base.unshare
        entered_user = False
        def child_unshare(flags):
            nonlocal entered_user
            if entered_user and flags == base.NEWNS:
                # Docker's network operations must be owned by its own user
                # namespace, rather than joining the parent's network space.
                original_unshare(flags | 0x40000000)
                pid = int(os.readlink('/proc/self'))
                base.new_file(output / 'network-ready.json', json.dumps({'host_pid': pid}).encode())
                end = time.monotonic() + 8
                while not (output / 'network-configured.json').exists():
                    base.require(time.monotonic() < end, 'private_B_network_configuration_deadline')
                    time.sleep(.02)
            else:
                original_unshare(flags)
                if flags == base.NEWUSER:
                    entered_user = True
        base.unshare = child_unshare
    original_child_manager(root, output, cgroup, ready, acknowledge)


def network_controller(workspace):
    root, owner = base.own_root(workspace)
    current_cgroup = Path('/proc/self/cgroup').read_text().strip()
    base.require(current_cgroup.endswith('/' + owner['unit'] + '/supervisor'), 'network_controller_owned_cgroup')
    base.require(base.namespaces()['net'] != owner['parent_namespaces']['net'], 'network_controller_private_net_required')
    ready = root / 'outputs/b/network-ready.json'
    end = time.monotonic() + 20
    while not ready.exists():
        base.require(time.monotonic() < end, 'network_child_not_ready')
        time.sleep(.02)
    pid = json.loads(ready.read_text())['host_pid']
    base.require(type(pid) is int and pid > 1, 'network_child_pid')
    child_group = Path('/proc/' + str(pid) + '/cgroup').read_text().strip()
    base.require(child_group.endswith('/' + owner['unit'] + '/role-b'), 'network_child_not_owned')
    base.require(base.namespaces(pid)['net'] != base.namespaces()['net'] and
                 base.namespaces(pid)['user'] != owner['parent_namespaces']['user'], 'network_child_namespace_identity')
    base.command(['/usr/sbin/ip', 'link', 'add', 'cps-b-outer', 'type', 'veth', 'peer', 'name', 'cps-b-inner'])
    base.command(['/usr/sbin/ip', 'address', 'add', '198.18.0.1/24', 'dev', 'cps-b-outer'])
    base.command(['/usr/sbin/ip', 'link', 'set', 'cps-b-outer', 'up'])
    base.command(['/usr/sbin/ip', 'link', 'set', 'cps-b-inner', 'netns', str(pid)])
    prefix = ['/usr/bin/nsenter', '--target', str(pid), '--net', '/usr/sbin/ip']
    for args in (['link', 'set', 'lo', 'up'],
                 ['link', 'set', 'cps-b-inner', 'name', 'eth0'],
                 ['address', 'add', ADDRESSES['b'] + '/24', 'dev', 'eth0'],
                 ['link', 'set', 'eth0', 'up']):
        base.command(prefix + args)
    proof = {'schema': 1, 'scope': 'owned_outer_to_user_owned_B_veth_only',
             'host_pid': pid, 'outer_net': base.namespaces()['net'],
             'B_net': base.namespaces(pid)['net'], 'operating_host_interfaces_changed': 0}
    base.new_file(root / 'outputs/b/network-configured.json', json.dumps(proof).encode())
    return 0


def supervisor(workspace):
    root, owner = base.own_root(workspace)
    base.require(Path('/proc/self/cgroup').read_text().strip().endswith('/' + owner['unit'] + '/supervisor'),
                 'backend_supervisor_owned_cgroup')
    base.require(base.namespaces()['net'] != owner['parent_namespaces']['net'],
                 'backend_supervisor_private_network_required')
    # This is the already-private outer network. No routes or host interface
    # addresses are changed, and no external interface is attached.
    for address in (ADDRESSES['a'], ADDRESSES['c']):
        base.command(['/usr/sbin/ip', 'address', 'add', address + '/32', 'dev', 'lo'])
    log = Path(workspace) / 'network-controller.log'
    original_new_file = base.new_file
    def staged_result(path, raw, mode=0o600):
        if path == Path(workspace) / 'supervisor-report.json':
            path = Path(workspace) / 'foundation-report.json'
        return original_new_file(path, raw, mode)
    base.new_file = staged_result
    with log.open('xb') as stream:
        helper = subprocess.Popen(['/usr/bin/python3', '-I', '-B', __file__, '--network-controller', str(workspace)],
                                  stdin=subprocess.DEVNULL, stdout=stream, stderr=stream, env=base.ENV)
        try:
            original_supervisor(workspace)
        finally:
            if helper.poll() is None:
                helper.terminate()
            helper.wait(timeout=3)
            base.new_file = original_new_file
    path = Path(workspace) / 'foundation-report.json'
    value = json.loads(path.read_text())
    value['scope'] = 'private_PID1_real_SSH_and_B_native_Docker_prerequisites'
    value['peer_SSH'] = (value.get('status') == 'verified' and
                         all(row.get('peer_ssh_verified') for row in value['roles'].values()) and
                         all(len(value['roles'].get(role, {}).get('peers', {})) == 2 for role in ('a', 'b')))
    value['docker_lifecycle'] = bool(value['roles'].get('b', {}).get('docker_native_stop_resume_verified'))
    value['lifecycle_recover'] = False
    value['production_root_entry'] = False
    value['network_controller_returncode'] = helper.returncode
    value['network_controller_diagnostic'] = log.read_text(errors='replace')[-2000:]
    network_proof = Path(workspace) / 'outputs/b/network-configured.json'
    if network_proof.exists():
        value['private_B_network'] = json.loads(network_proof.read_text())
    value['backend_diagnostics'] = {}
    for role in 'abc':
        log = Path(workspace) / 'outputs' / role / 'docker.stderr'
        if log.exists():
            value['backend_diagnostics'][role + '/docker.stderr'] = log.read_text(errors='replace')[-6000:]
    try:
        if value.get('status') == 'verified':
            base.require(helper.returncode == 0, 'network_controller_not_successful')
            for source in ('a', 'b'):
                for target, proof in value['roles'][source]['peers'].items():
                    base.require(proof['machine_sha256'] == value['roles'][target]['machine_id_sha256'], 'SSH_peer_machine_mismatch')
            base.require(value['roles']['a']['wrong_host_key_denied'], 'SSH_strict_host_key_negative_control')
            base.require(value['peer_SSH'] and value['docker_lifecycle'], 'real_backends_required')
    except Exception as error:
        value.update(status='failed', reason=type(error).__name__ + ':' + str(error)[:256])
    # The outer observer only sees the complete, cross-checked final report.
    original_new_file(Path(workspace) / 'supervisor-report.json', json.dumps(value, sort_keys=True).encode())
    return 0 if value.get('status') == 'verified' else 1


def main():
    base.pins = extended_pins
    base.populate = populate
    base.child_manager = child_manager
    base.supervisor = supervisor
    base.PROBE = (HERE / 'private_backend_probe.py').read_text()
    # run_owned copies and executes this wrapper, alongside the pinned engine.
    base.__file__ = __file__
    if len(sys.argv) == 3 and sys.argv[1] == '--network-controller':
        return network_controller(Path(sys.argv[2]))
    return base.main()


if __name__ == '__main__':
    raise SystemExit(main())
