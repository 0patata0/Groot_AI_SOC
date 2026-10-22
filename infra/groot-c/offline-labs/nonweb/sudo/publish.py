#!/usr/bin/env python3
"""Fixed C-only read-only runtime attestation and root-owned web receipt publisher."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time

CVE = 'CVE-2021-3156'
OPERATOR = 1991
LAB = Path('/opt/capstone-offline-labs/nonweb/sudo/lab.py')
CONFIG = Path('/etc/capstone-sudo-lab/config.json')
RECEIPT = Path('/var/lib/capstone-offline-labs/nonweb-status.json')
TTL = 300
OUTPUT_LIMIT = 128 * 1024


def require(condition, code):
    if not condition:
        raise ValueError(code)


def root_parents(path):
    for item in (path,) + tuple(path.parents):
        meta = item.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
                'untrusted_parent')


def root_file(path, private=False):
    root_parents(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0 and meta.st_nlink == 1
                and not meta.st_mode & (0o077 if private else 0o022)
                and (not private or stat.S_IMODE(meta.st_mode) == 0o600)
                and meta.st_size <= 128 * 1024, 'untrusted_file')
        return stream.read()


def unique(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'duplicate_json_key')
        out[key] = value
    return out


def existing_contract(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'checked_at', 'expires_at', 'labs'}
            and type(value['schema']) is int and value['schema'] == 1, 'receipt_schema')
    require(type(value['checked_at']) is int and type(value['expires_at']) is int
            and 0 < value['expires_at'] - value['checked_at'] <= 600, 'receipt_times')
    labs = value['labs']
    # Another publisher's entries must never be discarded or silently renewed.
    # A future multi-lab publisher needs a deliberate aggregation contract.
    require(isinstance(labs, dict) and set(labs) <= {CVE}, 'other_lab_receipt_refused')
    for item in labs.values():
        require(isinstance(item, dict) and set(item) == {'status'}
                and item['status'] in ('ready', 'needs_setup', 'error'), 'receipt_lab_schema')


def load_lab():
    root_file(LAB)
    spec = importlib.util.spec_from_file_location('fixed_sudo_lab', LAB)
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    return lab


def operator_run(args, timeout):
    root_parents(Path('/usr/bin'))
    limiter = Path('/usr/bin/prlimit').lstat()
    require(stat.S_ISREG(limiter.st_mode) and limiter.st_uid == 0 and limiter.st_nlink == 1
            and not limiter.st_mode & 0o022 and limiter.st_mode & 0o111, 'untrusted_output_limiter')
    account = pwd.getpwuid(OPERATOR)
    require(account.pw_name == 'capstone-sudo' and account.pw_gid == OPERATOR
            and account.pw_dir == '/var/lib/capstone-sudo-runtime'
            and account.pw_shell == '/usr/sbin/nologin', 'operator_identity_changed')
    command = ['/usr/sbin/runuser', '-u', 'capstone-sudo', '--', '/usr/bin/env', '-i',
               'PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=' + account.pw_dir,
               'XDG_RUNTIME_DIR=/run/user/1991', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus',
               'LANG=C', 'LC_ALL=C', 'PYTHONDONTWRITEBYTECODE=1',
               '/usr/bin/prlimit', '--fsize=131072:131072', '--'] + args
    root_parents(RECEIPT.parent)
    # Apply prlimit after runuser, which resets RLIMIT_FSIZE on util-linux >=2.38.
    # The child writes to a root-created file with a kernel-enforced size limit;
    # neither a dishonest daemon nor a failed CLI can fill the parent's memory.
    with tempfile.TemporaryFile(dir=RECEIPT.parent) as output:
        os.fchmod(output.fileno(), 0o600)
        os.fchown(output.fileno(), 0, 0)
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.DEVNULL, timeout=timeout)
        require(os.fstat(output.fileno()).st_size < OUTPUT_LIMIT, 'probe_output_limit')
        output.seek(0)
        return result.returncode, json.loads(output.read(OUTPUT_LIMIT), object_pairs_hook=unique)


def ready_contract(value, config, now):
    require(isinstance(value, dict) and type(value.get('schema')) is int and value.get('schema') == 1 and value.get('cve_id') == CVE
            and value.get('status') == 'running' and value.get('environment_ready') is True
            and value.get('package_verified') is True and value.get('isolation_verified') is True
            and value.get('attack_tested') is False and value.get('host_scenario_verified') is False
            and value.get('verification') == 'environment_only'
            and value.get('image_id') == config['image_id'], 'probe_not_verified')
    require(type(value.get('checked_at')) is int and 0 <= now - value['checked_at'] <= 90,
            'stale_probe')
    require(isinstance(value.get('container_id'), str)
            and re.fullmatch(r'[a-f0-9]{64}', value['container_id']), 'full_container_id_required')


def attest():
    lab = load_lab()
    config = lab.config_at(CONFIG, OPERATOR)
    code, value = operator_run(['/usr/bin/python3', '-B', str(LAB), 'verify'], 70)
    if code:
        require(isinstance(value, dict) and value.get('cve_id') == CVE
                and value.get('environment_ready') is False, 'unexpected_failed_probe')
        return 'needs_setup' if value.get('error') in ('lab_not_running', 'verification_unavailable') else 'error'
    ready_contract(value, config, int(time.time()))
    docker = lab.docker_binary()
    prefix = [docker, '--host', 'unix:///run/user/1991/docker.sock']
    code, images = operator_run(prefix + ['image', 'inspect', config['image_id']], 10)
    require(code == 0 and isinstance(images, list) and len(images) == 1, 'image_inspection_failed')
    lab.image_contract(images[0], config)
    code, containers = operator_run(prefix + ['container', 'inspect', value['container_id']], 10)
    require(code == 0 and isinstance(containers, list) and len(containers) == 1, 'container_inspection_failed')
    container = containers[0]
    lab.container_contract(container, config, value['container_id'])
    require(container.get('State', {}).get('Running') is True, 'container_stopped_during_probe')
    require(lab.running_isolation(container, config) == value.get('isolation'), 'root_attestation_mismatch')
    return 'ready'


def atomic_receipt(status):
    root_parents(RECEIPT.parent)
    try:
        existing_contract(json.loads(root_file(RECEIPT, private=True), object_pairs_hook=unique))
    except FileNotFoundError:
        pass
    now = int(time.time())
    value = {'schema': 1, 'checked_at': now, 'expires_at': now + TTL,
             'labs': {CVE: {'status': status}}}
    descriptor, temporary = tempfile.mkstemp(prefix='.sudo-status-', dir=RECEIPT.parent)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, RECEIPT)
        directory = os.open(RECEIPT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return value


def main():
    require(os.getuid() == 0 and os.geteuid() == 0 and len(sys.argv) == 1, 'root_no_arguments_required')
    root_parents(RECEIPT.parent)
    fd = os.open(RECEIPT.parent / '.sudo-status.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        meta = os.fstat(lock.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                and stat.S_IMODE(meta.st_mode) == 0o600, 'untrusted_lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            status = attest()
        except Exception:
            # A failed observation never promotes the lab and never controls it.
            status = 'error'
        value = atomic_receipt(status)
        print(json.dumps({'status': status, 'checked_at': value['checked_at'],
                          'expires_at': value['expires_at'], 'attack_tested': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print(json.dumps({'published': False, 'error': 'receipt_or_publisher_unavailable'}))
        raise SystemExit(1)
