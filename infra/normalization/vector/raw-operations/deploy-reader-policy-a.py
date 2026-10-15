#!/usr/bin/env python3
"""Operator-only, finite deployment; never installed as a runtime collector."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

MID = '096e90b6243e438aa8a7b392be754732'
ORIGINAL = '8fcfeb935e1d706fe37ce6b89b5de5ad0189023d1c3dc40693a68803f9769984'
CONFIG = Path('/var/ossec/etc/ossec.conf')
ROOT = Path('/var/backups/capstone-raw-reader-policy-20261014')
SOURCES = ('/home/groot_a/capstone/secstack/logs/suricata/eve.json',
           '/home/groot_a/capstone/secstack/logs/modsec/audit.log')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'LD_LIBRARY_PATH': '/var/ossec/lib', 'PYTHONDONTWRITEBYTECODE': '1'}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def command(argv, timeout=30):
    result = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    require(len(result.stdout) + len(result.stderr) < 1048576, 'command_output_limit')
    return result


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        os.fchmod(handle.fileno(), mode)
        os.fchown(handle.fileno(), 0, gid)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def config_identity():
    value = CONFIG.lstat()
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            value.st_nlink, stat.S_IMODE(value.st_mode))


def atomic_config(raw, label, expected_raw, expected_identity):
    temporary = CONFIG.with_name('.capstone-reader-policy-' + label)
    write_new(temporary, raw, 0o660, 110)
    require(config_identity() == expected_identity and CONFIG.read_bytes() == expected_raw,
            'configuration_compare_conflict')
    os.replace(temporary, CONFIG)
    sync_directory(CONFIG.parent)


def raw_identity(path, prefix_size=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'raw_identity_invalid')
        count = info.st_size if prefix_size is None else prefix_size
        require(0 <= count <= 536870912 and info.st_size >= count, 'raw_size_invalid')
        remaining = count
        h = hashlib.sha256()
        while remaining:
            chunk = handle.read(min(1048576, remaining))
            require(chunk, 'raw_short_read')
            h.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(handle.fileno())
        current = os.stat(path, follow_symlinks=False)
        require((after.st_dev, after.st_ino) == (current.st_dev, current.st_ino) ==
                (info.st_dev, info.st_ino), 'raw_identity_changed')
    return {'dev': info.st_dev, 'ino': info.st_ino, 'prefix_bytes': count,
            'prefix_sha256': h.hexdigest()}


def native_pid():
    values = []
    for file in Path('/var/ossec/var/run').glob('wazuh-logcollector-*.pid'):
        match = re.fullmatch(r'wazuh-logcollector-([1-9][0-9]*)\.pid', file.name)
        if match:
            pid = int(match.group(1))
            proc = Path('/proc') / str(pid)
            try:
                fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                if fields[0] != 'Z' and os.readlink(proc / 'exe') == '/var/ossec/bin/wazuh-logcollector':
                    values.append({'pid': pid, 'start_ticks': int(fields[19])})
            except FileNotFoundError:
                pass
    require(len(values) == 1, 'native_reader_count')
    return values[0]


def restart_and_verify(previous_pid):
    state_path = Path('/var/ossec/var/run/wazuh-agentd.state')
    old = state_path.stat()
    old_identity = (old.st_dev, old.st_ino, old.st_mtime_ns, old.st_ctime_ns)
    require(command(['/usr/bin/systemctl', 'restart', 'wazuh-agent.service'], 90).returncode == 0,
            'agent_restart_failed')
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        try:
            value = state_path.stat()
            fresh = (value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns) != old_identity
            state = state_path.read_text()
            reader = native_pid()
            active = command(['/usr/bin/systemctl', 'is-active', '--quiet', 'wazuh-agent.service']).returncode == 0
            if fresh and active and reader != previous_pid and re.search(r"^status=['\"]?connected['\"]?", state, re.M):
                return reader
        except (FileNotFoundError, RuntimeError):
            pass
        time.sleep(.5)
    raise RuntimeError('agent_fresh_connection_not_restored')


def main():
    require(sys.argv[1:] == ['check'] or sys.argv[1:] == ['apply'], 'fixed_operation_required')
    require(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'wrong_operator_host')
    os.umask(0o077)
    lock_path = Path('/var/lib/capstone-automation/ansible/vector.lock')
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    lock_info = os.fstat(lock_fd)
    require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 0 and lock_info.st_nlink == 1 and
            not stat.S_IMODE(lock_info.st_mode) & 0o022, 'shared_lock_identity_invalid')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    info = CONFIG.lstat()
    require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, info.st_nlink, stat.S_IMODE(info.st_mode)) ==
            (0, 110, 1, 0o660), 'configuration_identity_invalid')
    original = CONFIG.read_bytes()
    original_identity = config_identity()
    require(len(original) < 1048576 and digest(original) == ORIGINAL, 'configuration_changed')
    text = original.decode()
    selected = []
    def replace(match):
        block = match.group(0)
        locations = re.findall(r'<location>\s*([^<]+?)\s*</location>', block)
        if any(path in SOURCES for path in locations):
            require(len(locations) == 1 and locations[0] in SOURCES, 'raw_block_ambiguous')
            require('<only-future-events' not in block, 'raw_policy_already_defined')
            selected.append(locations[0])
            return block.replace('</localfile>', '  <only-future-events max-size="2GB">no</only-future-events>\n  </localfile>')
        return block
    candidate = re.sub(r'<localfile(?:\s[^>]*)?>.*?</localfile>', replace, text, flags=re.S).encode()
    require(sorted(selected) == sorted(SOURCES), 'raw_block_count')
    require(candidate.count(b'<only-future-events max-size="2GB">no</only-future-events>') ==
            original.count(b'<only-future-events max-size="2GB">no</only-future-events>') + 2, 'candidate_scope')
    before = {p: raw_identity(p) for p in SOURCES}
    pid_before = native_pid()
    require(command(['/usr/bin/systemctl', 'is-active', '--quiet', 'wazuh-agent.service']).returncode == 0,
            'operating_agent_not_active')
    if not ROOT.exists():
        ROOT.mkdir(mode=0o700)
        write_new(ROOT / 'original.conf', original, 0o400)
        write_new(ROOT / 'candidate.conf', candidate, 0o400)
        sync_directory(ROOT)
    else:
        meta = ROOT.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and stat.S_IMODE(meta.st_mode) == 0o700,
                'backup_directory_invalid')
        require((ROOT / 'original.conf').read_bytes() == original and (ROOT / 'candidate.conf').read_bytes() == candidate,
                'backup_binding_changed')
    test = command(['/var/ossec/bin/wazuh-logcollector', '-t', '-c', str(ROOT / 'candidate.conf')])
    result = {'operation': sys.argv[1], 'original_sha256': digest(original), 'candidate_sha256': digest(candidate),
              'native_config_test_exit': test.returncode, 'native_test_output_sha256': digest(test.stdout + test.stderr),
              'changed_raw_blocks': len(selected), 'backup_path': str(ROOT), 'pid_before': pid_before,
              'raw_before': before, 'rollback_performed': False, 'operational_checkpoint_rewritten': False,
              'raw_payload_exported': False}
    require(test.returncode == 0, 'native_config_test_failed')
    if sys.argv[1] == 'apply':
        require(CONFIG.read_bytes() == original, 'configuration_changed_before_apply')
        try:
            atomic_config(candidate, 'candidate', original, original_identity)
            result['pid_after'] = restart_and_verify(pid_before)
            require(result['pid_after'] != pid_before, 'reader_not_restarted')
            require(CONFIG.read_bytes() == candidate, 'applied_configuration_changed')
            result['raw_after'] = {p: raw_identity(p, before[p]['prefix_bytes']) for p in SOURCES}
            require(result['raw_after'] == before, 'raw_prefix_or_identity_changed')
            result['manager_connected'] = True
            result['status'] = 'applied'
        except BaseException:
            current_identity = config_identity()
            if current_identity[2:] == (0, 110, 1, 0o660) and CONFIG.read_bytes() == candidate:
                try:
                    rollback_before = native_pid()
                except RuntimeError:
                    rollback_before = pid_before
                atomic_config(original, 'rollback', candidate, current_identity)
                result['rollback_performed'] = True
                try:
                    result['rollback_pid_after'] = restart_and_verify(rollback_before)
                    result['rollback_healthy'] = CONFIG.read_bytes() == original
                except Exception:
                    result['rollback_healthy'] = False
            else:
                result['rollback_skipped_configuration_conflict'] = True
            write_new(ROOT / 'failed-result.json', (json.dumps(result, sort_keys=True) + '\n').encode())
            raise
    else:
        result['status'] = 'checked'
    target = ROOT / (sys.argv[1] + '-result.json')
    write_new(target, (json.dumps(result, sort_keys=True) + '\n').encode())
    sync_directory(ROOT)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'refused_or_failed', 'code': str(error) if isinstance(error, RuntimeError) else type(error).__name__}))
        sys.exit(1)
