#!/usr/bin/env python3
"""Fixed SSH MAC policy for the security role; no account or firewall changes."""
import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from zoneinfo import ZoneInfo

TARGET = Path('/etc/ssh/sshd_config.d/01-capstone-macs.conf')
BACKUPS = Path('/var/backups')
LOCK = Path('/etc/ssh/.capstone-macs.lock')
EXCLUDED = ('hmac-sha1', 'hmac-sha1-etm@openssh.com',
            'umac-64@openssh.com', 'umac-64-etm@openssh.com')
OPTION = 'MACs=-' + ','.join(EXCLUDED)
CONTENT = ('# Capstone security role: exclude legacy SSH MAC algorithms.\n'
           'MACs -' + ','.join(EXCLUDED) + '\n').encode()


def run(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    if p.returncode:
        raise RuntimeError('ssh_macs_command_failed:' + Path(argv[0]).name)
    return p.stdout


def trusted(path, directory=False):
    p = Path(path)
    for item in (p, *p.parents):
        s = item.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('ssh_macs_untrusted_path')
    s = p.lstat()
    if directory:
        if not stat.S_ISDIR(s.st_mode):
            raise ValueError('ssh_macs_not_directory')
    elif not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise ValueError('ssh_macs_not_single_regular_file')


def policy(candidate=False):
    args = ['/usr/sbin/sshd', '-T'] + (['-o', OPTION] if candidate else [])
    lines = run(args).splitlines()
    values = [x.split(None, 1)[1] for x in lines if x.startswith('macs ')]
    if len(values) != 1:
        raise ValueError('ssh_macs_missing_effective_policy')
    return values[0].split(','), [x for x in lines if not x.startswith('macs ')]


def check():
    trusted(TARGET.parent, directory=True)
    if TARGET.exists() or TARGET.is_symlink():
        trusted(TARGET)
        if TARGET.read_bytes() != CONTENT:
            raise ValueError('ssh_macs_unowned_existing_file')
    run(['/usr/sbin/sshd', '-t'])
    before, other = policy()
    run(['/usr/sbin/sshd', '-t', '-o', OPTION])
    after, proposed_other = policy(candidate=True)
    if not after or set(after) & set(EXCLUDED):
        raise ValueError('ssh_macs_candidate_invalid')
    # Do not accidentally replace a stricter administrator policy with defaults.
    if set(after) - set(before) or other != proposed_other:
        raise ValueError('ssh_macs_existing_policy_conflict')
    return before, after, other


def verify():
    trusted(TARGET)
    if TARGET.read_bytes() != CONTENT:
        raise ValueError('ssh_macs_file_drift')
    run(['/usr/sbin/sshd', '-t'])
    macs, _ = policy()
    candidate, _ = policy(candidate=True)
    if macs != candidate or set(macs) & set(EXCLUDED):
        raise ValueError('ssh_macs_effective_policy_mismatch')
    return {'status': 'verified', 'macs': macs,
            'sha256': hashlib.sha256(CONTENT).hexdigest()}


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install():
    before, after, other = check()
    if TARGET.exists():
        return {**verify(), 'changed': False}
    trusted(BACKUPS, directory=True)
    backup = Path(tempfile.mkdtemp(prefix='capstone-ssh-macs-', dir=BACKUPS))
    metadata = {'time_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
                'target': str(TARGET), 'target_existed': False,
                'before_macs': before, 'candidate_macs': after,
                'other_effective_options': other}
    (backup / 'before.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (backup / 'candidate.conf').write_bytes(CONTENT)
    for p in backup.iterdir():
        p.chmod(0o600)
        with p.open('rb') as f:
            os.fsync(f.fileno())
    sync_directory(backup)
    sync_directory(BACKUPS)
    fd, name = tempfile.mkstemp(prefix='.capstone-macs-', dir=TARGET.parent)
    published = False
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(CONTENT)
            f.flush()
            os.fsync(f.fileno())
        # Exclusive publication never overwrites a file created after preflight.
        os.link(name, TARGET)
        published = True
        os.unlink(name)
        sync_directory(TARGET.parent)
        actual, rest = policy()
        if actual != after or rest != other:
            raise ValueError('ssh_macs_include_order_or_policy_changed')
        result = verify()
        run(['systemctl', 'reload', 'ssh.service'])
        run(['systemctl', 'is-active', '--quiet', 'ssh.service'])
        return {**result, 'changed': True, 'backup': str(backup),
                'fresh_connection_required': True}
    except Exception:
        if published:
            trusted(TARGET)
            if TARGET.read_bytes() != CONTENT:
                raise RuntimeError('ssh_macs_rollback_refused_concurrent_edit')
            TARGET.unlink()
            sync_directory(TARGET.parent)
            run(['/usr/sbin/sshd', '-t'])
            run(['systemctl', 'reload', 'ssh.service'])
        raise
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'install', 'verify'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('ssh_macs_root_required')
    if args.action == 'check':
        before, after, _ = check()
        result = {'status': 'candidate_checked', 'before': before, 'candidate': after}
    elif args.action == 'verify':
        result = verify()
    else:
        trusted(LOCK.parent, directory=True)
        fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'r+') as lock:
            trusted(LOCK)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = install()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
