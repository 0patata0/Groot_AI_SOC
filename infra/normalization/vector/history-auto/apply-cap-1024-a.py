#!/usr/bin/env python3
"""A: raise the history-auto batch-directory cap 256 -> 1024. Run as root, once.

Replaces exactly two installed runtime files (auto-lib.sh, runtime.sha256) under
the job lock, keeping root:root 0400 nlink 1, after checking that both still
equal the reviewed previous bytes. Nothing in the store, jobs or the journal is
touched or deleted. Originals go to a private backup. On any failure after the
first replace, both originals are put back. No retry.
Usage: apply-cap-1024-a.py <new auto-lib.sh> <new runtime.sha256>
"""
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time

B = '/usr/local/lib/capstone-vector-history-auto'
LOCK = '/var/lib/capstone-vector-history-auto/.lock'
OLD = {'auto-lib.sh': '2604d5c6f9a7044f58d2c8c66995bf696d5bbdee69f49c9e48984556d1636ddf',
       'runtime.sha256': '5e6448f7cc4fd65c19ca2dfbc74ba286a249011e8f5a02274dbd535e4aca0926'}
NEW = {'auto-lib.sh': '3d05677ec17851a66b75138c744857c2a8a2757337183ea4d0ee88dc4380c61b', 'runtime.sha256': 'af89c0f013973f72157cdd8f410739ca8ef2d52e61544da6b6e652071ff7697e'}
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put(path, data):
    tmp = path + '.cap1024.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fchown(f.fileno(), 0, 0); os.fchmod(f.fileno(), 0o400); os.fsync(f.fileno())
    os.replace(tmp, path)


def main():
    new = {'auto-lib.sh': open(sys.argv[1], 'rb').read(), 'runtime.sha256': open(sys.argv[2], 'rb').read()}
    assert all(sha(new[n]) == NEW[n] for n in NEW), 'candidate_changed'
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW)
    deadline = time.time() + 105                      # a worker run holds the lock for <= ~100 s
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
        except BlockingIOError:
            assert time.time() < deadline, 'job_lock_busy_no_change'
            time.sleep(2)
    replaced = []
    try:
        old = {n: open(os.path.join(B, n), 'rb').read() for n in OLD}
        assert all(sha(old[n]) == OLD[n] for n in OLD), 'installed_runtime_differs_no_change'
        for n in OLD:
            s = os.lstat(os.path.join(B, n))
            assert (s.st_uid, s.st_gid, s.st_mode & 0o7777, s.st_nlink) == (0, 0, 0o400, 1), 'installed_metadata_differs_no_change'
        backup = '/var/backups/capstone-history-auto-cap1024-' + time.strftime('%Y%m%dT%H%M%S')
        os.mkdir(backup, 0o700)
        for n in OLD:
            with open(os.path.join(backup, n), 'xb') as f:
                f.write(old[n])
            os.chmod(os.path.join(backup, n), 0o400)
        out['backup'] = backup
        try:
            for n in ('auto-lib.sh', 'runtime.sha256'):
                put(os.path.join(B, n), new[n]); replaced.append(n)
            r = subprocess.run(['bash', '-c', 'cd %s && sha256sum --status -c runtime.sha256' % B], timeout=30)
            assert r.returncode == 0, 'manifest_check_failed'
        except Exception:
            for n in replaced:
                put(os.path.join(B, n), old[n])
            out['restored'] = replaced
            raise
        out['installed'] = {n: sha(open(os.path.join(B, n), 'rb').read())[:16] for n in OLD}
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
    r = subprocess.run(['/usr/local/sbin/capstone-vector-history-auto', 'inspect'], capture_output=True, text=True, timeout=60)
    out['inspect'] = [r.returncode, r.stdout.strip()[-600:]]
    out['status'] = 'applied' if r.returncode == 0 else 'applied_inspect_failed'


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e:
        out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:200]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
