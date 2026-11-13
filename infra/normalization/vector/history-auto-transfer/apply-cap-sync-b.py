#!/usr/bin/env python3
"""B: raise the transfer worker bounds to the A store/exporter bounds. Root, once.

Usage: apply-cap-sync-b.py <new worker-b.sh> <new transfer-lib.sh> <new runtime.sha256>
Under the transfer job lock (so no run is mid-way), replace exactly three
installed runtime files (root:root 0400 nlink 1) after checking they still equal
the reviewed previous bytes, then verify runtime.sha256. Originals go to a
private backup; any failure after the first replace puts all back. Receipts,
work attempts (including kept failures), the receiver and A are not touched.
It does not start a transfer; run the unit once afterwards and check status.json.
"""
import fcntl, hashlib, json, os, subprocess, sys, time
LIB = '/usr/local/lib/capstone-history-auto-transfer'
LOCK = '/var/lib/capstone-history-auto-transfer/.lock'
OLD = {'worker-b.sh': '7e783365c4af1ba44ec4b5b5705a336402632760cfb05b2e060b020e9bd80e59',
       'transfer-lib.sh': '012411c7a2f1a1b27f0e9ce5a120198a32bb9632f6f09a06ebcf6a86d4b733c2',
       'runtime.sha256': '141364913b6ae08a4a13064e8f6f3b57c774b9aee6ec8ef5995bca3a1db5c421'}
NEW = {'worker-b.sh': '6781b8fd74546f36e1b8bad3ddbcddb7055c5e7a5625acb914dd885d1c5304b5',
       'transfer-lib.sh': '52dbb82b0cb31ce8fc2e29257b56c43b46ead47afbb9c02a6b2e4385eff251d4',
       'runtime.sha256': '9a62534a4e2d320206fc4f44d218ea57e8a507cc97bce1313b8434aec975c64e'}
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def put(path, data):
    tmp = path + '.capsync.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fchown(f.fileno(), 0, 0); os.fchmod(f.fileno(), 0o400); os.fsync(f.fileno())
    os.replace(tmp, path)
def main():
    names = ('worker-b.sh', 'transfer-lib.sh', 'runtime.sha256')
    new = {n: open(p, 'rb').read() for n, p in zip(names, sys.argv[1:4])}
    assert all(sha(new[n]) == NEW[n] for n in names), 'candidate_changed'
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW); deadline = time.time() + 100
    while True:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
        except BlockingIOError:
            assert time.time() < deadline, 'transfer_lock_busy_no_change'; time.sleep(2)
    replaced = []
    try:
        old = {n: open(os.path.join(LIB, n), 'rb').read() for n in names}
        assert all(sha(old[n]) == OLD[n] for n in names), 'installed_runtime_differs_no_change'
        for n in names:
            s = os.lstat(os.path.join(LIB, n))
            assert (s.st_uid, s.st_gid, s.st_mode & 0o7777, s.st_nlink) == (0, 0, 0o400, 1), 'installed_metadata_differs_no_change'
        backup = '/var/backups/capstone-history-transfer-capsync-' + time.strftime('%Y%m%dT%H%M%S')
        os.mkdir(backup, 0o700)
        for n in names:
            with open(os.path.join(backup, n), 'xb') as f: f.write(old[n])
            os.chmod(os.path.join(backup, n), 0o400)
        out['backup'] = backup
        try:
            for n in names:
                put(os.path.join(LIB, n), new[n]); replaced.append(n)
            r = subprocess.run(['bash', '-c', 'cd %s && sha256sum --status -c runtime.sha256' % LIB], timeout=30)
            assert r.returncode == 0, 'manifest_check_failed'
        except Exception:
            for n in replaced: put(os.path.join(LIB, n), old[n])
            out['restored'] = replaced
            raise
        out['installed'] = {n: sha(open(os.path.join(LIB, n), 'rb').read())[:16] for n in names}
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
    out['status'] = 'applied'
if __name__ == '__main__':
    try: main()
    except AssertionError as e: out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e: out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:200]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
