#!/usr/bin/env python3
"""B: raise the published receipt-catalog bound to the 1024-batch bound. Root, once.

Usage: apply-publish-cap-b.py <new transfer-lib.sh> <new runtime.sha256>
2026-11-14: since 23:54 every run stopped at finalize (exit 65) because the
23:36 catalog (386 receipts, 262,370 bytes) exceeded the fixed 256 KiB publish
bound; the 11-13 19:31 batch-bound sync (256 -> 1024) had missed it.
Under the transfer job lock (so no run is mid-way), replace exactly two
installed runtime files (root:root 0400 nlink 1) after checking they and the
unchanged worker still equal the reviewed live bytes, then verify
runtime.sha256. Originals go to a private backup; any failure after the first
replace puts all back. Receipts, published catalogs, work attempts (including
kept failures), the receiver and A are not touched. It does not start a
transfer; run the unit once afterwards and check status.json.
"""
import fcntl, hashlib, json, os, subprocess, sys, tempfile, time
LIB = '/usr/local/lib/capstone-history-auto-transfer'
LOCK = '/var/lib/capstone-history-auto-transfer/.lock'
BACKUP = '/var/backups/capstone-history-transfer-publishcap-'
WORKER = '6781b8fd74546f36e1b8bad3ddbcddb7055c5e7a5625acb914dd885d1c5304b5'
OLD = {'transfer-lib.sh': '52dbb82b0cb31ce8fc2e29257b56c43b46ead47afbb9c02a6b2e4385eff251d4',
       'runtime.sha256': '9a62534a4e2d320206fc4f44d218ea57e8a507cc97bce1313b8434aec975c64e'}
NEW = {'transfer-lib.sh': '0ed5bbe69829a9d7dc3671241872da82590982f5ecd97167c2e05c0c8006cb2d',
       'runtime.sha256': 'abdd7d6748228e090770fa8f1f329551fda9c076ef8d184f7b54b7eed13eede8'}
NAMES = ('transfer-lib.sh', 'runtime.sha256')
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def put(path, data):
    tmp = path + '.publishcap.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fchown(f.fileno(), 0, 0); os.fchmod(f.fileno(), 0o400); os.fsync(f.fileno())
    os.replace(tmp, path)
def main():
    assert len(sys.argv) == 3, 'usage'
    new = {n: open(p, 'rb').read() for n, p in zip(NAMES, sys.argv[1:3])}
    assert all(sha(new[n]) == NEW[n] for n in NAMES), 'candidate_changed'
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW); deadline = time.time() + 100
    while True:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
        except BlockingIOError:
            assert time.time() < deadline, 'transfer_lock_busy_no_change'; time.sleep(2)
    replaced = []
    try:
        old = {n: open(os.path.join(LIB, n), 'rb').read() for n in NAMES}
        assert all(sha(old[n]) == OLD[n] for n in NAMES), 'installed_runtime_differs_no_change'
        assert sha(open(os.path.join(LIB, 'worker-b.sh'), 'rb').read()) == WORKER, 'installed_worker_differs_no_change'
        for n in NAMES + ('worker-b.sh',):
            s = os.lstat(os.path.join(LIB, n))
            assert (s.st_uid, s.st_gid, s.st_mode & 0o7777, s.st_nlink) == (0, 0, 0o400, 1), 'installed_metadata_differs_no_change'
        # Unique private directory (0700): never reuse or overwrite an earlier backup.
        backup = tempfile.mkdtemp(prefix=os.path.basename(BACKUP) + time.strftime('%Y%m%dT%H%M%S') + '-', dir=os.path.dirname(BACKUP))
        for n in NAMES:
            with open(os.path.join(backup, n), 'xb') as f: f.write(old[n])
            os.chmod(os.path.join(backup, n), 0o400)
        out['backup'] = backup
        try:
            for n in NAMES:
                put(os.path.join(LIB, n), new[n]); replaced.append(n)
            r = subprocess.run(['bash', '-c', 'cd %s && sha256sum --status -c runtime.sha256' % LIB], timeout=30)
            assert r.returncode == 0, 'manifest_check_failed'
        except Exception:
            for n in replaced: put(os.path.join(LIB, n), old[n])
            out['restored'] = replaced
            raise
        out['installed'] = {n: sha(open(os.path.join(LIB, n), 'rb').read())[:16] for n in NAMES}
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)
    out['status'] = 'applied'
if __name__ == '__main__':
    try: main()
    except AssertionError as e: out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e: out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:200]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
