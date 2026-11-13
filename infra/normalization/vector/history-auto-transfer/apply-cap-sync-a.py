#!/usr/bin/env python3
"""A: raise the read-only exporter bounds to the history-auto store bounds. Root, once.

Usage: apply-cap-sync-a.py <new export-a.sh>
The exporter is pinned by digest in /etc/sudoers.d/capstone-history-export, so
the binary and that one digest change together: new sudoers text is checked with
`visudo -cf`, both originals are backed up, both are replaced back to back and
the full sudoers tree is re-checked. Any failure restores both. The store, jobs,
journal, account, key and SSH gate are not touched. No retry.
"""
import hashlib, json, os, subprocess, sys, time
EXPORTER = '/usr/local/libexec/capstone-history-export'
SUDOERS = '/etc/sudoers.d/capstone-history-export'
OLD = 'dc4fc243116d27702b99613630a5488969a95033a7674d79eee137336fd00725'
NEW = 'fd1e7769f8da6828da31aac101fc29a3ea343a2ff1c57301b27f09483f80355e'
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def visudo(path):
    return subprocess.run(['/usr/sbin/visudo', '-cf', path], capture_output=True, text=True).returncode
def put(path, data, mode):
    tmp = path + '.capsync.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fchown(f.fileno(), 0, 0); os.fchmod(f.fileno(), mode); os.fsync(f.fileno())
    return tmp
def main():
    new = open(sys.argv[1], 'rb').read()
    assert sha(new) == NEW, 'candidate_changed'
    old = open(EXPORTER, 'rb').read(); st = os.lstat(EXPORTER)
    assert sha(old) == OLD and (st.st_uid, st.st_gid, st.st_mode & 0o7777, st.st_nlink) == (0, 0, 0o500, 1), 'exporter_not_baseline_no_change'
    sold = open(SUDOERS, 'rb').read(); ss = os.lstat(SUDOERS)
    assert (ss.st_uid, ss.st_gid, ss.st_mode & 0o7777) == (0, 0, 0o440) and sold.count(('sha256:' + OLD).encode()) == 1, 'sudoers_not_baseline_no_change'
    snew = sold.replace(('sha256:' + OLD).encode(), ('sha256:' + NEW).encode())
    backup = '/var/backups/capstone-history-transfer-capsync-' + time.strftime('%Y%m%dT%H%M%S')
    os.mkdir(backup, 0o700)
    for name, data in (('capstone-history-export', old), ('sudoers-capstone-history-export', sold)):
        with open(os.path.join(backup, name), 'xb') as f: f.write(data)
        os.chmod(os.path.join(backup, name), 0o400)
    out['backup'] = backup
    check = os.path.join(backup, 'sudoers.candidate')
    with open(check, 'xb') as f: f.write(snew)
    os.chmod(check, 0o440)
    assert visudo(check) == 0, 'candidate_sudoers_invalid_no_change'
    t_sudo = put(SUDOERS, snew, 0o440); t_exp = put(EXPORTER, new, 0o500)
    replaced = []
    try:
        os.replace(t_sudo, SUDOERS); replaced.append('sudoers')
        os.replace(t_exp, EXPORTER); replaced.append('exporter')
        assert visudo('/etc/sudoers') == 0, 'sudoers_tree_invalid'
        assert sha(open(EXPORTER, 'rb').read()) == NEW and open(SUDOERS, 'rb').read() == snew, 'post_write'
    except Exception:
        for path, data, mode in ((SUDOERS, sold, 0o440), (EXPORTER, old, 0o500)):
            if os.path.exists(path + '.capsync.tmp'): os.remove(path + '.capsync.tmp')
            os.replace(put(path, data, mode), path)
        out['restored'] = replaced
        raise
    out['exporter_sha16'] = NEW[:16]
    out['status'] = 'applied'
if __name__ == '__main__':
    try: main()
    except AssertionError as e: out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e: out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:200]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
