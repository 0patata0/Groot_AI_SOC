#!/usr/bin/env python3
"""B: deploy the read-time correction fix. Root, once, via the admin host.

Usage: apply_b.py <new review_channel_worker.py> <new chat_contract.py>
Replaces exactly four installed copies after checking each still equals the
reviewed previous bytes, keeps owner/mode, updates the Ollama trial receipt's
chat_contract.py digest, and restarts only capstone-ollama-chat (its runtime
loads chat_contract at start) when its queue is idle. Joint-channel Hermes jobs
start a fresh worker and management process per job, so they use the new files
without a restart. Originals go to a private backup; any failure restores all.
"""
import hashlib, json, os, shutil, sqlite3, subprocess, sys, time
OLD = {'worker': 'bba9a951405324c88ca82bc7a4c55b2ec50da3f63e85bfbfb83fe31f6167accb', 'contract': '4ef328b644c0bdf67088473de1d519273f6addacc0699510209e8a10e4b6c55c'}
NEW = {'worker': '9973fbf18762bd13cfed89982b84c7281da07bb415c4ac5f6788710d8db8e048', 'contract': '2cae4b65c553dc445b6d503dbf888b187a4656e95d10920dba7a21946e2eca96'}
TARGETS = [('/opt/capstone-review-chat/review_channel_worker.py', 'worker'),
           ('/opt/hermes-data/plugins/groot-query-completion/chat_contract.py', 'contract'),
           ('/opt/capstone-ollama-trial/chat_contract.py', 'contract'),
           ('/opt/capstone-prereqs/ollama-trial/source/infra/hermes/chat_contract.py', 'contract')]
RECEIPT = '/etc/capstone-ollama-trial/receipt.json'
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def busy():
    with sqlite3.connect('file:/var/lib/capstone-ollama-trial/chat/queue.sqlite?mode=ro', uri=True) as db:
        return db.execute("select count(*) from jobs where status in ('queued','running','delivery')").fetchone()[0]
def put(path, data, st):
    tmp = path + '.timefix.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fchown(f.fileno(), st.st_uid, st.st_gid); os.fchmod(f.fileno(), st.st_mode & 0o7777); os.fsync(f.fileno())
    os.replace(tmp, path)
def main():
    new = {'worker': open(sys.argv[1], 'rb').read(), 'contract': open(sys.argv[2], 'rb').read()}
    assert all(sha(new[k]) == NEW[k] for k in NEW), 'candidate_changed'
    old, stats = {}, {}
    for path, kind in TARGETS:
        raw = open(path, 'rb').read(); st = os.lstat(path)
        assert sha(raw) == OLD[kind] and st.st_nlink == 1 and not os.path.islink(path), ('target_not_baseline_no_change', path)
        old[path], stats[path] = raw, st
    rraw = open(RECEIPT, 'rb').read(); rec = json.loads(rraw); rst = os.lstat(RECEIPT)
    assert rec['sources'].get('chat_contract.py') == OLD['contract'], 'receipt_not_baseline_no_change'
    rec['sources']['chat_contract.py'] = NEW['contract']
    rec['time_correction_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    rnew = (json.dumps(rec, indent=2, ensure_ascii=False) + '\n').encode()
    assert busy() == 0, 'ollama_queue_busy_no_change'
    backup = '/var/backups/capstone-time-correction-' + time.strftime('%Y%m%dT%H%M%S'); os.mkdir(backup, 0o700)
    for path in list(old) + [RECEIPT]:
        dst = os.path.join(backup, path.strip('/').replace('/', '_'))
        with open(dst, 'xb') as f: f.write(old.get(path, rraw))
        os.chmod(dst, 0o400)
    out['backup'] = backup
    done = []
    try:
        for path, kind in TARGETS:
            put(path, new[kind], stats[path]); done.append(path)
        put(RECEIPT, rnew, rst); done.append(RECEIPT)
        assert all(sha(open(p, 'rb').read()) == NEW[k] for p, k in TARGETS), 'post_write'
    except Exception:
        for path in done: put(path, old.get(path, rraw), stats.get(path, rst))
        out['restored'] = done
        raise
    if busy() == 0:
        out['restart_ollama'] = subprocess.run(['systemctl', 'restart', 'capstone-ollama-chat.service'], capture_output=True, text=True, timeout=120).returncode
        time.sleep(5)
    out['ollama_active'] = subprocess.run(['systemctl', 'is-active', 'capstone-ollama-chat.service'], capture_output=True, text=True).stdout.strip()
    out['installed'] = {p: sha(open(p, 'rb').read())[:16] for p, _ in TARGETS}
    out['status'] = 'applied'
if __name__ == '__main__':
    try: main()
    except AssertionError as e: out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e: out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:200]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
