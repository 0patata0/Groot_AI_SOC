#!/usr/bin/env python3
"""B: deploy the peer-text id stripping fix: catalog ids (a0, e9) are removed
as standalone ASCII tokens, including before Korean particles ("증거 e9에"),
in lists and ranges ("e3~e4") and as bare ids ("e70으로" -> "조회 근거로");
hashes, MAC/IPv6 addresses and ids outside the catalog stay. 11-13 23:50,
11-14 00:04 and 04:17 peer posts leaked ids.

Usage: apply_b.py <review_channel_worker.py>
Exact previous SHA for the installed joint-channel worker and its review-chat
installer receipt entry; nothing else is touched. A private backup and a
45-minute rollback timer; the replacement under the controller lock; only
while both chat queues are idle. The worker runs per job, so no service is
restarted (the dispatcher keeps running).
"""
import fcntl, hashlib, json, os, shutil, sqlite3, subprocess, sys, time
from pathlib import Path
OLD = {'worker': '1cff48cc325f5facb09c73f5c7721c2a03a5e2a903309f022349dcfcef962002'}
NEW = {'worker': '679cd99237684a6ca42e6e0b9e0acd1329ed77d63ca4c39b0d7f8fe9f8bcb428'}
PLAN = [('/opt/capstone-review-chat/review_channel_worker.py', 'worker')]
REVIEW_RECEIPT = Path('/etc/capstone-review-chat/receipt.json')
REVIEW_QUEUE = '/var/lib/capstone-review-chat/queue.sqlite'
OLLAMA_QUEUE = '/var/lib/capstone-ollama-trial/chat/queue.sqlite'
SERVICE = 'capstone-review-chat.service'
DIR = Path('/var/lib/capstone-service-grounding/20261114-peer-ids')
LOCK = '/var/lib/capstone-management/controller.lock'
UNIT = 'capstone-rollback-peer-ids'
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def idle(path):
    with sqlite3.connect('file:' + path + '?mode=ro', uri=True) as db:
        return db.execute("select count(*) from jobs where status in ('queued','running','delivery')").fetchone()[0] == 0
def main():
    assert len(sys.argv) == 2, 'usage'
    new = {'worker': open(sys.argv[1], 'rb').read()}
    assert all(sha(new[k]) == NEW[k] for k in NEW), 'candidate_changed'
    for v in new.values(): compile(v, 'candidate', 'exec')
    assert not DIR.exists(), 'deploy_dir_exists'
    rows = []
    for path, kind in PLAN:
        p = Path(path); raw = p.read_bytes(); assert sha(raw) == OLD[kind] and p.stat().st_nlink == 1 and not p.is_symlink(), ('target_not_baseline_no_change', path)
        rows.append((p, raw, new[kind]))
    vraw = REVIEW_RECEIPT.read_bytes(); vrec = json.loads(vraw)
    for path, kind in PLAN:
        assert vrec['files'].get(path) == OLD[kind], ('review_receipt_not_baseline_no_change', path); vrec['files'][path] = NEW[kind]
    vrec['peer_ids_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'backup': str(DIR)}
    rows.append((REVIEW_RECEIPT, vraw, json.dumps(vrec).encode()))
    assert idle(REVIEW_QUEUE) and idle(OLLAMA_QUEUE), 'chat_queue_busy_no_change'
    DIR.mkdir(mode=0o700); (DIR / 'backup').mkdir(mode=0o700); meta = []
    for p, old, data in rows:
        st = p.stat(); dst = DIR / 'backup' / str(p).lstrip('/'); dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700); shutil.copy2(p, dst)
        meta.append({'path': str(p), 'old': sha(old), 'new': sha(data), 'uid': st.st_uid, 'gid': st.st_gid, 'mode': st.st_mode & 0o7777})
    (DIR / 'plan.json').write_text(json.dumps(meta, indent=1))
    rollback = ("import json,hashlib,shutil,os,fcntl,time,subprocess,sqlite3\nfrom pathlib import Path\nD=Path(%r)\n"
        "if (D/'CONFIRMED').exists() or (D/'ROLLED_BACK').exists():raise SystemExit(0)\n"
        "fd=os.open(%r,os.O_CREAT|os.O_RDWR,0o600);end=time.time()+600\n"
        "while True:\n try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break\n except BlockingIOError:\n  if time.time()>end:raise\n  time.sleep(2)\n"
        "plan=json.loads((D/'plan.json').read_text());res=[]\n"
        "for r in plan:\n p=Path(r['path']);cur=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        " if cur==r['old']:res.append((r['path'],'already_old'));continue\n"
        " if cur!=r['new']:res.append((r['path'],'changed_by_other_skip'));continue\n"
        " tmp=p.with_name('.'+p.name+'.rollback');shutil.copy2(D/'backup'/r['path'].lstrip('/'),tmp);os.chown(tmp,r['uid'],r['gid']);os.chmod(tmp,r['mode']);os.replace(tmp,p);res.append((r['path'],'restored'))\n"
        "(D/'ROLLED_BACK').write_text(json.dumps(res))\n"
        ) % (str(DIR), LOCK)
    (DIR / 'rollback.py').write_text(rollback); os.chmod(DIR / 'rollback.py', 0o700)
    r = subprocess.run(['systemd-run', '--unit=' + UNIT, '--on-active=2700', '--timer-property=AccuracySec=1s', '/usr/bin/python3', '-I', '-B', str(DIR / 'rollback.py')], capture_output=True, text=True)
    assert r.returncode == 0, ('arm_failed', r.stderr[-200:]); out['rollback_timer'] = UNIT + '.timer (45 min)'
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR, 0o600); end = time.time() + 90
    while True:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
        except BlockingIOError:
            if time.time() > end:
                subprocess.run(['systemctl', 'stop', UNIT + '.timer'], capture_output=True); (DIR / 'ABORTED').write_text('controller_busy'); raise AssertionError('controller_busy_no_change')
            time.sleep(1)
    done = []
    try:
        for m in meta:
            p = Path(m['path']); data = next(d for q, _, d in rows if str(q) == m['path'])
            assert sha(p.read_bytes()) == m['old'], ('changed_before_apply', m['path'])
            tmp = p.with_name('.' + p.name + '.peer-ids')
            fdw = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fdw, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
            os.chown(tmp, m['uid'], m['gid']); os.chmod(tmp, m['mode']); os.replace(tmp, p)
            assert sha(p.read_bytes()) == m['new'], ('post_write', m['path']); done.append(m['path'])
        (DIR / 'APPLIED').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z'))
    except Exception:
        for m in meta:
            if m['path'] in done:
                p = Path(m['path']); tmp = p.with_name('.' + p.name + '.restore'); shutil.copy2(DIR / 'backup' / m['path'].lstrip('/'), tmp)
                os.chown(tmp, m['uid'], m['gid']); os.chmod(tmp, m['mode']); os.replace(tmp, p)
        subprocess.run(['systemctl', 'stop', UNIT + '.timer'], capture_output=True); (DIR / 'FAILED_RESTORED').write_text('restored'); out['restored'] = done
        raise
    finally:
        os.close(fd)
    out['restart'] = 'none (worker runs per job)'
    out['dispatcher_active'] = subprocess.run(['systemctl', 'is-active', SERVICE], capture_output=True, text=True).stdout.strip()
    out['after'] = {m['path']: sha(Path(m['path']).read_bytes())[:16] for m in meta}
    out['status'] = 'applied'
if __name__ == '__main__':
    try: main()
    except AssertionError as e: out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e: out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:300]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
