#!/usr/bin/env python3
"""B: deploy claim-bound peer refusal diagnosis (the correction names the
refused claim, its evidence path, the reason and an acceptable fix) and the
path-only refusal audit (peer_validation_details) kept in the joint-channel
queue (11-14 01:49 both peer attempts were refused with the bare code).

Usage: apply_b.py <review_channel_worker.py> <review_channel.py>
Exact previous SHAs for the two installed joint-channel files and the
review-chat installer receipt entries; the Ollama and management copies are
not touched. A private backup and a 45-minute rollback timer; every
replacement under the controller lock; only while both chat queues are idle.
The worker runs per job, so it takes effect at once; the dispatcher
(capstone-review-chat) is restarted only if its queue is still idle, else the
restart is left pending and reported. Rollback restores both files and
restarts the dispatcher once its queue is idle (waits up to 10 minutes).
"""
import fcntl, hashlib, json, os, shutil, sqlite3, subprocess, sys, time
from pathlib import Path
OLD = {'worker': 'da7e3a3de93a92b7e6cd5e528595c819779cca49b410ba6d31d779dfd8f84275', 'dispatcher': '4e2383284bcb8c76a24e02e60379dc24fbe858c1776500866890d89946438eb5'}
NEW = {'worker': '1cff48cc325f5facb09c73f5c7721c2a03a5e2a903309f022349dcfcef962002', 'dispatcher': 'f52ec1a267da3b82139a500db890ea519c23d1928641d4c1aa4c214cc1706217'}
PLAN = [('/opt/capstone-review-chat/review_channel_worker.py', 'worker'), ('/opt/capstone-review-chat/review_channel.py', 'dispatcher')]
REVIEW_RECEIPT = Path('/etc/capstone-review-chat/receipt.json')
REVIEW_QUEUE = '/var/lib/capstone-review-chat/queue.sqlite'
OLLAMA_QUEUE = '/var/lib/capstone-ollama-trial/chat/queue.sqlite'
SERVICE = 'capstone-review-chat.service'
DIR = Path('/var/lib/capstone-service-grounding/20261114-peer-diagnosis')
LOCK = '/var/lib/capstone-management/controller.lock'
UNIT = 'capstone-rollback-peer-diagnosis'
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def idle(path):
    with sqlite3.connect('file:' + path + '?mode=ro', uri=True) as db:
        return db.execute("select count(*) from jobs where status in ('queued','running','delivery')").fetchone()[0] == 0
def main():
    assert len(sys.argv) == 3, 'usage'
    new = {k: open(p, 'rb').read() for k, p in zip(('worker', 'dispatcher'), sys.argv[1:3])}
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
    vrec['peer_diagnosis_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'backup': str(DIR)}
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
        "def idle():\n with sqlite3.connect('file:'+%r+'?mode=ro',uri=True) as db:return db.execute(\"select count(*) from jobs where status in ('queued','running','delivery')\").fetchone()[0]==0\n"
        "end=time.time()+600\n"
        "while not idle() and time.time()<end:time.sleep(5)\n"
        "subprocess.run(['systemctl','restart',%r])\n") % (str(DIR), LOCK, REVIEW_QUEUE, SERVICE)
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
            tmp = p.with_name('.' + p.name + '.peer-diagnosis')
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
    if idle(REVIEW_QUEUE):
        out['restart_dispatcher'] = subprocess.run(['systemctl', 'restart', SERVICE], capture_output=True, text=True, timeout=120).returncode
    else:
        out['restart_dispatcher'] = 'pending_queue_busy'
    out['dispatcher_active'] = subprocess.run(['systemctl', 'is-active', SERVICE], capture_output=True, text=True).stdout.strip()
    out['after'] = {m['path']: sha(Path(m['path']).read_bytes())[:16] for m in meta}
    out['status'] = 'applied'
if __name__ == '__main__':
    try: main()
    except AssertionError as e: out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e: out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:300]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
