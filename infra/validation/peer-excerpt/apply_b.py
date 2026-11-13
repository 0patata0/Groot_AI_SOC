#!/usr/bin/env python3
"""B: deploy self-describing peer-review excerpt keys (not_shown_in_excerpt,
not_shown_characters, not_shown instead of omitted_*), the excerpt format in
the reviewer instruction, the refusal of agree/disagree on display-excerpt
counts, and the corrected soc-investigate peer-review sentence (the 01:35
wording wrongly tied omitted_items to the reviewer's limit; 11-14 01:38 the
reviewer read "omitted_items 7" as seven alerts dropped by its limit).

Usage: apply_b.py <review_channel_worker.py> <soc-investigate SKILL.md>
Same procedure as the 11-14 01:35 peer-limit deploy: the joint-channel worker
(x1, plus the review-chat installer receipt) and the soc-investigate skill
(x3, plus the Ollama receipt key); runner and controller gate untouched. A
private backup and a 45-minute rollback timer; every replacement under the
controller lock; only while both chat queues are idle. capstone-ollama-chat
is restarted only when its queue is idle.
"""
import fcntl, hashlib, json, os, shutil, sqlite3, subprocess, sys, time
from pathlib import Path
OLD = {'worker': '923db59416ec1a7a0d68ce8c3c794aa995876974b90754bb2161c5ff589accf2',
       'skill': '125ed453d237d273092e23413b1ab4b1f1a9bbec61647edded8fc1ec1b56e372'}
NEW = {'worker': 'da7e3a3de93a92b7e6cd5e528595c819779cca49b410ba6d31d779dfd8f84275',
       'skill': '50825f277ea034916546d05ea908d30ed698419e8b519f730ee7357952016c40'}
PLAN = [('/opt/capstone-review-chat/review_channel_worker.py', 'worker'),
        ('/opt/hermes-data/plugins/groot-query-completion/skill-soc-investigate.md', 'skill'), ('/opt/capstone-ollama-trial/skill-soc-investigate.md', 'skill'),
        ('/opt/capstone-management/skill-soc-investigate.md', 'skill')]
RECEIPT_KEYS = {'skill-soc-investigate.md': 'skill'}
RECEIPT = Path('/etc/capstone-ollama-trial/receipt.json')
REVIEW_RECEIPT = Path('/etc/capstone-review-chat/receipt.json')
WORKER = '/opt/capstone-review-chat/review_channel_worker.py'
DIR = Path('/var/lib/capstone-service-grounding/20261114-peer-excerpt')
LOCK = '/var/lib/capstone-management/controller.lock'
UNIT = 'capstone-rollback-peer-excerpt'
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def idle(path):
    with sqlite3.connect('file:' + path + '?mode=ro', uri=True) as db:
        return db.execute("select count(*) from jobs where status in ('queued','running','delivery')").fetchone()[0] == 0
def main():
    assert len(sys.argv) == 3, 'usage'
    new = {k: open(p, 'rb').read() for k, p in zip(('worker', 'skill'), sys.argv[1:3])}
    assert all(sha(new[k]) == NEW[k] for k in NEW), 'candidate_changed'
    compile(new['worker'], 'candidate', 'exec')
    assert new['skill'].startswith(b'---\nname: soc-investigate\n') and '## 교차 검토 대조'.encode() in new['skill'], 'skill_shape'
    assert not DIR.exists(), 'deploy_dir_exists'
    rows = []
    for path, kind in PLAN:
        p = Path(path); raw = p.read_bytes(); assert sha(raw) == OLD[kind] and p.stat().st_nlink == 1 and not p.is_symlink(), ('target_not_baseline_no_change', path)
        rows.append((p, raw, new[kind]))
    rraw = RECEIPT.read_bytes(); rec = json.loads(rraw)
    for key, kind in RECEIPT_KEYS.items():
        assert rec['sources'].get(key) == OLD[kind], ('receipt_not_baseline_no_change', key); rec['sources'][key] = NEW[kind]
    rec['peer_excerpt_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'backup': str(DIR)}
    rows.append((RECEIPT, rraw, (json.dumps(rec, indent=2, ensure_ascii=False) + '\n').encode()))
    vraw = REVIEW_RECEIPT.read_bytes(); vrec = json.loads(vraw)
    assert vrec['files'].get(WORKER) == OLD['worker'], 'review_receipt_not_baseline_no_change'
    vrec['files'][WORKER] = NEW['worker']
    vrec['peer_excerpt_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'backup': str(DIR)}
    rows.append((REVIEW_RECEIPT, vraw, json.dumps(vrec).encode()))
    assert idle('/var/lib/capstone-review-chat/queue.sqlite') and idle('/var/lib/capstone-ollama-trial/chat/queue.sqlite'), 'chat_queue_busy_no_change'
    DIR.mkdir(mode=0o700); (DIR / 'backup').mkdir(mode=0o700); meta = []
    for p, old, data in rows:
        st = p.stat(); dst = DIR / 'backup' / str(p).lstrip('/'); dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700); shutil.copy2(p, dst)
        meta.append({'path': str(p), 'old': sha(old), 'new': sha(data), 'uid': st.st_uid, 'gid': st.st_gid, 'mode': st.st_mode & 0o7777})
    (DIR / 'plan.json').write_text(json.dumps(meta, indent=1))
    rollback = ("import json,hashlib,shutil,os,fcntl,time,subprocess\nfrom pathlib import Path\nD=Path(%r)\n"
        "if (D/'CONFIRMED').exists() or (D/'ROLLED_BACK').exists():raise SystemExit(0)\n"
        "fd=os.open(%r,os.O_CREAT|os.O_RDWR,0o600);end=time.time()+600\n"
        "while True:\n try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break\n except BlockingIOError:\n  if time.time()>end:raise\n  time.sleep(2)\n"
        "plan=json.loads((D/'plan.json').read_text());res=[]\n"
        "for r in plan:\n p=Path(r['path']);cur=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        " if cur==r['old']:res.append((r['path'],'already_old'));continue\n"
        " if cur!=r['new']:res.append((r['path'],'changed_by_other_skip'));continue\n"
        " tmp=p.with_name('.'+p.name+'.rollback');shutil.copy2(D/'backup'/r['path'].lstrip('/'),tmp);os.chown(tmp,r['uid'],r['gid']);os.chmod(tmp,r['mode']);os.replace(tmp,p);res.append((r['path'],'restored'))\n"
        "(D/'ROLLED_BACK').write_text(json.dumps(res))\n"
        "subprocess.run(['systemctl','restart','capstone-ollama-chat.service'])\n") % (str(DIR), LOCK)
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
            tmp = p.with_name('.' + p.name + '.peer-excerpt')
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
    if idle('/var/lib/capstone-ollama-trial/chat/queue.sqlite'):
        out['restart_ollama'] = subprocess.run(['systemctl', 'restart', 'capstone-ollama-chat.service'], capture_output=True, text=True, timeout=120).returncode
    out['ollama_active'] = subprocess.run(['systemctl', 'is-active', 'capstone-ollama-chat.service'], capture_output=True, text=True).stdout.strip()
    out['after'] = {m['path']: sha(Path(m['path']).read_bytes())[:16] for m in meta}
    out['status'] = 'applied'
if __name__ == '__main__':
    try: main()
    except AssertionError as e: out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e: out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:300]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
