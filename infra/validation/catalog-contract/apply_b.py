#!/usr/bin/env python3
"""B: deploy the Ollama MCP catalog-contract fix. Root, once, via the admin host.

Usage: apply_b.py <policy.py>
Replaces /opt/capstone-ollama-trial/policy.py (exact previous SHA) and the
matching Ollama receipt entry, with a private backup and a 45-minute rollback
timer, only while both chat queues are idle. The management runner and the
controller are not touched, so the controller lock is not needed. Joint-channel
peer jobs start a fresh worker process per job; capstone-ollama-chat is
restarted only when its queue is idle. Confirm later by writing CONFIRMED and
stopping the timer, or let it roll back.
"""
import hashlib, json, os, shutil, sqlite3, subprocess, sys, time
from pathlib import Path
OLD = '7716bdd32495dd547072cc1070d6c13a07d4fb9e5ca1a594aba152b63cdf496b'
NEW = '832d8c691a9721b40c894b69ad3f004b52a6348a4ec49514871bcd57f916ff9b'
TARGET = Path('/opt/capstone-ollama-trial/policy.py')
RECEIPT = Path('/etc/capstone-ollama-trial/receipt.json')
DIR = Path('/var/lib/capstone-service-grounding/20261113-catalog-contract')
UNIT = 'capstone-rollback-catalog-contract'
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def idle(path):
    with sqlite3.connect('file:' + path + '?mode=ro', uri=True) as db:
        return db.execute("select count(*) from jobs where status in ('queued','running','delivery')").fetchone()[0] == 0
def main():
    new = open(sys.argv[1], 'rb').read()
    assert sha(new) == NEW, 'candidate_changed'
    compile(new, 'candidate', 'exec')
    assert not DIR.exists(), 'deploy_dir_exists'
    raw = TARGET.read_bytes()
    assert sha(raw) == OLD and TARGET.stat().st_nlink == 1 and not TARGET.is_symlink(), 'target_not_baseline_no_change'
    rows = [(TARGET, raw, new)]
    rraw = RECEIPT.read_bytes(); rec = json.loads(rraw)
    assert rec['sources'].get('policy.py') == OLD, 'receipt_not_baseline_no_change'
    rec['sources']['policy.py'] = NEW
    rec['catalog_contract_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'backup': str(DIR)}
    rows.append((RECEIPT, rraw, (json.dumps(rec, indent=2, ensure_ascii=False) + '\n').encode()))
    assert idle('/var/lib/capstone-review-chat/queue.sqlite') and idle('/var/lib/capstone-ollama-trial/chat/queue.sqlite'), 'chat_queue_busy_no_change'
    DIR.mkdir(mode=0o700); (DIR / 'backup').mkdir(mode=0o700); meta = []
    for p, old, data in rows:
        st = p.stat(); dst = DIR / 'backup' / str(p).lstrip('/'); dst.parent.mkdir(parents=True, exist_ok=True, mode=0o700); shutil.copy2(p, dst)
        meta.append({'path': str(p), 'old': sha(old), 'new': sha(data), 'uid': st.st_uid, 'gid': st.st_gid, 'mode': st.st_mode & 0o7777})
    (DIR / 'plan.json').write_text(json.dumps(meta, indent=1))
    rollback = ("import json,hashlib,shutil,os,subprocess\nfrom pathlib import Path\nD=Path(%r)\n"
        "if (D/'CONFIRMED').exists() or (D/'ROLLED_BACK').exists():raise SystemExit(0)\n"
        "plan=json.loads((D/'plan.json').read_text());res=[]\n"
        "for r in plan:\n p=Path(r['path']);cur=hashlib.sha256(p.read_bytes()).hexdigest()\n"
        " if cur==r['old']:res.append((r['path'],'already_old'));continue\n"
        " if cur!=r['new']:res.append((r['path'],'changed_by_other_skip'));continue\n"
        " tmp=p.with_name('.'+p.name+'.rollback');shutil.copy2(D/'backup'/r['path'].lstrip('/'),tmp);os.chown(tmp,r['uid'],r['gid']);os.chmod(tmp,r['mode']);os.replace(tmp,p);res.append((r['path'],'restored'))\n"
        "(D/'ROLLED_BACK').write_text(json.dumps(res))\n"
        "subprocess.run(['systemctl','restart','capstone-ollama-chat.service'])\n") % (str(DIR),)
    (DIR / 'rollback.py').write_text(rollback); os.chmod(DIR / 'rollback.py', 0o700)
    r = subprocess.run(['systemd-run', '--unit=' + UNIT, '--on-active=2700', '--timer-property=AccuracySec=1s', '/usr/bin/python3', '-I', '-B', str(DIR / 'rollback.py')], capture_output=True, text=True)
    assert r.returncode == 0, ('arm_failed', r.stderr[-200:]); out['rollback_timer'] = UNIT + '.timer (45 min)'
    done = []
    try:
        for m in meta:
            p = Path(m['path']); data = next(d for q, _, d in rows if str(q) == m['path'])
            assert sha(p.read_bytes()) == m['old'], ('changed_before_apply', m['path'])
            tmp = p.with_name('.' + p.name + '.catalog-contract')
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
