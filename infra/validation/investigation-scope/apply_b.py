#!/usr/bin/env python3
"""B: deploy the investigation-scope rule and the shared peer-review skill section.

Usage: apply_b.py <soc_management_run.py> <query-completion __init__.py> <harness.py> <runtime.py>
                  <review_channel_worker.py> <workflow_contract.py> <soc-investigate SKILL.md>
Same procedure as the 11-13 query-scope deploy: exact previous SHAs for sixteen
installed copies (runner x4, query pin x2, harness x2, Ollama runtime,
joint-channel worker, workflow contract x3, soc-investigate skill x3), the
controller's embedded management gate, the Ollama receipt (grounding,
query_grounding, harness, runtime, workflow_contract, skill-soc-investigate)
and the review-chat installer receipt (worker); a private backup and a
45-minute rollback timer; every replacement under the controller lock; only
while both chat queues are idle. capstone-ollama-chat is restarted only when
its queue is idle. Confirm later by writing CONFIRMED and stopping the timer.
"""
import ast, fcntl, hashlib, json, os, shutil, sqlite3, subprocess, sys, time
from pathlib import Path
OLD = {'runner': 'bc19115d5c524a55b5b114442dfab4f4bcefb49c5adde697425e0585244f3326',
       'query': '3847d9c8bf37ce299acc832fd73f646f990f639cd1624a31d13f845e20c750cb',
       'harness': '5d79bb9dbee62b736f797382c1f5cb3c89790f4f5e55df9b744ed43c801e7f4a',
       'runtime': '026a2cf950a3c5ed64eff4f43bfb202a7f039541606085c703bcedd372ffc622',
       'worker': 'f4f426c74a0eae3720bc5567bdeeaeb5e62ea2e061de9a8637785bee75e258fa',
       'workflow': 'd788400327de19c083e8c1da832424b1a57b2862a4b9bc387c398860cbf8c5e9',
       'skill': 'f330681272911db96594e4fe900a2a1f10985cac396f02d3099428af6d0dba42'}
NEW = {'runner': '6b60566819fb5a6d9c1278bbb891d3ef5a104aec70603bdcc5a04ca73646592a',
       'query': 'fb935f63084af5d0d8953ad4785a49435e2ed876a1c23111197fb7399e89aa12',
       'harness': 'dba169a13203bf10754781ef52e217d88fd62b8436a66a44f616673ccee1afb0',
       'runtime': '75a8ffe15c36ebb6a83054c7534bcf60674e37a969c4df50a8dce99b6ded3540',
       'worker': '2c4b46f8445399cd006a01bac4bc4ad050c71029a14ac39a9a3a0b4e420f0b9b',
       'workflow': 'de984acab1a6ad594b979ec9a6f9a24cf374288880af22039a2946e495207bfa',
       'skill': '24fc9e24b32c344bbd48fe9ff019680e2ff7854686e7421fc95794ec68a1fa3f'}
PLAN = [('/opt/capstone-management/soc_management_run.py', 'runner'), ('/opt/hermes-data/management-code/run.py', 'runner'),
        ('/opt/hermes-data/plugins/groot-query-completion/grounding.py', 'runner'), ('/opt/capstone-ollama-trial/grounding.py', 'runner'),
        ('/opt/hermes-data/plugins/groot-query-completion/__init__.py', 'query'), ('/opt/capstone-ollama-trial/query_grounding.py', 'query'),
        ('/opt/capstone-ollama-trial/harness.py', 'harness'), ('/opt/hermes-data/plugins/groot-query-completion/chat_harness.py', 'harness'),
        ('/opt/capstone-ollama-trial/runtime.py', 'runtime'), ('/opt/capstone-review-chat/review_channel_worker.py', 'worker'),
        ('/opt/hermes-data/plugins/groot-query-completion/workflow_contract.py', 'workflow'), ('/opt/capstone-ollama-trial/workflow_contract.py', 'workflow'),
        ('/opt/capstone-management/workflow_contract.py', 'workflow'),
        ('/opt/hermes-data/plugins/groot-query-completion/skill-soc-investigate.md', 'skill'), ('/opt/capstone-ollama-trial/skill-soc-investigate.md', 'skill'),
        ('/opt/capstone-management/skill-soc-investigate.md', 'skill')]
RECEIPT_KEYS = {'grounding.py': 'runner', 'query_grounding.py': 'query', 'harness.py': 'harness', 'runtime.py': 'runtime',
                'workflow_contract.py': 'workflow', 'skill-soc-investigate.md': 'skill'}
CTRL = Path('/opt/capstone-management/soc_management_controller.py')
RECEIPT = Path('/etc/capstone-ollama-trial/receipt.json')
REVIEW_RECEIPT = Path('/etc/capstone-review-chat/receipt.json')
WORKER = '/opt/capstone-review-chat/review_channel_worker.py'
DIR = Path('/var/lib/capstone-service-grounding/20261113-investigation-scope')
LOCK = '/var/lib/capstone-management/controller.lock'
UNIT = 'capstone-rollback-investigation-scope'
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
def sha(b): return hashlib.sha256(b).hexdigest()
def gate_calls(raw):
    return [n for n in ast.walk(ast.parse(raw)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == 'management_gate_argument' and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, bytes)]
def idle(path):
    with sqlite3.connect('file:' + path + '?mode=ro', uri=True) as db:
        return db.execute("select count(*) from jobs where status in ('queued','running','delivery')").fetchone()[0] == 0
def main():
    new = {k: open(p, 'rb').read() for k, p in zip(('runner', 'query', 'harness', 'runtime', 'worker', 'workflow', 'skill'), sys.argv[1:8])}
    assert all(sha(new[k]) == NEW[k] for k in NEW), 'candidate_changed'
    for k, v in new.items():
        if k != 'skill': compile(v, 'candidate', 'exec')
    assert new['skill'].startswith(b'---\nname: soc-investigate\n') and '## 교차 검토 대조'.encode() in new['skill'], 'skill_shape'
    assert not DIR.exists(), 'deploy_dir_exists'
    rows = []
    for path, kind in PLAN:
        p = Path(path); raw = p.read_bytes(); assert sha(raw) == OLD[kind] and p.stat().st_nlink == 1 and not p.is_symlink(), ('target_not_baseline_no_change', path)
        rows.append((p, raw, new[kind]))
    craw = CTRL.read_bytes(); calls = gate_calls(craw)
    assert len(calls) == 1 and sha(calls[0].args[0].value) == OLD['runner'], 'controller_gate_not_baseline_no_change'
    node = calls[0].args[0]; lines = craw.split(b'\n'); starts = [0]
    for line in lines[:-1]: starts.append(starts[-1] + len(line) + 1)
    a = starts[node.lineno - 1] + node.col_offset; b = starts[node.end_lineno - 1] + node.end_col_offset
    assert eval(craw[a:b]) == calls[0].args[0].value, 'gate_span'
    cnew = craw[:a] + repr(new['runner']).encode() + craw[b:]; compile(cnew, str(CTRL), 'exec')
    check = gate_calls(cnew); assert len(check) == 1 and sha(check[0].args[0].value) == NEW['runner'], 'controller_patch_shape'
    rows.append((CTRL, craw, cnew))
    rraw = RECEIPT.read_bytes(); rec = json.loads(rraw)
    for key, kind in RECEIPT_KEYS.items():
        assert rec['sources'].get(key) == OLD[kind], ('receipt_not_baseline_no_change', key); rec['sources'][key] = NEW[kind]
    rec['investigation_scope_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'backup': str(DIR)}
    rows.append((RECEIPT, rraw, (json.dumps(rec, indent=2, ensure_ascii=False) + '\n').encode()))
    vraw = REVIEW_RECEIPT.read_bytes(); vrec = json.loads(vraw)
    assert vrec['files'].get(WORKER) == OLD['worker'], 'review_receipt_not_baseline_no_change'
    vrec['files'][WORKER] = NEW['worker']
    vrec['investigation_scope_update'] = {'at_kst': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'backup': str(DIR)}
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
        order = {str(CTRL): 0, '/opt/capstone-management/soc_management_run.py': 1}
        for m in sorted(meta, key=lambda m: order.get(m['path'], 2)):
            p = Path(m['path']); data = next(d for q, _, d in rows if str(q) == m['path'])
            assert sha(p.read_bytes()) == m['old'], ('changed_before_apply', m['path'])
            tmp = p.with_name('.' + p.name + '.investigation-scope')
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
