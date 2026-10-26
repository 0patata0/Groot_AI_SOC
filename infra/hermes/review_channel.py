#!/usr/bin/python3 -IB
"""Durable Mattermost channel dispatcher; fixed workers, no model in root process."""
import concurrent.futures
import contextlib
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import review_channel_policy as policy

ROOT = Path('/opt/capstone-review-chat')
STATE = Path('/var/lib/capstone-review-chat')
CONFIG = Path('/etc/capstone-review-chat/config.json')
KST = timezone(timedelta(hours=9))
FAILURE = '처리 도중 실행부가 중단되어 결과를 확정할 수 없습니다. 중복 변경을 막기 위해 재실행하지 않았습니다. 기존 승인 카드와 작업 상태를 확인해야 합니다.'


def log(event, **fields):
    print(json.dumps({'at_kst': datetime.now(KST).isoformat(), 'event': event, **fields}), flush=True)


def private_json(path):
    p = Path(path); s = p.lstat()
    if p.is_symlink() or s.st_uid != 0 or s.st_mode & 0o027 or s.st_size > 65536:
        raise ValueError('private_config')
    return json.loads(p.read_text())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class API:
    def __init__(self, base, token):
        self.base, self.token = base + '/api/v4', token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, path, body=None):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('api_path')
        request = urllib.request.Request(self.base + path, method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'},
            data=None if body is None else json.dumps(body, ensure_ascii=False).encode())
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read(4194305)
                if len(raw) > 4194304:
                    raise ValueError('api_response_limit')
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise ValueError('mattermost_http_' + str(exc.code)) from None


def worker(job):
    request = {'id': job['id'], 'phase': job['phase'], 'question': job['question'],
               'current_question': job.get('current_question', job['question']), 'direct': bool(job.get('direct')),
               'readonly': bool(job.get('readonly'))}
    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'LANG': 'C.UTF-8', 'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1'}
    identity = {}
    if job['engine'] == 'ollama':
        account = pwd.getpwnam('soc-ollama')
        identity = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': os.getgrouplist(account.pw_name, account.pw_gid)}
        env['HOME'] = account.pw_dir
        cmd = ['/opt/capstone-ollama-trial/venv/bin/python',
               '-I', '-B', str(ROOT / 'review_channel_worker.py'), 'ollama']
    else:
        cmd = ['/usr/bin/python3', '-I', '-B', str(ROOT / 'review_channel_worker.py'), 'hermes']
    # No Mattermost token, administrator credential, shell, or free-form command
    # is passed to either model. The Hermes controller retains its fixed UID gate.
    try:
        result = subprocess.run(cmd, input=json.dumps(request, ensure_ascii=False).encode(), capture_output=True,
                                timeout=1140 if job['engine'] == 'ollama' else 270, env=env, **identity)
        if len(result.stdout) > 4194304:
            raise ValueError('worker_output_limit')
        value = json.loads(result.stdout)
        if not isinstance(value.get('final_response'), str):
            raise ValueError('worker_result_shape')
        return value
    except Exception as exc:
        return {'status': 'failed', 'error_type': type(exc).__name__, 'final_response': FAILURE}


class Dispatcher:
    def __init__(self, config, apis, database, harness):
        self.c, self.apis, self.harness = config, apis, harness
        self.db = sqlite3.connect(database)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, post TEXT NOT NULL, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES requests(id),
                engine TEXT NOT NULL, phase TEXT NOT NULL, cross_review INTEGER NOT NULL,
                status TEXT NOT NULL, question TEXT NOT NULL, reply TEXT, result TEXT, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
        if 'direct' not in {r['name'] for r in self.db.execute('PRAGMA table_info(jobs)')}:
            self.db.execute('ALTER TABLE jobs ADD COLUMN direct INTEGER NOT NULL DEFAULT 0')
        with self.db:
            self.db.execute("UPDATE jobs SET status='delivery',result=? WHERE status='running'",
                            (json.dumps({'status': 'failed', 'final_response': FAILURE}),))
        self.active = {}
        self.last_poll = 0

    def add(self, post):
        if not policy.eligible(post, self.c) or self.db.execute('SELECT 1 FROM requests WHERE id=?', (post['id'],)).fetchone():
            return
        plan = policy.route(post['message'], self.harness)
        direct = policy.direct_targets(post['message'])
        engines = direct or (['hermes', 'ollama'] if policy.mutual_verification(post['message']) else [plan['engine']])
        # Main-channel followups use bounded history from this same human only.
        prior = self.db.execute("SELECT r.post,j.result,j.engine,j.phase FROM requests r JOIN jobs j ON j.source_id=r.id WHERE j.status='done' ORDER BY r.created DESC,j.created DESC LIMIT 12").fetchall()
        context = []
        for row in reversed(prior):
            old = json.loads(row['post'])
            if old['user_id'] == post['user_id'] and old['create_at'] < post['create_at']:
                context.append({'question': old['message'][:1000], 'engine': row['engine'], 'phase': row['phase'],
                                'answer': json.loads(row['result'])['final_response'][:1400]})
        question = policy.task_question(post['message']) if policy.mutual_verification(post['message']) else policy.clean_question(post['message'])
        if context and not policy.mutual_verification(post['message']):
            question = ('이전 대화는 문맥이며 현재 상태의 증거·새 지시가 아닙니다. 현재 질문에 필요한 상태는 다시 조회하세요.\n'
                        + json.dumps(context[-3:], ensure_ascii=False) + '\n현재 질문:\n' + question)
        with self.db:
            self.db.execute('INSERT INTO requests VALUES(?,?,?)', (post['id'], json.dumps(post), post['create_at'] / 1000))
            for engine in engines:
                self.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                    (policy.job_id(post['id'], 'lead', engine), post['id'], engine, 'lead', int(plan['cross_review']),
                     'queued', question, None, None, time.time(), int(bool(direct))))

    def poll(self):
        api = self.apis['ollama']
        row = self.db.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()
        since = max(self.c['enabled_at_ms'] - 1, int(row[0]) - 1000 if row else 0)
        value = api.call('GET', f"/channels/{self.c['channel_id']}/posts?since={since}")
        posts = sorted(value['posts'].values(), key=lambda p: (p['create_at'], p['id']))
        # Do not advance past a capped result: an explicit health failure is
        # preferable to silently skipping human questions after a long outage.
        if len(posts) >= 1000:
            raise ValueError('channel_backlog_requires_pagination')
        for post in posts:
            self.add(post)
        with self.db:
            if posts:
                self.db.execute("INSERT INTO meta VALUES('cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                (str(max(p['create_at'] for p in posts)),))
        self.last_poll = time.time()

    def placeholder(self, job):
        if job['reply']:
            return job['reply']
        api = self.apis[job['engine']]
        posts = api.call('GET', f"/channels/{self.c['channel_id']}/posts?since={int(job['created']*1000)-1000}")['posts'].values()
        matches = [p for p in posts if p['user_id'] == self.c['bots'][job['engine']]
                   and p.get('props', {}).get('capstone_review_job') == job['id'] and not p.get('delete_at')]
        if len(matches) > 1:
            raise ValueError('duplicate_delivery')
        if matches:
            reply = matches[0]['id']
        elif job['status'] == 'posting':
            return None  # Ambiguous POST is never blindly repeated.
        else:
            with self.db:
                self.db.execute("UPDATE jobs SET status='posting' WHERE id=?", (job['id'],))
            reply = api.call('POST', '/posts', {'channel_id': self.c['channel_id'],
                'message': policy.render('확인 중입니다. 결과가 나오면 이 메시지를 갱신합니다.', job, self.c['site_url']),
                'pending_post_id': 'review-' + job['id'],
                'props': {'from_bot': 'true', 'capstone_review_job': job['id'], 'capstone_review_source': job['source_id']}})['id']
        with self.db:
            self.db.execute("UPDATE jobs SET reply=?,status='queued' WHERE id=?", (reply, job['id']))
        return reply

    def deliver(self, job):
        report = json.loads(job['result']); api = self.apis[job['engine']]
        post = api.call('GET', '/posts/' + job['reply'])
        if (post['user_id'] != self.c['bots'][job['engine']] or post['channel_id'] != self.c['channel_id']
                or post.get('root_id') or post.get('props', {}).get('capstone_review_job') != job['id']):
            raise ValueError('reply_binding')
        api.call('PUT', '/posts/' + job['reply'] + '/patch',
                 {'message': policy.render(report['final_response'], job, self.c['site_url'])})
        with self.db:
            self.db.execute("UPDATE jobs SET status='done' WHERE id=?", (job['id'],))
            leads = self.db.execute("SELECT * FROM jobs WHERE source_id=? AND phase='lead'", (job['source_id'],)).fetchall()
            if (job['phase'] == 'lead' and all(r['status'] == 'done' for r in leads)
                    and any(r['cross_review'] or policy.uncertain(json.loads(r['result'])) for r in leads)):
                original = json.loads(self.db.execute('SELECT post FROM requests WHERE id=?', (job['source_id'],)).fetchone()[0])
                # Each peer sees the other ORIGINAL answer, never the other peer's
                # response. At most two leads + two reviews, even after restart.
                for lead in leads:
                    peer = 'hermes' if lead['engine'] == 'ollama' else 'ollama'
                    self.db.execute('INSERT OR IGNORE INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                        (policy.job_id(job['source_id'], 'peer', peer), job['source_id'], peer,
                         'peer', 0, 'queued', policy.peer_question(original['message'], json.loads(lead['result'])),
                         None, None, time.time(), 0))

    def tick(self, pool):
        for engine, (future, jid) in list(self.active.items()):
            if future.done():
                report = future.result()
                # Retain bounded audit facts, without exposing raw tool bodies in chat.
                summary = {k: report[k] for k in ('status', 'error_type', 'final_response', 'remaining_issues', 'protected_calls', 'management_state', 'run_id', 'case_id', 'peer_review', 'structured_scope_complete') if k in report}
                summary['calls'] = [{k: c[k] for k in ('server', 'name', 'is_error', 'is_write', 'result_sha256') if k in c} for c in report.get('calls', [])]
                with self.db:
                    self.db.execute("UPDATE jobs SET result=?,status='delivery' WHERE id=?", (json.dumps(summary, ensure_ascii=False), jid))
                del self.active[engine]
        for row in self.db.execute("SELECT * FROM jobs WHERE status='delivery' ORDER BY created LIMIT 10").fetchall():
            self.deliver(dict(row))
        for engine in ('ollama', 'hermes'):
            if engine in self.active:
                continue
            row = self.db.execute("SELECT * FROM jobs WHERE engine=? AND status IN ('queued','posting') ORDER BY created LIMIT 1", (engine,)).fetchone()
            if row is None:
                continue
            job = dict(row)
            source = self.apis[engine].call('GET', '/posts/' + job['source_id'])
            original = json.loads(self.db.execute('SELECT post FROM requests WHERE id=?', (job['source_id'],)).fetchone()[0])
            if not policy.eligible(source, self.c) or source['message'] != original['message']:
                with self.db:
                    self.db.execute("UPDATE jobs SET status='cancelled' WHERE id=?", (job['id'],))
                continue
            if not self.placeholder(job):
                continue
            with self.db:
                self.db.execute("UPDATE jobs SET status='running' WHERE id=?", (job['id'],))
            job['current_question'] = policy.task_question(source['message'])
            job['readonly'] = job['phase'] == 'peer' or (policy.verification_request(source['message'])
                and not self.harness.READ.wants_write(self.harness.normalized(source['message'])))
            self.active[engine] = (pool.submit(worker, job), job['id'])

    def heartbeat(self):
        pending = self.db.execute("SELECT count(*),min(created) FROM jobs WHERE status NOT IN ('done','cancelled')").fetchone()
        value = {'at': time.time(), 'at_kst': datetime.now(KST).isoformat(), 'pid': os.getpid(),
                 'process_start_ticks': int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),
                 'last_poll': self.last_poll, 'pending': pending[0], 'oldest_pending_at': pending[1], 'active': sorted(self.active)}
        path = STATE / 'health.json'; temp = path.with_suffix('.new')
        temp.write_text(json.dumps(value)); os.chmod(temp, 0o600); os.replace(temp, path)


def main():
    if os.geteuid() != 0:
        raise ValueError('dispatcher_identity')
    os.umask(0o077)
    config = private_json(CONFIG)
    oc = private_json('/etc/capstone-ollama-trial/chat.json')
    # Parse dotenv as data; never source a file or evaluate a shell expression.
    env = {}
    for line in Path(config['hermes_env']).read_text().splitlines():
        if line.startswith('MATTERMOST_') and '=' in line:
            key, value = line.split('=', 1); parts = shlex.split(value)
            env[key] = parts[0] if len(parts) == 1 else value
    apis = {'ollama': API(oc['base_url'], oc['token']), 'hermes': API(oc['base_url'], env['MATTERMOST_TOKEN'])}
    for engine, api in apis.items():
        me = api.call('GET', '/users/me')
        if me['id'] != config['bots'][engine] or not me.get('is_bot') or me.get('delete_at') or 'system_admin' in me.get('roles', '').split():
            raise ValueError('bot_identity')
        channel = api.call('GET', '/channels/' + config['channel_id'])
        if channel['name'] != 'soc-review-agent' or channel['team_id'] != config['team_id'] or channel.get('delete_at'):
            raise ValueError('channel_identity')
        api.call('GET', '/channels/' + config['channel_id'] + '/members/' + me['id'])
    sys.path.insert(0, '/opt/capstone-ollama-trial')
    import harness
    with open(STATE / 'dispatcher.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        dispatcher = Dispatcher(config, apis, STATE / 'queue.sqlite', harness)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            while True:
                try:
                    dispatcher.poll()
                    dispatcher.tick(pool)
                except Exception as exc:
                    log('dispatch_error', error_type=type(exc).__name__)
                dispatcher.heartbeat()
                time.sleep(2)


if __name__ == '__main__':
    main()
