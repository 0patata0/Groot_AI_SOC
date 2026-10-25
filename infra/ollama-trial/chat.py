#!/usr/bin/env python3
"""Mention-free private trial channel + authorized one-to-one DMs.

WebSocket events feed a durable, single-worker SOC agent queue. The bot token
never enters the LLM. Protected MCP calls retain the existing server approval gates.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import sqlite3
import sys
import time
from datetime import datetime
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime import run as agent_run, load_config as agent_config
import harness
from policy import require
from chat_policy import ID, KST, eligible, question_with_history, final_text


def log(event, **fields):
    print(json.dumps({'at_kst': datetime.now(KST).isoformat(), 'event': event, **fields}), flush=True)


def audit_json(report):
    """Keep bounded evidence and metadata when a vulnerability body is large."""
    audit = json.loads(json.dumps({k: v for k, v in report.items() if k not in ('evidence', 'catalog')}))
    for call in audit.get('calls', []):
        raw = call.get('result')
        if (call.get('server') == 'wazuh-ro' and call.get('name') == 'get_wazuh_vulnerability_summary'
                and isinstance(raw, str) and len(raw.encode()) > 1048576
                and harness.READ.successful(call)):
            compact = harness.READ.compact_vulnerability(raw)
            if isinstance(compact, str):
                call.update(source_result_sha256=call['result_sha256'], result=compact,
                            result_sha256=hashlib.sha256(compact.encode()).hexdigest(),
                            audit_result_bytes=len(compact.encode()), audit_compacted=True)
    encoded = json.dumps(audit, ensure_ascii=False)
    if len(encoded.encode()) > 4194304:
        audit['audit_truncated'] = True
        for call in sorted(audit.get('calls', []), key=lambda c: len(str(c.get('result', ''))), reverse=True):
            if 'result' not in call:
                continue
            call.pop('result')
            call['result_omitted_reason'] = 'chat_audit_size_limit; original hash/bytes retained'
            encoded = json.dumps(audit, ensure_ascii=False)
            if len(encoded.encode()) <= 4194304:
                break
    if len(encoded.encode()) > 4194304:
        # Exceptional oversized arguments/metadata must not bypass the DB cap.
        audit = {'status': report.get('status'), 'audit_truncated': True,
                 'metadata_omitted': True, 'original_audit_sha256': hashlib.sha256(encoded.encode()).hexdigest(),
                 'protected_calls': report.get('protected_calls'), 'calls': [
                     {'server': c.get('server'), 'name': c.get('name'), 'is_error': c.get('is_error'),
                      'arguments_sha256': hashlib.sha256(json.dumps(c.get('arguments'), sort_keys=True).encode()).hexdigest(),
                      'result_sha256': c.get('source_result_sha256', c.get('result_sha256')),
                      'result_bytes': c.get('result_bytes')} for c in audit.get('calls', [])]}
        encoded = json.dumps(audit, ensure_ascii=False)
    return encoded


def config_read(path):
    p = Path(path); st = p.lstat()
    require(not p.is_symlink() and st.st_uid == 0 and not st.st_mode & 0o027, 'chat_config_permissions')
    c = json.loads(p.read_text())
    require(c['schema'] == 1 and c['username'] == 'ollama' and c['allowed_users'], 'chat_config_shape')
    require(all(ID.fullmatch(x) for x in [c['bot_id'], c['channel_id'], c['team_id'], *c['allowed_users']]), 'chat_ids')
    u = urlsplit(c['base_url'])
    require(u.scheme == 'http' and ipaddress.ip_address(u.hostname).is_private and u.port == 8065 and
            not u.username and not u.password and not u.query and not u.fragment and not u.path, 'local_mattermost_only')
    require(ID.fullmatch(c['token']) and type(c['enabled_at_ms']) is int, 'chat_credential_shape')
    return c


class Gateway:
    def __init__(self, config, http, state=None):
        self.c, self.http = config, http
        self.runtime = agent_config('/etc/capstone-ollama-trial/config.json')
        self.state = Path(state) if state else None
        self.wake = asyncio.Event()
        self.db = None
        if self.state:
            self.db = sqlite3.connect(self.state / 'queue.sqlite')
            self.db.row_factory = sqlite3.Row
            self.db.execute('pragma journal_mode=WAL')
            self.db.execute('create table if not exists jobs (id text primary key, post text not null, status text not null, reply text, answer text, attempts integer not null default 0)')
            if 'evidence' not in {row[1] for row in self.db.execute('pragma table_info(jobs)')}:
                self.db.execute('alter table jobs add column evidence text')
            if 'report' not in {row[1] for row in self.db.execute('pragma table_info(jobs)')}:
                self.db.execute('alter table jobs add column report text')
            if 'protected_started' not in {row[1] for row in self.db.execute('pragma table_info(jobs)')}:
                self.db.execute('alter table jobs add column protected_started integer not null default 0')
            self.db.execute("update jobs set status='delivery',answer=? where status='running' and protected_started=1",
                ('보호 도구 요청 후 실행부가 재시작되어 최종 결과를 확인하지 못했습니다. 중복 실행을 피하기 위해 재요청하지 않았습니다. 승인 카드와 작업 ID의 현재 상태를 확인해야 합니다.',))
            self.db.execute("update jobs set status='queued' where status='running' and attempts<2")
            self.db.execute("update jobs set status='abandoned' where status='running'")
            self.db.commit()

    async def api(self, method, path, body=None):
        require(path.startswith('/') and not path.startswith('//'), 'api_path')
        r = await self.http.request(method, self.c['base_url'] + '/api/v4' + path, json=body)
        if r.status_code not in (200, 201):
            raise RuntimeError('mattermost_http_' + str(r.status_code))
        require(len(r.content) <= 4194304, 'mattermost_body_limit')
        return r.json()

    async def check_identity(self):
        me = await self.api('GET', '/users/me')
        require(me['id'] == self.c['bot_id'] and me['username'] == 'ollama' and
                me.get('is_bot') and not me.get('delete_at') and
                'system_admin' not in me.get('roles', '').split(), 'bot_identity')
        channel = await self.api('GET', '/channels/' + self.c['channel_id'])
        require(channel['name'] == 'soc-ollama' and channel['team_id'] == self.c['team_id'], 'bot_channel')
        await self.api('GET', '/channels/' + channel['id'] + '/members/' + me['id'])
        return channel

    async def accept(self, post_id):
        if not ID.fullmatch(str(post_id)) or self.db.execute('select 1 from jobs where id=?', (post_id,)).fetchone():
            return
        p = await self.api('GET', '/posts/' + post_id)
        if p.get('user_id') not in self.c['allowed_users'] or p.get('create_at', 0) < self.c['enabled_at_ms']:
            return
        channel = await self.api('GET', '/channels/' + p['channel_id'])
        members = []
        if channel.get('type') == 'D':
            members = [x['user_id'] for x in await self.api('GET', '/channels/' + channel['id'] + '/members')]
        if not eligible(p, self.c, channel, members):
            return
        # Only authorized human posts are persisted; bot messages cannot feed loops.
        with self.db:
            self.db.execute('insert or ignore into jobs(id,post,status) values(?,?,?)', (p['id'], json.dumps(p), 'queued'))
        self.wake.set()
        log('request_queued', post_id=p['id'])

    async def catchup(self):
        channels = await self.api('GET', '/users/me/teams/' + self.c['team_id'] + '/channels')
        for channel in channels:
            if channel['id'] != self.c['channel_id'] and channel.get('type') != 'D':
                continue
            posts = await self.api('GET', '/channels/' + channel['id'] + '/posts?per_page=60')
            rows = sorted(posts['posts'].values(), key=lambda p: (p['create_at'], p['id']))
            for p in rows:
                if p.get('user_id') in self.c['allowed_users'] and p.get('create_at', 0) >= self.c['enabled_at_ms']:
                    await self.accept(p['id'])

    async def thread(self, post):
        root = post.get('root_id') or post['id']
        require(ID.fullmatch(root), 'thread_root')
        result = await self.api('GET', '/posts/' + root + '/thread?per_page=200')
        return [p for p in result['posts'].values() if p['channel_id'] == post['channel_id']]

    async def history_for(self, post):
        channel = await self.api('GET', '/channels/' + post['channel_id'])
        if channel.get('type') == 'D' and not post.get('root_id'):
            recent = await self.api('GET', '/channels/' + post['channel_id'] + '/posts?per_page=60')
            return [p for p in recent['posts'].values() if p['channel_id'] == post['channel_id']]
        return await self.thread(post)

    def prior_evidence(self, post):
        # Reformat evidence only in the exact thread and for the same human.
        # An independent root intentionally starts with no cached facts.
        root = post.get('root_id')
        if not root:
            return None
        for row in self.db.execute("select post,evidence from jobs where status='done' and evidence is not null order by rowid desc limit 200"):
            previous = json.loads(row['post'])
            if (previous['channel_id'] == post['channel_id'] and previous['user_id'] == post['user_id'] and
                    (previous.get('root_id') or previous['id']) == root and previous['create_at'] < post['create_at']):
                return json.loads(row['evidence'])
        return None

    async def reply_id(self, job, post):
        if job['reply']:
            return job['reply']
        previous = await self.thread(post)
        matches = [p for p in previous if p['user_id'] == self.c['bot_id'] and
                   p.get('props', {}).get('capstone_ollama_source') == post['id'] and not p.get('delete_at')]
        require(len(matches) <= 1, 'duplicate_reply_detected')
        if matches:
            reply = matches[0]['id']
        elif job['status'] == 'uncertain':
            # Never blindly resend an ambiguous POST on a network timeout.
            return None
        else:
            with self.db:
                self.db.execute("update jobs set status='uncertain' where id=?", (post['id'],))
            reply = (await self.api('POST', '/posts', {
                'channel_id': post['channel_id'], 'root_id': post.get('root_id') or post['id'],
                'message': '확인하고 있습니다. 조회가 끝나면 이 답변을 갱신하겠습니다.',
                'pending_post_id': 'ollama-' + post['id'],
                'props': {'capstone_ollama_source': post['id'], 'from_bot': 'true'}}))['id']
        with self.db:
            self.db.execute("update jobs set reply=?,status='queued' where id=?", (reply, post['id']))
        return reply

    async def process(self, job):
        post = json.loads(job['post'])
        # Revalidate current source/authorization immediately before any response.
        fresh = await self.api('GET', '/posts/' + post['id'])
        if fresh.get('delete_at') or fresh.get('message') != post['message']:
            with self.db:
                self.db.execute("update jobs set status='cancelled' where id=?", (post['id'],))
            return
        reply = await self.reply_id(job, post)
        if not reply:
            return
        answer = job['answer']
        if not answer:
            with self.db:
                self.db.execute("update jobs set status='running',attempts=attempts+1 where id=?", (post['id'],))
            started = time.perf_counter()
            evidence = None
            audit = None
            def protected_start():
                with self.db:
                    self.db.execute('update jobs set protected_started=1 where id=?', (post['id'],))
            try:
                question = question_with_history(post, await self.history_for(post), self.c['bot_id'])
                with contextlib.redirect_stdout(sys.stderr):
                    report = await asyncio.wait_for(agent_run(self.runtime, {'question': question,
                        'current_question': post['message'], 'prior_evidence': self.prior_evidence(post)},
                        on_protected_start=protected_start), 1110)
                answer = final_text(report, time.perf_counter() - started)
                evidence = json.dumps(report['evidence'], ensure_ascii=False) if report.get('evidence') else None
                audit = audit_json(report)
                if evidence and len(evidence.encode()) > 1048576:
                    evidence = None
                log('generation_complete', post_id=post['id'], status=report['status'],
                    seconds=round(time.perf_counter() - started, 3), tool_calls=len(report.get('calls', [])),
                    model_calls=len(report.get('model_calls', [])), protected_calls=report.get('protected_calls', 0),
                    evidence_reused=report.get('evidence_reused', False), issues=report.get('remaining_issues', []))
            except Exception as exc:
                answer = final_text({'status': 'failed'}, time.perf_counter() - started)
                log('generation_failed', post_id=post['id'], error_type=type(exc).__name__)
            with self.db:
                self.db.execute("update jobs set answer=?,evidence=?,report=?,status='delivery' where id=?", (answer, evidence, audit, post['id']))
        existing = await self.api('GET', '/posts/' + reply)
        require(existing['user_id'] == self.c['bot_id'] and existing['channel_id'] == post['channel_id'] and
                existing.get('props', {}).get('capstone_ollama_source') == post['id'], 'reply_binding')
        await self.api('PUT', '/posts/' + reply + '/patch', {'message': answer})
        with self.db:
            self.db.execute("update jobs set status='done' where id=?", (post['id'],))
        log('reply_delivered', post_id=post['id'], reply_id=reply)

    async def worker(self):
        while True:
            # Clear before reading jobs: a new arrival during generation must
            # wake the next pass instead of adding the retry timer to latency.
            self.wake.clear()
            jobs = self.db.execute("select * from jobs where status in ('queued','delivery','uncertain') order by rowid limit 20").fetchall()
            for job in jobs:
                try:
                    await self.process(job)
                except Exception as exc:
                    log('request_retry', post_id=job['id'], error_type=type(exc).__name__)
            try:
                await asyncio.wait_for(self.wake.wait(), 5)
            except asyncio.TimeoutError:
                pass

    async def listen(self, once=False):
        from websockets.asyncio.client import connect
        url = self.c['base_url'].replace('http://', 'ws://', 1) + '/api/v4/websocket'
        while True:
            try:
                async with connect(url, additional_headers={'Authorization': 'Bearer ' + self.c['token']},
                                   proxy=None, open_timeout=10, close_timeout=5, ping_interval=20,
                                   ping_timeout=20, max_size=2097152) as ws:
                    hello = json.loads(await asyncio.wait_for(ws.recv(), 15))
                    require(hello.get('event') == 'hello', 'websocket_hello')
                    log('websocket_connected', bot='ollama', channel='soc-ollama')
                    if once:
                        return
                    await self.catchup()
                    async for raw in ws:
                        event = json.loads(raw)
                        if event.get('event') == 'posted':
                            post = json.loads(event['data']['post'])
                            await self.accept(post.get('id'))
            except Exception as exc:
                if once:
                    raise
                log('websocket_retry', error_type=type(exc).__name__)
                await asyncio.sleep(3)


async def main_async(args):
    import httpx
    require(os.geteuid() != 0, 'unprivileged_chat_required')
    config = config_read(args.config)
    async with httpx.AsyncClient(headers={'Authorization': 'Bearer ' + config['token']},
                                 timeout=15, follow_redirects=False, trust_env=False) as http:
        gateway = Gateway(config, http, None if args.check else '/var/lib/capstone-ollama-trial/chat')
        await gateway.check_identity()
        if args.check:
            await gateway.listen(once=True)
            log('check_passed', posts_sent=0, model_requests=0)
        else:
            async with asyncio.TaskGroup() as group:
                group.create_task(gateway.worker())
                group.create_task(gateway.listen())


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--config', default='/etc/capstone-ollama-trial/chat.json')
    p.add_argument('--check', action='store_true')
    args = p.parse_args()
    try:
        asyncio.run(main_async(args))
    except Exception as exc:
        log('gateway_failed', error_type=type(exc).__name__)
        sys.exit(1)
