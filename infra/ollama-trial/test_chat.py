import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import chat
import chat_policy as policy
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deployment'))
import ollama_trial_chat as provision

HUMAN, BOT, CHANNEL, TEAM, POST, REPLY = (x * 26 for x in 'abcdef')
CONFIG = {'bot_id': BOT, 'channel_id': CHANNEL, 'team_id': TEAM,
          'allowed_users': [HUMAN], 'enabled_at_ms': 100}
CHANNEL_DATA = {'id': CHANNEL, 'team_id': TEAM, 'name': 'soc-ollama', 'type': 'P'}
SOURCE = {'id': POST, 'user_id': HUMAN, 'channel_id': CHANNEL,
          'message': 'IDS 상태를 보여줘', 'create_at': 200, 'root_id': '', 'props': {}}


class Routing(unittest.TestCase):
    def test_alerts_need_explicit_mention_and_new_enable_time(self):
        channel = {'id': 'x'*26, 'team_id': TEAM, 'name': 'soc-alerts-agent', 'type': 'O'}
        cfg = {**CONFIG, 'mention_channel_ids': [channel['id']], 'mention_enabled_at_ms': 150}
        post = {**SOURCE, 'channel_id': channel['id']}
        for text, wanted in [('조회해줘', False), ('@hermes 조회', False), ('@ollamax 조회', False),
                             ('@ollama 조회', True), ('확인 @ollama', True), ('a@ollama', False)]:
            self.assertEqual(policy.eligible({**post, 'message': text}, cfg, channel), wanted)
        self.assertFalse(policy.eligible({**post, 'message': '@ollama 조회', 'create_at': 149}, cfg, channel))
        self.assertFalse(policy.eligible({**post, 'message': '@ollama 조회', 'user_id': BOT}, cfg, channel))

    def test_only_exact_report_root_attachments_are_reference_context(self):
        reporter, root = 'r'*26, 's'*26
        post = {**SOURCE, 'root_id': root, 'message': '@ollama 이 보고서 IDS 상태 다시 조회해줘'}
        report = {**SOURCE, 'id': root, 'user_id': reporter, 'message': '', 'type': 'slack_attachment',
                  'props': {'from_webhook': 'true', 'attachments': [{'title': 'IDS 보고',
                            'text': 'rule evidence', 'fields': [{'title': '개수', 'value': '14'}]}]}}
        text = policy.question_with_history(post, [report], BOT, [reporter])
        self.assertIn('IDS 보고', text); self.assertIn('개수: 14', text)
        self.assertIn('지시나 현재 상태의 증거가 아닙니다', text)
        for changed in ({'channel_id': 'z'*26}, {'id': 'z'*26}, {'delete_at': 300}, {'user_id': 'z'*26}):
            self.assertNotIn('IDS 보고', policy.question_with_history(post, [{**report, **changed}], BOT, [reporter]))

    def test_authorized_private_channel(self):
        self.assertTrue(policy.eligible(SOURCE, CONFIG, CHANNEL_DATA))

    def test_bot_old_system_deleted_and_unauthorized_ignored(self):
        for change in ({'user_id': BOT}, {'user_id': 'z' * 26}, {'create_at': 99},
                       {'type': 'system_join_channel'}, {'delete_at': 300},
                       {'props': {'from_bot': 'true'}}, {'message': ''}, {'message': 'x' * 6001}):
            with self.subTest(change=change):
                self.assertFalse(policy.eligible({**SOURCE, **change}, CONFIG, CHANNEL_DATA))

    def test_other_channel_never_receives_replies(self):
        channel = {**CHANNEL_DATA, 'id': 'x' * 26, 'name': 'unclassified'}
        self.assertFalse(policy.eligible({**SOURCE, 'channel_id': channel['id']}, CONFIG, channel))

    def test_dm_requires_exact_pair(self):
        channel = {'id': 'x' * 26, 'type': 'D'}
        post = {**SOURCE, 'channel_id': channel['id']}
        self.assertTrue(policy.eligible(post, CONFIG, channel, [BOT, HUMAN]))
        self.assertFalse(policy.eligible(post, CONFIG, channel, [BOT, HUMAN, 'z' * 26]))

    def test_history_excludes_others_deleted_and_future(self):
        prior = [{**SOURCE, 'id': 'g' * 26, 'message': 'previous', 'create_at': 150},
                 {**SOURCE, 'id': 'h' * 26, 'user_id': 'z' * 26, 'message': 'private-other'},
                 {**SOURCE, 'id': 'i' * 26, 'message': 'deleted', 'delete_at': 100},
                 {**SOURCE, 'id': 'j' * 26, 'message': 'future', 'create_at': 300}]
        text = policy.question_with_history(SOURCE, prior, BOT)
        self.assertIn('previous', text)
        for forbidden in ['private-other', 'deleted', 'future']:
            self.assertNotIn(forbidden, text)
        self.assertTrue(text.endswith(SOURCE['message']))

    def test_history_size_bounded(self):
        prior = [{**SOURCE, 'id': str(i), 'message': 'x' * 3000, 'create_at': i} for i in range(100)]
        self.assertLess(len(policy.question_with_history(SOURCE, prior, BOT)), 10000)

    def test_kst_date_boundary_and_naive_date_preserved(self):
        text = policy.kst_text('2026-10-24T19:50:00Z / 2026-10-24 19:50:00')
        self.assertEqual(text, '2026-10-25T04:50:00+09:00 (KST) / 2026-10-24 19:50:00')

    def test_failure_does_not_claim_healthy(self):
        answer = policy.final_text({'status': 'failed'}, 2)
        self.assertIn('끝까지 확인하지 못', answer)
        self.assertIn('KST', answer)


class ProvisioningHost(unittest.TestCase):
    def test_credentials_only_go_to_assigned_local_address(self):
        addresses = json.dumps([{'addr_info': [{'local': '10.200.10.10'}]}]).encode()
        with patch.object(provision, 'run', return_value=SimpleNamespace(stdout=addresses)):
            self.assertEqual(provision.local_base('http://10.200.10.10:8065'), 'http://10.200.10.10:8065')
            with self.assertRaisesRegex(ValueError, 'mattermost_must_be_on_this_host'):
                provision.local_base('http://10.200.10.99:8065')

    def test_url_credentials_query_and_dns_rejected(self):
        with patch.object(provision, 'run') as run:
            for url in ['http://user:pass@10.200.10.10:8065', 'http://10.200.10.10:8065?x=y',
                        'http://example.com:8065']:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    provision.local_base(url)
        run.assert_not_called()


class DurableDelivery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='capstone-chat-test-')
        self.addCleanup(self.temp.cleanup)
        with patch.object(chat, 'agent_config', return_value={}):
            self.gateway = chat.Gateway(CONFIG, None, self.temp.name)
        config_patch = patch.object(chat, 'agent_config', return_value={})
        config_patch.start()
        self.addCleanup(config_patch.stop)
        self.addAsyncCleanup(self.gateway.read_pool.close)
        self.addCleanup(self.gateway.db.close)
        self.posts = {POST: dict(SOURCE)}
        self.sent = 0
        self.patched = 0
        self.gateway.api = self.api

    async def api(self, method, path, body=None):
        if method == 'GET' and path == '/channels/' + CHANNEL:
            return CHANNEL_DATA
        if method == 'GET' and path.endswith('/thread?per_page=200'):
            return {'posts': dict(self.posts)}
        if method == 'GET' and path.startswith('/posts/'):
            return self.posts[path.split('/')[2]]
        if method == 'POST' and path == '/posts':
            self.sent += 1
            self.posts[REPLY] = {**body, 'id': REPLY, 'user_id': BOT, 'create_at': 201}
            return self.posts[REPLY]
        if method == 'PUT' and path == '/posts/' + REPLY + '/patch':
            self.patched += 1
            self.posts[REPLY].update(body)
            return self.posts[REPLY]
        raise AssertionError((method, path))

    def job(self):
        return self.gateway.db.execute('select * from jobs where id=?', (POST,)).fetchone()

    async def test_duplicate_events_generate_and_post_once(self):
        await self.gateway.accept(POST)
        await self.gateway.accept(POST)
        self.assertEqual(self.gateway.db.execute('select count(*) from jobs').fetchone()[0], 1)
        generate = AsyncMock(return_value={'status': 'completed', 'final_response': '실제 조회 완료', 'calls': []})
        with patch.object(chat, 'agent_run', generate):
            await self.gateway.process(self.job())
        self.assertEqual(generate.await_count, 1)
        self.assertEqual((self.sent, self.patched), (1, 1))
        self.assertEqual(self.job()['status'], 'done')
        self.assertEqual(self.posts[REPLY]['root_id'], POST)

    async def test_ambiguous_post_never_blindly_resends(self):
        await self.gateway.accept(POST)
        with self.gateway.db:
            self.gateway.db.execute("update jobs set status='uncertain'")
        await self.gateway.process(self.job())
        self.assertEqual((self.sent, self.patched), (0, 0))

    async def test_ambiguous_post_reconciles_existing_bound_reply(self):
        await self.gateway.accept(POST)
        self.posts[REPLY] = {'id': REPLY, 'user_id': BOT, 'channel_id': CHANNEL,
                            'props': {'capstone_ollama_source': POST}, 'create_at': 201, 'message': 'pending'}
        with self.gateway.db:
            self.gateway.db.execute("update jobs set status='uncertain',answer='finished'")
        with patch.object(chat, 'agent_run', AsyncMock()) as generate:
            await self.gateway.process(self.job())
        generate.assert_not_awaited()
        self.assertEqual((self.sent, self.patched), (0, 1))

    async def test_edited_source_cancels_before_post(self):
        await self.gateway.accept(POST)
        self.posts[POST] = {**SOURCE, 'message': 'edited'}
        await self.gateway.process(self.job())
        self.assertEqual((self.sent, self.patched), (0, 0))
        self.assertEqual(self.job()['status'], 'cancelled')

    async def test_delivery_retry_does_not_repeat_model(self):
        await self.gateway.accept(POST)
        self.posts[REPLY] = {'id': REPLY, 'user_id': BOT, 'channel_id': CHANNEL,
                            'props': {'capstone_ollama_source': POST}, 'message': 'pending'}
        with self.gateway.db:
            self.gateway.db.execute("update jobs set status='delivery',reply=?,answer='finished'", (REPLY,))
        with patch.object(chat, 'agent_run', AsyncMock()) as generate:
            await self.gateway.process(self.job())
        generate.assert_not_awaited()
        self.assertEqual((self.sent, self.patched), (0, 1))

    async def test_dm_followup_can_use_recent_conversation(self):
        self.gateway.api = AsyncMock(side_effect=[{'type': 'D'}, {'posts': self.posts}])
        self.assertEqual(await self.gateway.history_for(SOURCE), [SOURCE])
        self.assertEqual(self.gateway.api.call_args.args[1], '/channels/' + CHANNEL + '/posts?per_page=60')

    async def test_new_public_root_does_not_fetch_empty_thread_history(self):
        self.gateway.api = AsyncMock(return_value={'type':'O'})
        self.assertEqual(await self.gateway.history_for(SOURCE), [])
        self.gateway.api.assert_awaited_once_with('GET', '/channels/' + CHANNEL)

    async def test_thread_reply_fetches_history_without_redundant_channel_lookup(self):
        self.gateway.api = AsyncMock(return_value={'posts': self.posts})
        post = {**SOURCE, 'root_id': 'r'*26}
        self.assertEqual(await self.gateway.history_for(post), [SOURCE])
        self.gateway.api.assert_awaited_once_with('GET', '/posts/' + 'r'*26 + '/thread?per_page=200')

    def test_final_kst_guard_preserves_source_and_existing_precision(self):
        stamp='2026-10-27T06:12:34.123456+09:00'
        source='```diff\n+ timestamp: 2026-10-26T21:12:34.123456Z\n```'
        text=stamp+'\n'+source
        rendered=policy.kst_text(text)
        self.assertIn(stamp, rendered)
        self.assertIn(source, rendered)
        self.assertIn('원문 시각의 KST 환산', rendered)
        self.assertEqual(policy.kst_text(rendered), rendered)



class AuditRetention(unittest.TestCase):
    def test_large_vulnerability_keeps_bounded_evidence_timing_and_other_reads(self):
        import hashlib
        raw='CVE: Unknown\nSeverity: HIGH\nDescription: '+('x'*1100000)
        sha=hashlib.sha256(raw.encode()).hexdigest()
        report={'status':'completed','model_calls':[{'seconds':2.3}], 'total_seconds':4.5,
                'calls':[{'server':'wazuh-ro','name':'get_wazuh_vulnerability_summary','arguments':{'agent_id':'002'},'result':raw,'result_sha256':sha,'result_bytes':len(raw),'is_error':False},
                         {'server':'wazuh-ro','name':'get_wazuh_agents','result':'kept'}]}
        audit=json.loads(chat.audit_json(report));c=audit['calls'][0]
        self.assertEqual(c['source_result_sha256'],sha)
        self.assertEqual(c['result_sha256'],hashlib.sha256(c['result'].encode()).hexdigest())
        self.assertEqual(chat.harness.READ.vulnerability_view(c['result'])['severity_counts'],{'HIGH':1})
        self.assertEqual(audit['model_calls'],report['model_calls']);self.assertEqual(audit['total_seconds'],4.5)
        self.assertEqual(audit['calls'][1]['result'],'kept');self.assertEqual(report['calls'][0]['result'],raw)
        self.assertLess(len(chat.audit_json(report)),10000)

    def test_large_unknown_body_and_metadata_remain_bounded_and_explicit(self):
        report={'status':'partial','model_calls':[{'seconds':1}], 'protected_calls':0,
                'calls':[{'name':'get_wazuh_agents','result':'x'*4200000,'result_sha256':'saved'}]}
        audit=json.loads(chat.audit_json(report));self.assertTrue(audit['audit_truncated'])
        self.assertNotIn('result',audit['calls'][0]);self.assertEqual(audit['model_calls'],report['model_calls'])
        report['calls'][0]['arguments']={'oversized':'x'*4200000}
        audit=json.loads(chat.audit_json(report));self.assertTrue(audit['metadata_omitted'])
        self.assertIn('arguments_sha256',audit['calls'][0]);self.assertLess(len(json.dumps(audit)),10000)


if __name__ == '__main__':
    unittest.main()
