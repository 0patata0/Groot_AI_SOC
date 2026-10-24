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
    def test_authorized_private_channel(self):
        self.assertTrue(policy.eligible(SOURCE, CONFIG, CHANNEL_DATA))

    def test_bot_old_system_deleted_and_unauthorized_ignored(self):
        for change in ({'user_id': BOT}, {'user_id': 'z' * 26}, {'create_at': 99},
                       {'type': 'system_join_channel'}, {'delete_at': 300},
                       {'props': {'from_bot': 'true'}}, {'message': ''}, {'message': 'x' * 6001}):
            with self.subTest(change=change):
                self.assertFalse(policy.eligible({**SOURCE, **change}, CONFIG, CHANNEL_DATA))

    def test_other_channel_never_receives_replies(self):
        channel = {**CHANNEL_DATA, 'id': 'x' * 26}
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
        self.assertEqual(text, '2026-10-25T04:50:00+09:00 / 2026-10-24 19:50:00')

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


if __name__ == '__main__':
    unittest.main()
