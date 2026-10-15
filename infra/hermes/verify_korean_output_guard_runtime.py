#!/usr/bin/env python3
"""Exercise installed Hermes transports using fake HTTP, never a real chat post.

Run inside the existing container as its normal Hermes user with Python -B.
--model additionally exercises the existing DGX correction API, with synthetic
text and no tools. No packages, files, messages, or server rules are created.
"""
import argparse
import asyncio
import json
from unittest.mock import patch

import capstone_korean_output_guard as guard
import plugins.platforms.mattermost.adapter as mattermost
import gateway.platforms.base as base

BAD = '각 대상에 대해以下步骤이 필요합니다:'
GOOD = '각 대상에 대해 다음 절차가 필요합니다:'


class Reply:
    def __init__(self, status=201):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def json(self):
        return {'id': 'synthetic-message-id'}

    async def text(self):
        return 'invalid root_id'


class FakeSession:
    def __init__(self, *args, **kwargs):
        self.payloads = []
        self.fail_thread = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def post(self, url, **kwargs):
        payload = kwargs['json']
        self.payloads.append(payload)
        return Reply(400 if self.fail_thread and payload.get('root_id') else 201)

    def put(self, url, **kwargs):
        return self.post(url, **kwargs)


async def main(model=False):
    adapter = object.__new__(mattermost.MattermostAdapter)
    session = FakeSession()
    adapter._session = session
    adapter._base_url = 'https://invalid.example'
    adapter._token = 'synthetic-token'
    adapter._reply_mode = 'flat'
    adapter.warning_text = lambda detailed, short: detailed
    checks = []
    engine = guard.detector_metadata()
    assert engine['package'] == 'regex' and engine['version'] == guard.ENGINE_VERSION
    assert engine['backend'] == 'regex._regex' and engine['origin'] == 'isolated_runtime'
    assert guard._CJK.fullmatch('\U00033400') is not None
    assert guard._CJK.search('한국어 · API ✅') is None
    checks.append('pinned_unicode_package_engine')
    with guard.turn_context('룰 수정 절차를 알려줘'):
        result = await adapter.send('synthetic-channel', BAD)
        assert result.success and session.payloads[-1]['message'] == GOOD
        checks.append('send')
        result = await adapter.edit_message('synthetic-channel', 'synthetic-post', BAD, finalize=True)
        assert result.success and session.payloads[-1]['message'] == GOOD
        checks.append('edit')
        result = await adapter._post_with_file('synthetic-channel', 'synthetic-file', BAD, None, None)
        assert result.success and session.payloads[-1]['message'] == GOOD
        checks.append('caption')
        payload = {'channel_id': 'synthetic-channel', 'message': BAD}
        await adapter._api('POST', 'posts', payload)
        assert session.payloads[-1]['message'] == GOOD and payload['message'] == BAD
        checks.append('direct_api_and_input_preserved')
    raw = ('認証失敗\n' * 1200).rstrip('\n')
    text = '확인한 원문입니다.\n```text\n' + raw + '\n```'
    with guard.turn_context('로그 원문을 보여줘'):
        guard.set_turn_evidence([{'role': 'user', 'content': '로그 원문을 보여줘'},
                                 {'role': 'tool', 'content': raw}])
        session.payloads.clear()
        result = await adapter.send('synthetic-channel', text)
        assert result.success and len(session.payloads) > 1
        combined = '\n'.join(p['message'] for p in session.payloads)
        assert combined.count('認証失敗') == 1200 and guard.FALLBACK_NOTICE not in combined
        checks.append('verified_raw_split_preserved')
        session.payloads.clear()
        session.fail_thread = True
        # Same branch as a stale thread on the actual adapter, with fake HTTP only.
        checked = await guard.guard_text('`認証失敗`')
        result = await adapter._post_preserving_thread('synthetic-channel',
                    {'channel_id': 'synthetic-channel', 'root_id': 'synthetic-root', 'message': checked},
                    {'notify': True})
        assert result.get('id') and len(session.payloads) == 2
        assert '認証失敗' in session.payloads[-1]['message']
        assert guard.FALLBACK_NOTICE not in session.payloads[-1]['message']
        checks.append('thread_fallback_verified_raw_preserved')
        session.fail_thread = False
    with guard.turn_context('이 문장을 일본어로 번역해줘: 규칙'):
        previous = await guard.guard_text('`規則`')
    with guard.turn_context('현재 상태를 한국어로 알려줘'):
        session.payloads.clear()
        session.fail_thread = True
        result = await adapter._post_preserving_thread('synthetic-channel',
                    {'channel_id': 'synthetic-channel', 'root_id': 'synthetic-root', 'message': previous},
                    {'notify': True})
        assert result.get('id') and len(session.payloads) == 2
        assert all('規則' not in p['message'] for p in session.payloads)
        checks.append('thread_retry_rejects_previous_turn_marker')
        session.fail_thread = False
    # A failed repair at the final transport must not send mixed model prose.
    async def failed_repair(_text):
        raise RuntimeError('synthetic private failure')

    with guard.turn_context('현재 상태를 한국어로 알려줘'), \
            patch.object(guard, '_default_rewrite', side_effect=failed_repair):
        session.payloads.clear()
        await adapter._api('POST', 'posts', {'channel_id': 'synthetic-channel',
                                            'message': '상태=pending\n이 规则 조정이 필요합니다.'})
        assert session.payloads[-1]['message'] == '상태=pending\n' + guard.FALLBACK_NOTICE
        checks.append('transport_failed_repair_blocks_foreign_prose')
    standalone = FakeSession()
    with patch.object(mattermost, '_url_and_token', return_value=('https://invalid.example', 'synthetic-token')), \
            patch('aiohttp.ClientSession', return_value=standalone), \
            patch.object(base, 'resolve_proxy_url', return_value=None):
        result = await mattermost._standalone_send(None, 'synthetic-channel', BAD)
        assert result['success'] and standalone.payloads[-1]['message'] == GOOD
        checks.append('standalone_cron')
    # Same-task /queue refresh must revoke the prior explicit translation exception.
    with guard.turn_context('이 문장을 일본어로 번역해줘: 정상입니다.'):
        guard.begin_turn('이 문장을 일본어로 번역해줘: 정상입니다.')
        assert await guard.guard_text('正常です。') == '正常です。'
        guard.begin_turn('현재 상태를 한국어로 알려줘')
        assert await guard.guard_text(BAD) == GOOD
        checks.append('queued_request_language_reset')
    if model:
        with guard.turn_context('현재 상태를 알려줘'):
            result = await guard.guard_text('이 规则 조정이 필요합니다.\n상태=pending, IP=211.170.162.111:11434')
            assert result == '이 규칙 조정이 필요합니다.\n상태=pending, IP=211.170.162.111:11434', 'model rewrite did not validate'
            checks.append('dgx_model_rewrite_and_facts_preserved')
    print(json.dumps({'runtime_checks': checks, 'passed': len(checks),
                      'unicode_engine': engine, 'real_chat_posts': 0}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', action='store_true')
    args = parser.parse_args()
    asyncio.run(main(args.model))
