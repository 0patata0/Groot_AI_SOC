import asyncio
from types import SimpleNamespace as NS
import unittest
from unittest.mock import AsyncMock,Mock,patch
import progress


class NativeProgress(unittest.IsolatedAsyncioTestCase):
    def setup_turn(self):
        adapter=NS(send=AsyncMock(return_value=NS(success=True,message_id='m'*26)),edit_message=AsyncMock(),_capstone_progress_ids=set())
        runner=NS(_delivery_adapter_for=lambda source:adapter,
                  _should_emit_long_running_notification=Mock(side_effect=[True,True,False]),
                  _agent_activity_summary=lambda agent:{'current_tool':'mcp__x__read','last_activity_desc':'SECRET'})
        turn=NS(source=NS(platform='mattermost',chat_id='c'*26),session_key='run',agent_holder=[object()],
                _status_thread_metadata={'thread_id':'r'*26},_cleanup_progress=True,_cleanup_msg_ids=[])
        return adapter,runner,turn

    async def test_one_bound_bubble_fixed_phase_and_native_post_delivery_cleanup(self):
        adapter,runner,turn=self.setup_turn()
        callback=progress.wrapper(AsyncMock(),NS(allowed=lambda *a:True),lambda m:m,lambda m,**k:m)
        with patch.object(progress.asyncio,'sleep',AsyncMock()):
            await callback(runner,None,turn,[NS(done=lambda:True,cancelled=lambda:False)])
        self.assertEqual(adapter.send.await_count,1)
        self.assertEqual(adapter.edit_message.await_count,2)
        self.assertEqual(turn._cleanup_msg_ids,['m'*26])
        self.assertIn('MCP 조회 중',adapter.send.call_args.args[1]);self.assertNotIn('SECRET',str(adapter.send.call_args))
        self.assertEqual(adapter.send.call_args.kwargs['metadata'],{'thread_id':'r'*26})

    async def test_ambiguous_post_is_not_replayed(self):
        adapter,runner,turn=self.setup_turn();adapter.send.side_effect=TimeoutError
        callback=progress.wrapper(AsyncMock(),NS(allowed=lambda *a:True),lambda m:m,lambda m,**k:m)
        with patch.object(progress.asyncio,'sleep',AsyncMock()):await callback(runner,None,turn,[None])
        self.assertEqual(adapter.send.await_count,1);self.assertFalse(turn._cleanup_msg_ids)

    async def test_cleanup_cannot_delete_unbound_or_other_bots_message(self):
        original=AsyncMock(return_value=False);delete=progress.delete_wrapper(original)
        adapter=NS(_capstone_progress_ids={('c'*26,'m'*26)},_bot_user_id='b'*26,
                   _api_get=AsyncMock(return_value={'channel_id':'c'*26,'user_id':'x'*26}),_session=NS(delete=Mock()))
        self.assertFalse(await delete(adapter,'c'*26,'z'*26));original.assert_awaited_once()
        self.assertFalse(await delete(adapter,'c'*26,'m'*26));adapter._session.delete.assert_not_called()

    def test_protected_phase_is_not_a_claim_of_execution_success(self):
        self.assertEqual(progress.phase({'current_tool':'mcp__x__write'},NS(allowed=lambda *a:False)),'승인·작업 절차 진행 중')

if __name__=='__main__':unittest.main()
