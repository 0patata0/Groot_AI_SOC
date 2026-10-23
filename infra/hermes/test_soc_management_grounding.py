"""Bounded native-loop retry: model selects a read; no action/argument synthesis."""
import copy
import types
import unittest
from unittest.mock import patch
from test_soc_management_run import wrapper, definition, READ_NAMES, WRITE_NAMES


class Grounding(unittest.TestCase):
    def setUp(self):
        self.completed=[];self.original_calls=[]
        self.tools=[definition(n) for n in READ_NAMES+WRITE_NAMES+['terminal']]
        self.request={'model':'qwen3.6:35b','tools':self.tools,'tool_choice':'auto',
                      'reasoning_effort':'none','extra_body':{'think':False}}
        self.builder=lambda:copy.deepcopy(self.request)
        self.agent=types.SimpleNamespace(_build_api_kwargs=self.builder,tools=self.tools,
            api_mode='chat_completions',provider='custom',model='qwen3.6:35b',
            base_url='http://211.170.162.111:11434/v1',_current_turn_id='turn-a',
            _interrupt_requested=False,max_iterations=12,iteration_budget=types.SimpleNamespace(remaining=8),
            _emit_pending_fallback_notice=lambda:None,_clear_status_buffer=lambda:None,
            _build_assistant_message=lambda msg,reason:{'role':'assistant','content':msg.content})
        self.kw=dict(assistant_message=types.SimpleNamespace(content='조회하겠습니다.',tool_calls=None),
            finish_reason='stop',messages=[{'role':'user','content':'최근 보안 이벤트를 확인해줘'}],
            user_message='최근 보안 이벤트를 확인해줘',api_call_count=1,codex_ack_continuations=0,
            active_system_prompt='policy',_turn_exit_reason=None,_preflight_compression_blocked=False,
            truncated_response_parts=[],length_continue_retries=0,_pending_verification_response=None,
            _pending_verification_response_previewed=False)
        def original(agent,**kw):self.original_calls.append(kw);return 'original'
        self.call=wrapper.grounding_wrapper(original,types.SimpleNamespace(FinalResponseVerdict=types.SimpleNamespace),
            lambda rows,row:rows.append(row),lambda rows,user:0,self.completed)

    def test_zero_calls_retry_offers_reads_once_without_selecting_tool_or_arguments(self):
        verdict=self.call(self.agent,**self.kw);self.assertEqual(verdict.action,'continue')
        self.assertEqual(verdict.codex_ack_continuations,1)
        request=self.agent._build_api_kwargs()
        self.assertEqual(request['tool_choice'],'required')
        self.assertEqual({t['function']['name'] for t in request['tools']},set(READ_NAMES))
        self.assertNotIn('arguments',request);self.assertNotIn('reasoning_effort',request)
        self.assertNotIn('think',request['extra_body'])
        self.assertIs(self.agent._build_api_kwargs,self.builder)
        next_request=self.agent._build_api_kwargs()
        self.assertEqual(next_request['reasoning_effort'],'none');self.assertFalse(next_request['extra_body']['think'])
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_actual_read_or_native_pending_tool_does_not_force_more_calls(self):
        self.completed.append('search_suricata_alerts')
        self.assertEqual(self.call(self.agent,**self.kw),'original')
        self.completed.clear();self.kw['assistant_message'].tool_calls=[{'name':'native-selected'}]
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_interrupt_budget_pending_verification_and_turn_limits_preserved(self):
        cases=[('kw','api_call_count',11),('kw','codex_ack_continuations',1),
               ('kw','_pending_verification_response','pending'),('agent','_interrupt_requested',True)]
        for where,key,value in cases:
            with self.subTest(key=key):
                if where=='kw':old=self.kw[key];self.kw[key]=value
                else:old=getattr(self.agent,key);setattr(self.agent,key,value)
                self.assertEqual(self.call(self.agent,**self.kw),'original')
                if where=='kw':self.kw[key]=old
                else:setattr(self.agent,key,old)
        self.agent.iteration_budget.remaining=1
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_reanchor_cannot_point_at_another_user_message(self):
        self.kw['messages']=[{'role':'user','content':'old unrelated request'}]
        self.assertEqual(self.call(self.agent,**self.kw),'original')
        self.assertIs(self.agent._build_api_kwargs,self.builder)

    def test_no_read_tools_or_other_api_cannot_arm_retry(self):
        self.agent.tools=[definition(WRITE_NAMES[0])]
        self.assertEqual(self.call(self.agent,**self.kw),'original')
        self.agent.tools=self.tools;self.agent.api_mode='responses'
        self.assertEqual(self.call(self.agent,**self.kw),'original')

    def test_new_turn_cancels_required_request_without_changing_original_builder(self):
        self.call(self.agent,**self.kw);self.agent._current_turn_id='replacement'
        self.assertEqual(self.agent._build_api_kwargs()['tool_choice'],'auto')
        self.assertIs(self.agent._build_api_kwargs,self.builder)

    def test_other_provider_keeps_its_reasoning_settings(self):
        self.agent.base_url='https://other.example/v1'
        self.call(self.agent,**self.kw)
        request=self.agent._build_api_kwargs()
        self.assertEqual(request['reasoning_effort'],'none');self.assertFalse(request['extra_body']['think'])

    def test_unrecognized_native_source_refuses_before_installing_hook(self):
        with patch.object(wrapper.Path,'read_bytes',side_effect=OSError),self.assertRaisesRegex(RuntimeError,'source_changed'):
            wrapper.install_grounding_retry([])


if __name__=='__main__':unittest.main()
