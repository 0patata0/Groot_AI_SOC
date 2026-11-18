"""Compact initial-selection repair retains Native budgets and read authority."""
import copy
import json
import os
import types
import unittest
from unittest.mock import patch

import soc_management_run as w
import test_native_incident_phase as f

class NativeSelectionRepair(unittest.TestCase):
    setUp=f.NativePhase.setUp
    initial=f.NativePhase.initial
    response=f.NativePhase.response
    invoke=f.NativePhase.invoke
    lease=f.NativePhase.lease
    value=f.NativePhase.value

    def prepare(self):
        self.agent._capstone_initial_selection=None
        if hasattr(self.agent,'_capstone_chat_selection_turn'):del self.agent._capstone_chat_selection_turn
        request,selection,catalog=self.initial()
        incoming={**self.request,'tool_choice':'required','messages':[{'role':'user','content':'OLD-HISTORY'*10000}],
            'tools':[{'type':'function','function':{'name':n,'parameters':s}} for n,s in catalog.items()]}
        return request,selection,incoming

    def plan(self,selection,duplicate=False):
        names=(f.MOD,f.SUR,f.SUR if duplicate else f.BLOCK)
        return {'request_nonce':selection['nonce'],'calls':[{'tool':n,'arguments':{} if n==f.BLOCK else {
            'since_kst':'2026-11-17T00:00:00+09:00','until_kst':'2026-11-18T00:00:00+09:00'}} for n in names]}

    def continuation(self,text,counter=0,remaining=8):
        agent=self.agent;agent.max_iterations=12;agent.iteration_budget=types.SimpleNamespace(remaining=remaining)
        agent._emit_pending_fallback_notice=agent._clear_status_buffer=lambda:None
        agent._build_assistant_message=lambda message,kind:{'role':'assistant','content':message.content}
        original_calls=[];native=types.SimpleNamespace(FinalResponseVerdict=lambda **kw:types.SimpleNamespace(**kw))
        wrapped=w.grounding_wrapper(lambda agent,**kw:original_calls.append(kw) or 'original',native,
            lambda messages,message:messages.append(message),lambda messages,user:0,[])
        user=self.chat['request'];messages=[{'role':'user','content':user}]
        kw={'assistant_message':types.SimpleNamespace(content=text,tool_calls=None),'messages':messages,
            'user_message':user,'api_call_count':1+counter,'codex_ack_continuations':counter,'finish_reason':'stop',
            '_pending_verification_response':None}
        for key in ('active_system_prompt','_turn_exit_reason','_preflight_compression_blocked',
                    'truncated_response_parts','length_continue_retries','_pending_verification_response_previewed'):
            kw[key]=None
        return wrapped(agent,**kw),messages,original_calls

    def reject(self,request,selection,value=None):
        result,calls,logs=self.invoke(request,self.response(value or self.plan(selection,True)))
        self.assertIsNone(result.response.choices[0].message.tool_calls)
        self.assertEqual(len(calls),1)
        return result.response.choices[0].message.content,logs

    def test_observed_duplicate_peer_repair_keeps_small_context_and_native_dispatch(self):
        request,selection,incoming=self.prepare();original=copy.deepcopy(request)
        text,logs=self.reject(request,selection)
        self.assertIn('실제 조회는 수행하지 않았습니다',text)
        state=self.agent._capstone_initial_selection
        self.assertEqual(state['feedback']['missing_tools'],[f.BLOCK])
        continued,messages,old=self.continuation(text)
        self.assertEqual(continued.action,'continue');self.assertEqual(continued.codex_ack_continuations,1)
        self.assertEqual(old,[]);self.assertEqual(len(messages),3)
        retry=w.management_read_request(incoming,self.agent,pending=True)
        next_selection=self.agent._capstone_management_selection
        self.assertNotEqual(selection['nonce'],next_selection['nonce'])
        self.assertNotIn('OLD-HISTORY',json.dumps(retry['messages']))
        self.assertLess(len(json.dumps(retry['messages'],ensure_ascii=False).encode()),10000)
        self.assertEqual(len(retry['messages']),len(original['messages'])+1)
        self.assertEqual(request,original)
        result,_,_=self.invoke(retry,self.response(self.plan(next_selection)))
        self.assertEqual(result.response.choices[0].finish_reason,'tool_calls')
        self.assertEqual([c.function['name'] for c in result.response.choices[0].message.tool_calls],
            [f.MOD,f.SUR,f.BLOCK])
        self.assertFalse(state['last_rejected'])

    def test_rejection_feedback_never_echoes_model_argument_values(self):
        request,selection,incoming=self.prepare();value=self.plan(selection)
        value['calls'][0]['arguments']={'secret':'DO-NOT-ECHO'}
        text,logs=self.reject(request,selection,value);self.continuation(text)
        retry=w.management_read_request(incoming,self.agent,pending=True)
        self.assertNotIn('DO-NOT-ECHO',json.dumps(retry['messages'])+logs)

    def test_changed_outgoing_messages_are_rejected_before_native_transport(self):
        request,selection,incoming=self.prepare();request=copy.deepcopy(request)
        request['messages'].append({'role':'user','content':'OLD-HISTORY'*10000})
        with self.assertRaisesRegex(RuntimeError,'initial_selection_lease_changed'):
            self.invoke(request,self.response(self.plan(selection)))

    def test_wrong_nonce_and_unchanged_rejection_stop_without_large_retry(self):
        request,selection,incoming=self.prepare();value=self.plan(selection,True);value['request_nonce']='wrong'
        text,_=self.reject(request,selection,value)
        stopped,_,old=self.continuation(text);self.assertEqual(stopped,'original');self.assertEqual(len(old),1)
        request,selection,incoming=self.prepare();text,_=self.reject(request,selection);self.continuation(text)
        retry=w.management_read_request(incoming,self.agent,pending=True);selection=self.agent._capstone_management_selection
        text,_=self.reject(retry,selection)
        self.assertFalse(self.agent._capstone_initial_selection['repair_pending'])
        stopped,_,_=self.continuation(text,counter=1);self.assertEqual(stopped,'original')

    def test_changed_root_schema_model_or_mode_cannot_restore_an_old_lease(self):
        for kind in ('clock','schema','model','mode','pending'):
            request,selection,incoming=self.prepare();text,_=self.reject(request,selection);self.continuation(text)
            with patch.dict(os.environ,{}):
                if kind=='clock':os.environ['CAPSTONE_CHAT_READ_JSON']=json.dumps({**self.chat,'requested_at_kst':'2026-11-18T05:01:00+09:00'})
                if kind=='schema':incoming['tools'][0]['function']['parameters']['properties']['extra']={'type':'string'}
                if kind=='model':incoming['model']='unapproved-model'
                if kind=='mode':os.environ['CAPSTONE_MANAGEMENT_MODE']='manage'
                with self.assertRaisesRegex(RuntimeError,
                        'chat_read_context_invalid' if kind=='mode' else 'management_initial_selection_'):
                    w.management_read_request(incoming,self.agent,pending=kind!='pending')

    def test_two_distinct_repairs_respect_the_runner_budget_and_do_not_accumulate_prompts(self):
        request,selection,incoming=self.prepare();text,_=self.reject(request,selection)
        stopped,_,_=self.continuation(text,remaining=1);self.assertEqual(stopped,'original')
        first,_,_=self.continuation(text);self.assertEqual(first.action,'continue')
        retry=w.management_read_request(incoming,self.agent,pending=True);selection=self.agent._capstone_management_selection
        value=self.plan(selection);value['calls'][0]['arguments']={'lookback_minutes':30}
        text,_=self.reject(retry,selection,value);second,_,_=self.continuation(text,counter=1)
        self.assertEqual(second.codex_ack_continuations,2)
        retry=w.management_read_request(incoming,self.agent,pending=True)
        self.assertEqual(len(retry['messages']),len(request['messages'])+1)
        selection=self.agent._capstone_management_selection;value=self.plan(selection)
        value['calls'][1]['arguments']={'lookback_minutes':30}
        text,_=self.reject(retry,selection,value)
        self.assertEqual(self.agent._capstone_initial_selection['repairs'],2)
        stopped,_,_=self.continuation(text,counter=2);self.assertEqual(stopped,'original')

    def test_a_new_turn_does_not_inherit_pending_repair_or_its_feedback(self):
        request,selection,incoming=self.prepare();text,_=self.reject(request,selection);self.continuation(text)
        self.agent._current_turn_id='next-turn'
        fresh=w.management_read_request(incoming,self.agent,pending=True)
        self.assertEqual(self.agent._capstone_initial_selection['continuations'],0)
        self.assertNotIn('selection_validation',json.dumps(fresh['messages']))

    def test_initial_continuation_is_counted_before_a_report_repair(self):
        request,selection,incoming=self.prepare();text,_=self.reject(request,selection);self.continuation(text)
        retry=w.management_read_request(incoming,self.agent,pending=True);selection=self.agent._capstone_management_selection
        self.invoke(retry,self.response(self.plan(selection)))
        self.agent._capstone_management_report=self.snapshot
        request,selection=self.lease();value=self.value(selection)
        value['report']['basis']='현재 IP 차단 목록은 미확인입니다.'
        result,_,_=self.invoke(request,self.response(value))
        continued,_,_=f.NativePhase.continue_repair(self,result.response.choices[0].message.content,counter=1)
        self.assertEqual(continued.action,'continue');self.assertEqual(continued.codex_ack_continuations,2)

if __name__=='__main__':unittest.main()
