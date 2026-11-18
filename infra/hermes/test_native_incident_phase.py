"""Native report leases: no network, commands, model, or approval execution."""
import contextlib
import copy
from dataclasses import dataclass
import hashlib
import io
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

import soc_management_run as w
from test_native_incident_report import AT, BLOCK, MOD, Q, SUR, records

MODEL='soc-qwen36:35b-balanced-q4km-20261108'

@dataclass
class Verdict:
    action: str
    response: object

class NativePhase(unittest.TestCase):
    def setUp(self):
        self.h=w.chat_lookup_harness()
        self.chat={'request':Q,'requested_at_kst':AT,'tools':None,'background':''}
        ledger,receipts=records()
        self.catalog={n:{'type':'object','additionalProperties':False,'properties':{
            'lookback_minutes':{'type':'integer','minimum':1,'maximum':1440}}} for n in (MOD,SUR)}
        self.catalog[BLOCK]={'type':'object','additionalProperties':False,'properties':{}}
        self.agent=types.SimpleNamespace(_current_turn_id='turn_current',provider='custom',api_mode='chat_completions',
            base_url='http://10.200.10.10:11435/v1',model=MODEL,valid_tool_names=set(self.catalog))
        self.snapshot={'turn':self.agent._current_turn_id,'read_ledger':ledger,'receipts':receipts,
            'service_context':None,'facts':[],'reads':list(self.catalog)}
        self.agent._capstone_management_report=self.snapshot
        self.request={'model':MODEL,'messages':[{'role':'user','content':Q}],
            'tools':[{'type':'function','function':{'name':n,'parameters':s}} for n,s in self.catalog.items()]}
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ,{'CAPSTONE_EVIDENCE_REPORT_COMPACT':'1',
            'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps(self.chat)},clear=True))
        self.stack.enter_context(patch.object(w,'diagnostic_contract',return_value=self.h.CONTRACT))
        # Only the already-existing provider class is substituted on this Mac.
        tool=types.SimpleNamespace
        self.stack.enter_context(patch.dict(sys.modules,{'openai':types.ModuleType('openai'),
            'openai.types':types.ModuleType('openai.types'),
            'openai.types.chat':types.SimpleNamespace(ChatCompletionMessageToolCall=tool)}))

    def lease(self):
        result=w.native_incident_report_request(self.request,self.agent,self.snapshot)
        self.assertIsNot(result,self.request)
        return result,self.agent._capstone_management_selection

    def value(self,selection):
        return {'request_nonce':selection['nonce'],'more_evidence':False,'report':{
            'assessment':'unresolved','basis':'확보한 경보 표본으로는 실제 사건의 영향과 과거 웹 요청의 차단 여부를 확정할 수 없습니다.',
            'evidence_indexes':list(range(len(selection['report_context']['evidence_tools']))),
            'limitations':['실제 침해 영향은 추가 근거가 필요합니다.'],'next_steps':[],'status':'needs_review',
            'unverified_blocking_scope':'과거 웹 요청의 차단·거부'}}

    def response(self,value):
        return types.SimpleNamespace(model=MODEL,choices=[types.SimpleNamespace(finish_reason='stop',
            message=types.SimpleNamespace(content=json.dumps(value,ensure_ascii=False),tool_calls=None,refusal=None))],usage=None)

    def invoke(self,request,response):
        calls=[]
        wrapped=w.management_selection_call_wrapper(lambda agent,**kw:(calls.append(kw) or Verdict('fallthrough',response)))
        stderr=io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result=wrapped(self.agent,api_kwargs=request,turn_id=self.agent._current_turn_id)
        return result,calls,stderr.getvalue()

    def test_disabled_and_nonmatching_paths_are_unchanged(self):
        for key,value in (('CAPSTONE_EVIDENCE_REPORT_COMPACT','0'),('CAPSTONE_MANAGEMENT_MODE','manage')):
            with patch.dict(os.environ,{key:value}):
                if key.endswith('MODE'):
                    with patch.object(w,'chat_read_context',return_value=None):
                        self.assertIs(w.native_incident_report_request(self.request,self.agent,self.snapshot),self.request)
                else:self.assertIs(w.native_incident_report_request(self.request,self.agent,self.snapshot),self.request)
        for change in ({'provider':'other'},{'base_url':'http://example.invalid'},{'_interrupt_requested':True}):
            with patch.multiple(self.agent,create=True,**change):
                self.assertIs(w.native_incident_report_request(self.request,self.agent,self.snapshot),self.request)
        with patch.dict(self.snapshot,{'service_context':{'kind':'service'}}):
            self.assertIs(w.native_incident_report_request(self.request,self.agent,self.snapshot),self.request)

    def test_request_uses_shared_schema_context_and_no_tools(self):
        before=copy.deepcopy(self.request);result,selection=self.lease()
        self.assertEqual(before,self.request);self.assertNotIn('tools',result)
        self.assertEqual(selection['report_context']['current_ip_inventory']['returned_ip_count'],0)
        self.assertEqual(selection['remaining_read_calls'],4)
        self.assertEqual(result['response_format']['json_schema']['schema'],selection['schema'])
        self.assertEqual(selection['report_calls'][0]['result'],self.snapshot['receipts'][0]['output'])

    def test_protected_catalog_and_extra_body_override_are_refused(self):
        request=copy.deepcopy(self.request);request['tools'].append({'type':'function','function':{
            'name':'mcp__resp__block_ip','parameters':{'type':'object'}}})
        with self.assertRaisesRegex(RuntimeError,'catalog_invalid'):
            w.native_incident_report_request(request,self.agent,self.snapshot)
        for key in ('model','messages'):
            request={**self.request,'extra_body':{key:'override'}}
            with self.assertRaisesRegex(RuntimeError,'body_override'):
                w.native_incident_report_request(request,self.agent,self.snapshot)

    def test_valid_report_uses_native_transport_and_preserves_raw_private_audit(self):
        request,selection=self.lease();value=self.value(selection);response=self.response(value)
        raw=response.choices[0].message.content
        result,calls,logs=self.invoke(request,response)
        self.assertEqual(len(calls),1);self.assertIn('MANAGEMENT_STATUS: needs_review',result.response.choices[0].message.content)
        self.assertIn('판단문의 미확인 차단 범위',result.response.choices[0].message.content)
        self.assertEqual(response.choices[0].message.content,raw)
        line=next(v for v in logs.splitlines() if v.startswith('management_incident_report_audit '))
        audit=json.loads(line.split(' ',1)[1]);self.assertEqual(audit['untrusted_raw_response'],raw)
        self.assertEqual(audit['raw_response_sha256'],hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(audit['inference_profile'],selection['incident_inference_profile'])
        self.assertNotEqual(result.response.choices[0].message.content,raw)

    def test_invalid_json_nonce_or_claim_is_not_returned_as_a_report(self):
        for kind in ('json','nonce','current_unknown','success'):
            request,selection=self.lease();value=self.value(selection)
            if kind=='nonce':value['request_nonce']='other'
            if kind=='current_unknown':value['report']['basis']='현재 IP 차단 목록은 미확인입니다. 추가 조회가 필요합니다.'
            if kind=='success':value['report'].update(assessment='remediated',status='resolved',basis='모든 공격이 차단되었으며 실제 서버 침해도 모두 복구 완료했습니다.')
            response=self.response(value)
            if kind=='json':response.choices[0].message.content='{not json'
            result,calls,logs=self.invoke(request,response)
            text=result.response.choices[0].message.content
            self.assertIn('모델의 최종 판단이 완료되지 않았거나',text,kind)
            self.assertIn('MANAGEMENT_STATUS: needs_review',text,kind)
            self.assertIsNone(result.response.choices[0].message.tool_calls)
            self.assertIn('"accepted": false',logs)
            if kind=='current_unknown':self.assertIn('current_block_inventory_unknown_scope',logs)

    def test_current_receipts_or_root_context_cannot_change_after_the_lease(self):
        for kind in ('receipt','clock','question'):
            request,selection=self.lease();response=self.response(self.value(selection))
            with contextlib.ExitStack() as stack:
                if kind=='receipt':
                    changed=copy.deepcopy(self.snapshot);changed['receipts'][0]['output']='changed'
                    stack.enter_context(patch.object(self.agent,'_capstone_management_report',changed))
                else:
                    chat={**self.chat,**({'requested_at_kst':'2026-11-18T05:01:00+09:00'} if kind=='clock' else {'request':'다른 사건 조사해줘'})}
                    stack.enter_context(patch.dict(os.environ,{'CAPSTONE_CHAT_READ_JSON':json.dumps(chat)}))
                result,_,_=self.invoke(request,response)
                self.assertIn('MANAGEMENT_STATUS: needs_review',result.response.choices[0].message.content)

    def test_changed_schema_or_turn_refuses_before_native_transport(self):
        request,selection=self.lease();self.agent._current_turn_id='other'
        with self.assertRaisesRegex(RuntimeError,'lease_invalid'):
            self.invoke(request,self.response(self.value(selection)))
        self.agent._current_turn_id='turn_current';request,selection=self.lease()
        request=copy.deepcopy(request);request['response_format']['json_schema']['schema']={}
        with self.assertRaisesRegex(RuntimeError,'lease_invalid'):
            self.invoke(request,self.response(self.value(selection)))

    def test_native_inquiry_is_read_only_and_rejects_repeat_or_invalid_time(self):
        request,selection=self.lease();value={'request_nonce':selection['nonce'],'more_evidence':True,
            'report':None,'calls':[{'tool':MOD,'arguments':{'lookback_minutes':30}}]}
        result,_,_=self.invoke(request,self.response(value))
        message=result.response.choices[0].message
        self.assertEqual(result.response.choices[0].finish_reason,'tool_calls')
        self.assertEqual(message.tool_calls[0].function['name'],MOD)
        self.assertIsNone(message.content);self.assertEqual(self.agent._capstone_incident_phase['inquiries'],1)
        request,selection=self.lease();value['request_nonce']=selection['nonce'];value['calls'][0]['arguments']={}
        result,_,_=self.invoke(request,self.response(value))
        self.assertIsNone(result.response.choices[0].message.tool_calls)
        self.assertIn('MANAGEMENT_STATUS: needs_review',result.response.choices[0].message.content)

    def test_phase_budget_is_bounded_and_state_is_not_inherited_across_turns(self):
        self.agent._capstone_incident_phase={'turn':'turn_current','requests':6,'inquiries':0}
        with self.assertRaisesRegex(RuntimeError,'budget_exhausted'):self.lease()
        self.agent._capstone_incident_phase={'turn':'old_turn','requests':6,'inquiries':2}
        _,selection=self.lease();self.assertEqual(self.agent._capstone_incident_phase['requests'],1)
        self.agent._capstone_incident_phase['inquiries']=2
        _,selection=self.lease();self.assertEqual(selection['remaining_read_calls'],0)

    def test_lost_evidence_after_phase_start_cannot_fall_back_to_unbound_prompt(self):
        self.lease();self.snapshot['receipts']=[]
        with self.assertRaisesRegex(RuntimeError,'receipts_unavailable'):self.lease()

    def initial(self,question=None,missing=()):
        question=question or self.chat['request']
        catalog=copy.deepcopy(self.catalog)
        for name in (MOD,SUR):
            catalog[name]['properties'].update(since_kst={'type':'string'},until_kst={'type':'string'},
                limit={'type':'integer','minimum':1,'maximum':50})
        for name in missing:catalog.pop(name)
        request={**self.request,'tool_choice':'required','tools':[
            {'type':'function','function':{'name':n,'parameters':s}} for n,s in catalog.items()]}
        self.agent.valid_tool_names=set(catalog)
        with patch.dict(os.environ,{'CAPSTONE_CHAT_READ_JSON':json.dumps({**self.chat,'request':question})}):
            result=w.management_read_request(request,self.agent,pending=True)
        return result,self.agent._capstone_management_selection,catalog

    def test_initial_named_sensors_and_current_list_form_one_complete_read_batch(self):
        from jsonschema import ValidationError
        request,selection,_=self.initial()
        self.assertTrue(selection['shared_incident_initial'])
        self.assertEqual(set(selection['catalog']),{MOD,SUR,BLOCK})
        self.assertEqual(selection['schema']['title'],'RequiredReadToolSelection')
        self.assertEqual(selection['schema']['properties']['calls']['minItems'],3)
        calls=[{'tool':n,'arguments':{} if n==BLOCK else {
            'since_kst':'2026-11-17T00:00:00+09:00','until_kst':'2026-11-18T00:00:00+09:00'}} for n in (MOD,SUR,BLOCK)]
        value={'request_nonce':selection['nonce'],'calls':calls}
        result,count=w.management_selection_response(self.response(value),selection,self.agent)
        self.assertEqual(count,3);self.assertEqual(result.choices[0].finish_reason,'tool_calls')
        with self.assertRaises(ValidationError):
            w.management_selection_response(self.response({**value,'calls':calls[:2]}),selection,self.agent)
        repeated=[calls[0],{**calls[0],'arguments':{**calls[0]['arguments'],'limit':5}},calls[1]]
        with self.assertRaises(ValidationError):
            w.management_selection_response(self.response({**value,'calls':repeated}),selection,self.agent)

    def test_initial_calendar_binding_matches_shared_today_and_yesterday_rules(self):
        from jsonschema import Draft202012Validator
        for word,start,end in (('어제','2026-11-17T00:00:00+09:00','2026-11-18T00:00:00+09:00'),
                               ('오늘','2026-11-18T00:00:00+09:00',AT)):
            question=f'{word} WAF·IDS 경보 조사해줘. 현재 임시 IP 차단도 확인해줘.'
            if hasattr(self.agent,'_capstone_chat_selection_turn'):del self.agent._capstone_chat_selection_turn
            _,selection,_=self.initial(question)
            schema=selection['schema'];nonce=selection['nonce']
            calls=[{'tool':n,'arguments':{} if n==BLOCK else {'since_kst':start,'until_kst':end}} for n in (MOD,SUR,BLOCK)]
            self.assertTrue(Draft202012Validator(schema).is_valid({'request_nonce':nonce,'calls':calls}))
            for bad in ({'lookback_minutes':30},{'since_kst':'2026-11-18T04:30:00+09:00','until_kst':AT}):
                changed=copy.deepcopy(calls);changed[0]['arguments']=bad
                self.assertFalse(Draft202012Validator(schema).is_valid({'request_nonce':nonce,'calls':changed}))

    def test_initial_missing_registered_companion_never_silently_narrows_scope(self):
        for name in (MOD,SUR,BLOCK):
            if hasattr(self.agent,'_capstone_chat_selection_turn'):del self.agent._capstone_chat_selection_turn
            with self.assertRaisesRegex(RuntimeError,'initial_read_scope_missing'):self.initial(missing=(name,))

    def test_initial_explicit_period_and_controller_bound_dates_are_preserved(self):
        from jsonschema import Draft202012Validator
        _,selection,_=self.initial('어제 11시부터 12시까지 WAF·IDS 경보 조사해줘.')
        self.assertEqual(set(selection['catalog']),{MOD,SUR})
        self.assertNotIn(BLOCK,selection['catalog'])
        value={'request_nonce':selection['nonce'],'calls':[{'tool':n,'arguments':{
            'since_kst':'2026-11-17T11:00:00+09:00','until_kst':'2026-11-17T12:00:00+09:00'}} for n in (MOD,SUR)]}
        self.assertTrue(Draft202012Validator(selection['schema']).is_valid(value))
        schema={'type':'object','additionalProperties':False,'properties':{
            'since_kst':{'const':'2026-11-16T00:00:00+09:00'},'until_kst':{'const':'2026-11-17T00:00:00+09:00'},
            'lookback_minutes':{'type':'integer'}},'required':['since_kst','until_kst']}
        self.assertEqual(self.h.initial_event_day_schemas('어제 WAF 조사해줘.',{MOD:schema},[],AT),{MOD:schema})

    def test_initial_default_off_and_follow_up_do_not_rebind_prior_selection(self):
        with patch.dict(os.environ,{'CAPSTONE_EVIDENCE_REPORT_COMPACT':'0'}):
            _,selection,_=self.initial()
        self.assertNotIn('shared_incident_initial',selection)
        self.assertNotIn(BLOCK,selection['catalog'])
        self.agent._capstone_chat_selection_turn=self.agent._current_turn_id
        _,selection,_=self.initial()
        self.assertNotIn('shared_incident_initial',selection)
        self.assertIn(BLOCK,selection['catalog'])

    def test_report_uses_the_shared_inference_profile_instead_of_inherited_thinking(self):
        self.request.update(reasoning_effort='medium',think=True,max_tokens=1024,max_completion_tokens=1024,
            temperature=1,top_p=1,extra_body={'think':True,'reasoning':'enabled','reasoning_effort':'medium',
                'max_tokens':1,'max_completion_tokens':1,'temperature':1,'top_p':1})
        before=copy.deepcopy(self.request);request,selection=self.lease()
        expected={'reasoning_effort':'none','max_tokens':self.h.CONTRACT.OUTPUT_TOKENS,
            'temperature':self.h.CONTRACT.TEMPERATURE,'top_p':self.h.CONTRACT.TOP_P}
        self.assertEqual(selection['incident_inference_profile'],expected)
        self.assertEqual({k:request[k] for k in expected},expected)
        self.assertNotIn('think',request);self.assertNotIn('max_completion_tokens',request)
        self.assertEqual(request['extra_body'],{});self.assertEqual(before,self.request)
        with patch.object(self.h.CONTRACT,'REASONING',True):
            request,selection=self.lease();self.assertEqual(request['reasoning_effort'],'medium')

    def test_changed_inference_profile_is_rejected_before_native_transport(self):
        for change in ({'reasoning_effort':'medium'},{'max_tokens':1},{'temperature':1},{'top_p':1},
                       {'extra_body':{'think':True}}):
            request,selection=self.lease();request=copy.deepcopy(request);request.update(change);calls=[]
            def transport(agent,**kw):calls.append(kw);return Verdict('fallthrough',self.response(self.value(selection)))
            wrapped=w.management_selection_call_wrapper(transport)
            with self.assertRaisesRegex(RuntimeError,'lease_invalid'):
                wrapped(self.agent,api_kwargs=request,turn_id=self.agent._current_turn_id)
            self.assertEqual(calls,[])

    def test_invalid_shared_profile_never_reaches_the_provider(self):
        for name,value in (('REASONING','none'),('OUTPUT_TOKENS',0),('TEMPERATURE',float('nan')),('TOP_P',2)):
            with patch.object(self.h.CONTRACT,name,value):
                with self.assertRaisesRegex(RuntimeError,'inference_profile_invalid'):self.lease()

    def reject_claim(self):
        request,selection=self.lease();value=self.value(selection)
        value['report']['basis']='현재 IP 차단 목록은 미확인입니다. 추가 조회가 필요합니다.'
        result,calls,logs=self.invoke(request,self.response(value))
        return result,selection,value

    def continue_repair(self,text,counter=0,remaining=8):
        agent=self.agent;agent.max_iterations=12;agent.iteration_budget=types.SimpleNamespace(remaining=remaining)
        agent._emit_pending_fallback_notice=agent._clear_status_buffer=lambda:None
        agent._build_assistant_message=lambda message,kind:{'role':'assistant','content':message.content}
        original_calls=[]
        native=types.SimpleNamespace(FinalResponseVerdict=lambda **kw:types.SimpleNamespace(**kw))
        wrapped=w.grounding_wrapper(lambda agent,**kw:original_calls.append(kw) or 'original',native,
            lambda messages,message:messages.append(message),lambda messages,user:0,['completed'],
            facts=[],successful_reads=set(self.catalog))
        user=self.chat['request'];messages=[{'role':'user','content':user}]
        kw={'assistant_message':types.SimpleNamespace(content=text,tool_calls=None),'messages':messages,
            'user_message':user,'api_call_count':3,'codex_ack_continuations':counter,'finish_reason':'stop',
            '_pending_verification_response':None}
        for key in ('active_system_prompt','_turn_exit_reason','_preflight_compression_blocked',
                    'truncated_response_parts','length_continue_retries','_pending_verification_response_previewed'):
            kw[key]=None
        return wrapped(agent,**kw),messages,original_calls

    def test_rejected_claim_continues_native_iteration_with_same_evidence_and_feedback(self):
        result,selection,value=self.reject_claim();state=self.agent._capstone_incident_phase
        self.assertTrue(state['repair_pending']);self.assertEqual(state['claim_repairs'],1)
        continued,messages,original=self.continue_repair(result.response.choices[0].message.content)
        self.assertEqual(continued.action,'continue');self.assertEqual(continued.codex_ack_continuations,1)
        self.assertEqual(original,[]);self.assertFalse(state['repair_pending'])
        request,next_selection=self.lease();body=json.loads(request['messages'][1]['content'])
        self.assertEqual(body['untrusted_report_feedback']['issues'],['current_block_inventory_unknown_scope'])
        self.assertEqual(body['untrusted_report_feedback']['untrusted_rejected_report']['basis'],value['report']['basis'])
        self.assertEqual(next_selection['report_calls'],selection['report_calls'])
        self.assertEqual(len(messages),3)
        good=self.value(next_selection);accepted,_,_=self.invoke(request,self.response(good))
        self.assertIn('INCIDENT_DISPOSITION:',accepted.response.choices[0].message.content)
        self.assertNotIn('feedback',state);self.assertNotIn('repair_pending',state)

    def test_claim_repairs_stop_at_shared_limit_and_native_iteration_budget(self):
        for counter in range(self.h.CONTRACT.REPAIR_PASSES):
            result,_,_=self.reject_claim()
            continued,_,_=self.continue_repair(result.response.choices[0].message.content,counter=counter)
            self.assertEqual(continued.action,'continue')
        result,_,_=self.reject_claim()
        self.assertFalse(self.agent._capstone_incident_phase['repair_pending'])
        self.assertEqual(self.agent._capstone_incident_phase['claim_repairs'],self.h.CONTRACT.REPAIR_PASSES)
        self.assertIn('MANAGEMENT_STATUS: needs_review',result.response.choices[0].message.content)
        # A pending repair cannot bypass the runner's own remaining budget.
        self.agent._capstone_incident_phase['repair_pending']=True
        stopped,_,original=self.continue_repair(result.response.choices[0].message.content,counter=2,remaining=1)
        self.assertEqual(stopped,'original');self.assertEqual(len(original),1)

    def test_repair_feedback_is_not_reused_for_changed_receipts_or_root_question(self):
        _,selection,_=self.reject_claim()
        for kind in ('receipt','question'):
            with contextlib.ExitStack() as stack:
                if kind=='receipt':
                    snapshot=copy.deepcopy(self.snapshot);raw=json.dumps({'result':json.dumps({'blocks':['192.0.2.10']})})
                    snapshot['receipts'][-1]['output']=raw
                    snapshot['read_ledger'][-1]['result_sha256']=hashlib.sha256(raw.encode()).hexdigest()
                    stack.enter_context(patch.dict(self.snapshot,snapshot))
                else:
                    stack.enter_context(patch.dict(os.environ,{'CAPSTONE_CHAT_READ_JSON':json.dumps({**self.chat,'request':Q+' 출발지 비교도 해줘.'})}))
                request,_=self.lease()
                self.assertNotIn('untrusted_report_feedback',json.loads(request['messages'][1]['content']))

    def test_nonce_failure_does_not_create_a_claim_repair(self):
        request,selection=self.lease();value=self.value(selection);value['request_nonce']='wrong'
        result,_,_=self.invoke(request,self.response(value))
        self.assertFalse(self.agent._capstone_incident_phase.get('repair_pending',False))
        self.assertNotIn('feedback',self.agent._capstone_incident_phase)

    def test_repeated_inquiry_gets_feedback_once_without_reexecuting_reads(self):
        request,selection=self.lease()
        value={'request_nonce':selection['nonce'],'more_evidence':True,'report':None,
            'calls':[{'tool':MOD,'arguments':{}}]}
        result,_,_=self.invoke(request,self.response(value));state=self.agent._capstone_incident_phase
        self.assertTrue(state['repair_pending']);self.assertEqual(state['feedback']['issues'],['already_completed_read'])
        self.assertIsNone(result.response.choices[0].message.tool_calls)
        continued,_,_=self.continue_repair(result.response.choices[0].message.content)
        self.assertEqual(continued.action,'continue')
        request,selection=self.lease();body=json.loads(request['messages'][1]['content'])
        self.assertIn('untrusted_rejected_reads',body['untrusted_report_feedback'])
        value['request_nonce']=selection['nonce'];result,_,_=self.invoke(request,self.response(value))
        self.assertFalse(state['repair_pending']);self.assertEqual(len(state['rejected_reads']),1)
        self.assertIsNone(result.response.choices[0].message.tool_calls)

if __name__=='__main__':unittest.main()
