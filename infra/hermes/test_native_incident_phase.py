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

if __name__=='__main__':unittest.main()
