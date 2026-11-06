"""Explicit investigation scope and typed IDs; no model/network/service writes."""
import asyncio
import copy
import importlib.util
import json
from datetime import datetime, timedelta
from pathlib import Path
import unittest
from unittest.mock import patch

from test_soc_management_run import wrapper as w, Harness

NAME='mcp__system_diagnostics__get_system_diagnostics'
ROOT=Path(__file__).resolve().parents[2]
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value
core=load('scope_diagnostics',ROOT/'infra/mcp/system_diagnostics.py')
mcp=load('scope_mcp',ROOT/'infra/mcp/system-diagnostics-mcp.py')
mcp._library=core

def request():
    t=mcp.tools()[0]
    return {'tools':[{'type':'function','function':{'name':NAME,'parameters':t['inputSchema']}}]}

class ExplicitScope(unittest.TestCase):
    def setUp(self):
        start=(datetime.now(w.KST)-timedelta(days=1)).replace(second=0,microsecond=0)
        self.window={'since_kst':start.isoformat(),'until_kst':(start+timedelta(minutes=1,microseconds=-1)).isoformat()}
        self.ctx={'case_id':'a'*32,'operator_reason':'','mode':'verify','purpose':'후속 조사',
                  'evidence_scope':{'incident_windows':[self.window]}}
        self.env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_MANAGEMENT_REVIEW':'1',
                  'CAPSTONE_WEB_IMPACT_REVIEW':'1','CAPSTONE_OPERATOR_REVIEW':'1'}

    def activate(self, reason):
        self.ctx['operator_reason']=reason
        return patch.dict(w.os.environ,{**self.env,'CAPSTONE_REVIEW_CONTEXT_JSON':json.dumps(self.ctx)},clear=True)

    def options(self, reason, receipts=(), req=None):
        with self.activate(reason):return w.operator_diagnostic_options(request() if req is None else req,receipts)

    def test_current_and_exact_incident_read_survive_separate_write_prohibition(self):
        rows=self.options('c:apache 서비스의 현재 상태와 사건 구간 오류도 실제로 조회해서 보고해줘. 쓰기 변경은 하지 마.')
        self.assertEqual(rows,[{'tool':NAME,'arguments':{'target':'c:apache'}},
            {'tool':NAME,'arguments':{'target':'c:apache',**self.window}}])

    def test_other_units_and_scopes_use_catalog_not_example_answer(self):
        units=[k for k,v in core.TARGETS.items() if isinstance(v,str)]
        self.assertGreater(len(units),10)
        for target in units:
            with self.subTest(target=target):
                self.assertEqual(self.options(f'{target} 지금 확인'),[{'tool':NAME,'arguments':{'target':target}}])
                self.assertEqual(self.options(f'{target} 당시 이력 조회'),[{'tool':NAME,'arguments':{'target':target,**self.window}}])

    def test_negative_conflicting_quoted_unknown_and_similar_targets_are_not_bound(self):
        for reason in ('c:apache 조회하지 마','c:apache 보고해. c:apache 제외해',
                       '```c:apache``` 조회','c:apache-unknown 조회','xc:apache 조회',
                       'b:apache 조회','apache 오류 확인','soc:coverage 과거 조회'):
            with self.subTest(reason=reason):self.assertEqual(self.options(reason),[])

    def test_negative_other_clause_does_not_hide_positive_target(self):
        self.assertEqual(self.options('c:apache 조회하지 마; a:vector 현재 조회'),
                         [{'tool':NAME,'arguments':{'target':'a:vector'}}])

    def test_missing_context_capability_and_wrong_mode_fall_back(self):
        for field in tuple(self.env):
            old=self.env.copy();self.env.pop(field)
            self.assertEqual(self.options('c:apache 현재 조회'),[]);self.env=old
        req=request();req['tools'][0]['function']['parameters']['allOf']=[]
        self.assertEqual(self.options('c:apache 현재 조회',req=req),[])
        with patch.dict(w.os.environ,self.env,clear=True):self.assertEqual(w.operator_diagnostic_options(request()),[])

    def test_invalid_or_stale_windows_never_get_silently_repaired(self):
        for window in ({'since_kst':'bad','until_kst':'bad'},dict(self.window,until_kst=self.window['since_kst']),
                       dict(self.window,since_kst='2020-01-01T00:00:00+09:00')):
            self.ctx['evidence_scope']['incident_windows']=[window]
            self.assertEqual(self.options('c:apache 사건 구간 조회'),[])

    def test_only_exact_executed_receipt_completes_scope(self):
        reason='c:apache 현재와 사건 구간 조회';rows=self.options(reason)
        self.assertEqual(self.options(reason,rows),[])
        wrong=copy.deepcopy(rows);wrong[1]['arguments']['until_kst']=self.window['until_kst'].replace('.999999','')
        self.assertEqual(self.options(reason,wrong),[rows[1]])
        wrong=copy.deepcopy(rows);wrong[0]['arguments']['target']='c:sudo-status'
        self.assertEqual(self.options(reason,wrong),[rows[0]])

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
    def test_bundle_pages_without_dropping_later_requirements(self):
        start=datetime.fromisoformat(self.window['since_kst'])
        self.ctx['evidence_scope']['incident_windows']=[{
            'since_kst':(start+timedelta(minutes=i)).isoformat(),
            'until_kst':(start+timedelta(minutes=i+1,microseconds=-1)).isoformat()} for i in range(9)]
        with self.activate('c:apache 현재와 사건 구간 조회'):
            req,first=w.required_read_bundle(request(),[],[],[],[])
            self.assertEqual(len(first),8);self.assertEqual(req['tool_choice'],'required')
            _,second=w.required_read_bundle(request(),[],[],[],[],first)
            self.assertEqual(len(second),2)
            self.assertIsNone(w.required_read_bundle(request(),[],[],[],[],first+second))

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
    def test_transport_flattening_cannot_hide_registered_history_capability(self):
        native=request()['tools'];wire=request()
        wire['tools'][0]['function']['parameters'].pop('allOf')
        with self.activate('c:apache 현재와 사건 구간 조회'):
            _,options=w.required_read_bundle(wire,[],[],[],[],native_catalog=native)
            self.assertEqual(options,self.options('c:apache 현재와 사건 구간 조회'))
            self.assertEqual(len(options),2)
            with self.assertRaisesRegex(RuntimeError,'required_bundle_catalog_invalid'):
                w.required_read_bundle({'tools':[]},[],[],[],[],native_catalog=native)
        h=Harness(native);h.api_kwargs=wire
        def check(h):
            with self.activate('c:apache 현재와 사건 구간 조회'):
                agent=h.AIAgent();agent.tools=copy.deepcopy(wire['tools']);agent._build_api_kwargs()
                self.assertEqual(len(agent._capstone_pending_options[1]),2)
                self.assertEqual(h.wire_calls,[])
        h.run(check,mode='verify')

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
    def test_failed_real_wire_attempt_is_not_retried_or_claimed_healthy(self):
        h=Harness(request()['tools'])
        def check(h):
            with self.activate('c:apache 현재 조회'):
                client=h.ClientSession(content=[type('C',(),{'text':'{"error":"unavailable"}'})()],is_error=True)
                asyncio.run(client.call_tool('get_system_diagnostics',arguments={'target':'c:apache'}))
                self.assertEqual(len(h.wire_calls),1)
                self.assertEqual(h.AIAgent()._build_api_kwargs()['tools'],request()['tools'])
                h.Emitter().emit_result({'final_response':'정상입니다'})
                self.assertNotEqual(h.emissions[-1][0]['final_response'],'정상입니다')
        h.run(check,mode='verify')

@unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
class TypedStatus(unittest.TestCase):
    def test_known_wrong_kind_and_host_excluded_unknowns_and_correct_ids_allowed(self):
        from jsonschema import Draft202012Validator
        refs=[{'target':'a:incident-ip','proposal_id':'a'*32}]
        for name in ('mcp__rule_a__get_operation_status','mcp__rule_a__get_rule_change_status','mcp__rule_b__get_operation_status'):
            key='proposal_id' if name.endswith('change_status') else 'request_id'
            schema={'type':'object','required':[key],'additionalProperties':False,
                    'properties':{key:{'type':'string','pattern':'^[0-9a-f]{32}$'}}}
            before=copy.deepcopy(schema)
            selected=w.known_status_selection_schema(name,schema,refs)
            self.assertEqual(selected['properties'][key]['type'],'string')
            v=Draft202012Validator(selected)
            self.assertFalse(v.is_valid({key:{}}))
            self.assertEqual(v.is_valid({key:'a'*32}),name=='mcp__rule_a__get_operation_status')
            self.assertTrue(v.is_valid({key:'b'*32}));self.assertEqual(schema,before)
        both=refs+[{'target':'b:wazuh-local-rules','proposal_id':'a'*32}]
        schema={'properties':{'proposal_id':{'type':'string'}}}
        self.assertTrue(Draft202012Validator(w.known_status_selection_schema(
            'mcp__rule_b__get_rule_change_status',schema,both)).is_valid({'proposal_id':'a'*32}))

    def test_history_schema_rejects_runtime_but_keeps_current_runtime(self):
        from jsonschema import Draft202012Validator
        v=Draft202012Validator(request()['tools'][0]['function']['parameters'])
        args={'target':'soc:coverage'}
        self.assertTrue(v.is_valid(args))
        args.update(since_kst='2026-11-05T01:00:00+09:00',until_kst='2026-11-05T01:01:00+09:00')
        self.assertFalse(v.is_valid(args))
        args['target']='c:apache';self.assertTrue(v.is_valid(args))
