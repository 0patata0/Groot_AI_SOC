"""Actual-catalog Native service selection; fake transport, no server access."""
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
import test_gateway_evidence as base

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'infra/ollama-trial').is_dir())
sys.path.append(str(ROOT/'infra/ollama-trial'))
from test_service_identity_scope import NAME, QUESTION, catalog


class ServiceCatalogPhase(unittest.TestCase):
    setUp=base.GatewayEvidence.setUp
    build=base.GatewayEvidence.build
    respond=base.GatewayEvidence.respond

    def prepare(self,question=QUESTION):
        at=datetime.now(base.H.EVIDENCE.KST).isoformat()
        tools=catalog()['tools']
        for tool in tools:tool['type']='function'
        with patch.object(base,'catalog',return_value=tools):
            return base.GatewayEvidence.prepare(self,question=question,at=at)

    def initial(self):
        phase=self.h.agent._capstone_gateway_phase
        return {'request_nonce':phase['nonce'],'indexes':list(range(len(self.options())))}

    def options(self):
        return copy.deepcopy(self.h.agent._capstone_gateway_phase['context']['required_reads'])

    def observations(self,failed=False):
        plan=self.h.agent._capstone_gateway_phase['service_plan'];calls=[]
        at=datetime.now(base.H.EVIDENCE.KST).isoformat()
        for choice in plan['requirements']:
            args=choice['arguments'];target=args['target']
            data={'schema':1,'host':target[0],'target':target,'unit':plan['units'][target],
                'status':'observed','mutation_performed':False,'observed_at_kst':at,'age_seconds':0}
            if args.get('view')=='journal':
                data.update(kind='journal_excerpt',live_query=True,redacted_excerpts_returned=True,
                    raw_messages_returned=False,journal_retention_verified=False,
                    requested_window_total_count=None,has_more=False,response_size_limited=False,
                    journal_scope=args.get('journal_scope','errors'),entries=[],returned_entries=0,
                    requested_since_kst=args['since_kst'],requested_until_kst=args['until_kst'])
                if failed:data={'error':'fixture_transport_failure'}
            else:
                data['properties']={'Type':'oneshot','LoadState':'loaded','ActiveState':'inactive',
                    'SubState':'dead','Result':'success','ExecMainCode':1,'ExecMainStatus':0}
            raw=json.dumps(data)
            calls.append({'server':'system-diagnostics','name':'get_system_diagnostics',
                'arguments':copy.deepcopy(args),'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),
                'is_error':bool(failed and args.get('view')=='journal')})
        self.h.kw['messages']=self.h.kw['messages'][:2]+base.H.linked_rows(calls)
        return calls

    def report(self):
        phase=self.h.agent._capstone_gateway_phase
        if phase['context'].get('lookup_only') is True:
            return {'request_nonce':phase['nonce'],'more_evidence':False,'report':{
                'scope':'verified_service_lookup','assessment':'observed','status':'resolved','evidence_indexes':[0]}}
        return {'request_nonce':phase['nonce'],'more_evidence':False,'report':{
            'assessment':'unresolved','status':'needs_review','evidence_indexes':[0],
            'basis':'조회 구간의 journal 반환 표본은 0행이며 최근 실행의 세부 내용은 미확인입니다.',
            'current_observation':'현재 수집 속성은 Type=oneshot, ActiveState=inactive, Result=success이며 마지막 종료값은 0입니다.',
            'limitations':['반환 표본만으로 과거 실패 원인과 전체 실행 이력을 확인하지 못했습니다.'],
            'next_steps':[]}}

    def test_real_catalog_labels_select_same_bound_plan_across_registered_services(self):
        for question,target in ((QUESTION,'a:certificate-monitor'),
                ('A 서버 저장소 감시 서비스 현재 상태와 마지막 실행 결과 알려줘','a:storage-monitor'),
                ('B 서버 도커 현재 상태와 최근 실행 결과 보여줘','b:docker'),
                ('C 서버 apache2.service 현재 상태와 직전 실행 기록 보여줘','c:apache')):
            with self.subTest(question=question):
                request=self.prepare(question);phase=self.h.agent._capstone_gateway_phase
                self.assertEqual(set(phase['service_plan']['units']),{target})
                self.assertEqual(phase['kind'],'initial')
                self.assertNotIn('OLD-CHANNEL-HISTORY',str(request['messages']))
                Draft202012Validator(phase['schema']).validate(self.initial())
                result=self.respond(self.initial())
                actual=result.response.choices[0].message.tool_calls
                self.assertEqual(len(actual),len(self.options()))
                self.assertEqual([{'tool':c.function.name,'arguments':json.loads(c.function.arguments)} for c in actual],self.options())

    def test_wrong_window_host_view_unasked_agent_and_protected_calls_are_rejected(self):
        self.prepare();schema=self.request['response_format']['json_schema']['schema']
        for mutation in ('lookback','future','host','view','agent','write','missing'):
            value={'request_nonce':self.initial()['request_nonce'],'calls':self.options()}
            if mutation=='lookback':value['calls'][-1]['arguments']={'target':'a:certificate-monitor','lookback_minutes':1440}
            elif mutation=='future':value['calls'][-1]['arguments']['until_kst']='2099-01-01T00:00:00+09:00'
            elif mutation=='host':value['calls'][0]['arguments']['target']='b:management'
            elif mutation=='view':value['calls'][-1]['arguments'].pop('journal_scope')
            elif mutation=='agent':value['calls'][0]={'tool':'mcp__wazuh_ro__get_wazuh_agents','arguments':{}}
            elif mutation=='write':value['calls'][0]={'tool':'mcp__resp__block_ip','arguments':{'ip':'192.0.2.9'}}
            else:value['calls'].pop()
            with self.subTest(mutation=mutation):self.assertFalse(Draft202012Validator(schema).is_valid(value))

    def test_completed_current_read_is_not_offered_again_for_history(self):
        self.prepare();choices=self.options();self.respond(self.initial());self.observations()
        self.h.kw['messages']=self.h.kw['messages'][:-2]
        self.build();remaining=self.options()
        self.assertEqual(remaining,[choices[-1]])
        self.assertEqual(remaining[0]['arguments']['view'],'journal')

    def test_service_report_survives_native_final_without_static_alias_override(self):
        self.prepare();self.respond(self.initial());self.observations();self.build()
        phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['kind'],'service')
        self.assertEqual(len(phase['context']['untrusted_completed_reads']),2)
        Draft202012Validator(phase['schema']).validate(self.report())
        result=self.respond(self.report());text=result.response.choices[0].message.content
        self.assertIn('a:certificate-monitor',text);self.assertIn('journal',text)
        self.assertNotIn('Agent ID',text)
        final=self.h.call(assistant_message=result.response.choices[0].message)
        self.assertEqual(final.action,'break')
        self.assertEqual(final.final_response.replace('\n\n','\n'),text.replace('\n\n','\n'))
        self.assertTrue(any(r.get('content')==phase['raw_response'] for r in self.h.kw['messages']))

    def test_additional_read_stays_native_and_cannot_repeat_completed_query(self):
        self.prepare(QUESTION+' 원인도 확인해줘');completed=self.options();self.respond(self.initial());self.observations();self.build()
        phase=self.h.agent._capstone_gateway_phase
        value={'request_nonce':phase['nonce'],'more_evidence':True,'report':None,'calls':[completed[-1]]}
        result=self.respond(value)
        self.assertFalse(result.response.choices[0].message.tool_calls)
        self.assertTrue(phase['rejected'])

    def test_failed_history_cannot_become_admitted_or_verified_lookup(self):
        self.prepare();self.respond(self.initial());self.observations(failed=True);self.build()
        self.assertIsNone(self.h.agent._capstone_gateway_phase)
        self.assertFalse(getattr(self.h.agent,'_capstone_query_completion_local_format',None))

    def test_required_schema_rejects_invalid_missing_and_duplicate_catalog_options(self):
        self.prepare();options=self.options();schema=catalog()['tools'][0]['function']['parameters']
        for choices,schemas in ((options,{}),([options[0],options[0]],{NAME:schema}),
                ([{'tool':NAME,'arguments':{'target':'unregistered'}}],{NAME:schema})):
            with self.subTest(choices=choices),self.assertRaises(ValueError):
                base.H.CONTRACT.service_required_read_selection(choices,schemas)

    def test_native_wire_projection_retains_actual_registry_conditions_for_service_plan(self):
        raw=catalog();wire=copy.deepcopy(raw);parameters=wire['tools'][0]['function']['parameters']
        for key in ('allOf','anyOf','oneOf','enum','not'):parameters.pop(key,None)
        entry={'name':NAME,'parameters':raw['tools'][0]['function']['parameters']}
        fake=SimpleNamespace(registry=SimpleNamespace(get_schema=lambda name:copy.deepcopy(entry)))
        agent=SimpleNamespace(valid_tool_names={NAME})
        before=copy.deepcopy(wire)
        with patch.dict(sys.modules,{'tools.registry':fake}):
            actual=base.a.registered_service_catalog(agent,wire,base.H)
        self.assertEqual(actual,raw);self.assertEqual(wire,before)
        self.assertIsNotNone(base.H.CONTRACT.service_history_plan(actual,QUESTION,
            datetime.now(base.H.EVIDENCE.KST).isoformat()))

    def test_registry_drift_omitted_tool_and_changed_wire_are_not_restored(self):
        raw=catalog();wire=copy.deepcopy(raw)
        wire['tools'][0]['function']['parameters'].pop('allOf')
        entry={'name':NAME,'parameters':raw['tools'][0]['function']['parameters']}
        fake=SimpleNamespace(registry=SimpleNamespace(get_schema=lambda name:copy.deepcopy(entry)))
        for mode in ('omitted','invalid_name','changed_wire','invalid_registry'):
            current=copy.deepcopy(wire);value=copy.deepcopy(entry)
            if mode=='omitted':current={'tools':[]}
            elif mode=='invalid_name':value['name']='mcp__resp__block_ip'
            elif mode=='changed_wire':current['tools'][0]['function']['parameters']['properties']['lookback_minutes']['maximum']=239
            else:value['parameters']['allOf']=[]
            fake.registry.get_schema=lambda name,value=value:copy.deepcopy(value)
            with self.subTest(mode=mode),patch.dict(sys.modules,{'tools.registry':fake}):
                self.assertEqual(base.a.registered_service_catalog(SimpleNamespace(valid_tool_names={NAME}),current,base.H),current)

    def test_required_index_grammar_rejects_actual_mixed_window_failure_and_missing_choices(self):
        self.prepare();phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(set(phase['schema']['properties']),{'indexes','request_nonce'})
        rejected={'request_nonce':phase['nonce'],'calls':self.options()}
        rejected['calls'][0]=copy.deepcopy(rejected['calls'][-1])
        rejected['calls'][0]['arguments']['lookback_minutes']=15
        self.assertFalse(Draft202012Validator(phase['schema']).is_valid(rejected))
        for indexes in ([0],[0,0],[0,2],['0',1]):
            self.assertFalse(Draft202012Validator(phase['schema']).is_valid({**self.initial(),'indexes':indexes}))

    def test_bad_indexes_use_service_feedback_and_stop_without_dispatch(self):
        self.prepare();result=self.respond({**self.initial(),'indexes':[0,0]})
        self.assertFalse(result.response.choices[0].message.tool_calls)
        phase=self.h.agent._capstone_gateway_phase
        self.assertTrue(phase['rejected']);self.assertIn('schema_validation_errors',phase['feedback'])
        first=self.h.call(assistant_message=result.response.choices[0].message)
        self.assertEqual(first.action,'continue');self.build()
        result=self.respond({**self.initial(),'indexes':[0,0]})
        self.assertTrue(self.h.agent._capstone_gateway_phase['repeat'])
        final=self.h.call(assistant_message=result.response.choices[0].message,codex_ack_continuations=1)
        self.assertEqual(final.action,'break');self.assertTrue(self.h.agent._capstone_alignment_partial)

    def test_actual_native_display_label_enters_factual_lookup_and_keeps_control_record_terminal(self):
        for question in (QUESTION,'A 서버 저장소 감시 서비스의 현재 상태와 마지막 실행 결과를 표로 알려줘.'):
            with self.subTest(question=question):
                self.prepare('[operator.42] '+question);self.respond(self.initial());self.observations();self.build()
                phase=self.h.agent._capstone_gateway_phase
                self.assertTrue(phase['context']['lookup_only'])
                result=self.respond(self.report());text=result.response.choices[0].message.content
                self.assertTrue(text.startswith('기간을 지정하지 않아'))
                self.assertTrue(text.rstrip().endswith('MANAGEMENT_STATUS: resolved'))
                final=self.h.call(assistant_message=result.response.choices[0].message)
                self.assertEqual(final.action,'break')

    def test_current_only_service_keeps_one_actual_read_through_native_final(self):
        for question,target in (
                ('[operator.42] A 서버 저장소 감시 상태 보여줘','a:storage-monitor'),
                ('B 서버 도커 현재 상태 보여줘','b:docker'),
                ('C 서버 apache2.service 상태 확인해줘','c:apache')):
            with self.subTest(question=question):
                self.prepare(question)
                phase=self.h.agent._capstone_gateway_phase
                self.assertTrue(phase['service_plan']['current_only'])
                self.assertEqual(self.options(),[{'tool':NAME,'arguments':{'target':target}}])
                self.respond(self.initial());calls=self.observations();self.build()
                self.assertEqual(len(calls),1)
                phase=self.h.agent._capstone_gateway_phase
                self.assertTrue(phase['context']['lookup_only'])
                self.assertEqual(phase['context']['requested_service_scope']['history_windows'],[])
                result=self.respond(self.report());text=result.response.choices[0].message.content
                self.assertIn(target,text)
                self.assertNotIn('15분 표본',text)
                self.assertNotIn('journal 원문',text)
                final=self.h.call(assistant_message=result.response.choices[0].message)
                self.assertEqual(final.action,'break')
                self.assertIn(target,final.final_response)

    def test_current_only_index_does_not_offer_unrequested_history(self):
        self.prepare('A 서버 인증서 감시 상태 보여줘')
        phase=self.h.agent._capstone_gateway_phase
        self.assertTrue(phase['service_plan']['current_only'])
        self.assertEqual(len(self.options()),1)
        value={'request_nonce':self.initial()['request_nonce'],'indexes':[1]}
        self.assertFalse(Draft202012Validator(phase['schema']).is_valid(value))
        result=self.respond(value)
        self.assertFalse(result.response.choices[0].message.tool_calls)

    def test_current_only_failed_snapshot_is_not_a_completed_lookup(self):
        self.prepare('A 서버 저장소 감시 상태 보여줘');self.respond(self.initial());calls=self.observations()
        calls[0]['result']='{"error":"fixture_unavailable"}'
        calls[0]['result_sha256']=hashlib.sha256(calls[0]['result'].encode()).hexdigest()
        calls[0]['is_error']=True
        self.h.kw['messages']=self.h.kw['messages'][:2]+base.H.linked_rows(calls)
        self.build()
        phase=self.h.agent._capstone_gateway_phase
        self.assertFalse(phase and phase.get('context',{}).get('lookup_only'))

    def test_current_service_ambiguity_asks_once_before_native_model_or_read(self):
        self.prepare('[operator.42] Docker 상태 보여줘')
        self.assertIsNone(self.h.agent._capstone_gateway_phase)
        turn,request,notice=self.h.agent._capstone_scope_clarification
        self.assertEqual(turn,self.h.agent._current_turn_id)
        self.assertIn('어느 대상의 상태',notice)
        self.assertIn('아직 조회하지 않았습니다',notice)
        result=self.h.call()
        self.assertEqual(result.action,'break')
        self.assertEqual(result.final_response,notice)

    def test_current_ambiguity_uses_exact_registry_when_native_strips_conditions(self):
        raw=catalog();wire=copy.deepcopy(raw['tools'])
        for tool in wire:
            tool['type']='function'
            for key in ('allOf','anyOf','oneOf','enum','not'):
                tool['function']['parameters'].pop(key,None)
        entry={'name':NAME,'parameters':raw['tools'][0]['function']['parameters']}
        fake=SimpleNamespace(registry=SimpleNamespace(get_schema=lambda name:copy.deepcopy(entry)))
        with patch.dict(sys.modules,{'tools.registry':fake}),patch.object(base,'catalog',return_value=wire):
            base.GatewayEvidence.prepare(self,question='Docker 상태 보여줘',
                at=datetime.now(base.H.EVIDENCE.KST).isoformat())
        self.assertIsNone(self.h.agent._capstone_gateway_phase)
        self.assertIn('어느 대상의 상태',self.h.agent._capstone_scope_clarification[2])

    def test_catalog_bound_service_receipts_precede_legacy_aliases_only_when_complete(self):
        question='[socadmin] A 서버 저장소 감시 서비스의 현재 상태와 마지막 실행 결과를 표로 알려줘.'
        self.prepare(question);plan=self.h.agent._capstone_gateway_phase['service_plan']
        self.respond(self.initial());calls=self.observations()
        text='현재 a:storage-monitor의 반환 속성은 ActiveState=inactive, SubState=dead입니다.'
        self.assertNotIn('current_state_requires_actual_read',base.H.violations(question,text,calls,service_plan=plan))
        variants=[calls[:-1]]
        for kind in ('hash','target','stale'):
            changed=copy.deepcopy(calls)
            if kind=='hash':changed[0]['result_sha256']='0'*64
            else:
                data=json.loads(changed[0]['result'])
                if kind=='target':data['target']='b:management'
                else:data['observed_at_kst']='2000-01-01T00:00:00+09:00'
                changed[0]['result']=json.dumps(data)
                changed[0]['result_sha256']=hashlib.sha256(changed[0]['result'].encode()).hexdigest()
            variants.append(changed)
        for changed in variants:
            self.assertIn('current_state_requires_actual_read',base.H.violations(question,text,changed,service_plan=plan))
        self.assertIn('current_state_requires_actual_read',base.H.violations(question,text,calls))


if __name__=='__main__':unittest.main()
