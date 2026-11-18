"""Ordinary Mattermost Native phases; real contracts and fake transport only."""
import copy
from dataclasses import dataclass
import hashlib
import json
import os
import importlib.util
import sys
import types
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
import alignment as a
from test_completion import Harness, PLUGIN, message

H=a.load_harness()
MOD='mcp__security_events__search_modsecurity_alerts'
SUR='mcp__security_events__search_suricata_alerts'
BLOCK='mcp__resp__list_blocks'
EXTRA='mcp__security_events__search_wazuh_alerts'
WRITE='mcp__rule_write_a__propose_rule_edit'
Q='어제 IDS랑 WAF 경보 조사해줘. 출발지 비교하고 현재 임시차단 목록도 알려줘'
AT='2026-11-18T10:00:00+09:00'


@dataclass
class Request:
    api_kwargs: object
    api_messages: object=None
    _original_api_kwargs: object=None


@dataclass
class ApiVerdict:
    action: str
    response: object


def catalog():
    props={'since_kst':{'type':'string'},'until_kst':{'type':'string'},
           'lookback_minutes':{'type':'integer','minimum':1,'maximum':129600},
           'limit':{'type':'integer','minimum':1,'maximum':100},'source_ip':{'type':'string'}}
    return [{'type':'function','function':{'name':name,'description':name,'parameters':{
        'type':'object','additionalProperties':False,'properties':copy.deepcopy(props) if name!=BLOCK else {}}}}
        for name in (MOD,SUR,BLOCK,EXTRA,WRITE)]


class GatewayEvidence(unittest.TestCase):
    def test_implicit_observation_intent_enters_actual_native_initial_phase(self):
        for question in (
                '어제 WAF와 IDS 사이에 출발지가 겹쳤는지 조사해줘. 지금 임시 IP 차단도 알려줘',
                '어제 WAF와 IDS의 출발지를 비교해줘. 403이면 모두 차단 성공으로 봐도 되는지 판단해줘. 지금 임시 IP 차단도 알려줘.'):
            with self.subTest(question=question):
                request=self.prepare(question=question)
                self.assertIn('response_format',request)
                self.assertEqual(self.h.agent._capstone_gateway_phase['kind'],'initial')
                self.assertEqual(request['response_format']['json_schema']['name'],'soc_gateway_initial')
                result=self.respond(self.initial())
                calls=result.response.choices[0].message.tool_calls
                self.assertEqual({c.function.name for c in calls},{MOD,SUR,BLOCK})
                for c in calls:
                    arguments=json.loads(c.function.arguments)
                    if c.function.name!=BLOCK:
                        self.assertEqual(arguments['since_kst'],'2026-11-17T00:00:00+09:00')
                        self.assertEqual(arguments['until_kst'],'2026-11-17T23:59:59.999999+09:00')

    def setUp(self):
        if importlib.util.find_spec('openai') is None:
            # Mac has no server package installation. Linux runs use the real SDK.
            def tool(**kw):
                return SimpleNamespace(**{**kw,'function':SimpleNamespace(**kw['function'])})
            stub=patch.dict(sys.modules,{'openai':types.ModuleType('openai'),
                'openai.types':types.ModuleType('openai.types'),
                'openai.types.chat':SimpleNamespace(ChatCompletionMessageToolCall=tool)})
            stub.start();self.addCleanup(stub.stop)

    def prepare(self,question=Q,at=AT):
        h=Harness(request=question)
        h.agent.model='soc-qwen36:35b-balanced-q4km-20261108'
        h.agent.provider='custom';h.agent.api_mode='chat_completions'
        h.agent.base_url='http://10.200.10.10:11435/v1'
        h.agent.tools=catalog();h.agent.valid_tool_names={t['function']['name'] for t in h.agent.tools}
        h.agent._capstone_turn_clock=(h.agent._current_turn_id,H.CONTRACT.turn_clock(at))
        h.kw['messages']=[{'role':'system','content':'OLD-CHANNEL-HISTORY'*1000},
                          {'role':'user','content':question}]
        self.h=h;self.question=question;self.outgoing=[]
        self.builder=a.request_wrapper(lambda *args,**kw:Request({'model':h.agent.model,
            'messages':copy.deepcopy(h.kw['messages']),'tools':copy.deepcopy(h.agent.tools)}),PLUGIN,H)
        h.wrapper=a.final_wrapper(h.wrapper,h.original,h.native,h.append,h.reanchor,PLUGIN,H)
        return self.build()

    def build(self):
        self.request=self.builder(self.h.agent,original_user_message=self.question,
            turn_id=self.h.agent._current_turn_id,messages=self.h.kw['messages']).api_kwargs
        return self.request

    def respond(self,value,mutate=None):
        response=SimpleNamespace(choices=[SimpleNamespace(message=message(json.dumps(value,ensure_ascii=False)),
            finish_reason='stop')])
        def transport(agent,**kw):
            self.outgoing.append(copy.deepcopy(kw['api_kwargs']))
            if mutate:mutate(agent)
            return ApiVerdict('fallthrough',response)
        wrapper=a.selection_call_wrapper(transport,PLUGIN,H)
        return wrapper(self.h.agent,api_kwargs=self.request,turn_id=self.h.agent._current_turn_id)

    def initial(self):
        schema=self.request['response_format']['json_schema']['schema']
        return {'request_nonce':schema['properties']['request_nonce']['const'],'calls':[
            {'tool':n,'arguments':{} if n==BLOCK else {
                'since_kst':'2026-11-17T00:00:00+09:00','until_kst':'2026-11-17T23:59:59.999999+09:00','limit':10}}
            for n in (MOD,SUR,BLOCK)]}

    def observations(self,extra=False):
        calls=[]
        for name,source in ((MOD,'modsecurity'),(SUR,'suricata')):
            data={'source':source,'alerts':[{'source_ip':'192.0.2.43','timestamp':'2026-11-17T12:00:00+09:00'}],
                  'returned_count':1,'indexed_window_total_count':None,
                  'requested_since_kst':'2026-11-17T00:00:00+09:00','requested_until_kst':'2026-11-17T23:59:59.999999+09:00'}
            raw=json.dumps(data)
            calls.append({'server':'security-events','name':name.split('__')[-1],
                'arguments':self.initial()['calls'][0]['arguments'],'result':raw,
                'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False})
        raw=json.dumps({'blocks':[]})
        calls.append({'server':'resp','name':'list_blocks','arguments':{},'result':raw,
            'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False})
        if extra:
            raw=json.dumps({'source':'wazuh','alerts':[],'returned_count':0})
            calls.append({'server':'security-events','name':'search_wazuh_alerts',
                'arguments':{'lookback_minutes':30},'result':raw,
                'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False})
        self.h.kw['messages']=self.h.kw['messages'][:2]+H.linked_rows(calls)
        return calls

    def report_phase(self):
        self.prepare();self.respond(self.initial());self.observations();return self.build()

    def report(self):
        schema=self.request['response_format']['json_schema']['schema']
        return {'request_nonce':self.h.agent._capstone_gateway_phase['nonce'],'more_evidence':False,
            'report':{'assessment':'unresolved','status':'needs_review','evidence_indexes':[0,1,2],
                'basis':'WAF와 IDS 반환 표본에 공통 출발지가 있으나 실제 침해 여부와 영향은 미확인입니다.',
                'limitations':['반환 표본만으로 실제 침해 여부를 입증하지 못했습니다.'],
                'next_steps':[],'unverified_blocking_scope':None}}

    def test_ordinary_gateway_first_batch_has_exact_calendar_day_nonce_and_all_members(self):
        source=self.prepare();schema=source['response_format']['json_schema']['schema']
        self.assertEqual(schema['title'],'RequiredReadToolSelection')
        self.assertNotIn('tools',source);self.assertEqual(len(source['messages']),2)
        self.assertNotIn('OLD-CHANNEL-HISTORY',str(source['messages']))
        self.assertIn('SOC_ROLE_CONTRACT_V1',source['messages'][0]['content'])
        self.assertIn('사건 읽기 선택',source['messages'][0]['content'])
        Draft202012Validator(schema).validate(self.initial())
        for change in ('last24','nonce','missing','write'):
            value=self.initial()
            if change=='last24':value['calls'][0]['arguments']={'lookback_minutes':1440,'until_kst':AT}
            if change=='nonce':value['request_nonce']='wrong'
            if change=='missing':value['calls'].pop()
            if change=='write':value['calls'][1]['tool']=WRITE
            self.assertFalse(Draft202012Validator(schema).is_valid(value),change)
        result=self.respond(self.initial())
        self.assertEqual(result.response.choices[0].finish_reason,'tool_calls')
        self.assertEqual(len(result.response.choices[0].message.tool_calls),3)

    def test_report_uses_only_current_native_receipts_and_shared_inference_profile(self):
        source=self.report_phase();phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['kind'],'report');self.assertEqual(source['reasoning_effort'],'none')
        self.assertEqual(source['max_tokens'],H.CONTRACT.OUTPUT_TOKENS)
        self.assertNotIn('OLD-CHANNEL-HISTORY',str(source['messages']))
        context=json.loads(source['messages'][1]['content'])
        self.assertEqual(len(context['untrusted_completed_reads']),3)
        self.assertEqual(context['current_ip_inventory']['returned_ip_count'],0)
        value=self.report();Draft202012Validator(phase['schema']).validate(value)
        result=self.respond(value);text=result.response.choices[0].message.content
        self.assertIn('공통 출발지',text);self.assertNotIn('evidence_indexes',text)
        self.assertTrue(self.h.agent._capstone_alignment_partial)
        final=self.h.call(assistant_message=result.response.choices[0].message)
        self.assertEqual(final.action,'break')
        self.assertEqual(final.final_response.replace('\n\n','\n'),text.replace('\n\n','\n'))
        raw=self.h.agent._capstone_gateway_phase['raw_response']
        self.assertTrue(any(r.get('finish_reason')=='incomplete' and r.get('content')==raw
                            for r in self.h.kw['messages']))

    def test_initial_rejection_continues_with_small_context_and_repeated_plan_stops(self):
        self.prepare();value=self.initial();value['calls'][2]=copy.deepcopy(value['calls'][1])
        result=self.respond(value);self.assertFalse(result.response.choices[0].message.tool_calls)
        first=self.h.call(assistant_message=result.response.choices[0].message)
        self.assertEqual(first.action,'continue');self.assertEqual(first.codex_ack_continuations,1)
        self.build();self.assertEqual(len(self.request['messages']),2)
        self.assertNotIn('OLD-CHANNEL-HISTORY',str(self.request['messages']))
        value=self.initial();value['calls'][2]=copy.deepcopy(value['calls'][1]);result=self.respond(value)
        self.assertTrue(self.h.agent._capstone_gateway_phase['repeat'])
        final=self.h.call(assistant_message=result.response.choices[0].message,codex_ack_continuations=1)
        self.assertEqual(final.action,'break');self.assertTrue(self.h.agent._capstone_alignment_partial)

    def test_inquiry_uses_native_dispatch_and_rejects_entire_protected_batch(self):
        self.report_phase();phase=self.h.agent._capstone_gateway_phase
        value={'request_nonce':phase['nonce'],
            'more_evidence':True,'calls':[{'tool':EXTRA,'arguments':{'lookback_minutes':30}}],'report':None}
        bad=copy.deepcopy(value);bad['calls'].append({'tool':WRITE,'arguments':{}})
        result=self.respond(bad);self.assertFalse(result.response.choices[0].message.tool_calls)
        self.assertEqual(self.h.agent._capstone_gateway_evidence['inquiries'],0)
        self.h.call(assistant_message=result.response.choices[0].message);self.build()
        value['request_nonce']=self.h.agent._capstone_gateway_phase['nonce']
        result=self.respond(value)
        self.assertEqual(result.response.choices[0].message.tool_calls[0].function.name,EXTRA)
        self.assertEqual(self.h.agent._capstone_gateway_evidence['inquiries'],1)

    def test_changed_binding_is_rejected_before_original_transport(self):
        for kind in ('turn','model','clock','schema','messages','calls'):
            with self.subTest(kind=kind):
                self.prepare();value=self.initial()
                if kind=='turn':self.h.agent._current_turn_id='other'
                if kind=='model':self.h.agent.model='unapproved-model'
                if kind=='clock':self.h.agent._capstone_turn_clock=('turn-a',H.CONTRACT.turn_clock('2026-11-19T10:00:00+09:00'))
                if kind=='schema':self.request['response_format']['json_schema']['schema']['additionalProperties']=True
                if kind=='messages':self.request['messages'].append({'role':'user','content':'unbound'})
                if kind=='calls':self.h.agent._capstone_proposal_context[2].append({'result':'changed'})
                with self.assertRaisesRegex(ValueError,'gateway_evidence_lease_changed'):self.respond(value)
                self.assertEqual(self.outgoing,[])

    def test_turn_change_during_transport_is_rejected_after_original_call(self):
        self.prepare();value=self.initial()
        with self.assertRaisesRegex(ValueError,'gateway_evidence_lease_changed'):
            self.respond(value,mutate=lambda agent:setattr(agent,'_current_turn_id','changed'))
        self.assertEqual(len(self.outgoing),1)

    def test_native_redirect_or_interruption_keeps_original_verdict(self):
        for interrupted in (False,True):
            self.prepare();verdict=ApiVerdict('fallthrough' if interrupted else 'redirect',None)
            verdict.interrupted=interrupted
            wrapped=a.selection_call_wrapper(lambda *args,**kw:verdict,PLUGIN,H)
            self.assertIs(wrapped(self.h.agent,api_kwargs=self.request,turn_id=self.h.agent._current_turn_id),verdict)
            self.assertIsNone(self.h.agent._capstone_gateway_phase)

    def test_new_ambiguous_turn_does_not_retain_the_previous_phase(self):
        self.prepare();self.h.agent._current_turn_id='next';self.question='룰 조회해줘'
        self.h.kw['messages']=[{'role':'user','content':self.question}]
        self.build();self.assertIsNone(self.h.agent._capstone_gateway_phase)
        self.assertIn('어느 장비',self.h.agent._capstone_query_completion_local_format[1])

    def test_current_membership_does_not_prove_feature_activation(self):
        self.report_phase();value=self.report()
        value['report']['basis']='현재 IP 차단 기능이 활성화되어 있습니다. WAF와 IDS의 실제 침해 영향은 미확인입니다.'
        result=self.respond(value)
        self.assertTrue(self.h.agent._capstone_gateway_phase['rejected'])
        self.assertFalse(result.response.choices[0].message.tool_calls)
        self.assertIn('block_inventory_does_not_verify_activation',
                      self.h.agent._capstone_gateway_phase['feedback']['issues'])
        next_turn=self.h.call(assistant_message=result.response.choices[0].message)
        self.assertEqual(next_turn.action,'continue');self.build()
        context=json.loads(self.request['messages'][1]['content'])
        self.assertEqual(context['current_ip_inventory']['returned_ip_count'],0)
        self.assertIn('current_inventory_scope_check',context['report_validation'])

    def test_failed_latest_inventory_is_not_a_zero_or_a_complete_report(self):
        self.prepare();self.respond(self.initial());self.observations()
        self.h.kw['messages']+=H.linked_rows([{'server':'resp','name':'list_blocks','arguments':{},
            'result':json.dumps({'error':'fixture_unavailable'}),'result_sha256':'unused'}])
        self.build()
        self.assertIsNone(self.h.agent._capstone_gateway_phase)
        self.assertNotEqual(self.request.get('response_format',{}).get('json_schema',{}).get('name'),'soc_gateway_report')

    def test_model_tool_call_cannot_bypass_the_structured_response(self):
        self.prepare();value=self.initial()
        response=SimpleNamespace(choices=[SimpleNamespace(message=message(json.dumps(value),
            calls=[{'function':{'name':WRITE,'arguments':'{}'}}]),finish_reason='tool_calls')])
        wrapped=a.selection_call_wrapper(lambda *args,**kw:ApiVerdict('fallthrough',response),PLUGIN,H)
        result=wrapped(self.h.agent,api_kwargs=self.request,turn_id=self.h.agent._current_turn_id)
        self.assertFalse(result.response.choices[0].message.tool_calls)
        self.assertEqual(result.response.choices[0].finish_reason,'stop')
        self.assertTrue(self.h.agent._capstone_gateway_phase['rejected'])

    def test_oversized_response_stops_before_repair_or_dispatch(self):
        self.prepare()
        response=SimpleNamespace(choices=[SimpleNamespace(message=message('x'*65537),finish_reason='stop')])
        wrapped=a.selection_call_wrapper(lambda *args,**kw:ApiVerdict('fallthrough',response),PLUGIN,H)
        with self.assertRaisesRegex(ValueError,'gateway_evidence_unusable_response'):
            wrapped(self.h.agent,api_kwargs=self.request,turn_id=self.h.agent._current_turn_id)
        self.assertFalse(self.h.agent._capstone_gateway_evidence['rejections'])

    def test_initial_schema_feedback_does_not_echo_untrusted_argument_values(self):
        self.prepare();value=self.initial()
        value['calls'][0]['arguments']['unknown']='DO_NOT_ECHO_ARGUMENT'
        result=self.respond(value);self.h.call(assistant_message=result.response.choices[0].message)
        self.build();self.assertNotIn('DO_NOT_ECHO_ARGUMENT',str(self.request['messages']))

    def test_native_read_budget_and_inquiry_limit_remain_closed(self):
        self.report_phase();self.h.agent._capstone_read_selection_count=('turn-a',H.CONTRACT.TOOL_CALLS)
        self.build();phase=self.h.agent._capstone_gateway_phase
        self.assertEqual(phase['remaining'],0)
        result=self.respond({'request_nonce':phase['nonce'],'more_evidence':True,
            'calls':[{'tool':EXTRA,'arguments':{'lookback_minutes':30}}],'report':None})
        self.assertFalse(result.response.choices[0].message.tool_calls)
        self.assertEqual(self.h.agent._capstone_gateway_evidence['inquiries'],0)

    def test_clock_handles_year_boundary_and_does_not_reinfer_after_first_reads(self):
        self.prepare(at='2027-01-01T00:00:01+09:00')
        schema=self.h.agent._capstone_gateway_phase['schema']
        value=self.initial()
        for row in value['calls']:
            if row['tool']==BLOCK:continue
            row['arguments'].update(since_kst='2026-12-31T00:00:00+09:00',until_kst='2026-12-31T23:59:59.999999+09:00')
        Draft202012Validator(schema).validate(value)
        self.assertFalse(Draft202012Validator(schema).is_valid(self.initial()))

    def test_selection_skill_is_loaded_only_by_its_phase(self):
        self.prepare()
        self.assertIn('## 사건 읽기 선택',self.request['messages'][0]['content'])
        self.assertNotIn('## 사건 읽기 선택',H.CONTRACT.workflow_policy(('soc-query',)))
        with self.assertRaisesRegex(ValueError,'shared_soc_phase_invalid'):
            H.CONTRACT.system_prompt(read_only=False,agent_role='hermes',phase='read-selection')

    def test_unapproved_or_write_requests_keep_existing_path(self):
        self.prepare()
        for kind in ('model','write','reference','disabled'):
            with self.subTest(kind=kind):
                self.prepare();agent=self.h.agent
                if kind=='model':agent.model='other'
                question='WAF 룰 추가해줘' if kind=='write' else Q
                with patch.dict(os.environ,{'CAPSTONE_GATEWAY_EVIDENCE_COMPACT':'0'} if kind=='disabled' else {}):
                    result=a.gateway_evidence_request(agent,self.request,{'tools':catalog()},question,[],H,
                        agent._capstone_turn_clock,{'card':'fixture'} if kind=='reference' else None)
                self.assertIsNone(result)

    def test_independent_agents_and_new_turn_do_not_share_context_or_environment(self):
        environment=dict(os.environ);self.prepare();agent=self.h.agent;phase=copy.deepcopy(agent._capstone_gateway_phase)
        self.prepare(question='어제 IDS 경보 조사해줘',at='2026-11-19T00:00:01+09:00')
        self.assertNotEqual(phase['schema'],self.h.agent._capstone_gateway_phase['schema'])
        self.assertEqual(agent._capstone_gateway_phase,phase);self.assertEqual(dict(os.environ),environment)
        self.h.agent._current_turn_id='next';self.h.agent._capstone_turn_clock=('next',H.CONTRACT.turn_clock(AT))
        self.build();self.assertEqual(self.h.agent._capstone_gateway_evidence['requests'],1)


if __name__=='__main__':unittest.main()
