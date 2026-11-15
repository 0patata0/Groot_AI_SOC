"""Catalog-bound ambiguity and cause-vs-absence regressions, no real I/O."""
from pathlib import Path
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import patch
import asyncio
import copy
import importlib.util
import json
import os
import sys
import types
import unittest

ROOT=Path(os.environ['SOC_BOUNDARIES_ROOT']).resolve()
sys.path.insert(0,str(ROOT/'infra/mcp'))
sys.path.insert(0,str(ROOT/'infra/ollama-trial'))
sys.path.insert(0,str(ROOT/'infra/hermes/query-completion'))
from test_diagnostic_journal import d,h,j,m,NOW

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

C=load('boundary_scope_contract',ROOT/'infra/hermes/chat_contract.py')
NAME='mcp__system_diagnostics__get_system_diagnostics'
AT=h.shown(NOW*1000000+750000)

def catalog():
    return {'tools':[{'function':{'name':NAME,'parameters':copy.deepcopy(m.tools()[0]['inputSchema'])}}]}

class MetadataTargets(unittest.TestCase):
    def test_shared_aliases_ask_for_real_registered_targets(self):
        for label in ['systemd','Vector','docker.service','capstone-vector.service']:
            with self.subTest(label=label):
                question=label+' 오류 로그 확인해줘'
                selected=C.service_target_selection(catalog(),question)
                expected={'a:vector','b:vector'} if label in ('Vector','capstone-vector.service') else {x+(':systemd' if label=='systemd' else ':docker') for x in 'abc'}
                self.assertEqual(selected['ambiguous'],expected)
                self.assertIsNone(C.service_history_plan(catalog(),question,AT))
                notice=C.service_scope_notice(catalog(),question)
                self.assertIn('아직 조회하지 않았습니다',notice)
                for target in selected['ambiguous']:self.assertIn('`'+target+'`',notice)

    def test_same_resolver_binds_host_name_and_exact_target(self):
        for question,target in [('B systemd 오류 로그 봐줘','b:systemd'),
                ('A 서버 Vector 로그 확인해줘','a:vector'),
                ('C docker.service 로그 보여줘','c:docker'),
                ('b:vector 로그 보여줘','b:vector')]:
            with self.subTest(question=question):
                self.assertIsNone(C.service_scope_notice(catalog(),question))
                plan=C.service_history_plan(catalog(),question,AT)
                self.assertEqual(set(plan['units']),{target})
                self.assertTrue(all(v['arguments']['target']==target for v in plan['requirements']))

    def test_unique_registered_service_does_not_need_an_extra_host_question(self):
        question='soc-bot 로그 보여줘'
        self.assertIsNone(C.service_scope_notice(catalog(),question))
        self.assertEqual(set(C.service_history_plan(catalog(),question,AT)['units']),{'b:soc-bot'})

    def test_generic_or_non_os_logs_do_not_get_silently_reclassified(self):
        for question in ['로그 보여줘','오류 로그 확인해줘','WAF 차단 로그 봐줘','DNS 경보 보여줘','현재 서비스 목록 보여줘']:
            with self.subTest(question=question):self.assertIsNone(C.service_scope_notice(catalog(),question))

    def test_explicit_plural_hosts_are_not_missing_host(self):
        for question in ['전체 서버 systemd 오류 로그 보여줘','모든 호스트 Vector 로그 보여줘',
                '각 서버 docker 로그 보여줘','all hosts systemd error logs','A 서버와 B 서버 systemd 오류 로그 보여줘']:
            with self.subTest(question=question):self.assertIsNone(C.service_scope_notice(catalog(),question))

    def test_quoted_negative_explanation_and_write_requests_do_not_trigger_lookup_question(self):
        for question in ['systemd 로그 사용법 설명만 해줘','```systemd 오류 로그``` 번역해줘',
                'systemd 오류 로그 조회하지 마','B 말고 C systemd 오류 로그 봐줘',
                'Vector 오류 로그 보고 재시작해줘']:
            with self.subTest(question=question):self.assertIsNone(C.service_scope_notice(catalog(),question))

    def test_no_ip_or_unregistered_target_host_inference(self):
        for question in ['192.168.16.230 systemd 오류 로그 보여줘','d:vector 로그 보여줘','없는.service 오류 로그 보여줘','D systemd 오류 로그 보여줘','D 서버 Vector 오류 로그 보여줘']:
            with self.subTest(question=question):
                self.assertIsNone(C.service_scope_notice(catalog(),question))
                self.assertIsNone(C.service_history_plan(catalog(),question,AT))

    def test_schema_must_be_single_complete_and_unmodified(self):
        data=catalog();before=copy.deepcopy(data)
        C.service_scope_notice(data,'systemd 오류 로그 확인해줘')
        self.assertEqual(data,before)
        for bad in [{}, {'tools':[]}, {'tools':data['tools']*2},
                {'tools':[{'function':{'name':NAME,'parameters':{'properties':{'target':{'enum':['b:vector']}}}}}]}]:
            with self.subTest(catalog=bad):self.assertIsNone(C.service_scope_notice(bad,'Vector 오류 로그 확인해줘'))

    def test_current_and_history_capabilities_are_still_separate(self):
        plan=C.service_history_plan(catalog(),'B Vector 로그와 지금 상태 알려줘',AT)
        self.assertEqual({v['arguments'].get('view','current') for v in plan['requirements']},{'current','journal'})
        self.assertIn('b:collection',plan['current_companions'])
        plan=C.service_history_plan(catalog(),'B systemd 지난 24시간 오류 로그만 보여줘',AT)
        self.assertEqual(len(plan['requirements']),1)
        self.assertEqual(plan['requirements'][0]['arguments']['view'],'journal')

class RelativePeriods(unittest.TestCase):
    def test_precise_relative_lookback_is_used_without_rounding(self):
        for phrase,seconds in [('최근 1초',1),('지난 15분',900),('지난 24시간',86400),('최근 1일',86400)]:
            with self.subTest(phrase=phrase):
                plan=C.service_history_plan(catalog(),'B systemd '+phrase+' 오류 로그 보여줘',AT)
                args=plan['requirements'][0]['arguments']
                self.assertEqual(args['until_kst'],AT)
                self.assertEqual((C._diagnostic_instant(args['until_kst'])-C._diagnostic_instant(args['since_kst'])).total_seconds(),seconds)

    def test_outside_budget_or_nonpositive_relative_window_stays_unsupported(self):
        for phrase in ['최근 0초','최근 25시간','지난 2일','최근 86401초','지난 999999시간']:
            with self.subTest(phrase=phrase):self.assertIsNone(C.service_history_plan(catalog(),'B systemd '+phrase+' 오류 로그 보여줘',AT))

    def test_ambiguous_or_compound_period_does_not_fall_back_to_fifteen_minutes(self):
        for phrase in ['지난 24시간은 아니고','최근 5분 또는 지난 1시간','최근 5분부터 지금까지',
                '어제 지난 15분','지난 24시간 중 앞 5분','최근 10분쯤','대략 지난 1시간','최근 24시간 UTC']:
            with self.subTest(phrase=phrase):self.assertIsNone(C.service_history_plan(catalog(),'B systemd '+phrase+' 오류 로그 보여줘',AT))

    def test_relative_period_is_resolved_after_service_names(self):
        plan=C.service_history_plan(catalog(),'B Wazuh 에이전트 지난 15분 오류 로그 보여줘',AT)
        self.assertEqual(set(plan['units']),{'b:wazuh-agent'})


class CauseSubject(unittest.TestCase):
    def issues(self,text):
        return C.snapshot_health_violations(text,[{'kind':'diagnostics','target':'b:systemd','requested_window_total_count':None}])

    def test_unknown_cause_parenthetical_is_not_error_absence(self):
        for text in ['오류 원인(예: 설정 오류, 포트 충돌 등)은 확인되지 않음',
                '오류의 원인(설정 오류 등)은 확인되지 않았습니다.',
                '장애 원인(예: 포트 충돌)은 확인되지 않았습니다.',
                '세부 원인(설정 오류, 권한 문제 등)은 확인되지 않았다.']:
            with self.subTest(text=text):self.assertNotIn('sample_zero_presented_as_absence',self.issues(text))

    def test_real_absence_is_not_excused_by_parentheses_or_a_cause_disclaimer(self):
        for text in ['오류가 확인되지 않았습니다.',
                '오류(에러)가 확인되지 않았습니다.',
                '오류 원인(예: 설정 오류)은 확인되지 않았으며 오류가 발생하지 않았습니다.',
                '오류 원인(오류가 발생하지 않았음)은 확인되지 않았습니다.',
                '오류는 확인되지 않았습니다. 원인(설정 오류)은 미확인입니다.']:
            with self.subTest(text=text):self.assertIn('sample_zero_presented_as_absence',self.issues(text))

class SDKBoundary(unittest.TestCase):
    def test_ambiguous_lookup_closes_sessions_without_model_or_data_call(self):
        import runtime
        calls=[];closed=[];models=[]
        class Connector:
            async def list_tools(self):
                return [SimpleNamespace(name='get_system_diagnostics',description='registered diagnostic read',inputSchema=m.tools()[0]['inputSchema'])]
            async def call_tool(self,*a,**kw):calls.append(a);raise AssertionError('unexpected data call')
        class Client:
            def __init__(self,**kw):pass
            def get_all_active_sessions(self):return {'system-diagnostics':SimpleNamespace(connector=Connector())}
            async def close_all_sessions(self):closed.append(True)
        class Agent:
            def __init__(self,**kw):self.client=kw['client']
            async def initialize(self):await self.adapter.create_all(self.client)
            async def run(self,*a,**kw):models.append(True);raise AssertionError('unexpected inference')
        class Model:
            def __init__(self,**kw):pass
            def with_structured_output(self,*a,**kw):models.append(True);raise AssertionError('unexpected inference')
        class Tool:
            def __init__(self,**kw):self.__dict__.update(kw)
        fake={}
        for name in ['mcp_use','mcp_use.agents','mcp_use.agents.adapters','mcp_use.agents.adapters.langchain_adapter',
                'langchain_ollama','langchain_core','langchain_core.tools','langchain_core.callbacks']:
            fake[name]=types.ModuleType(name)
        fake['mcp_use'].MCPClient=Client;fake['mcp_use'].MCPAgent=Agent
        fake['mcp_use.agents.adapters.langchain_adapter'].LangChainAdapter=object
        fake['langchain_ollama'].ChatOllama=Model;fake['langchain_core.tools'].StructuredTool=Tool
        fake['langchain_core.callbacks'].AsyncCallbackHandler=object
        with patch.dict(sys.modules,fake),patch.object(runtime,'capabilities',return_value={'system-diagnostics':['get_system_diagnostics']}),patch.object(runtime,'filter_catalog',side_effect=lambda *a:a[1]):
            result=asyncio.run(runtime.run({'model':'fixture-model','base_url':'http://127.0.0.1:11434','access_mode':'hermes-parity',
                'mcpServers':{'system-diagnostics':{'command':'unused'}}},{'question':'systemd 오류 로그 확인해줘'}))
        self.assertEqual(result['scope_resolution'],'clarification_required')
        self.assertEqual(result['status'],'partial');self.assertEqual(result['calls'],[]);self.assertEqual(result['model_calls'],[])
        self.assertFalse(calls or models);self.assertEqual(closed,[True]);self.assertNotIn('_service_catalog',result)
        self.assertEqual(result['protected_calls'],0);self.assertEqual(result['chat_posts'],0)

class NativeBoundary(unittest.TestCase):
    def test_registered_ambiguity_is_bound_to_turn_and_current_request(self):
        import alignment
        import test_completion as native_fixture
        harness=alignment.load_harness()
        @dataclass
        class Request:
            api_kwargs: object
        agent=SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',max_iterations=12,_current_turn_id='scope-turn')
        question='systemd 오류 로그 확인해줘';rows=[{'role':'user','content':question}]
        request=Request(dict(catalog(),messages=rows))
        alignment.request_wrapper(lambda *a,**kw:request,native_fixture.PLUGIN,harness)(agent,
            original_user_message=question,turn_id='scope-turn',messages=rows)
        self.assertEqual(agent._capstone_scope_clarification[:2],('scope-turn',question))
        self.assertIn('b:systemd',agent._capstone_query_completion_local_format[1])
        self.assertIsNone(agent._capstone_read_selection)

if __name__=='__main__':unittest.main()
