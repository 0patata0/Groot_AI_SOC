"""Real runtime with deterministic SDK boundaries; no network or service writes."""
import asyncio
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import runtime

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
ROOT=Path(__file__).resolve().parents[2]
core=load('sdk_service_core',ROOT/'infra/mcp/system_diagnostics.py')
mcp=load('sdk_service_mcp',ROOT/'infra/mcp/system-diagnostics-mcp.py');mcp._library=core

@unittest.skipUnless(importlib.util.find_spec('jsonschema'),'existing server jsonschema required')
class ServiceRuntime(unittest.TestCase):
    def run_case(self,selection=None,failed=False,compact_report=None,enabled=True,inquiry_plan=None):
        order=[];prompts=[];calls=[]
        class Connector:
            async def list_tools(self):return [types.SimpleNamespace(**mcp.tools()[0])]
            async def call_tool(self,name,arguments,**kw):
                order.append('read');calls.append(arguments)
                from datetime import datetime,timedelta,timezone
                data={'schema':1,'target':'b:management','host':'b','unit':'capstone-management.service',
                      'mutation_performed':False,'observed_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat()}
                past='since_kst' in arguments
                if past:data.update(kind='journal_history',history_coverage={'status':'partial_or_unavailable'},has_more=False,
                    requested_since_kst=arguments['since_kst'],requested_until_kst=arguments['until_kst'],recent_errors=[])
                elif arguments['target']=='b:management-pipeline':
                    data.update(target='b:management-pipeline',kind='runtime',status='degraded',metrics={'review_required_cases':2},codes=['case_review_required'],lookback_scope='latest_snapshot_only_not_requested_history');data.pop('unit')
                else:data.update(status='observed',properties={'ActiveState':'active','Result':'success'})
                if past and failed:data={'error':'history unavailable'}
                return types.SimpleNamespace(isError=bool(past and failed),content=[types.SimpleNamespace(type='text',text=json.dumps(data))])
        class Client:
            def __init__(self,**kw):pass
            def get_all_active_sessions(self):return {'system-diagnostics':types.SimpleNamespace(connector=Connector())}
            async def close_all_sessions(self):pass
        class Tool:
            def __init__(self,**kw):self.__dict__.update(kw)
            async def ainvoke(self,args):return await self.coroutine(**args)
        def self_report():
            return {'more_evidence':False,'report':{'assessment':'unresolved',
                'basis':'현재 서비스 관측과 과거 오류 메타데이터를 구분했으며 배경 원인은 미확인입니다.',
                'evidence_indexes':[0],'limitations':['과거 오류는 부분 표본입니다.'],
                'next_steps':[],'status':'needs_review'}}
        class LLM:
            def __init__(self,**kw):pass
            def with_structured_output(self,*args,**kw):
                async def select(messages):
                    if 'anyOf' in args[0]:
                        order.append('compact');prompts.append(messages)
                        return copy.deepcopy((compact_report[min(order.count('compact')-1,len(compact_report)-1)] if isinstance(compact_report,list) else compact_report) or self_report())
                    if 'request_nonce' in args[0].get('properties',{}):
                        order.append('inquiry');prompts.append(messages)
                        value=copy.deepcopy(inquiry_plan if inquiry_plan is not None else {'calls':[{
                            'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':{'target':'b:management','limit':50}}],'report':None})
                        value.setdefault('request_nonce',args[0]['properties']['request_nonce']['const'])
                        return value
                    order.append('select')
                    return {'indexes':[0,1,2]} if selection is None else selection
                return types.SimpleNamespace(ainvoke=select)
        class Agent:
            def __init__(self,client,**kw):self.client=client
            async def initialize(self):await self.adapter.create_all(self.client)
            async def run(self,prompt):
                order.append('assess');prompts.append(prompt)
                return '과거 오류 원인은 반환된 제한된 메타데이터만으로 확정할 수 없습니다. 현재 상태와 사건 당시 상태는 구분해야 합니다.'
        definitions={'mcp_use':{'MCPClient':Client,'MCPAgent':Agent},
            'mcp_use.agents.adapters.langchain_adapter':{'LangChainAdapter':object},
            'langchain_ollama':{'ChatOllama':LLM},'langchain_core.tools':{'StructuredTool':Tool},
            'langchain_core.callbacks':{'AsyncCallbackHandler':object}}
        modules={}
        for name,values in definitions.items():
            m=types.ModuleType(name);m.__dict__.update(values);modules[name]=m
        with patch.dict(runtime.os.environ,{'CAPSTONE_SERVICE_REPORT_COMPACT':'1' if enabled else '0'}),patch.dict(sys.modules,modules),patch.object(runtime,'capabilities',return_value={'system-diagnostics':['get_system_diagnostics']}),patch.object(runtime,'filter_catalog',side_effect=lambda server,tools,mode:tools):
            result=asyncio.run(runtime.run({'model':'qwen3.6:35b','base_url':'http://fixture.invalid','access_mode':'hermes-parity',
                'mcpServers':{'system-diagnostics':{}}},{'question':'오늘 B 서버 capstone-management.service 실패 원인과 지금 상태 확인해줘. 설정은 바꾸지 마.'}))
        return result,order,prompts,calls

    def test_model_selects_both_reads_before_judgment_with_real_evidence(self):
        result,order,prompts,calls=self.run_case()
        self.assertNotEqual(result['status'],'failed',result)
        self.assertEqual(order[:5],['select','read','read','read','compact'])
        self.assertEqual(len(calls),3)
        self.assertNotIn('since_kst',calls[0]);self.assertIn('since_kst',calls[1])
        self.assertIn('journal_history',json.dumps(prompts[0]));self.assertIn('ActiveState',json.dumps(prompts[0]));self.assertNotIn('assess',order)
        self.assertNotIn('unqueried',result);self.assertEqual(result['protected_calls'],0)
        receipts=runtime.harness.service_history_receipts(result['calls']);self.assertEqual(len(receipts),3)
        tampered=[dict(c,result_sha256='0'*64) for c in result['calls']]
        self.assertEqual(runtime.harness.service_history_receipts(tampered),[])

    def test_compact_model_report_keeps_real_reads_and_avoids_agent_replay(self):
        value={'more_evidence':False,'report':{'assessment':'unresolved',
            'basis':'현재 상태와 과거 오류 메타데이터를 각각 확인했으며 상세 실패 원인은 미확인입니다.',
            'evidence_indexes':[0],'limitations':['과거 기록은 부분 표본입니다.'],
            'next_steps':[{'kind':'capability_gap','needed_evidence':'해당 시각의 잠금 소유자와 실행 이력'}],'status':'needs_review'}}
        result,order,prompts,calls=self.run_case(compact_report=value)
        self.assertNotEqual(result['status'],'failed',result)
        self.assertEqual(len(calls),3);self.assertEqual(result['protected_calls'],0)
        self.assertEqual(result['service_compact_report'],{'more_evidence':False})
        self.assertNotIn('assess',order)
        body=json.loads(prompts[0][1]['content'])
        self.assertEqual(body['background'],'')
        self.assertEqual(len(body['untrusted_completed_reads']),3)
        self.assertIn('등록 target 스키마',body['available_read_descriptions']['mcp__system_diagnostics__get_system_diagnostics'])
        self.assertIn('b:management',body['available_read_descriptions']['mcp__system_diagnostics__get_system_diagnostics'])

    def test_literal_claim_repair_keeps_compact_context_and_actual_receipts(self):
        good={'more_evidence':False,'report':{'assessment':'unresolved',
            'basis':'과거 실패 원인은 현재 조회 범위만으로 확정할 수 없어 미확인으로 구분합니다.',
            'evidence_indexes':[0],'limitations':['과거 오류는 부분 표본입니다.'],
            'next_steps':[{'kind':'capability_gap','needed_evidence':'해당 시각의 잠금 소유자와 실행 이력'}],'status':'needs_review'}}
        bad=copy.deepcopy(good);bad['report']['basis']='현재 b:management 서비스는 완전히 정상이며 모든 기능이 정상으로 복구되었습니다.'
        result,order,prompts,calls=self.run_case(compact_report=[bad,good])
        self.assertNotEqual(result['status'],'failed',result)
        self.assertEqual(len(calls),3);self.assertNotIn('assess',order)
        self.assertEqual(order.count('compact'),2)
        body=json.loads(prompts[1][1]['content'])
        self.assertIn('diagnostic_snapshot_is_not_functional_health',body['report_validation_issues'])
        self.assertEqual(len(body['untrusted_completed_reads']),3)
        self.assertEqual(result['service_compact_reports'],[{'more_evidence':False,'repair':False},{'more_evidence':False,'repair':True}])
        saved=result['service_report_audit']
        self.assertEqual(saved[0]['response'],bad)
        self.assertEqual(saved[1]['response'],good)
        self.assertFalse(saved[0]['repair']);self.assertTrue(saved[1]['repair'])
        self.assertEqual(saved[0]['read_result_sha256'],[c['result_sha256'] for c in result['calls']])
        self.assertNotIn(bad['report']['basis'],result['final_response'])
        self.assertNotIn(bad['report']['basis'],str(prompts[1]))

    def test_more_evidence_dispatches_selected_read_then_returns_to_structured_report(self):
        more={'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        good={'more_evidence':False,'report':{'assessment':'unresolved',
            'basis':'현재 관측과 추가 반환 표본은 확인했지만 과거의 배경 원인은 미확인입니다.',
            'evidence_indexes':[0],'limitations':['반환 기록은 전체 기능 검증이 아닙니다.'],
            'next_steps':[],'status':'needs_review'}}
        result,order,prompts,calls=self.run_case(compact_report=[more,good])
        self.assertNotIn('assess',order);self.assertEqual(order.count('inquiry'),1)
        self.assertEqual(len(calls),4);self.assertEqual(calls[-1],{'target':'b:management','limit':50})
        self.assertEqual(result['service_inquiry_count'],1);self.assertEqual(result['protected_calls'],0)
        self.assertEqual(len(json.loads(prompts[-1][1]['content'])['untrusted_completed_reads']),4)
        audit=result['service_report_audit'];self.assertEqual(audit[1]['phase'],'inquiry')
        self.assertEqual(len(audit[1]['read_result_sha256']),3)
        self.assertEqual(len(audit[2]['read_result_sha256']),4)
        self.assertEqual(audit[2]['response'],good)

    def test_invalid_additional_read_is_audited_and_never_dispatched(self):
        more={'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        for bad in (
            {'calls':[{'tool':'mcp__resp__block_ip','arguments':{'ip':'192.0.2.5'}}],'report':None},
            {'calls':[{'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':{'target':'b:management','raw_messages_returned':True}}],'report':None},
            {'calls':[{'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':{'target':'b:management'}}],'report':None,'request_nonce':'old'},
        ):
            with self.subTest(bad=bad):
                result,order,prompts,calls=self.run_case(compact_report=more,inquiry_plan=bad)
                self.assertEqual(len(calls),3);self.assertEqual(result['protected_calls'],0)
                self.assertNotEqual(result['status'],'completed');self.assertNotIn('assess',order)
                self.assertEqual(result['service_report_audit'][-1]['phase'],'inquiry')

    def test_unavailable_read_name_is_rejected_before_selector(self):
        result,order,prompts,calls=self.run_case(compact_report={
            'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__journalctl']})
        self.assertEqual(len(calls),3);self.assertNotIn('inquiry',order)
        self.assertNotEqual(result['status'],'completed');self.assertEqual(result['protected_calls'],0)

    def test_repeated_successful_read_rejects_whole_batch_and_allows_grounded_report(self):
        more={'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        good={'more_evidence':False,'report':{'assessment':'unresolved',
            'basis':'현재 상태와 과거 오류 표본은 확인했으나 원문 기록은 제공되지 않아 배경 원인은 미확인입니다.',
            'evidence_indexes':[0],'limitations':['원문 기록은 현재 도구에서 반환되지 않습니다.'],
            'next_steps':[{'kind':'capability_gap','needed_evidence':'지정 구간의 원문 오류 기록'}],'status':'needs_review'}}
        plan={'calls':[{'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':{'target':'b:management','limit':50}},
                       {'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':{'target':'b:management-pipeline'}}],'report':None}
        result,order,prompts,calls=self.run_case(compact_report=[more,good],inquiry_plan=plan)
        self.assertEqual(len(calls),3);self.assertNotIn('assess',order)
        self.assertEqual(result['protected_calls'],0);self.assertNotIn('service_inquiry_count',result)
        self.assertFalse(result['service_inquiry_rejections'][0]['dispatched'])
        body=json.loads(prompts[-1][1]['content'])
        self.assertEqual(body['execution_rejections'][0]['code'],'already_completed_read')
        self.assertEqual(len(body['untrusted_completed_reads']),3)
        self.assertIn('원문',result['final_response'])

    def test_repeated_rejected_plan_stops_without_claiming_investigation_success(self):
        more={'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        plan={'calls':[{'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':{'target':'b:management-pipeline'}}],'report':None}
        result,order,prompts,calls=self.run_case(compact_report=more,inquiry_plan=plan)
        self.assertEqual(len(calls),3);self.assertNotIn('assess',order)
        self.assertEqual(order.count('inquiry'),2)
        self.assertEqual(result['stop_reason'],'repeated_service_inquiry_without_new_evidence')
        self.assertEqual(result['status'],'partial');self.assertEqual(result['protected_calls'],0)

    def test_compact_candidate_can_be_disabled_for_recovery(self):
        result,order,prompts,calls=self.run_case(enabled=False)
        self.assertNotEqual(result['status'],'failed',result)
        self.assertNotIn('compact',order);self.assertIn('assess',order)
        self.assertEqual(len(calls),3)

    def test_invalid_followup_is_audited_without_dispatch_or_completed_answer(self):
        bad={'more_evidence':False,'report':{'assessment':'unresolved',
            'basis':'현재 관측과 과거 오류를 구분했으나 상세 원인은 미확인입니다.',
            'evidence_indexes':[0],'limitations':['당시 잠금 소유자는 미확인입니다.'],
            'next_steps':[{'kind':'read_proposal','tool':'mcp__system_diagnostics__get_system_diagnostics',
                'arguments':{'target':'b:management','raw_messages_returned':True}}],'status':'needs_review'}}
        result,order,prompts,calls=self.run_case(compact_report=bad)
        self.assertNotEqual(result['status'],'completed');self.assertEqual(result['protected_calls'],0)
        self.assertEqual(len(calls),3);self.assertNotIn('assess',order)
        self.assertEqual(result['service_report_audit'][0]['response'],bad)
        self.assertNotIn('raw_messages_returned',result.get('final_response',''))

    def test_valid_followup_is_a_proposal_and_not_an_extra_mcp_call(self):
        value={'more_evidence':False,'report':{'assessment':'unresolved',
            'basis':'현재 관측과 과거 오류를 구분했으나 상세 원인은 미확인입니다.',
            'evidence_indexes':[0],'limitations':['당시 잠금 소유자는 미확인입니다.'],
            'next_steps':[{'kind':'read_proposal','tool':'mcp__system_diagnostics__get_system_diagnostics',
                'arguments':{'target':'b:management','limit':50}}],'status':'needs_review'}}
        result,order,prompts,calls=self.run_case(compact_report=value)
        self.assertEqual(len(calls),3);self.assertEqual(result['protected_calls'],0)
        self.assertIn('미실행·미예약',result['final_response'])
        self.assertNotIn('assess',order)

    def test_invalid_or_incomplete_selection_dispatches_nothing(self):
        for plan in ({'indexes':[0]},{'indexes':[0,0]},{'indexes':[0,2]},{'indexes':[True,1]}):
            with self.subTest(plan=plan):
                result,order,prompts,calls=self.run_case(selection=plan)
                self.assertEqual(result['status'],'failed');self.assertEqual(calls,[]);self.assertEqual(prompts,[])

    def test_failed_history_is_partial_and_not_silently_complete(self):
        result,order,prompts,calls=self.run_case(failed=True)
        self.assertEqual(result['status'],'partial',result)
        self.assertTrue(result.get('unqueried') or result.get('remaining_issues'))
        self.assertEqual(sum('since_kst' in c for c in calls),1)

if __name__=='__main__':unittest.main()
