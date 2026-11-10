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
    def run_case(self,selection=None,failed=False,compact_report=None,enabled=True,inquiry_plan=None,question=None,blocks=False,failed_blocks=False,selection_prompts=None,agent_response=None,extra_read=False,stale_first=False,stale_always=False,failed_extra=False,direct=False):
        order=[];prompts=[];calls=[]
        class Connector:
            async def list_tools(self):return [types.SimpleNamespace(**mcp.tools()[0])]
            async def call_tool(self,name,arguments,**kw):
                order.append('read');calls.append(arguments)
                from datetime import datetime,timedelta,timezone
                target=arguments['target'];host=target.split(':')[0]
                unit=core.TARGETS.get(target)
                data={'schema':1,'target':target,'host':host,'unit':unit,
                      'mutation_performed':False,'observed_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat()}
                past='since_kst' in arguments
                if past:data.update(kind='journal_history',history_coverage={'status':'partial_or_unavailable'},has_more=False,
                    requested_since_kst=arguments['since_kst'],requested_until_kst=arguments['until_kst'],recent_errors=[])
                elif arguments['target']=='b:management-pipeline':
                    data.update(target='b:management-pipeline',kind='runtime',status='degraded',metrics={'review_required_cases':2},codes=['case_review_required'],lookback_scope='latest_snapshot_only_not_requested_history');data.pop('unit')
                elif target in ('a:collection','b:collection'):
                    data.update(kind='runtime',status='ok',codes=[],lookback_scope='latest_snapshot_only_not_requested_history',
                        metrics={'agent_connected':True,'msg_buffer':0,'vector_error_series_nonzero':0})
                    data.pop('unit')
                else:data.update(status='observed',properties={'ActiveState':'active','Result':'success'})
                if arguments.get('view')=='journal':
                    at=datetime.fromisoformat(arguments['since_kst'])+timedelta(microseconds=1)
                    row={'_SYSTEMD_UNIT':unit,'__REALTIME_TIMESTAMP':str(int(at.timestamp()*1000000)),
                         '__CURSOR':'fixture1','PRIORITY':'6','MESSAGE':'{"status":"failed","error":"controller_already_running"}'}
                    history=load('sdk_journal_fixture_history',ROOT/'infra/mcp/diagnostic_history.py');history.core=core
                    journal=load('sdk_journal_fixture_excerpt',ROOT/'infra/mcp/diagnostic_journal.py');journal.core=core
                    with patch.object(core,'_history',history):
                        data=journal.answer(arguments,host,now=int(datetime.now(timezone.utc).timestamp())+1,
                            runner=lambda *args:(0,json.dumps(row).encode()+b'\n'))
                if past and failed:data={'error':'history unavailable'}
                if not past and (stale_always or stale_first and sum(a.get('target')==target and 'since_kst' not in a for a in calls)==1):
                    data['observed_at_kst']=(datetime.now(timezone(timedelta(hours=9)))-timedelta(seconds=181)).isoformat()
                return types.SimpleNamespace(isError=bool(past and failed),content=[types.SimpleNamespace(type='text',text=json.dumps(data))])
        class Client:
            def __init__(self,**kw):pass
            def get_all_active_sessions(self):
                sessions={'system-diagnostics':types.SimpleNamespace(connector=Connector())}
                if blocks:sessions['resp']=types.SimpleNamespace(connector=BlockConnector())
                if extra_read:sessions['rule-b']=types.SimpleNamespace(connector=ExtraConnector())
                return sessions
            async def close_all_sessions(self):pass
        class BlockConnector:
            async def list_tools(self):return [types.SimpleNamespace(name='list_blocks',description='현재 동적 차단 목록',inputSchema={'type':'object','properties':{}})]
            async def call_tool(self,name,arguments,**kw):
                order.append('block_read');calls.append(arguments)
                return types.SimpleNamespace(isError=failed_blocks,content=[types.SimpleNamespace(type='text',text=json.dumps({'error':'unavailable'} if failed_blocks else {'blocks':['192.0.2.7']}))])
        class ExtraConnector:
            async def list_tools(self):return [types.SimpleNamespace(name='get_service_action_target',description='등록 서비스 설정 조회',inputSchema={
                'type':'object','additionalProperties':False,'required':['target'],'properties':{'target':{'enum':['b:management']}}})]
            async def call_tool(self,name,arguments,**kw):
                order.append('extra_read');calls.append(arguments)
                return types.SimpleNamespace(isError=failed_extra,content=[types.SimpleNamespace(type='text',text=json.dumps(
                    {'error':'fixture_unavailable'} if failed_extra else {
                    'target':'b:management','fixture_marker':'additional_actual_service_receipt'}))])
        class Tool:
            def __init__(self,**kw):self.__dict__.update(kw)
            async def ainvoke(self,args):return await self.coroutine(**args)
        def self_report():
            return {'more_evidence':False,'report':{'assessment':'unresolved',
                'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
                'basis':'현재 서비스 관측과 과거 오류 메타데이터를 구분했으며 배경 원인은 미확인입니다.',
                'evidence_indexes':list(range(2 if blocks else 1)),'limitations':['과거 오류는 부분 표본입니다.'],
                'next_steps':[],'status':'needs_review'}}
        class LLM:
            def __init__(self,**kw):pass
            def with_structured_output(self,*args,**kw):
                async def select(messages):
                    if args[0].get('properties',{}).get('report',{}).get('properties',{}).get('scope',{}).get('const')=='verified_service_lookup':
                        order.append('compact');prompts.append(messages)
                        return {'more_evidence':False,'report':{k:v['const'] for k,v in args[0]['properties']['report']['properties'].items()}}
                    if 'anyOf' in args[0]:
                        order.append('compact');prompts.append(messages)
                        return copy.deepcopy((compact_report[min(order.count('compact')-1,len(compact_report)-1)] if isinstance(compact_report,list) else compact_report) or self_report())
                    if 'request_nonce' in args[0].get('properties',{}):
                        order.append('inquiry');prompts.append(messages)
                        value=copy.deepcopy((inquiry_plan[min(order.count('inquiry')-1,len(inquiry_plan)-1)]
                            if isinstance(inquiry_plan,list) else inquiry_plan) if inquiry_plan is not None else {'calls':[{
                            'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':{'target':'b:management','limit':50}}],'report':None})
                        value.setdefault('request_nonce',args[0]['properties']['request_nonce']['const'])
                        return value
                    order.append('select')
                    if selection_prompts is not None:selection_prompts.append(copy.deepcopy(messages))
                    body=json.loads(messages[1][1])
                    if body.get('selection_reason')=='expired_current_refresh' and selection is None:
                        return {'indexes':list(range(len(body['options'])))}
                    if isinstance(selection,list):return copy.deepcopy(selection[min(order.count('select')-1,len(selection)-1)])
                    return {'indexes':[0,1,2]} if selection is None else selection
                return types.SimpleNamespace(ainvoke=select)
        class Agent:
            def __init__(self,client,**kw):self.client=client
            async def initialize(self):await self.adapter.create_all(self.client)
            async def run(self,prompt):
                order.append('assess');prompts.append(prompt)
                if agent_response is not None:return agent_response
                return '과거 오류 원인은 반환된 제한된 메타데이터만으로 확정할 수 없습니다. 현재 상태와 사건 당시 상태는 구분해야 합니다.'
        definitions={'mcp_use':{'MCPClient':Client,'MCPAgent':Agent},
            'mcp_use.agents.adapters.langchain_adapter':{'LangChainAdapter':object},
            'langchain_ollama':{'ChatOllama':LLM},'langchain_core.tools':{'StructuredTool':Tool},
            'langchain_core.callbacks':{'AsyncCallbackHandler':object}}
        modules={}
        for name,values in definitions.items():
            m=types.ModuleType(name);m.__dict__.update(values);modules[name]=m
        with patch.dict(runtime.os.environ,{'CAPSTONE_SERVICE_REPORT_COMPACT':'1' if enabled else '0','CAPSTONE_SERVICE_DIRECT_READS':'1' if direct else '0'}),patch.dict(sys.modules,modules),patch.object(runtime,'capabilities',return_value={'system-diagnostics':['get_system_diagnostics'],'resp':['list_blocks'],'rule-b':['get_service_action_target']}),patch.object(runtime,'filter_catalog',side_effect=lambda server,tools,mode:tools):
            result=asyncio.run(runtime.run({'model':'qwen3.6:35b','base_url':'http://fixture.invalid','access_mode':'hermes-parity',
                'mcpServers':{'system-diagnostics':{},**({'resp':{}} if blocks else {}),**({'rule-b':{}} if extra_read else {})}},
                {'question':question or '오늘 B 서버 capstone-management.service 실패 원인과 지금 상태 확인해줘. 설정은 바꾸지 마.'}))
        return result,order,prompts,calls

    def test_direct_plan_executes_identical_read_with_one_less_model_phase(self):
        tool='mcp__rule_b__get_service_action_target';call={'tool':tool,'arguments':{'target':'b:management'}}
        done={'more_evidence':False,'report':{'assessment':'unresolved','status':'needs_review',
            'basis':'등록 서비스 설정과 오류 이력을 대조했으며 배경 원인은 미확인입니다.',
            'current_observation':'현재 검토 상태는 2건으로 관측했으며 전송 영향은 미확인입니다.',
            'evidence_indexes':[0,1],'limitations':['원인 배경은 확인하지 못했습니다.'],'next_steps':[]}}
        before=self.run_case(extra_read=True,compact_report=[{'more_evidence':True,'read_tools':[tool],'report':None},done],
            inquiry_plan={'calls':[call],'report':None})
        after=self.run_case(extra_read=True,direct=True,compact_report=[{'more_evidence':True,'calls':[call],'report':None},done])
        r,order,prompts,calls=after
        self.assertEqual(calls[-1],before[3][-1]);self.assertEqual(len(calls),len(before[3]))
        self.assertEqual(order.count('compact'),2);self.assertNotIn('inquiry',order)
        self.assertEqual(before[1].count('inquiry'),1);self.assertEqual(r['service_direct_read_plans'],1)
        self.assertNotIn('error_type',r);self.assertEqual(r['protected_calls'],0)
        self.assertEqual(r['service_judgment'],before[0]['service_judgment'])

    def test_direct_invalid_time_can_be_corrected_without_dispatching_bad_batch(self):
        tool='mcp__system_diagnostics__get_system_diagnostics'
        args={'target':'b:management','view':'journal','journal_scope':'all',
              'since_kst':'2026-11-06T16:40:00+09:00','until_kst':'2026-11-06T16:20:00+09:00'}
        fixed=dict(args,since_kst='2026-11-06T16:19:00+09:00')
        plans=[{'more_evidence':True,'calls':[{'tool':tool,'arguments':v}],'report':None} for v in (args,fixed)]
        r,order,prompts,calls=self.run_case(direct=True,compact_report=plans+[None])
        self.assertNotIn('error_type',r);self.assertNotIn('inquiry',order)
        self.assertEqual(len(calls),4);self.assertNotIn(args,calls);self.assertEqual(calls[-1],fixed)
        self.assertEqual(r['service_inquiry_rejections'][0]['code'],'invalid_read_time')
        self.assertEqual(r['protected_calls'],0)

    def test_direct_plan_rejects_protected_tools_without_dispatch(self):
        r,order,prompts,calls=self.run_case(direct=True,compact_report={'more_evidence':True,
            'calls':[{'tool':'mcp__resp__block_ip','arguments':{'ip':'192.0.2.7'}}],'report':None})
        self.assertEqual(r['error_type'],'ValidationError');self.assertEqual(len(calls),3)
        self.assertEqual(r['protected_calls'],0);self.assertNotIn('inquiry',order)

    def test_failed_extra_read_keeps_successful_evidence_and_explicit_failure(self):
        tool='mcp__rule_b__get_service_action_target'
        done={'more_evidence':False,'report':{'assessment':'unresolved','status':'needs_review',
            'basis':'과거 오류 표본을 확인했지만 추가 설정 조회가 실패하여 상세 원인은 미확인입니다.',
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
            'evidence_indexes':[0],'limitations':['추가 설정 조회는 실패했습니다.'],'next_steps':[]}}
        result,order,prompts,calls=self.run_case(extra_read=True,failed_extra=True,
            compact_report=[{'more_evidence':True,'read_tools':[tool],'report':None},done],
            inquiry_plan={'calls':[{'tool':tool,'arguments':{'target':'b:management'}}],'report':None})
        self.assertNotIn('error_type',result);self.assertNotIn('assess',order)
        self.assertEqual(order.count('extra_read'),1);self.assertEqual(len(calls),4)
        body=json.loads(prompts[-1][1]['content'])
        self.assertEqual(len(body['untrusted_completed_reads']),3)
        self.assertEqual(body['untrusted_failed_read_attempts'][0]['data'],{'error':'fixture_unavailable'})
        self.assertEqual(list(body['current_successful_tools'].values()),['mcp__system_diagnostics__get_system_diagnostics'])
        self.assertTrue(result['calls'][-1]['is_error']);self.assertEqual(result['protected_calls'],0)

    def test_reversed_time_is_not_dispatched_and_model_can_correct_it(self):
        tool='mcp__system_diagnostics__get_system_diagnostics'
        more={'more_evidence':True,'read_tools':[tool],'report':None}
        args={'target':'b:management','view':'journal','journal_scope':'all',
              'since_kst':'2026-11-06T16:40:00+09:00','until_kst':'2026-11-06T16:20:00+09:00'}
        fixed=dict(args,since_kst='2026-11-06T16:19:00+09:00')
        result,order,prompts,calls=self.run_case(compact_report=[more,more,None],inquiry_plan=[
            {'calls':[{'tool':tool,'arguments':args}],'report':None},
            {'calls':[{'tool':tool,'arguments':fixed}],'report':None}])
        self.assertNotIn('error_type',result);self.assertNotIn('assess',order)
        self.assertEqual(len(calls),4);self.assertNotIn(args,calls);self.assertEqual(calls[-1],fixed)
        self.assertEqual(result['service_inquiry_rejections'][0]['code'],'invalid_read_time')
        self.assertEqual(result['service_inquiry_count'],1);self.assertEqual(result['protected_calls'],0)
        body=json.loads(prompts[2][1]['content'])
        self.assertEqual(len(body['untrusted_completed_reads']),3)
        self.assertEqual(body['execution_rejections'][0]['calls'][0]['arguments'],args)

    def test_expired_current_reads_refresh_without_replaying_history_or_agent(self):
        selected=[]
        result,order,prompts,calls=self.run_case(stale_first=True,selection_prompts=selected)
        self.assertEqual(order,['select','read','read','read','select','read','read','compact'])
        self.assertEqual(sum('since_kst' in a for a in calls),1)
        self.assertEqual(result['service_current_refreshes'][0]['still_expired'],[])
        self.assertEqual(json.loads(selected[1][1][1])['selection_reason'],'expired_current_refresh')
        self.assertEqual(len(json.loads(prompts[0][1]['content'])['untrusted_completed_reads']),5)
        self.assertEqual(result['protected_calls'],0)

    def test_duplicate_tool_names_do_not_repeat_dispatch_or_lose_model_choice(self):
        tool='mcp__rule_b__get_service_action_target'
        done={'more_evidence':False,'report':{'assessment':'unresolved','status':'needs_review',
            'basis':'등록 서비스 설정과 오류 이력을 대조했으며 배경 원인은 미확인입니다.',
            'current_observation':'현재 검토 상태는 2건으로 관측했으며 전송 영향은 미확인입니다.',
            'evidence_indexes':[0,1],'limitations':['원인 배경은 확인하지 못했습니다.'],'next_steps':[]}}
        first={'more_evidence':True,'read_tools':[tool,tool],'report':None}
        result,order,prompts,calls=self.run_case(extra_read=True,compact_report=[first,done],
            inquiry_plan={'calls':[{'tool':tool,'arguments':{'target':'b:management'}}],'report':None})
        self.assertEqual(result['deduplicated_read_tool_names'],1)
        self.assertEqual(order.count('extra_read'),1)
        self.assertEqual(result['service_report_audit'][0]['response'],first)
        self.assertEqual(result['protected_calls'],0);self.assertNotIn('error_type',result)

    def test_still_expired_after_refresh_stops_without_claiming_success(self):
        result,order,prompts,calls=self.run_case(stale_always=True)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['stop_reason'],'service_current_refresh_unavailable')
        self.assertEqual(len(calls),5)
        self.assertEqual(sum('since_kst' in a for a in calls),1)
        self.assertNotIn('assess',order);self.assertNotIn('compact',order)
        self.assertTrue(result['unqueried']);self.assertEqual(result['protected_calls'],0)

    def test_additional_registered_service_read_keeps_compact_context(self):
        tool='mcp__rule_b__get_service_action_target'
        inquiry={'calls':[{'tool':tool,'arguments':{'target':'b:management'}}],'report':None}
        report={'more_evidence':False,'report':{'assessment':'unresolved',
            'basis':'현재 속성과 과거 오류 표본을 구분해 읽었으며, 추가 서비스 설정 조회도 원인 확정 근거는 아닙니다.',
            'current_observation':'현재 검토 상태는 2건으로 관측됐으며 처리·전송 영향은 미확인입니다.',
            'evidence_indexes':[0,1],'limitations':['과거 실패의 상세 배경은 확보하지 못했습니다.'],
            'next_steps':[],'status':'needs_review'}}
        result,order,prompts,calls=self.run_case(extra_read=True,inquiry_plan=inquiry,
            compact_report=[{'more_evidence':True,'read_tools':[tool],'report':None},report])
        self.assertNotIn('assess',order)
        self.assertEqual(order.count('extra_read'),1)
        self.assertEqual(len(result['calls']),4)
        self.assertEqual(result['protected_calls'],0)
        body=json.loads(prompts[-1][1]['content'])
        self.assertEqual(len(body['untrusted_completed_reads']),4)
        self.assertEqual(body['untrusted_completed_reads'][-1]['data']['fixture_marker'],'additional_actual_service_receipt')

    def test_compound_service_and_blocks_are_selected_read_and_passed_to_model(self):
        question='오늘 B 서버 capstone-management.service 실패 원문과 지금 관제 처리 대기를 확인해줘. 현재 임시차단 목록도 함께 보여줘. 변경은 하지 마.'
        result,order,prompts,calls=self.run_case(question=question,blocks=True,selection={'indexes':[0,1,2,3,4]})
        self.assertNotEqual(result['status'],'failed',result)
        self.assertEqual(order[:6],['select','read','read','read','read','block_read'])
        self.assertEqual(len(calls),5);self.assertEqual(calls[-1],{})
        self.assertEqual(result['protected_calls'],0);self.assertIn('compact',order)
        self.assertNotIn('agent',order)
        self.assertIn('192.0.2.7',str(prompts));self.assertIn('journal_excerpt',str(prompts))
        receipts=runtime.harness.service_history_receipts(result['calls'])
        self.assertEqual(receipts[-1]['tool'],'mcp__resp__list_blocks')
        self.assertEqual(runtime.harness.missing_reads(question,result['calls']),[])

    def test_factual_lookup_finishes_without_incident_verdict_or_redundant_inquiry(self):
        question='오늘 B capstone-management.service 오류 원문과 지금 관제 처리 대기 상태를 표로 정리해줘. 현재 차단 목록도 보여줘. 설정 변경은 하지 마.'
        result,order,prompts,calls=self.run_case(question=question,blocks=True,selection={'indexes':[0,1,2,3,4]})
        self.assertEqual(result['status'],'completed',result)
        self.assertTrue(result['service_lookup_complete'])
        self.assertEqual(order,['select','read','read','read','read','block_read','compact'])
        self.assertEqual(len(calls),5);self.assertEqual(result['protected_calls'],0)
        self.assertIn('192.0.2.7',result['final_response'])
        self.assertIn('controller_already_running',result['final_response'])
        self.assertIn('사건 종결을 뜻하지',result['final_response'])
        self.assertNotIn('INCIDENT_DISPOSITION',result['final_response'])

    def test_cause_request_keeps_model_investigation(self):
        result,order,prompts,calls=self.run_case(question='오늘 b:management 오류 원인이 뭔지 확인해줘. 지금 상태도 확인해줘.')
        self.assertEqual(result['status'],'partial',result)
        self.assertFalse(result.get('service_lookup_complete'))
        self.assertEqual(result['service_judgment'],{'assessment':'unresolved','status':'needs_review'})
        self.assertIn('**판단**',result['final_response'])
        self.assertIn('배경 원인은 미확인',result['final_response'])

    def test_failed_companion_read_remains_partial_without_invented_empty_list(self):
        question='오늘 B 서버 capstone-management.service 오류와 지금 상태 확인해줘. 현재 차단 목록도 보여줘.'
        result,order,prompts,calls=self.run_case(question=question,blocks=True,failed_blocks=True,selection={'indexes':[0,1,2,3]})
        self.assertEqual(order.count('block_read'),1)
        self.assertEqual(result['status'],'partial',result)
        self.assertEqual(result['protected_calls'],0)
        self.assertIn('list_blocks: 현재 동적 차단 목록 미확인',runtime.harness.missing_reads(question,result['calls']))

    def test_model_selects_both_reads_before_judgment_with_real_evidence(self):
        result,order,prompts,calls=self.run_case()
        self.assertNotEqual(result['status'],'failed',result)
        self.assertEqual(order[:5],['select','read','read','read','compact'])
        self.assertEqual(len(calls),3)
        self.assertNotIn('since_kst',calls[0]);self.assertIn('since_kst',calls[1])
        self.assertIn('journal_history',json.dumps(prompts[0]));self.assertIn('ActiveState',json.dumps(prompts[0]));self.assertNotIn('assess',order)
        self.assertNotIn('unqueried',result);self.assertEqual(result['protected_calls'],0)
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['service_judgment'],{'assessment':'unresolved','status':'needs_review'})
        receipts=runtime.harness.service_history_receipts(result['calls']);self.assertEqual(len(receipts),3)
        tampered=[dict(c,result_sha256='0'*64) for c in result['calls']]
        self.assertEqual(runtime.harness.service_history_receipts(tampered),[])

    def test_compact_model_report_keeps_real_reads_and_avoids_agent_replay(self):
        value={'more_evidence':False,'report':{'assessment':'unresolved',
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
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

    def test_explicit_journal_reaches_model_and_table_without_losing_other_reads(self):
        result,order,prompts,calls=self.run_case(selection={'indexes':[0,1,2,3]},
            question='오늘 B 서버 capstone-management.service 오류 원문하고 지금 상태 확인해줘. 설정은 바꾸지 마.')
        self.assertEqual(result['status'],'partial',result)
        self.assertEqual(len(calls),4);self.assertEqual(result['protected_calls'],0)
        self.assertEqual([x.get('view') for x in calls],[None,None,'journal',None])
        self.assertEqual(calls[-1]['target'],'b:management-pipeline')
        body=json.loads(prompts[0][1]['content'])
        receipts=body['untrusted_completed_reads'];self.assertEqual(len(receipts),4)
        self.assertEqual(receipts[2]['data']['kind'],'journal_excerpt')
        highlighted=body['untrusted_journal_structured_messages'][0]
        original=receipts[2]['data']['entries'][0]
        self.assertEqual(highlighted['message'],json.loads(original['message_excerpt']))
        self.assertEqual(highlighted['record_sha256'],original['record_sha256'])
        self.assertEqual(highlighted['receipt_sha256'],receipts[2]['receipt_sha256'])
        self.assertEqual(highlighted['at_kst'],original['at_kst'])
        self.assertIn('controller_already_running',result['final_response'])
        self.assertIn('반환 1행',result['final_response'])
        self.assertNotIn('assess',order)

    def test_observation_success_does_not_resolve_open_incident(self):
        for assessment,status,expected in (('unresolved','resolved','partial'),('benign','needs_review','partial'),
                                          ('benign','monitor','partial'),('benign','awaiting_approval','partial'),
                                          ('benign','resolved','partial')):
            with self.subTest(assessment=assessment,status=status):
                value={'more_evidence':False,'report':{'assessment':assessment,
                    'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
                    'basis':'반환된 현재 서비스 관측과 과거 오류 표본의 범위를 구분하여 확인했습니다.',
                    'evidence_indexes':[0],'limitations':['반환 범위 밖은 확인하지 않았습니다.'],
                    'next_steps':[],'status':status}}
                result,order,prompts,calls=self.run_case(compact_report=value)
                self.assertEqual(result['status'],expected,result)
                self.assertNotIn('service_judgment',result)
                self.assertEqual(result['error_type'],'ValidationError')
                self.assertEqual(result['protected_calls'],0)

    def test_literal_claim_repair_keeps_compact_context_and_actual_receipts(self):
        good={'more_evidence':False,'report':{'assessment':'unresolved',
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
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
        self.assertEqual(body['untrusted_rejected_model_claims']['basis'],bad['report']['basis'])
        self.assertNotIn(bad['report']['basis'],prompts[1][0]['content'])

    def test_service_cause_repair_uses_complete_journal_evidence_without_unrelated_event_reads(self):
        for host in ('A','B'):
            question=f'{host} 서버 Vector 오류 원인과 지금 로그 수집 영향 확인해줘. 설정은 변경하지 마.'
            good={'more_evidence':False,'report':{'assessment':'unresolved',
                'current_observation':'수집 연결 지표는 true, 메시지 버퍼는 0으로 관측됐습니다. 지속 전달과 손실 여부는 미확인입니다.',
                'basis':'오류 표본과 현재 프로세스 관측을 확인했지만 질문한 과거 사건의 배경 원인은 미확인입니다.',
                'evidence_indexes':[0],'limitations':['초기 조회 구간 밖의 과거 기록은 아직 확인하지 않았습니다.'],
                'next_steps':[],'status':'needs_review'}}
            bad=copy.deepcopy(good);bad['report']['basis']='현재 서비스는 완전히 정상이며 모든 기능이 정상으로 복구되었습니다.'
            result,order,prompts,calls=self.run_case(question=question,selection={'indexes':[0,1,2]},compact_report=[bad,good])
            with self.subTest(host=host):
                self.assertEqual(len(calls),3,result)
                self.assertEqual([x.get('view') for x in calls],[None,'journal',None])
                self.assertEqual([x['target'] for x in calls],[host.lower()+':vector',host.lower()+':vector',host.lower()+':collection'])
                self.assertEqual(order.count('compact'),2,result)
                self.assertNotIn('assess',order)
                self.assertEqual(result['service_compact_reports'],[{'more_evidence':False,'repair':False},{'more_evidence':False,'repair':True}])
                self.assertNotIn('incident_evidence_missing',result['repair']['issues'])
                self.assertNotIn('remaining_issues',result)
                self.assertIn(good['report']['basis'],result['final_response'])
                self.assertNotIn(bad['report']['basis'],result['final_response'])
                self.assertEqual(result['status'],'partial')
                self.assertEqual(result['protected_calls'],0)

    def test_empty_model_answer_preserves_observations_and_cannot_be_completed(self):
        result,order,prompts,calls=self.run_case(enabled=False,agent_response='')
        self.assertEqual(result['status'],'partial',result)
        self.assertIn('empty_model_answer',result['remaining_issues'])
        self.assertTrue(result['final_response'].strip())
        self.assertIn('b:management',result['final_response'])
        self.assertNotIn('정상으로 복구',result['final_response'])

    def test_service_evidence_scope_cannot_hide_missing_stale_or_separate_incident_reads(self):
        q='A 서버의 Vector 오류는 왜 난 거고 지금 로그 수집에도 영향이 있어? 실제 로그와 현재 상태를 확인해서 알려줘. 설정은 바꾸지 마.'
        result,_,_,_=self.run_case(question=q,selection={'indexes':[0,1,2]})
        h=runtime.harness
        plan=h.CONTRACT.service_history_plan({'tools':[{'function':{'name':'mcp__system_diagnostics__get_system_diagnostics',
            'parameters':mcp.tools()[0]['inputSchema']}}]},q,result['at_kst'])
        calls=result['calls']
        self.assertFalse(h.incident_evidence_gap(q,calls,service_plan=plan))
        self.assertEqual(h.missing_reads(q,calls,service_plan=plan),[])
        stale=copy.deepcopy(calls);payload=json.loads(stale[0]['result'])
        payload['observed_at_kst']='2000-01-01T00:00:00+09:00'
        stale[0]['result']=json.dumps(payload)
        stale[0]['result_sha256']=hashlib.sha256(stale[0]['result'].encode()).hexdigest()
        failed=copy.deepcopy(calls);failed[0]['is_error']=True
        for label,changed in (('missing',calls[:-1]),('stale',stale),('failed',failed)):
            with self.subTest(label=label):
                self.assertTrue(h.incident_evidence_gap(q,changed,service_plan=plan))
                self.assertTrue(h.missing_reads(q,changed,service_plan=plan))
        corrupted=copy.deepcopy(calls);corrupted[0]['result_sha256']='0'*64
        self.assertTrue(h.incident_evidence_gap(q,corrupted,service_plan=plan))
        ref={'families':['suricata'],'source_ips':['192.0.2.9'],
             'since_kst':'2026-11-08T00:00:00+09:00','until_kst':'2026-11-08T00:05:00+09:00'}
        self.assertTrue(h.incident_evidence_gap(q,calls,reference=ref,service_plan=plan))
        mixed=copy.deepcopy(plan);mixed['only_service']=False
        self.assertTrue(h.incident_evidence_gap(q,calls,service_plan=mixed))

    def test_more_evidence_dispatches_selected_read_then_returns_to_structured_report(self):
        more={'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        good={'more_evidence':False,'report':{'assessment':'unresolved',
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
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

    def test_additional_journal_explicit_filter_is_validated_before_dispatch(self):
        more={'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        good={'more_evidence':False,'report':{'assessment':'unresolved',
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 미확인입니다.',
            'basis':'실제 오류 발췌와 현재 관측을 확인했지만 배경 원인은 추가 검토가 필요합니다.',
            'evidence_indexes':[0],'limitations':['전체 기능 검증은 수행하지 않았습니다.'],
            'next_steps':[],'status':'needs_review'}}
        for scope in (None,'errors','all','unknown'):
            args={'target':'b:management','view':'journal','since_kst':'2026-11-08T00:00:00+09:00',
                  'until_kst':'2026-11-08T00:01:00+09:00'}
            if scope is not None:args['journal_scope']=scope
            plan={'calls':[{'tool':'mcp__system_diagnostics__get_system_diagnostics','arguments':args}],'report':None}
            result,order,prompts,calls=self.run_case(compact_report=[more,good],inquiry_plan=plan)
            with self.subTest(scope=scope):
                self.assertEqual(result['protected_calls'],0)
                self.assertEqual(len(calls),4 if scope in ('errors','all') else 3)
                if scope in ('errors','all'):self.assertEqual(calls[-1],args)
                else:self.assertEqual(result['error_type'],'ValidationError')

    def test_unavailable_read_name_is_rejected_before_selector(self):
        result,order,prompts,calls=self.run_case(compact_report={
            'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__journalctl']})
        self.assertEqual(len(calls),3);self.assertNotIn('inquiry',order)
        self.assertNotEqual(result['status'],'completed');self.assertEqual(result['protected_calls'],0)

    def test_repeated_successful_read_rejects_whole_batch_and_allows_grounded_report(self):
        more={'more_evidence':True,'report':None,'read_tools':['mcp__system_diagnostics__get_system_diagnostics']}
        good={'more_evidence':False,'report':{'assessment':'unresolved',
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
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
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
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
            'current_observation':'현재 검토 상태 사건은 2건이며 처리·전송 지표는 반환되지 않아 미확인입니다.',
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
                self.assertIsInstance(result['final_response'],str)
                self.assertIn(result['error_type'],result['final_response'])
                self.assertIn('확정하지 못했습니다',result['final_response'])
                self.assertEqual(order.count('select'),2)
                self.assertEqual(len(result['service_report_audit']),2)
                self.assertTrue(all(x['dispatched'] is False for x in result['service_report_audit']))

    def test_one_based_compound_selection_is_repaired_before_any_tool_dispatch(self):
        question='오늘 B 서버 capstone-management.service 오류와 지금 상태 확인해줘. 현재 차단 목록도 보여줘.'
        selected_prompts=[]
        result,order,prompts,calls=self.run_case(question=question,blocks=True,
            selection=[{'indexes':[1,2,3,4]},{'indexes':[0,1,2,3]}],selection_prompts=selected_prompts)
        self.assertEqual([x['index'] for x in json.loads(selected_prompts[0][1][1])['options']],[0,1,2,3])
        self.assertFalse(json.loads(selected_prompts[1][-1][1])['executed'])
        self.assertEqual(order[:2],['select','select'])
        self.assertEqual(len(calls),4);self.assertEqual(order.count('block_read'),1)
        self.assertEqual(result['protected_calls'],0)
        rejected=result['service_report_audit'][0]
        self.assertEqual(rejected['response'],{'indexes':[1,2,3,4]})
        self.assertEqual(rejected['phase'],'required_read_selection_rejected')
        self.assertEqual(rejected['validator'],'maximum');self.assertFalse(rejected['dispatched'])

    def test_failed_history_is_partial_and_not_silently_complete(self):
        result,order,prompts,calls=self.run_case(failed=True)
        self.assertEqual(result['status'],'partial',result)
        self.assertTrue(result.get('unqueried') or result.get('remaining_issues'))
        self.assertEqual(sum('since_kst' in c for c in calls),1)

if __name__=='__main__':unittest.main()
