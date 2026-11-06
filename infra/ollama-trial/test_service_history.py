"""Real runtime with deterministic SDK boundaries; no network or service writes."""
import asyncio
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
    def run_case(self,selection=None,failed=False):
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
        class LLM:
            def __init__(self,**kw):pass
            def with_structured_output(self,*args,**kw):
                async def select(messages):
                    order.append('select')
                    return {'indexes':[0,1]} if selection is None else selection
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
        with patch.dict(sys.modules,modules),patch.object(runtime,'capabilities',return_value={'system-diagnostics':['get_system_diagnostics']}),patch.object(runtime,'filter_catalog',side_effect=lambda server,tools,mode:tools):
            result=asyncio.run(runtime.run({'model':'qwen3.6:35b','base_url':'http://fixture.invalid','access_mode':'hermes-parity',
                'mcpServers':{'system-diagnostics':{}}},{'question':'오늘 B 서버 capstone-management.service 실패 원인과 지금 상태 확인해줘. 설정은 바꾸지 마.'}))
        return result,order,prompts,calls

    def test_model_selects_both_reads_before_judgment_with_real_evidence(self):
        result,order,prompts,calls=self.run_case()
        self.assertNotEqual(result['status'],'failed',result)
        self.assertEqual(order[:4],['select','read','read','assess'])
        self.assertEqual(len(calls),2)
        self.assertNotIn('since_kst',calls[0]);self.assertIn('since_kst',calls[1])
        self.assertIn('journal_history',prompts[0]);self.assertIn('ActiveState',prompts[0])
        self.assertNotIn('unqueried',result);self.assertEqual(result['protected_calls'],0)
        receipts=runtime.harness.service_history_receipts(result['calls']);self.assertEqual(len(receipts),2)
        tampered=[dict(c,result_sha256='0'*64) for c in result['calls']]
        self.assertEqual(runtime.harness.service_history_receipts(tampered),[])

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
