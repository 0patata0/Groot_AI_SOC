"""Typed identity and execution provenance: no model, network or writes."""
from pathlib import Path
from datetime import datetime,timedelta,timezone
from types import SimpleNamespace
from unittest.mock import patch
import asyncio,copy,hashlib,importlib.util,json,os,sys,types,unittest
ROOT=Path(os.environ['SOC_TYPED_ROOT']).resolve()
sys.path[:0]=[str(ROOT/'infra/mcp'),str(ROOT/'infra/ollama-trial'),str(ROOT/'infra/hermes/query-completion')]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
C=load('typed_contract',ROOT/'infra/hermes/chat_contract.py')
G=load('typed_gate',ROOT/'infra/hermes/soc_management_run.py')
H=load('typed_harness',ROOT/'infra/ollama-trial/harness.py')
M=load('typed_mcp',ROOT/'infra/mcp/system-diagnostics-mcp.py')
D=load('typed_core',ROOT/'infra/mcp/system_diagnostics.py');M._library=D
DIAG='mcp__system_diagnostics__get_system_diagnostics';INV='mcp__system_diagnostics__get_host_inventory'
NOW=datetime.now(timezone(timedelta(hours=9)));AT=NOW.isoformat();Q='B Vector 지금 상태와 최근 10분 로그 보여줘'
def catalog():
 return {'tools':[{'type':'function','function':{'name':'mcp__system_diagnostics__'+t['name'],'description':t['description'],'parameters':copy.deepcopy(t['inputSchema'])}} for t in M.tools()]}
def receipt(name,args,data,error=False):
 raw=json.dumps(data,ensure_ascii=False)
 return {'tool':name,'arguments':copy.deepcopy(args),'data':copy.deepcopy(data),'is_error':error,'receipt_sha256':hashlib.sha256(raw.encode()).hexdigest()}
def current(target='b:vector',load_state='not-found'):
 return {'schema':1,'target':target,'host':target[0],'unit':D.TARGETS[target],'status':'observed','mutation_performed':False,'publisher_stale':False,'observed_at_kst':AT,'age_seconds':0,'properties':{'LoadState':load_state,'ActiveState':'inactive','SubState':'dead','Result':'success','ExecMainStartTimestampMonotonic':0,'ExecMainExitTimestampMonotonic':0},'process_termination':{'kind':'not_recorded','exit_status':None}}
def base():return receipt(DIAG,{'target':'b:vector'},current())
def args(view,offset=0,host='b'):return {'host':host,'view':view,'state':'all','limit':100,'offset':offset}
def page(view,rows=None,total=0,offset=0,more=False,stamp=AT,host='b'):
 rows=[({'unit':r.get('unit','x.service'),'load':'loaded','active':'active','sub':'running'} if view=='services' else {'id':'a'*64,'name':r.get('name','other'),'image':'fixture:1','state':r.get('state','running'),'status':'Up'}) for r in (rows or [])]
 a=args(view,offset,host);data={'kind':'host_inventory','request':a,'mutation_performed':False,'hosts':[{'host':host,'view':view,'state':'all','limit':100,'offset':offset,'status':'observed','observed_at_kst':stamp,'age_seconds':0,'total':total,'rows':rows or [],'has_more':more,'next_offset':offset+len(rows or []) if more else None}]}
 return receipt(INV,a,data)
def fact(data=None):
 data=data or current();return {'kind':'diagnostics','target':data['target'],'properties':data['properties'],'process_termination':data['process_termination'],**C.diagnostic_observation_fields(data)}
class Execution(unittest.TestCase):
 def issues(self,text,rows=None):return C.snapshot_health_violations(text,rows or [fact()])
 def test_default_result_is_not_successful_execution(self):
  for text in ['b:vector 마지막 실행이 성공했습니다.','b:vector는 정상 종료했습니다.','직전 종료 성공으로 관측됩니다.','b:vector의 마지막 실행이 완료되었습니다.','b:vector exited successfully.']:
   with self.subTest(text=text):self.assertIn('diagnostic_execution_success_unverified',self.issues(text))
 def test_not_found_is_not_actual_process_state(self):
  for text in ['b:vector 프로세스가 실행되지 않습니다.','b:vector 서비스가 중지 상태입니다.','b:vector는 현재 실행 중입니다.','b:vector process is not running.']:
   with self.subTest(text=text):self.assertIn('diagnostic_unloaded_unit_not_process_state',self.issues(text))
 def test_raw_defaults_and_unknowns_are_preserved(self):
  for text in ['b:vector LoadState=not-found, ActiveState=inactive, SubState=dead, Result=success입니다.','b:vector의 마지막 실행 성공 여부는 미확인입니다.','b:vector가 정상 종료했는지는 미확인입니다.','b:vector 프로세스가 실행 중인지는 미확인입니다.']:
   with self.subTest(text=text):self.assertFalse(set(self.issues(text)) & {'diagnostic_execution_success_unverified','diagnostic_unloaded_unit_not_process_state'})
 def test_attached_condition_negation_and_uncertainty_are_not_execution_assertions(self):
  for text in ['b:vector 정상 종료했다면 로그를 확인해야 합니다.','b:vector 마지막 실행은 성공하지 않았습니다.','b:vector가 정상 종료한 것은 아닙니다.','b:vector가 정상 종료했을 가능성은 미확인입니다.','b:vector 프로세스가 실행 중이면 로그를 확인하세요.','b:vector가 정상 종료했다고 단정할 수 없습니다.']:
   with self.subTest(text=text):self.assertNotIn('diagnostic_execution_success_unverified',self.issues(text))
 def test_double_negation_does_not_hide_a_default_success_assertion(self):
  self.assertIn('diagnostic_execution_success_unverified',self.issues('b:vector가 정상 종료하지 않았다는 뜻은 아닙니다.'))
 def test_result_alone_is_not_proof_even_for_loaded_unit(self):
  self.assertIn('diagnostic_execution_success_unverified',self.issues('b:vector 마지막 실행이 성공했습니다.',[fact(current(load_state='loaded'))]))
 def test_actual_zero_exit_with_result_supports_last_exit(self):
  d=current(load_state='loaded');d['process_termination']={'kind':'exited','exit_status':0};d['properties']['ExecMainStartTimestampMonotonic']=1;d['properties']['ExecMainExitTimestampMonotonic']=2
  self.assertNotIn('diagnostic_execution_success_unverified',self.issues('b:vector 마지막 실행이 성공했습니다.',[fact(d)]))
 def test_another_unit_does_not_lend_success(self):
  d=current('b:docker','loaded');d['process_termination']={'kind':'exited','exit_status':0}
  self.assertIn('diagnostic_execution_success_unverified',self.issues('b:vector 마지막 실행이 성공했습니다.',[fact(),fact(d)]))
 def test_global_disclaimer_does_not_erase_assertion(self):
  self.assertIn('diagnostic_execution_success_unverified',self.issues('b:vector 마지막 실행이 성공했습니다. 전체 기능은 미확인입니다.'))
 def test_literal_explanation_of_default_is_not_a_success_claim(self):
  text='함께 반환된 inactive/dead·Result=success는 실제 프로세스 정지·과거 실행 성공의 증거가 아닙니다.'
  self.assertNotIn('diagnostic_execution_success_unverified',self.issues(text))
 def test_real_observed_last_attempt_phrase_is_not_default_success(self):
  text='Result=success는 마지막 실행(또는 종료 시도)이 성공적으로 끝났음을 나타내지만, 현재 상태가 dead이므로 이는 과거의 종료를 의미합니다.'
  self.assertIn('diagnostic_execution_success_unverified',self.issues(text))
 def test_a_same_unit_journal_receipt_does_not_invalidate_real_current_exit(self):
  d=current(load_state='loaded');d['process_termination']={'kind':'exited','exit_status':0}
  rows=[fact(d),{'kind':'diagnostics','target':'b:vector','unit':D.TARGETS['b:vector'],'diagnostic_mode':'journal_excerpt'},{'kind':'diagnostics','target':'b:collection','diagnostic_mode':'runtime'}]
  self.assertNotIn('diagnostic_execution_success_unverified',self.issues('b:vector 마지막 실행이 성공했습니다.',rows))
 def test_host_journal_start_record_is_not_reinterpreted_as_a_unit_default(self):
  rows=[{'kind':'diagnostics','target':'b:systemd','diagnostic_mode':'journal_excerpt','journal_valid':True,'journal_entries':[{'message_excerpt':'Started example.service'}]}]
  self.assertEqual(C.diagnostic_execution_claim_violations("반환 표본의 메시지는 Started로 시작 성공 기록입니다.",rows),[])
 def test_boolean_timestamp_is_not_execution(self):
  d=current();d['properties']['ExecMainStartTimestampMonotonic']=True
  info=C.diagnostic_observation_fields(d)['unit_execution'];self.assertFalse(info['main_start_observed']);self.assertNotIn('ExecMainStartTimestampMonotonic',info['monotonic_timestamps_us'])
class Identity(unittest.TestCase):
 def state(self,rows=None,question=Q,request=None):return C.service_identity_state(request or catalog(),question,[base()] if rows is None else rows,NOW)
 def test_actual_same_host_catalog_is_offered_without_container_guess(self):
  s=self.state();self.assertEqual(s['pending'],[{'tool':INV,'arguments':args('services')},{'tool':INV,'arguments':args('containers')}]);self.assertFalse(s['observations']);self.assertEqual(s['missing_units'][0]['target'],'b:vector')
 def test_explicit_unit_is_not_replaced_with_docker(self):
  self.assertEqual(self.state(question='B capstone-vector.service 지금 상태와 로그 보여줘')['pending'],[])
 def test_loaded_unit_does_not_force_discovery(self):
  self.assertEqual(self.state([receipt(DIAG,{'target':'b:vector'},current(load_state='loaded'))])['pending'],[])
 def test_missing_target_and_wrong_host_are_not_inferred(self):
  for question in ['Vector 지금 상태 보여줘','D Vector 상태 보여줘','192.168.16.231 Vector 상태 보여줘']:
   with self.subTest(question=question):self.assertFalse(self.state(question=question)['pending'])
 def test_stale_and_failed_unit_are_not_reused(self):
  for change in ['failed','stale','wronghost','wrongunit','mutation']:
   r=base()
   if change=='failed':r['is_error']=True
   if change=='stale':r['data']['observed_at_kst']=(NOW-timedelta(seconds=181)).isoformat()
   if change=='wronghost':r['data']['host']='a'
   if change=='wrongunit':r['data']['unit']='other.service'
   if change=='mutation':r['data']['mutation_performed']=True
   with self.subTest(change=change):self.assertFalse(self.state([r])['pending'])
 def test_missing_registered_read_is_a_capability_gap(self):
  c=catalog();c['tools']=[t for t in c['tools'] if t['function']['name']!=INV]
  s=self.state(request=c);self.assertFalse(s['pending']);self.assertIn('service_identity:inventory_capability_unavailable',s['incomplete'])
 def test_full_empty_catalogs_are_scoped_observations(self):
  s=self.state([base(),page('services'),page('containers')]);self.assertFalse(s['pending'] or s['incomplete']);self.assertEqual([r['total'] for r in s['observations']],[0,0]);self.assertTrue(all(r['component_identity_verified'] is False for r in s['observations']))
 def test_only_real_next_page_is_offered(self):
  rows=[{'unit':'u'+str(i)+'.service','load':'loaded','active':'active','sub':'running'} for i in range(100)]
  s=self.state([base(),page('services',rows,101,more=True),page('containers')]);self.assertEqual(s['pending'],[{'tool':INV,'arguments':args('services',100)}])
 def test_complete_pages_use_one_snapshot(self):
  rows=[{'unit':'u'+str(i)+'.service'} for i in range(100)]
  s=self.state([base(),page('services',rows,101,more=True),page('services',[{'unit':'last.service'}],101,100),page('containers')]);self.assertFalse(s['pending'] or s['incomplete']);self.assertEqual(s['observations'][0]['returned_rows'],101)
 def test_changed_page_snapshot_stays_incomplete_without_replay(self):
  rows=[{'unit':'u'+str(i)+'.service'} for i in range(100)]
  s=self.state([base(),page('services',rows,101,more=True),page('services',[{'unit':'last.service'}],101,100,stamp=(NOW-timedelta(seconds=1)).isoformat()),page('containers')]);self.assertFalse(s['pending']);self.assertIn('service_identity:b:services:pagination_snapshot_changed',s['incomplete'])
 def test_failed_inventory_does_not_turn_into_zero_or_repeat(self):
  r=page('containers');r['is_error']=True;s=self.state([base(),page('services'),r]);self.assertFalse(s['pending']);self.assertIn('service_identity:b:containers:unavailable',s['incomplete']);self.assertEqual([x['view'] for x in s['observations']],['services'])
 def test_malformed_pagination_cannot_fabricate_next_offset(self):
  r=page('services',[{'unit':'x.service'}],2,more=True);r['data']['hosts'][0]['next_offset']=50
  s=self.state([base(),r,page('containers')]);self.assertFalse(s['pending']);self.assertIn('service_identity:b:services:scope_or_page_unverified',s['incomplete'])
 def test_malformed_typed_row_is_not_complete_inventory(self):
  r=page('services',[{'unit':'x.service'}],1);r['data']['hosts'][0]['rows'][0]['unit']={'untrusted':'not an identity'}
  s=self.state([base(),r,page('containers')]);self.assertIn('service_identity:b:services:scope_or_page_unverified',s['incomplete']);self.assertFalse(s['pending'])
 def test_untyped_load_state_is_not_inserted_into_typed_facts(self):
  d=current();d['properties']['LoadState']={'untrusted':'not a state'}
  self.assertIsNone(C.diagnostic_observation_fields(d)['unit_execution']['load_state'])
 def test_a_different_host_inventory_does_not_complete_b(self):
  s=self.state([base(),page('services',host='a'),page('containers',host='a')]);self.assertEqual(len(s['pending']),2)
 def test_unasked_writes_explanations_and_negations_are_not_navigation(self):
  for q in ['B Vector 오류 로그 보고 재시작해줘','B Vector not-found 설명만 해줘','B Vector 조회하지 마','```B Vector 오류``` 번역해줘']:
   with self.subTest(q=q):self.assertFalse(self.state(question=q)['pending'])
 def test_shared_schema_is_exact_not_host_view_cartesian_product(self):
  from jsonschema import Draft202012Validator
  options=[{'tool':INV,'arguments':args('services')},{'tool':INV,'arguments':args('containers')}]
  narrowed=H.refine_read_schemas(Q,{INV:next(t['function']['parameters'] for t in catalog()['tools'] if t['function']['name']==INV)},[],identity_options=options)
  v=Draft202012Validator(narrowed[INV]);self.assertTrue(v.is_valid(args('containers')));self.assertFalse(v.is_valid(args('containers',host='a')));self.assertFalse(v.is_valid(dict(args('containers'),view='container_logs',container='guessed')))
 def test_native_required_options_use_same_actual_receipts(self):
  chat={'request':Q,'requested_at_kst':AT,'background':''}
  with patch.object(G,'chat_read_context',return_value=chat):
   options=G.operator_diagnostic_options(catalog(),[base()])
  inventories=[o for o in options if o['tool']==INV];self.assertEqual(inventories,self.state()['pending'])

class Native(unittest.TestCase):
 def test_native_follow_up_exposes_only_actual_same_host_inventory_calls(self):
  import alignment
  import test_completion as fixture
  from dataclasses import dataclass
  from jsonschema import Draft202012Validator
  @dataclass
  class Request:
   api_kwargs:object
   api_messages:object=None
   _original_api_kwargs:object=None
  h=alignment.load_harness();q='B Vector 현재 상태 보여줘';turn='typed-native'
  r=base();raw=json.dumps(r['data'],ensure_ascii=False)
  wire={'server':'system-diagnostics','name':'get_system_diagnostics','arguments':r['arguments'],'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False}
  agent=SimpleNamespace(platform='mattermost',model='qwen3.6:35b',provider='custom',max_iterations=12,_current_turn_id=turn,_capstone_alignment_diagnostic_targets=M.tools()[0]['inputSchema']['properties']['target']['enum'])
  messages=[{'role':'user','content':q}];source=dict(catalog(),messages=messages)
  wrapper=alignment.request_wrapper(lambda *a,**kw:Request(copy.deepcopy(source)),fixture.PLUGIN,h)
  with patch.object(alignment,'calls_from_rows',return_value=[wire]):result=wrapper(agent,original_user_message=q,turn_id=turn,messages=messages)
  schema=result.api_kwargs['response_format']['json_schema']['schema'];branches=schema['properties']['calls']['items']['anyOf']
  self.assertEqual([b['properties']['tool']['const'] for b in branches],[INV])
  v=Draft202012Validator(branches[0]['properties']['arguments']);self.assertTrue(v.is_valid(args('containers')));self.assertFalse(v.is_valid(args('containers',host='a')))
  self.assertEqual(agent._capstone_service_identity[:2],(turn,q));self.assertEqual(len(agent._capstone_service_identity[2]['pending']),2)
  agent._current_turn_id='different-turn'
  with patch.object(alignment,'calls_from_rows',return_value=[]):wrapper(agent,original_user_message=q,turn_id='different-turn',messages=messages)
  self.assertFalse(agent._capstone_service_identity[2]['missing_units'])

class SDK(unittest.TestCase):
 def run_case(self,explicit=False,current_only=False):
  import runtime
  dispatches=[];selected=[];closed=[];models=[]
  question='B Vector 현재 상태 보여줘' if current_only else '오늘 B Vector 오류 이력과 지금 상태 보여줘'
  class Connector:
   async def list_tools(self):return [SimpleNamespace(name=t['name'],description=t['description'],inputSchema=t['inputSchema']) for t in M.tools() if t['name'] in ['get_system_diagnostics','get_host_inventory']]
   async def call_tool(self,name,a,**kw):
    dispatches.append((name,copy.deepcopy(a)))
    if name=='get_host_inventory':
     rows=([{'unit':'u'+str(i)+'.service'} for i in range(100)] if a['offset']==0 else [{'unit':'last.service'}]) if a['view']=='services' else [{'name':'other','state':'running'}]
     data=page(a['view'],rows,101 if a['view']=='services' else 1,a['offset'],a['view']=='services' and a['offset']==0)['data']
    else:
     data=current(a['target'])
     if a['target']=='b:collection':data={'schema':1,'target':a['target'],'host':'b','kind':'runtime','status':'ok','mutation_performed':False,'observed_at_kst':AT,'codes':[],'metrics':{},'lookback_scope':'latest_snapshot_only_not_requested_history'}
     elif 'since_kst' in a:data={'schema':1,'target':a['target'],'host':'b','unit':D.TARGETS[a['target']],'kind':'journal_history','mutation_performed':False,'observed_at_kst':AT,'age_seconds':0,'requested_since_kst':a['since_kst'],'requested_until_kst':a['until_kst'],'recent_errors':[],'history_coverage':{'status':'partial_or_unavailable'},'has_more':False}
    return SimpleNamespace(isError=False,content=[SimpleNamespace(type='text',text=json.dumps(data))])
  class Client:
   def __init__(self,**kw):pass
   def get_all_active_sessions(self):return {'system-diagnostics':SimpleNamespace(connector=Connector())}
   async def close_all_sessions(self):closed.append(True)
  class Tool:
   def __init__(self,**kw):self.__dict__.update(kw)
   async def ainvoke(self,args):return await self.coroutine(**args)
  class Agent:
   def __init__(self,**kw):self.client=kw['client']
   async def initialize(self):await self.adapter.create_all(self.client)
   async def run(self,*a,**kw):raise AssertionError('unexpected unconstrained agent')
  class Model:
   def __init__(self,**kw):pass
   def with_structured_output(self,schema,**kw):
    async def invoke(messages):
     models.append(copy.deepcopy(schema))
     if 'indexes' in schema.get('properties',{}):
      body=json.loads(messages[1][1]);selected.append(body);return {'indexes':list(range(len(body['options'])))}
     if 'calls' in schema.get('properties',{}):return {'calls':[{'tool':DIAG,'arguments':{'target':'b:vector'}}]}
     return {'more_evidence':False,'report':{'assessment':'unresolved','status':'needs_review','basis':'등록된 b:vector unit은 LoadState=not-found로 관측되었으며 과거 실행 여부는 미확인입니다.','current_observation':'같은 호스트에서 서비스와 컨테이너 목록을 구분하여 확인했으며 실제 구성요소의 동작은 미확인입니다.','evidence_indexes':[0] if explicit else [0,1],'limitations':['loaded unit과 Docker 목록은 전체 프로세스 목록이 아닙니다.'],'next_steps':[]}}
    return SimpleNamespace(ainvoke=invoke)
  fake={name:types.ModuleType(name) for name in ['mcp_use','mcp_use.agents','mcp_use.agents.adapters','mcp_use.agents.adapters.langchain_adapter','langchain_ollama','langchain_core','langchain_core.tools','langchain_core.callbacks']}
  fake['mcp_use'].MCPClient=Client;fake['mcp_use'].MCPAgent=Agent;fake['mcp_use.agents.adapters.langchain_adapter'].LangChainAdapter=object
  fake['langchain_ollama'].ChatOllama=Model;fake['langchain_core.tools'].StructuredTool=Tool;fake['langchain_core.callbacks'].AsyncCallbackHandler=object
  request={'question':question}
  if explicit:request['tools']=[DIAG]
  with patch.dict(sys.modules,fake),patch.object(runtime,'capabilities',return_value={'system-diagnostics':['get_system_diagnostics','get_host_inventory']}),patch.object(runtime,'filter_catalog',side_effect=lambda *a:a[1]):
   report=asyncio.run(runtime.run({'model':'fixture','base_url':'http://127.0.0.1:11434','access_mode':'hermes-parity','mcpServers':{'system-diagnostics':{}}},request))
  return report,dispatches,selected,closed
 def test_runtime_dispatches_typed_reads_and_real_next_page_before_report(self):
  r,c,s,closed=self.run_case();self.assertNotIn('error_type',r);self.assertEqual([a for n,a in c if n=='get_host_inventory'],[args('services'),args('containers'),args('services',100)]);self.assertEqual(closed,[True]);self.assertEqual(r['protected_calls'],0);self.assertEqual(r['chat_posts'],0);self.assertEqual(len(r['service_identity_discovery']['observations']),2)
 def test_explicit_tool_subset_is_never_expanded(self):
  r,c,s,closed=self.run_case(explicit=True);self.assertNotIn('error_type',r);self.assertFalse(any(n=='get_host_inventory' for n,a in c));self.assertIn('service_identity:inventory_capability_unavailable',r['service_identity_discovery']['incomplete'])
 def test_current_short_lookup_uses_deferred_registered_read_without_initial_exposure(self):
  r,c,s,closed=self.run_case(current_only=True);self.assertNotIn('error_type',r);self.assertEqual([a for n,a in c if n=='get_host_inventory'],[args('services'),args('containers'),args('services',100)]);self.assertEqual(r['exposed_tools'],[DIAG]);self.assertEqual(r['protected_calls'],0);self.assertEqual(r['status'],'partial');self.assertIn('같은 호스트의 구성요소 조회 범위',r['final_response']);self.assertIn('실제 프로세스 정지·과거 실행 성공의 증거가 아닙니다',r['final_response'])
if __name__=='__main__':unittest.main()
