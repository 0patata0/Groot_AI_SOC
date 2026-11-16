"""Typed partial lookup and source-claim provenance; no model or network."""
from pathlib import Path
from datetime import timedelta
from unittest.mock import patch
import copy,hashlib,importlib.util,json,os,sys,unittest
from types import SimpleNamespace,ModuleType
import asyncio
ROOT=Path(os.environ['SOC_PROVENANCE_ROOT']).resolve();os.environ['SOC_FACTUAL_ROOT']=str(ROOT)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
P=load('provenance_factual_fixtures',Path(os.environ.get('SOC_FACTUAL_TEST',Path(__file__).parents[3]/'infra/validation/factual-service/test_factual_service.py')))
F=P.F;C=P.C;G=P.G;H=P.H;DIAG=P.DIAG;INV=P.INV;NOW=P.NOW;AT=P.AT
Q='B Vector 지금 상태랑 최근 6분 로그 간단히 보여줘'
def receipts(question=Q):
 return P.completed(question,'not-found')+[F.page('services',[{'unit':'unrelated-web.service'}],1),F.page('containers',[{'name':'unrelated-web'}],1)]
def context(question=Q,rows=None):return P.context(question,receipts(question) if rows is None else rows)
def calls(rows):
 out=[]
 for row in rows:
  raw=json.dumps(row['data'],ensure_ascii=False);out.append({'server':'system-diagnostics','name':row['tool'].split('__')[-1],
   'arguments':copy.deepcopy(row['arguments']),'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':row['is_error']})
 return out
def partial_report():return {'scope':'unresolved_service_lookup','assessment':'unresolved','status':'needs_review','evidence_indexes':[0,1]}
def report_schema():return C.service_report_schema([DIAG,INV],lookup_incomplete=True)
def with_source_quote(message='b:vector의 물리 유닛 파일이 없습니다.',include_calls=False):
 rows=P.completed(Q,'not-found');r=next(row for row in rows if row['arguments'].get('view')=='journal')
 library=load('provenance_journal_fixture',ROOT/'infra/mcp/diagnostic_journal.py');library.core=P.D
 history=load('provenance_history_fixture',ROOT/'infra/mcp/diagnostic_history.py');history.core=P.D
 def runner(*args):
  event={'_SYSTEMD_UNIT':P.D.TARGETS['b:vector'],'__REALTIME_TIMESTAMP':str(history.instant(AT)-60000000),
   '__CURSOR':'provenance-fixture','PRIORITY':'3','MESSAGE':message}
  return 0,(json.dumps(event)+'\n').encode()
 with patch.object(P.D,'_history',history):r['data']=library.answer(r['arguments'],'b',history.QueryClock(int(NOW.timestamp()),history.instant(AT)),runner=runner)
 return calls(rows) if include_calls else H.facts_for(calls(rows))

class PartialScope(unittest.TestCase):
 def test_plain_missing_component_has_typed_unresolved_lookup(self):
  value=context();self.assertTrue(value['lookup_incomplete']);self.assertNotIn('lookup_only',value)
 def test_discovery_pending_is_not_silently_finished(self):
  self.assertIsNone(context(rows=P.completed(Q,'not-found')))
 def test_failed_catalog_is_visible_not_zero_or_resolved(self):
  rows=receipts();rows[-1]['is_error']=True;value=context(rows=rows)
  self.assertTrue(value['lookup_incomplete']);self.assertTrue(value['untrusted_failed_read_attempts'])
  self.assertIn('service_identity:b:containers:unavailable',value['service_identity_discovery']['incomplete'])
 def test_stale_inventory_stays_a_gap_without_an_empty_count(self):
  rows=receipts();rows[-1]['data']['hosts'][0]['observed_at_kst']=(NOW-timedelta(seconds=181)).isoformat();value=context(rows=rows)
  self.assertTrue(value['lookup_incomplete']);self.assertEqual([x['view'] for x in value['service_identity_discovery']['observations']],['services'])
 def test_extra_unasked_read_prevents_closed_partial_projection(self):
  rows=receipts();r=F.page('containers');r['arguments']={**r['arguments'],'view':'container_details','container':'unrelated-web'};r['data']['request']=r['arguments'];rows.append(r)
  self.assertNotIn('lookup_incomplete',context(rows=rows))
 def test_wrong_host_cannot_replace_missing_discovery(self):
  rows=P.completed(Q,'not-found')+[F.page('services',host='a'),F.page('containers',host='a')];self.assertIsNone(context(rows=rows))
 def test_real_cause_question_stays_with_the_investigator(self):
  q='B Vector 현재 상태와 최근 6분 로그의 오류 원인 확인해줘'
  value=context(q);self.assertNotIn('lookup_incomplete',value);self.assertNotIn('lookup_only',value)
 def test_mixed_extra_subject_does_not_become_partial_lookup(self):
  value=context(Q+' CPU도 보여줘');self.assertNotIn('lookup_incomplete',value or {})
 def test_explicit_unit_preserves_its_requested_scope(self):
  q='B capstone-vector.service 현재 상태와 최근 6분 로그 보여줘';value=P.context(q,P.completed(q,'not-found'))
  self.assertTrue(value['lookup_only']);self.assertNotIn('lookup_incomplete',value)
 def test_the_same_navigation_receipts_are_not_mutated(self):
  rows=receipts();before=copy.deepcopy(rows);context(rows=rows);self.assertEqual(rows,before)

class PartialSchema(unittest.TestCase):
 def test_model_can_acknowledge_unresolved_scope_only(self):
  from jsonschema import Draft202012Validator
  v=Draft202012Validator(report_schema());self.assertTrue(v.is_valid({'more_evidence':False,'report':partial_report()}))
 def test_no_prose_relations_normal_verdict_or_write(self):
  from jsonschema import Draft202012Validator
  v=Draft202012Validator(report_schema())
  for field,value in [('basis','현재 프로세스가 멈췄습니다.'),('current_observation','관련 컨테이너는 unrelated-web입니다.'),('assessment','benign'),('status','resolved'),('calls',[{'tool':'restart'}])]:
   bad={'more_evidence':False,'report':partial_report()};bad['report'][field]=value
   with self.subTest(field=field):self.assertFalse(v.is_valid(bad))
 def test_untrusted_model_does_not_supply_identity(self):
  from jsonschema import Draft202012Validator
  value={'more_evidence':False,'report':partial_report(),'lookup_identity':context()['service_identity_discovery']}
  self.assertFalse(Draft202012Validator(report_schema()).is_valid(value))
 def test_conflicting_completion_modes_are_refused(self):
  with self.assertRaisesRegex(ValueError,'lookup'):C.service_report_schema([DIAG],lookup_only=True,lookup_incomplete=True)

class PartialDisplay(unittest.TestCase):
 def render(self,rows=None):
  rows=receipts() if rows is None else rows;value=context(rows=rows);report=partial_report();report.pop('evidence_indexes');report['evidence_tools']=[DIAG,INV]
  return G.render_model_review(report,H.facts_for(calls(rows)),lookup_identity=value['service_identity_discovery'])
 def test_renderer_uses_unit_attributes_and_unresolved_identity(self):
  text=self.render();self.assertIn('not-found',text);self.assertIn('구성요소 식별 미확인',text)
  self.assertNotIn('현재 프로세스 실행 상태는',text);self.assertNotIn('관련 컨테이너',text);self.assertNotIn('unrelated-web',text)
 def test_lookup_gap_never_closes_a_security_incident(self):
  text=self.render();self.assertNotIn('INCIDENT_DISPOSITION',text);self.assertEqual(G.management_status(text),'needs_review')
 def test_projected_partial_output_passes_the_full_claim_gate(self):
  rows=receipts();self.assertEqual(G.evidence_claim_violations(self.render(rows),H.facts_for(calls(rows))),[])
 def test_failed_catalog_is_displayed_as_unverified_not_zero(self):
  rows=receipts();rows[-1]['is_error']=True;text=self.render(rows)
  self.assertIn('containers',text);self.assertIn('미확인',text);self.assertNotIn('Docker 컨테이너 | 0',text)
 def test_missing_trusted_identity_cannot_render_the_new_scope(self):
  report=partial_report();report.pop('evidence_indexes');report['evidence_tools']=[DIAG,INV]
  with self.assertRaisesRegex(ValueError,'identity'):G.render_model_review(report,[])
 def test_pending_or_falsely_verified_identity_is_rejected(self):
  value=context()['service_identity_discovery'];report=partial_report();report.pop('evidence_indexes');report['evidence_tools']=[DIAG,INV]
  for case in ['pending','verified']:
   d=copy.deepcopy(value)
   if case=='pending':d['pending']=[{'tool':INV,'arguments':F.args('services')}]
   else:d['observations'][0]['component_identity_verified']=True
   with self.subTest(case=case):
    with self.assertRaisesRegex(ValueError,'identity'):G.render_model_review(report,[],lookup_identity=d)

class ClaimProvenance(unittest.TestCase):
 def test_sdk_normalization_does_not_turn_a_source_quote_into_a_claim(self):
  rows=with_source_quote('b:vector의 탐지 규칙 파일이 없습니다.',include_calls=True);facts=H.facts_for(rows)
  self.assertNotIn('diagnostic_unit_file_existence_unverified',H.violations(Q,G.literal_evidence_table(facts),rows))
 def test_authentic_rendered_quote_is_not_a_model_file_assertion(self):
  facts=with_source_quote();before=copy.deepcopy(facts);text=G.literal_evidence_table(facts)
  self.assertNotIn('diagnostic_unit_file_existence_unverified',G.evidence_claim_violations(text,facts));self.assertEqual(facts,before)
 def test_appending_the_same_words_as_a_new_claim_is_still_rejected(self):
  facts=with_source_quote();text=G.literal_evidence_table(facts)+'\nb:vector의 물리 유닛 파일이 없습니다.'
  self.assertIn('diagnostic_unit_file_existence_unverified',G.evidence_claim_violations(text,facts))
 def test_arbitrary_markdown_table_is_not_exempt(self):
  facts=with_source_quote();text='| 모델 판단 | b:vector의 물리 유닛 파일이 없습니다. | 확인 |'
  self.assertIn('diagnostic_unit_file_existence_unverified',G.evidence_claim_violations(text,facts))
 def test_changed_source_row_loses_its_exact_attribution(self):
  facts=with_source_quote();text=G.literal_evidence_table(facts).replace('로그 발췌 1 / 1행','로그 발췌 1 / 2행')
  self.assertIn('diagnostic_unit_file_existence_unverified',G.evidence_claim_violations(text,facts))
 def test_raw_property_as_process_phrase_is_not_proof(self):
  facts=H.facts_for(calls(P.completed(Q,'not-found')))
  self.assertIn('diagnostic_unloaded_unit_not_process_state',G.evidence_claim_violations('현재 프로세스 실행 상태는 ActiveState=inactive, SubState=dead입니다.',facts))
 def test_property_literal_and_explicit_process_unknown_remain_allowed(self):
  facts=H.facts_for(calls(P.completed(Q,'not-found')))
  self.assertNotIn('diagnostic_unloaded_unit_not_process_state',G.evidence_claim_violations('unit 속성은 ActiveState=inactive, SubState=dead이며 실제 프로세스 상태는 미확인입니다.',facts))
 def test_invalid_receipt_does_not_acquire_trusted_source_display(self):
  rows=calls(P.completed(Q,'not-found'));facts=H.facts_for(rows);text=G.literal_evidence_table(facts);rows[0]['result_sha256']='0'*64
  self.assertIsNone(H.payload(rows[0]))
  self.assertIn('diagnostic_property_value_unverified',H.violations(Q,text,rows))

class ModelProjection(unittest.TestCase):
 def test_factual_confirmation_does_not_receive_raw_log_payloads(self):
  q='B Docker 현재 상태와 최근 5분 로그 보여줘';value=P.context(q)
  value['untrusted_completed_reads'][-1]['data']['entries']=[{'message_excerpt':'UNTRUSTED_RAW_LOG_PAYLOAD'}]
  messages=C.service_report_messages(value,{},[DIAG]);wire=json.dumps(messages,ensure_ascii=False)
  self.assertNotIn('UNTRUSTED_RAW_LOG_PAYLOAD',wire);self.assertIn('requested_service_scope',wire);self.assertIn('receipt_sha256',wire)
 def test_genuine_investigation_preserves_its_actual_payload(self):
  q='B Docker 현재 상태와 최근 5분 실제 로그에서 오류 원인 확인해줘';value=P.context(q)
  value['untrusted_completed_reads'][-1]['data']['entries']=[{'message_excerpt':'UNTRUSTED_RAW_LOG_PAYLOAD'}]
  self.assertIn('UNTRUSTED_RAW_LOG_PAYLOAD',json.dumps(C.service_report_messages(value,{},[DIAG]),ensure_ascii=False))

class NativeBinding(unittest.TestCase):
 def wire(self):
  rows=receipts();value=context(rows=rows);req=F.catalog();req.update(model='qwen3.6:35b',tool_choice='auto',messages=[{'role':'system','content':'FULL_POLICY'},{'role':'user','content':Q}])
  req['tools']=[t for t in req['tools'] if t['function']['name'] in {DIAG,INV}]
  names={DIAG,INV};schemas={t['function']['name']:t['function']['parameters'] for t in req['tools']}
  agent=SimpleNamespace(provider='custom',model='qwen3.6:35b',api_mode='chat_completions',base_url='http://10.200.10.10:11435/v1',_current_turn_id='current',valid_tool_names=names,_capstone_registered_read_conditions=('current',schemas))
  snapshot={'turn':'current','reads':sorted(names),'facts':H.facts_for(calls(rows)),
   'receipts':[{'tool':r['tool'],'is_error':r['is_error'],'output':json.dumps(r['data'])} for r in rows],
   'service_context':value,'service_attempts':rows}
  env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_SERVICE_REPORT_COMPACT':'1','CAPSTONE_SERVICE_DIRECT_READS':'0',
   'CAPSTONE_CHAT_READ_JSON':json.dumps({'request':Q,'background':'','tools':sorted(names),'requested_at_kst':AT})}
  with patch.dict(G.os.environ,env,clear=True):wire=G.management_report_request(req,agent,snapshot)
  return wire,agent,agent._capstone_management_selection
 def response(self,lease,nonce=None):
  report={k:v['const'] for k,v in lease['schema']['properties']['report']['properties'].items()}
  return SimpleNamespace(model='qwen3.6:35b',choices=[SimpleNamespace(finish_reason='stop',message=SimpleNamespace(content=json.dumps({'request_nonce':nonce or lease['nonce'],'more_evidence':False,'report':report}),tool_calls=None,refusal=None))])
 def decode(self,response,lease,agent):
  # The report branch never instantiates a tool call; no SDK dependency or skip.
  modules={n:ModuleType(n) for n in ['openai','openai.types','openai.types.chat']};modules['openai.types.chat'].ChatCompletionMessageToolCall=SimpleNamespace
  with patch.dict(sys.modules,modules):return G.management_selection_response(response,lease,agent)
 def test_native_wire_binds_identity_outside_model_payload(self):
  wire,a,lease=self.wire();self.assertEqual(lease['schema']['properties']['report']['properties']['scope']['const'],'unresolved_service_lookup')
  self.assertTrue(lease['service_lookup_identity']['missing_units']);self.assertNotIn('tools',wire)
  decoded,count=self.decode(self.response(lease),lease,a);self.assertEqual(count,0);self.assertEqual(G.management_status(decoded.choices[0].message.content),'needs_review')
  self.assertNotIn('INCIDENT_DISPOSITION',decoded.choices[0].message.content)
 def test_native_nonce_and_turn_replay_are_refused(self):
  wire,a,lease=self.wire()
  with self.assertRaises(Exception):self.decode(self.response(lease,'old-nonce'),lease,a)
  a._current_turn_id='later'
  with self.assertRaisesRegex(ValueError,'shape'):self.decode(self.response(lease),lease,a)
 def test_native_model_cannot_change_partial_to_resolved(self):
  wire,a,lease=self.wire();response=self.response(lease);value=json.loads(response.choices[0].message.content);value['report']['status']='resolved';response.choices[0].message.content=json.dumps(value)
  from jsonschema import ValidationError
  with self.assertRaises(ValidationError):self.decode(response,lease,a)

class SDKBinding(unittest.TestCase):
 def run_case(self,explicit=False,loaded=False,cause=False):
  import runtime
  target='b:docker' if loaded or cause else 'b:vector';question=('B Docker 최근 6분 실제 로그에서 오류 원인과 지금 상태 확인해줘' if cause else 'B '+('Docker' if loaded else 'Vector')+' 현재 상태와 최근 6분 로그 보여줘')
  dispatched=[];closed=[];seen=[]
  class Connector:
   async def list_tools(self):return [SimpleNamespace(name=t['name'],description=t['description'],inputSchema=t['inputSchema']) for t in F.M.tools() if t['name'] in ['get_system_diagnostics','get_host_inventory']]
   async def call_tool(self,name,args,**kw):
    dispatched.append((name,copy.deepcopy(args)))
    if name=='get_host_inventory':data=F.page(args['view'],[{'unit':'unrelated.service'}] if args['view']=='services' else [{'name':'unrelated'}],1)['data']
    elif args.get('view')=='journal':data=P.journal(args)
    elif args['target']=='b:collection':data={'schema':1,'target':'b:collection','host':'b','kind':'runtime','status':'ok','mutation_performed':False,'observed_at_kst':AT,'codes':[],'metrics':{},'lookback_scope':'latest_snapshot_only_not_requested_history'}
    else:data=F.current(args['target'],'loaded' if loaded or cause else 'not-found')
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
   async def run(self,*a,**kw):raise AssertionError('unexpected unconstrained model')
  class Model:
   def __init__(self,**kw):pass
   def with_structured_output(self,schema,**kw):
    async def invoke(messages):
     seen.append(copy.deepcopy(schema))
     if 'indexes' in schema.get('properties',{}):
      body=json.loads(messages[1][1]);return {'indexes':list(range(len(body['options'])))}
     if 'calls' in schema.get('properties',{}):return {'calls':[{'tool':DIAG,'arguments':{'target':target}}]}
     fields=schema.get('properties',{}).get('report',{}).get('properties',{})
     if fields and all('const' in value for value in fields.values()):return {'more_evidence':False,'report':{k:v['const'] for k,v in fields.items()}}
     branch=next(b for b in schema['anyOf'] if b['properties']['more_evidence']['const'] is False);fields=branch['properties']['report']['properties']
     value={'assessment':'unresolved','status':'needs_review','basis':'반환된 journal 표본과 현재 unit 속성을 확인했으며 원인과 전체 기능 영향은 미확인입니다.',
      'limitations':['표본은 전체 기록과 기능 검증을 대신하지 않습니다.'],'next_steps':[],'evidence_indexes':fields['evidence_indexes']['const']}
     if 'current_observation' in fields:value['current_observation']='현재 unit 속성과 실제 기능 영향은 별도이며 추가 기능 근거는 미확인입니다.'
     return {'more_evidence':False,'report':value}
    return SimpleNamespace(ainvoke=invoke)
  names=['mcp_use','mcp_use.agents','mcp_use.agents.adapters','mcp_use.agents.adapters.langchain_adapter','langchain_ollama','langchain_core','langchain_core.tools','langchain_core.callbacks'];modules={n:ModuleType(n) for n in names}
  modules['mcp_use'].MCPClient=Client;modules['mcp_use'].MCPAgent=Agent;modules['mcp_use.agents.adapters.langchain_adapter'].LangChainAdapter=object
  modules['langchain_ollama'].ChatOllama=Model;modules['langchain_core.tools'].StructuredTool=Tool;modules['langchain_core.callbacks'].AsyncCallbackHandler=object
  request={'question':question}
  if explicit:request['tools']=[DIAG]
  with patch.dict(sys.modules,modules),patch.object(runtime,'capabilities',return_value={'system-diagnostics':['get_system_diagnostics','get_host_inventory']}),patch.object(runtime,'filter_catalog',side_effect=lambda *a:a[1]):
   report=asyncio.run(runtime.run({'model':'fixture','base_url':'http://127.0.0.1:11434','access_mode':'hermes-parity','mcpServers':{'system-diagnostics':{}}},request))
  return report,dispatched,closed,seen
 def test_sdk_partial_scope_is_projected_without_free_prose(self):
  report,calls_,closed,seen=self.run_case();self.assertNotIn('error_type',report);self.assertEqual(report['status'],'partial');self.assertEqual(closed,[True])
  self.assertEqual(report['last_service_review']['scope'],'unresolved_service_lookup');self.assertEqual(report['protected_calls'],0)
  self.assertIn('구성요소 식별 미확인',report['final_response']);self.assertNotIn('관련 컨테이너',report['final_response'])
 def test_sdk_explicit_tool_subset_is_not_expanded(self):
  report,calls_,closed,seen=self.run_case(explicit=True);self.assertNotIn('error_type',report)
  self.assertFalse(any(name=='get_host_inventory' for name,args in calls_));self.assertIn('inventory_capability_unavailable',report['final_response'])
 def test_sdk_loaded_scope_is_completed_as_a_lookup(self):
  report,calls_,closed,seen=self.run_case(loaded=True);self.assertNotIn('error_type',report)
  self.assertTrue(report['service_lookup_complete']);self.assertEqual(report['last_service_review']['scope'],'verified_service_lookup')
 def test_sdk_cause_request_keeps_model_investigation(self):
  report,calls_,closed,seen=self.run_case(cause=True);self.assertNotIn('error_type',report)
  self.assertNotIn('scope',report['last_service_review']);self.assertTrue(any(args.get('view')=='journal' for name,args in calls_))

class UnchangedBoundaries(unittest.TestCase):
 def test_control_and_citation_checks_still_receive_the_original_text(self):
  facts=with_source_quote();text=G.literal_evidence_table(facts)
  with patch.object(G,'disposition_citation_violations',return_value=[]) as control:
   G.evidence_claim_violations(text,facts)
  self.assertEqual(control.call_args.args[0],text)
 def test_unresolved_lookup_is_not_sentence_pruned_into_a_verdict(self):
  self.assertEqual(C.prune_rejected_review(partial_report(),[],['diagnostic_unloaded_unit_not_process_state']),(None,0))
 def test_conditional_property_attribution_is_not_an_assertion(self):
  facts=H.facts_for(calls(P.completed(Q,'not-found')))
  self.assertNotIn('diagnostic_unloaded_unit_not_process_state',G.evidence_claim_violations('프로세스 상태가 ActiveState=inactive라면 추가 조회가 필요합니다.',facts))
 def test_factual_confirmation_policy_is_loaded_once_from_existing_skill_section(self):
  value=context();messages=C.service_report_messages(value,{},[DIAG,INV]);section=C.workflow_policy(('soc-query',),section='factual-service-lookup')
  self.assertEqual(messages[0]['content'].count(section),1)
  self.assertNotIn('## 서비스 사실 조회 확인',C.workflow_policy(('soc-query',)))

if __name__=='__main__':unittest.main()
