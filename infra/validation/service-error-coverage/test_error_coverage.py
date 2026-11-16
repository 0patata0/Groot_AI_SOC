"""Message scope and real filtered-source alternatives; no model/network."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import copy,hashlib,importlib.util,json,os,unittest

ROOT=Path(os.environ['SOC_ERROR_COVERAGE_ROOT']).resolve()
os.environ['SOC_PROVENANCE_ROOT']=str(ROOT)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
V=load('error_parent_provenance',Path(os.environ.get('SOC_PROVENANCE_TEST',Path(__file__).parents[3]/'infra/validation/service-provenance/test_service_provenance.py')))
P=V.P;F=V.F;C=V.C;G=V.G;H=V.H;D=P.D;DIAG=V.DIAG;INV=V.INV;AT=V.AT;NOW=V.NOW
Q='B Docker 현재 상태와 최근 7분 오류 로그로 원인 확인해줘'
def plan(q=Q,request=None):return C.service_history_plan(request or F.catalog(),q,AT)
def rows(q=Q):return P.completed(q)
def options(q=Q,rs=None,request=None):return C.service_journal_unfiltered_options(request or F.catalog(),rows(q) if rs is None else rs,plan(q,request))

class RequestedScope(unittest.TestCase):
 def test_all_registered_raw_log_cause_requests_do_not_silently_filter(self):
  from jsonschema import Draft202012Validator
  for target,unit in D.TARGETS.items():
   if not isinstance(unit,str):continue
   q=target+' 최근 7분 실제 로그에서 오류 원인과 지금 상태 확인해줘'
   p=plan(q);past=[r for r in p['requirements'] if r['arguments'].get('view')=='journal']
   self.assertEqual(len(past),1,target);self.assertEqual(past[0]['arguments']['journal_scope'],'all',target)
   self.assertFalse(C.service_lookup_scope(p,q),target)
   Draft202012Validator(F.catalog()['tools'][0]['function']['parameters']).validate(past[0]['arguments'])
 def test_log_postpositions_do_not_change_scope_to_error_candidates(self):
  for noun in ['로그에서','로그에도','로그로부터','로그들에서','로그만','로그로']:
   q='B Docker 최근 7분 실제 '+noun+' 오류 원인과 현재 상태 확인해줘'
   self.assertEqual(next(r['arguments'] for r in plan(q)['requirements'] if r['arguments'].get('view')=='journal')['journal_scope'],'all')
 def test_requested_error_logs_keep_their_filter(self):
  for q in [Q,'B Docker 최근 7분 오류 로그만 보여줘','B Docker 최근 7분 에러 로그 보여줘','B Docker 최근 7분 error logs 보여줘']:
   p=plan(q);past=[r['arguments'] for r in p['requirements'] if r['arguments'].get('view')=='journal']
   self.assertTrue(past,q);self.assertTrue(all(r.get('journal_scope','errors')=='errors' for r in past),q)
 def test_explicit_all_and_normal_logs_are_not_error_only(self):
  for words in ['오류 원인과 전체 로그','오류 로그와 정상 로그','all logs 오류 원인','필터 없이 실제 로그 오류 원인']:
   q='B Docker 최근 7분 '+words+' 확인해줘'
   self.assertTrue(all(r['arguments'].get('journal_scope')=='all' for r in plan(q)['requirements'] if r['arguments'].get('view')=='journal'),q)
 def test_default_cause_window_and_plain_lookup_window_preserved(self):
  p=plan('B Docker 오류 원인 조사해줘');self.assertEqual(p['initial_history_window_minutes'],1440)
  self.assertEqual(next(r['arguments'] for r in p['requirements'] if r['arguments'].get('view')=='journal').get('journal_scope','errors'),'errors')
  self.assertEqual(plan('B Docker 로그 보여줘')['initial_history_window_minutes'],15)
 def test_explicit_metadata_is_not_silently_replaced(self):
  p=plan('B Docker 최근 7분 오류 이력 색인 메타데이터 보여줘')
  self.assertTrue(any('since_kst' in r['arguments'] for r in p['requirements']))
  self.assertFalse(any(r['arguments'].get('view')=='journal' for r in p['requirements']))
 def test_unknown_target_host_or_negated_lookup_is_not_forced(self):
  for q in ['D Docker 최근 7분 실제 로그에서 오류 원인 확인','B 가짜엔진 최근 7분 실제 로그에서 오류 원인 확인','B Docker 로그 조회하지 마']:
   self.assertIsNone(plan(q),q)
 def test_all_capability_absence_is_visible_not_narrowed_to_errors(self):
  request=F.catalog();request['tools'][0]['function']['parameters']['properties']['journal_scope']['enum']=['errors']
  p=plan('B Docker 최근 7분 실제 로그에서 오류 원인 확인해줘',request)
  self.assertIn('journal_excerpt',p['unavailable_capabilities'])
  self.assertFalse(any(r['arguments'].get('view')=='journal' for r in p['requirements']))
  self.assertIn('journal_excerpt:tool_capability_unavailable',C.service_history_state(p,[],NOW)['incomplete'])

class UnfilteredOptions(unittest.TestCase):
 def test_successful_zero_filter_offers_unexecuted_same_scope_source(self):
  out=options();self.assertEqual(len(out),1)
  source=next(r for r in rows() if r['arguments'].get('view')=='journal')
  self.assertEqual(out[0]['call']['arguments'],{**source['arguments'],'journal_scope':'all','limit':50})
  self.assertEqual(out[0]['returned_filtered_rows'],0);self.assertIn('unexecuted',out[0]['coverage'])
  self.assertEqual(out[0]['source_receipt_sha256'],source['receipt_sha256'])
 def test_nonzero_candidates_are_not_assumed_to_contain_all_context(self):
  rs=rows();row=next(r for r in rs if r['arguments'].get('view')=='journal')
  # The library constructs a valid masked excerpt, not an invented error count.
  library=P.load('error_fixture_journal',ROOT/'infra/mcp/diagnostic_journal.py');library.core=D
  history=P.load('error_fixture_history',ROOT/'infra/mcp/diagnostic_history.py');history.core=D
  def runner(*args):
   event={'_SYSTEMD_UNIT':'docker.service','__REALTIME_TIMESTAMP':str(history.instant(AT)-60000000),
    '__CURSOR':'error-fixture','PRIORITY':'3','MESSAGE':'Failed with result exit-code'}
   return 0,(json.dumps(event)+'\n').encode()
  with patch.object(D,'_history',history):row['data']=library.answer(row['arguments'],'b',history.QueryClock(int(NOW.timestamp()),history.instant(AT)),runner=runner)
  out=options(rs=rs);self.assertEqual(len(out),1);self.assertEqual(out[0]['returned_filtered_rows'],1)
 def test_failed_filter_is_not_a_successful_coverage_observation(self):
  rs=rows();next(r for r in rs if r['arguments'].get('view')=='journal')['is_error']=True
  self.assertEqual(options(rs=rs),[])
 def test_unbound_host_or_time_receipt_cannot_offer_new_scope(self):
  for mutation in ['host','time']:
   rs=rows();r=next(x for x in rs if x['arguments'].get('view')=='journal')
   if mutation=='host':r['arguments']['target']='a:docker';r['data']['target']='a:docker'
   else:r['arguments']['since_kst']='2026-11-08T01:00:00+09:00'
   self.assertEqual(options(rs=rs),[],mutation)
 def test_wrong_returned_scope_or_window_is_not_accepted(self):
  for k,v in [('journal_scope','all'),('requested_since_kst','2026-11-08T01:00:00+09:00'),('target','a:docker')]:
   rs=rows();next(r for r in rs if r['arguments'].get('view')=='journal')['data'][k]=v
   self.assertEqual(options(rs=rs),[],k)
 def test_receipt_provenance_identifier_is_required(self):
  for v in [None,'not-a-hash','0'*63]:
   rs=rows();next(r for r in rs if r['arguments'].get('view')=='journal')['receipt_sha256']=v
   self.assertEqual(options(rs=rs),[])
 def test_same_alternative_is_not_repeated_after_success_or_failure(self):
  for failed in [False,True]:
   rs=rows();choice=options(rs=rs)[0]['call'];rs.append(F.receipt(DIAG,choice['arguments'],P.journal(choice['arguments'])))
   rs[-1]['is_error']=failed
   self.assertEqual(options(rs=rs),[],failed)
 def test_completed_all_request_has_no_expansion(self):
  q='B Docker 최근 7분 실제 로그에서 오류 원인 확인해줘';self.assertEqual(options(q),[])
 def test_catalog_without_all_scope_does_not_offer_unregistered_read(self):
  request=F.catalog();request['tools'][0]['function']['parameters']['properties']['journal_scope']['enum']=['errors']
  self.assertEqual(options(request=request),[])
 def test_options_do_not_mutate_the_original_question_or_receipts(self):
  rs=rows();before=copy.deepcopy(rs);options(rs=rs);self.assertEqual(rs,before)
 def test_duplicate_receipt_does_not_duplicate_alternative(self):
  rs=rows();rs.append(copy.deepcopy(rs[-1]));self.assertEqual(len(options(rs=rs)),1)
 def test_empty_filter_cannot_be_presented_as_completed_cause_context(self):
  self.assertIsNone(P.context(Q))
  rs=rows();choice=options(rs=rs)[0]['call'];rs.append(F.receipt(DIAG,choice['arguments'],P.journal(choice['arguments'])))
  value=P.context(Q,rs);self.assertIsNotNone(value);self.assertNotIn('lookup_only',value)
 def test_alternative_is_not_successful_read_or_causal_evidence(self):
  rs=rows();before=copy.deepcopy(rs);options(rs=rs);self.assertEqual(rs,before)
  self.assertTrue(C.service_history_state(plan(),rs,NOW)['pending'])

class PathBinding(unittest.TestCase):
 def test_sdk_dispatch_uses_all_for_explicit_cause_logs(self):
  report,dispatched,closed,seen=V.SDKBinding().run_case(cause=True)
  self.assertNotIn('error_type',report);self.assertEqual(closed,[True])
  self.assertTrue(any(args.get('view')=='journal' and args.get('journal_scope')=='all' for name,args in dispatched))
  self.assertNotIn('scope',report['last_service_review'])
 def test_sdk_completes_empty_error_source_through_model_selected_real_dispatch(self):
  import runtime
  original=runtime.run
  def rewrite(cfg,request,**kw):return original(cfg,{**request,'question':Q},**kw)
  with patch.object(runtime,'run',new=rewrite):report,dispatched,closed,seen=V.SDKBinding().run_case(cause=True)
  self.assertNotIn('error_type',report);self.assertEqual(closed,[True])
  scopes=[args.get('journal_scope','errors') for name,args in dispatched if args.get('view')=='journal']
  self.assertEqual(scopes,['errors','all']);self.assertEqual(report['protected_calls'],0)
 def test_native_offers_the_same_bound_pending_source_before_judgment(self):
  rs=rows();req=F.catalog();names=[DIAG,INV]
  env={'CAPSTONE_MANAGEMENT_MODE':'verify','CAPSTONE_CHAT_READ_JSON':json.dumps({'request':Q,'background':'','tools':names,'requested_at_kst':AT})}
  with patch.dict(G.os.environ,env,clear=True):
   # G loads the same file in its own module; bind its state clock explicitly.
   contract=G.diagnostic_contract();original=contract.service_history_state
   with patch.object(contract,'service_history_state',side_effect=lambda p,r,now=None,**kw:original(p,r,NOW if now is None else now,**kw)):
    pending=G.operator_diagnostic_options(req,rs)
  self.assertEqual(pending,[options()[0]['call']])

class EmptySourceClosure(unittest.TestCase):
 def test_actual_zero_filter_requires_same_scope_all_read(self):
  value=C.service_history_state(plan(),rows(),NOW)
  self.assertEqual(value['pending'],[options()[0]['call']]);self.assertTrue(value['incomplete'])
 def test_zero_all_read_finishes_evidence_without_a_normal_verdict(self):
  rs=rows();choice=options()[0]['call'];rs.append(F.receipt(DIAG,choice['arguments'],P.journal(choice['arguments'])))
  self.assertEqual(C.service_history_state(plan(),rs,NOW),{'pending':[],'incomplete':[]})
  value=P.context(Q,rs);self.assertNotIn('lookup_only',value)
 def test_failed_all_read_is_a_gap_not_an_infinite_retry(self):
  rs=rows();choice=options()[0]['call'];rs.append(F.receipt(DIAG,choice['arguments'],{},error=True))
  value=C.service_history_state(plan(),rs,NOW)
  self.assertEqual(value['pending'],[]);self.assertTrue(value['incomplete'])
 def test_wrong_scope_or_time_cannot_complete_the_source_read(self):
  for changed in [('target','a:docker'),('since_kst','2026-11-08T00:00:00+09:00')]:
   rs=rows();choice=copy.deepcopy(options()[0]['call']);choice['arguments'][changed[0]]=changed[1]
   rs.append(F.receipt(DIAG,choice['arguments'],P.journal(choice['arguments'])))
   self.assertTrue(C.service_history_state(plan(),rs,NOW)['incomplete'])
 def test_explicit_error_only_constraint_is_preserved(self):
  q='B Docker 최근 7분 오류 로그만으로 원인 확인해줘';p=plan(q)
  self.assertFalse(p['cause_source_coverage']['required'])
  self.assertEqual(C.service_history_state(p,rows(q),NOW)['pending'],[])
 def test_noncausal_error_lookup_does_not_trigger_all(self):
  q='B Docker 최근 7분 오류 로그만 보여줘'
  self.assertEqual(C.service_history_state(plan(q),rows(q),NOW)['pending'],[])
 def test_missing_all_capability_is_explicit_without_an_unregistered_call(self):
  request=F.catalog();request['tools'][0]['function']['parameters']['properties']['journal_scope']['enum']=['errors']
  value=C.service_history_state(plan(Q,request),rows(),NOW)
  self.assertEqual(value['pending'],[]);self.assertTrue(any('unfiltered_journal:tool_capability_unavailable' in x for x in value['incomplete']))
 def test_stale_filter_cannot_trigger_a_new_coverage_observation(self):
  rs=rows();next(r for r in rs if r['arguments'].get('view')=='journal')['data']['observed_at_kst']='2026-11-07T00:00:00+09:00'
  value=C.service_history_state(plan(),rs,NOW);self.assertTrue(value['incomplete']);self.assertEqual(value['pending'],[])

class ClaimBoundaries(unittest.TestCase):
 def facts(self):return H.facts_for(V.calls(rows()))
 def test_no_such_file_does_not_prove_file_loss(self):
  self.assertIn('diagnostic_file_loss_unverified',G.evidence_claim_violations('관련 파일이 손실되었음을 나타냅니다.',self.facts()))
 def test_loss_uncertainty_conditional_and_negative_proof_are_allowed(self):
  for text in ['관련 파일의 손실은 미확인입니다.','파일이 손실되었다면 추가 조회가 필요합니다.','파일이 손실되었다고 단정할 수 없습니다.']:
   self.assertNotIn('diagnostic_file_loss_unverified',G.evidence_claim_violations(text,self.facts()),text)
 def test_generic_current_state_is_not_functional_health(self):
  self.assertIn('diagnostic_snapshot_is_not_functional_health',G.evidence_claim_violations('현재 상태는 정상 작동 중으로 관측되었습니다.',self.facts()))
 def test_current_property_values_and_health_uncertainty_remain_allowed(self):
  for text in ['현재 상태는 ActiveState=active, SubState=running으로 관측됩니다.','현재 상태가 정상 작동 중인지 미확인입니다.']:
   self.assertNotIn('diagnostic_snapshot_is_not_functional_health',G.evidence_claim_violations(text,self.facts()),text)
 def test_exact_authenticated_quote_does_not_become_a_new_loss_claim(self):
  facts=V.with_source_quote('관련 파일이 손실되었습니다.');text=G.literal_evidence_table(facts)
  self.assertNotIn('diagnostic_file_loss_unverified',G.evidence_claim_violations(text,facts))
  self.assertIn('diagnostic_file_loss_unverified',G.evidence_claim_violations(text+'\n관련 파일이 손실되었습니다.',facts))

class HostAndProjection(unittest.TestCase):
 def source(self):
  q='B systemd 최근 7분 실제 로그에서 실패 원인 확인해줘';p=plan(q)
  call=next(r for r in p['requirements'] if r['arguments'].get('view')=='journal')
  library=P.load('projection_journal_fixture',ROOT/'infra/mcp/diagnostic_journal.py');library.core=D
  history=P.load('projection_history_fixture',ROOT/'infra/mcp/diagnostic_history.py');history.core=D
  def runner(*args):
   event={'_SYSTEMD_UNIT':'ssh.service','_TRANSPORT':'syslog','__REALTIME_TIMESTAMP':str(history.instant(AT)-60000000),
    '__CURSOR':'projection-fixture','PRIORITY':'6','MESSAGE':'APP_LOG_TEXT_KEEP_VERBATIM session opened'}
   return 0,(json.dumps(event)+'\n').encode()
  with patch.object(D,'_history',history):data=library.answer(call['arguments'],'b',history.QueryClock(int(NOW.timestamp()),history.instant(AT)),runner=runner)
  return q,[F.receipt(DIAG,call['arguments'],data)]
 def test_host_journal_is_not_an_unnamed_service_or_unit(self):
  q,rs=self.source();facts=H.facts_for(V.calls(rs))
  self.assertIn('diagnostic_host_journal_not_unit',G.evidence_claim_violations('해당 서비스의 실제 실행 이력이나 unit 이름 불일치는 미확인입니다.',facts))
 def test_exact_observed_unit_can_be_named_and_referred_to(self):
  q,rs=self.source();facts=H.facts_for(V.calls(rs))
  self.assertNotIn('diagnostic_host_journal_not_unit',G.evidence_claim_violations('ssh.service의 메시지입니다. 해당 서비스가 남긴 접속 로그의 표본입니다.',facts))
 def test_explicit_host_not_single_service_statement_is_allowed(self):
  q,rs=self.source();facts=H.facts_for(V.calls(rs))
  self.assertNotIn('diagnostic_host_journal_not_unit',G.evidence_claim_violations('호스트 journal은 해당 서비스가 아닙니다.',facts))
 def test_cause_projection_preserves_every_message_and_its_scope(self):
  q,rs=self.source();value=P.context(q,rs);messages=C.service_report_messages(value,{DIAG:'diagnostics'},[DIAG])
  wire=json.loads(messages[1]['content']);original=rs[0]['data'];projected=wire['untrusted_completed_reads'][0]['data']
  for name in ['requested_since_kst','requested_until_kst','journal_scope','has_more','response_size_limited','requested_window_total_count','journal_target_scope']:
   self.assertEqual(projected[name],original[name],name)
  for key in ['message_excerpt','at_kst','priority','source_units','source_transport','message_state']:
   self.assertEqual(projected['entries'][0][key],original['entries'][0][key],key)
 def test_per_row_hashes_stay_in_original_audit_without_model_repetition(self):
  q,rs=self.source();value=P.context(q,rs);before=copy.deepcopy(value)
  messages=C.service_report_messages(value,{DIAG:'diagnostics'},[DIAG]);wire=json.dumps(messages,ensure_ascii=False)
  for k in ['record_sha256','message_sha256','excerpt_sha256']:self.assertNotIn(rs[0]['data']['entries'][0][k],wire)
  self.assertEqual(value,before);self.assertEqual(value['untrusted_completed_reads'][0]['receipt_sha256'],rs[0]['receipt_sha256'])
 def test_projected_message_text_is_never_an_instruction_or_approval(self):
  q,rs=self.source();value=P.context(q,rs);wire=C.service_report_messages(value,{DIAG:'diagnostics'},[DIAG])
  self.assertIn('불신',wire[0]['content']);self.assertIn('승인',wire[0]['content'])
  self.assertIn(rs[0]['data']['entries'][0]['message_excerpt'],wire[1]['content'])

class ReportSchemaRecovery(unittest.TestCase):
 def report(self):return {'more_evidence':False,'report':{'assessment':'unresolved','status':'needs_review','basis':'확인된 로그와 현재 속성을 구분했으며 원인은 미확인입니다.','evidence_indexes':[0],'limitations':['근본 원인과 현재 기능 영향은 미확인입니다.'],'next_steps':['실제 추가 근거를 확인해야 합니다.']}}
 def test_long_report_feedback_identifies_exact_field_without_tool_execution(self):
  schema=C.service_report_schema([DIAG]);value=self.report();value['report']['basis']='가'*600
  feedback=C.service_schema_repair_feedback(value,schema)
  self.assertTrue(any(x['path']==['report','basis'] and x['validator']=='maxLength' and x['expected']==512 for x in feedback['schema_validation_errors']))
  self.assertEqual(len(feedback['untrusted_invalid_report']['basis']),600)
 def test_valid_response_does_not_generate_schema_repair_feedback(self):
  with self.assertRaisesRegex(ValueError,'requires_invalid'):C.service_schema_repair_feedback(self.report(),C.service_report_schema([DIAG]))
 def test_invalid_tool_shape_is_data_not_an_executable_call(self):
  feedback=C.service_schema_repair_feedback({'more_evidence':True,'report':None,'calls':[{'tool':'unregistered','arguments':{'cmd':'never execute'}}]},C.service_report_schema([DIAG]))
  self.assertNotIn('calls',feedback);self.assertNotIn('never execute',json.dumps(feedback))
 def test_unknown_file_loss_cause_is_not_a_positive_loss_assertion(self):
  facts=H.facts_for(V.calls(rows()))
  for text in ['오류의 직접적인 파일 손실 원인 및 서비스 지속 영향은 미확인입니다.','파일 조회 실패의 직접적인 원인(파일 손실·삭제 주체)은 확인되지 않았습니다.']:
   self.assertNotIn('diagnostic_file_loss_unverified',G.evidence_claim_violations(text,facts),text)
  self.assertIn('diagnostic_file_loss_unverified',G.evidence_claim_violations('관련 파일이 삭제되어 실패했습니다.',facts))
 def test_cached_snapshot_count_is_grouped_away_from_requested_journal(self):
  q='B Docker 최근 7분 실제 로그에서 오류 원인과 현재 상태 확인해줘';value=P.context(q);before=copy.deepcopy(value)
  for r in value['untrusted_completed_reads']:
   if 'properties' in r['data']:r['data']['returned_error_count']=0;r['data']['requested_since_kst']='2026-11-08T00:00:00+09:00'
  before=copy.deepcopy(value);body=json.loads(C.service_report_messages(value,{DIAG:'diagnostics'},[DIAG])[1]['content'])
  current=next(r['data'] for r in body['untrusted_completed_reads'] if 'properties' in r['data'])
  self.assertNotIn('returned_error_count',current)
  self.assertEqual(current['cached_snapshot_sample_not_requested_journal']['returned_error_count'],0)
  self.assertEqual(value,before)
 def test_sdk_repairs_schema_once_without_rereading_the_same_evidence(self):
  import runtime,sys
  original=runtime.run;injected=[]
  async def rewrite(cfg,request,**kw):
   base=sys.modules['langchain_ollama'].ChatOllama
   class Model(base):
    def with_structured_output(self,schema,**options):
     runner=super().with_structured_output(schema,**options)
     async def invoke(messages):
      value=await runner.ainvoke(messages)
      if isinstance(value.get('report'),dict) and 'basis' in value['report'] and not injected:
       value['report']['basis']='가'*600;injected.append(True)
      return value
     return SimpleNamespace(ainvoke=invoke)
   with patch.object(sys.modules['langchain_ollama'],'ChatOllama',Model):return await original(cfg,request,**kw)
  with patch.object(runtime,'run',new=rewrite):report,dispatched,closed,seen=V.SDKBinding().run_case(cause=True)
  self.assertNotIn('error_type',report);self.assertEqual(report['service_schema_repairs'],1)
  self.assertEqual(len(dispatched),2);self.assertEqual(closed,[True]);self.assertEqual(report['protected_calls'],0)
  self.assertEqual(len(report['service_report_audit'][0]['response']['report']['basis']),600)

if __name__=='__main__':unittest.main()
