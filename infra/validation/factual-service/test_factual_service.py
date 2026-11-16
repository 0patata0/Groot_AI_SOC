"""Factual service scope, source limits and reporting; no model or network."""
from pathlib import Path
from datetime import datetime,timedelta
from unittest.mock import patch
import copy,hashlib,importlib.util,json,os,sys,unittest
ROOT=Path(os.environ['SOC_FACTUAL_ROOT']).resolve()
os.environ['SOC_TYPED_ROOT']=str(ROOT)
sys.path[:0]=[str(ROOT/'infra/mcp'),str(ROOT/'infra/ollama-trial')]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
F=load('factual_parent_fixtures',Path(os.environ.get('SOC_TYPED_TEST',Path(__file__).parents[3]/'infra/validation/typed-service/test_typed_service.py')))
C=F.C;G=F.G;H=F.H;D=F.D;DIAG=F.DIAG;INV=F.INV;AT=F.AT;NOW=F.NOW
def plan(q,request=None):return C.service_history_plan(request or F.catalog(),q,AT)
def scope(q,request=None):return C.service_lookup_scope(plan(q,request),q)
def journal(args,entries=None):
 entries=entries or []
 return {'schema':1,'kind':'journal_excerpt','status':'observed','target':args['target'],'host':args['target'][0],
  'unit':D.TARGETS[args['target']],'mutation_performed':False,'observed_at_kst':AT,'live_query':True,
  'requested_since_kst':args['since_kst'],'requested_until_kst':args['until_kst'],
  'journal_scope':args.get('journal_scope','errors'),'entries':entries,'returned_entries':len(entries),
  'has_more':False,'requested_window_total_count':None,'journal_retention_verified':False,
  'raw_messages_returned':False,'redacted_excerpts_returned':True,'response_size_limited':False,'untrusted_evidence':True}
def completed(q,load_state='loaded'):
 rows=[]
 for r in plan(q)['requirements']:
  args=r['arguments'];target=args['target']
  if args.get('view')=='journal':data=journal(args)
  elif 'since_kst' in args:
   data={'schema':1,'kind':'journal_history','status':'observed','target':target,'host':target[0],
    'unit':D.TARGETS[target],'mutation_performed':False,'observed_at_kst':AT,'age_seconds':0,
    'requested_since_kst':args['since_kst'],'requested_until_kst':args['until_kst'],
    'history_coverage':{},'has_more':False}
  elif target.endswith(':collection'):
   data={'schema':1,'kind':'runtime','status':'ok','target':target,'host':target[0],
    'mutation_performed':False,'observed_at_kst':AT,'metrics':{},'codes':[],
    'lookback_scope':'latest_snapshot_only_not_requested_history'}
  else:data=F.current(target,load_state)
  rows.append(F.receipt(r['tool'],args,data))
 return rows
def context(q,rows=None):
 return C.service_report_context(F.catalog(),q,AT,completed(q) if rows is None else rows,
  now=NOW,allowed_reads={DIAG,INV})

class FactualScope(unittest.TestCase):
 def absolute_scope(self,q,at):
  # The reference instant belongs to this fixture, never the wall-clock hour.
  instant=datetime.fromisoformat(at)
  class Clock(datetime):
   @classmethod
   def now(cls,tz=None):return instant.astimezone(tz) if tz else instant.replace(tzinfo=None)
  with patch.object(C,'datetime',Clock):
   return C.service_lookup_scope(C.service_history_plan(F.catalog(),q,at),q)
 def test_observed_short_state_and_recent_logs_are_a_lookup(self):
  self.assertTrue(scope('B Docker 현재 상태와 최근 5분 로그 보여줘.'))
 def test_all_registered_short_labels_use_actual_catalog(self):
  for target,unit in D.TARGETS.items():
   if not isinstance(unit,str):continue
   q=target[0].upper()+' '+target.split(':',1)[1].upper()+' 현재 상태와 최근 7분 로그 보여줘'
   with self.subTest(target=target):self.assertTrue(scope(q))
 def test_registered_display_names_and_case_are_not_unknown_clauses(self):
  request=F.catalog();prop=request['tools'][0]['function']['parameters']['properties']['target']
  prop['x-capstone-service-labels']={'b:docker':['컨테이너 엔진']}
  self.assertTrue(scope('B 컨테이너 엔진 현재 상태와 최근 4분 로그 보여줘',request))
 def test_no_invented_alias_or_unknown_host(self):
  for q in ['B 가짜엔진 현재 상태와 최근 4분 로그 보여줘','D Docker 최근 4분 로그 보여줘','Docker 최근 4분 로그 보여줘']:
   with self.subTest(q=q):self.assertFalse(scope(q))
 def test_relative_time_units_are_bound_not_generic_noise(self):
  for period in ['최근 9초','지난 17분','최근 2시간','지난 1일']:
   with self.subTest(period=period):self.assertTrue(scope('B Docker '+period+' 로그 보여줘'))
 def test_ambiguous_approximate_or_invalid_period_not_closed(self):
  for period in ['최근 0초','최근 25시간','최근 5분 또는 7분','대략 최근 5분','UTC 최근 5분','최근 5분 이전']:
   with self.subTest(period=period):self.assertFalse(scope('B Docker '+period+' 로그 보여줘'))
 def test_natural_absolute_period_uses_the_same_parse(self):
  for period in ['오늘 오전 1시 10분부터 오전 1시 20분까지','오늘 01:10~01:20 KST']:
   with self.subTest(period=period):self.assertTrue(self.absolute_scope('B Docker '+period+' 로그 보여줘','2026-11-16T12:00:00+09:00'))
 def test_today_future_period_stays_outside_factual_completion(self):
  for period in ['오늘 오전 1시 10분부터 오전 1시 20분까지','오늘 01:10~01:20 KST']:
   with self.subTest(period=period):self.assertFalse(self.absolute_scope('B Docker '+period+' 로그 보여줘','2026-11-16T00:30:00+09:00'))
 def test_yesterday_period_is_valid_on_both_sides_of_midnight(self):
  for at in ['2026-11-16T23:30:00+09:00','2026-11-17T00:30:00+09:00']:
   with self.subTest(at=at):self.assertTrue(self.absolute_scope('B Docker 어제 01:10~01:20 KST 로그 보여줘',at))
 def test_plain_style_and_conjunctions_do_not_require_causal_prose(self):
  for style in ['간단히','간단하게','짧게','표로']:
   with self.subTest(style=style):self.assertTrue(scope('B Vector 지금 상태랑 최근 5분 로그 '+style+' 보여줘'))
 def test_real_cause_impact_comparison_write_and_extra_scope_retained(self):
  for suffix in [' 왜 그랬는지도 알려줘',' 원인도 확인해줘',' 영향도 알려줘',' 정상인지 판단해줘',' 어제와 비교해줘',
   ' 재시작해줘',' 설정도 보여줘',' CPU도 보여줘',' 전체 누락 없이 보여줘',' 파일이 없는지 확인해줘']:
   with self.subTest(suffix=suffix):self.assertFalse(scope('B Docker 현재 상태와 최근 5분 로그 보여줘'+suffix))
 def test_actual_window_and_current_reads_remain_mandatory(self):
  q='B Docker 현재 상태와 최근 5분 로그 보여줘';p=plan(q)
  self.assertEqual(len(p['requirements']),2)
  past=next(r['arguments'] for r in p['requirements'] if 'since_kst' in r['arguments'])
  self.assertEqual(past['until_kst'],AT)
  self.assertEqual(C._diagnostic_instant(AT)-C._diagnostic_instant(past['since_kst']),timedelta(minutes=5))
  self.assertEqual(past['journal_scope'],'all')
 def test_postpositions_still_require_real_log_messages(self):
  for noun in ['로그에서','로그에도','로그로부터','로그들에서','로그만','로그로']:
   q='B Docker 최근 10분 실제 '+noun+' 오류 원인과 지금 상태 확인해줘'
   with self.subTest(noun=noun):
    p=plan(q);self.assertTrue(C.service_log_request(q));self.assertTrue(any(r['arguments'].get('view')=='journal' for r in p['requirements']))
    self.assertFalse(scope(q));self.assertFalse(any('since_kst' in r['arguments'] and 'view' not in r['arguments'] for r in p['requirements']))
 def test_embedded_login_and_target_names_are_not_log_requests(self):
  for text in ['로그인 상태 확인해줘','로그아웃 동작 확인해줘','b:raw-logins.service 오류 조회']:
   with self.subTest(text=text):self.assertFalse(C.service_log_request(text))

class FactualContext(unittest.TestCase):
 q='B Docker 현재 상태와 최근 5분 로그 보여줘'
 def test_only_fresh_complete_bound_reads_unlock_literal_report(self):
  rows=completed(self.q);before=copy.deepcopy(rows);value=context(self.q,rows)
  self.assertTrue(value['lookup_only']);self.assertEqual(rows,before)
 def test_missing_failed_or_stale_read_is_not_lookup_completion(self):
  for variant in ['missing','failed','stale','wrong_unit','wrong_scope']:
   rows=completed(self.q)
   if variant=='missing':rows.pop()
   elif variant=='failed':rows[-1]['is_error']=True
   elif variant=='stale':rows[0]['data']['observed_at_kst']=(NOW-timedelta(seconds=181)).isoformat()
   elif variant=='wrong_unit':rows[-1]['data']['unit']='different.service'
   else:rows[-1]['data']['journal_scope']='errors'
   with self.subTest(variant=variant):self.assertIsNone(context(self.q,rows))
 def test_extra_read_does_not_get_silently_dropped(self):
  rows=completed(self.q)+[F.receipt(DIAG,{'target':'a:docker'},F.current('a:docker','loaded'))]
  self.assertNotIn('lookup_only',context(self.q,rows))
 def test_not_found_logical_component_does_not_become_completed_lookup(self):
  q='B Vector 지금 상태랑 최근 5분 로그 간단히 보여줘';rows=completed(q,'not-found')+[F.page('services'),F.page('containers')]
  value=context(q,rows);self.assertNotIn('lookup_only',value);self.assertTrue(value['service_identity_discovery']['missing_units'])
 def test_literal_schema_cannot_generate_a_cause_or_incident_verdict(self):
  from jsonschema import Draft202012Validator
  value=context(self.q);schema=C.service_report_schema([DIAG],lookup_only=value['lookup_only'])
  v=Draft202012Validator(schema);good={'more_evidence':False,'report':{'scope':'verified_service_lookup','assessment':'observed','status':'resolved','evidence_indexes':[0]}}
  self.assertTrue(v.is_valid(good))
  for field,claim in [('basis','연결이 끊어졌습니다.'),('assessment','benign'),('current_observation','정상입니다.')]:
   bad=copy.deepcopy(good);bad['report'][field]=claim;self.assertFalse(v.is_valid(bad))
 def test_native_and_sdk_share_scope_and_no_incident_disposition(self):
  value=context(self.q);self.assertTrue(value['lookup_only'])
  report={'scope':'verified_service_lookup','assessment':'observed','status':'resolved','evidence_tools':[DIAG]}
  text=G.render_model_review(report,H.facts_for(SummaryLimits().calls('b:docker','loaded')))
  self.assertNotIn('INCIDENT_DISPOSITION',text);self.assertIn('조회 완료',text)
 def test_real_journal_projection_preserves_codes_and_terms_without_cause_generation(self):
  q=self.q;rows=completed(q);r=next(r for r in rows if r['arguments'].get('view')=='journal')
  library=load('factual_journal_fixture',ROOT/'infra/mcp/diagnostic_journal.py');library.core=D
  def runner(*args):
   event={'_SYSTEMD_UNIT':'docker.service','__REALTIME_TIMESTAMP':str(int((NOW-timedelta(minutes=1)).timestamp()*1000000)),
    '__CURSOR':'factual-source','PRIORITY':'3','MESSAGE':'status=500 uri=/v1.56/containers/json?all=1&size=1 error="Canceled: context canceled"; failed to resolve container image'}
   return 0,(json.dumps(event)+'\n').encode()
  history=load('factual_history_fixture',ROOT/'infra/mcp/diagnostic_history.py');history.core=D
  with patch.object(D,'_history',history):
   r['data']=library.answer(r['arguments'],'b',history.QueryClock(int(NOW.timestamp()),history.instant(AT)),runner=runner)
  self.assertTrue(C.diagnostic_journal_fields(r['data'])['journal_valid'])
  value=context(q,rows);self.assertTrue(value['lookup_only'])
  calls=[]
  for item in rows:
   raw=json.dumps(item['data']);calls.append({'server':'system-diagnostics','name':'get_system_diagnostics',
    'arguments':item['arguments'],'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False})
  report={'scope':'verified_service_lookup','assessment':'observed','status':'resolved','evidence_tools':[DIAG]}
  text=G.render_model_review(report,H.facts_for(calls))
  for literal in ['status=500','Canceled: context canceled','resolve container image']:self.assertIn(literal,text)
  self.assertNotIn('해상도',text);self.assertNotIn('연결이 끊어',text)

class SummaryLimits(unittest.TestCase):
 def calls(self,target='b:vector',load='not-found'):
  raw=json.dumps(F.current(target,load))
  return [{'server':'system-diagnostics','name':'get_system_diagnostics','arguments':{'target':target},
   'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'is_error':False}]
 def report(self,target='b:vector',load='not-found',identity=None):
  return H.diagnostic_report('B '+target.split(':')[1]+' 현재 상태 보여줘',self.calls(target,load),[target],identity=identity)
 def test_logical_unknown_is_visible_in_summary_despite_received_reads(self):
  identity=C.service_identity_state(F.catalog(),'B Vector 현재 상태 보여줘',[F.base(),F.page('services'),F.page('containers')],NOW)
  text=self.report(identity=identity);summary=text.split('**확인 내역**')[0]
  self.assertIn('논리 구성요소 식별 미확인',summary);self.assertIn('b:vector',summary);self.assertNotIn('미확인 0개',summary)
 def test_unit_not_found_is_not_hidden_as_a_successful_component(self):
  text=self.report();summary=text.split('**확인 내역**')[0]
  self.assertIn('not-found 1개',summary);self.assertIn('조회 응답 1/1개',summary)
 def test_loaded_and_unknown_load_are_separate_from_receipt_validity(self):
  summary=self.report('b:docker','loaded').split('**확인 내역**')[0]
  self.assertIn('loaded 1개',summary);self.assertNotIn('논리 구성요소 식별 미확인',summary)
 def test_unknown_load_is_not_invented_as_loaded_or_not_found(self):
  summary=self.report('b:docker','error').split('**확인 내역**')[0]
  self.assertIn('loaded 0개',summary);self.assertIn('not-found 0개',summary)
 def test_explicit_unit_lookup_keeps_the_unit_scope(self):
  identity=C.service_identity_state(F.catalog(),'B capstone-vector.service 현재 상태 보여줘',[F.base()],NOW)
  text=self.report(identity=identity)
  self.assertNotIn('논리 구성요소 식별 미확인',text.split('**확인 내역**')[0])
  self.assertIn('물리 파일',text)
 def test_pending_identity_never_renders_as_completed(self):
  self.assertIsNone(self.report(identity={'pending':[{'tool':INV,'arguments':F.args('services')}]}))

class UnloadedSourceBoundary(unittest.TestCase):
 def issues(self,text):return C.diagnostic_execution_claim_violations(text,[F.fact()])
 def test_unit_lookup_cannot_prove_physical_file_absence(self):
  for text in ['b:vector의 물리 유닛 파일이 없습니다.','b:vector unit 파일은 존재하지 않습니다.','b:vector 서비스 파일이 삭제되었습니다.']:
   with self.subTest(text=text):self.assertIn('diagnostic_unit_file_existence_unverified',self.issues(text))
 def test_not_found_literal_and_file_uncertainty_are_not_absence_claims(self):
  for text in ['b:vector LoadState=not-found입니다.','b:vector의 unit 파일 존재 여부는 미확인입니다.',
   'b:vector의 파일이 없는지는 별도 조회가 필요합니다.','b:vector의 파일이 없다면 배포 구성을 확인합니다.']:
   with self.subTest(text=text):self.assertNotIn('diagnostic_unit_file_existence_unverified',self.issues(text))
 def test_different_loaded_unit_cannot_lend_physical_file_proof(self):
  rows=[F.fact(),F.fact(F.current('b:docker','loaded'))]
  self.assertIn('diagnostic_unit_file_existence_unverified',C.diagnostic_execution_claim_violations('b:vector의 유닛 파일이 없습니다.',rows))
 def test_attached_negation_of_claim_or_planned_file_check_is_not_asserted_absence(self):
  for text in ['b:vector의 파일이 없다고 단정할 수 없습니다.','b:vector의 파일이 삭제되면 배포 구성을 확인합니다.']:
   with self.subTest(text=text):self.assertNotIn('diagnostic_unit_file_existence_unverified',self.issues(text))

if __name__=='__main__':unittest.main()
