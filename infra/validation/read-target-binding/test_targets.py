"""Bound query-outcome counterexamples for entities, view, windows and phases."""
from pathlib import Path
import copy,hashlib,importlib.util,json,os,sys,unittest
ROOT=Path(os.environ['SOC_TARGET_ROOT']);sys.path[:0]=[str(ROOT/'infra/hermes'),str(ROOT/'infra/ollama-trial')];import soc_management_run as g;import harness as h
DIAG='mcp__system_diagnostics__get_system_diagnostics';INV='mcp__system_diagnostics__get_host_inventory'
START='2026-11-15T16:00:00+09:00';END='2026-11-15T16:15:00+09:00'
def data(target='b:systemd',**more):return {'schema':1,'target':target,'host':target[0],'kind':'runtime','lookback_scope':'latest_snapshot_only_not_requested_history','mutation_performed':False,**more}
def record(target='b:systemd', *, tool=DIAG,args=None,value=None,phase='returned',flag=False,raw=None):
 args={'target':target} if args is None else args
 value=data(target) if value is None else value
 raw=json.dumps(value) if raw is None else raw
 return {'tool':tool,'arguments':args,'output':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest(),'phase':phase,'is_error':flag}
def history(target='b:vector'):
 return record(target,args={'target':target,'since_kst':START,'until_kst':END},value={'schema':1,'target':target,'unit':'vector.service','kind':'journal_history','requested_since_kst':START,'requested_until_kst':END,'recent_errors':[]})
def journal(target='b:vector'):
 return record(target,args={'target':target,'view':'journal','since_kst':START,'until_kst':END},value={'schema':1,'target':target,'unit':'vector.service','kind':'journal_excerpt','status':'observed','live_query':True,'mutation_performed':False,'redacted_excerpts_returned':True,'raw_messages_returned':False,'journal_retention_verified':False,'requested_window_total_count':None,'has_more':False,'response_size_limited':False,'journal_scope':'errors','entries':[],'returned_entries':0,'requested_since_kst':START,'requested_until_kst':END})
def check(text,records=(),complete=True):return g.read_attempt_claim_violations(text,g.read_attempt_view(list(records),complete=complete))
class TargetBinding(unittest.TestCase):
 def test_actual_failure_requires_same_target(self):
  failed=record('c:vector',value={'error':'backend_timeout'})
  self.assertTrue(check('b:vector 조회 실패했습니다.',[failed]));self.assertEqual(check('c:vector 조회 실패했습니다.',[failed]),[])
 def test_success_requires_same_target(self):
  self.assertTrue(check('a:systemd 현재 조회 성공했습니다.',[record()]));self.assertEqual(check('b:systemd 현재 조회 성공했습니다.',[record()]),[])
 def test_runtime_success_cannot_prove_a_failed_history_read(self):
  for phrase in ['b:systemd (과거 오류 이력) | 조회 실패 |','B 서버 systemd 과거 이력 조회 실패했습니다.','B systemd 과거 조회 실패했습니다.']:
   with self.subTest(phrase=phrase):self.assertTrue(check(phrase,[record()]))
 def test_runtime_success_cannot_prove_a_successful_history_read(self):
  for phrase in ['b:systemd 과거 오류 이력 조회 완료했습니다.','b:systemd 최근 30일 오류 조회 결과입니다.']:
   with self.subTest(phrase=phrase):self.assertTrue(check(phrase,[record()]))
 def test_honest_snapshot_and_unsupported_unperformed_are_preserved(self):
  for text in ['b:systemd 현재 조회 완료했습니다.','b:systemd 과거 journal은 미지원이며 이번에는 미실행입니다.','b:systemd의 과거 조회 실패 여부는 미확인입니다.','b:systemd 과거 조회 실패라면 등록 서비스를 확인합니다.','b:systemd 과거 조회 실패한 것은 아닙니다.']:
   with self.subTest(text=text):self.assertEqual(check(text,[record()]),[])
 def test_real_historical_wire_failure_is_not_erased(self):
  r=history();r['output']='{"error":"backend_timeout"}';r['result_sha256']=hashlib.sha256(r['output'].encode()).hexdigest()
  self.assertEqual(check('b:vector 과거 이력 조회 실패했습니다.',[r]),[])
 def test_current_success_cannot_borrow_history_failure(self):
  r=history();r['output']='{"error":"timeout"}';r['result_sha256']=hashlib.sha256(r['output'].encode()).hexdigest()
  self.assertTrue(check('b:vector 현재 조회 실패했습니다.',[r,record('b:vector')]))
  self.assertEqual(check('b:vector 과거 이력 조회 실패했습니다.',[r,record('b:vector')]),[])
 def test_current_and_error_sample_are_both_real_in_a_unit_snapshot(self):
  r=record('b:vector',args={'target':'b:vector','lookback_minutes':15},value={'schema':1,'target':'b:vector','unit':'vector.service','recent_errors':[],'requested_since_kst':START,'requested_until_kst':END})
  self.assertEqual(check('b:vector 현재 조회 완료했습니다.',[r]),[]);self.assertEqual(check('b:vector 최근 15분 오류 이력 조회 완료했습니다.',[r]),[])
 def test_real_history_does_not_become_raw_journal(self):
  self.assertEqual(check('b:vector 과거 이력 조회 완료했습니다.',[history()]),[]);self.assertTrue(check('b:vector journal 원문 조회 완료했습니다.',[history()]))
 def test_valid_journal_view_and_mode_are_bound(self):
  self.assertEqual(check('b:vector view=journal 조회 완료했습니다.',[journal()]),[]);self.assertEqual(check('b:vector journal 원문 조회 성공했습니다.',[journal()]),[])
 def test_bogus_or_wrong_echo_does_not_verify_a_journal_read(self):
  r=journal();d=json.loads(r['output']);d['target']='c:vector';r['output']=json.dumps(d);r['result_sha256']=hashlib.sha256(r['output'].encode()).hexdigest();self.assertTrue(check('b:vector journal 원문 조회 성공했습니다.',[r]))
 def test_args_and_response_period_must_agree(self):
  r=history();d=json.loads(r['output']);d['requested_since_kst']='2026-11-15T15:00:00+09:00';r['output']=json.dumps(d);r['result_sha256']=hashlib.sha256(r['output'].encode()).hexdigest();self.assertTrue(check('b:vector 과거 이력 조회 완료했습니다.',[r]))
 def test_recent_duration_cannot_expand_a_15_minute_history(self):
  self.assertEqual(check('b:vector 최근 15분 이력 조회 결과입니다.',[history()]),[]);self.assertTrue(check('b:vector 최근 30일 이력 조회 결과입니다.',[history()]))
 def test_explicit_bounds_are_compared_as_instants(self):
  text='b:vector since_kst='+START+' until_kst='+END+' 과거 이력 조회 완료했습니다.'
  self.assertEqual(check(text,[history()]),[]);self.assertTrue(check(text.replace('16:00:00','15:00:00'),[history()]))
 def test_explicit_integer_argument_cannot_be_invented(self):
  r=record(args={'target':'b:systemd','lookback_minutes':15});self.assertEqual(check('b:systemd lookback_minutes=15 현재 조회 완료했습니다.',[r]),[]);self.assertTrue(check('b:systemd lookback_minutes=30 현재 조회 완료했습니다.',[r]))
 def test_argument_key_cannot_be_described_as_supplied_if_missing(self):
  self.assertTrue(check('b:systemd 현재 조회 완료했고 lookback_minutes만 제공하고 진행했습니다.',[record()]))
 def test_method_and_target_constraints_do_not_lose_each_other(self):
  wrong=record(tool='mcp__rule_a__get_service_action_target',value={'target':'b:systemd'})
  self.assertTrue(check(DIAG+' target=b:systemd 조회 성공했습니다.',[wrong]));self.assertEqual(check(DIAG+' target=b:systemd 현재 조회 완료했습니다.',[record()]),[])
 def test_unit_and_explicit_host_do_not_borrow_another_host(self):
  r=record(tool=INV,args={'host':'c','view':'service_details','unit':'vector.service'},value={'error':'unavailable'})
  self.assertTrue(check('B 서버 vector.service 조회 실패했습니다.',[r]));self.assertEqual(check('C 서버 vector.service 조회 실패했습니다.',[r]),[])
 def test_inventory_container_and_view_match_the_real_call(self):
  r=record(tool=INV,args={'host':'b','view':'container_logs','container':'web'},value={'kind':'host_inventory'})
  self.assertEqual(check('get_host_inventory host=b container=web view=container_logs 조회 완료했습니다.',[r]),[])
  self.assertTrue(check('get_host_inventory host=b container=db view=container_logs 조회 완료했습니다.',[r]));self.assertTrue(check('get_host_inventory host=c container=web 조회 완료했습니다.',[r]))
 def test_same_target_separate_current_and_historical_claims(self):
  r=history();r['output']='{"error":"timeout"}';r['result_sha256']=hashlib.sha256(r['output'].encode()).hexdigest()
  self.assertEqual(check('b:vector 과거 이력 조회 실패했습니다. b:vector 현재 조회 완료했습니다.',[r,record('b:vector')]),[])
 def test_live_fault_is_not_a_failed_query(self):
  self.assertEqual(check('b:vector는 서비스 시작 실패 상태입니다.',[record('b:vector')]),[])
 def test_advice_conditional_and_disclaimer_do_not_license_a_real_false_claim(self):
  self.assertTrue(check('b:systemd 과거 조회 실패했습니다. 실패 여부를 단정할 수 없습니다.',[record()]));self.assertEqual(check('b:systemd 과거 조회할 예정입니다.',[record()]),[])
 def test_tampered_or_incomplete_provenance_stays_unknown(self):
  r=record();r['result_sha256']='0'*64;self.assertEqual(check('b:systemd 조회 실패했습니다.',[r]),['read_attempt_provenance_unverified'])
 def test_no_real_call_does_not_become_a_target_failure(self):self.assertTrue(check('c:apache 조회 실패했습니다.'))
 def test_selectors_and_input_are_not_mutated(self):
  r=journal();before=copy.deepcopy(r);check('b:vector journal 원문 조회 완료했습니다.',[r]);self.assertEqual(r,before)
 def test_scope_view_contains_no_health_or_approval_verdict(self):
  row=g.read_attempt_view([record()])['rows'][0];self.assertFalse({'healthy','benign','resolved','approved'}&set(row['receipt_scope']))
 def test_native_and_sdk_use_same_projection_and_gate(self):
  r=record();msgs=[{'role':'assistant','tool_calls':[{'id':'a','function':{'name':DIAG,'arguments':json.dumps(r['arguments'])}}]},{'role':'tool','tool_call_id':'a','content':r['output']}]
  sdk={'server':'system-diagnostics','name':'get_system_diagnostics','arguments':r['arguments'],'result':r['output'],'result_sha256':r['result_sha256'],'is_error':False}
  self.assertEqual(g.read_attempts_from_messages(msgs),h.read_attempts_for([sdk]));self.assertTrue(g.evidence_claim_violations('b:systemd 과거 조회 실패했습니다.',[],read_attempts=g.read_attempts_from_messages(msgs)))
 def test_native_pin_matches_exact_changed_gate(self):self.assertEqual(h.SHARED.EVIDENCE_SOURCE_SHA256,hashlib.sha256((ROOT/'infra/hermes/soc_management_run.py').read_bytes()).hexdigest())
 def test_unit_name_period_is_not_a_sentence_boundary(self):
  r=history();self.assertEqual(check('B 서버 vector.service 과거 이력 조회 완료했습니다.',[r]),[])
  self.assertTrue(check('B 서버 other.service 과거 이력 조회 완료했습니다.',[r]))
 def test_container_name_period_is_not_a_sentence_boundary(self):
  r=record(tool=INV,args={'host':'b','view':'container_logs','container':'web.app'},value={'kind':'host_inventory'})
  self.assertEqual(check('get_host_inventory host=b container=web.app 조회 완료했습니다.',[r]),[])
  self.assertTrue(check('get_host_inventory host=c container=web.app 조회 완료했습니다.',[r]))
 def test_unverified_alias_does_not_invent_unit_identity(self):
  r=record('c:vector',value={'error':'unavailable'});self.assertTrue(check('C 서버 vector.service 조회 실패했습니다.',[r]))
 def test_double_negation_is_not_a_modality_exemption(self):
  self.assertTrue(check('b:systemd 과거 조회 실패한 것은 아니라는 것은 아닙니다.',[record()]))
 def test_entity_before_method_keeps_both_constraints(self):
  r=record('c:systemd',value={'error':'unavailable'})
  self.assertTrue(check('b:systemd (get_system_diagnostics) 조회 실패했습니다.',[r]))
  self.assertEqual(check('c:systemd (get_system_diagnostics) 조회 실패했습니다.',[r]),[])
 def test_coordinated_targets_each_need_their_own_actual_outcome(self):
  self.assertTrue(check('a:systemd와 b:systemd 조회 완료했습니다.',[record()]))
  self.assertEqual(check('a:systemd와 b:systemd 조회 완료했습니다.',[record('a:systemd'),record()]),[])
 def test_returned_journal_scope_must_match_the_request(self):
  r=journal();d=json.loads(r['output']);d['journal_scope']='all';r['output']=json.dumps(d);r['result_sha256']=hashlib.sha256(r['output'].encode()).hexdigest()
  self.assertTrue(check('b:vector journal 원문 조회 완료했습니다.',[r]))
 def test_wrong_host_echo_cannot_verify_target_success(self):
  r=record(value=data(host='c'));self.assertTrue(check('b:systemd 현재 조회 완료했습니다.',[r]))
 def test_transport_error_keeps_requested_history_mode_without_a_server_payload(self):
  r={'tool':DIAG,'arguments':{'target':'b:vector','view':'journal','since_kst':START,'until_kst':END},'phase':'transport_error','error_type':'TimeoutError','output':None,'result_sha256':None}
  self.assertEqual(check('b:vector journal 원문 조회 실패했습니다.',[r]),[]);self.assertTrue(check('b:vector 현재 조회 실패했습니다.',[r]))
 def test_runtime_fault_payload_does_not_license_a_query_failure(self):
  r=record(value=data(status='unavailable'));self.assertTrue(check('b:systemd 조회 실패했습니다.',[r]));self.assertEqual(check('b:systemd 자료 상태는 unavailable로 반환됐습니다.',[r]),[])
 def test_false_input_rejection_server_stage_is_still_blocked(self):
  r=record('b:vector',args={'target':'b:vector','view':'journal','since_kst':START,'until_kst':END},value={'error':'invalid_arguments'},phase='input_rejected')
  self.assertEqual(check('b:vector journal 조회 거절되었습니다.',[r]),[]);self.assertTrue(check('b:vector journal 조회 중 MCP 오류입니다.',[r]))
if __name__=='__main__':unittest.main(verbosity=2)
