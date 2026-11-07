"""Exit and lifecycle claims must remain bound to observed subject and time."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parent
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
c=load('claim_contract',ROOT/'chat_contract.py')
g=load('claim_gate',ROOT/'soc_management_run.py')
STAMP='2026-10-30T12:34:56.123456+09:00'

def diagnostic(target='c:vector',code=0):
    return {'kind':'diagnostics','target':target,'unit':'vector.service','diagnostic_mode':'snapshot',
            'properties':{'Type':'oneshot','ActiveState':'inactive','SubState':'dead','Result':'success'},
            'process_termination':{'kind':'exited','exit_status':code,'signal_number':None}}

def historical(target='c:vector',code=3):
    return {'kind':'diagnostics','target':target,'unit':'vector.service','diagnostic_mode':'journal_history',
            'error_exit_observations':[{'exit_status':code,'observed_at_kst':STAMP,'record_sha256':'a'*64}]}

class DiagnosticClaims(unittest.TestCase):
    def setUp(self):self.facts=[diagnostic(),historical()]
    def issues(self,text):return g.evidence_claim_violations(text,self.facts)

    def test_structured_incident_closure_cannot_hide_behind_process_only_prose(self):
        basis='과거 종료값 3; 현재 마지막 종료값 0으로 종료했습니다.'
        for assessment,status in (('benign','resolved'),('remediated','resolved'),('benign','needs_review')):
            report={'basis':basis,'assessment':assessment,'evidence_tools':['mcp__system_diagnostics__get_system_diagnostics'],
                    'limitations':['전체 영향은 별도 검증이 필요합니다.'],'next_steps':['관측을 계속합니다.'],'status':status}
            with self.subTest(assessment=assessment):
                self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues(g.render_model_review(report,self.facts)))
        report.update(assessment='unresolved',status='needs_review')
        self.assertNotIn('diagnostic_snapshot_is_not_functional_health',self.issues(g.render_model_review(report,self.facts)))
        self.assertEqual(self.issues(basis),[])

    def test_bare_state_pair_is_bound_to_subject_time_and_actual_properties(self):
        for text in ('현재 vector.service는 activating/start 상태입니다.',
                     '현재 vector.service는 activating/start이며 다시 확인해야 합니다.',
                     '어제.vector.service 실패; 현재 activating/start 상태입니다.',
                     '어제.vector.service 실패했고 현재는 activating/start 상태입니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_property_value_mismatch',self.issues(text))
        self.assertEqual(self.issues('현재 vector.service는 inactive/dead 상태입니다.'),[])
        self.assertEqual(self.issues('현재 vector.service는 activating/start가 아닙니다.'),[])
        self.assertEqual(self.issues('서비스가 active/running 상태가 되는지 관측합니다.'),[])
        self.assertIn('diagnostic_property_value_unverified',self.issues('어제 vector.service는 inactive/dead 상태였습니다.'))

    def test_unqualified_restart_denial_cannot_be_inferred_from_current_snapshot(self):
        for text in ('현재 서비스는 종료 후 대기 중이며 재시작은 발생하지 않았습니다.',
                     '재기동이 이루어지지 않았습니다.', 'restart는 발생하지 않았습니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_restart_counter_not_history',self.issues(text))
        self.assertEqual(self.issues('재시작을 수행하지 않았으며 읽기만 진행했습니다.'),[])
        self.assertEqual(self.issues('재시작은 발생하지 않았다고 단정할 수 없습니다.'),[])

    def test_future_monitoring_goal_is_not_an_observed_health_claim(self):
        text='서비스의 정상 진입까지 모니터링 필요 (unresolved)'
        self.assertEqual(self.issues(text),[])
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues(text+'; 서비스는 정상입니다.'))
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues('서비스의 정상 진입을 확인했습니다.'))

    def test_direct_functional_health_disclaimer_is_not_a_positive_claim(self):
        for text in ('장기 실행 서비스의 정상 가동 상태를 증명하지 않습니다.',
                     '서비스의 정상 동작을 보장하지 않습니다.',
                     '서비스가 정상적으로 작동함을 뜻하지 않습니다.',
                     '현재 서비스의 정상 운영 상태임을 입증하지 않습니다.'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_snapshot_is_not_functional_health',self.issues(text))

    def test_disclaimer_does_not_excuse_positive_or_double_negative_claim(self):
        for text in ('서비스의 정상 가동 상태를 증명합니다.',
                     '서비스의 정상 동작을 보장하지 않는 것은 아닙니다.',
                     '서비스의 정상 동작을 보장하지 않습니다. 서비스는 정상입니다.',
                     '서비스는 정상입니다. 전체 기능은 미확인입니다.',
                     '서비스의 정상 동작을 보장하지 않았습니다. 현재 서비스는 정상입니다.'):
            with self.subTest(text=text):
                self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues(text))

    def test_conditional_successful_oneshot_termination_is_not_global_health(self):
        text='현재 c:vector 서비스의 inactive/dead 상태는 정상적인 작업 완료 후 종료일 수 있습니다.'
        self.assertEqual(self.issues(text),[])
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues(text+' 서비스는 완전히 정상입니다.'))
        for key,value in [('Type','simple'),('ActiveState','activating'),('Result','exit-code')]:
            with self.subTest(key=key):
                self.facts=[diagnostic()];self.facts[0]['properties'][key]=value
                self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues(text))
        self.facts=[diagnostic(code=1)]
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues(text))
        self.facts=[historical()]
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues(text))

    def test_valid_historical_exit_does_not_conflict_with_current_success(self):
        for text in ('과거 오류 표본 c:vector process_exit exit_code=3.',
                     f'과거 c:vector 종료값 3 ({STAMP})',
                     f'vector.service exit_code=3 ({STAMP})',
                     '과거 종료값 3; 현재 종료값 0.',
                     '| 과거 오류 표본 | c:vector | exit_code=3 |',
                     '과거 오류 표본 종료값 3, 현재 마지막 메인 프로세스 종료값 0.'):
            with self.subTest(text=text):self.assertEqual(self.issues(text),[])

    def test_relative_past_and_english_history_are_not_current(self):
        for text in ('어제 c:vector 실패 exit_code=3','Yesterday c:vector exit_code=3','Previous failure exit_code=3'):
            with self.subTest(text=text):self.assertEqual(self.issues(text),[])
        self.assertIn('diagnostic_exit_status_mismatch',self.issues('어제 exit_code=3; 현재 exit_code=3'))

    def test_current_wrong_exit_never_borrows_historical_value(self):
        for text in ('현재 c:vector 종료값 3.',f'현재 c:vector 종료값 3 ({STAMP})',
                     '과거 오류 표본 종료값 3; 현재 종료값 3.',
                     '과거 오류 표본 종료값 3, 현재 마지막 메인 프로세스 종료값 3.',
                     'ExecMainStatus=3'):
            with self.subTest(text=text):self.assertIn('diagnostic_exit_status_mismatch',self.issues(text))

    def test_wrong_historical_time_value_and_subject_are_not_excused(self):
        for text in ('과거 c:vector 종료값 5',
                     '과거 c:vector 종료값 3 (2026-10-30T12:35:56.123456+09:00)',
                     f'과거 a:vector 종료값 3 ({STAMP})',
                     f'과거 unknown.service 종료값 3 ({STAMP})'):
            with self.subTest(text=text):self.assertTrue(self.issues(text))

    def test_explicit_host_prevents_cross_host_history_reuse(self):
        self.facts.append(historical('a:vector',9))
        self.assertEqual(self.issues('과거 a:vector 종료값 9'),[])
        self.assertIn('diagnostic_historical_exit_status_unverified',self.issues('과거 c:vector 종료값 9'))
        self.assertIn('diagnostic_historical_exit_status_unverified',self.issues('과거 c:vector 종료값 9; 과거 a:vector 종료값 9'))

    def test_history_only_cannot_establish_current_exit(self):
        self.facts=[historical()]
        self.assertIn('diagnostic_current_exit_status_unverified',self.issues('현재 c:vector 종료값 3'))

    def test_active_property_claim_matches_the_actual_current_snapshot(self):
        self.facts[0]['properties'].update(ActiveState='activating',SubState='start')
        for text in ('현재 c:vector ActiveState=inactive, SubState=dead',
                     '| **현재 상태** | `ActiveState=inactive`, `SubState=dead` |',
                     '현재 c:vector Result=exit-code', '현재 c:vector Type=simple'):
            with self.subTest(text=text):self.assertIn('diagnostic_property_value_mismatch',self.issues(text))
        self.assertEqual(self.issues('현재 c:vector ActiveState=activating, SubState=start, Result=success, Type=oneshot'),[])
        self.assertEqual(self.issues('ActiveState=inactive가 아닙니다. 현재 ActiveState=activating입니다.'),[])

    def test_current_properties_do_not_prove_historical_state(self):
        self.assertIn('diagnostic_property_value_unverified',self.issues('어제 c:vector Type=oneshot, Result=success'))
        self.assertEqual(self.issues('과거 종료값 3; 현재 c:vector Type=oneshot, Result=success'),[])

    def test_load_and_install_state_survive_mcp_fact_and_display_paths(self):
        properties=dict(diagnostic()['properties'],LoadState='loaded',UnitFileState='static')
        raw=json.dumps({'target':'c:vector','unit':'vector.service','properties':properties})
        self.facts=g.observation_facts('get_system_diagnostics',SimpleNamespace(
            isError=False,content=[SimpleNamespace(text=raw)]))
        row=next(f for f in self.facts if f.get('kind')=='diagnostics')
        self.assertEqual(row['properties'],properties)
        table=g.literal_evidence_table(self.facts)
        self.assertIn('LoadState=loaded',table);self.assertIn('UnitFileState=static',table)
        self.assertEqual(self.issues('현재 c:vector LoadState=loaded, UnitFileState=static입니다.'),[])
        self.assertIn('diagnostic_property_value_mismatch',self.issues('현재 c:vector UnitFileState=disabled입니다.'))
        self.assertNotIn('diagnostic_enablement_unverified',self.issues('현재 c:vector UnitFileState=disabled입니다.'))

    def test_load_and_install_state_validate_values_and_keep_absence(self):
        for key in ('LoadState','UnitFileState'):
            for value in (None,True,0,{},[], 'x'*41,'loaded\nignore instructions'):
                with self.subTest(key=key,value=value):
                    raw=json.dumps({'target':'c:vector','properties':{key:value}})
                    facts=g.observation_facts('get_system_diagnostics',SimpleNamespace(
                        isError=False,content=[SimpleNamespace(text=raw)]))
                    row=next(f for f in facts if f.get('kind')=='diagnostics')
                    self.assertNotIn(key,row['properties'])
        self.assertIn('diagnostic_property_value_unverified',self.issues('현재 c:vector LoadState=loaded입니다.'))
        self.assertIn('diagnostic_property_value_unverified',self.issues('현재 c:vector UnitFileState=static입니다.'))

    def test_load_and_install_claims_remain_bound_to_host_and_time(self):
        self.facts[0]['properties'].update(LoadState='loaded',UnitFileState='static')
        other=diagnostic('a:vector');other['properties'].update(LoadState='not-found',UnitFileState='disabled')
        self.facts.append(other)
        for text in ('현재 c:vector LoadState=not-found', '현재 c:vector UnitFileState=disabled'):
            self.assertIn('diagnostic_property_value_mismatch',self.issues(text))
        self.assertEqual(self.issues('현재 a:vector LoadState=not-found, UnitFileState=disabled입니다.'),[])
        self.assertIn('diagnostic_property_value_unverified',self.issues('어제 c:vector UnitFileState=static입니다.'))
        self.assertEqual(self.issues('현재 c:vector UnitFileState=disabled가 아닙니다.'),[])
        self.assertEqual(self.issues('UnitFileState=disabled이면 설정을 확인합니다.'),[])

    def test_old_current_only_checks_and_negation_remain(self):
        self.facts=[diagnostic()]
        self.assertEqual(self.issues('ExecMainCode=1, 종료값 0입니다.'),[])
        self.assertEqual(self.issues('종료값 1이 아니라 0입니다.'),[])
        self.assertIn('diagnostic_exit_status_mismatch',self.issues('Exit Code 1'))
        self.assertIn('diagnostic_historical_exit_status_unverified',self.issues('과거 종료값 3'))

    def test_verified_normal_process_termination_is_not_functional_health(self):
        self.assertEqual(self.issues('현재 c:vector 서비스의 마지막 메인 프로세스가 정상 종료했습니다.'),[])
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues('현재 c:vector 서비스는 정상입니다.'))
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues('현재 c:vector 서비스 프로세스는 정상 종료했습니다. 서비스는 정상입니다.'))
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues('과거 c:vector 서비스는 정상 종료했습니다.'))

    def test_unsuccessful_process_cannot_gain_normal_termination_exception(self):
        self.facts=[diagnostic(code=3)]
        self.assertIn('diagnostic_snapshot_is_not_functional_health',self.issues('현재 서비스가 정상 종료했습니다.'))

    def test_successful_oneshot_inactive_is_not_proof_of_failure(self):
        for text in ('현재 c:vector 서비스는 inactive/dead이므로 비정상 상태입니다.',
                     '지금 oneshot inactive이며 여전히 실패한 채 멈춰 있습니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_oneshot_state_is_not_failure',self.issues(text))
        self.assertEqual(self.issues('현재 c:vector는 inactive/dead, Result=success, Type=oneshot입니다. 지속 장애 여부는 미확인입니다.'),[])
        self.assertEqual(self.issues('현재 inactive/dead만으로 지속 장애를 단정하지 않습니다.'),[])

    def test_actual_failed_service_is_not_excused_as_successful_oneshot(self):
        self.facts[0]['properties'].update(ActiveState='failed',SubState='failed',Result='exit-code')
        self.assertNotIn('diagnostic_oneshot_state_is_not_failure',self.issues('현재 c:vector는 failed, Result=exit-code로 실패 상태입니다.'))

    def test_successful_oneshot_does_not_prove_failed_rerun(self):
        for text in ('현재 c:vector는 inactive 상태로 정상 재실행되지 않았습니다.',
                     '현재 oneshot inactive로 재가동이 되지 않았습니다.'):
            self.assertIn('diagnostic_oneshot_state_is_not_failure',self.issues(text))
        self.assertEqual(self.issues('현재 c:vector inactive만으로 재실행되지 않았다고 단정하지 않습니다.'),[])

    def test_lock_rejection_does_not_prove_a_restart_or_retry_was_attempted(self):
        self.facts.append({'kind':'diagnostics','target':'b:management','error_code_observations':[
            {'code':'controller_already_running'}]})
        for text in ('어제 controller_already_running 오류로 재시작에 실패했습니다.',
                     'controller_already_running 발생 후 재시도를 수행했습니다.'):
            self.assertIn('diagnostic_lock_metadata_not_restart_history',self.issues(text))
            self.assertNotIn('diagnostic_restart_counter_not_history',self.issues(text))
        for text in ('controller_already_running은 배타 잠금 획득 실패입니다.',
                     'controller_already_running만으로 재시작 실패 여부는 미확인입니다.',
                     'controller_already_running 이후 재시도 시행은 단정하지 않습니다.'):
            self.assertNotIn('diagnostic_lock_metadata_not_restart_history',self.issues(text))

    def test_inactive_does_not_prove_disabled_configuration(self):
        for text in ('현재 c:vector는 inactive이므로 비활성화된 설정입니다.',
                     '현재 c:vector UnitFileState=disabled입니다.',
                     '현재 c:vector는 자동 시작이 비활성화되어 있습니다.'):
            with self.subTest(text=text):
                self.assertIn('diagnostic_enablement_unverified',self.issues(text))
        for text in ('현재 c:vector는 inactive/dead이며 자동 시작 설정은 미확인입니다.',
                     'inactive는 자동 시작 비활성화를 뜻하지 않습니다.',
                     '승인 후 자동 시작 비활성화를 검토합니다.'):
            with self.subTest(text=text):
                self.assertNotIn('diagnostic_enablement_unverified',self.issues(text))
        self.facts[0]['properties']['UnitFileState']='disabled'
        self.assertNotIn('diagnostic_enablement_unverified',self.issues('현재 c:vector UnitFileState=disabled입니다.'))
        self.facts=[diagnostic(),{'kind':'events'}]
        self.assertNotIn('diagnostic_enablement_unverified',self.issues('현재 c:vector UnitFileState=disabled입니다.'))

    def test_review_count_with_empty_processing_queues_does_not_prove_congestion(self):
        row={'kind':'diagnostics','target':'b:management-pipeline','pipeline_metrics':{
            'pending_reports':0,'running_cases':0,'overdue_cases':0,'review_required_cases':285}}
        self.facts.append(row)
        for text in ('SOC 처리대기열은 병목 상태입니다.','현재 관제 처리 지연이 있습니다.',
                     '관제 검토 대기열은 과부하 상태입니다.','SOC 처리 대기열은 성능 저하 상태입니다.'):
            self.assertIn('diagnostic_pipeline_congestion_unverified',self.issues(text))
        for text in ('검토 상태 285건이며 현재 처리 병목 여부는 미확인입니다.',
                     '이 수치만으로 관제 병목이라고 단정하지 않습니다.',
                     '어제 관제 처리 지연이 있었습니다.',
                     '관제 병목 가능성은 추가 확인 필요합니다.'):
            self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues(text))
        row['pipeline_metrics']['pending_reports']=3
        self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues('관제 처리 병목 상태입니다.'))

    def pipeline(self):
        return {'kind':'diagnostics','target':'b:management-pipeline','observed_at_kst':STAMP,
            'pipeline_metrics':{'pending_reports':0,'running_cases':0,'overdue_cases':0,'review_required_cases':285}}

    def test_direct_pipeline_disclaimer_is_not_congestion(self):
        self.facts=[self.pipeline()]
        for text in ('degraded 상태는 검토 미완료 표지이며 성능 저하를 의미하지 않습니다.',
                     '관제 병목이라고 단정하지 않습니다.',
                     '검토 상태 수만으로 처리 지연을 입증하지 않습니다.'):
            with self.subTest(text=text):self.assertEqual(self.issues(text),[])

    def test_other_read_does_not_disable_explicit_pipeline_claim_validation(self):
        for other in ({'kind':'blocks'}, {'kind':'events'}, {'kind':'web_access'}):
            self.facts=[self.pipeline(),diagnostic('b:management'),other]
            for text in ('현재 b:management-pipeline 처리 지연이 있습니다.',
                         '현재 관제 처리 대기열은 285건입니다.',
                         '관리 파이프라인이 정상화되었는지 확인하고, 대기 중인 285건의 사건 처리 지연에 따른 운영적 영향 검토가 필요합니다.'):
                with self.subTest(other=other,text=text):
                    self.assertTrue(set(self.issues(text)) & {
                        'diagnostic_pipeline_count_mismatch','diagnostic_pipeline_congestion_unverified'})

    def test_mixed_pipeline_scope_preserves_other_subject_and_uncertainty(self):
        self.facts=[self.pipeline(),diagnostic('c:vector'),{'kind':'web_access'}]
        for text in ('c:vector 처리 지연이 있습니다.', 'DVWA 요청 처리 지연이 있습니다.',
                     '처리 대기열은 285건입니다.', '어제 관제 처리 지연이 있었습니다.',
                     '현재 관제 병목 가능성은 추가 확인이 필요합니다.',
                     '관제 처리 대기열은 0건이며 검토 상태 사건은 285건입니다.',
                     '관리 파이프라인의 처리 지연을 단정하지 않습니다.'):
            with self.subTest(text=text):
                self.assertFalse(set(self.issues(text)) & {
                    'diagnostic_pipeline_count_mismatch','diagnostic_pipeline_congestion_unverified'})

    def test_mixed_pipeline_does_not_invent_zero_metrics(self):
        self.facts=[self.pipeline(),{'kind':'blocks'}]
        self.facts[0]['pipeline_metrics']['pending_reports']=2
        self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues('현재 관제 처리 지연이 있습니다.'))
        del self.facts[0]['pipeline_metrics']['pending_reports']
        self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues('현재 관제 처리 지연이 있습니다.'))
        self.facts=[diagnostic('c:vector'),{'kind':'blocks'}]
        self.assertEqual(c.diagnostic_pipeline_claim_violations('현재 관제 처리 지연이 있습니다.',self.facts),[])

    def test_mixed_review_trend_and_period_need_their_own_observations(self):
        self.facts=[self.pipeline(),{'kind':'blocks'}]
        self.assertIn('diagnostic_pipeline_trend_unverified',self.issues('관제 검토 사건이 증가했습니다.'))
        self.assertIn('diagnostic_pipeline_period_unverified',self.issues('관제 검토 사건은 이틀 치입니다.'))
        self.assertEqual(c.diagnostic_pipeline_claim_violations('웹 요청 처리량이 증가했습니다.',self.facts),[])

    def test_pipeline_other_uncertainty_does_not_excuse_positive_claim(self):
        self.facts=[self.pipeline()]
        for text in ('관제 검토 대기 증가로 저하 상태이며 원인은 미확인입니다.',
                     '관제 병목은 미확인이나 성능 저하는 발생했습니다.',
                     '관제 성능 저하를 의미하지 않는 것은 아닙니다.',
                     '관제 성능 저하를 의미하지 않습니다. 처리 병목이 있습니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_pipeline_congestion_unverified',self.issues(text))

    def test_one_pipeline_observation_cannot_supply_review_count_trend(self):
        self.facts=[self.pipeline()]
        self.assertIn('diagnostic_pipeline_trend_unverified',self.issues('검토 상태 사건이 증가했습니다.'))
        self.assertEqual(self.issues('검토 상태 사건의 증가 여부는 미확인입니다.'),[])
        self.assertEqual(self.issues('검토 상태 사건이 증가하면 해당 사건을 확인합니다.'),[])
        self.assertEqual(self.issues('관제 병목이 발생하면 처리 지표를 확인합니다.'),[])
        self.facts.append(copy.deepcopy(self.facts[0]))
        self.assertIn('diagnostic_pipeline_trend_unverified',self.issues('검토 상태 사건이 증가했습니다.'))
        self.facts[-1].update(observed_at_kst='2026-10-30T12:35:56+09:00')
        self.facts[-1]['pipeline_metrics']['review_required_cases']=286
        self.assertNotIn('diagnostic_pipeline_trend_unverified',self.issues('검토 상태 사건이 증가했습니다.'))

    def test_zero_processing_metrics_cannot_be_reported_as_pending(self):
        self.facts=[self.pipeline()]
        for text in ('현재 처리 대기 건수는 존재합니다.', '관제 전송 대기가 있습니다.', '관제 기한 초과 사건이 남아 있습니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_pipeline_pending_unverified',self.issues(text))
        for text in ('현재 검토 대기 사건은 있습니다.', '처리 대기는 존재하지 않습니다.', '어제 처리 대기 건수가 있었습니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_pipeline_pending_unverified',self.issues(text))

    def test_pipeline_metrics_do_not_describe_a_different_explicit_target(self):
        self.facts=[self.pipeline(),diagnostic()]
        for text in ('c:vector 처리 지연이 있습니다.', 'c:vector 처리 대기 건수는 존재합니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues(text))

    def test_natural_pipeline_subject_after_service_name_keeps_claim_guard(self):
        self.facts=[self.pipeline(),diagnostic('b:management')]
        for text in ('어제 b:management 오류 후 오늘 SOC 처리 파이프라인은 검토 대기 때문에 병목 상태입니다.',
                     'b:management는 종료됐으나 관제 처리 파이프라인은 성능 저하 상태입니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_pipeline_congestion_unverified',self.issues(text))

    def test_service_then_natural_queue_cannot_borrow_review_count(self):
        self.facts=[self.pipeline(),diagnostic('b:management')]
        text='어제 capstone-management.service가 실패했으며 현재 관제 처리 대기열은 285건으로 지연 중입니다.'
        issues=self.issues(text)
        self.assertIn('diagnostic_pipeline_count_mismatch',issues)
        self.assertIn('diagnostic_pipeline_congestion_unverified',issues)

    def test_processing_queue_count_guard_preserves_review_and_negation(self):
        self.facts=[self.pipeline()]
        for text in ('관제 검토 상태 사건은 285건입니다.', '현재 처리 대기열은 0건입니다.',
                     '관제 처리 대기열은 285건이 아닙니다.', '어제 처리 대기열은 285건이었습니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_pipeline_count_mismatch',self.issues(text))
        self.facts[0]['pipeline_metrics']['pending_reports']=2
        self.assertNotIn('diagnostic_pipeline_count_mismatch',self.issues('처리 대기열은 2건입니다.'))

    def code_samples(self):
        return {**historical('b:management'),'unit':'capstone-management.service','indexed_error_count':876,
            'error_code_observations':[{'code':'controller_already_running','observed_at_kst':STAMP,'record_sha256':str(i)*64} for i in range(5)]}

    def test_whole_index_count_is_not_a_known_code_count(self):
        self.facts=[self.code_samples()]
        for text in ('capstone-management.service는 controller_already_running(876회)으로 잠금 획득에 실패했습니다.',
                     'controller_already_running 876건이 발생했습니다.',
                     'controller_already_running 5회 발생했습니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_error_code_total_unverified',self.issues(text))

    def test_error_code_sample_count_is_bound_to_that_code(self):
        self.facts=[self.code_samples()]
        self.assertNotIn('diagnostic_error_code_total_unverified',self.issues('controller_already_running / 표본 5건'))
        self.assertNotIn('diagnostic_error_code_sample_mismatch',self.issues('반환 controller_already_running 5건'))
        self.assertIn('diagnostic_error_code_sample_mismatch',self.issues('controller_already_running 표본 20건'))
        self.facts.append(copy.deepcopy(self.facts[0]))
        self.assertNotIn('diagnostic_error_code_sample_mismatch',self.issues('controller_already_running 표본 5건'))

    def test_code_count_denial_does_not_make_a_count_claim(self):
        self.facts=[self.code_samples()]
        for text in ('controller_already_running 876회라고 단정하지 않습니다.',
                     'controller_already_running(876회)이 아닙니다.',
                     'controller_already_running 횟수는 미확인입니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_error_code_total_unverified',self.issues(text))

    def test_code_count_guard_does_not_borrow_another_target(self):
        self.facts=[self.code_samples(),historical('c:vector')]
        self.assertNotIn('diagnostic_error_code_sample_mismatch',self.issues('c:vector controller_already_running 표본 20건'))

    def test_today_observation_marker_does_not_borrow_past_state(self):
        self.assertEqual(self.issues('어제 실패했으나 오늘(10/30) 수집 시각 기준 inactive/dead 상태입니다.'),[])
        self.assertEqual(self.issues('어제 실패했으나 오늘 관측 시점 기준 ActiveState=inactive입니다.'),[])
        self.assertIn('diagnostic_property_value_mismatch',self.issues('어제 실패했으나 오늘 관측 시점 기준 ActiveState=active입니다.'))
        self.assertIn('diagnostic_property_value_unverified',self.issues('어제 수집 시각 기준 ActiveState=inactive였습니다.'))
        self.assertIn('diagnostic_property_value_unverified',self.issues('어제와 오늘의 과거 ActiveState=inactive 이력입니다.'))

    def history_samples(self,target='c:vector',day='2026-10-29',count=2):
        return dict(historical(target),observed_at_kst=STAMP,returned_error_count=count,
            requested_since_kst=day+'T00:00:00+09:00',requested_until_kst=day+'T23:59:59.999999+09:00',
            error_sample_instants=[day+'T12:00:00+09:00'] if count else [],history_coverage_status='scanned_sample')

    def test_returned_history_cannot_be_reported_as_failed_read(self):
        self.facts=[self.history_samples()]
        for text in ('어제 c:vector 오류 이력 조회가 실패했습니다.',
                     '2026-10-29 c:vector 오류 표본 반환이 안 됐습니다.',
                     'c:vector 오류 이력 확보가 불가합니다.'):
            with self.subTest(text=text):self.assertIn('diagnostic_history_return_denied',self.issues(text))
        for text in ('어제 c:vector 오류 이력 조회 실패가 아닙니다.',
                     '어제 c:vector 원문 이력 조회가 불가합니다.',
                     'c:vector 오류 표본을 조회했으나 전체 구간의 수집 완전성은 미확인입니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_history_return_denied',self.issues(text))

    def test_read_success_is_bound_to_target_and_period(self):
        self.facts=[self.history_samples(),self.history_samples(day='2026-10-30',count=0)]
        for text in ('오늘 c:vector 오류 이력 조회가 실패했습니다.',
                     '어제 a:vector 오류 이력 조회가 실패했습니다.',
                     '2026-10-28 c:vector 오류 이력 조회가 실패했습니다.',
                     'c:vector 오류 이력 조회가 실패했습니다.'):
            with self.subTest(text=text):self.assertNotIn('diagnostic_history_return_denied',self.issues(text))
        self.assertIn('diagnostic_history_return_denied',self.issues('어제 c:vector 오류 이력 조회가 실패했습니다.'))

    def test_missing_or_invalid_counts_do_not_establish_returned_history(self):
        for count in (0,None,True,'2'):
            self.facts=[self.history_samples(count=count)]
            self.assertNotIn('diagnostic_history_return_denied',self.issues('어제 c:vector 오류 이력 조회가 실패했습니다.'))

    def report_prose(self,basis='현재 수집한 프로세스 상태만 확인했습니다.',limit='원문은 미확인입니다.',step='남은 사건 검토 항목을 확인합니다.'):
        return ('**판단**\n'+basis+'\n\n| 확인 항목 | 값 |\n|---|---|\n| 근거 | 표본 |\n\n'
            '**미확인·한계**\n- '+limit+'\n\n**다음 조치**\n- '+step+'\n\n'
            'INCIDENT_DISPOSITION: {"assessment":"unresolved"}\nMANAGEMENT_STATUS: needs_review')

    def test_projected_report_rejects_punctuation_only_action(self):
        for empty in (',','...','\u200b','123',' '):
            with self.subTest(empty=empty):
                self.assertIn('diagnostic_report_empty_field',self.issues(self.report_prose(step=empty)))

    def test_empty_basis_cannot_borrow_words_from_evidence_table(self):
        self.assertIn('diagnostic_report_empty_field',self.issues(self.report_prose(basis='')))
        self.assertIn('diagnostic_report_empty_field',self.issues(self.report_prose(limit=',')))

    def test_valid_projected_prose_keeps_its_literal_action(self):
        for step in ('관리자에게 원문 보관 위치를 확인합니다.','b:management 상태 관측을 다음 실행 시각에 대조합니다.'):
            text=self.report_prose(step=step)
            self.assertNotIn('diagnostic_report_empty_field',self.issues(text))
            self.assertIn(step,text)

    def test_one_valid_action_does_not_hide_an_empty_item(self):
        self.assertIn('diagnostic_report_empty_field',self.issues(self.report_prose(step='사건을 검토합니다.\n- ,')))

    def test_empty_field_guard_does_not_rewrite_plain_failures_or_other_reports(self):
        self.assertNotIn('diagnostic_report_empty_field',self.issues('조회 근거 부족으로 판단을 완료하지 못했습니다.'))
        self.assertEqual(c.diagnostic_report_text_violations(self.report_prose(step=','),[{'kind':'rules'}]),[])

    def test_current_review_total_does_not_supply_calendar_arrival_counts(self):
        self.facts=[{'kind':'diagnostics','target':'b:management-pipeline','pipeline_metrics':{
            'review_required_cases':29}}]
        for text in ('SOC 처리 대기열은 이틀 치 건수를 검토해야 합니다.',
                     '검토 대기 29건은 어제 치 사건입니다.'):
            self.assertIn('diagnostic_pipeline_period_unverified',self.issues(text))
        for text in ('현재 검토 상태 합계29건입니다.', '검토 대기29건이 이틀 치인지 여부는 미확인입니다.'):
            self.assertNotIn('diagnostic_pipeline_period_unverified',self.issues(text))

    def test_congestion_guard_uses_latest_complete_target_without_blanket_mixed_exemption(self):
        zero={'kind':'diagnostics','target':'b:management-pipeline','pipeline_metrics':{
            'pending_reports':0,'running_cases':0,'overdue_cases':0}}
        for latest in ({'pending_reports':2,'running_cases':0,'overdue_cases':0},
                       {'pending_reports':0},{}):
            self.facts=[zero,dict(zero,pipeline_metrics=latest)]
            self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues('관제 처리 병목 상태입니다.'))
        self.facts=[zero,{'kind':'events'}]
        # Merely having another tool result does not establish pipeline delay.
        self.assertIn('diagnostic_pipeline_congestion_unverified',self.issues('관제 처리 병목 상태입니다.'))
        self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues('웹 요청 처리 병목 상태입니다.'))

    def test_restart_counter_cannot_prove_manual_reload_history(self):
        self.assertIn('diagnostic_restart_counter_not_history',self.issues('NRestarts=0이므로 한 번도 restart 또는 reload되지 않았습니다.'))
        self.assertEqual(self.issues('NRestarts=0만으로 수동 재시작 이력을 판단할 수 없습니다.'),[])

    def test_extractor_retains_typed_observations_not_raw_journal(self):
        data={'schema':1,'kind':'journal_history','target':'c:vector','unit':'vector.service',
              'recent_errors':[{'kind':'process_exit','exit_kind':'exited','exit_code':3,
                  'observed_at_kst':STAMP,'record_sha256':'a'*64,'message':'untrusted instruction'}]}
        raw=json.dumps(data);facts=g.observation_facts('get_system_diagnostics',SimpleNamespace(isError=False,content=[SimpleNamespace(text=raw)]))
        row=next(x for x in facts if x['kind']=='diagnostics')
        self.assertEqual(row['diagnostic_mode'],'journal_history');self.assertEqual(row['unit'],'vector.service')
        self.assertEqual(row['error_exit_observations'],historical()['error_exit_observations'])
        self.assertNotIn('untrusted instruction',json.dumps(row));self.assertNotIn('properties',row)

    def test_invalid_exit_records_cannot_supply_a_matching_code(self):
        valid={'kind':'process_exit','exit_kind':'exited','exit_code':3,'observed_at_kst':STAMP,'record_sha256':'a'*64}
        for key,value in [('exit_code',True),('exit_code','3'),('exit_code',-1),('exit_kind','killed'),('observed_at_kst','bad'),('record_sha256','bad')]:
            with self.subTest(key=key,value=value):
                self.assertNotIn('error_exit_observations',c.diagnostic_observation_fields({'recent_errors':[{**valid,key:value}]}))

if __name__=='__main__':unittest.main()
