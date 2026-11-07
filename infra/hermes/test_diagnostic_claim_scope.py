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

    def test_current_review_total_does_not_supply_calendar_arrival_counts(self):
        self.facts=[{'kind':'diagnostics','target':'b:management-pipeline','pipeline_metrics':{
            'review_required_cases':29}}]
        for text in ('SOC 처리 대기열은 이틀 치 건수를 검토해야 합니다.',
                     '검토 대기 29건은 어제 치 사건입니다.'):
            self.assertIn('diagnostic_pipeline_period_unverified',self.issues(text))
        for text in ('현재 검토 상태 합계29건입니다.', '검토 대기29건이 이틀 치인지 여부는 미확인입니다.'):
            self.assertNotIn('diagnostic_pipeline_period_unverified',self.issues(text))

    def test_congestion_guard_uses_latest_complete_target_and_keeps_other_evidence(self):
        zero={'kind':'diagnostics','target':'b:management-pipeline','pipeline_metrics':{
            'pending_reports':0,'running_cases':0,'overdue_cases':0}}
        for latest in ({'pending_reports':2,'running_cases':0,'overdue_cases':0},
                       {'pending_reports':0},{}):
            self.facts=[zero,dict(zero,pipeline_metrics=latest)]
            self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues('관제 처리 병목 상태입니다.'))
        self.facts=[zero,{'kind':'events'}]
        self.assertNotIn('diagnostic_pipeline_congestion_unverified',self.issues('관제 처리 병목 상태입니다.'))

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
