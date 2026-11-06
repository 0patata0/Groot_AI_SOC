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
