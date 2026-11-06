"""Reported health must not exceed the observed process/log scope."""
import unittest
import soc_management_run as m


class ObservationScope(unittest.TestCase):
    def setUp(self):
        self.web={'kind':'web_access','target':'c:dvwa','logging_continuity_verified':False,
                  'coverage':{'files_unavailable':0},'apache_unit':{'ActiveState':'active'}}
        self.vector={'kind':'diagnostics','target':'a:vector',
                     'properties':{'ActiveState':'active','SubState':'running','Result':'success'}}
        self.facts=[self.web,self.vector]

    def test_nonweb_health_is_rejected_for_the_correct_scope(self):
        for text in ('a:vector 서비스는 정상 작동 중입니다.', 'Vector 서비스는 정상입니다.'):
            self.assertEqual(m.web_evidence_violations(text,self.facts),[])
            self.assertEqual(m.snapshot_health_violations(text,self.facts),
                             ['diagnostic_snapshot_is_not_functional_health'])
            self.assertIn('diagnostic_snapshot_is_not_functional_health',m.evidence_claim_violations(text,self.facts))
        self.assertEqual(m.snapshot_health_violations('서비스는 정상입니다.',[self.vector]),
                         ['diagnostic_snapshot_is_not_functional_health'])

    def test_known_nonweb_subject_never_excuses_a_separate_web_claim(self):
        for text in ('Vector 서비스는 정상입니다. Apache 서비스도 정상입니다.',
                     'Vector 서비스는 정상이며 DVWA도 정상입니다.',
                     'Vector가 처리하는 웹 서비스는 정상입니다.'):
            self.assertIn('web_snapshot_is_not_application_health',m.snapshot_health_violations(text,self.facts))

    def test_literal_process_observation_and_health_uncertainty_are_allowed(self):
        for text in ('a:vector의 ActiveState=active, SubState=running입니다. 서비스 기능 정상 여부는 미확인입니다.',
                     'Vector 서비스의 정상 작동 여부는 미확인입니다.',
                     'Apache 프로세스는 active입니다. 앱 정상 여부는 미확인입니다.'):
            self.assertEqual(m.snapshot_health_violations(text,self.facts),[])

    def test_negative_statement_cannot_hide_later_health_claim(self):
        text='서비스 영향은 미확인이지만 Apache는 정상입니다.'
        self.assertIn('web_snapshot_is_not_application_health',m.snapshot_health_violations(text,self.facts))

    def test_explicit_health_disclaimer_is_not_a_positive_claim(self):
        for text in ('failed 0개가 모든 서비스 정상을 뜻하지 않습니다.',
                     '서비스 정상 상태를 의미하지 않습니다.',
                     '서비스의 정상/장애 여부와는 무관합니다.'):
            self.assertEqual(m.snapshot_health_violations(text,self.facts),[])
            self.assertIn('web_snapshot_is_not_application_health',m.snapshot_health_violations(
                text+' 하지만 DVWA는 정상입니다.',self.facts))

    def test_unverified_is_not_a_failed_test_or_outage(self):
        for text in ('접근 로그 연속성 검증에 실패했습니다.',
                     '로그 연속성 검증 실패로 수집 복구가 필요합니다.'):
            self.assertIn('web_continuity_unverified_is_not_outage',m.web_evidence_violations(text,self.facts))
        for text in ('로그 연속성은 미검증이며 수집 장애 여부는 미확인입니다.',
                     '로그 수집 장애가 확인되면 복구안을 준비합니다.',
                     '로그 연속성 검증 실패로 단정하지 않습니다.',
                     '로그 연속성 검증에 실패한 것은 아닙니다.'):
            self.assertEqual(m.web_evidence_violations(text,self.facts),[])
        changed={**self.web,'coverage':{'files_unavailable':1}}
        self.assertNotIn('web_continuity_unverified_is_not_outage',m.web_evidence_violations(
            '접근 로그 수집 장애가 발생했습니다.',[changed]))

    def test_attached_negative_proof_predicate_does_not_trigger_rewrite(self):
        for text in ('전체 서비스 정상 상태를 증명하는 것이 아닙니다.',
                     '서비스가 정상임을 입증한 것은 아닙니다.',
                     '서비스 정상이라는 것을 보장하는 건 아님.',
                     '서비스가 정상 상태가 아닙니다.'):
            with self.subTest(text=text):
                self.assertEqual(m.snapshot_health_violations(text,[self.vector]),[])
                self.assertEqual(m.snapshot_health_violations(text,[self.web]),[])
                self.assertIn('web_snapshot_is_not_application_health',
                    m.snapshot_health_violations(text+' 하지만 DVWA는 정상입니다.',self.facts))

    def test_proof_discussion_does_not_hide_positive_or_rhetorical_claim(self):
        for text in ('전체 서비스 정상 상태를 증명했습니다.',
                     '서비스가 정상임을 입증하는 것이 아닌가?',
                     '서비스는 정상입니다. 이것이 위험 해소를 증명하는 것은 아닙니다.',
                     '서비스 정상 상태를 보장한 것은 아니지만 앱은 정상입니다.',
                     '서비스가 정상이라고 판단했으나 다른 오류는 미확인입니다.'):
            with self.subTest(text=text):
                self.assertTrue(m.snapshot_health_violations(text,[self.web]))

    def test_literal_diagnostic_receipt_does_not_invent_a_health_claim(self):
        facts=[{'kind':'diagnostics','target':h+':systemd',
                'lookback_scope':'latest_snapshot_only_not_requested_history',
                'observed_at_kst':'2026-11-06T20:00:00+09:00',
                'metrics':{'failed_units_total':0,'returned_units':0,'unit_list_truncated':False}}
               for h in 'abc']
        summary=m.literal_evidence_summary(facts)
        self.assertIn('전체 서비스 정상 판정이 아닙니다',summary)
        self.assertEqual(m.snapshot_health_violations(summary,facts),[])
        self.assertEqual(m.snapshot_health_violations(m.factual_review_report(facts),facts),[])
        self.assertTrue(m.snapshot_health_violations(summary+'\n전체 서비스는 정상입니다.',facts))

    def test_snapshot_only_cannot_prove_service_recovery_or_restarts(self):
        facts=[{'kind':'diagnostics','target':'b:systemd',
                'lookback_scope':'latest_snapshot_only_not_requested_history','metrics':{'failed_units_total':0}}]
        for text in ('현재 failed unit0이므로 해당 서비스들은 재기동되거나 복구된 상태입니다.',
                     '서비스는 복구되었습니다.', '서비스 재시작이 아니라 재기동된 상태입니다.'):
            self.assertEqual(m.snapshot_health_violations(text,facts),['diagnostic_snapshot_is_not_functional_health'])
        for text in ('서비스 복구 여부는 미확인입니다.', '서비스가 복구된 상태인지는 미확인입니다.',
                     '서비스가 복구된 것은 아닙니다.', '서비스가 복구되면 다시 검증합니다.'):
            self.assertEqual(m.snapshot_health_violations(text,facts),[])

    def test_window_total_without_count_unit_is_still_unverified(self):
        facts=[{'kind':'events','source':'wazuh','indexed_window_total_count':None,'returned_count':10}]
        for text in ('경보 10건(구간 전체 10)이 반환됐습니다.', '구간 전체: 10'):
            self.assertIn('unknown_window_total_claimed',m.evidence_claim_violations(text,facts))
        for text in ('반환 표본10건, 구간 전체 건수는 미확인입니다.', '구간 전체10인지 미확인입니다.'):
            self.assertNotIn('unknown_window_total_claimed',m.evidence_claim_violations(text,facts))

    def test_server_and_host_health_need_more_than_a_current_snapshot(self):
        facts=[{'kind':'diagnostics','target':'b:systemd',
                'lookback_scope':'latest_snapshot_only_not_requested_history','metrics':{'failed_units_total':0}}]
        for text in ('현재 서버 상태는 정상이다.', '호스트는 건강합니다.', 'systemd는 정상입니다.'):
            self.assertEqual(m.snapshot_health_violations(text,facts),['diagnostic_snapshot_is_not_functional_health'])
        for text in ('서버 정상 여부는 미확인입니다.', '현재 호스트 정상 상태를 증명하는 것이 아닙니다.',
                     'systemd 정상 판정이 아닙니다.'):
            self.assertEqual(m.snapshot_health_violations(text,facts),[])


if __name__=='__main__':unittest.main()
