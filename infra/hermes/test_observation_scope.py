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


if __name__=='__main__':unittest.main()
