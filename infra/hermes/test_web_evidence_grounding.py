"""Backend file samples cannot become full HTTP totals or health attestations."""
import json
import unittest
from types import SimpleNamespace
from test_soc_management_run import wrapper

class WebEvidence(unittest.TestCase):
    def facts(self):
        value={'source':'c_apache_access_snapshot','target':'c:dvwa',
            'observed_at_kst':'2026-11-04T18:00:00+09:00','requested_since_kst':'2026-11-04T17:00:00+09:00',
            'requested_until_kst':'2026-11-04T18:00:00+09:00','returned_count':0,'retained_index_match_count':0,
            'actual_request_total_count':None,'logging_continuity_verified':False,
            'apache_unit':{'ActiveState':'active'},'records':[]}
        return wrapper.observation_facts('search_web_access',SimpleNamespace(isError=False,
            content=[SimpleNamespace(text=json.dumps(value))]))

    def test_web_reads_are_registered_as_reads_without_new_writes(self):
        for name in ('get_web_service_target','search_web_access'):
            self.assertIn(name,wrapper.EVENT_READ);self.assertNotIn(name,wrapper.WRITE)

    def test_actual_web_total_remains_unknown_in_claim_guard(self):
        facts=self.facts();self.assertEqual(facts[0]['kind'],'web_access')
        self.assertTrue(wrapper.evidence_claim_violations('전체 0건의 요청입니다.',facts))
        self.assertFalse(wrapper.evidence_claim_violations('반환 표본 0건이며 실제 전체 요청 수는 미확인입니다.',facts))

    def test_fallback_report_is_table_and_preserves_evidence_limits(self):
        facts=self.facts();text=wrapper.factual_review_report(facts)
        self.assertIn('|',text);self.assertNotIn('```',text)
        self.assertIn('실제 전체 요청 수 미확인',text);self.assertIn('로깅 연속성 미검증',text)
        self.assertIn('c:dvwa',text);self.assertIn('프런트',wrapper.literal_evidence_summary(facts))

    def test_bounded_web_index_caveat_and_application_health_claim_are_checked(self):
        facts=self.facts();facts[0]['coverage']={'rows_truncated':True}
        bad='DVWA 접근 기록입니다.\nApache 상태: active (정상)\n반환 표본 0건, 전체 요청 수 미확인.'
        issues=wrapper.evidence_claim_violations(bad,facts)
        self.assertIn('web_access_coverage_limit_omitted',issues)
        self.assertIn('web_snapshot_is_not_application_health',issues)
        good='보관 행 상한으로 잘림이 있습니다. Apache 프로세스는 실행 중이며 앱 정상 여부는 미확인입니다.'
        self.assertFalse(wrapper.web_evidence_violations(good,facts))
        self.assertFalse(wrapper.web_evidence_violations(wrapper.factual_review_report(facts),facts))
        self.assertIn('잘림',wrapper.literal_evidence_summary(facts))

    def test_negative_health_caution_does_not_hide_a_separate_positive_claim(self):
        facts=self.facts()
        self.assertFalse(wrapper.web_evidence_violations('Apache active는 앱 정상을 증명하지 않습니다.',facts))
        self.assertIn('web_snapshot_is_not_application_health',wrapper.web_evidence_violations('앱 정상 미확인입니다. Apache 정상입니다.',facts))

if __name__=='__main__':unittest.main()
