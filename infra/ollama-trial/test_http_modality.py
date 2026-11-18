"""Outcome evidence negation and embedded questions do not assert causality."""
import unittest
import harness as h
import test_evidence_report as f

ISSUE='http_status_used_as_security_outcome'

class HttpModality(unittest.TestCase):
    def setUp(self):
        self.calls=[f.call(f.MOD,{'source':'modsecurity','alerts':[{'http_status':403}]})]

    def test_actual_plain_negation_and_embedded_questions_remain_non_assertions(self):
        for line in (
                'HTTP 403은 응답 코드일 뿐이며 WAF 차단 성공·백엔드 미도달·공격 실패의 증거가 아니다.',
                'HTTP 403은 WAF가 요청을 차단했는지, 백엔드에 도달했는지, 공격이 실패했는지는 이 데이터만으로는 확인할 수 없습니다.',
                'HTTP 상태 코드403이 실제 네트워크 차단이나 백엔드 접근 실패를 의미하는지는 추가 검증이 필요합니다.',
                'HTTP 403은 WAF 차단 성공을 의미하는지는 미확인입니다.'):
            self.assertNotIn(ISSUE,h.incident_field_violations(line,self.calls),line)

    def test_outcome_assertions_double_negations_and_independent_claims_remain_rejected(self):
        for line in ('HTTP 403이므로 WAF 차단 성공을 확인했습니다.',
                     'HTTP 403은 WAF 차단 성공을 의미합니다.',
                     'HTTP 403은 WAF 차단 성공의 증거가 아닌 것은 아니다.',
                     'HTTP 403은 WAF 차단 성공의 증거가 아니다는 것은 아닙니다.',
                     'HTTP 403은 WAF 차단 성공의 증거가 아니다. HTTP 403이므로 WAF 차단 성공입니다.'):
            self.assertIn(ISSUE,h.incident_field_violations(line,self.calls),line)

    def test_shared_modality_keeps_finite_predicates_and_other_claims_separate(self):
        for suffix in ('는지는 미확인입니다.','을 의미하는지는 확인이 필요합니다.',
                       '이 확인되는지는 미확인입니다.','의 증거가 아니다.'):
            self.assertIn(h.CONTRACT.claim_modality(suffix),('not_asserted','conditional_or_unverified'),suffix)
        for suffix in ('했다. 다른 주장은 근거가 아니다.','했지만 별개 근거는 아니다.',
                       '의 증거가 아닌 것은 아니다.'):
            self.assertNotIn(h.CONTRACT.claim_modality(suffix),('not_asserted','conditional_or_unverified'),suffix)

if __name__=='__main__':unittest.main()
