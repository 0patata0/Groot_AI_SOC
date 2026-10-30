"""Actual failed reasoning replay and counterexamples, no risk classification."""
import copy
import hashlib
import json
import unittest
import harness as h


class AuthorizationEvidence(unittest.TestCase):
    def test_internal_address_is_not_a_benign_or_no_response_basis(self):
        for text in (
            '외부 공격자가 아닌 내부 IP에서 발생했으므로 긴급 차단 대상은 아닙니다.',
            '사설 주소이므로 대응이 불필요합니다.',
            'DVWA는 테스트 환경이므로 정상으로 판정합니다.',
            '내부 테스트 환경(DVWA) 접근이므로 필요시 WAF 예외 처리가 적절합니다.'):
            self.assertIn('environment_used_as_authorization',h.incident_context_violations(text),text)

    def test_unapproved_test_is_not_a_reason_to_allowlist(self):
        text='만약 이 트래픽이 비인가된 테스트라면 사용자에게 WAF 규칙 예외(whitelist) 추가 권고를 전달합니다.'
        self.assertIn('unapproved_activity_allowlist_advice',h.incident_context_violations(text))

    def test_valid_uncertainty_authorization_and_investigation_are_preserved(self):
        for text in (
            '내부 IP이므로 정상이라고 단정할 수 없습니다.',
            'DVWA 테스트 환경은 정상 판정의 근거가 아닙니다.',
            '사설 주소이지만 공격 근거가 있어 추가 조사와 제한된 대응안을 검토해야 합니다.',
            '내부 IP에서 탐지되었습니다. 해당 시각·출발지의 시험 승인을 관리자가 확인했습니다. 영향은 미확인입니다.',
            '비인가 테스트에 WAF 예외를 추가해서는 안 됩니다.',
            '미승인 행위에 whitelist 등록을 권장하지 않습니다.',
            '현재 증거만으로 즉시 차단 필요성을 확정할 수 없어 추가 조사합니다.',
            '내부 IP는 정책의 보호 주소 목록과 별도로 확인해야 합니다.'):
            self.assertEqual(h.incident_context_violations(text),[],text)

    def test_actual_observations_do_not_authorize_the_actor(self):
        raw=json.dumps({'source':'modsecurity','alerts':[],'returned_count':0,'indexed_window_total_count':None})
        c=dict(server='security-events',name='search_modsecurity_alerts',arguments={},result=raw,
               result_sha256=hashlib.sha256(raw.encode()).hexdigest())
        q='DVWA 공격인지 실제 근거로 조사해줘'
        draft='사설 주소이므로 대응이 불필요합니다.'
        a=h.incident_judgment_check(q,draft,[c])
        self.assertIn('environment_used_as_authorization',a['issues'])
        prompt=h.incident_judgment_instruction(q,draft,[c],a['issues'])
        self.assertIn('flagged_lines',prompt)
        self.assertIn('시험 여부는 미확인',prompt)
        self.assertIn('<untrusted_tool_observations>',prompt)

    def test_scope_does_not_reclassify_an_ordinary_policy_explanation(self):
        self.assertEqual(h.violations('사설 IP의 의미를 설명해줘','사설 주소이므로 대응이 불필요합니다.',[]),[])

if __name__=='__main__':unittest.main()
