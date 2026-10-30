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
            'DVWA는 실습용 취약 서비스이므로, 공격 탐지 알림은 정상적인 테스트 행위일 가능성이 높다.',
            '내부 테스트 환경(DVWA) 접근이므로 필요시 WAF 예외 처리가 적절합니다.'):
            self.assertIn('environment_used_as_authorization',h.incident_context_violations(text),text)

    def test_unapproved_test_is_not_a_reason_to_allowlist(self):
        text='만약 이 트래픽이 비인가된 테스트라면 사용자에게 WAF 규칙 예외(whitelist) 추가 권고를 전달합니다.'
        self.assertIn('unapproved_activity_allowlist_advice',h.incident_context_violations(text))

    def test_valid_uncertainty_authorization_and_investigation_are_preserved(self):
        for text in (
            '내부 IP이므로 정상이라고 단정할 수 없습니다.',
            'DVWA 실습 환경이므로 정상 가능성이 높다고 단정할 수 없습니다.',
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

class FieldEvidence(unittest.TestCase):
    def setUp(self):
        self.row={'http_status':'302','engine':'DetectionOnly',
                  'transaction_id_sha256':'e9a86aa0'+'f'*56,
                  'wazuh_rule_id':'100102','wazuh_rule_description':'WAF command injection alert',
                  'waf_rule_matches':[{'rule_id':'949110','description':'Inbound Anomaly Score Exceeded (Total Score: 25)'}]}
        self.calls=self.make_calls(self.row)

    def make_calls(self,row):
        raw=json.dumps({'alerts':[row]})
        return [dict(server='security-events',name='search_modsecurity_alerts',result=raw,
                     result_sha256=hashlib.sha256(raw.encode()).hexdigest())]

    def test_observed_bad_field_and_causality_claims(self):
        cases={
            'HTTP 302는 WAF가 요청을 차단/리다이렉트했음을 시사합니다.':'http_status_used_as_security_outcome',
            'HTTP 302는 WAF가 요청을 차단/리다이렉트했음을 시사하나, 실제 서비스 서버 내부 처리 결과는 확인되지 않음.':'http_status_used_as_security_outcome',
            'HTTP200을 통해 명령 실행 성공 가능성을 알 수 있습니다.':'http_status_used_as_security_outcome',
            '응답 코드 403이므로 공격 실패입니다.':'http_status_used_as_security_outcome',
            'transaction_id: e9a86aa0… 로 원본 로그를 조회합니다.':'hash_presented_as_original_transaction_id',
            'Wazuh rule 100102: Inbound Anomaly Score Exceeded':'sensor_description_attributed_to_wazuh_rule',
            'Wazuh rule: 100102 (level 10, anomaly score exceeded)':'sensor_description_attributed_to_wazuh_rule'}
        for draft,issue in cases.items():
            with self.subTest(draft=draft):
                self.assertIn(issue,h.incident_field_violations(draft,self.calls))
                audit=h.incident_judgment_check('DVWA 공격인지 조사해줘',draft,self.calls)
                self.assertIn(issue,audit['issues'])
                instruction=h.incident_judgment_instruction('DVWA 공격인지 조사해줘',draft,self.calls,audit['issues'])
                self.assertIn(draft,instruction)
                self.assertIn(h.CONTRACT.EVENT_FIELD_GUIDANCE,instruction)

    def test_event_mode_is_not_a_current_configuration_read(self):
        self.assertIn('event_mode_presented_as_current_configuration',h.incident_field_violations(
            '현재 DetectionOnly이므로 실제 차단 모드로 변경하도록 설정을 검토합니다.',self.calls))
        for text in ('당시 경보에는 DetectionOnly라고 기록되어 있습니다.',
                     '현재 모드는 DetectionOnly인지 미확인입니다.',
                     '현재 WAF가 DetectionOnly인지, 아니면 차단 모드로 전환 가능한지 서비스 상태를 조회해야 합니다.',
                     '현재 DetectionOnly 모드인지 확인이 필요합니다.',
                     '만약 현재 DetectionOnly라면 운영 정책을 확인해야 합니다.'):
            self.assertEqual(h.incident_field_violations(text,self.calls),[],text)
        raw=json.dumps({'content':'SecRuleEngine DetectionOnly'})
        current=dict(server='resp',name='get_rule_change_target',result=raw,result_sha256=hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(h.incident_field_violations('현재 DetectionOnly입니다.',self.calls+[current]),[])

    def test_correct_observations_and_separate_execution_evidence_are_allowed(self):
        for text in (
            'HTTP302가 관측됐습니다. 이것만으로 WAF 차단 여부는 미확인입니다.',
            'HTTP 200은 명령 실행 성공을 입증하지 못합니다.',
            'HTTP 302는 리다이렉션 응답이며 생성 주체는 미확인입니다.',
            'HTTP 403입니다. 별도 실행 결과에서 WAF 차단을 확인했습니다.',
            'HTTP 200입니다. 호스트 프로세스 로그를 통해 명령 실행 성공을 확인했습니다.',
            'transaction_id_sha256: e9a86aa0… (해시 앞부분, 원본 ID 아님)',
            'Wazuh rule 100102는 WAF command injection alert입니다.',
            'Wazuh rule 100102와 WAF 949110의 Inbound Anomaly Score Exceeded는 다른 계층입니다.',
            'Wazuh rule 100102를 Inbound Anomaly Score Exceeded라고 부르면 안 됩니다.'):
            self.assertEqual(h.incident_field_violations(text,self.calls),[],text)

    def test_no_unverified_or_failed_read_is_used_for_field_comparisons(self):
        bad='transaction_id: e9a86aa0'
        for patch in ({'result_sha256':'bad'},{'is_error':True},{'server':'other'},{'name':'other'}):
            self.assertEqual(h.incident_field_violations(bad,[{**self.calls[0],**patch}]),[])
        self.assertEqual(h.incident_field_violations(bad,[]),[])
        row={**self.row,'waf_rule_matches':None}
        self.assertEqual(h.incident_field_violations('Wazuh rule 100102',self.make_calls(row)),[])

    def test_same_label_actually_present_on_both_layers_is_not_rejected(self):
        row={**self.row,'wazuh_rule_description':'Inbound Anomaly Score Exceeded'}
        self.assertEqual(h.incident_field_violations('Wazuh rule 100102 Inbound Anomaly Score Exceeded',self.make_calls(row)),[])

    def test_guidance_reaches_initial_and_repair_model_context(self):
        self.assertIn(h.CONTRACT.EVENT_FIELD_GUIDANCE,h.SYSTEM_PROMPT)
        self.assertIn(h.CONTRACT.EVENT_FIELD_GUIDANCE,h.incident_observation_prompt('DVWA 조사',self.calls))

if __name__=='__main__':unittest.main()
