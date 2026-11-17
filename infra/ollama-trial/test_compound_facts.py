"""Counterexamples from compound model reports; no new tools or verdicts."""
import copy
import hashlib
import json
import unittest
import harness as h


def call(source, ips, envelope=False):
    raw=json.dumps({'source':source,'alerts':[{'source_ip':ip,'http_status':'403'} for ip in ips]})
    if envelope:raw=json.dumps({'result':raw})
    return {'server':'security-events','name':'search_'+source+'_alerts','arguments':{},
            'result':raw,'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}


class CompoundFactBinding(unittest.TestCase):
    def setUp(self):
        self.calls=[call('modsecurity',['192.0.2.232']),call('suricata',['192.0.2.232','192.0.2.230'])]

    def test_table_and_prose_status_claims_need_more_than_response_codes(self):
        for text in (
            '| ModSecurity 경보 차단 여부 | 차단 입증됨 | http_status가 403으로 기록됨 |',
            'ModSecurity 요청들은 모두 HTTP 403으로 차단되었습니다.',
            'ModSecurity의 http_status: 403 필드에서 웹 요청 차단을 입증했습니다.',
            'WAF는 HTTP 403으로 요청을 차단하고 있는 상태입니다.'):
            with self.subTest(text=text):
                self.assertIn('http_status_used_as_security_outcome',h.incident_field_violations(text,self.calls))

    def test_status_only_uncertainty_and_separate_proof_are_not_rewritten(self):
        for text in ('WAF http_status: 403입니다. 차단 주체는 미확인입니다.',
                     '| WAF 요청 차단 | 미확인 | HTTP 403만 관측 |',
                     'HTTP 403입니다. 별도 실행 기록에서 WAF 차단을 확인했습니다.',
                     'WAF HTTP 403 응답이지만 실제 차단은 확인해야 합니다.'):
            self.assertNotIn('http_status_used_as_security_outcome',h.incident_field_violations(text,self.calls))

    def test_a_peer_source_is_not_a_source_of_this_sensor(self):
        before=copy.deepcopy(self.calls)
        for text in ('| ModSecurity 경보 | 192.0.2.230, 192.0.2.232 | 주요 출발지 IP | 전체 건수 미확인 |',
                     'WAF 출발지는 192.0.2.230입니다.'):
            self.assertIn('source_address_attributed_to_wrong_sensor',h.incident_field_violations(text,self.calls))
        self.assertEqual(self.calls,before)

    def test_correct_unknown_destination_and_joint_source_claims_remain_distinct(self):
        for text in ('| WAF 출발지 | 192.0.2.232 | 실제 표본 |',
                     '| IDS 출발지 | 192.0.2.230, 192.0.2.232 | 실제 표본 |',
                     '| WAF 출발지 | 192.0.2.230은 미확인 | 추가 근거 필요 |',
                     'WAF와 IDS의 출발지 표본에는 192.0.2.230, 192.0.2.232가 있습니다.',
                     'WAF 출발지 192.0.2.232, 목적지 192.0.2.230은 별도 확인이 필요합니다.'):
            self.assertNotIn('source_address_attributed_to_wrong_sensor',h.incident_field_violations(text,self.calls))

    def test_native_envelopes_keep_the_same_sensor_boundary(self):
        calls=[call('modsecurity',['192.0.2.232'],True),call('suricata',['192.0.2.230'],True)]
        text='| WAF 경보 출발지 | 192.0.2.230 | 반환 표본 |'
        self.assertIn('source_address_attributed_to_wrong_sensor',h.incident_field_violations(text,calls))
        calls[0]['result_sha256']='0'*64
        self.assertNotIn('source_address_attributed_to_wrong_sensor',h.incident_field_violations(text,calls))

    def test_factual_claim_checks_do_not_require_incident_routing(self):
        for q in ('WAF 경보 보여줘', 'WAF와 IDS 경보의 공통 출발지를 비교해줘'):
            draft='| ModSecurity 경보 | 192.0.2.230 | 주요 출발지 IP | 전체 건수 미확인 |\nModSecurity 요청들은 모두 HTTP 403으로 차단되었습니다.'
            issues=h.violations(q,draft,self.calls)
            self.assertIn('http_status_used_as_security_outcome',issues)
            self.assertIn('source_address_attributed_to_wrong_sensor',issues)

    def test_nonobject_or_failed_native_envelopes_never_crash_or_supply_fields(self):
        for data in ([],['bad'],'not an event',None,{'result':'{}','isError':True}):
            raw=json.dumps({'result':json.dumps(data)})
            c=dict(self.calls[0],result=raw,result_sha256=hashlib.sha256(raw.encode()).hexdigest())
            self.assertEqual(h.incident_field_violations('WAF HTTP 403으로 요청 차단됨',[c]),[])


if __name__=='__main__':unittest.main()
