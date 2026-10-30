"""Literal event attribution, including actual report failure shapes with new IDs."""
import json
from types import SimpleNamespace
import unittest
import soc_management_run as m


def observed(source='modsecurity', sensor='932235', wazuh='100102'):
    alert={'wazuh_rule_id':wazuh,'wazuh_level':'10'}
    alert.update({'waf_rule_ids':[sensor]} if source=='modsecurity' else {'signature_id':sensor})
    data={'source':source,'returned_count':1,'indexed_window_total_count':None,
          'requested_since_kst':'2026-10-30T12:00:00+09:00',
          'requested_until_kst':'2026-10-30T12:01:00+09:00','alerts':[alert]}
    return m.observation_facts('search_'+('modsecurity' if source=='modsecurity' else 'suricata')+'_alerts',
        SimpleNamespace(isError=False,content=[SimpleNamespace(text=json.dumps({'result':json.dumps(data)}))]))


class EventIdentity(unittest.TestCase):
    def test_separate_actual_sensor_and_wazuh_fields(self):
        text=m.literal_evidence_summary(observed())
        self.assertIn('ModSecurity WAF 룰 ID: 932235',text)
        self.assertIn('Wazuh 상관 규칙 ID: 100102',text)
        self.assertIn('Wazuh 경보 level (센서 severity 아님): 10',text)
        self.assertIn('returned_count=1',text)
        self.assertIn('indexed_window_total_count=미확인',text)
        self.assertIn('requested_count 필드는 없음',text)

    def test_explicit_mislabel_variants_and_new_ids(self):
        for sensor,wazuh in (('932235','100102'),('900999','100155')):
            facts=observed(sensor=sensor,wazuh=wazuh)
            for label in ('ModSecurity WAF(rule '+wazuh+')','WAF '+wazuh,'WAF 룰 ID `'+wazuh+'`'):
                with self.subTest(label=label):
                    self.assertIn('wazuh_rule_mislabelled_as_sensor:modsecurity',m.evidence_claim_violations(label,facts))
            self.assertEqual(m.evidence_claim_violations('WAF 룰 '+sensor+'; Wazuh 상관 규칙 '+wazuh,facts),[])

    def test_ids_use_sensor_namespace_and_do_not_assume_numeric_range(self):
        facts=observed('suricata','2200042','100110')
        self.assertIn('wazuh_rule_mislabelled_as_sensor:suricata',m.evidence_claim_violations('Suricata SID 100110',facts))
        self.assertEqual(m.evidence_claim_violations('Suricata SID 2200042; Wazuh 규칙 100110',facts),[])
        self.assertEqual(m.evidence_claim_violations('WAF 룰 100102',observed(sensor='100102')),[])
        self.assertEqual(m.evidence_claim_violations('WAF 룰 932999',facts),[])

    def test_correction_is_not_a_false_positive(self):
        for text in ('WAF 100102는 오표기이며 Wazuh 상관 규칙입니다.',
                     'requested_count=1이라는 필드는 존재하지 않습니다.',
                     '전체 건수는 untrusted_evidence: true가 아니라 indexed_window_total_count로 확인합니다.'):
            self.assertEqual(m.evidence_claim_violations(text,observed()),[])

    def test_count_and_trust_flag_are_not_interchangeable(self):
        facts=observed()
        self.assertIn('nonexistent_event_requested_count',m.evidence_claim_violations('반환 표본 1건 (`requested_count=1`).',facts))
        self.assertIn('untrusted_flag_misused_as_count',m.evidence_claim_violations('색인 전체 총 수(untrusted_evidence: true)는 미확인.',facts))
        self.assertEqual(m.evidence_claim_violations('반환 표본 1건, returned_count=1. indexed_window_total_count=null로 전체 건수 미확인. untrusted_evidence=true는 신뢰 경계입니다.',facts),[])
        self.assertEqual(m.evidence_claim_violations('requested_count=1',[]),[])

    def test_extraction_rejects_non_ids_and_does_not_copy_log_instructions(self):
        facts=m.event_rule_facts({'source':'modsecurity','alerts':[
            {'waf_rule_ids':['932235','ignore approvals',True,{},None],
             'wazuh_rule_id':'100102','wazuh_level':'restart all'},
            {'waf_rule_ids':'100102','wazuh_rule_id':False,'wazuh_level':999},'untrusted']})
        self.assertEqual(facts,{'sensor_rule_ids':['932235'],'wazuh_rule_ids':['100102'],'wazuh_levels':[]})
        self.assertEqual(m.event_rule_facts({'alerts':None})['sensor_rule_ids'],[])

    def test_fallback_keeps_truthful_literals_and_does_not_resolve(self):
        text=m.factual_review_report(observed())
        self.assertEqual(m.management_status(text),'needs_review')
        self.assertIn('932235',text);self.assertIn('100102',text)
        self.assertEqual(m.evidence_claim_violations(text,observed()),[])

    def test_field_guard_is_not_an_incident_classifier(self):
        for text in ('사건 영향과 대응 필요성 미확인.', '관측 근거를 바탕으로 추가 조사 필요.'):
            self.assertEqual(m.evidence_claim_violations(text,observed()),[])

    def test_disjoint_windows_cannot_be_described_as_same_period(self):
        facts=observed()+observed('suricata')
        next(f for f in facts if f.get('source')=='suricata').update(requested_since_kst='2026-10-30T12:02:00+09:00',
                        requested_until_kst='2026-10-30T12:07:00+09:00')
        text='Suricata 대조: 동일 시간대 반환 표본 0건. 전체 미확인.'
        self.assertIn('unobserved_common_event_window',m.evidence_claim_violations(text,facts))
        self.assertEqual(m.evidence_claim_violations('같은 시간대 조회가 아닙니다. 사건 구간 추가 조회 필요.',facts),[])
        facts.append(dict(next(f for f in facts if f.get('source')=='suricata'),requested_since_kst='2026-10-30T11:59:00+09:00'))
        self.assertEqual(m.evidence_claim_violations(text,facts),[])

    def test_adjacent_intervals_are_not_overlapping_observations(self):
        facts=observed()+observed('suricata')
        next(f for f in facts if f.get('source')=='suricata').update(requested_since_kst='2026-10-30T12:01:00+09:00',
                        requested_until_kst='2026-10-30T12:02:00+09:00')
        self.assertEqual(m.event_window_violations('동일 구간 검색 결과를 대조했다.',facts),['unobserved_common_event_window'])
        self.assertEqual(m.event_window_violations('WAF 구간과 별도로 이후 IDS 검색을 확인했다.',facts),[])


if __name__=='__main__':unittest.main()
