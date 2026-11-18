"""Compare only literal returned source sets; keep complete existing evidence."""
import copy
import unittest
import harness as h
import test_evidence_report as fixture

Q='최근30분 WAF·IDS 경보를 조사해서 출발지를 장비별로 비교해줘'

def context(q=Q,ips=(('192.0.2.232',),('192.0.2.230','192.0.2.232'))):
    rows=[fixture.call(tool,{'source':source,'alerts':[{'source_ip':ip} for ip in addresses],
         'requested_since_kst':'2026-11-18T01:00:00+09:00','requested_until_kst':'2026-11-18T01:30:00+09:00'})
         for tool,source,addresses in zip((fixture.MOD,fixture.SUR),('modsecurity','suricata'),ips)]
    return h.evidence_report_context(q,rows,fixture.AT,(fixture.MOD,fixture.SUR)),rows

class SourceComparison(unittest.TestCase):
    def test_shared_source_and_only_one_sensor_source_have_separate_rows(self):
        body,_=context();before=copy.deepcopy(body);text=h.evidence_source_comparison(body)
        self.assertIn('| 출발지 IP | WAF 표본 | IDS 표본 |',text)
        self.assertIn('| 192.0.2.230 | 이 반환 표본에서 확인 안 됨 | 관측됨 |',text)
        self.assertIn('| 192.0.2.232 | 관측됨 | 관측됨 |',text)
        self.assertEqual(body,before);self.assertIn('같은 흐름/사건',text)
        self.assertNotIn('공격자',text);self.assertNotIn('receipt_sha256',text)
    def test_comparison_retains_all_existing_fact_tables_and_the_model_decision(self):
        body,calls=context();review={'assessment':'unresolved','basis':'현재 표본의 출발지를 대조했으나 실제 영향과 승인 여부는 미확인입니다.',
            'evidence_tools':[fixture.MOD,fixture.SUR],'limitations':['표본 범위입니다.'],'next_steps':[],'status':'needs_review'}
        body['question']=Q+' 상세 표로 보여줘'
        prior=h.EVIDENCE.render_model_review(review,h.facts_for(calls));text=h.evidence_report_text(review,calls,body)
        self.assertTrue(text.endswith(prior));self.assertTrue(text.startswith('**출발지 표본 비교**'))
        self.assertTrue(text.endswith('MANAGEMENT_STATUS: needs_review'));self.assertEqual(text.count('INCIDENT_DISPOSITION:'),1)
    def test_unasked_quoted_and_prohibited_comparisons_are_not_added(self):
        body,_=context()
        for q in ('WAF·IDS 사건을 조사해줘','WAF·IDS 출발지를 비교하지 말고 원문만 보여줘','"WAF IDS 출발지 비교"라는 문구를 설명해줘'):
            body['question']=q;self.assertEqual(h.evidence_source_comparison(body),'',q)
    def test_empty_samples_are_not_an_absence_or_host_identity_verdict(self):
        body,_=context(ips=((),()));text=h.evidence_source_comparison(body)
        self.assertIn('유효 출발지 IP는 0개',text);self.assertIn('반환 표본끼리',text)
        self.assertNotIn('공격이 없',text);self.assertNotIn('정상',text)
    def test_different_queries_of_one_sensor_are_not_merged_across_windows(self):
        body,calls=context();extra=fixture.call(fixture.MOD,{'source':'modsecurity','alerts':[{'source_ip':'192.0.2.231'}],
            'requested_since_kst':'2026-11-18T00:00:00+09:00','requested_until_kst':'2026-11-18T00:30:00+09:00'},arguments={'window':'earlier'})
        body=h.evidence_report_context(Q,[*calls,extra],fixture.AT,(fixture.MOD,fixture.SUR));text=h.evidence_source_comparison(body)
        self.assertIn('| 출발지 IP | WAF 표본 1 | IDS 표본 | WAF 표본 2 |',text)
        self.assertIn('| 192.0.2.231 | 이 반환 표본에서 확인 안 됨 | 이 반환 표본에서 확인 안 됨 | 관측됨 |',text)
        self.assertIn('2026-11-18T00:00:00+09:00',text)
    def test_display_bounds_are_explicit_and_never_report_missing_ips_as_absent(self):
        body,_=context(ips=(tuple('192.0.2.'+str(i) for i in range(129)),('198.51.100.1',)))
        text=h.evidence_source_comparison(body);self.assertIn('표시 한도',text);self.assertIn('미완료',text)
    def test_known_kst_is_not_shifted_and_utc_scope_is_converted_only_for_display(self):
        body,_=context();body['derived_sample_source_sets'][0]['requested_since_kst']='2026-11-17T16:00:00+00:00'
        text=h.evidence_source_comparison(body);self.assertIn('2026-11-18T01:00:00+09:00',text)
        self.assertNotIn('2026-11-18T10:00:00',text)

    def test_fallback_and_repeated_formatting_keep_verified_table_and_unknowns(self):
        body,_=context();unknown='조사를 완료하지 못했습니다. 실제 영향은 미확인입니다.'
        text=h.add_evidence_source_comparison(body,unknown)
        self.assertTrue(text.endswith(unknown));self.assertTrue(text.startswith('**출발지 표본 비교**'))
        self.assertEqual(h.add_evidence_source_comparison(body,text),text)

if __name__=='__main__':unittest.main()
