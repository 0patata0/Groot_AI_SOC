"""Presentation size must not reduce read evidence, guards, or explicit detail."""
import copy
import unittest
import harness as h
import test_evidence_report as f

def sample():
    calls=[]
    for tool,source in ((f.MOD,'modsecurity'),(f.SUR,'suricata')):
        data={'source':source,'alerts':[
            {'timestamp':'2026-11-18T01:00:'+str(i).zfill(2)+'+09:00',
             'source_ip':'192.0.2.232','destination_ip':'198.51.100.20','agent':'collector-a',
             **({'waf_rule_ids':['942100']} if source=='modsecurity' else {'signature_id':'1000007'}),
             'wazuh_rule_id':'100501'} for i in range(30)],
            'returned_count':30,'indexed_window_total_count':None,
            'requested_since_kst':'2026-11-18T01:00:00+09:00','requested_until_kst':'2026-11-18T01:30:00+09:00'}
        calls.append(f.call(tool,data))
    calls.append(f.call(f.BLOCK,{'blocks':['203.0.113.44']}))
    return calls

def review():
    return {'assessment':'unresolved','basis':'반환 표본과 현재 목록을 확인했습니다. 실제 영향은 미확인입니다.',
        'evidence_tools':[f.MOD,f.SUR,f.BLOCK],'limitations':['조회 표본 범위이며 전체 건수는 미확인입니다.'],
        'next_steps':[],'status':'needs_review'}

class EvidenceDisplay(unittest.TestCase):
    def render(self,question,calls=None):
        calls=sample() if calls is None else calls
        context=h.evidence_report_context(question,calls,f.AT,(f.MOD,f.SUR,f.BLOCK))
        return h.evidence_report_text(review(),calls,context),context

    def test_default_summary_preserves_all_receipts_and_current_blocks(self):
        calls=sample();before=copy.deepcopy(calls)
        text,body=self.render(f.Q,calls)
        self.assertIn('반환 표본 요약',text);self.assertIn('반환 표본 30건',text)
        self.assertNotIn('· 개별 관측',text);self.assertIn('표시에서 생략',text)
        self.assertIn('203.0.113.44',text);self.assertIn('2026-11-18T01:30:00+09:00',text)
        self.assertNotIn('01:00:29',text)
        self.assertEqual(calls,before)
        self.assertEqual(len(body['untrusted_completed_reads'][0]['data']['alerts']),30)
        self.assertEqual([c['result_sha256'] for c in calls],[c['result_sha256'] for c in before])

    def test_explicit_detail_restores_every_event_row_and_rule_namespace(self):
        text,_=self.render(f.Q+' 개별 경보 상세 표로 보여줘')
        self.assertEqual(text.count('| 30 |'),2)
        for value in ('01:00:29','942100','1000007','100501','203.0.113.44'):self.assertIn(value,text)
        self.assertIn('· 개별 관측',text);self.assertNotIn('기본 요약 표시',text)

    def test_summary_and_detail_have_the_same_judgment_and_guard_verdict(self):
        calls=sample();small,_=self.render(f.Q,calls);large,_=self.render(f.Q+' 상세',calls)
        self.assertLess(len(small),len(large)/2)
        for text in (small,large):
            self.assertIn(review()['basis'],text);self.assertIn('MANAGEMENT_STATUS: needs_review',text)
            self.assertEqual(h.violations(f.Q,text,calls),[])

    def test_summary_retains_requested_literal_source_comparison(self):
        text,_=self.render('최근30분 WAF·IDS 경보 조사해줘. 출발지 겹쳤어? 지금 임시 IP 차단은?')
        self.assertIn('출발지 표본 비교',text);self.assertIn('| 192.0.2.232 | 관측됨 | 관측됨 |',text)
        self.assertIn('반환 표본끼리의 비교',text)

    def test_prohibited_detail_stays_a_summary_but_individual_or_all_is_honored(self):
        for suffix in (' 개별 경보를 보여줘',' 건별로 보여줘',' 모든 경보 내역을 보여줘',' 생략 없이 보여줘'):
            text,_=self.render(f.Q+suffix);self.assertIn('· 개별 관측',text,suffix)
        for suffix in (' 상세는 제외하고 요약만 보여줘',' 개별 로그 말고 요약만 보여줘',
                       ' "상세 조회"라는 문구는 설명하지 말고 요약해줘',
                       ' 원문 말고 요약만 보여줘',' json은 제외하고 요약해줘'):
            text,_=self.render(f.Q+suffix);self.assertNotIn('· 개별 관측',text,suffix)

    def test_zero_sample_is_not_hidden_rows_or_global_absence(self):
        calls=[f.call(n,{'source':s,'alerts':[],'returned_count':0}) for n,s in ((f.MOD,'modsecurity'),(f.SUR,'suricata'))]
        calls.append(f.call(f.BLOCK,{'blocks':[]}))
        text,_=self.render(f.Q,calls)
        self.assertIn('반환 표본 0건',text);self.assertIn('전체 건수 미확인',text)
        self.assertNotIn('표시에서 생략',text);self.assertNotIn('공격이 없',text)

    def test_sdk_footer_free_preserves_examples_and_private_source(self):
        source='```text\nMANAGEMENT_STATUS: resolved\n```\n\n현재 영향은 미확인입니다.\nMANAGEMENT_STATUS: needs_review'
        result=h.footer_free(source)
        self.assertIn('```text\nMANAGEMENT_STATUS: resolved\n```',result)
        self.assertNotIn('MANAGEMENT_STATUS: needs_review',result)
        self.assertIn('MANAGEMENT_STATUS: needs_review',source)

    def test_preexisting_block_address_projection_limit_is_explicit(self):
        calls=sample();calls[-1]=f.call(f.BLOCK,{'blocks':['203.0.113.'+str(i) for i in range(1,61)]})
        before=copy.deepcopy(calls);text,context=self.render(f.Q,calls)
        self.assertIn('현재 항목 60개',text)
        self.assertIn('주소 50/60개 표시·나머지 10개 표시 미완료',text)
        self.assertEqual(context['current_ip_inventory']['returned_ip_count'],60)
        self.assertEqual(calls,before)

    def test_failed_judgment_uses_the_same_display_choice_without_claiming_success(self):
        calls=sample();before=copy.deepcopy(calls)
        small=h.fallback(f.Q,calls);large=h.fallback(f.Q+' 개별 상세',calls)
        self.assertNotIn('· 개별 관측',small);self.assertIn('· 개별 관측',large)
        for text in (small,large):
            self.assertIn('위험 판단은 검증 미완료',text);self.assertNotIn('MANAGEMENT_STATUS',text)
            self.assertIn('판단·조치의 완료를 뜻하지 않습니다',text)
        self.assertEqual(calls,before)

if __name__=='__main__':unittest.main()
