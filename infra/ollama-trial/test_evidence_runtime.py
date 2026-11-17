"""Exercise the opt-in report/read seam with real JSON Schema validation."""
import json
import hashlib
import unittest
import test_runtime

MOD='mcp__security_events__search_modsecurity_alerts'
EXTRA='mcp__security_events__search_wazuh_alerts'
WRITE='mcp__rule_write_a__propose_rule_edit'
Q='DVWA 공격인지 실제 근거와 영향을 조사해줘'

def report(indexes=(0,),basis=None):
    return {'more_evidence':False,'report':{'assessment':'unresolved',
        'basis':basis or '현재 반환 표본으로 실제 공격 여부와 영향은 미확인이며 추가 근거가 필요합니다.',
        'evidence_indexes':list(indexes),'limitations':['조회 표본만으로 사건 종결을 입증하지 못했습니다.'],
        'next_steps':[],'status':'needs_review'}}

def inquiry(tool=EXTRA,args=None):
    return {'more_evidence':True,'calls':[{'tool':tool,'arguments':args or {'target':'fixture'}}],'report':None}

class EvidenceRuntime(unittest.TestCase):
    def execute(self,plans,**kwargs):
        fixture=test_runtime.PreparationLoop()
        result,prompts,calls=fixture.execute(question=kwargs.pop('question',Q),read_incident=True,compact_plans=plans,**kwargs)
        self.fixture=fixture
        return result,prompts,calls

    def test_report_uses_real_current_receipts_without_a_second_unstructured_model(self):
        result,prompts,calls=self.execute([report()])
        self.assertEqual(calls,['search_modsecurity_alerts']);self.assertEqual(prompts,[])
        self.assertEqual(result['status'],'partial');self.assertEqual(result['protected_calls'],0)
        self.assertFalse(result.get('remaining_issues'))
        context=json.loads(self.fixture.compact_prompts[0][1]['content'])
        self.assertEqual(context['untrusted_completed_reads'][0]['receipt_sha256'],result['calls'][0]['result_sha256'])
        self.assertEqual(context['untrusted_completed_reads'][0]['data']['source'],'modsecurity')
        self.assertIn('미확인',result['final_response']);self.assertEqual(result['last_evidence_review']['evidence_tools'],[MOD])
        self.assertEqual(json.loads(result['evidence_report_audit'][0]['raw_response']),result['evidence_report_audit'][0]['response'])
        self.assertIsNone(result['evidence_report_audit'][0]['parsing_error_type'])

    def test_model_selected_additional_read_is_executed_before_a_new_judgment(self):
        result,prompts,calls=self.execute([inquiry(),report((0,1))])
        self.assertEqual(calls,['search_modsecurity_alerts','search_wazuh_alerts']);self.assertEqual(prompts,[])
        self.assertEqual(result['evidence_inquiry_count'],1);self.assertEqual(result['status'],'partial')
        self.assertFalse(result.get('remaining_issues'))
        body=json.loads(self.fixture.compact_prompts[1][1]['content'])
        self.assertEqual(len(body['untrusted_completed_reads']),2)
        self.assertEqual({r['receipt_sha256'] for r in body['untrusted_completed_reads']},{r['result_sha256'] for r in result['calls']})
        self.assertEqual(set(result['last_evidence_review']['evidence_tools']),{MOD,EXTRA})
        self.assertEqual(result['protected_calls'],0)

    def test_protected_member_rejects_the_whole_batch_before_any_dispatch(self):
        bad=inquiry();bad['calls'].append({'tool':WRITE,'arguments':{}})
        result,_,calls=self.execute([bad,report()])
        self.assertEqual(calls,['search_modsecurity_alerts']);self.assertEqual(result['evidence_schema_repairs'],1)
        self.assertTrue(result['evidence_report_audit'][0]['rejected_before_dispatch'])
        self.assertEqual(result['protected_calls'],0)

    def test_identical_successful_read_is_not_dispatched_again(self):
        result,_,calls=self.execute([inquiry(MOD,{'target':'fixture'}),report()])
        self.assertEqual(calls,['search_modsecurity_alerts'])
        self.assertEqual(result['evidence_inquiry_rejections'][0]['code'],'already_completed_read')
        self.assertEqual(result['status'],'partial');self.assertFalse(result.get('remaining_issues'))

    def test_repeat_rejection_stops_with_no_fake_completion_or_protected_call(self):
        result,_,calls=self.execute([inquiry(MOD,{'target':'fixture'})])
        self.assertEqual(calls,['search_modsecurity_alerts']);self.assertEqual(result['status'],'partial')
        self.assertEqual(result['stop_reason'],'repeated_evidence_inquiry_rejection');self.assertEqual(result['protected_calls'],0)

    def test_failed_extra_read_is_visible_and_is_not_a_successful_citation(self):
        result,_,calls=self.execute([inquiry(),report()],extra_read_error=True)
        self.assertEqual(calls,['search_modsecurity_alerts','search_wazuh_alerts'])
        body=json.loads(self.fixture.compact_prompts[1][1]['content'])
        self.assertEqual(len(body['untrusted_failed_reads']),1)
        self.assertTrue(body['untrusted_failed_reads'][0]['is_error'])
        self.assertEqual(result['last_evidence_review']['evidence_tools'],[MOD]);self.assertEqual(result['protected_calls'],0)

    def test_false_claim_is_returned_to_the_same_phase_for_correction_without_rereading(self):
        bad=report(basis='WAF 경보는 0건이므로 실제 공격이 없고 정상 상태임을 확인했습니다.')
        result,prompts,calls=self.execute([bad,report()])
        self.assertEqual(calls,['search_modsecurity_alerts']);self.assertEqual(prompts,[])
        self.assertEqual(result['status'],'partial');self.assertEqual(len(self.fixture.compact_prompts),2)
        self.assertFalse(result.get('remaining_issues'))
        feedback=json.loads(self.fixture.compact_prompts[-1][1]['content'])['untrusted_report_feedback']
        self.assertTrue(feedback['issues']);self.assertEqual(feedback['untrusted_rejected_report']['basis'],bad['report']['basis'])
        self.assertNotIn(bad['report']['basis'],result['final_response'])

    def test_pending_read_is_not_accepted_or_silently_executed_before_model_inquiry(self):
        value=report();value['report']['next_steps']=[{'kind':'read_proposal','tool':EXTRA,'arguments':{'target':'fixture'}}]
        result,_,calls=self.execute([value,inquiry(),report((0,1))])
        self.assertEqual(calls,['search_modsecurity_alerts','search_wazuh_alerts'])
        self.assertEqual(result['evidence_schema_repairs'],1);self.assertEqual(result['evidence_inquiry_count'],1)
        self.assertTrue(result['evidence_report_audit'][0]['rejected_before_dispatch'])
        self.assertFalse(result.get('remaining_issues'));self.assertEqual(result['protected_calls'],0)

    def test_exhausted_inquiry_can_keep_a_pending_proposal_without_executing_it(self):
        value=report((0,1));value['report']['next_steps']=[{'kind':'read_proposal','tool':EXTRA,'arguments':{'target':'later'}}]
        result,_,calls=self.execute([inquiry(args={'target':'one'}),inquiry(args={'target':'two'}),value])
        self.assertEqual(calls,['search_modsecurity_alerts','search_wazuh_alerts','search_wazuh_alerts'])
        self.assertEqual(result['evidence_inquiry_count'],2);self.assertEqual(result['status'],'partial')
        self.assertIn('미실행·미예약',result['final_response']);self.assertEqual(result['protected_calls'],0)

    def test_parse_failure_keeps_raw_output_and_repairs_without_another_read(self):
        result,_,calls=self.execute([report()],compact_parse_error=True)
        self.assertEqual(calls,['search_modsecurity_alerts']);self.assertEqual(result['evidence_schema_repairs'],1)
        first=result['evidence_report_audit'][0]
        self.assertEqual(first['raw_response'],'{"invalid_json"');self.assertIsNone(first['response'])
        self.assertEqual(first['parsing_error_type'],'ValueError')
        self.assertEqual(first['raw_response_sha256'],hashlib.sha256(first['raw_response'].encode()).hexdigest())
        self.assertTrue(first['rejected_before_dispatch']);self.assertFalse(result.get('remaining_issues'))

    def test_rejected_model_report_keeps_real_two_sensor_sample_comparison(self):
        result,_,calls=self.execute([inquiry(MOD,{'target':'fixture'})],
            question='WAF·Wazuh 경보 조사해줘. 출발지 겹쳤어?',
            selector_plans=[{'calls':[{'tool':t,'arguments':{'target':'fixture'}} for t in (MOD,EXTRA)]}])
        self.assertEqual(calls,['search_modsecurity_alerts','search_wazuh_alerts'])
        self.assertEqual(result['status'],'partial');self.assertEqual(result['protected_calls'],0)
        self.assertEqual(result['stop_reason'],'repeated_evidence_inquiry_rejection')
        self.assertIn('**출발지 표본 비교**',result['final_response'])
        self.assertIn('유효 출발지 IP는 0개',result['final_response'])

    def test_activation_claim_is_repaired_inside_same_phase_without_rereading(self):
        bad=report();bad['report']['limitations']=['임시 IP 차단은 현재 비활성 상태입니다.']
        result,prompts,calls=self.execute([bad,report()])
        self.assertEqual(calls,['search_modsecurity_alerts']);self.assertEqual(prompts,[])
        self.assertEqual(result['evidence_claim_repairs'],1)
        self.assertIn('block_inventory_does_not_verify_activation',result['evidence_report_audit'][0]['issues'])
        self.assertNotIn('비활성',result['final_response']);self.assertEqual(result['protected_calls'],0)

    def test_unattempted_registered_read_gap_is_returned_to_model_then_actually_read(self):
        bad=report();bad['report']['next_steps']=[{'kind':'capability_gap','needed_evidence':EXTRA+' 원문 경보'}]
        result,prompts,calls=self.execute([bad,inquiry(),report((0,1))])
        self.assertEqual(calls,['search_modsecurity_alerts','search_wazuh_alerts']);self.assertEqual(prompts,[])
        self.assertEqual(result['evidence_schema_repairs'],1);self.assertEqual(result['evidence_inquiry_count'],1)
        self.assertTrue(result['evidence_report_audit'][0]['rejected_before_dispatch'])
        self.assertEqual(result['protected_calls'],0);self.assertFalse(result.get('remaining_issues'))

    def test_persistent_claim_failure_stays_incomplete_without_a_fake_report(self):
        bad=report();bad['report']['limitations']=['임시 차단 기능은 활성화되었습니다.']
        result,_,calls=self.execute([bad])
        self.assertEqual(calls,['search_modsecurity_alerts']);self.assertEqual(result['status'],'partial')
        self.assertEqual(result['stop_reason'],'evidence_report_claim_repair_budget_exhausted')
        self.assertNotIn('활성화되었습니다',result['final_response']);self.assertEqual(result['protected_calls'],0)

if __name__=='__main__':unittest.main()
