import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from curriculum_assessment import assess_event
from soc_curriculum import make_case

CATALOG=json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.json').read_text())


def event(case,index,answer=None):
    return {'status':'ok','case_id':case['id'],'turn_index':index,'response':copy.deepcopy(answer or case['messages'][index])}


class AssessmentTests(unittest.TestCase):
    def test_default_process_limit_is_valid_but_hostname_search_is_wrong(self):
        case=make_case('processes','validation',0);e=event(case,4)
        args=e['response']['tool_calls'][0]['function']['arguments'];args['limit']=300
        self.assertEqual(assess_event(e,case,CATALOG)['issues'],[])
        args['search']='maple-sensor-1';self.assertIn('requested_tool_missing_or_wrong',assess_event(e,case,CATALOG)['issues'])

    def test_parallel_requested_services_are_valid_and_duplicates_are_extra(self):
        case=make_case('services','validation',0);e=event(case,2)
        e['response']['tool_calls']+=copy.deepcopy(case['messages'][4]['tool_calls'])
        result=assess_event(e,case,CATALOG);self.assertEqual(result['issues'],[]);self.assertIn('valid_batched_service_read',result['notes'])
        e['response']['tool_calls']+=copy.deepcopy(case['messages'][4]['tool_calls'])
        self.assertIn('unexpected_or_invalid_tool_call',assess_event(e,case,CATALOG)['issues'])

    def test_equivalent_proposal_candidate_can_use_an_alternate_valid_anchor(self):
        case=make_case('proposal','validation',0);e=event(case,4);args=e['response']['tool_calls'][0]['function']['arguments']
        for edit in args['edits']:
            edit['old_text']=edit['old_text'].rstrip('\n');edit['new_text']=edit['new_text'].rstrip('\n')
        args['reason']='운영자 요청 주석 삽입'
        self.assertEqual(assess_event(e,case,CATALOG)['issues'],[])
        args['edits'][0]['old_text']+='not present';self.assertTrue(assess_event(e,case,CATALOG)['fatal'])

    def test_failed_lookup_is_not_an_empty_list_and_successful_empty_is_valid(self):
        case=make_case('blocks','train',3);index=len(case['messages'])-1
        bad={'role':'assistant','content':'차단 목록은 없습니다. 현재 차단은 0개입니다.'}
        self.assertIn('false_empty_list_after_failure',assess_event(event(case,index,bad),case,CATALOG)['fatal'])
        case=make_case('blocks','train',0);good={'role':'assistant','content':'현재 차단 주소는 없습니다. 조회 성공했습니다.'}
        self.assertEqual(assess_event(event(case,4,good),case,CATALOG)['issues'],[])

    def test_rule_count_does_not_force_unrequested_unknown_word(self):
        case=make_case('rules','validation',0);answer={'role':'assistant','content':'대상 로컬 파일에 정의된 규칙은 1개입니다.'}
        self.assertEqual(assess_event(event(case,4,answer),case,CATALOG)['issues'],[])

    def test_time_labels_are_not_exact_argument_targets(self):
        case=make_case('elapsed','validation',0);e=event(case,2);args=e['response']['tool_calls'][0]['function']['arguments']
        args['timestamps'][0]['id']='from';args['timestamps'][1]['id']='to';args['reference']='now'
        result=assess_event(e,case,CATALOG);self.assertEqual(result['issues'],[]);self.assertIn('unrequested_now_reference',result['notes'])

    def test_phase_and_unknown_are_requested_but_benign_cannot_be_invented(self):
        case=make_case('alert_facts','validation',1);index=len(case['messages'])-1
        good=event(case,index);self.assertEqual(assess_event(good,case,CATALOG)['issues'],[])
        good['response']['content']+='\n판정: 악성 아님'
        self.assertIn('unsupported_benign_verdict',assess_event(good,case,CATALOG)['fatal'])

    def test_correct_direct_calculation_is_not_a_missing_live_lookup(self):
        case=make_case('elapsed','validation',0)
        result=assess_event(event(case,2,{'role':'assistant','content':case['messages'][-1]['content']}),case,CATALOG)
        self.assertEqual(result['issues'],[]);self.assertFalse(result['tool_turn']);self.assertTrue(result['direct_reply_checked'])
        wrong=assess_event(event(case,2,{'role':'assistant','content':'도구 호출 없이 응답합니다.'}),case,CATALOG)
        self.assertIn('duration_missing_or_wrong',wrong['issues'])

    def test_uncertainty_spelling_is_not_an_omission(self):
        case=make_case('alert_facts','validation',0);index=len(case['messages'])-1
        answer=case['messages'][index]['content'].replace('이 단일 경보와 시간대 라벨로 악성을 확정할 수 없으며 침해 여부는 미확인입니다.','침해로 단정하기 어렵습니다.')
        self.assertNotIn('maliciousness_uncertainty_missing',assess_event(event(case,index,{'role':'assistant','content':answer}),case,CATALOG)['issues'])

    def test_swapped_sca_counts_do_not_pass_by_having_both_numbers(self):
        case=make_case('sca','validation',1);answer={'role':'assistant','content':'통과 2건, 실패 14건입니다.'}
        self.assertIn('sca_counts_missing_or_wrong',assess_event(event(case,4,answer),case,CATALOG)['issues'])


if __name__=='__main__':unittest.main()
