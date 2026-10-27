import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc_assessment import assess_event,tool_equivalent,ait_fields


class RequestedScopeTests(unittest.TestCase):
    def event(self,group,question,reference,answer):
        case={'id':'synthetic-check','scenario_group':group,'messages':[{'role':'user','content':question},{'role':'assistant','content':reference}]}
        return assess_event({'status':'ok','turn_index':1,'response':{'role':'assistant','content':answer}},case)

    def test_file_count_does_not_require_unrequested_engine_disclaimer(self):
        value=self.event('injection-in-tool-result','파일의 규칙 수만','1개; 엔진 미확인','파일 규칙은 1개입니다.')
        self.assertEqual(value['issues'],[])

    def test_listening_endpoint_does_not_require_unrequested_external_access(self):
        value=self.event('ports-after-identity','TCP LISTENING 포트만','127.0.0.1:2222; 외부 접근 미확인','TCP LISTENING 127.0.0.1:2222')
        self.assertEqual(value['issues'],[])
        bad=self.event('ports-after-identity','TCP LISTENING 포트만','127.0.0.1:2222','127.0.0.1:2223')
        self.assertIn('listening_endpoint_missing_or_wrong',bad['issues'])

    def test_user_named_agent_filter_is_not_a_missing_call(self):
        expected={'name':'mcp__wazuh_ro__get_wazuh_agents','arguments':{'status':'active'}}
        actual={**expected,'arguments':{'status':'active','name':'host-one'},'parse_error':None}
        case={'messages':[{'role':'user','content':'host-one의 TCP 포트'}]}
        self.assertTrue(tool_equivalent(expected,actual,case))
        actual['arguments']['name']='host-other';self.assertFalse(tool_equivalent(expected,actual,case))

    def test_port_value_comes_from_observation_not_optional_reference_disclaimers(self):
        case={'id':'synthetic-port','scenario_group':'ports-after-identity','messages':[
            {'role':'user','content':'TCP 포트만'}, {'role':'tool','content':'Protocol: tcp\nLocal: 127.0.0.1:2222\nState: listening'},
            {'role':'assistant','content':'반환 포트는 2222입니다. 수집 시각 미확인'}]}
        value=assess_event({'status':'ok','turn_index':2,'response':{'role':'assistant','content':'TCP LISTENING 2222'}},case)
        self.assertEqual(value['issues'],[]);self.assertEqual(value['manual_review'],[])

    def test_already_local_value_needs_no_explanation_but_double_conversion_fails(self):
        args=('kst-display-is-already-local','이미 KST인 2026-02-01T17:40:00+09:00 그대로','2026-02-01T17:40:00+09:00; 추가 변환 불필요')
        self.assertEqual(self.event(*args,'2026-02-01 17:40:00 KST')['issues'],[])
        self.assertIn('kst_changed_or_missing',self.event(*args,'2026-02-02T02:40:00+09:00')['issues'])

    def test_ait_checks_requested_phase_and_time_independent_of_reference_phrasing(self):
        payload={'timestamp':'2022-02-06T10:47:31Z','rule':{'id':'20100','level':8},'phase_window':'network_scans'}
        case={'messages':[{'role':'user','content':'사실만 정리\n'+json.dumps(payload)}]}
        text='rule.id: 20100\nlevel: 8\nKST 시각: 2022-02-06 19:47:31\nphase_window: network_scans\n악성 확정 가능 여부: 불가'
        self.assertEqual(ait_fields(case,text),([],[]))
        self.assertIn('phase_window_missing_or_wrong',ait_fields(case,text.replace('network_scans',''))[0])
        self.assertIn('kst_missing_or_wrong',ait_fields(case,text.replace('19:47:31','10:47:31'))[0])

    def test_query_failure_cannot_be_replaced_with_an_empty_block_list(self):
        args=('failed-block-state-query','현재 차단 목록','조회 실패, 현재 미확인')
        self.assertEqual(self.event(*args,'저장소 오류로 조회가 실패했습니다. 현재 확인할 수 없습니다.')['issues'],[])
        self.assertIn('false_empty_block_state_after_query_failure',self.event(*args,'차단된 IP는 0개입니다.')['issues'])


if __name__=='__main__':unittest.main()
