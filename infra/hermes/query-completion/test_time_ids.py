import copy
import json
import unittest
from test_completion import PLUGIN as P, Harness, definition, message
from test_evidence_kst import exchange


class TimeIDS(unittest.TestCase):
    def tools(self, h):
        for name in (P._IDS_SERVICE, 'mcp__rule_b__get_service_action_target', P._TIME_TOOL):
            item = definition(name)
            if name != P._TIME_TOOL:
                item['function']['parameters']['properties']['target'] = {
                    'type':'string','enum':['a:suricata','a:waf','b:wazuh-manager']}
            h.agent.tools.append(item)
        h.agent.valid_tool_names = {x['function']['name'] for x in h.agent.tools}
        h.api_kwargs['tools'] = copy.deepcopy(h.agent.tools)

    def test_explicit_ids_first_request_has_only_suricata_enum_and_restores(self):
        h = Harness(request='현재 IDS 활성 여부 확인해줘'); self.tools(h)
        original = copy.deepcopy(h.agent.tools)
        self.assertTrue(P._arm_read_request(h.agent,'turn-a',target_scope=P.ids_status_scope(h.kw['user_message'])))
        out = h.agent._build_api_kwargs([])
        self.assertEqual([x['function']['name'] for x in out['tools']], [P._IDS_SERVICE])
        self.assertEqual(out['tools'][0]['function']['parameters']['properties']['target']['enum'], ['a:suricata'])
        self.assertEqual(h.agent.valid_tool_names, {P._IDS_SERVICE})
        h.agent._capstone_query_completion_names_restore()
        self.assertEqual(h.agent.tools,original)
        self.assertIn('mcp__rule_write_a__propose_rule_edit',h.agent.valid_tool_names)

    def test_quoted_mixed_other_device_write_and_history_do_not_force_ids(self):
        for text in ('현재 Wazuh 활성 여부 확인해줘','현재 IDS와 Wazuh 활성 여부 비교해줘',
                     '현재 IDS 활성 여부 확인하고 재시작해줘','"IDS 활성" 문구 번역해줘',
                     'IDS 말고 다른 장비 활성 여부 확인해줘','장비별 활성 여부 보여줘'):
            self.assertIsNone(P.ids_status_scope(text), text)

    def test_wrong_service_evidence_never_closes_ids_as_confirmed(self):
        h = Harness(text='IDS는 활성 상태입니다.',request='현재 IDS 활성 여부 확인해줘')
        data={'target':'b:wazuh-manager','observation':{'started_at':'2026-10-24T10:00:00Z','running':True}}
        h.kw['messages'] += exchange(data,'mcp__rule_b__get_service_action_target')
        first=h.call();self.assertEqual(first.action,'continue')
        h.kw['codex_ack_continuations']=first.codex_ack_continuations
        h.kw['assistant_message']=message('IDS는 활성 상태입니다.')
        h.call()
        self.assertIn('IDS(a:suricata)',h.original_calls[-1].content)
        self.assertIn('활성 여부는 미확인',h.original_calls[-1].content)
        self.assertEqual(h.kw['messages'][-1]['content'],h.original_calls[-1].content)

    def test_time_tool_is_readonly_but_not_a_service_observation(self):
        self.assertTrue(P.EVIDENCE.allowed(P._TIME_TOOL,'verify'))
        self.assertTrue(P.EVIDENCE.allowed(P._TIME_TOOL,'manage'))
        h=Harness();self.tools(h)
        self.assertTrue(P._arm_read_request(h.agent,'turn-a',target_scope={P._TIME_TOOL:None}))
        out=h.agent._build_api_kwargs([])
        self.assertEqual([x['function']['name'] for x in out['tools']],[P._TIME_TOOL])
        self.assertTrue(P.time_calculation_request('2026-10-24T15:55:11Z를 KST로 변환해줘'))
        self.assertFalse(P.time_calculation_request('도구 없이 2026-10-24T15:55:11Z를 KST로 변환해줘'))
        self.assertTrue(P.time_calculation_request('합성 자료다. 외부 조회나 실제 변경 없이 2026-10-24T15:55:11Z를 KST로 계산해줘'))

    def test_common_utc_prose_and_table_formats_are_stored_as_kst(self):
        for text in ('시작 UTC: 2026-10-24 15:55:11', '시작 2026-10-24 15:55:11 (UTC)',
                     '| 장비 | 시작 시각 (UTC) |\n| --- | --- |\n| IDS | 2026-10-24 15:55:11 |\n'):
            h=Harness(text=text,request='현재 상태 설명해줘');h.call()
            shown=h.original_calls[-1].content
            self.assertIn('2026-10-25T00:55:11+09:00',shown)
            self.assertNotIn('UTC',shown)
            self.assertEqual(P.EVIDENCE.kst_display(shown),shown)
            self.assertEqual(h.kw['messages'][-1]['content'],shown)

    def test_time_calculation_cannot_be_claimed_without_a_real_call(self):
        h=Harness(text='10분입니다.',request='2026-10-24T15:55:11Z부터 2026-10-25T01:05:11+09:00까지 시간차 계산해줘')
        first=h.call();self.assertEqual(first.action,'continue')
        h.kw['codex_ack_continuations']=first.codex_ack_continuations
        h.kw['assistant_message']=message('10분입니다.')
        h.call()
        self.assertIn('모델의 계산값은 확정하지 않았습니다',h.original_calls[-1].content)

    def test_answer_that_omits_calculated_values_gets_one_correction(self):
        h=Harness(text='제공된 합성 자료와 시간 계산을 기반',request='2026-10-24T15:55:11Z를 KST로 계산해줘')
        data={'kind':'time_calculation','live_observation':False,'timestamps':[
            {'id':'A','kst':'2026-10-25T00:55:11+09:00'}],'differences':[]}
        h.kw['messages']+=exchange(data,P._TIME_TOOL)
        first=h.call();self.assertEqual(first.action,'continue')
        h.kw['codex_ack_continuations']=first.codex_ack_continuations
        h.kw['assistant_message']=message('자료를 기반')
        h.call()
        self.assertIn('2026-10-25T00:55:11+09:00',h.original_calls[-1].content)


class CalculationFields(unittest.TestCase):
    def test_mismatched_order_and_reverse_durations(self):
        fact={'kind':'time_calculation','chronological_order':['start','end'],
              'timestamps':[{'id':'end','kst':'2026-10-25T01:05:11+09:00','minutes_until_reference':10},
                            {'id':'start','kst':'2026-10-25T00:55:11+09:00','minutes_until_reference':20}],
              'differences':[{'from':'end','to':'start','seconds':-600,'minutes':-10}]}
        wrong={'event_order':['end','start'],'start_to_end_minutes':-10,'since_latest_minutes':-10}
        self.assertEqual(len(P.EVIDENCE.calculated_json_violations(json.dumps(wrong),[fact])),3)
        self.assertEqual(len(P.EVIDENCE.calculated_json_violations('설명\n```json\n'+json.dumps(wrong)+'\n```\n끝',[fact])),3)
        right={'event_order':['start','end'],'start_to_end_minutes':10,'end_to_start_seconds':-600,
               'since_latest_minutes':10,'start_kst':'2026-10-25T00:55:11+09:00'}
        fenced='```json\n'+json.dumps(right)+'\n```'
        self.assertEqual(P.EVIDENCE.calculated_json_violations(fenced,[fact]),[])
        self.assertEqual(P.EVIDENCE.calculated_json_violations(json.dumps(wrong),[]),[])
        self.assertEqual(P.EVIDENCE.kst_display(fenced),fenced)

    def test_wrong_calculation_cannot_be_saved_after_retry(self):
        h=Harness(text='{"a_to_b_minutes":-10}',request='2026-10-24T15:55:11Z부터 2026-10-25T01:05:11+09:00까지 시간차 계산해줘')
        fact={'kind':'time_calculation','live_observation':False,'chronological_order':['A','B'],
              'timestamps':[{'id':'A','kst':'2026-10-25T00:55:11+09:00'}, {'id':'B','kst':'2026-10-25T01:05:11+09:00'}],
              'differences':[{'from':'B','to':'A','seconds':-600,'minutes':-10}]}
        h.kw['messages']+=exchange(fact,P._TIME_TOOL)
        first=h.call();self.assertEqual(first.action,'continue')
        h.kw['codex_ack_continuations']=first.codex_ack_continuations
        h.kw['assistant_message']=message('{"a_to_b_minutes":-10}')
        h.call()
        self.assertIn('계산된 시간순',h.original_calls[-1].content)
        self.assertNotIn('"a_to_b_minutes":-10',h.kw['messages'][-1]['content'])


if __name__ == '__main__': unittest.main()
