"""Regression for 58k-token stale lookup replay, without a model or network."""
import copy
import unittest

from test_completion import PLUGIN as P, hydrated

READ = 'mcp__rule_a__get_service_action_target'
WRITE = 'mcp__rule_write_a__propose_service_action'
QUESTION = 'IDS는 왜 활성화 안 됐지? 실제 조회 근거로 확인해줘'


def exchange(name=READ, call_id='old-read'):
    return [
        {'role': 'assistant', 'content': '앞선 조사 설명', 'tool_calls': [
            {'id': call_id, 'type': 'function', 'function': {
                'name': name, 'arguments': '{"target":"a:suricata"}'}}]},
        {'role': 'tool', 'tool_call_id': call_id, 'content': 'old evidence ' * 9000},
    ]


class ReadHistoryTests(unittest.TestCase):
    def test_brief_status_guidance_does_not_take_over_analysis_or_choose_tools(self):
        hint = P.status_lookup_guidance(QUESTION)
        self.assertIn('현재 활성 여부', hint)
        self.assertIn('변경안 준비', hint)
        self.assertNotIn('mcp__', hint)
        for request in ('현재 IDS 공격 원인 분석해줘', '현재 적용된 룰 보여줘',
                        'IDS 활성 여부를 상세히 분석해줘', 'IDS 룰 원문 보여줘'):
            self.assertEqual(P.status_lookup_guidance(request), '')

    def rows(self, question=QUESTION):
        user = hydrated(question)
        rows = [{'role': 'system', 'content': 'approval and safety policy'},
                {'role': 'user', 'content': '앞으로도 변경은 정확 승인 후 수행해'},
                *exchange(), {'role': 'assistant', 'content': '이전 요약'},
                {'role': 'user', 'content': user}, *exchange(call_id='current-read')]
        return rows, user

    def test_big_old_read_elided_but_policy_current_evidence_and_history_preserved(self):
        rows, user = self.rows(); before = copy.deepcopy(rows)
        out = P.compact_read_history(rows, user)
        self.assertEqual(out[3]['content'], P._OLD_READ_NOTICE)
        for i in (0, 1, 2, 4, 5, 6, 7):
            self.assertEqual(out[i], rows[i])
        self.assertEqual(rows, before)
        self.assertLess(sum(len(str(r)) for r in out), sum(len(str(r)) for r in rows) * .6)

    def test_protected_and_unknown_payloads_are_never_elided(self):
        for name in (WRITE, 'unknown_reader', 'mcp__resp__block_ip'):
            rows, user = self.rows(); rows[2:4] = exchange(name)
            self.assertEqual(P.compact_read_history(rows, user), rows)

    def test_unlinked_duplicate_or_mismatched_result_is_preserved(self):
        for kind in ('unlinked', 'duplicate_call', 'duplicate_result', 'wrong_name',
                     'wrong_tool_name', 'result_before_call', 'malformed_calls'):
            rows, user = self.rows()
            if kind == 'unlinked': rows[3]['tool_call_id'] = 'absent'
            if kind == 'duplicate_call': rows.insert(3, copy.deepcopy(rows[2]))
            if kind == 'duplicate_result': rows.insert(4, copy.deepcopy(rows[3]))
            if kind == 'wrong_name': rows[3]['name'] = WRITE
            if kind == 'wrong_tool_name': rows[3]['tool_name'] = WRITE
            if kind == 'result_before_call': rows[2], rows[3] = rows[3], rows[2]
            if kind == 'malformed_calls': rows[2]['tool_calls'] = 123
            self.assertEqual(P.compact_read_history(rows, user), rows)

    def test_missing_or_ambiguous_current_wire_anchor_is_preserved(self):
        rows, user = self.rows()
        for changed in (rows[:-3], rows + [{'role': 'user', 'content': user}]):
            self.assertEqual(P.compact_read_history(changed, user), changed)

    def test_historical_comparison_followup_and_write_keep_original_payloads(self):
        for question in ('현재 IDS 룰을 이전 결과와 비교해서 보여줘',
                         '장비별로 표로 보여줘', 'IDS는 왜 어제 비활성이었지? 확인해줘',
                         '현재 IDS 룰을 보여주고 수정해줘', '그 결과에 있는 IDS 룰을 확인해줘'):
            rows, user = self.rows(question)
            self.assertEqual(P.compact_read_history(rows, user), rows)

    def test_new_inventory_can_elide_previous_payload_and_keep_current_hash_input(self):
        rows, user = self.rows('현재 적용된 룰 보여줘')
        out = P.compact_read_history(rows, user)
        self.assertEqual(out[3]['content'], P._OLD_READ_NOTICE)
        self.assertEqual(out[-1], rows[-1])


if __name__ == '__main__':
    unittest.main()
