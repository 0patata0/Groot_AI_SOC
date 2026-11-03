"""Intent, receipts and sequential pagination; never model answer fixtures."""
import asyncio
import importlib.util
import unittest

import harness as h
from test_block_lists import receipt
from test_firewall_harness import call


FW = 'mcp__resp__get_firewall_rules'
JSONSCHEMA_AVAILABLE = importlib.util.find_spec('jsonschema') is not None


def schemas():
    return {FW: {'type': 'object', 'properties': {
        'snapshot': {'type': 'string'}, 'offset': {'type': 'integer'},
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 200}},
        'additionalProperties': False}}


class ShortReadRegressions(unittest.TestCase):
    def test_colloquial_inventory_endings_keep_one_device_or_ask_once(self):
        for ending in ('좀 볼래?', '볼 수 있나?', '볼까요?', '봐줘', '봐줄래요?'):
            with self.subTest(ending=ending):
                self.assertIn('어느 장비', h.scope_notice('규칙 ' + ending))
                self.assertEqual(h.tool_scope('방화벽 규칙 ' + ending), {FW})
                self.assertEqual(h.tool_scope('와프 규칙 ' + ending), {'mcp__rule_a__get_security_rules'})
                self.assertEqual(h.security_inventory_request('와주 규칙 ' + ending)['origin'], 'all')
                resolved = h.resolve_short_read('규칙 ' + ending, ['IDS 룰 보여줘'])
                self.assertEqual(h.rule_scope_request(resolved)['devices'], ['Suricata'])

    def test_ambiguous_question_exits_before_sdk_model_or_tool(self):
        import runtime
        report = asyncio.run(runtime.run({'model': 'qwen3.6:35b'}, {'question': '규칙 좀 볼 수 있나요?'}))
        self.assertEqual(report['scope_resolution'], 'clarification_required')
        self.assertEqual(report['calls'], [])
        self.assertEqual(report['model_calls'], [])

    def test_view_endings_do_not_override_changes_concepts_or_history(self):
        for question in ('WAF 규칙 삭제해줄 수 있나?', 'FW 룰 수정하고 볼래?',
                         '규칙이란 개념 설명해볼래?', '"WAF 룰 볼래"라는 문장 번역',
                         '어제 WAF 규칙 볼 수 있나?', '내일 WAF 룰 볼래?',
                         '룰 볼래? 조회하지 마', '도구 없이 FW 룰 볼래?'):
            self.assertIsNone(h.rule_scope_request(question), question)

    def test_plural_and_reversed_block_questions_are_one_current_read(self):
        for question in ('막혀 있는 주소들은?', '현재 차단된 IPv4 주소들 보여줄래?',
                         '차단된 아이피들은 뭐야?', '어떤 IP가 차단됐어?', '어느 주소가 막혔나요?'):
            self.assertEqual(h.tool_scope(question), {h.READ.BLOCKS}, question)
            self.assertTrue(h.missing_reads(question, []))
            self.assertEqual(h.missing_reads(question, [receipt()]), [])
        for question in ('막힌 주소들 해제해줘', '지난주 막힌 주소들은?',
                         '막힌 IP들과 WAF 룰 보여줘', '막힌 IP들은 왜 차단됐어?',
                         '차단된 주소들이란 무슨 뜻이야?'):
            self.assertIsNone(h.READ.block_list_plan(h.normalized(question)), question)

    def test_unclassified_zero_and_rule_counts_still_need_receipts(self):
        for answer in ('현재 차단된 IPv4 주소는 없습니다.', '막힌 아이피는 0개입니다.',
                       '현재 차단 중인 IP들은 없습니다.'):
            self.assertIn('unobserved_block_list_claim', h.action_claim_violations('지금 상태 어때?', answer, []))
            self.assertEqual(h.action_claim_violations('지금 상태 어때?', answer, [receipt()]), [])
            damaged = {**receipt(), 'result_sha256': '0' * 64}
            self.assertIn('unobserved_block_list_claim', h.action_claim_violations('지금 상태 어때?', answer, [receipt(), damaged]))
        for answer in ('현재 WAF 규칙 45개가 설치되어 있습니다.', 'IDS 룰을 조회했습니다.'):
            self.assertIn('unobserved_rule_inventory_claim', h.action_claim_violations('룰 뭐 있어?', answer, []))
        question = '방화벽 규칙 봐줄래?'
        self.assertEqual(h.action_claim_violations(question, h.firewall_report(question, [call()]), [call()]), [])
        for answer in ('현재 차단된 IPv4 주소는 미확인입니다.', '차단 목록이 없다면 추가 차단은 하지 않습니다.'):
            self.assertEqual(h.action_claim_violations('지금 상태 어때?', answer, []), [])
        self.assertEqual(h.action_claim_violations('규칙 개념 설명해줘', '예시: WAF 룰 3개를 정의합니다.', []), [])

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, 'Requires existing server SDK jsonschema; do not install on Mac')
    def test_first_fw_page_cannot_invent_snapshot_or_future_offset(self):
        from jsonschema import ValidationError
        refined = h.refine_read_schemas('FW 규칙 봐줘', schemas(), [])
        schema = h.selection_schema(refined, 32)
        self.assertEqual(schema['properties']['calls']['maxItems'], 1)
        for args in ({'snapshot': '0' * 32}, {'offset': 200}):
            with self.assertRaises(ValidationError):
                h.validated_selection({'calls': [{'tool': FW, 'arguments': args}]}, schema)
        choice = {'tool': FW, 'arguments': {'offset': 0, 'limit': 200}}
        selected, removed = h.validated_selection({'calls': [choice, choice]}, schema)
        self.assertEqual(selected['calls'], [choice]); self.assertEqual(removed, 1)
        self.assertEqual(h.refine_read_schemas('FW 규칙 봐줘', schemas(), [call()]), {})

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, 'Requires existing server SDK jsonschema; do not install on Mac')
    def test_followup_is_bound_to_actual_next_offset_and_snapshot(self):
        from jsonschema import ValidationError
        first = call(objects=[{'chain': {}}], complete=False, next_offset=1)
        refined = h.refine_read_schemas('FW 규칙 봐줘', schemas(), [first])
        schema = h.selection_schema(refined, 32)
        for args in ({'snapshot': 'c' * 32, 'offset': 1}, {'snapshot': 'b' * 32, 'offset': 200}):
            with self.assertRaises(ValidationError):
                h.validated_selection({'calls': [{'tool': FW, 'arguments': args}]}, schema)
        valid = {'tool': FW, 'arguments': {'snapshot': 'b' * 32, 'offset': 1}}
        self.assertEqual(h.validated_selection({'calls': [valid]}, schema)[0]['calls'], [valid])

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, 'Requires existing server SDK jsonschema; do not install on Mac')
    def test_mixed_tool_selection_cannot_preselect_two_fw_pages(self):
        from jsonschema import ValidationError
        source = schemas(); source[h.READ.BLOCKS] = {'type': 'object', 'properties': {}, 'additionalProperties': False}
        schema = h.selection_schema(source, 8)
        choice = lambda limit: {'tool': FW, 'arguments': {'offset': 0, 'limit': limit}}
        with self.assertRaisesRegex(ValidationError, 'sequential_observations'):
            h.validated_selection({'calls': [choice(50), choice(100)]}, schema)


if __name__ == '__main__':
    unittest.main()
