"""Short requests must retain device/scope, evidence and write boundaries."""
import copy
import asyncio
import hashlib
import json
from dataclasses import dataclass
from types import SimpleNamespace
import unittest

import alignment
from test_completion import Harness, PLUGIN
from test_inventory_render import payload

H = alignment.load_harness()


class ShortQueries(unittest.TestCase):
    def test_review_mentions_do_not_turn_a_short_read_into_a_complex_review(self):
        import importlib.util
        from pathlib import Path
        path = Path(__file__).resolve().parents[1] / 'review_channel_policy.py'
        spec = importlib.util.spec_from_file_location('_short_review_policy', path)
        policy = importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
        self.assertEqual(policy.route('@hermes @ollama FW 룰', H), policy.route('FW 룰', H))
        self.assertFalse(policy.route('@hermes @ollama FW 룰', H)['cross_review'])
        self.assertTrue(policy.route('@hermes @ollama FW 룰 서로 검증해줘', H)['cross_review'])

    def test_native_sender_label_does_not_change_scope_or_write_boundary(self):
        for question in ('FW 룰', 'WAF 룰', 'IPS 룰', '와주 룰', '룰 보여줘',
                         'WAF 기본 룰', 'FW와 WAF 룰 보여줘', 'FW 룰 수정해줘'):
            labeled = '[socadmin] ' + question
            self.assertEqual(H.scope_notice(labeled), H.scope_notice(question), question)
            self.assertEqual(H.tool_scope(labeled), H.tool_scope(question), question)
        self.assertIsNone(H.scope_notice('[operator-2] FW 룰 삭제해줘'))
        self.assertIsNone(H.scope_notice('[operator-2] FW 룰 조회하지 마'))

    def test_ollama_notice_needs_no_sdk_model_or_network(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'ollama-trial'))
        import runtime
        for question in ('FW 룰', '룰 보여줘', 'WAF 기본 룰'):
            result = asyncio.run(runtime.run({'model':'qwen3.6:35b'}, {'question':question}))
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['calls'], [])
            self.assertEqual(result['model_calls'], [])
            self.assertEqual(result['protected_calls'], 0)
            self.assertEqual(result['final_response'], H.scope_notice(question))

    def test_full_rule_request_discloses_partial_coverage_before_observed_data(self):
        data = payload()
        raw = json.dumps(data)
        call = {'server':'rule-a', 'name':'get_rule_change_target', 'arguments':{'target':'a:modsecurity-custom'},
                'result':raw, 'result_sha256':hashlib.sha256(raw.encode()).hexdigest()}
        full = H.inventory('WAF 룰', [call])
        custom = H.inventory('WAF 커스텀 룰', [call])
        self.assertTrue(full.startswith('**조회 범위: 커스텀 파일만 확인**'))
        self.assertIn('전체 룰 확인은 미완료', full)
        self.assertNotIn('전체 룰 확인은 미완료', custom)
        self.assertIn(str(data['rule_inventory']['declared_count']), full)
        self.assertTrue(H.missing_reads('FW 룰', [call]))

    def test_firewall_variants_cannot_become_custom_rule_queries(self):
        for question in ('FW 룰', 'fw룰 보여줘', '방화벽 규칙 조회', 'nftables rules 목록',
                         'F/W 룰 출력', '지금 fw 률 츌력해볼래', '방화벽 보여줘'):
            with self.subTest(question=question):
                self.assertEqual(H.rule_scope_request(question)['devices'], ['FW'])
                self.assertEqual(H.tool_scope(question), set())
                self.assertIsNone(H.inventory_question(question))
                self.assertIn('미완료', H.scope_notice(question))
                self.assertTrue(H.missing_reads(question, []))

    def test_known_short_and_long_device_queries_have_identical_scope(self):
        for short, long in (('WAF 룰', '현재 WAF 규칙 목록 보여줘'),
                            ('IPS 룰', '현재 Suricata 규칙 목록 보여줘'),
                            ('와프 규칙', '현재 WAF 규칙 목록 보여줘'),
                            ('와주 룰', '현재 Wazuh 규칙 목록 보여줘'),
                            ('웹 방화벽 룰', '현재 WAF 규칙 목록 보여줘')):
            with self.subTest(short=short):
                self.assertEqual(H.tool_scope(short), H.tool_scope(long))
                self.assertEqual(H.missing_reads(short, []), H.missing_reads(long, []))
                self.assertIsNone(H.scope_notice(short))

    def test_subjectless_short_query_requests_only_one_clarification(self):
        for question in ('룰 보여줘', '규칙 출력', '기본 룰', '룰?'):
            with self.subTest(question=question):
                self.assertIn('어느 장비', H.scope_notice(question))
                self.assertEqual(H.tool_scope(question), set())
                self.assertIsNone(H.inventory_question(question))

    def test_unknown_device_does_not_silently_query_three_other_devices(self):
        self.assertIn('어느 장비', H.scope_notice('UTM 룰 보여줘'))

    def test_basic_only_never_uses_custom_rule_as_substitute(self):
        for question in ('WAF 기본 룰', 'IDS 내장 규칙 보여줘', 'Wazuh 기본 규칙 조회'):
            self.assertIn('기본·내장', H.scope_notice(question))
            self.assertEqual(H.tool_scope(question), set())
            self.assertIsNone(H.inventory_question(question))
            self.assertTrue(H.missing_reads(question, []))

    def test_mixed_fw_and_waf_keeps_both_requested_scopes(self):
        question = 'FW와 WAF 룰 보여줘'
        self.assertIsNone(H.scope_notice(question))
        self.assertEqual(H.tool_scope(question), {'mcp__rule_a__get_rule_change_target'})
        missing = H.missing_reads(question, [])
        self.assertEqual(len(missing), 2)
        self.assertIn('FW', missing[0])
        self.assertEqual(missing[1], 'a:modsecurity-custom')
        self.assertNotIn('Suricata', H.inventory_question(question))

    def test_negated_device_is_not_retained_as_positive_scope(self):
        for question in ('FW 말고 WAF 룰 보여줘', 'FW는 제외하고 WAF 룰 출력'):
            self.assertIsNone(H.scope_notice(question))
            self.assertEqual(H.rule_scope_request(question)['devices'], ['WAF'])
        question = 'WAF 말고 IDS 룰 보여줘'
        self.assertEqual(H.missing_reads(question, []), ['a:suricata-local'])
        self.assertNotIn('WAF', H.inventory_question(question))

    def test_actions_and_explanations_are_not_replaced_with_read_notices(self):
        for question in ('FW 룰 삭제', 'FW 룰 삭제해줘', 'FW 룰 조회하고 수정해줘',
                         'FW 룰 변경안 준비해줘', 'FW 룰이 무엇인지 설명해줘',
                         '"FW 룰 보여줘"라는 문장 번역', 'FW 룰 조회하지 마',
                         'WAF 기본 룰의 차이를 분석해줘'):
            self.assertIsNone(H.scope_notice(question), question)

    def test_hermes_short_notice_skips_provider_and_never_creates_tool_calls(self):
        @dataclass
        class Request:
            api_kwargs: dict
            api_messages: list
            _original_api_kwargs: object = None
        for question in ('FW 룰', '룰 보여줘', 'WAF 기본 룰'):
            agent = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom',
                                    _current_turn_id='t', max_iterations=12)
            rows = [{'role': 'user', 'content': question}]
            original = Request({'messages': copy.deepcopy(rows)}, copy.deepcopy(rows))
            result = alignment.request_wrapper(lambda *a, **kw: original, PLUGIN, H)(
                agent, original_user_message=question, turn_id='t', messages=rows)
            self.assertIs(result, original)
            self.assertEqual(agent._capstone_query_completion_local_format, ('t', H.scope_notice(question)))
            self.assertIsNone(agent._capstone_read_selection)
            self.assertEqual(rows, [{'role': 'user', 'content': question}])

    def test_hermes_final_corrects_unobserved_scope_claim(self):
        h = Harness(request='FW 룰', text='WAF 규칙을 모두 확인했습니다.')
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        h.call()
        self.assertEqual(h.original_calls[-1].content, H.scope_notice('FW 룰'))


if __name__ == '__main__':
    unittest.main()
