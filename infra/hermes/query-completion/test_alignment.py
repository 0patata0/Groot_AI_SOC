"""Shared chat boundaries: native adapter, partial proposals and trusted evidence."""
import copy
from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

import alignment
from test_completion import Harness, PLUGIN, message, hydrated

H = alignment.load_harness()
C = H.CONTRACT


def proposal(target, pid='1' * 32, **updates):
    data = dict(target=target, proposal_id=pid, before_sha256='a' * 64,
                after_sha256='b' * 64, status='pending', review_posted=True)
    data.update(updates)
    raw = json.dumps(data)
    return dict(server='rule-write-' + target[0], name='propose_rule_edit',
                arguments={'target': target}, result=raw,
                result_sha256=hashlib.sha256(raw.encode()).hexdigest())


class SharedContract(unittest.TestCase):
    def test_new_root_context_matches_thread_only_gateway_without_erasing_history(self):
        root = hydrated(scope='same_channel_top_level')
        rows = [{'role': 'user', 'content': root}]
        projected, changed = alignment.project_new_thread(rows, root, PLUGIN.current_request_text(root), PLUGIN._CONTEXT_PREFIX)
        self.assertTrue(changed)
        self.assertNotIn('GROOT_MATTERMOST_CONTEXT', projected[0]['content'])
        self.assertEqual(rows[0]['content'], root)
        thread = hydrated(scope='same_thread')
        rows = [{'role': 'user', 'content': thread}]
        projected, changed = alignment.project_new_thread(rows, thread, PLUGIN.current_request_text(thread), PLUGIN._CONTEXT_PREFIX)
        self.assertFalse(changed); self.assertEqual(projected, rows)

    def test_payload_overrides_cannot_restore_reasoning_or_duplicate_policy(self):
        rows = [{'role': 'system', 'content': 'native persona\n<!-- rule-change-policy:start -->old<!-- rule-change-policy:end -->'},
                {'role': 'user', 'content': 'unchanged history'}]
        original = copy.deepcopy(rows)
        wire = C.normalize_openai({'messages': rows, 'temperature': 0.7, 'max_completion_tokens': 9999,
            'extra_body': {'reasoning_effort': 'medium', 'think': True, 'temperature': 1}})
        self.assertEqual(rows, original)
        self.assertEqual(wire['reasoning_effort'], 'none')
        self.assertEqual((wire['temperature'], wire['top_p'], wire['max_tokens']), (0, 0.95, 2048))
        self.assertEqual(wire['extra_body'], {})
        self.assertNotIn('max_completion_tokens', wire)
        again = C.normalize_openai(wire)
        self.assertEqual(wire, again)
        self.assertIn('native persona', wire['messages'][0]['content'])
        self.assertIn(C.system_prompt(), wire['messages'][0]['content'])
        self.assertEqual(wire['messages'][1], original[1])

    def test_host_scope_keeps_only_actual_host_and_no_new_tool(self):
        tools = [{'type': 'function', 'function': {'name': name, 'parameters': {'type': 'object',
            'properties': {'target': {'type': 'string', 'enum': ['a:suricata', 'b:wazuh-manager']}}}}}
            for name in ('mcp__rule_a__get_service_action_target', 'mcp__rule_write_a__propose_service_action')]
        out = C.normalize_openai({'tools': tools}, {'mcp__rule_a__get_service_action_target'})
        self.assertEqual(len(out['tools']), 1)
        self.assertEqual(out['tools'][0]['function']['parameters']['properties']['target']['enum'], ['a:suricata'])
        self.assertEqual(len(tools), 2)

    def test_native_request_only_changes_matched_chat_turn(self):
        @dataclass
        class Request:
            api_kwargs: object
            api_messages: object = None
            _original_api_kwargs: object = None
        agent = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom',
                                max_iterations=100, _current_turn_id='t')
        original = Request({'messages': [{'role': 'user', 'content': 'hello'}]})
        wrap = alignment.request_wrapper(lambda *a, **k: original, PLUGIN, H)
        out = wrap(agent, original_user_message='hello', turn_id='t')
        self.assertEqual(agent.max_iterations, 12)
        self.assertEqual(out.api_kwargs['reasoning_effort'], 'none')
        self.assertIsNot(out, original)
        agent.platform = 'cli'; agent.max_iterations = 100
        self.assertIs(wrap(agent, original_user_message='hello', turn_id='t'), original)
        self.assertEqual(agent.max_iterations, 100)
        agent.platform = 'mattermost'
        self.assertIs(wrap(agent, original_user_message='hello', turn_id='other'), original)

    def test_all_proposals_survive_later_failure_and_missing_device(self):
        q = 'WAF IDS Wazuh 룰 주석 변경안을 작성해줘. 다른 룰은 수정하지 마.'
        calls = [proposal('a:modsecurity-custom'), proposal('a:suricata-local', '2' * 32),
                 proposal('a:modsecurity-custom', error='invalid anchor')]
        out = H.write_progress(q, calls)
        self.assertFalse(out['complete'])
        self.assertIn('1' * 32, out['text']); self.assertIn('2' * 32, out['text'])
        self.assertIn('b:wazuh-local-rules', out['missing'])
        self.assertIn('invalid anchor', out['text'])
        self.assertNotIn('실패/미적용', out['text'])

    def test_unknown_outcome_and_bad_receipt_never_claim_success(self):
        for call in [proposal('a:modsecurity-custom', review_posted=False),
                     {**proposal('a:modsecurity-custom'), 'result_sha256': '0' * 64},
                     {'server': 'rule-write-a', 'name': 'propose_rule_edit',
                      'arguments': {'target': 'a:modsecurity-custom'}, 'error_type': 'TimeoutError'}]:
            out = H.write_progress('WAF 룰 변경안을 작성해줘', [call])
            self.assertFalse(out['complete'])
            self.assertNotIn('제출 당시 승인 대기', out['text'])
        self.assertIsNone(H.write_progress('WAF 룰 수정하지 말고 조회만 해줘', []))
        self.assertTrue(H.write_progress('WAF 룰 변경안을 작성해줘', [proposal('a:modsecurity-custom')])['complete'])

    def test_negated_prefix_does_not_hide_later_compound_write_goals(self):
        q = '기존 룰은 수정하지 말고 WAF IDS Wazuh 주석 변경안을 작성해줘'
        out = H.write_progress(q, [proposal('a:modsecurity-custom')])
        self.assertEqual(set(out['missing']), {'a:suricata-local', 'b:wazuh-local-rules'})

    def test_negated_or_quoted_proposal_is_not_a_write_goal(self):
        for q in ('WAF 변경안 작성하지 말고 룰 조회해줘', 'WAF 룰 변경안 만들지 말고 조회해줘',
                  '"WAF 룰 변경안을 작성해줘"라는 문장의 뜻을 설명해줘'):
            self.assertIsNone(H.write_progress(q, []))

    def test_duplicate_ids_even_after_result_and_unlinked_data_are_rejected(self):
        rows = H.linked_rows([proposal('a:modsecurity-custom')])
        self.assertEqual(len(alignment.calls_from_rows(rows, PLUGIN._inventory_payload)), 1)
        self.assertEqual(alignment.calls_from_rows(rows + [rows[0]], PLUGIN._inventory_payload), [])
        self.assertEqual(alignment.calls_from_rows(rows + [rows[1]], PLUGIN._inventory_payload), [])
        self.assertEqual(alignment.calls_from_rows(rows[1:], PLUGIN._inventory_payload), [])
        self.assertEqual(alignment.calls_from_rows(list(reversed(rows)), PLUGIN._inventory_payload), [])

    def test_native_final_preserves_partial_devices_in_persisted_answer(self):
        q = 'WAF IDS Wazuh 룰 주석 변경안을 작성해줘'
        h = Harness(text='모두 완료했습니다', request=q)
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        h.kw['messages'] += H.linked_rows([proposal('a:modsecurity-custom')])
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        out = h.call()
        self.assertNotIn('모두 완료', out.final_response)
        self.assertIn('1' * 32, out.final_response)
        self.assertIn('a:suricata-local', out.final_response)
        self.assertEqual(h.flushes[-1]['content'], out.final_response)
        self.assertTrue(h.agent._capstone_alignment_partial)

    def test_native_read_repair_is_bounded_and_never_creates_fake_evidence(self):
        h = Harness(text='조회 완료')
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        first = h.call()
        self.assertEqual(first.action, 'continue')
        second = h.call(codex_ack_continuations=first.codex_ack_continuations)
        self.assertEqual(second.action, 'continue')
        final = h.call(codex_ack_continuations=second.codex_ack_continuations)
        self.assertEqual(final.action, 'break')
        self.assertNotIn('조회 완료', final.final_response)
        self.assertIn('미확인', final.final_response)
        self.assertTrue(h.agent._capstone_alignment_partial)


if __name__ == '__main__': unittest.main()
