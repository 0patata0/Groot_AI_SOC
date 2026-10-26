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
    def test_submitted_scope_impact_and_denial_prose_follow_actual_receipts(self):
        from test_inventory_render import payload as inventory_payload
        data = inventory_payload(); data['impact'] = 'configuration test and reload; inode-preserving write'
        raw = json.dumps(data)
        read = dict(server='rule-a', name='get_rule_change_target', arguments={'target': data['target']},
                    result=raw, result_sha256=hashlib.sha256(raw.encode()).hexdigest())
        validation = 'offline guard checks passed; full engine syntax test after approval and before reload'
        submitted = proposal(data['target'], before_sha256=data['sha256'], validation=validation)
        progress = H.write_progress('WAF 주석 변경안 만들어줘', [read, submitted])
        text = ('- **검증 범위**: 엔진 구문 검사(approval 후 reload 전)로 검증됨.\n'
                '- **적용 영향**: 완전히 영향 없음.\n'
                '- **되돌리는 방법**: 승인이 거부되거나 만료되면 원본 파일로 복원 가능.')
        fence = '```text\n' + text + '\n```'
        report = H.write_report(text + '\n' + fence, progress)
        prose = report.split('```')[0]
        self.assertNotIn('검증됨', prose); self.assertNotIn('완전히 영향 없음', prose)
        self.assertIn(validation, prose); self.assertIn(data['impact'], prose)
        self.assertIn('파일을 복원할 필요가 없습니다', prose); self.assertIn(fence, report)
        forged = dict(read, result_sha256='0' * 64)
        progress = H.write_progress('WAF 주석 변경안 만들어줘', [forged, submitted])
        self.assertIn('a:modsecurity-custom: 미확인', H.write_report(text, progress))

    def test_write_counts_and_rollback_base_use_verified_file_metadata(self):
        from test_inventory_render import payload as inventory_payload
        data = inventory_payload()
        raw = json.dumps(data)
        read = dict(server='rule-a', name='get_rule_change_target', arguments={'target': data['target']},
                    result=raw, result_sha256=hashlib.sha256(raw.encode()).hexdigest())
        submitted = proposal(data['target'], before_sha256=data['sha256'])
        progress = H.write_progress('WAF 주석 변경안 만들어줘', [read, submitted])
        text = '나머지 12개 규칙은 불변입니다.\n현재 파일 SHA: ' + 'b'*64 + '\n수정 대상 2개 규칙은 별도 검토합니다.'
        fence = '```text\n나머지 12개 규칙\n```'
        report = H.write_report(text + '\n' + fence, progress)
        self.assertNotIn('나머지 12개 규칙은 불변', report)
        self.assertIn('a:modsecurity-custom: 10개', report)
        self.assertIn('원복 시 실제 파일을 재조회', report)
        self.assertIn('수정 대상 2개 규칙', report)
        self.assertIn(fence, report)
        for rollback_text in ('되돌리는 방법: 기존 SHA 62c855cf...를 기준으로 복원하는 편집안 제출',
                     '원복 방법: 현재 파일 SHA를 기준으로 삭제 제안'):
            self.assertIn('원복 시 실제 파일을 재조회', H.write_report(rollback_text, progress))
            self.assertNotIn('기존 SHA 62c855cf', H.write_report(rollback_text, progress))
        self.assertIn('미적용 후보는 승인 카드에서 거부', report)
        read['result_sha256'] = '0' * 64
        progress = H.write_progress('WAF 주석 변경안 만들어줘', [read, submitted])
        self.assertIsNone(progress['file_metadata'][0]['declared_count'])
        self.assertIn('a:modsecurity-custom: 미확인', H.write_report(text, progress))

    def test_unstarted_edit_gets_one_continuation_but_never_retries_attempted_changes(self):
        q = 'Wazuh 규칙 description 주석 변경안을 만들어줘'
        self.assertEqual(H.preparation_gap(q, []), ['b:wazuh-local-rules'])
        for call in (proposal('b:wazuh-local-rules', error='unknown'),
                     {'server':'rule-write-b','name':'propose_rule_edit','error_type':'TimeoutError'},
                     {'server':'resp','name':'block_ip','result':''}):
            self.assertEqual(H.preparation_gap(q, [call]), [])
        self.assertEqual(H.preparation_gap('WAF 규칙 모드를 바꾸고 IDS 컨테이너 재구성해줘', []), [])
        h = Harness(text='변경안을 준비하겠습니다.', request=q)
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        first = h.call()
        self.assertEqual(first.action, 'continue')
        self.assertIn('b:wazuh-local-rules', h.kw['messages'][-1]['content'])
        second = h.call()
        self.assertNotEqual(second.action, 'continue')
        self.assertIn('미처리/확인 필요', second.final_response)

    def test_expiry_presentation_uses_receipt_and_preserves_raw_and_fenced_data(self):
        call = proposal('a:modsecurity-custom', approval_expires_at=1793037565)
        original = copy.deepcopy(call)
        shown = json.loads(H.model_view(call['server'], call['name'], call['result']))
        self.assertEqual(shown['approval_expires_at_kst'], '2026-10-27T02:59:25+09:00 (KST)')
        self.assertEqual(shown['approval_expires_at'], 1793037565)
        self.assertEqual(call, original)
        progress = H.write_progress('WAF 룰 변경안 작성해줘', [call])
        wrong = '승인 만료: 2026-10-27 11:59:25 KST, 약 9시간 후 만료.'
        fence = '```json\n{"approval_expires_at": 1793037565}\n```'
        answer = H.write_report(wrong + '\n' + fence, progress)
        self.assertNotIn('11:59:25', answer); self.assertNotIn('9시간', answer)
        self.assertIn(fence, answer); self.assertIn(shown['approval_expires_at_kst'], answer)
        forged = {**call, 'result_sha256': '0' * 64}
        self.assertEqual(H.write_progress('WAF 룰 변경안 작성해줘', [forged])['expiries'], [])
        for value in (True, '1793037565', 10**100):
            self.assertIsNone(H.approval_expiry_kst(value))

    def test_native_proposal_time_is_projected_only_to_api_copy(self):
        @dataclass
        class Request:
            api_kwargs: object
            api_messages: object = None
            _original_api_kwargs: object = None
        q = 'WAF 룰 변경안 작성해줘'
        agent = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom',
                                max_iterations=12, _current_turn_id='t')
        rows = [{'role': 'user', 'content': q}] + H.linked_rows([proposal('a:modsecurity-custom', approval_expires_at=1793037565)])
        original = copy.deepcopy(rows)
        request = Request({'messages': rows})
        out = alignment.request_wrapper(lambda *a, **k: request, PLUGIN, H)(agent,
            original_user_message=q, turn_id='t', messages=rows)
        self.assertEqual(rows, original)
        self.assertIn('approval_expires_at_kst', out.api_kwargs['messages'][-1]['content'])
        self.assertNotIn('approval_expires_at_kst', rows[-1]['content'])

    def test_known_presubmit_rejection_recovers_only_after_verified_receipt(self):
        messages = ['edit 2 old_text must match exactly once in the original file',
                    'edit 1 old_text is absent from the original file',
                    'base_sha256 must be a SHA-256 from get_rule_change_target',
                    'target changed since it was read; fetch current content and retry',
                    'Wazuh comments must use XML syntax; non-whitespace text outside rule elements is forbidden']
        for error in messages:
            for depth in range(3):
                wrapped = error
                for _ in range(depth): wrapped = json.dumps({'error': wrapped})
                failed = proposal('a:modsecurity-custom', error=wrapped)
                failed['is_error'] = True
                # Real error responses have no proposal receipt, unlike the helper default.
                failed['result'] = json.dumps({'error': wrapped})
                failed['result_sha256'] = hashlib.sha256(failed['result'].encode()).hexdigest()
                with self.subTest(error=error, depth=depth):
                    self.assertFalse(H.write_progress('WAF 룰 수정해줘', [failed])['complete'])
                    fixed = H.write_progress('WAF 룰 수정해줘', [failed, proposal('a:modsecurity-custom')])
                    self.assertTrue(fixed['complete'])
                    self.assertIn('이전 거절 이력', fixed['text'])
                    self.assertFalse(H.write_progress('WAF 룰 수정해줘', [proposal('a:modsecurity-custom'), failed])['complete'])

    def test_unknown_transport_outcome_not_cleared_by_later_receipt(self):
        for error in ('TimeoutError', 'HTTP 502', 'unknown', 'edit 1 old_text is absent from the original file; applied'):
            failed = proposal('a:modsecurity-custom', error=json.dumps({'error': error}))
            self.assertFalse(H.write_progress('WAF 룰 수정해줘', [failed, proposal('a:modsecurity-custom', '2'*32)])['complete'])

    def test_recovered_write_keeps_model_report_and_appends_verified_metadata(self):
        q = 'WAF 룰 주석 변경안을 작성해줘'
        bad = proposal('a:modsecurity-custom', error=json.dumps({'error': 'edit 1 old_text is absent from the original file'}))
        good = proposal('a:modsecurity-custom', validation='offline guards only; engine test after approval',
                        approval_expires_at=1793031551)
        h = Harness(text='승인 대기입니다. 원복 방법은 새 후보를 제출하는 것입니다.', request=q)
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        h.kw['messages'] += H.linked_rows([bad, good])
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        result = h.call().final_response
        self.assertIn('원복 방법', result)
        self.assertIn('제출 검증 범위', result)
        self.assertIn('2026-10-27T01:19:11+09:00', result)
        self.assertNotIn('일부 미완료', result)

    def test_write_request_cannot_skip_execution_claim_checks(self):
        h = Harness(text='실행 결과: 차단 요청 실패 (서버 거부). 현재 차단 목록에 없습니다.',
                    request='관리 서버의 차단 요청을 처리해줘')
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        result = h.call().final_response
        self.assertNotIn('현재 차단 목록에 없습니다', result)
        self.assertIn('호출하지 않았습니다', result)

    def test_write_intent_includes_mode_change_without_forcing_a_fake_read(self):
        q = '보호 모드를 바꾸고 IDS 컨테이너를 inline으로 재구성해줘'
        self.assertTrue(H.READ.wants_write(q))
        self.assertNotIn('current_state_requires_actual_read', H.violations(q,
            '허용된 기능으로는 두 작업을 수행할 수 없습니다. 조회와 변경을 실행하지 않았습니다.', []))
        for text in ('시각을 KST로 바꾸고 시간 차를 계산해줘', 'Wazuh 규칙 조회 결과를 표로 바꿔줘'):
            self.assertFalse(H.READ.wants_write(text))
        self.assertTrue(H.READ.wants_write('WAF 모드를 On으로 바꾸고 시각은 KST로 바꿔줘'))

    def test_unsupported_changes_keep_explanation_but_not_false_completion(self):
        q = 'WAF 규칙 처리 모드를 바꾸고 IDS 컨테이너를 inline으로 재구성해줘'
        reason = '현재 도구는 모드 변경과 컨테이너 재구성을 지원하지 않습니다. 두 작업을 실행하지 않았습니다.'
        progress = H.write_progress(q, [])
        self.assertFalse(progress['complete'])
        self.assertIn(reason, H.write_report(reason, progress))
        self.assertNotIn('모두 성공', H.write_report(reason + ' 모두 성공했습니다.', progress))
        h = Harness(text=reason, request=q)
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        self.assertIn(reason, h.call().final_response)

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
