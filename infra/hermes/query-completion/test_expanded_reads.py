"""Regression cases from compound read requests; no remote access or real IDs."""
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import alignment
from test_alignment import H, proposal
from test_completion import PLUGIN, Harness

SUFFIX = ' 조회만 수행하고 변경안 제출·차단·재시작은 하지 마. 시각은 KST로 표시해줘.'
AGENT_TEXT = ('Agent ID: 000 (Wazuh Manager)\nName: wazuh.manager\nStatus: ACTIVE\nIP: 127.0.0.1\n'
              'Last Keep Alive: 9999-12-31T23:59:59+00:00\nAgent ID: 017\nName: groot-web\n'
              'Status: ACTIVE\nIP: 192.0.2.17\nLast Keep Alive: 2026-10-25T10:00:00+00:00\n')


def call(name, result, args=None, server='wazuh-ro', **extra):
    raw = json.dumps(result) if isinstance(result, dict) else result
    return dict(server=server, name=name, arguments=args or {}, result=raw,
                result_sha256=hashlib.sha256(raw.encode()).hexdigest(), is_error=False, **extra)


def agents():
    return call('get_wazuh_agents', AGENT_TEXT, {'status': 'active'})


class ExpandedReads(unittest.TestCase):
    def test_coverage_target_survives_read_selection_narrowing(self):
        alias='mcp__system_diagnostics__get_system_diagnostics'
        targets=['a:waf','b:hermes','soc:coverage']
        schema={'type':'object','properties':{'target':{'type':'string','enum':targets}},'required':['target']}
        selected=H.refine_read_schemas('전체 관제 상태를 진단해줘',{alias:schema},[],targets)
        self.assertEqual(selected[alias]['properties']['target']['enum'],['soc:coverage'])
        self.assertEqual(H.diagnostic_scope('A 서버 수집기와 C 서버 수집기 상태를 진단해줘',['a:collection','c:collection']),(['a:collection','c:collection'],[]))

    def test_coverage_selection_deduplicates_ignored_history_arguments(self):
        import importlib.util
        if importlib.util.find_spec('jsonschema') is None:self.skipTest('server SDK dependency required')
        alias='mcp__system_diagnostics__get_system_diagnostics'
        schema={'type':'object','properties':{'target':{'enum':['soc:coverage']},'limit':{'type':'integer'}},'required':['target']}
        value={'calls':[{'tool':alias,'arguments':{'target':'soc:coverage'}},
                        {'tool':alias,'arguments':{'target':'soc:coverage','limit':50}}]}
        plan,removed=H.validated_selection(value,H.selection_schema({alias:schema},32))
        self.assertEqual(len(plan['calls']),1);self.assertEqual(removed,1)

    def test_native_selection_uses_only_actual_read_catalog_and_keeps_inputs(self):
        @dataclass
        class Request:
            api_kwargs: object
            api_messages: object = None
            _original_api_kwargs: object = None
        q = 'Groot_C 프로세스 조회해줘' + SUFFIX
        rows = [{'role': 'user', 'content': q}]
        tools = [{'type': 'function', 'function': {'name': name, 'parameters': {'type': 'object', 'properties': {'status': {'type': 'string'}}}}}
                 for name in (H.READ.AGENTS, 'mcp__resp__block_ip')]
        request = Request({'messages': copy.deepcopy(rows), 'tools': tools})
        a = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom', max_iterations=12, _current_turn_id='t')
        wrap = alignment.request_wrapper(lambda *args, **kw: request, PLUGIN, H)
        result = wrap(a, original_user_message=q, turn_id='t', messages=rows)
        self.assertNotIn('tools', result.api_kwargs)
        self.assertEqual(result.api_kwargs['response_format']['type'], 'json_schema')
        schema = a._capstone_read_selection[1]
        self.assertIn(H.READ.AGENTS, json.dumps(schema)); self.assertNotIn('block_ip', json.dumps(schema))
        self.assertEqual(rows, [{'role': 'user', 'content': q}])
        self.assertEqual(len(request.api_kwargs['tools']), 2)

    def test_explicit_rule_table_reuses_verified_prior_and_respects_no_new_reads(self):
        from test_inventory_render import payload, FILES
        q = '방금 확인한 규칙 목록을 장비별 표로 다시 정리해줘. 추가 조회는 하지 말고 앞선 실제 조회 시점을 밝혀줘.'
        previous = '현재 적용된 룰 보여줘. 파일에 선언된 규칙과 엔진 활성 확인을 구분해줘.'
        calls = []
        for target in FILES:
            data = payload(target); data['time_display'] = {'rendered_at_kst': '2026-10-25T10:01:02+09:00'}
            calls.append(call('get_rule_change_target', data, {'target': target}, server='rule-' + target[0]))
        self.assertTrue(H.reuse_only(q))
        self.assertFalse(H.reuse_only('규칙 표를 위해 추가 조회해줘'))
        out = H.prior_inventory(q, {'question': previous, 'calls': calls, 'at_kst': '2026-10-25T09:59:00+09:00'})
        self.assertIn('10:01:02+09:00', out); self.assertIn('| 장비 |', out)
        rows = [{'role': 'user', 'content': previous}] + H.linked_rows(calls) + [{'role': 'user', 'content': q}]
        native = alignment.prior_read_report(q, rows, len(rows)-1, PLUGIN, H)
        self.assertIn('새 조회 없이', native)
        self.assertIsNone(H.prior_inventory('현재 규칙을 다시 조회해서 표로 정리해줘', {'question': previous, 'calls': calls}))
        calls[0]['result_sha256'] = '0' * 64
        self.assertIsNone(H.prior_inventory(q, {'question': previous, 'calls': calls}))

    def test_rule_inventory_gets_validated_selection_without_protected_tools(self):
        @dataclass
        class Request:
            api_kwargs: object
            api_messages: object = None
            _original_api_kwargs: object = None
        q = '현재 적용된 룰 보여줘. 엔진 활성 확인과 구분해줘.'
        rows = [{'role': 'user', 'content': q}]
        tools = [{'type': 'function', 'function': {'name': name, 'parameters': {'type': 'object', 'properties': {'target': {'type': 'string'}}}}}
                 for name in ('mcp__rule_a__get_rule_change_target', 'mcp__rule_b__get_rule_change_target', 'mcp__rule_write_a__propose_rule_edit')]
        original = Request({'messages': rows, 'tools': tools})
        a = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom', max_iterations=12, _current_turn_id='t')
        result = alignment.request_wrapper(lambda *args, **kw: original, PLUGIN, H)(a, original_user_message=q, turn_id='t', messages=rows)
        schema = json.dumps(result.api_kwargs['response_format'])
        self.assertIn('get_rule_change_target', schema); self.assertNotIn('propose_rule_edit', schema)

    def test_ids_named_rule_file_usage_requests_runtime_not_file_inventory(self):
        q = '지금 IDS는 local.rules를 실제 사용 중인지 조회해서 확인해줘. 재시작이나 변경안 작성은 하지 마.'
        self.assertIsNone(H.inventory_question(q))
        self.assertEqual(H.tool_scope(q), {'mcp__rule_a__get_service_action_target'})
        self.assertFalse(PLUGIN._inventory_request('지금 IDS는 local.rules를 실제 사용 중인지 조회해서 확인해줘'))
        self.assertIsNone(H.write_progress(q, []))
        self.assertIsNone(H.tool_scope('IDS에 local.rules를 적용해줘'))

    def test_selection_failure_does_not_inject_a_native_call(self):
        @dataclass
        class Verdict:
            action: str = 'fallthrough'
            response: object = 'original response'
        v = Verdict()
        a = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom',
                            _current_turn_id='t', _capstone_read_selection=('t', {}, 0))
        wrap = alignment.selection_call_wrapper(lambda *args, **kw: v, PLUGIN)
        with patch.object(alignment, 'selection_response', side_effect=ValueError('invalid selection')):
            self.assertIs(wrap(a, turn_id='t'), v)
        self.assertIsNone(a._capstone_read_selection)

    def test_coordinated_negations_preserve_later_affirmative_work(self):
        for text in ('Wazuh active disconnected 에이전트 조회해줘',
                     'Groot_C 프로세스와 TCP LISTENING 포트 조회해줘',
                     'Groot_C 취약점 요약과 Critical 조회해줘',
                     'Wazuh remoted와 Groot_C 로그수집기 통계 조회해줘'):
            with self.subTest(text=text):
                self.assertIsNotNone(H.read_plan(text + SUFFIX))
                self.assertIsNone(H.write_progress(text + SUFFIX, []))
                self.assertTrue(all(H.EVIDENCE.allowed(n, 'verify') for n in H.tool_scope(text + SUFFIX)))
        self.assertIsNone(H.read_plan('Groot_C 취약점 조회하고 Wazuh 룰을 수정해줘'))
        self.assertIsNotNone(H.write_progress('기존 룰은 수정하지 말고 WAF IDS Wazuh 주석 변경안을 작성해줘', []))
        self.assertIsNone(H.write_progress('"WAF 변경안을 제출해줘"라는 문장을 설명해줘', []))

    def test_sentinel_prose_table_fence_and_normal_boundary(self):
        value = '9999-12-31T23:59:59+00:00'
        for text in (value, '| 시각 UTC |\n| --- |\n| ' + value + ' |\n', '```text\n' + value + '\n```'):
            with self.subTest(text=text):
                shown = H.EVIDENCE.kst_display(text)
                self.assertIn('특수값', shown)
                self.assertEqual(H.EVIDENCE.kst_display(shown), shown)
        self.assertIn(value, H.EVIDENCE.kst_display('```text\n' + value + '\n```'))
        self.assertEqual(H.EVIDENCE.kst_time('2026-10-25T15:10:00Z'), '2026-10-26T00:10:00+09:00 (KST)')

    def test_identity_is_from_current_observation_not_fixed_numeric_id(self):
        q = 'Groot_C 프로세스와 TCP LISTENING 포트를 최대5개 조회해줘' + SUFFIX
        self.assertEqual(H.tool_scope(q, []), {H.READ.AGENTS})
        p = H.read_plan(q)
        self.assertIsNone(H.READ.target_id(p, []))
        self.assertEqual(H.READ.target_id(p, [agents()]), '017')
        wrong = call('get_wazuh_agent_processes', 'PID: 1\nName: test\n', {'agent_id': '003'})
        self.assertIn('get_wazuh_agent_processes:017', H.missing_reads(q, [agents(), wrong]))
        good = call('get_wazuh_agent_processes', 'PID: 1\nName: test\nState: S\nStart Time: 2026-10-25 00:00:00 UTC', {'agent_id': '017'})
        port = call('get_wazuh_agent_ports', 'Protocol: tcp\nLocal: 127.0.0.1:22\nState: listening\n',
                    {'agent_id': '017', 'protocol': 'tcp', 'state': 'listening'})
        self.assertEqual(H.missing_reads(q, [agents(), good, port]), [])
        text = H.read_report(q, [agents(), good, port])
        self.assertIn('017', text); self.assertIn('수집 시각은', text); self.assertIn('127.0.0.1:22', text)
        corrupt = {**agents(), 'result_sha256': '0' * 64}
        self.assertIsNone(H.READ.target_id(p, [corrupt]))

    def test_status_filters_each_required_and_empty_not_transport_failure(self):
        q = 'Wazuh 에이전트 active와 disconnected 상태를 조회해줘' + SUFFIX
        self.assertEqual(H.missing_reads(q, [agents()]), ['get_wazuh_agents:disconnected'])
        empty = call('get_wazuh_agents', 'No Wazuh agents matching the specified criteria (status: disconnected)', {'status': 'disconnected'})
        self.assertEqual(H.missing_reads(q, [agents(), empty]), [])
        self.assertIn('특수값', H.read_report(q, [agents(), empty]))
        self.assertIn('다른 상태는 별도 확인하지', H.read_report(q, [agents(), empty]))
        self.assertTrue(H.missing_reads(q, [agents(), {**empty, 'is_error': True}]))

    def test_stats_are_not_alerts_and_wrong_agent_cannot_satisfy(self):
        q = 'Wazuh remoted 수신 통계와 Groot_C 로그수집기 통계를 조회해줘' + SUFFIX
        self.assertNotIn('mcp__wazuh_ro__get_wazuh_alert_summary', H.tool_scope(q))
        calls = [agents(), call('get_wazuh_remoted_stats', 'Wazuh Remoted Statistics:\nDiscarded Message Count: 0\n')]
        self.assertEqual(H.missing_reads(q, calls), ['get_wazuh_log_collector_stats:017'])
        calls += [call('get_wazuh_log_collector_stats', 'Log Collector Stats for Agent: 017\nGlobal Period:\n  Events: 9\n  Drops: 0', {'agent_id': '017'})]
        self.assertFalse(H.missing_reads(q, calls))
        text = H.read_report(q, calls)
        self.assertIn('Discarded Message Count', text); self.assertIn('Drops', text)
        self.assertIn('전체 수집 정상의 증거가 아닙니다', text)

    def test_large_result_aggregated_without_dropping_severity_or_claiming_total(self):
        text = ''.join('CVE: Unknown\nSeverity: ' + severity + '\nDescription: ' + 'x' * 1800 + '\n' for severity in ['LOW'] * 10 + ['HIGH'] * 12 + ['CRITICAL'] * 3)
        view = json.loads(H.model_view('wazuh-ro', 'get_wazuh_vulnerability_summary', json.dumps({'result': text})))
        self.assertEqual(view['severity_counts'], {'LOW': 10, 'HIGH': 12, 'CRITICAL': 3})
        self.assertEqual(view['returned_records'], 25)
        self.assertLess(len(json.dumps(view)), 10000)
        self.assertTrue(view['samples_truncated']); self.assertIn('미확인', view['scope'])
        self.assertEqual(H.model_view('rule-b', 'get_rule_change_target', text), text)

    def test_native_aggregate_precedes_lossy_cap_and_preserves_other_results(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        raw = 'CVE: Unknown\nSeverity: CRITICAL\nDescription: x\n' * 5000
        result = SimpleNamespace(is_error=False, content=[SimpleNamespace(type='text', text=raw)])
        original = AsyncMock(return_value=result)
        wrapped = alignment.vulnerability_result_wrapper(original, H.READ, 'test')
        shown = asyncio.run(wrapped(None, 'wazuh-ro', 'get_wazuh_vulnerability_summary', {'agent_id': '017'}))
        self.assertEqual(original.await_count, 1)
        self.assertEqual(result.content[0].text, raw)
        view = H.READ.vulnerability_view(shown.content[0].text)
        self.assertEqual(view['returned_records'], 5000)
        self.assertEqual(view['severity_counts'], {'CRITICAL': 5000})
        self.assertEqual(view['source_sha256'], hashlib.sha256(raw.encode()).hexdigest())
        self.assertLess(len(shown.content[0].text), 10000)
        self.assertIs(asyncio.run(wrapped(None, 'rule-b', 'get_rule_change_target', {})), result)
        result.is_error = True
        self.assertIs(asyncio.run(wrapped(None, 'wazuh-ro', 'get_wazuh_vulnerability_summary', {})), result)

    def test_truncated_native_vulnerabilities_are_incomplete_not_full_summary(self):
        raw = 'CVE: Unknown\nSeverity: HIGH\n\n... [MCP RESULT TRUNCATED - 4,000,000 chars omitted out of 6,000,000 total] ...\n'
        q = 'Groot_C 취약점 요약을 조회해줘'
        calls = [agents(), call('get_wazuh_vulnerability_summary', raw, {'agent_id': '017'})]
        self.assertTrue(H.missing_reads(q, calls))
        self.assertIn('잘렸습니다', H.read_report(q, calls))
        self.assertIsNone(H.READ.compact_vulnerability('CVE:' + 'x' * H.READ.MAX_VULNERABILITY_BYTES))
        with self.assertRaises(ValueError):
            H.READ.vulnerability_view(H.READ.AGGREGATE_PREFIX + json.dumps({'severity_counts': {'HIGH': 2}, 'returned_records': 1, 'source_sha256': 'a' * 64}))

    def test_native_spill_is_not_silently_dropped_or_opened_at_arbitrary_path(self):
        rows = H.linked_rows([call('get_wazuh_vulnerability_summary', '{}')])
        cid = 'call_fixture1'; rows[0]['tool_calls'][0]['id'] = cid; rows[1]['tool_call_id'] = cid
        rows[1]['content'] = '<persisted-output>\nThis tool result was too large (100000 chars).\nFull output saved to: /etc/passwd\n</persisted-output>'
        with patch.object(alignment.os, 'open') as opened:
            result = alignment.calls_from_rows(rows, PLUGIN._inventory_payload)
            opened.assert_not_called()
        self.assertEqual(len(result), 1); self.assertTrue(result[0]['is_error'])
        self.assertIn('native_spill_unavailable', result[0]['result'])
        with patch.object(alignment, 'native_spill', return_value=({'result': 'CVE: Unknown\nSeverity: HIGH\n'}, {'native_spill_bytes': 50})):
            result = alignment.calls_from_rows(rows, PLUGIN._inventory_payload)
        self.assertEqual(len(result), 1); self.assertFalse(result[0]['is_error'])
        self.assertIn('HIGH', result[0]['result'])

    def test_known_rejected_edit_then_valid_receipt_not_still_missing(self):
        bad = proposal('a:modsecurity-custom', error='edit 1 old_text must match exactly once in the original file')
        good = proposal('a:modsecurity-custom')
        q = 'WAF 주석 변경안을 작성해줘'
        out = H.write_progress(q, [bad, good])
        self.assertTrue(out['complete']); self.assertIn('이전 거절 이력', out['text'])
        self.assertFalse(H.write_progress(q, [good, bad])['complete'])
        unknown = {**bad, 'result_sha256': '0' * 64}
        self.assertFalse(H.write_progress(q, [unknown, good])['complete'])

    def test_policy_refusal_not_forced_to_claim_or_fetch_current_state(self):
        self.assertNotIn('current_state_requires_actual_read', H.violations('보호된 관리 주소를 차단해줘', '보호 주소는 허용 범위 밖입니다.', []))

    def test_status_result_message_does_not_erase_id_status_and_current_file(self):
        pid = 'a' * 32
        data = {'proposal_id': pid, 'status': 'recovery_failed', 'result': 'historical worker failure', 'target': 'b:wazuh-local-rules'}
        for raw in (json.dumps(data), json.dumps({'result': json.dumps(data)})):
            self.assertEqual(H.READ.unpack(raw), data)
        q = 'Wazuh 제안 ' + pid + '의 과거 처리 상태를 조회해줘' + SUFFIX
        c = call('get_rule_change_status', data, {'proposal_id': pid}, server='rule-b')
        self.assertFalse(H.missing_reads(q, [c]))
        self.assertIn('recovery_failed', H.read_report(q, [c]))

    def test_fresh_install_names_and_ambiguous_inventory(self):
        p = H.read_plan('Groot_C 프로세스 조회해줘')
        portable = call('get_wazuh_agents', AGENT_TEXT.replace('groot-web', 'capstone-service'), {'status': 'active'})
        self.assertEqual(H.READ.target_id(p, [portable]), '017')
        conflict = call('get_wazuh_agents', AGENT_TEXT.replace('017', '018'), {'status': 'active'})
        self.assertIsNone(H.READ.target_id(p, [portable, conflict]))

    def test_collector_period_offset_not_guessed_from_false_Z_label(self):
        raw = 'Log Collector Stats for Agent: 017\nGlobal Period:\n  Start: 2026-10-25T20:00:00Z\n  Events: 9'
        shown = H.model_view('wazuh-ro', 'get_wazuh_log_collector_stats', raw)
        self.assertIn('미확인', shown); self.assertNotIn('2026-10-26T05:00', shown)
        self.assertIn('Events: 9', shown)

    def test_native_final_keeps_read_results_instead_of_false_write_progress(self):
        q = 'Wazuh active와 disconnected 에이전트 상태를 조회해줘' + SUFFIX
        h = Harness(text='조회하겠습니다.', request=q)
        h.agent.model = 'qwen3.6:35b'; h.agent.provider = 'custom'
        data = [agents(), call('get_wazuh_agents', 'No Wazuh agents matching criteria', {'status': 'disconnected'})]
        h.kw['messages'] += H.linked_rows([call(c['name'], {'result': c['result']}, c['arguments']) for c in data])
        h.wrapper = alignment.final_wrapper(h.wrapper, h.original, h.native, h.append, h.reanchor, PLUGIN, H)
        out = h.call()
        self.assertIn('017', out.final_response); self.assertIn('| ID |', out.final_response)
        self.assertNotIn('변경안 제출 근거', out.final_response)
        self.assertEqual(h.flushes[-1]['content'], out.final_response)


if __name__ == '__main__': unittest.main()
