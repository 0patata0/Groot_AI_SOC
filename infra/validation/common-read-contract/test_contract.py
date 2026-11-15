"""Short scope, supplied-time and citation counterexamples; no remote calls.

Set SOC_CONTRACT_ROOT to a reconstructed candidate (or baseline). The same
questions run against both arms. These are development regressions, not an
independent SOC or model-quality score.
"""
import asyncio
import copy
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(os.environ.get('SOC_CONTRACT_ROOT', Path(__file__).resolve().parents[3])).resolve()
sys.path.insert(0, str(ROOT / 'infra/ollama-trial'))
sys.path.insert(0, str(ROOT / 'infra/hermes/query-completion'))
import harness as H
import runtime as R
import alignment

DIAG = 'mcp__system_diagnostics__get_system_diagnostics'
INVENTORY = H.HOST_INVENTORY_TOOL
STAMP = '2026-11-06T01:24:00+09:00'


def sealed(name, data, arguments=None, server='security-events'):
    raw = json.dumps(data)
    return dict(server=server, name=name, arguments=arguments or {}, result=raw,
                result_sha256=hashlib.sha256(raw.encode()).hexdigest(), is_error=False)


class HostScope(unittest.TestCase):
    def test_short_labels_select_only_named_systemd(self):
        for host in 'ABC':
            with self.subTest(host=host):
                self.assertEqual(H.diagnostic_request(host + ' systemd 지금 문제 있어?')['requested'],
                                 [host.lower() + ':systemd'])

    def test_formal_and_short_names_share_the_scope(self):
        for name in ('B 서버', 'B 호스트', 'Groot_B', 'groot-siem-host', 'SIEM 서버', 'B'):
            with self.subTest(name=name):
                self.assertEqual(H.diagnostic_request(name + ' systemd 상태 확인')['requested'], ['b:systemd'])

    def test_wazuh_named_features_use_the_same_short_host_mapping(self):
        for host, asset in (('A', 'groot-sec'), ('B', 'groot-siem-host'), ('C', 'groot-web')):
            with self.subTest(host=host):
                self.assertEqual(H.read_plan(host + ' 취약점 보여줘')['agent_name'], asset)

    def test_excluded_host_does_not_expand_or_replace_requested_host(self):
        for text in ('B 말고 C systemd 상태 확인', 'B 제외하고 C systemd 상태 확인',
                     'B 서버는 빼고 C systemd 상태 확인'):
            with self.subTest(text=text):
                self.assertEqual(H.diagnostic_request(text)['requested'], ['c:systemd'])

    def test_multiple_qualified_services_keep_their_own_host(self):
        self.assertEqual(set(H.diagnostic_request('A Vector와 B Docker 현재 상태?')['requested']),
                         {'a:vector', 'b:docker'})
        self.assertEqual(set(H.diagnostic_request('A systemd와 C systemd 상태 확인')['requested']),
                         {'a:systemd', 'c:systemd'})

    def test_explicit_host_does_not_fall_back_to_service_default(self):
        self.assertEqual(H.diagnostic_scope('C Vector 상태 확인', ['a:vector']), ([], ['c:vector']))

    def test_lowercase_article_names_paths_and_addresses_are_not_short_hosts(self):
        for text in ('a Docker container', 'CAB state', '/tmp/B/config', 'B.service',
                     '192.0.2.1', 'x-B', 'a:b', '/tmp/Groot_B/config', 'Groot_B.service'):
            with self.subTest(text=text):
                self.assertEqual(H.READ.host_mentions(text), [])

    def test_inventory_views_keep_the_named_host(self):
        for phrase in ('메모리 보여줘', '네트워크 보여줘', '디스크 용량 보여줘',
                       '프로세스 보여줘', '수신 포트 보여줘', 'Docker 사용량 보여줘',
                       'systemd 서비스 보여줘'):
            with self.subTest(phrase=phrase):
                rows = H.host_inventory_request('B ' + phrase)
                self.assertTrue(rows)
                self.assertEqual({r['host'] for r in rows}, {'b'})

    def test_service_and_container_details_keep_object_kind(self):
        service = H.host_inventory_request('C ssh.service 상세 상태 보여줘')[0]
        container = H.host_inventory_request('B hermes 컨테이너 상세 보여줘')[0]
        self.assertEqual((service['host'], service['view'], service['unit']), ('c', 'service_details', 'ssh.service'))
        self.assertEqual((container['host'], container['view'], container['container']), ('b', 'container_details', 'hermes'))

    def test_followup_keeps_unit_host_and_explicit_topic_switch_wins(self):
        previous = ['C ssh.service 상세 상태 보여줘']
        followup = H.resolve_short_read('메모리는?', previous)
        self.assertEqual(H.host_inventory_request(followup)[0]['host'], 'c')
        self.assertEqual(H.host_inventory_request(followup)[0]['unit'], 'ssh.service')
        switched = 'B Docker 사용량 보여줘'
        self.assertEqual(H.resolve_short_read(switched, previous), switched)

    def test_schema_cannot_choose_a_different_host(self):
        source = {DIAG: {'type': 'object', 'properties': {'target': {'type': 'string',
            'enum': ['a:systemd', 'b:systemd', 'c:systemd']}}, 'required': ['target']}}
        before = copy.deepcopy(source)
        selected = H.refine_read_schemas('B systemd 지금 문제 있어?', source, [], ['a:systemd', 'b:systemd', 'c:systemd'])
        self.assertEqual(selected[DIAG]['properties']['target']['enum'], ['b:systemd'])
        self.assertEqual(source, before)


class SuppliedTime(unittest.TestCase):
    def test_kst_display_is_not_time_arithmetic_in_either_adapter(self):
        for stamp in (STAMP, STAMP.replace('+09:00', '+0900'), STAMP.replace('+09:00', ' KST')):
            q = stamp + ' 이 시각 정리해줘.'
            with self.subTest(stamp=stamp):
                self.assertIsNone(H.read_plan(q))
                self.assertFalse(H.SHARED.time_calculation_request(q))
                self.assertIn(stamp, H.supplied_time_report(q))

    def test_preserves_fractional_seconds_and_each_supplied_value(self):
        a = '2026-11-06T01:24:00.123456789+09:00'
        b = '2026-11-06T01:25:00+09:00'
        report = H.supplied_time_report(a + '\n' + b + '\n시각 표로 정리해줘')
        self.assertIn(a, report)
        self.assertIn(b, report)
        self.assertNotIn('0초', report)
        self.assertNotIn('기준 시각:', report)

    def test_arithmetic_order_and_real_conversion_still_require_calculation(self):
        for q in (STAMP + '부터 2026-11-06T01:25:00+09:00까지 시간차 계산해줘',
                  STAMP + ' 이 시각 이후 얼마나 지났어?',
                  STAMP + ' 시간순 정렬해줘',
                  '2026-11-05T16:24:00Z를 KST로 변환해줘'):
            with self.subTest(q=q):
                self.assertTrue(H.SHARED.time_calculation_request(q))
                self.assertEqual(H.read_plan(q)['kind'], 'time')
                self.assertIsNone(H.supplied_time_report(q))

    def test_mixed_operational_requests_are_not_formatting_shortcuts(self):
        for extra in ('B systemd 상태도 확인해줘', '로그에서 이 시각 찾아줘', 'FW 룰도 조회해줘',
                      '차단해줘', 'JSON으로 출력해줘', '원인은 뭐야?'):
            with self.subTest(extra=extra):
                self.assertIsNone(H.supplied_time_report(STAMP + ' ' + extra))

    def test_ambiguous_naive_date_and_timestamp_only_do_not_invent_offset(self):
        self.assertIsNone(H.supplied_time_report('2026-11-06T01:24:00 이 시각 정리해줘'))
        self.assertFalse(H.SHARED.time_calculation_request('2026-11-06T01:24:00 시간차 계산해줘'))
        self.assertIsNone(H.supplied_time_report('2026-02-31T01:24:00+09:00 이 시각 정리해줘'))

    def test_sdk_display_returns_before_mcp_or_model_initialization(self):
        config = {'model': 'fixture-model', 'access_mode': 'hermes-parity'}
        result = asyncio.run(R.run(config, {'question': STAMP + ' 이 시각 정리해줘.'}))
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['calls'], [])
        self.assertEqual(result['model_calls'], [])
        self.assertEqual(result['protected_calls'], 0)
        self.assertTrue(result['supplied_data_only'])
        self.assertIn('| 항목 | KST 원시각 |', result['final_response'])

    def test_native_display_uses_the_same_local_formatter(self):
        @dataclass
        class Request:
            api_kwargs: object
        q = STAMP + ' 이 시각 정리해줘.'
        request = Request({'messages': [{'role': 'user', 'content': q}], 'tools': []})
        agent = SimpleNamespace(platform='mattermost', model='qwen3.6:35b', provider='custom',
                                max_iterations=12, _current_turn_id='time-turn')
        result = alignment.request_wrapper(lambda *a, **kw: request, H.SHARED, H)(
            agent, original_user_message=q, turn_id='time-turn', messages=[{'role': 'user', 'content': q}])
        self.assertIs(result, request)
        self.assertEqual(agent._capstone_query_completion_local_format,
                         ('time-turn', H.supplied_time_report(q)))
        self.assertFalse(agent._capstone_alignment_partial)
        provider = lambda *a, **kw: self.fail('provider must not run for supplied KST display')
        native = SimpleNamespace(ApiCallVerdict=lambda **kw: SimpleNamespace(**kw), stop_thinking_spinner=lambda *a: None)
        response = H.SHARED.make_call_wrapper(provider, native, response_factory=lambda text, turn: (turn, text))(
            agent, turn_id='time-turn')
        self.assertEqual(response.response, ('time-turn', H.supplied_time_report(q)))
        self.assertFalse(hasattr(agent, '_capstone_query_completion_local_format'))


class EvidenceContract(unittest.TestCase):
    def test_observation_prompt_exposes_exact_successful_tool_identity(self):
        c = sealed('search_suricata_alerts', {'source': 'suricata', 'alerts': [], 'returned_count': 0})
        prompt = H.incident_observation_prompt('DNS 경보 조사해', [c])
        self.assertIn('"tool": "mcp__security_events__search_suricata_alerts"', prompt)
        self.assertNotIn('mcp__security_events__search_wazuh_alerts', prompt)

    def test_skills_load_through_the_shared_section_contract(self):
        text = H.CONTRACT.workflow_policy(('soc-investigate',), section='investigation-evidence')
        self.assertIn('반환 표본 0건', text)
        self.assertIn('evidence_tools', text)
        self.assertIn('unresolved', text)
        self.assertNotIn('교차 검토 단계에서만', text)

    def test_repair_reuses_policy_and_does_not_normalize_invalid_citations(self):
        c = sealed('search_suricata_alerts', {'source': 'suricata', 'alerts': [], 'returned_count': 0})
        text = H.incident_judgment_instruction('DNS 경보 조사해', '미확인', [c], ['incident_disposition_evidence_missing'])
        self.assertIn('조사 근거 확인과 인용', text)
        self.assertIn('mcp__security_events__search_suricata_alerts', text)
        full = 'mcp__security_events__search_suricata_alerts'
        for cite, expected in ((full, None), ('search_suricata_alerts', 'incident_disposition_evidence_missing')):
            answer = 'INCIDENT_DISPOSITION: ' + json.dumps({'assessment': 'unresolved', 'basis': '조회 표본 0건이며 요청 구간의 전체 건수와 위험은 미확인입니다.', 'evidence_tools': [cite]})
            _, error = H.EVIDENCE.parse_incident_disposition(answer, {full})
            self.assertEqual(error, expected)

    def test_no_operational_scope_or_protected_permission_is_added(self):
        for q in ('B systemd 재시작해줘', 'B Docker 삭제해줘'):
            self.assertIsNone(H.diagnostic_request(q))
            self.assertIsNone(H.host_inventory_request(q))
            self.assertIsNone(H.supplied_time_report(q))


if __name__ == '__main__':
    unittest.main(verbosity=2)
