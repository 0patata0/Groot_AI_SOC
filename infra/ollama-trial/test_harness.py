import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness
import policy
import chat


def fixture(target='a:modsecurity-custom'):
    content = 'fixture rule file\n'
    sha = hashlib.sha256(content.encode()).hexdigest()
    kind = {'a:modsecurity-custom': 'waf', 'a:suricata-local': 'suricata', 'b:wazuh-local-rules': 'wazuh'}[target]
    details = {'waf': {}, 'suricata': {'local_sid_count': 1, 'et_override_count': 0,
               'other_sid_count': 0, 'noalert_count': 0}, 'wazuh': {'level_counts': {'0': 1}, 'level0_count': 1}}[kind]
    data = {'target': target, 'content': content, 'sha256': sha, 'rule_inventory': {
        'schema_version': 1, 'scope': 'target_file_definitions', 'kind': kind,
        'source_sha256': sha, 'status': 'complete', 'runtime_load_verified': False,
        'ids': [10100], 'duplicate_ids': [], 'declared_count': 1, 'unique_id_count': 1, 'details': details}}
    raw = json.dumps(data)
    return {'server': 'rule-' + target[0], 'name': 'get_rule_change_target',
            'arguments': {'target': target}, 'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest(), 'is_error': False}


class Grounding(unittest.TestCase):
    def test_structured_read_selection_never_offers_protected_tools(self):
        with self.assertRaises(ValueError):
            harness.selection_schema({'mcp__rule_write_a__propose_rule_edit': {'type': 'object'}}, 3)
        with self.assertRaises(ValueError):
            harness.selection_schema({'execute_shell': {'type': 'object'}}, 3)
        schema = harness.selection_schema({'mcp__rule_a__get_rule_change_target': {'type': 'object'}}, 2)
        self.assertEqual(schema['properties']['calls']['maxItems'], 2)

    def test_inventory_and_ids_read_scope_do_not_strip_change_authority(self):
        self.assertEqual(harness.tool_scope('현재 적용된 규칙을 장비별로 표로 보여줘'),
                         {'mcp__rule_a__get_rule_change_target', 'mcp__rule_b__get_rule_change_target'})
        self.assertEqual(harness.tool_scope('IDS는 왜 활성화 안됐지? 지금 실제 상태와 SID 적재 확인해줘'),
                         {'mcp__rule_a__get_service_action_target'})
        self.assertIsNone(harness.tool_scope('IDS 규칙을 변경해줘'))
        self.assertIsNone(harness.tool_scope('IDS를 재시작해줘'))

    def test_event_and_diagnostic_coverage_requires_actual_success(self):
        q = 'WAF IDS Wazuh 보안 로그 조회해줘'
        self.assertEqual(len(harness.missing_reads(q, [])), 3)
        q = 'A/B/C 서버의 실패한 서비스 오류 조회'
        calls = [{'name': 'get_system_diagnostics', 'server': 'system-diagnostics',
                  'arguments': {'target': 'a:vector'}, 'result': '{}', 'is_error': False}]
        self.assertEqual(harness.missing_reads(q, calls, ['a:vector', 'b:vector']), ['a:vector', 'b:vector'])
        raw = json.dumps({'schema': 1, 'target': 'a:vector'})
        calls[0].update(result=raw, result_sha256=hashlib.sha256(raw.encode()).hexdigest())
        self.assertEqual(harness.missing_reads(q, calls, ['a:vector', 'b:vector']), ['b:vector'])
        calls[0]['is_error'] = True
        self.assertEqual(harness.missing_reads(q, calls, ['a:vector']), ['a:vector'])

    def test_diagnostic_renderer_keeps_every_host_and_unknowns(self):
        calls = []
        for target in ('a:one', 'b:two', 'c:three'):
            raw = json.dumps({'schema': 1, 'target': target, 'properties': {'Type': 'oneshot',
                'ActiveState': 'inactive', 'SubState': 'dead', 'Result': 'success'},
                'returned_error_count': 0, 'recent_errors': [], 'observed_at_kst': '2026-10-25T07:00:00+09:00'})
            calls.append({'name': 'get_system_diagnostics', 'arguments': {'target': target},
                'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest()})
        text = harness.diagnostic_report('A/B/C 서버 실패한 서비스 오류 조회', calls,
                                         ['a:one', 'b:two', 'c:three', 'c:missing'])
        for target in ('a:one', 'b:two', 'c:three', 'c:missing'):
            self.assertIn(target, text)
        self.assertIn('미확인(0건 아님)', text)
        self.assertNotIn('모두 정상', text)

    def test_event_renderer_preserves_actual_range_and_wazuh_timezone(self):
        raw = json.dumps({'result': 'Alert ID: 1.2\nTime: 2026-10-24T21:45:00+0000\nAgent: fixture\nLevel: 3\nDescription: sample\n'})
        calls = [{'server': 'wazuh-ro', 'name': 'get_wazuh_alert_summary', 'arguments': {'limit': 5},
                  'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest()}]
        text = harness.event_report('WAF IDS Wazuh 보안 로그 조회', calls)
        self.assertIn('반환 표본 1건', text)
        self.assertIn('2026-10-25T06:45:00+09:00', text)
        self.assertEqual(text.count('조회 미완료/실패'), 2)
        self.assertIn('절대 시작/종료 구간을 지원하지', text)
        calls[0]['result'] = json.loads(raw)['result']
        calls[0]['result_sha256'] = hashlib.sha256(calls[0]['result'].encode()).hexdigest()
        self.assertIn('반환 표본 1건', harness.event_report('WAF IDS Wazuh 보안 로그 조회', calls))
        self.assertIn('2026-10-25T06:45:00+09:00', harness.model_view('wazuh-ro', 'get_wazuh_alert_summary', calls[0]['result']))

    def test_ids_report_preserves_running_without_claiming_sid_load(self):
        raw = json.dumps({'target': 'a:suricata', 'observation': {'running': True, 'health': 'not_reported'},
            'rule_source_evidence': {'rule_source_option': '-S', 'rule_source_path': '/rules/all.rules',
                'combined_is_exact_et_plus_local': True}})
        call = {'server': 'rule-a', 'name': 'get_service_action_target', 'arguments': {'target': 'a:suricata'},
                'result': raw, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest()}
        text = harness.service_report('IDS는 왜 활성화 안됐지? 실제 조회해줘', [call])
        self.assertIn('**실행 중**', text)
        self.assertIn('개별 SID 엔진 적재는 미확인', text)
        self.assertIn('not_reported', text)
        self.assertNotIn('정상 가동', text)

    def test_state_and_test_label_do_not_hide_inventory(self):
        question = '[비교시험 Q1] 현재 적용된 룰 보여줘. 현재 상태 조회만 해줘.'
        missing = harness.inventory(question, [fixture()], missing_targets=True)
        self.assertEqual(missing, ['a:suricata-local', 'b:wazuh-local-rules'])

    def test_tampered_result_or_claimed_engine_load_is_not_evidence(self):
        for change in ({'result': 'fabricated'}, {'is_error': True}):
            c = {**fixture(), **change}
            self.assertEqual(harness.inventory('WAF 규칙 보여줘', [c], verified_targets=True), [])
        c = fixture(); data = json.loads(c['result']); data['rule_inventory']['runtime_load_verified'] = True
        c['result'] = json.dumps(data); c['result_sha256'] = hashlib.sha256(c['result'].encode()).hexdigest()
        self.assertEqual(harness.inventory('WAF 규칙 보여줘', [c], verified_targets=True), [])

    def test_latest_failure_invalidates_previous_success(self):
        good = fixture(); failed = {**good, 'is_error': True}
        self.assertEqual(harness.inventory('WAF 규칙 보여줘', [good, failed], verified_targets=True), [])

    def test_reformat_requires_complete_verified_evidence(self):
        evidence = {'question': '현재 적용된 규칙 보여줘', 'calls': [fixture()], 'at_kst': '2026-10-25T06:00:00+09:00'}
        self.assertIsNone(harness.prior_inventory('장비별로 표로 보여줘', evidence))
        evidence['calls'] += [fixture('a:suricata-local'), fixture('b:wazuh-local-rules')]
        self.assertIn('이전 실제 조회 시각', harness.prior_inventory('장비별로 표로 보여줘', evidence))
        self.assertIsNone(harness.prior_inventory('지금 다시 조회해서 표로 보여줘', evidence))

    def test_no_tool_current_claim_and_real_facts(self):
        self.assertIn('current_state_requires_actual_read', harness.violations('서버 오류 확인해줘', '조회 완료', []))
        facts = harness.facts_for([fixture()])
        self.assertEqual(facts[0]['kind'], 'rules')
        self.assertEqual(facts[0]['declared_count'], 1)

    def test_wazuh_legacy_text_times_are_grounded_and_presented_in_kst(self):
        raw = json.dumps({'result': 'Time: 2026-10-24T21:45:00.110+0000'})
        call = {'server': 'wazuh-ro', 'name': 'get_wazuh_alert_summary', 'result': raw}
        facts = harness.facts_for([call])
        self.assertEqual(facts[0]['instants'], ['2026-10-24T21:45:00.110+0000'])
        self.assertIn('2026-10-25T06:45:00.110000+09:00', harness.model_view('wazuh-ro', call['name'], raw))
        self.assertEqual(harness.model_view('rule-a', 'get_rule_change_target', raw), raw)

    def test_footer_and_explicit_kst_conversion(self):
        self.assertEqual(harness.footer_free('답변\n---\n읽기 전용 시험 · 옛날 · 처리 12.3초'), '답변')
        self.assertIn('2026-10-25T04:50:00', harness.EVIDENCE.kst_display('2026-10-24 19:50:00 UTC'))


class Parity(unittest.TestCase):
    def test_exact_hermes_capabilities_and_no_general_execution(self):
        tools = policy.capabilities('hermes-parity')
        self.assertEqual(sum(map(len, tools.values())), 36)
        self.assertEqual(sum(policy.protected(s, t) for s, names in tools.items() for t in names), 9)
        policy.validate_call('rule-write-a', 'propose_service_action', {'target': 'a:suricata'}, 'hermes-parity')
        for server, name, args in [('rule-write-a', 'propose_service_action', {'target': 'b:wazuh-manager'}),
                ('rule-a', 'propose_rule_edit', {}), ('rule-write-b', 'temporarily_contain_ip', {}),
                ('resp', 'execute_shell', {})]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                policy.validate_call(server, name, args, 'hermes-parity')

    def test_restart_never_replays_a_protected_attempt(self):
        with tempfile.TemporaryDirectory() as state, patch.object(chat, 'agent_config', return_value={}):
            g = chat.Gateway({}, None, state)
            g.db.execute("insert into jobs(id,post,status,protected_started) values('p','{}','running',1)")
            g.db.commit(); g.db.close()
            g = chat.Gateway({}, None, state)
            row = g.db.execute('select status,answer from jobs').fetchone()
            self.assertEqual(row['status'], 'delivery')
            self.assertIn('재요청하지 않았', row['answer']); g.db.close()

    def test_evidence_never_crosses_root_or_human(self):
        with tempfile.TemporaryDirectory() as state, patch.object(chat, 'agent_config', return_value={}):
            g = chat.Gateway({}, None, state)
            prior = {'id': 'old', 'user_id': 'u', 'channel_id': 'c', 'create_at': 1}
            g.db.execute("insert into jobs(id,post,status,evidence) values(?,?,'done',?)", ('old', json.dumps(prior), '{"calls":[]}'))
            g.db.commit()
            current = {'id': 'new', 'user_id': 'u', 'channel_id': 'c', 'create_at': 2}
            self.assertIsNone(g.prior_evidence(current))
            self.assertIsNotNone(g.prior_evidence({**current, 'root_id': 'old'}))
            self.assertIsNone(g.prior_evidence({**current, 'root_id': 'old', 'user_id': 'other'}))
            g.db.close()


if __name__ == '__main__':
    unittest.main()
