"""Service reads must retain their object through repair and final rendering."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

import harness as h

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'infra/mcp/system-diagnostics-mcp.py').is_file())
NAME = 'mcp__system_diagnostics__get_system_diagnostics'
AT = '2026-11-18T17:10:23+09:00'
QUESTION = 'A 서버 인증서 감시 서비스의 현재 상태와 최근 실행 결과를 표로 보여줘. 예전 실패와 지금 상태를 구분해줘.'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mcp = load('service_identity_mcp', ROOT / 'infra/mcp/system-diagnostics-mcp.py')
mcp._library = load('service_identity_core', ROOT / 'infra/mcp/system_diagnostics.py')


def catalog():
    tool = next(t for t in mcp.tools() if t['name'] == 'get_system_diagnostics')
    return {'tools': [{'function': {'name': NAME, 'parameters': copy.deepcopy(tool['inputSchema'])}}]}


def call(name, arguments, value, server='system-diagnostics'):
    raw = value if isinstance(value, str) else json.dumps(value)
    return {'server': server, 'name': name, 'arguments': arguments,
            'is_error': False, 'is_write': False, 'result': raw,
            'result_sha256': hashlib.sha256(raw.encode()).hexdigest()}


def snapshot():
    return call('get_system_diagnostics', {'target': 'a:certificate-monitor'},
        {'schema': 1, 'host': 'a', 'target': 'a:certificate-monitor',
         'unit': 'capstone-cert-monitor.service', 'status': 'observed',
         'mutation_performed': False, 'observed_at_kst': AT,
         'properties': {'Type': 'oneshot', 'Result': 'success', 'ExecMainStatus': 0}})


def agent():
    return call('get_wazuh_agents', {'status': 'active'},
        'Agent ID: 073\nName: groot-sec\nIP: 192.0.2.73\nStatus: ACTIVE\n'
        'Last Keep Alive: 2026-11-18T17:10:23+09:00\n', 'wazuh-ro')


class ServiceIdentityScope(unittest.TestCase):
    def plan(self, question=QUESTION, request=None):
        return h.CONTRACT.service_history_plan(request or catalog(), question, AT)

    def test_observed_failure_has_service_plan_and_no_agent_identity_requirement(self):
        self.assertIsNone(h.read_plan(QUESTION))
        plan = self.plan()
        self.assertTrue(plan['only_service'])
        self.assertTrue(plan['compact_scope'])
        self.assertEqual(plan['units'], {'a:certificate-monitor': 'capstone-cert-monitor.service'})
        self.assertEqual([r['arguments']['target'] for r in plan['requirements']],
                         ['a:certificate-monitor', 'a:certificate-monitor'])

    def test_generic_operating_objects_and_other_services_are_not_agent_tables(self):
        for question in ('B 서버 수집 서비스 현재 상태 보여줘',
                         'C 서버 백업 감시기 상태 알려줘',
                         'A 서버 처음 보는 새 서비스 연결 상태 보여줘',
                         'B 서버 probe-agent.timer 상태 확인해줘',
                         'C 서버 example.socket 상태 알려줘',
                         'B 서버 시스템 상태 보여줘',
                         'A 서버 저장소 감시 서비스 현재 상태와 마지막 실행 결과 보여줘',
                         'B 서버 메모리 감시 서비스 현재 상태 보여줘',
                         'C 서버 패키지 검증 서비스 상태 보여줘',
                         '서비스 서버의 도커 컨테이너 상태 보여줘',
                         'A 서버 a:storage-monitor 상태 알려줘'):
            with self.subTest(question=question):
                self.assertIsNone(h.read_plan(question))

    def test_host_location_alias_and_explicit_agent_identity_are_preserved(self):
        for question, name in [('서비스 서버 에이전트 ID 보여줘', 'groot-web'),
                               ('보안 서버 에이전트 연결 상태 확인', 'groot-sec'),
                               ('B 서버의 Wazuh Manager 연결 상태', 'wazuh.manager')]:
            with self.subTest(question=question):
                self.assertEqual(h.read_plan(question)['subjects'][0]['agent_name'], name)
        self.assertEqual(h.read_plan('Wazuh 에이전트 ID 004 조회')['kind'], 'agent_identity')
        plan=h.read_plan('서비스 서버 Wazuh 에이전트 프로세스 목록 조회')
        self.assertEqual(plan['kind'],'wazuh')
        self.assertIn('get_wazuh_agent_processes',plan['features'])

    def test_valid_unrelated_agent_read_cannot_replace_service_result(self):
        self.assertFalse(h.READ.identity_missing(h.read_plan('A 서버 에이전트 ID 보여줘'), [agent()]))
        self.assertIsNone(h.read_report(QUESTION, [snapshot(), agent()]))
        self.assertIsNone(h.lookup_report(QUESTION, [snapshot(), agent()]))

    def test_current_snapshot_does_not_satisfy_requested_execution_history(self):
        plan = self.plan()
        receipts = h.service_history_receipts([snapshot(), agent()])
        state = h.CONTRACT.service_history_state(plan, receipts, datetime.fromisoformat(AT))
        self.assertEqual(state['incomplete'], ['a:certificate-monitor:journal:not_read'])
        self.assertEqual(state['pending'], [plan['requirements'][1]])
        self.assertNotIn('get_wazuh_agents', str(state))

    def test_recent_default_is_catalog_bound_and_marked_as_initial_sample(self):
        request = catalog()
        request['tools'][0]['function']['parameters']['properties']['lookback_minutes']['default'] = 37
        original = copy.deepcopy(request)
        plan = self.plan(request=request)
        args = plan['requirements'][1]['arguments']
        self.assertEqual(datetime.fromisoformat(args['until_kst']) - datetime.fromisoformat(args['since_kst']),
                         timedelta(minutes=37))
        self.assertTrue(plan['initial_window'])
        self.assertEqual(plan['initial_history_window_minutes'], 37)
        self.assertIn('기본 37분', plan['scope_period_phrase'])
        self.assertEqual(request, original)

    def test_missing_invalid_or_out_of_bounds_default_is_not_invented(self):
        for value in ('absent', True, '15', 0, 241):
            request = catalog()
            prop = request['tools'][0]['function']['parameters']['properties']['lookback_minutes']
            if value == 'absent':
                prop.pop('default')
            else:
                prop['default'] = value
            for question in (QUESTION, 'A 서버 인증서 감시 서비스 마지막 실행 결과 보여줘'):
                with self.subTest(value=value, question=question):
                    self.assertIsNone(self.plan(question, request))

    def test_explicit_supported_lookback_keeps_requested_window(self):
        question = 'A 서버 인증서 감시 서비스 최근 30분 오류와 현재 상태 보여줘'
        plan = self.plan(question)
        args = next(r['arguments'] for r in plan['requirements'] if 'since_kst' in r['arguments'])
        self.assertEqual(datetime.fromisoformat(args['until_kst']) - datetime.fromisoformat(args['since_kst']),
                         timedelta(minutes=30))
        self.assertFalse(plan['initial_window'])

    def test_unsupported_qualified_or_multiple_period_never_becomes_default(self):
        for period in ('최근 2일', '최근 0분', '최근 -5분', '최근 한 시간',
                       '최근 일주일', '최근 10분쯤', '최근 10분과 지난 1시간',
                       '최근 CET', '최근 America/New_York'):
            with self.subTest(period=period):
                self.assertIsNone(self.plan('A 서버 인증서 감시 서비스 ' + period + ' 오류 보여줘'))

    def test_other_registered_services_and_unit_names_use_the_same_contract(self):
        for question, target in [
            ('B 서버 관리 서비스 현재 상태와 최근 실행 결과 보여줘', 'b:management'),
            ('A 서버 저장소 감시 서비스 현재 상태와 마지막 실행 결과 보여줘', 'a:storage-monitor'),
            ('B 서버 Docker 현재 상태와 직전 실행 기록 보여줘', 'b:docker'),
            ('C 서버 apache2.service 현재 상태와 최근 실행 결과 보여줘', 'c:apache'),
        ]:
            with self.subTest(question=question):
                plan = self.plan(question)
                self.assertEqual(set(plan['units']), {target})
                journal = next(r['arguments'] for r in plan['requirements'] if r['arguments'].get('view') == 'journal')
                self.assertEqual(journal['journal_scope'], 'all')
                self.assertTrue(plan['initial_window'])

    def test_ambiguous_host_and_unknown_target_remain_unresolved(self):
        for question in ('Vector 최근 실행 결과 보여줘',
                         'D 서버 Docker 최근 실행 결과 보여줘',
                         'A 서버 b:management 최근 실행 결과 보여줘',
                         'A 서버 invented-monitor.service 최근 실행 결과 보여줘'):
            with self.subTest(question=question):
                self.assertIsNone(self.plan(question))

    def test_requested_metadata_and_error_filter_are_not_dropped(self):
        question = 'A 서버 인증서 감시 서비스 현재 상태와 최근 실행 결과 및 오류 로그와 색인 메타데이터 보여줘'
        plan = self.plan(question)
        self.assertTrue(any('since_kst' in r['arguments'] and 'view' not in r['arguments'] for r in plan['requirements']))
        journal = next(r['arguments'] for r in plan['requirements'] if r['arguments'].get('view') == 'journal')
        self.assertNotIn('journal_scope', journal)

    def test_execution_lookup_uses_literal_facts_but_cause_and_judgment_remain_investigation(self):
        for question in (QUESTION,'A 서버 저장소 감시 서비스 현재 상태와 마지막 실행 결과를 표로 알려줘'):
            self.assertTrue(h.CONTRACT.service_lookup_scope(self.plan(question),question))
            for suffix in (' 원인도 확인해줘',' 정상인지 판단해줘',' 영향도 알려줘',' 복구해줘'):
                self.assertFalse(h.CONTRACT.service_lookup_scope(self.plan(question+suffix),question+suffix))

    def test_initial_sample_note_preserves_window_and_never_calls_observation_execution_time(self):
        context={'lookup_only':True,'history_window_origin':'initial_recent_sample_not_incident_time',
                 'initial_history_window_minutes':37}
        before=copy.deepcopy(context);note=h.CONTRACT.service_lookup_note(context)
        self.assertIn('37분',note);self.assertIn('수집 관측 시각은 실제 실행 시각과 다릅니다',note)
        self.assertIn('구간 밖',note);self.assertEqual(context,before)
        for change in ({'history_window_origin':'user_specified_period'},
                       {'initial_history_window_minutes':True},{'initial_history_window_minutes':0}):
            self.assertEqual(h.CONTRACT.service_lookup_note({**context,**change}),'')

    def test_transport_labels_use_common_normalization_without_erasing_device_or_other_actor_scope(self):
        for prefix in ('[socadmin] ','[operator.42] ','@hermes ','[socadmin] @hermes '):
            question=prefix+QUESTION
            self.assertTrue(h.CONTRACT.service_lookup_scope(self.plan(question),question))
        for prefix in ('[WAF] ','@hermes @ollama '):
            question=prefix+QUESTION
            self.assertFalse(h.CONTRACT.service_lookup_scope(self.plan(question),question))
        text='조회 결과\nMANAGEMENT_STATUS: resolved'
        context={'lookup_only':True,'history_window_origin':'initial_recent_sample_not_incident_time',
                 'initial_history_window_minutes':15}
        rendered=h.CONTRACT.service_lookup_text(text,context)
        self.assertTrue(rendered.endswith(text));self.assertTrue(rendered.startswith('기간을 지정하지 않아'))
        cause=h.CONTRACT.service_lookup_text(text,{**context,'lookup_only':False})
        self.assertTrue(cause.endswith(text))
        self.assertIn('초기 확인 범위',cause)
        self.assertIn('추가 조회의 범위',cause)


if __name__ == '__main__':
    unittest.main()
