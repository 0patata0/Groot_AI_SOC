"""Deployed model and explicit host scope reach the existing native contracts.

No model, MCP, chat, OS command, or protected operation is executed here.
"""
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import inspect
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import alignment
from test_completion import PLUGIN, Harness

H = alignment.load_harness()
MODELS = ('qwen3.6:35b', 'soc-qwen36:35b-balanced-q4km-20261108')
EVENT = 'mcp__security_events__search_suricata_alerts'
DIAGNOSTICS = 'mcp__system_diagnostics__get_system_diagnostics'
NOW = datetime.fromisoformat('2026-11-17T21:45:00+09:00')


class Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


@dataclass
class Request:
    api_kwargs: object
    api_messages: object = None
    _original_api_kwargs: object = None


def tool(name, schema):
    return {'type': 'function', 'function': {
        'name': name, 'description': 'fixture', 'parameters': schema}}


def receipt(name, arguments, value):
    server, operation = name[5:].split('__', 1)
    raw = json.dumps(value)
    return {'server': server.replace('_', '-'), 'name': operation,
            'arguments': arguments, 'result': raw, 'is_error': False,
            'is_write': False, 'result_sha256': hashlib.sha256(raw.encode()).hexdigest()}


def event_receipt(source='modsecurity', minutes=60):
    return receipt('mcp__security_events__search_'+source+'_alerts',
                   {'lookback_minutes': minutes, 'limit': 2}, {
        'source': source, 'window_mode': 'lookback', 'applied_filters': {},
        'requested_since_kst': (NOW-timedelta(minutes=minutes)).isoformat(),
        'requested_until_kst': NOW.isoformat(), 'returned_count': 0,
        'indexed_window_total_count': None, 'limit': 2, 'scan_capped': False,
        'alerts': []})


class TrainedChatAlignment(unittest.TestCase):
    def setUp(self):
        clock = patch.object(H, 'datetime', Clock)
        clock.start()
        self.addCleanup(clock.stop)

    def request(self, model, question, tools, calls=()):
        rows = [{'role': 'system', 'content': 'native'},
                {'role': 'user', 'content': question}, *H.linked_rows(calls)]
        original = {'model': model, 'messages': rows, 'tools': tools}
        agent = SimpleNamespace(platform='mattermost', model=model, provider='custom',
                                max_iterations=12, _current_turn_id='turn')
        wrapped = alignment.request_wrapper(
            lambda *args, **kw: Request(copy.deepcopy(original)), PLUGIN, H)
        value = wrapped(agent, original_user_message=question,
                        turn_id='turn', messages=rows)
        self.assertEqual(original, {'model': model, 'messages': rows, 'tools': tools})
        self.assertEqual(rows[1]['content'], question)
        return agent, value

    def test_exact_shared_model_identity_applies_to_all_adapter_phases(self):
        # Both installed API signatures are accepted only to reproduce the old
        # snapshot; the assertions concern the operator identity, not arity.
        def enabled(agent):
            args = (agent, H.EVIDENCE) if 'evidence' in inspect.signature(alignment.enabled).parameters else (agent,)
            return alignment.enabled(*args)
        for model in MODELS:
            agent = SimpleNamespace(platform='mattermost', model=model, provider='custom')
            self.assertTrue(enabled(agent), model)
            for field, value in (('model', model+'-copy'), ('model', 'unknown'),
                                 ('provider', 'other'), ('platform', 'cli'),
                                 ('api_mode', 'responses')):
                changed = copy.copy(agent)
                setattr(changed, field, value)
                self.assertFalse(enabled(changed), (field, value))

    def test_both_models_receive_the_same_bounded_relative_read_selection(self):
        tools = [tool(EVENT, {'type': 'object', 'properties': {
            'lookback_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 1440},
            'since_kst': {'type': 'string'}, 'until_kst': {'type': 'string'},
            'limit': {'type': 'integer', 'minimum': 1, 'maximum': 50}},
            'required': [], 'additionalProperties': False}),
            tool('mcp__system_diagnostics__calculate_time', {'type': 'object'}),
            tool('mcp__resp__unblock_ip', {'type': 'object'})]
        schemas = []
        for model in MODELS:
            agent, value = self.request(model,
                '[socadmin] @hermes 최근 30분 IDS 경보 2건만 보여줘', tools)
            self.assertNotIn('tools', value.api_kwargs)
            schema = value.api_kwargs['response_format']['json_schema']['schema']
            schemas.append(schema)
            self.assertNotIn('calculate_time', json.dumps(schema))
            self.assertNotIn('unblock_ip', json.dumps(schema))
            args = schema['properties']['calls']['items']['anyOf'][0]['properties']['arguments']
            self.assertEqual(args['properties']['lookback_minutes']['enum'], [30])
            self.assertEqual(args['properties']['limit']['enum'], [2])
            self.assertNotIn('since_kst', args['properties'])
            self.assertNotIn('until_kst', args['properties'])
            self.assertIsNotNone(agent._capstone_read_selection)
        self.assertEqual(*schemas)

    def test_current_b_host_is_the_only_diagnostic_schema_target_for_both_models(self):
        tools = [tool(DIAGNOSTICS, {'type': 'object', 'properties': {
            'target': {'type': 'string', 'enum': ['a:systemd', 'b:systemd', 'c:systemd']},
            'since_kst': {'type': 'string'}, 'until_kst': {'type': 'string'}},
            'required': ['target'], 'additionalProperties': False})]
        for model in MODELS:
            _, value = self.request(model, 'B systemd 상태 보여줘', tools)
            schema = value.api_kwargs['response_format']['json_schema']['schema']
            args = schema['properties']['calls']['items']['anyOf'][0]['properties']['arguments']
            self.assertEqual(args['properties']['target']['enum'], ['b:systemd'])
            self.assertNotIn('since_kst', args['properties'])

    def test_completed_empty_event_read_uses_evidence_table_without_another_model(self):
        for model in MODELS:
            agent, _ = self.request(model, '최근 WAF 차단 경보 2건만 보여줘',
                                     [], [event_receipt()])
            report = agent._capstone_query_completion_local_format[1]
            self.assertIn('| 조회 시작(KST) | 조회 종료(KST) |', report)
            self.assertIn('반환 표본 0건', report)
            self.assertIn('전체 경보·공격 부재의 증거가 아님', report)

    def test_native_systemd_final_never_calls_returned_failed_units_running_units(self):
        data = {'schema': 1, 'kind': 'runtime', 'status': 'ok', 'target': 'b:systemd',
                'host': 'b', 'codes': [], 'mutation_performed': False,
                'observed_at': int(NOW.timestamp()), 'observed_at_kst': NOW.isoformat(),
                'expires_at': int(NOW.timestamp())+120, 'age_seconds': 0,
                'metrics': {'failed_units_total': 0, 'returned_units': 0,
                            'unit_list_truncated': False},
                'limits': ['loaded_failed_units_only', 'not_a_historical_journal_query',
                           'zero_failed_units_is_not_all_services_healthy'],
                'lookback_scope': 'latest_snapshot_only_not_requested_history'}
        call = receipt(DIAGNOSTICS, {'target': 'b:systemd'}, data)
        for model in MODELS:
            harness = Harness(request='B systemd 상태 보여줘', text='실행 단위 수 0')
            harness.agent.model, harness.agent.provider = model, 'custom'
            harness.agent._capstone_alignment_diagnostic_targets = ['a:systemd', 'b:systemd', 'c:systemd']
            harness.kw['messages'] += H.linked_rows([call])
            harness.wrapper = alignment.final_wrapper(harness.wrapper, harness.original,
                harness.native, harness.append, harness.reanchor, PLUGIN, H)
            harness.call()
            report = harness.original_calls[-1].content
            self.assertIn('현재 로드된 failed unit 0개', report)
            self.assertNotIn('실행 단위 수', report)
            self.assertNotIn('a:systemd', report)
            self.assertNotIn('c:systemd', report)
            self.assertIn('failed 0개가 모든 서비스 정상을 뜻하지 않습니다', report)

    def test_trained_model_keeps_native_proposal_preflight_without_context(self):
        agent = SimpleNamespace(platform='mattermost', model=MODELS[1], provider='custom',
                                _current_turn_id='turn')
        arguments = {'target': 'a:modsecurity-custom'}
        ref = SimpleNamespace(name='mcp__rule_write_a__propose_rule_edit', call_id='fixture')
        wrapped = alignment.proposal_input_wrapper(lambda *args: (None, arguments), H, PLUGIN.VERSION)
        block, returned = wrapped(agent, ref)
        self.assertEqual(json.loads(block)['error'], 'proposal_preflight_context_unavailable')
        self.assertEqual(returned, arguments)


class ExplicitHostScope(unittest.TestCase):
    def test_diagnostic_host_forms_and_logical_targets_do_not_expand(self):
        for host in 'abc':
            for prefix in (host.upper(), host.upper()+' 서버', host.upper()+' 호스트',
                           'Groot_'+host.upper()):
                for subject, target in (('systemd', 'systemd'), ('Vector', 'vector'),
                                        ('Docker', 'docker')):
                    question = prefix+' '+subject+' 상태 보여줘'
                    self.assertEqual(H.diagnostic_request(question)['requested'], [host+':'+target], question)
            for target in ('systemd', 'management', 'vector'):
                question = host+':'+target+' 상태 보여줘'
                self.assertEqual(H.diagnostic_request(question)['requested'], [host+':'+target], question)

    def test_same_host_is_retained_for_inventory_details_and_followup(self):
        for host in 'abc':
            for subject in ('디스크', '메모리', '네트워크', '실행 중인 서비스',
                            '도커 컨테이너 자원', 'hermes 컨테이너 상태',
                            'ssh.service 상태'):
                question = host.upper()+' '+subject+' 보여줘'
                requests = H.host_inventory_request(question)
                self.assertTrue(requests, question)
                self.assertEqual({r['host'] for r in requests}, {host}, question)
                self.assertNotIn('B', [r.get('container') for r in requests])
            prior = host.upper()+' ssh.service 상태 보여줘'
            resolved = H.resolve_short_read('로그 보여줘', [prior])
            self.assertIn(host.upper()+' 서버', resolved)
            self.assertIn('ssh.service', resolved)
        self.assertEqual(H.host_inventory_request('b:hermes 컨테이너 상태 보여줘')[0]['container'], 'hermes')

    def test_negated_hosts_and_targets_are_not_reintroduced(self):
        for question in ('B 말고 A systemd 상태 보여줘',
                         'b:systemd 말고 a:systemd 상태 보여줘',
                         'B 서버는 제외하고 A Vector 상태 보여줘'):
            targets = H.diagnostic_request(question)['requested']
            self.assertTrue(targets)
            self.assertTrue(all(t.startswith('a:') for t in targets), question)

    def test_host_tokens_do_not_rewrite_urls_paths_units_or_lowercase_articles(self):
        for value in ('https://example.test/b:systemd', '/tmp/B/file',
                      'a systemd', 'b:systemd.service', 'abc:systemd', 'myB systemd'):
            self.assertEqual(H.READ.host_mentions(value), [], value)


if __name__ == '__main__':
    unittest.main()
