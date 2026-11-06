"""Actual MCP/runtime time contracts also survive both model schema adapters."""
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import soc_management_run as gate
from test_soc_management_selection import agent, request

ROOT = Path(__file__).parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


server = load('_time_contract_mcp', 'infra/mcp/security-events-mcp.py')
web = load('_time_contract_web', 'infra/mcp/web_evidence.py')
sdk = load('_time_contract_sdk', 'infra/ollama-trial/harness.py')
NAMES = ('search_suricata_alerts', 'search_modsecurity_alerts',
         'search_wazuh_alerts', 'search_web_access')
TIMES = {'since_kst': '2026-11-06T00:00:00+09:00',
         'until_kst': '2026-11-06T01:00:00+09:00', 'lookback_minutes': 60}


@unittest.skipUnless(importlib.util.find_spec('jsonschema'), 'server jsonschema required')
class EventTimeContract(unittest.TestCase):
    def setUp(self):
        from jsonschema import Draft202012Validator
        self.validator = Draft202012Validator
        self.schemas = {t['name']: t['inputSchema'] for t in server.TOOLS if t['name'] in NAMES}

    def test_32_clock_combinations_match_runtime_and_both_model_adapters(self):
        for name, schema in self.schemas.items():
            alias = 'mcp__security_events__' + name
            projected = gate.chat_read_schema(alias, schema)
            sdk_schema = sdk.selection_schema({alias: schema}, 4)
            self.validator.check_schema(projected)
            self.assertIn('anyOf', projected)
            for bits in itertools.product((False, True), repeat=3):
                args = {k: TIMES[k] for k, bit in zip(TIMES, bits) if bit}
                if name == 'search_web_access':
                    args['target'] = 'c:dvwa'
                expected = not ('since_kst' in args and
                                ('until_kst' not in args or 'lookback_minutes' in args))
                with self.subTest(name=name, args=args):
                    for candidate in (schema, projected):
                        self.assertEqual(self.validator(candidate).is_valid(args), expected)
                    self.assertEqual(self.validator(sdk_schema).is_valid(
                        {'calls': [{'tool': alias, 'arguments': args}]}), expected)
                    try:
                        if name == 'search_web_access':
                            web.request({'operation': name, 'arguments': args},
                                        server.datetime(2026, 11, 6, 12, tzinfo=server.KST))
                        else:
                            server.validate_args(name.split('_')[1], args)
                        accepted = True
                    except ValueError:
                        accepted = False
                    self.assertEqual(accepted, expected)

    def test_projection_preserves_required_target_filters_types_and_source_schema(self):
        for name, schema in self.schemas.items():
            before = copy.deepcopy(schema)
            alias = 'mcp__security_events__' + name
            projected = gate.chat_read_schema(alias, schema)
            valid = {'since_kst': '2026-11-05T23:59:45.500000+09:00',
                     'until_kst': '2026-11-06T00:00:00.500000+09:00',
                     'source_ip': '192.0.2.1', 'limit': 10}
            if name == 'search_web_access':
                valid['target'] = 'c:dvwa'
            self.assertTrue(self.validator(projected).is_valid(valid))
            for changes in ({'limit': 0}, {'lookback_minutes': True}, {'extra': 'ignored?'},
                            {'until_kst': '2026-11-06T00:00:00Z'}, {'since_kst': True}):
                args = dict(valid, **changes)
                self.assertFalse(self.validator(projected).is_valid(args))
            if name == 'search_web_access':
                valid.pop('target')
                self.assertFalse(self.validator(projected).is_valid(valid))
            self.assertEqual(schema, before)

    def test_unknown_conditions_are_not_silently_removed(self):
        alias = 'mcp__security_events__search_wazuh_alerts'
        schema = copy.deepcopy(self.schemas['search_wazuh_alerts'])
        schema['allOf'].append({'required': ['agent_id']})
        self.assertIs(gate.chat_read_schema(alias, schema), schema)
        self.assertIs(gate.chat_read_schema('unknown_tool', schema), schema)

    def test_native_selector_projects_grammar_but_keeps_original_validation_catalog(self):
        name = 'mcp__security_events__search_wazuh_alerts'
        schema = self.schemas['search_wazuh_alerts']
        a = agent(); a.valid_tool_names = {name}
        r = request(); r['tools'] = [{'type': 'function', 'function': {'name': name, 'parameters': schema}}]
        env = {'CAPSTONE_MANAGEMENT_MODE': 'verify', 'CAPSTONE_CHAT_READ_JSON': json.dumps({
            'request': '오늘 경보 조회', 'background': '', 'tools': [name],
            'requested_at_kst': '2026-11-06T12:00:00+09:00'})}
        with patch.dict(gate.os.environ, env, clear=True):
            out = gate.management_read_request(r, a, pending=True)
        lease = a._capstone_management_selection
        self.assertEqual(lease['catalog'][name], schema)
        selected = out['response_format']['json_schema']['schema']
        for args, valid in ((dict(TIMES), False),
                            ({k: TIMES[k] for k in ('since_kst', 'until_kst')}, True)):
            payload = {'request_nonce': lease['nonce'], 'calls': [{'tool': name, 'arguments': args}]}
            self.assertEqual(self.validator(selected).is_valid(payload), valid)

    def test_invalid_clocks_rejected_before_indexer_io(self):
        for name in NAMES[:3]:
            with patch.object(server, 'indexer_search') as read:
                for args in ({'since_kst': TIMES['since_kst']}, dict(TIMES),
                             {'since_kst': TIMES['since_kst'], 'lookback_minutes': 10}):
                    self.assertTrue(server.call_tool(name, args)['isError'])
                read.assert_not_called()

    def test_calendar_duration_and_retention_remain_execution_checks(self):
        name = 'search_wazuh_alerts'
        schema = gate.chat_read_schema('mcp__security_events__' + name, self.schemas[name])
        for start, end in (('2026-11-06T01:00:00+09:00', '2026-11-06T00:00:00+09:00'),
                           ('2026-11-05T00:00:00+09:00', '2026-11-06T00:00:01+09:00'),
                           ('2026-02-30T00:00:00+09:00', '2026-02-30T01:00:00+09:00')):
            args = {'since_kst': start, 'until_kst': end}
            self.assertTrue(self.validator(schema).is_valid(args))
            with self.assertRaises(ValueError):
                server.validate_args('wazuh', args)
        args = server.validate_args('wazuh', {'until_kst': '2026-11-07T00:00:00+09:00'})
        with self.assertRaises(ValueError):
            server.build_query('wazuh', args, server.datetime(2026, 11, 6, tzinfo=server.KST))


if __name__ == '__main__':
    unittest.main()
