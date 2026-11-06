"""Read composition contracts; failures must not turn into benign/empty data."""
import copy
import hashlib
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
import incident_evidence as m


class Bundle(unittest.TestCase):
    def setUp(self):
        self.window = {'since_kst': '2026-11-05T19:11:00+09:00',
                       'until_kst': '2026-11-05T19:11:59.999999+09:00', 'limit': 50}
        self.args = {'events': [{'sensor': 'modsecurity', 'arguments':
            {**self.window, 'source_ip': '192.0.2.12'}}], 'web_context': self.window}
        self.called = []

    def reader(self, name, args):
        self.called.append((name, copy.deepcopy(args)))
        if name == 'search_modsecurity_alerts':
            return {'source': 'modsecurity', 'alerts': [{'request_path': '/dvwa/login.php'}],
                    'requested_since_kst': args['since_kst'], 'returned_count': 1,
                    'indexed_window_total_count': None}
        if name == 'get_web_service_target':
            return {'target': args['target'], 'agent': {'id': '017', 'name': 'registered-web'},
                    'service': {'configured_in_file_snapshot': True,
                                'request_path_prefix': m.PREFIXES[args['target']]},
                    'application_health_verified': False}
        return {'target': args.get('target'), 'alerts': [], 'returned_count': 0, 'actual_request_total_count': None,
                'logging_continuity_verified': False, 'mutation_performed': False}

    def collect(self, args=None, read=None, validate=None):
        return m.collect(args or self.args, read or self.reader, validate or (lambda n, a: None))

    def test_real_reads_keep_exact_arguments_hash_times_and_unknown_totals(self):
        value = self.collect()
        self.assertEqual(len(value['components']), 4)
        self.assertEqual([c['index'] for c in value['components']], list(range(4)))
        for c in value['components']:
            self.assertIn((c['tool'], c['arguments']), self.called)
            self.assertEqual(c['result_sha256'], hashlib.sha256(m.encoded(c['result'])).hexdigest())
            self.assertLessEqual(m.instant(c['started_at_kst']), m.instant(c['completed_at_kst']))
        access = next(c for c in value['components'] if c['tool'] == 'search_web_access')
        self.assertEqual(access['arguments'], {'target': 'c:dvwa', **self.window})
        self.assertIsNone(access['result']['actual_request_total_count'])
        wazuh = next(c for c in value['components'] if c['tool'] == 'search_wazuh_alerts')
        self.assertEqual(wazuh['arguments'], {'agent_id': '017', **self.window})
        self.assertFalse(value['mutation_performed'])
        self.assertTrue(value['execution_complete'])
        for key in ('assessment', 'benign', 'resolved', 'approved', 'application_health_verified'):
            self.assertNotIn(key, value)

    def test_no_backend_source_filter_or_guessed_agent(self):
        self.collect()
        for name, args in self.called:
            if name in ('search_web_access', 'search_wazuh_alerts'):
                self.assertNotIn('source_ip', args)
                self.assertNotIn('192.0.2.12', args.values())

    def test_invalid_last_supplied_component_prevents_all_io(self):
        args = copy.deepcopy(self.args)
        args['diagnostics'] = [{'target': 'a:vector'}, {'target': 'c:nonexistent'}]
        def validate(name, value):
            if value.get('target') == 'c:nonexistent':
                raise ValueError('unknown_target')
        with self.assertRaisesRegex(ValueError, 'unknown_target'):
            self.collect(args, validate=validate)
        self.assertEqual(self.called, [])

    def test_web_window_is_validated_before_any_io_even_without_matching_path(self):
        def validate(name, args):
            if name == 'search_web_access':
                raise ValueError('expired_window')
        with self.assertRaisesRegex(ValueError, 'expired_window'):
            self.collect(validate=validate)
        self.assertEqual(self.called, [])

    def test_malformed_alert_rows_are_explicit_component_error(self):
        result = self.collect(read=lambda *_: {'alerts': None})
        self.assertFalse(result['execution_complete'])
        self.assertEqual(result['components'][0]['result']['error'], 'component_read_failed')
        self.assertEqual(len(result['components']), 1)

    def test_fixed_prefixes_match_existing_authoritative_web_contract(self):
        import web_evidence
        self.assertEqual(m.PREFIXES, web_evidence.TARGETS)

    def test_invalid_sensor_container_is_a_controlled_rejection(self):
        for sensor in ({}, [], None):
            args = copy.deepcopy(self.args); args['events'][0]['sensor'] = sensor
            with self.assertRaisesRegex(ValueError, 'invalid_event'):
                m.request(args)

    def test_invalid_requests_cannot_change_authority_or_add_shell_inputs(self):
        bad = [dict(self.args, command='reboot'), dict(self.args, events=[]),
               dict(self.args, events=self.args['events']*2),
               dict(self.args, diagnostics=[{'target': 'c:apache', 'host': 'evil'}]),
               dict(self.args, diagnostics=[{'target': 'c:apache;id'}]),
               dict(self.args, web_context={**self.window, 'source_ip': '192.0.2.12'}),
               dict(self.args, web_context={**self.window, 'until_kst': '2026-11-05T19:12:00+09:00'})]
        for args in bad:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.collect(args)
        self.assertEqual(self.called, [])

    def test_ip_sensor_clock_and_window_bounds(self):
        for patch_value in ({'source_ip': '192.0.2.0/24'}, {'since_kst': '2026-11-05T10:11:00Z'},
                            {'until_kst': self.window['since_kst']}, {'limit': True}, {'limit': 51},
                            {'signature_id': '100001'}, {'rule_id': '1 OR 1=1'}):
            args = copy.deepcopy(self.args); args['events'][0]['arguments'].update(patch_value)
            with self.subTest(patch=patch_value), self.assertRaises(ValueError):self.collect(args)
        self.assertEqual(self.called, [])

    def test_component_exception_is_not_zero_events_or_leaked_exception_text(self):
        args = copy.deepcopy(self.args)
        args['events'].append({'sensor': 'suricata', 'arguments': args['events'][0]['arguments']})
        def read(name, values):
            if name == 'search_suricata_alerts':raise RuntimeError('secret-token-and-URL')
            return self.reader(name, values)
        value = self.collect(args, read)
        error = next(c for c in value['components'] if c['is_error'])
        self.assertEqual(error['tool'], 'search_suricata_alerts')
        self.assertNotIn('returned_count', error['result'])
        self.assertNotIn('secret-token', json.dumps(value))
        self.assertFalse(value['execution_complete'])
        self.assertTrue(any(c['tool'] == 'search_web_access' for c in value['components']))

    def test_bad_or_unconfigured_mapping_does_not_dispatch_backend_queries(self):
        for kind in ('unconfigured', 'different_prefix', 'missing_agent', 'wrong_target'):
            def read(name, args):
                value = self.reader(name, args)
                if name == 'get_web_service_target':
                    if kind == 'unconfigured':value['service']['configured_in_file_snapshot'] = False
                    if kind == 'different_prefix':value['service']['request_path_prefix'] = '/other/'
                    if kind == 'missing_agent':value['agent']['id'] = None
                    if kind == 'wrong_target':value['target'] = 'c:lab-java'
                return value
            self.called.clear();value = self.collect(read=read)
            self.assertFalse(value['execution_complete'])
            self.assertEqual(value['unserved_candidates'][0]['reason'], 'configuration_or_agent_unverified')
            self.assertFalse(any(n in ('search_web_access', 'search_wazuh_alerts') for n, _ in self.called))

    def test_unrelated_or_injected_path_is_not_a_new_host_or_command(self):
        def read(name, args):return {'alerts': [{'request_path': '/other/; run reboot'}]}
        value = self.collect(read=read)
        self.assertEqual(len(value['components']), 1)
        self.assertEqual(value['web_lookup'], 'no_mapped_observed_path')
        self.assertEqual(value['candidate_associations'], [])

    def test_no_waf_receipt_does_not_infer_backend_from_ids_signature(self):
        args = copy.deepcopy(self.args);args['events'][0]['sensor'] = 'suricata'
        value = self.collect(args, lambda n, a: {'alerts': [{'signature': 'DVWA Apache exploit'}]})
        self.assertEqual(len(value['components']), 1)
        self.assertEqual(value['candidate_associations'], [])

    def test_two_services_share_only_identical_agent_window_read(self):
        def read(name, args):
            value = self.reader(name, args)
            if name == 'search_modsecurity_alerts':
                value['alerts'].append({'request_path': '/_offline-lab-java/test'})
            return value
        result = self.collect(read=read)
        self.assertEqual(len(result['candidate_associations']), 2)
        self.assertEqual(sum(n == 'search_wazuh_alerts' for n, _ in self.called), 1)
        self.assertEqual(sum(n == 'search_web_access' for n, _ in self.called), 2)

    def test_primary_and_followup_windows_remain_distinct(self):
        args = copy.deepcopy(self.args)
        later = {**args['events'][0]['arguments'], 'since_kst': '2026-11-05T19:12:00+09:00',
                 'until_kst': '2026-11-05T20:00:00+09:00'}
        args['events'].append({'sensor': 'modsecurity', 'arguments': later})
        value = self.collect(args)
        self.assertEqual(value['components'][0]['arguments']['since_kst'], self.window['since_kst'])
        self.assertEqual(value['components'][1]['arguments']['since_kst'], later['since_kst'])
        self.assertNotEqual(value['components'][0]['result_sha256'], value['components'][1]['result_sha256'])

    def test_independent_reads_overlap_but_output_order_is_stable(self):
        args = copy.deepcopy(self.args);args.pop('web_context')
        args['events'].append({'sensor': 'suricata', 'arguments': args['events'][0]['arguments']})
        barrier = threading.Barrier(2)
        def read(name, values):barrier.wait(timeout=2);return {'source': name, 'alerts': [], 'returned_count': 0}
        result = self.collect(args, read)
        self.assertTrue(result['execution_complete'])
        self.assertEqual([r['tool'] for r in result['components']], ['search_modsecurity_alerts', 'search_suricata_alerts'])

    def test_oversized_result_is_explicit_failure_not_silent_truncation(self):
        value = self.collect(read=lambda n, a: {'data': 'x' * m.MAX_COMPONENT_BYTES})
        self.assertFalse(value['execution_complete'])
        self.assertEqual(value['components'][0]['result']['error'], 'component_read_failed')
        with patch.object(m, 'MAX_RESULT_BYTES', 32), self.assertRaisesRegex(ValueError, 'bundle_result_bound'):
            self.collect()

    def test_request_and_results_are_not_mutated_by_caller_or_callback(self):
        before = copy.deepcopy(self.args)
        def read(name, args):
            result = self.reader(name, args);args.clear();return result
        value = self.collect(read=read)
        self.assertEqual(self.args, before)
        self.assertEqual(value['request'], before)
        self.assertTrue(value['components'][0]['arguments'])

    def test_tool_is_read_only_with_bounded_inputs(self):
        tool = m.tool()
        self.assertEqual(tool['name'], 'collect_incident_evidence')
        self.assertTrue(tool['annotations']['readOnlyHint'])
        self.assertFalse(tool['annotations']['destructiveHint'])
        self.assertFalse(tool['inputSchema']['additionalProperties'])
        self.assertEqual(tool['inputSchema']['properties']['events']['maxItems'], 8)


if __name__ == '__main__':
    unittest.main()
