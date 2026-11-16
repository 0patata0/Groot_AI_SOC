"""Whole-device omissions, mixed policy and approval-scope counterexamples."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest

p = Path(__file__).parents[1] / 'management_policy.py'
s = importlib.util.spec_from_file_location('test_global_management_contract', p)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 17, 8, 0, tzinfo=timezone(timedelta(hours=9)))
        self.before = {'schema': 1, 'revision': 1, 'administrator_cidrs': ['192.168.16.231/32'],
                       'audit': 'retain', 'public_inspection': 'enforce'}
        self.desired = ['192.0.2.21/32']
        self.after = m.next_registry(self.before, self.desired)

    def receipts(self, mode='prepared'):
        return [{'schema': 1, 'target': target, 'host': host, 'effect': effect,
                 'policy_sha256': m.digest(self.after), 'observed_at_kst': self.now.isoformat(),
                 'base_policy_sha256': m.digest(self.before), 'candidate_source_sha256': 'd'*64,
                 'status': mode, 'source_sha256': ('d' if mode == 'verified' else 'a')*64, 'adapter_sha256': 'b'*64,
                 'evidence_sha256': m.digest({'target': target, 'mode': mode}),
                 'checks': {k: True for k in m.CHECKS}, 'runtime_verified': mode == 'verified',
                 'source_transport': 'ipv4',
                 'effective_source_cidrs': ['10.200.10.1/32'] if host != 'a' else self.desired,
                 'source_mapping_sha256': 'c'*64} for target, (host, effect) in m.SURFACES.items()]

    def make(self, rows=None):
        return m.prepare(self.before, self.desired, self.receipts() if rows is None else rows,
                         now=self.now)

    def readback(self, plan, rows):
        return m.verify(plan, rows, now=self.now, expected_plan_sha256=m.digest(plan))

    def test_complete_candidate_has_no_operating_or_approval_side_effect(self):
        result = self.make()
        self.assertEqual(result['status'], 'ready_for_exact_approval')
        self.assertFalse(result['operating_change_performed'])
        self.assertFalse(result['approval_record_created'])
        self.assertEqual(result['plan_sha256'], m.digest(result['plan']))

    def test_required_coverage_includes_security_engines_and_all_host_routes(self):
        self.assertEqual(set(m.SURFACES), {
            'a:fw-access', 'a:fw-protection', 'a:waf-management', 'a:suricata-management',
            'b:wazuh-response', 'b:wazuh-management', 'b:wazuh-events', 'a:host-ssh',
            'b:host-ssh', 'c:host-ssh', 'a:mcp-route', 'b:mcp-route', 'c:mcp-route',
            'c:lab-management'})

    def test_every_single_missing_surface_blocks_whole_proposal(self):
        for target in m.SURFACES:
            with self.subTest(target=target), self.assertRaisesRegex(m.PolicyError, 'global_candidate_incomplete'):
                self.make([r for r in self.receipts() if r['target'] != target])

    def test_one_device_cannot_be_reported_as_global_success(self):
        result = m.coverage(self.receipts('verified')[:2], expected_policy_sha256=m.digest(self.after),
                            now=self.now, mode='verified')
        self.assertFalse(result['complete'])
        self.assertEqual(result['satisfied'], 2)
        self.assertEqual(result['required'], 14)

    def test_duplicate_target_cannot_replace_missing_device(self):
        rows = self.receipts(); rows[-1] = deepcopy(rows[0])
        with self.assertRaisesRegex(m.PolicyError, 'receipt_target'):
            self.make(rows)

    def test_unknown_target_or_wrong_host_or_effect_refused(self):
        for key, value in [('target', 'd:arbitrary'), ('host', 'c'), ('effect', 'allow_all_attacks')]:
            rows = self.receipts(); rows[0][key] = value
            with self.subTest(key=key), self.assertRaises(m.PolicyError):
                self.make(rows)

    def test_failed_unavailable_and_not_applicable_are_not_success(self):
        for status in ('failed', 'unavailable', 'not_applicable'):
            rows = self.receipts(); rows[0]['status'] = status
            with self.subTest(status=status), self.assertRaisesRegex(m.PolicyError, 'global_candidate_incomplete'):
                self.make(rows)

    def test_each_failed_safety_check_blocks_whole_proposal(self):
        for check in m.CHECKS:
            rows = self.receipts(); rows[0]['checks'][check] = False
            with self.subTest(check=check), self.assertRaisesRegex(m.PolicyError, 'global_candidate_incomplete'):
                self.make(rows)

    def test_mixed_policy_refused_even_all_device_statuses_are_prepared(self):
        rows = self.receipts(); rows[3]['policy_sha256'] = m.digest(self.before)
        with self.assertRaisesRegex(m.PolicyError, 'global_candidate_incomplete'):
            self.make(rows)

    def test_stale_future_or_utc_receipts_refused(self):
        for stamp in ((self.now-timedelta(seconds=61)).isoformat(),
                      (self.now+timedelta(seconds=3)).isoformat(),
                      self.now.astimezone(timezone.utc).isoformat()):
            rows = self.receipts(); rows[0]['observed_at_kst'] = stamp
            with self.subTest(stamp=stamp), self.assertRaises(m.PolicyError):
                self.make(rows)

    def test_widely_spaced_preparation_not_a_single_current_snapshot(self):
        rows = self.receipts(); rows[0]['observed_at_kst'] = (self.now-timedelta(seconds=20)).isoformat()
        with self.assertRaisesRegex(m.PolicyError, 'receipt_span'):
            self.make(rows)

    def test_exact_proposal_binds_source_adapter_route_and_candidate(self):
        before = self.make()['plan_sha256']
        for field in ('source_sha256', 'candidate_source_sha256', 'adapter_sha256', 'source_mapping_sha256', 'evidence_sha256'):
            rows = self.receipts(); rows[0][field] = 'e'*64
            with self.subTest(field=field):
                self.assertNotEqual(self.make(rows)['plan_sha256'], before)

    def test_input_order_does_not_create_a_different_approval(self):
        self.assertEqual(self.make()['plan_sha256'], self.make(list(reversed(self.receipts())))['plan_sha256'])

    def test_complete_readback_requires_actual_runtime_verification(self):
        plan = self.make()['plan']; rows = self.receipts('verified')
        result = self.readback(plan, rows)
        self.assertTrue(result['complete'])
        self.assertFalse(result['mutation_performed'])
        rows[3]['runtime_verified'] = False
        self.assertFalse(self.readback(plan, rows)['complete'])

    def test_every_missing_readback_is_incomplete(self):
        plan = self.make()['plan']
        for target in m.SURFACES:
            with self.subTest(target=target):
                rows = [r for r in self.receipts('verified') if r['target'] != target]
                self.assertFalse(self.readback(plan, rows)['complete'])

    def test_mixed_revision_readback_is_incomplete(self):
        plan = self.make()['plan']; rows = self.receipts('verified'); rows[2]['policy_sha256'] = m.digest(self.before)
        self.assertEqual(self.readback(plan, rows)['status'], 'incomplete')

    def test_changed_route_adapter_or_effective_sources_fail_readback(self):
        plan = self.make()['plan']
        for field, value in [('adapter_sha256', 'd'*64), ('source_mapping_sha256', 'e'*64),
                             ('effective_source_cidrs', ['192.0.2.55/32'])]:
            rows = self.receipts('verified'); rows[0][field] = value
            with self.subTest(field=field):
                result = self.readback(plan, rows)
                self.assertFalse(result['complete'])
                self.assertIn('adapter_or_route_changed', result['surfaces'][0]['reasons'])

    def test_noop_is_not_a_new_policy_change(self):
        with self.assertRaisesRegex(m.PolicyError, 'unchanged'):
            m.next_registry(self.before, ['192.168.16.231'])

    def test_model_cannot_add_audit_or_inspection_bypass(self):
        for key, value in [('audit', 'discard'), ('public_inspection', 'bypass')]:
            before = {**self.before, key: value}
            with self.subTest(key=key), self.assertRaisesRegex(m.PolicyError, 'protection_boundary'):
                m.next_registry(before, self.desired)

    def test_unknown_registry_field_cannot_change_infrastructure_or_permissions(self):
        for key in ('sudo', 'mcp_sources', 'shell', 'infrastructure_cidrs'):
            with self.subTest(key=key), self.assertRaisesRegex(m.PolicyError, 'registry_fields'):
                m.registry({**self.before, key: True})

    def test_noncanonical_or_broad_forbidden_and_ipv6_inputs_refused(self):
        for value in ['192.0.2.21/24', '0.0.0.0/0', '127.0.0.1', '169.254.1.2',
                      '224.0.0.1', '255.255.255.255', '::1', 'localhost', '192.0.2.1\n']:
            with self.subTest(value=value), self.assertRaises(m.PolicyError):
                m.next_registry(self.before, [value])

    def test_empty_addresses_cannot_remove_last_manager(self):
        with self.assertRaises(m.PolicyError):
            m.next_registry(self.before, [])

    def test_registry_version_rejects_bool_and_unrepresentable_next_version(self):
        for key, value in [('schema', True), ('revision', True), ('revision', 2**53-1)]:
            with self.subTest(key=key), self.assertRaises(m.PolicyError):
                m.next_registry({**self.before, key: value}, self.desired)

    def test_canonical_normalization_is_stable_without_expanding_host_bits(self):
        self.assertEqual(m.addresses(['192.0.2.22', '192.0.2.21/32', '192.0.2.22/32']),
                         ['192.0.2.21/32', '192.0.2.22/32'])

    def test_old_installed_config_cannot_claim_the_new_policy_loaded(self):
        plan = self.make()['plan']; rows = self.receipts('verified'); rows[0]['source_sha256'] = 'a'*64
        result = self.readback(plan, rows)
        self.assertFalse(result['complete'])
        self.assertIn('installed_candidate_or_base_changed', result['surfaces'][0]['reasons'])

    def test_one_device_with_different_base_registry_blocks_proposal(self):
        rows = self.receipts(); rows[0]['base_policy_sha256'] = 'f'*64
        with self.assertRaisesRegex(m.PolicyError, 'prepared_base_policy_changed'):
            self.make(rows)

    def test_changed_approved_plan_refused_before_readback(self):
        result = self.make(); plan = deepcopy(result['plan']); plan['prepared'][0]['source_sha256'] = 'f'*64
        with self.assertRaisesRegex(m.PolicyError, 'approved_plan_changed'):
            m.verify(plan, self.receipts('verified'), now=self.now,
                     expected_plan_sha256=result['plan_sha256'])

    def test_forged_hash_with_incomplete_preparation_is_still_invalid(self):
        plan = self.make()['plan']; plan['prepared'] = plan['prepared'][:-1]
        with self.assertRaisesRegex(m.PolicyError, 'prepared_targets'):
            self.readback(plan, self.receipts('verified'))

    def test_unavailable_device_can_report_unknowns_without_fabricating_hashes(self):
        rows = self.receipts('verified'); row = rows[0]; row['status'] = 'unavailable'
        for field in ('policy_sha256', 'base_policy_sha256', 'source_sha256', 'candidate_source_sha256',
                      'adapter_sha256', 'evidence_sha256', 'source_mapping_sha256'):
            row[field] = None
        row['effective_source_cidrs'] = []; row['runtime_verified'] = False
        row['checks'] = {k: False for k in m.CHECKS}
        result = self.readback(self.make()['plan'], rows)
        self.assertEqual(result['satisfied'], 13)
        self.assertFalse(result['complete'])

    def test_successful_device_cannot_report_unknown_configuration_hash(self):
        rows = self.receipts(); rows[0]['source_sha256'] = None
        with self.assertRaisesRegex(m.PolicyError, 'receipt_hash'):
            self.make(rows)

    def test_readback_cannot_mix_widely_spaced_observations(self):
        rows = self.receipts('verified'); rows[0]['observed_at_kst'] = (self.now-timedelta(seconds=20)).isoformat()
        result = self.readback(self.make()['plan'], rows)
        self.assertFalse(result['complete'])
        self.assertEqual(result['satisfied'], 0)

    def test_local_mcp_transport_does_not_need_a_fake_network_source(self):
        before = self.receipts(); after = self.receipts('verified')
        for rows in (before, after):
            row = next(r for r in rows if r['target'] == 'b:mcp-route')
            row['source_transport'] = 'stdio'; row['effective_source_cidrs'] = []
        self.assertTrue(self.readback(self.make(before)['plan'], after)['complete'])

    def test_non_mcp_access_cannot_claim_local_transport_to_skip_ip_mapping(self):
        rows = self.receipts(); rows[0]['source_transport'] = 'stdio'; rows[0]['effective_source_cidrs'] = []
        with self.assertRaisesRegex(m.PolicyError, 'local_route_identity'):
            self.make(rows)

    def test_root_mapped_loopback_does_not_grant_an_administrator_loopback_range(self):
        rows = self.receipts(); row = next(r for r in rows if r['target'] == 'b:mcp-route')
        row['effective_source_cidrs'] = ['127.0.0.1/32']
        self.assertEqual(self.make(rows)['status'], 'ready_for_exact_approval')
        with self.assertRaises(m.PolicyError):
            m.next_registry(self.before, ['127.0.0.1/32'])


if __name__ == '__main__':
    unittest.main()
