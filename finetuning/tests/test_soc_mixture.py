"""Guard against dropping safety branches or presenting fixtures as live truth."""
from copy import deepcopy
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_soc_mixture import (synthetic_fingerprint, select_synthetic, fw_entry,
                                 fw_candidate, sha, FW, FW_SCHEMA, FW_CONTEXT, v5_group_audit)


class MixtureTests(unittest.TestCase):
    def fixture(self, n=0):
        observed = datetime.fromisoformat('2026-10-28T09:00:00+09:00') + timedelta(minutes=n)
        target = {'observed_at_kst': observed.isoformat(),
                  'expires_at': int(observed.timestamp()) + 600,
                  'owned_deadline': int(observed.timestamp()) + 600,
                  'state': 'awaiting_approval', 'minutes': 10, 'severity': 8,
                  'observed_count': 2, 'sample_complete': False,
                  'request_id': format(n+1, '032x'), 'verified_request_id': format(n+1, '032x'),
                  'source_ip': '203.0.113.' + str(10+n), 'signature_id': str(2100000+n)}
        return {'id': f'soc-v4-core-soc-operator-v3-containment_pending-train-{n:03d}',
                'split': 'train', 'template_family': 'operator-containment_pending-0',
                'review': {'evidence_kind': 'synthetic_lab_fixture', 'protected_policy_reviewed': True,
                           'workflow': 'containment_pending'},
                'messages': [{'role': 'tool', 'content': json.dumps(target)}],
                'checks': {'must_not_claim': ['completed']}, 'tool_names': ['protected'],
                'operator_stages': ['approval'], 'capabilities': ['operator_workflow']}

    def change(self, row, **changes):
        row = deepcopy(row)
        target = json.loads(row['messages'][0]['content']);target.update(changes)
        row['messages'][0]['content'] = json.dumps(target)
        return row

    def test_generated_identity_and_absolute_shift_only_collapse(self):
        a, b = self.fixture(0), self.fixture(3)
        before = deepcopy([a, b])
        selected, ledger = select_synthetic([b, a])
        self.assertEqual(len(selected), 1)
        self.assertEqual(len(ledger[0]['members']), 2)
        self.assertEqual([a, b], before)  # actual text is never normalized

    def test_ttl_duration_and_deadline_differences_survive(self):
        a = self.fixture();p = json.loads(a['messages'][0]['content'])
        for change in ({'minutes': 60}, {'expires_at': p['expires_at']+60},
                       {'owned_deadline': p['owned_deadline']-600}):
            self.assertNotEqual(synthetic_fingerprint(a), synthetic_fingerprint(self.change(a, **change)))

    def test_approval_failure_and_expiration_are_distinct(self):
        a = self.fixture()
        for state in ('applied', 'failed', 'expired', 'needs_review'):
            self.assertNotEqual(synthetic_fingerprint(a), synthetic_fingerprint(self.change(a, state=state)))

    def test_severity_evidence_count_and_coverage_are_not_masked(self):
        a = self.fixture()
        for change in ({'severity': 1}, {'observed_count': 0}, {'sample_complete': True}):
            self.assertNotEqual(synthetic_fingerprint(a), synthetic_fingerprint(self.change(a, **change)))

    def test_mismatched_request_ids_do_not_collapse(self):
        a = self.fixture()
        self.assertNotEqual(synthetic_fingerprint(a), synthetic_fingerprint(self.change(a, verified_request_id='f'*32)))

    def test_protected_review_and_required_checks_preserved(self):
        a = self.fixture();b = deepcopy(a);b['review']['protected_policy_reviewed'] = False
        self.assertNotEqual(synthetic_fingerprint(a), synthetic_fingerprint(b))
        b = deepcopy(a);b['checks']['must_not_claim'] = []
        self.assertNotEqual(synthetic_fingerprint(a), synthetic_fingerprint(b))

    def test_real_rule_or_ip_changes_not_relabelled(self):
        a = self.fixture()
        for change in ({'signature_id': '942100'}, {'source_ip': '93.184.216.34'}):
            self.assertNotEqual(synthetic_fingerprint(a), synthetic_fingerprint(self.change(a, **change)))

    def test_wording_families_are_kept_separate(self):
        a = self.fixture();b = deepcopy(a);b['template_family'] = 'operator-containment_pending-1'
        self.assertEqual(len(select_synthetic([a, b])[0]), 2)

    def test_only_original_controlled_train_templates_allowed(self):
        a = self.fixture()
        for key, value in [('split', 'test'), ('id', 'unknown')]:
            b = deepcopy(a);b[key] = value
            with self.assertRaises(ValueError): synthetic_fingerprint(b)
        b = deepcopy(a);b['review']['evidence_kind'] = 'public_testbed_log'
        with self.assertRaises(ValueError): synthetic_fingerprint(b)

    def entry(self):
        path = Path(__file__).resolve().parents[2] / 'infra/mcp/response-mcp.py'
        return fw_entry(path.read_text())

    def proof(self):
        result = json.dumps({'complete': True, 'offset': 0, 'next_offset': None,
                             'objects': [{'type': 'test'}], 'total_objects': 1})
        return {'stages': {'ollama': {'result': {'at_kst': '2026-10-29T16:38:55+09:00',
            'catalog': [{'name': 'get_firewall_rules', 'schema_sha256': FW_SCHEMA}],
            'calls': [{'name': 'get_firewall_rules', 'arguments': {}, 'is_error': False,
                       'result': result, 'result_sha256': sha(result.encode())}]}}}}

    def catalog(self):
        return {'tools': [{'name': name, 'description': 'competing read tool', 'protected': False,
                           'parameters': {'type': 'object', 'properties': {}}} for name in sorted(FW_CONTEXT - {FW})]}

    def test_fw_selection_contains_competitor_but_no_fabricated_result(self):
        catalog, row, lineage = fw_candidate(self.catalog(), self.entry(), self.proof())
        self.assertEqual(len(row['tools']), 6)
        self.assertEqual([m['role'] for m in row['messages']], ['system', 'user', 'assistant'])
        self.assertEqual(row['messages'][-1]['tool_calls'][0]['function']['name'], FW)
        self.assertFalse(lineage['tool_result_copied'])
        self.assertFalse(lineage['training_admitted'])

    def test_fw_schema_or_ambiguous_source_refused(self):
        with self.assertRaises(ValueError): fw_entry('TOOLS=[]')
        with self.assertRaises(ValueError): fw_entry('TOOLS=[{"name":"get_firewall_rules","inputSchema":{}}]')
        with self.assertRaises(ValueError): fw_entry('TOOLS=[{"name":"get_firewall_rules","inputSchema":danger()}]')

    def test_historical_fw_hash_and_error_not_ignored(self):
        for key, value in [('result_sha256', 'a'*64), ('is_error', True), ('arguments', {'offset': 2})]:
            p = self.proof();p['stages']['ollama']['result']['calls'][0][key] = value
            with self.assertRaises(ValueError): fw_candidate(self.catalog(), self.entry(), p)

    def test_incomplete_fw_snapshot_rejected_even_with_valid_hash(self):
        p = self.proof();call = p['stages']['ollama']['result']['calls'][0]
        data = json.loads(call['result']);data.update(complete=False, next_offset=1)
        call['result'] = json.dumps(data);call['result_sha256'] = sha(call['result'].encode())
        with self.assertRaises(ValueError): fw_candidate(self.catalog(), self.entry(), p)

    def test_preexisting_fw_tool_requires_new_review(self):
        cat = self.catalog();cat['tools'].append(self.entry())
        with self.assertRaises(ValueError): fw_candidate(cat, self.entry(), self.proof())

    def test_missing_or_protected_competitor_cannot_simplify_exercise(self):
        cat = self.catalog();cat['tools'].pop()
        with self.assertRaises(ValueError): fw_candidate(cat, self.entry(), self.proof())
        cat = self.catalog();cat['tools'][0]['protected'] = True
        with self.assertRaises(ValueError): fw_candidate(cat, self.entry(), self.proof())

    def test_report_and_entity_group_leakage_visible(self):
        cases = [{'id': '1', 'provider': 'CISA report', 'split': 'train'},
                 {'id': '2', 'provider': 'CISA report', 'split': 'test'},
                 {'id': '3', 'provider': 'MITRE ATT&CK', 'entity': 'group', 'split': 'train'},
                 {'id': '4', 'provider': 'MITRE ATT&CK', 'entity': 'group', 'split': 'validation'}]
        self.assertEqual(len(v5_group_audit(cases)['cross_split_groups']), 2)


if __name__ == '__main__':
    unittest.main()
