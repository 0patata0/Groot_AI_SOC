"""Protect source identity, table coverage and split leakage in provider labels."""
import tempfile
from pathlib import Path
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cisa_tables import extract
from evidence_groups import Groups, report_key, related_groups
from prepare_evidence_v5 import observation_text, record, safe_bytes, select, matches_historical_title
from audit_evidence_v5 import verify_record
from evaluate_evidence_v5 import assess
from review_evidence_results import review
import copy, json


class EvidenceTests(unittest.TestCase):
    def test_one_report_cannot_split_by_tracking_or_CISA_attachment_version(self):
        self.assertEqual(report_key('https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a'),
                         report_key('https://www.cisa.gov/files/AA24-038A_update.pdf?utm_source=test'))
        self.assertEqual(report_key('https://www.example.org/paper#section'), report_key('http://example.org/paper?utm_source=test'))
        with self.assertRaises(ValueError): report_key('https://secret@example.org/report')

    def test_shared_report_and_campaign_attribution_keep_same_component(self):
        actor = {'id': 'g1', 'type': 'intrusion-set', 'external_references': [{'source_name': 'mitre-attack', 'external_id': 'G001'}]}
        campaign = {'id': 'c1', 'type': 'campaign'}
        other = {'id': 'g2', 'type': 'intrusion-set'}
        rels = [{'id': 'r1', 'type': 'relationship', 'source_ref': 'c1', 'description': 'Observation', 'external_references': [{'url': 'https://example.org/report'}]},
                {'id': 'r2', 'type': 'relationship', 'source_ref': 'g2', 'description': 'Other observation', 'external_references': [{'url': 'https://www.example.org/report#s2'}]}]
        attribution = {'id': 'a', 'type': 'relationship', 'relationship_type': 'attributed-to', 'source_ref': 'c1', 'target_ref': 'g1'}
        groups = related_groups([actor, campaign, other, attribution], rels, [])
        self.assertEqual(groups['entity:g1'], groups['entity:g2'])

    def test_group_identity_is_order_independent(self):
        a, b = Groups(), Groups()
        a.join('b', 'a'); a.join('b', 'c'); b.join('c', 'b', 'a')
        self.assertEqual(a.identities(), b.identities())

    def test_original_uncertainty_survives_markup_removal(self):
        self.assertEqual(observation_text('[Actor](https://attack.mitre.org/groups/G001) may use a tunnel.(Citation: Report)'), 'Actor may use a tunnel.')

    def test_historical_parent_child_titles_do_not_discard_subtechniques(self):
        taxonomy = {'T1059': {'name': 'Command and Scripting Interpreter'}, 'T1059.001': {'name': 'PowerShell'}}
        self.assertTrue(matches_historical_title('Command and Scripting Interpreter: PowerShell', 'T1059.001', taxonomy))
        self.assertTrue(matches_historical_title('PowerShell', 'T1059.001', taxonomy))
        self.assertFalse(matches_historical_title('Unix Shell', 'T1059.001', taxonomy))

    def test_cisa_wrapped_cells_and_continued_use_do_not_drop_text(self):
        lines = ['Table 2: ATT&CK Techniques for Execution', '        Technique Title                ID                    Use',
                 '        Command and                 T1059.001     Actor used PowerShell to',
                 '        Scripting Interpreter:                    disable antivirus.',
                 '        PowerShell', '', '                                                  A second source sentence.', '',
                 'Table 3: ATT&CK Techniques for Impact', '        Technique Title                ID                    Use',
                 '        Inhibit System              T1490         Actor removed shadow copies.',
                 '        Recovery']
        rows, audit = extract('\n'.join(lines), {'first_page': 1, 'last_page': 1, 'tables': [2, 3]})
        self.assertEqual(audit['encountered_table_IDs'], 2); self.assertFalse(audit['rejected'])
        self.assertIn('second source sentence', rows[0]['description'])
        self.assertNotIn('second source sentence', rows[1]['description'])
        self.assertEqual(rows[1]['technique_id'], 'T1490')

    def test_ambiguous_table_IDs_are_accounted_for_and_quarantined(self):
        row = '        A description               T1059 T1490    Ambiguous source statement.'
        rows, audit = extract('Table 2: ATT&CK Techniques\n' + row, {'first_page': 1, 'last_page': 1, 'tables': [2]})
        self.assertEqual(rows, []); self.assertEqual(audit['encountered_table_IDs'], 2)
        self.assertEqual(audit['rejected'][0]['reason'], 'ambiguous_ID_block')

    def test_source_tampering_and_path_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / 'file').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'checksum'): safe_bytes(root, 'file', '0' * 64)
            with self.assertRaisesRegex(ValueError, 'Unsafe'): safe_bytes(root, '../outside', '0' * 64)

    def test_multilabel_record_has_unique_identity_and_no_execution_claim(self):
        base = {'id': 'first', 'provider': 'MITRE ATT&CK', 'entity': 'Source actor', 'version': 'pinned',
                'evidence_ref': 'EVD-1', 'observation': 'A provider observation.', 'split': 'train', 'group': 'group1',
                'mappings': [{'id': 'T1059', 'name': 'Command and Scripting Interpreter'}, {'id': 'T1490', 'name': 'Inhibit System Recovery'}], 'source_rows': []}
        first, second = record(base), record({**base, 'id': 'second'})
        self.assertNotEqual(first['id'], second['id']); self.assertEqual(first['tools'], [])
        self.assertIn('reported_mapping_only', first['messages'][-1]['content'])
        self.assertIn('T1490', first['messages'][-1]['content'])

    def test_sampling_preserves_cisa_and_does_not_duplicate_observations(self):
        rows = [{'id': str(i), 'provider': 'CISA test' if i == 0 else 'MITRE ATT&CK', 'group': str(i % 3),
                 'mappings': [{'id': 'T' + str(i % 4)}]} for i in range(10)]
        selected = select(rows, 5)
        self.assertEqual(len({r['id'] for r in selected}), 5); self.assertIn('0', [r['id'] for r in selected])
        self.assertEqual(selected, select(list(reversed(rows)), 5))

    def test_auditor_rejects_fabricated_labels_even_with_valid_JSON(self):
        case = {'id': 'c', 'provider': 'MITRE ATT&CK', 'entity': 'actor', 'version': 'pinned', 'evidence_ref': 'EVD-1',
                'observation': 'Original statement.', 'split': 'train', 'group': 'g', 'source_rows': [],
                'mappings': [{'id': 'T1490', 'name': 'Inhibit System Recovery'}]}
        row = record(case); verify_record(case, row, case['mappings'])
        changed = copy.deepcopy(row); changed['messages'][-1]['content'] = changed['messages'][-1]['content'].replace('T1490', 'T1059')
        with self.assertRaisesRegex(ValueError, 'Gold mapping'): verify_record(case, changed, case['mappings'])
        changed = copy.deepcopy(row); changed['messages'][-2]['content'] = changed['messages'][-2]['content'].replace('Original statement.', 'Invented outcome.')
        with self.assertRaisesRegex(ValueError, 'Prompt'): verify_record(case, changed, case['mappings'])

    def test_evaluation_separates_format_from_ID_recall_and_penalizes_extra_labels(self):
        expected = {'mappings': [{'id': 'T1490', 'name': 'Inhibit System Recovery'}], 'evidence_ref': 'EVD-1'}
        natural = assess({'content': 'The report maps this to T1490.'}, expected)
        self.assertEqual(natural['f1'], 1); self.assertFalse(natural['format_valid']); self.assertFalse(natural['strict_complete'])
        content = {**copy.deepcopy(expected), 'scope': 'reported_mapping_only', 'local_status': 'not_assessed'}
        self.assertTrue(assess({'content': json.dumps(content)}, expected)['strict_complete'])
        content['mappings'] += [{'id': 'T1059', 'name': 'Command and Scripting Interpreter'}]
        extra = assess({'content': json.dumps(content)}, expected)
        self.assertEqual(extra['unsupported_IDs'], ['T1059']); self.assertFalse(extra['strict_complete'])

    def test_fabricated_local_completion_or_unavailable_tool_fails_strict_completeness(self):
        expected = {'mappings': [{'id': 'T1490', 'name': 'Inhibit System Recovery'}], 'evidence_ref': 'EVD-1'}
        content = {**expected, 'scope': 'reported_mapping_only', 'local_status': 'blocked'}
        self.assertFalse(assess({'content': json.dumps(content)}, expected)['scope_preserved'])
        content['local_status'] = 'not_assessed'
        self.assertTrue(assess({'content': json.dumps(content), 'tool_calls': [{'function': {'name': 'block_ip'}}]}, expected)['attempted_unavailable_tool'])

    def test_review_distinguishes_coarse_parent_from_unrelated_prediction(self):
        result = {'summary': {'strict_complete': 0}, 'results': [
            {'case_id': 'one', 'assessment': {'missing_IDs': ['T1059.001', 'T1490'],
             'unsupported_IDs': ['T1059', 'T1021']}}]}
        original = copy.deepcopy(result)
        diagnostic = review(result)
        self.assertEqual(diagnostic['omitted_children_with_predicted_parent'], 1)
        self.assertEqual(diagnostic['non_reference_prediction_IDs'], 2)
        self.assertEqual(diagnostic['cases'][0]['parent_instead_of_child'],
                         [{'expected': 'T1059.001', 'predicted_parent': 'T1059'}])
        self.assertEqual(result, original)


if __name__ == '__main__': unittest.main()
