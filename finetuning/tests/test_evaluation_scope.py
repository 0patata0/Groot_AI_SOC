import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation_scope import audit_rows, fingerprints, usage_sets


def example(question='Check this incident', *, tools=False):
    row = {'id': 'case', 'messages': [{'role': 'user', 'content': question}]}
    if tools:
        row['tools'] = [{'type': 'function', 'function': {'name': 'read', 'parameters': {'type': 'object'}}}]
        row['messages'] += [{'role': 'assistant', 'tool_calls': [{'function': {'name': 'read', 'arguments': {}}}]},
                            {'role': 'tool', 'content': '{"current":"unknown"}'}]
    row['messages'].append({'role': 'assistant', 'content': 'The outcome remains unknown'})
    return row


def registry(rows=()):
    return {'schema': 'groot-evaluation-usage-v1', 'consumed': [{'status': 'consumed',
        'evidence': 'Frozen previous evaluation result', 'data_sha256': 'a'*64,
        'records': len(rows), 'fingerprints': [fingerprints(r) for r in rows]}]}


class ScopeTests(unittest.TestCase):
    def test_relabelled_case_or_changed_answer_cannot_become_unseen(self):
        old = example(); new = copy.deepcopy(old); new['id'] = 'new'
        new['messages'][-1]['content'] = 'A revised label'
        report = audit_rows([new], registry([old]))
        self.assertEqual(report['known_consumed_record'], 0)
        self.assertEqual(report['known_consumed_visible_input'], 1)
        self.assertEqual(report['allowed_use'], 'development_regression_only')
        # Distinct consumed references may legitimately share an input. Keep
        # both source records and union their exposure; never drop one silently.
        report = audit_rows([new], registry([old, new]))
        self.assertEqual(report['known_consumed_record'], 1)
        self.assertEqual(report['known_consumed_visible_input'], 1)

    def test_changed_system_policy_is_potential_overlap_not_exact_prompt_equality(self):
        old = example(); new = copy.deepcopy(old)
        new['messages'].insert(0, {'role': 'system', 'content': 'New policy'})
        report = audit_rows([new], registry([old]))
        self.assertEqual(report['known_consumed_visible_input'], 0)
        self.assertEqual(report['known_consumed_nonassistant_input'], 1)
        self.assertEqual(report['allowed_use'], 'development_regression_only')

    def test_tool_definitions_alone_are_not_workflow_coverage(self):
        row = example(); row['tools'] = [{'name': 'read'}]
        report = audit_rows([row], registry())
        self.assertEqual(report['tool_definition_rows'], 1)
        self.assertEqual(report['assistant_tool_call_rows'], 0)
        self.assertEqual(report['tool_observation_rows'], 0)
        self.assertFalse(report['independent_operational_quality_proven'])

    def test_unused_tool_fixture_does_not_prove_independence_or_quality(self):
        report = audit_rows([example(tools=True)], registry())
        self.assertEqual(report['assistant_tool_call_rows'], 1)
        self.assertEqual(report['tool_observation_rows'], 1)
        self.assertEqual(report['allowed_use'], 'unverified_evaluation_candidate_only')
        self.assertFalse(report['promotion_evidence_allowed_by_this_audit'])

    def test_training_overlap_and_unseen_rows_remain_in_denominator(self):
        a, b = example('First'), example('Second')
        report = audit_rows([a, b], registry(), [a])
        self.assertEqual(report['records'], 2)
        self.assertEqual(report['training_overlap_visible_input'], 1)
        self.assertEqual(report['training_overlap_nonassistant_input'], 1)

    def test_incomplete_or_nonfinite_references_and_empty_sets_are_refused(self):
        cases = [{}, {'messages': [{'role': 'user'}]},
                 {'messages': [{'role': 'user'}, {'role': 'function'}]},
                 {'messages': [{'role': 'user', 'content': ''}, {'role': 'assistant', 'content': 'Answer'}]},
                 {'messages': [{'role': 'user', 'content': 'Question'}, {'role': 'assistant', 'content': ''}]}]
        row = example(); row['messages'][-1]['value'] = float('nan'); cases.append(row)
        for row in cases:
            with self.subTest(row=row), self.assertRaises(ValueError): fingerprints(row)
        with self.assertRaises(ValueError): audit_rows([], registry())

    def test_missing_corrupt_or_duplicate_usage_cannot_hide_known_exposure(self):
        good = registry([example()])
        for edit in ('count', 'duplicate', 'invalid', 'missing', 'invalid_source_hash'):
            value = copy.deepcopy(good)
            if edit == 'count': value['consumed'][0]['records'] = 2
            if edit == 'duplicate': value['consumed'][0]['fingerprints'] *= 2; value['consumed'][0]['records'] = 2
            if edit == 'invalid': value['consumed'][0]['fingerprints'][0]['record_sha256'] = 'unknown'
            if edit == 'missing': del value['consumed']
            if edit == 'invalid_source_hash': value['consumed'][0]['data_sha256'] = 1
            with self.subTest(edit=edit), self.assertRaises(ValueError): usage_sets(value)


if __name__ == '__main__': unittest.main()
