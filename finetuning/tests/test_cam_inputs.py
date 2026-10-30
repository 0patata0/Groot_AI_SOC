import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_cam_inputs import audit, parse, visible_annotations


def fixtures():
    labels = {'1_a-1': {'scenario_variant': '1_a', 'event_id': '1', 'metadata': {'T1001.001': {}}},
              '1_b-1': {'scenario_variant': '1_b', 'event_id': '1', 'metadata': {'T1001.001': {}}},
              '2-1': {'scenario_variant': '2', 'event_id': '1', 'metadata': {'T1002': {}}}}
    rows = [{'scenario': '1', 'variant': 'a', 'step': '1', 'prompt': 'log', 'ground_truth': ['T1001.001']},
            {'scenario': '1', 'variant': 'b', 'step': '1', 'prompt': 'log', 'ground_truth': ['T1001.001']}]
    return rows, labels


class CAMTests(unittest.TestCase):
    def test_repeats_are_not_independent_steps(self):
        rows, labels = fixtures()
        r = audit(rows, labels)
        self.assertEqual((r['scenario_steps'], r['unique_prompts'], r['steps_with_identical_all_repetitions']), (1, 1, 1))
        self.assertEqual(r['step_repetition_counts'], {2: 1})

    def test_full_label_scope_is_separate_from_query_scope(self):
        r = audit(*fixtures())
        self.assertEqual(r['unqueried_ids'], ['T1002'])
        self.assertEqual(r['all_label_parent_ids'], ['T1001', 'T1002'])
        self.assertEqual(r['query_parent_ids'], ['T1001'])
        self.assertEqual(r['unqueried_id_label_keys'], {'T1002': ['2-1']})

    def test_cross_step_conflicting_labels_are_visible_not_silently_deduped(self):
        rows, labels = fixtures()
        rows.append({'scenario': '2', 'variant': '', 'step': '1', 'prompt': 'log', 'ground_truth': ['T1002']})
        r = audit(rows, labels)
        self.assertEqual(r['cross_step_identical_prompt_groups'], 1)
        self.assertEqual(r['identical_prompt_conflicting_label_groups'], 1)

    def test_unknown_or_mismatching_ground_truth_fails(self):
        rows, labels = fixtures()
        for ids in ([], ['T1002'], ['T1001.001', 'T1001.001']):
            mutated = copy.deepcopy(rows)
            mutated[0]['ground_truth'] = ids
            with self.assertRaises(ValueError): audit(mutated, labels)

    def test_missing_identity_or_unreviewed_query_fields_fail(self):
        rows, labels = fixtures()
        for change in ({'variant': 'unknown'}, {'scenario': 1}, {'step': '01'}, {'extra': 'x'}):
            changed = copy.deepcopy(rows); changed[0].update(change)
            with self.assertRaises(ValueError): audit(changed, labels)

    def test_label_identity_and_id_validation(self):
        rows, labels = fixtures()
        for key, value in [('event_id', '2'), ('metadata', {'T1001.01': {}})]:
            changed = copy.deepcopy(labels); changed['1_a-1'][key] = value
            with self.assertRaises(ValueError): audit(rows, changed)

    def test_raw_literal_is_not_automatically_a_structured_answer_hint(self):
        literal, structured, paths = visible_annotations('audit key="T1001.001" example AT1002 T1003.01')
        self.assertEqual(literal, {'T1001.001'})
        self.assertFalse(structured); self.assertFalse(paths)

    def test_nested_annotation_paths_and_parent_match_are_separate(self):
        rows, labels = fixtures()
        event = {'rule': {'mitre': {'id': ['T1001']}}, 'data': {'audit': {'key': 'T1003'},
                 'alert': {'metadata': {'mitre_technique_id': ['T1004']}}}}
        rows[0]['prompt'] = '        ' + json.dumps(event)
        r = audit(rows, labels)
        self.assertEqual(r['parsed_annotation_parent_gold_queries'], 1)
        self.assertEqual(r['parsed_annotation_exact_gold_queries'], 0)
        self.assertEqual(r['unique_prompt_identifier_counts']['parsed_parent_gold_overlap'], 1)
        self.assertEqual(set(r['visible_identifier_coordinates'][0]['parsed_annotation_line_counts']),
                         {'rule.mitre.id', 'data.audit.key', 'data.alert.metadata.mitre_technique_id'})

    def test_unrelated_json_and_bad_json_are_only_literal_flags(self):
        raw = '{"message":"T1001"}\n{broken T1002}'
        literal, structured, _ = visible_annotations(raw)
        self.assertEqual(literal, {'T1001', 'T1002'}); self.assertFalse(structured)

    def test_sources_are_preserved_and_no_admission(self):
        rows, labels = fixtures(); before = copy.deepcopy((rows, labels))
        result = audit(rows, labels)
        self.assertEqual((rows, labels), before)
        self.assertEqual((result['training_admitted'], result['new_final_evaluation_records']), (0, 0))

    def test_duplicate_json_and_empty_source_rejected(self):
        with self.assertRaises(ValueError): parse('{"a":1,"a":2}')
        with self.assertRaises(ValueError): audit([], {})


if __name__ == '__main__':
    unittest.main()
