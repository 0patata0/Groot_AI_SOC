"""Synthetic benchmark/scorer fixtures only; results are not model evaluations."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_cam_benchmark import build
from score_cam_benchmark import score_response, score
from check_cam_benchmark_tokens import measure


def response(ids=None):
    return json.dumps({'techniques': ids or ['T' + str(1000 + i) for i in range(10)],
                       'confidence': 'Neutral', 'explanation': 'Synthetic scoring fixture.'})


def sources():
    row = {'scenario': '1', 'variant': 'a', 'step': '1', 'prompt': 'Synthetic input', 'ground_truth': ['T1000']}
    label = {'1_a-1': {'scenario_variant': '1_a', 'event_id': 1, 'metadata': {'T1000': {}}}}
    return [row, deepcopy(row)], label


class BenchmarkTests(unittest.TestCase):
    def test_collapse_repeats_preserves_prompt_gold_and_both_coordinates(self):
        queries, labels = sources()
        inputs, gold, traces, counts = build(queries, labels)
        self.assertEqual(counts['unique_inputs'], 1)
        self.assertEqual(inputs[0]['messages'], [{'role': 'user', 'content': queries[0]['prompt']}])
        self.assertNotIn('ground_truth', inputs[0])
        self.assertEqual(gold[0]['techniques'], ['T1000'])
        self.assertEqual([x['source_line'] for x in traces[0]['occurrences']], [1, 2])
        self.assertFalse(traces[0]['eligible_for_training'])

    def test_no_original_annotation_is_removed(self):
        q, labels = sources()
        q[0]['prompt'] = q[1]['prompt'] = json.dumps({'rule': {'mitre': {'id': ['T1000']}}})
        inputs, _, traces, _ = build(q, labels)
        self.assertEqual(inputs[0]['messages'][0]['content'], q[0]['prompt'])
        self.assertEqual(traces[0]['stratum'], 'structured_technique_identifier')
        self.assertTrue(traces[0]['exact_gold_id_visible'])

    def test_literal_only_is_not_a_structured_detector_annotation(self):
        q, labels = sources();q[0]['prompt'] = q[1]['prompt'] = 'File contains T1000'
        self.assertEqual(build(q, labels)[2][0]['stratum'], 'other_literal_technique_identifier')

    def test_conflicting_labels_rejected(self):
        q, labels = sources();q[1]['variant'] = 'b';q[1]['ground_truth'] = ['T1001']
        labels['1_b-1'] = {'scenario_variant': '1_b', 'event_id': 1, 'metadata': {'T1001': {}}}
        with self.assertRaises(ValueError): build(q, labels)

    def test_cross_step_identical_input_requires_review(self):
        q, labels = sources();q[1]['step'] = '2'
        labels['1_a-2'] = {'scenario_variant': '1_a', 'event_id': 2, 'metadata': {'T1000': {}}}
        with self.assertRaises(ValueError): build(q, labels)

    def test_more_than_ten_gold_is_not_an_impossible_model_penalty(self):
        gold = ['T' + str(1000 + i) for i in range(13)]
        row = score_response(response(), gold)
        self.assertEqual(row['unavoidable_omissions_at10'], 3)
        self.assertEqual(row['avoidable_omissions_at10'], 0)
        self.assertEqual(row['exact_recall']['10'], 10 / 13)
        self.assertEqual(row['exact_recall_at10_ceiling'], 10 / 13)
        self.assertFalse(row['all_provider_labels_present'])

    def test_top10_distractors_not_called_fabricated_facts(self):
        row = score_response(response(), ['T1000'])
        self.assertTrue(row['valid_response'])
        self.assertEqual(row['top1_hit'], 1)
        self.assertEqual(row['exact_recall']['10'], 1)
        self.assertNotIn('hallucinations', row)
        self.assertFalse(row['confidence_accuracy_scored'])
        self.assertFalse(row['explanation_factuality_scored'])

    def test_missing_or_malformed_outputs_receive_no_credit(self):
        for raw in [None, '{bad', '```json\n' + response() + '\n```']:
            row = score_response(raw, ['T1000'])
            self.assertFalse(row['valid_response'])
            self.assertEqual(row['exact_recall']['10'], 0)
            self.assertEqual(row['avoidable_omissions_at10'], 1)

    def test_duplicates_wrong_count_confidence_and_empty_explanation_fail(self):
        base = json.loads(response())
        for key, value in [('techniques', ['T1000'] * 10), ('techniques', ['T1000']),
                           ('techniques', list(range(10))), ('confidence', 'CERTAIN'),
                           ('confidence', 1), ('explanation', ' ')]:
            obj = deepcopy(base);obj[key] = value
            self.assertEqual(score_response(json.dumps(obj), ['T1000'])['failure'], 'invalid_response_schema')

    def test_duplicate_response_json_key_rejected(self):
        raw = response()[:-1] + ',"confidence":"Certain: Attack"}'
        self.assertFalse(score_response(raw, ['T1000'])['valid_response'])

    def test_parent_score_distinct_from_exact_and_respects_rank(self):
        ids = ['T1000.001', 'T1000.002', 'T1001'] + ['T' + str(1002 + i) for i in range(7)]
        row = score_response(response(ids), ['T1000', 'T1001'])
        self.assertEqual(row['exact_recall']['1'], 0)
        self.assertEqual(row['parent_recall']['1'], .5)
        self.assertEqual(row['parent_recall']['3'], 1)
        self.assertAlmostEqual(row['label_mean_reciprocal_rank'], 1 / 6)

    def fixture(self):
        gold = [{'id': str(i), 'techniques': ['T1000']} for i in range(3)]
        traces = [{'id': str(i), 'scenario_group': 'A' if i < 2 else 'B',
                   'scenario_step': 'A-1' if i < 2 else 'B-1', 'stratum': 'no_literal_technique_identifier',
                   'partition': 'reserved_external_benchmark_candidate', 'eligible_for_training': False}
                  for i in range(3)]
        return gold, traces

    def test_macro_scenarios_not_biased_by_extra_prompts_or_missing_outputs(self):
        gold, traces = self.fixture()
        result = score(gold, traces, [{'id': str(i), 'response': response()} for i in range(2)])
        self.assertEqual(result['aggregate']['scenario_macro']['top1_hit'], .5)
        self.assertAlmostEqual(result['aggregate']['unique_input_micro']['top1_hit'], 2 / 3)
        self.assertEqual(result['aggregate']['failure_counts']['missing_response'], 1)
        self.assertFalse(result['model_promotion_allowed'])

    def test_prediction_duplicates_unknown_ids_and_gold_alignment_rejected(self):
        gold, traces = self.fixture()
        for predictions in [[{'id': 'unknown', 'response': response()}], [{'id': '0', 'response': response()}] * 2]:
            with self.assertRaises(ValueError): score(gold, traces, predictions)
        with self.assertRaises(ValueError): score(gold, list(reversed(traces)), [])

    def test_training_partition_change_rejected(self):
        gold, traces = self.fixture();traces[0]['eligible_for_training'] = True
        with self.assertRaises(ValueError): score(gold, traces, [])

    def test_context_accounting_includes_output_reserve_and_never_truncates(self):
        class Fake:
            def apply_chat_template(self, messages, **kwargs):
                if kwargs.get('tokenize'):
                    assert kwargs == {'tokenize': True, 'return_dict': False, 'add_generation_prompt': True, 'enable_thinking': False}
                    return [1] * 3900
                assert kwargs == {'tokenize': False, 'add_generation_prompt': True, 'enable_thinking': False}
                return 'template fixture'
            def encode(self, text, **kwargs):
                assert kwargs == {'add_special_tokens': False}
                return [1] * 3900
        inputs = [{'id': 'x', 'messages': [{'role': 'user', 'content': 'fixture'}]}]
        result = measure(inputs, Fake(), 512)
        self.assertEqual(result['max_required_context'], 4412)
        self.assertEqual(result['context_budget_analysis']['4096'], {'fit': 0, 'over': 1})
        self.assertEqual(result['context_budget_analysis']['8192'], {'fit': 1, 'over': 0})
        self.assertFalse(result['records'][0]['truncated'])
        for reserve in (0, True, 4097):
            with self.assertRaises(ValueError): measure(inputs, Fake(), reserve)

    def test_mapping_batched_tokens_and_lost_prompt_are_rejected(self):
        class Fake:
            value = {'input_ids': [1] * 9000, 'attention_mask': [1] * 9000}
            text = 'fixture'
            def apply_chat_template(self, messages, **kwargs): return self.text
            def encode(self, text, **kwargs): return self.value
        inputs = [{'id': 'x', 'messages': [{'role': 'user', 'content': 'fixture'}]}]
        fake = Fake()
        for value in ({'input_ids': [1] * 9000, 'attention_mask': [1] * 9000}, [[1, 2]], [], [True]):
            fake.value = value
            with self.assertRaises(ValueError): measure(inputs, fake, 512)
        fake.value = [1, 2];fake.text = 'missing content'
        with self.assertRaises(ValueError): measure(inputs, fake, 512)

    def test_outer_whitespace_trim_allowed_but_token_api_disagreement_rejected(self):
        class Fake:
            direct = [1, 2, 3]
            def apply_chat_template(self, messages, **kwargs):
                return self.direct if kwargs['tokenize'] else 'prefix fixture suffix'
            def encode(self, text, **kwargs): return [1, 2, 3]
        inputs = [{'id': 'x', 'messages': [{'role': 'user', 'content': ' fixture\n '}]}]
        fake = Fake()
        self.assertEqual(measure(inputs, fake, 512)['inputs_with_template_outer_whitespace_trimmed'], 1)
        fake.direct = [9, 9, 9]
        with self.assertRaises(ValueError): measure(inputs, fake, 512)


if __name__ == '__main__':
    unittest.main()
