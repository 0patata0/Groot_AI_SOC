"""Comparison integrity: held-out answers, matched runtime and honest recovery."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evaluate_evidence_pair as pair


class FakeAPI:
    def __init__(self, gold):
        self.gold = gold
        self.calls = []
        self.fail_candidate = False
        self.length_candidate = False
        self.wrong_runtime = False
        self.bad_digest = False
        self.fail_restore = False

    def __call__(self, path, payload=None):
        self.calls.append((path, copy.deepcopy(payload)))
        if path == 'tags':
            return {'models': [{'name': pair.ORIGINAL, 'digest': pair.ORIGINAL_DIGEST},
                               {'name': 'control', 'digest': 'base'},
                               {'name': 'candidate', 'digest': 'wrong' if self.bad_digest else 'trained'}]}
        if path == 'ps':
            return {'models': [{'name': pair.ORIGINAL, 'context_length': 262144}]}
        if path == 'show':
            return {'template': 'same' if not self.wrong_runtime or payload['model'] == 'control' else 'different',
                    'parameters': 'temperature 1', 'details': {'quantization_level': 'Q4_K_M', 'runner': 'llamacpp'},
                    'capabilities': ['completion', 'tools']}
        if path == 'generate':
            if self.fail_restore and payload['model'] == pair.ORIGINAL:
                raise TimeoutError('simulated restore failure')
            return {'done': True, 'model': payload['model'], 'eval_count': 1}
        if path == 'chat':
            if self.fail_candidate and payload['model'] == 'candidate':
                raise TimeoutError('simulated transport failure')
            return {'done': True, 'model': payload['model'],
                    'done_reason': 'length' if self.length_candidate and payload['model'] == 'candidate' else 'stop',
                    'message': {'content': json.dumps(self.gold)}}
        raise AssertionError(path)


class PairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.gold = {'mappings': [{'id': 'T1003', 'name': 'OS Credential Dumping'}],
                     'scope': 'reported_mapping_only', 'local_status': 'not_assessed', 'evidence_ref': 'ref'}
        rows = [{'id': name, 'messages': [{'role': 'user', 'content': 'Evidence '+name},
                {'role': 'assistant', 'content': json.dumps(self.gold)}]} for name in ('one', 'two')]
        raw = ''.join(json.dumps(row)+'\n' for row in rows).encode()
        for split in ('validation', 'test'):
            (self.root/(split+'.jsonl')).write_bytes(raw)
        self.frozen = {'data_sha256': {'validation': pair.sha(raw), 'test': pair.sha(raw)},
                       'records': {'test': 2}, 'HF_control_digest': 'base'}
        self.development = {'case_ids': ['one', 'two'], 'validation_sha256': pair.sha(raw)}
        self.registration = {'status': 'completed', 'variant': 'v5', 'model': 'candidate', 'digest': 'trained',
                             'training_coverage': {'status': 'passed', 'steps': 512, 'distinct_observations': 1024}}
        self.api = FakeAPI(self.gold)
        self.plan = self.make_plan()
        self.path = self.root/'plan.json'
        self.write_plan()

    def make_plan(self, split='validation'):
        return pair.pin_plan(self.root, self.frozen, self.development, self.registration,
                             split, 'control', 'candidate', request=self.api)

    def write_plan(self):
        self.path.write_text(json.dumps(self.plan))

    def run_pair(self):
        return pair.run_pair(self.root, self.path, self.root/'result.json', request=self.api)

    def test_pair_withholds_gold_executes_no_tools_and_preserves_original_context(self):
        r = self.run_pair()
        self.assertEqual(r['status'], 'completed')
        self.assertEqual([r['arms'][arm]['summary']['strict_complete'] for arm in ('control', 'candidate')], [2, 2])
        chats = [p for name, p in self.api.calls if name == 'chat']
        self.assertEqual(len(chats), 4)
        self.assertTrue(all(len(p['messages']) == 1 and p['messages'][0]['role'] == 'user' and 'tools' not in p for p in chats))
        self.assertEqual(r['restoration']['context_length'], 262144)
        self.assertTrue(r['restoration']['original_generation_verified'])
        self.assertFalse(any(p.get('model') == pair.ORIGINAL and p.get('keep_alive') == 0
                             for n, p in self.api.calls if n == 'generate'))

    def test_runtime_mismatch_and_unverified_registration_cannot_be_pinned(self):
        self.api.wrong_runtime = True
        with self.assertRaises(ValueError): self.make_plan()
        self.api.wrong_runtime = False
        self.registration['training_coverage']['steps'] = 2
        with self.assertRaises(ValueError): self.make_plan()

    def test_changed_digest_fails_before_any_inference(self):
        self.api.calls.clear(); self.api.bad_digest = True
        with self.assertRaises(ValueError): self.run_pair()
        self.assertFalse(any(n in ('chat', 'generate') for n, _ in self.api.calls))

    def test_hidden_runtime_fields_are_checked_before_inference(self):
        for field in ('renderer', 'parser', 'requires', 'messages'):
            with self.subTest(field=field):
                api = FakeAPI(self.gold)
                def changed(path, payload=None):
                    response = api(path, payload)
                    if path == 'show' and payload['model'] == 'candidate':
                        response[field] = 'different'
                    return response
                with self.assertRaises(ValueError):
                    pair.run_pair(self.root, self.path, self.root/'result.json', request=changed)
                self.assertFalse(any(n in ('chat', 'generate') for n, _ in api.calls))

    def test_completed_arm_is_released_before_next_model_load(self):
        r = self.run_pair()
        calls = self.api.calls
        released = [i for i, (n, p) in enumerate(calls)
                    if n == 'generate' and p.get('model') == 'control' and p.get('keep_alive') == 0]
        candidate_load = next(i for i, (n, p) in enumerate(calls)
                              if n == 'generate' and p.get('model') == 'candidate' and p.get('keep_alive') != 0)
        self.assertEqual(len(released), 1)
        self.assertLess(released[0], candidate_load)
        self.assertTrue(all(r['arms'][arm]['released_after_arm'] for arm in ('control', 'candidate')))

    def test_preexisting_comparison_model_is_not_released(self):
        def with_existing(path, payload=None):
            response = self.api(path, payload)
            if path == 'ps':
                response['models'].append({'name': 'control', 'context_length': 8192})
            return response
        r = pair.run_pair(self.root, self.path, self.root/'result.json', request=with_existing)
        self.assertEqual(r['status'], 'completed')
        self.assertNotIn('released_after_arm', r['arms']['control'])
        self.assertFalse(any(n == 'generate' and p.get('model') == 'control' and p.get('keep_alive') == 0
                             for n, p in self.api.calls))

    def test_failed_candidate_preserves_partial_evidence_and_restores(self):
        self.api.fail_candidate = True
        with self.assertRaises(TimeoutError): self.run_pair()
        r = json.loads((self.root/'result.json').read_text())
        self.assertEqual(r['status'], 'failed')
        self.assertEqual(len(r['arms']['control']['results']), 2)
        self.assertEqual(r['restoration']['status'], 'verified')

    def test_truncated_output_is_not_a_strict_success_even_if_json_parses(self):
        self.api.length_candidate = True
        r = self.run_pair()
        self.assertEqual(r['arms']['candidate']['summary']['strict_complete'], 0)

    def test_restore_failure_is_persisted_and_cannot_be_reported_as_full_success(self):
        self.api.fail_restore = True
        with self.assertRaises(RuntimeError): self.run_pair()
        r = json.loads((self.root/'result.json').read_text())
        self.assertEqual(r['status'], 'completed')
        self.assertEqual(r['restoration']['status'], 'failed')
        self.assertEqual(r['restoration']['error_type'], 'TimeoutError')

    def test_final_holdout_cannot_be_subsampled_or_overwrite_an_old_report(self):
        self.plan = self.make_plan('test'); self.plan['case_ids'] = ['one']; self.write_plan()
        with self.assertRaises(ValueError): self.run_pair()
        self.plan = self.make_plan('test'); self.write_plan(); self.run_pair()
        original = (self.root/'result.json').read_bytes()
        with self.assertRaises(ValueError): self.run_pair()
        self.assertEqual((self.root/'result.json').read_bytes(), original)

    def test_changed_input_and_scorer_are_rejected(self):
        self.plan['source_sha256']['evaluate_evidence_pair.py'] = 'changed'; self.write_plan()
        with self.assertRaises(ValueError): self.run_pair()
        self.plan = self.make_plan(); self.write_plan()
        (self.root/'validation.jsonl').write_text('{}\n')
        with self.assertRaises(ValueError): self.run_pair()


if __name__ == '__main__':
    unittest.main()
