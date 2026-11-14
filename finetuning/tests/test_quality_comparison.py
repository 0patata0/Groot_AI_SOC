import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_quality_comparison import build, dump, sha


class ComparisonTests(unittest.TestCase):
    def fixture(self, root):
        for name, records in (('full', [{'id': 'one'}, {'id': 'two'}]),
                              ('balanced', [{'id': 'one'}])):
            d = root/name; d.mkdir()
            for row in records:
                row['messages'] = [{'role': 'user', 'content': 'Training '+row['id']},
                                   {'role': 'assistant', 'content': 'Training reference'}]
            (d/'train.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in records))
            for split in ('validation', 'test'):
                (d/(split+'.jsonl')).write_text(json.dumps({'id': split, 'messages': [
                    {'role': 'user', 'content': 'Reserved '+split},
                    {'role': 'assistant', 'content': 'Reserved reference'}]})+'\n')
            dump(d/'admission.json', {'truncation': False,
                'status': 'source_and_token_verified_waiting_final_review_and_gpu_smoke',
                'files': {p.name: sha(p) for p in d.glob('*.jsonl')}})
        e = root/'eval'; e.mkdir()
        (e/'test.jsonl').write_text('{"id":"private_test_fixture"}\n')
        dump(e/'manifest.json', {'training_included': False,
            'training_sha256': sha(root/'balanced/train.jsonl'),
            'files': {'test.jsonl': sha(e/'test.jsonl')}})
        return root/'full', root/'balanced', e, root/'output'

    def test_only_profiles_and_hash_plan_no_release_or_evaluation_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp)); plan = build(*args)
            self.assertEqual(len(plan['arms']), 6)
            self.assertEqual(plan['gpu_jobs_started'], 0)
            self.assertFalse(plan['main_training_release_issued'])
            self.assertEqual(len(list(args[-1].iterdir())), 7)
            self.assertFalse(any('private_test_fixture' in p.read_text() for p in args[-1].iterdir()))
            for split in ('validation', 'test'):
                audit = plan['evaluation']['existing'][split]['scope_audit']
                self.assertEqual(audit['tool_observation_rows'], 0)
                self.assertEqual(audit['allowed_use'], 'development_regression_only')
                self.assertFalse(audit['independent_operational_quality_proven'])
            for arm in plan['arms']:
                c = json.loads((args[-1]/arm['profile']).read_text())
                self.assertNotIn('resume_from_checkpoint', c)
                self.assertEqual(c['max_steps'], 128)
                self.assertEqual(c['eval_steps'], 32)
                self.assertEqual(arm['profile_sha256'], sha(args[-1]/arm['profile']))

    def test_modified_admitted_data_fails_before_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp)); (args[1]/'train.jsonl').write_text('{"id":"changed"}\n')
            with self.assertRaisesRegex(ValueError, 'mixture changed'): build(*args)
            self.assertFalse(args[-1].exists())

    def test_evaluation_admission_cannot_turn_into_training(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp)); p = args[2]/'manifest.json'
            value = json.loads(p.read_text()); value['training_included'] = True; dump(p, value)
            with self.assertRaisesRegex(ValueError, 'separate'): build(*args)
            self.assertFalse(args[-1].exists())

    def test_missing_evaluation_conversations_fail_before_profiles_are_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            for root in args[:2]:
                p = root/'test.jsonl'; p.write_text('{"id":"incomplete"}\n')
                admission = json.loads((root/'admission.json').read_text())
                admission['files']['test.jsonl'] = sha(p); dump(root/'admission.json', admission)
            with self.assertRaisesRegex(ValueError, 'conversation'): build(*args)
            self.assertFalse(args[-1].exists())


if __name__ == '__main__': unittest.main()
