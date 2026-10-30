"""Synthetic leakage/integrity regressions; no provider answers or model scores."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_soc_observation_history import read_frozen, compare_groups, safe_path


class HistoryTests(unittest.TestCase):
    def trace(self):
        return {'record_id': 'candidate', 'leakage_group': 'ait-lds-ads:fox',
                'partition': 'historical_training_candidate_only', 'training_admitted': False,
                'bindings': {'E01': {'member': 'gather/log', 'line': 4, 'sha256': 'a' * 64}}}

    def case(self, split='train'):
        return {'id': 'historical', 'split': split, 'source_uri': 'provider:fixture',
                'review': {'ait_environment': 'fox', 'source_rows': [
                    {'environment': 'fox', 'source_file': 'gather/log', 'source_line': 4,
                     'source_line_sha256': 'a' * 64}]}}

    def test_same_source_training_is_reuse_not_an_unseen_incident(self):
        result = compare_groups([self.trace()], [self.case()], [])
        self.assertEqual(result['candidates_reusing_v4_training_environments'], 1)
        self.assertEqual(result['shared_v4_cases'], 1)  # both metadata paths deduplicated
        self.assertEqual(len(result['exact_original_row_matches']), 1)
        self.assertFalse(result['known_held_out_group_conflicts'])

    def test_held_out_environment_blocks_even_when_words_differ(self):
        for split in ('validation', 'test'):
            result = compare_groups([self.trace()], [self.case(split)], [])
            self.assertEqual(result['known_held_out_group_conflicts'][0]['held_out_splits'], [split])

    def test_same_coordinate_changed_bytes_are_not_exact(self):
        case = self.case();case['review']['source_rows'][0]['source_line_sha256'] = 'b' * 64
        result = compare_groups([self.trace()], [case], [])
        self.assertFalse(result['exact_original_row_matches'])
        self.assertEqual(len(result['same_coordinate_different_hash']), 1)

    def test_processed_hash_domain_not_compared_to_original(self):
        case = self.case();case['review']['source_rows'][0]['source_file'] = 'datasets/processed/log'
        result = compare_groups([self.trace()], [case], [])
        self.assertEqual(result['v4_raw_rows_comparable'], 0)
        self.assertFalse(result['exact_original_row_matches'])
        self.assertEqual(result['shared_v4_cases'], 1)

    def test_partition_changes_rejected(self):
        for key, value in [('partition', 'test'), ('training_admitted', True)]:
            trace = self.trace();trace[key] = value
            with self.assertRaises(ValueError): compare_groups([trace], [], [])

    def fixture(self, root):
        spec = {'data_folder': 'data-history', 'source_cases': 'cases.jsonl',
                'data_sha256': {}, 'records': {s: 1 for s in ('train', 'validation', 'test')}}
        (root / 'data-history').mkdir()
        cases = []
        for split in spec['records']:
            raw = (json.dumps({'id': split, 'messages': []}) + '\n').encode()
            (root / 'data-history' / (split + '.jsonl')).write_bytes(raw)
            spec['data_sha256'][split] = hashlib.sha256(raw).hexdigest()
            cases.append({'id': split, 'split': split})
        raw = ''.join(json.dumps(c) + '\n' for c in cases).encode()
        (root / 'cases.jsonl').write_bytes(raw)
        spec['source_cases_sha256'] = hashlib.sha256(raw).hexdigest()
        return spec

    def test_modified_split_rejected_by_frozen_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);spec = self.fixture(root)
            self.assertEqual(read_frozen(root, spec)[1]['cases'], 3)
            (root / 'data-history/train.jsonl').write_text('{}\n')
            with self.assertRaises(ValueError): read_frozen(root, spec)

    def test_split_identity_mismatch_rejected_even_with_matching_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);spec = self.fixture(root)
            raw = (root / 'cases.jsonl').read_bytes().replace(b'"id": "train"', b'"id": "unknown"')
            (root / 'cases.jsonl').write_bytes(raw)
            spec['source_cases_sha256'] = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError): read_frozen(root, spec)

    def test_absent_split_and_unknown_partition_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d);spec = self.fixture(root)
            changed = deepcopy(spec);del changed['data_sha256']['test']
            with self.assertRaises(ValueError): read_frozen(root, changed)
            (root / 'data-history/test.jsonl').unlink()
            with self.assertRaises(FileNotFoundError): read_frozen(root, spec)

    def test_path_escape_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for path in ('../outside', '/etc/passwd'):
                with self.assertRaises(ValueError): safe_path(root, path)
            (root / 'link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): safe_path(root, 'link')


if __name__ == '__main__':
    unittest.main()
