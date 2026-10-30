"""Guard source separation, unchanged rows and non-equivalent exposure metrics."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_soc_pilot import choose_replay, group_partitions, statistics, load_inventory, sha


class PilotTests(unittest.TestCase):
    def cases(self):
        return [{'id': str(i), 'split': 'train', 'group': 'g'+str(i//2),
                 'provider': 'p2' if i >= 8 else 'p1', 'mappings': [{'id': 'T'+str(i)}]} for i in range(12)]

    def test_selection_is_order_independent_without_duplicate_source_groups(self):
        c = self.cases();a = choose_replay(c, 4);b = choose_replay(list(reversed(c)), 4)
        self.assertEqual(a, b);self.assertEqual(len({x['group'] for x in a}), 4)
        self.assertEqual({x['provider'] for x in a}, {'p1','p2'})

    def test_training_only_even_when_requested_count_small(self):
        c = self.cases();c[-1]['split'] = 'test'
        with self.assertRaises(ValueError): choose_replay(c, 2)

    def test_group_shortage_cannot_be_filled_by_rewordings(self):
        c = self.cases()
        with self.assertRaises(ValueError): choose_replay(c, 7)

    def test_duplicate_identity_or_mapping_rejected(self):
        c = self.cases();c.append(deepcopy(c[0]))
        with self.assertRaises(ValueError): choose_replay(c, 2)
        c = self.cases();c[0]['mappings'].append(c[0]['mappings'][0])
        with self.assertRaises(ValueError): choose_replay(c, 2)

    def test_provider_coverage_cannot_be_silently_dropped(self):
        with self.assertRaises(ValueError): choose_replay(self.cases(), 1)

    def test_related_report_split_conflict_detected(self):
        c = self.cases();c[1]['split'] = 'validation'
        with self.assertRaises(ValueError): group_partitions(c)
        c = self.cases();self.assertEqual(group_partitions(c)['train'], 6)

    def test_rows_tokens_and_gradients_are_not_equated(self):
        stats = statistics({'short':['a'], 'long':['b']}, {
            'a': {'tokens':5,'supervised_tokens':1,'assistant_turns':1},
            'b': {'tokens':12,'supervised_tokens':9,'assistant_turns':1}})
        self.assertEqual(stats['categories']['short']['row_share_percent'], 50)
        self.assertEqual(stats['categories']['short']['target_token_share_percent'], 10)
        self.assertFalse(stats['gradient_contribution_measured'])

    def fixture(self, root):
        manifest = {'status':'separate_candidate_inventory_not_training_release','training_admitted':0,
                    'V4_observation_revision':{'records':126},'pool_files':{}}
        measurements = {};counter = 0
        for name, count in [('cti-replay-candidates.jsonl',1024),('observation-candidates.jsonl',143),('optional-harness-candidates.jsonl',30)]:
            rows = [{'id': str(counter+i)} for i in range(count)];counter += count
            raw = ''.join(json.dumps(r)+'\n' for r in rows).encode();(root/name).write_bytes(raw)
            manifest['pool_files'][name] = {'rows':count,'sha256':sha(raw)}
            measurements[name] = {'rows':count,'alignment_errors':{},'over_4096':0,
                'records':[{'id':r['id'],'tokens':10,'supervised_tokens':2,'assistant_turns':1,'truncated':False,'over_4096':False} for r in rows]}
        raw = json.dumps(manifest).encode();(root/'manifest.json').write_bytes(raw)
        proof = {'state':{'Running':False,'ExitCode':0,'OOMKilled':False},'token_check':{
            'manifest_sha256':sha(raw),'pool_files':manifest['pool_files'],
            'all_fit_4096_and_aligned':True,'rows_dropped':0,'truncated':False,'measurements':measurements}}
        path=root/'proof.json';path.write_text(json.dumps(proof));return path,proof

    def test_all_ids_covered_by_successful_token_proof(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path,p=self.fixture(root)
            self.assertEqual(len(load_inventory(root,path)[2]),1197)

    def test_still_running_or_failed_gate_not_reused(self):
        for changes in ({'Running':True},{'ExitCode':2},{'OOMKilled':True}):
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);path,p=self.fixture(root);p['state'].update(changes);path.write_text(json.dumps(p))
                with self.assertRaises(ValueError):load_inventory(root,path)

    def test_missing_token_row_cannot_disappear_from_denominator(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path,p=self.fixture(root)
            p['token_check']['measurements']['observation-candidates.jsonl']['records'].pop();path.write_text(json.dumps(p))
            with self.assertRaises(ValueError):load_inventory(root,path)

    def test_different_corpus_or_truncation_refused(self):
        for key,value in [('manifest_sha256','a'*64),('rows_dropped',1),('truncated',True)]:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);path,p=self.fixture(root);p['token_check'][key]=value;path.write_text(json.dumps(p))
                with self.assertRaises(ValueError):load_inventory(root,path)

    def test_modified_row_bytes_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path,p=self.fixture(root);(root/'observation-candidates.jsonl').write_bytes(b'{}\n')
            with self.assertRaises(ValueError):load_inventory(root,path)


if __name__ == '__main__':unittest.main()
