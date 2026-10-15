"""Local stdlib contract checks; no native process or operating paths accessed."""
import collections
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('load_fixture', HERE/'run-load-b.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
base = module.load_base(HERE.parent/'correlation-diagnosis/run-isolated-b.py')


class Contract(unittest.TestCase):
    def test_frozen_helper(self):
        self.assertEqual(module.BASE_SHA, base.digest(HERE.parent/'correlation-diagnosis/run-isolated-b.py'))

    def test_groups_identities_and_negatives(self):
        rows = module.dataset(base,HERE.parent/'fixtures/correlation','a'*32,groups=2)
        self.assertEqual(len(rows),30)
        for group in range(2):
            events = rows[group*15:(group+1)*15]
            decoded = [json.loads(row['text']) for row in events]
            self.assertEqual(len({row['run_id'] for row in events}),1)
            self.assertEqual([row['capstone_validation']['load_sequence'] for row in decoded],list(range(group*15+1,(group+1)*15+1)))
            self.assertEqual(len({row['event_id'] for row in events[:5]}),5)
            self.assertEqual(len({row['event_id'] for row in events[7:12]}),1)
            self.assertEqual(len({row['event_id'] for row in events[12:]}),3)
            self.assertTrue(all(row['capstone_norm']['correlation_eligible'] is False for row in decoded[12:]))
            self.assertTrue(all(row['capstone_norm']['correlation_time_class']=='historical' for row in decoded[12:]))
            self.assertTrue(all(row['wire'].endswith(b'\0') and len(row['wire'])<6000 for row in events))
        self.assertNotEqual(rows[0]['run_id'],rows[15]['run_id'])

    def test_missing_and_extra_never_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            obs=module.Observer(base,Path(tmp),[])
            obs.group_leaves=collections.Counter({(0,'100293'):2,(0,'100294'):1,(1,'100294'):1})
            result=obs.summary(2)
            self.assertFalse(result['exact_group_expectations'])
            self.assertEqual(result['group_leaf_mismatches'],[
                {'group':0,'rule_id':'100293','actual':2,'expected':1},
                {'group':1,'rule_id':'100293','actual':0,'expected':1}])

    def test_incremental_partial_and_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'records'
            reader=module.JsonLines(path)
            path.write_bytes(b'{"a":1}\n{"a":')
            self.assertEqual(reader.poll(),[{'a':1}])
            self.assertFalse(reader.at_eof())
            with path.open('ab') as handle:
                handle.write(b'2}\n')
            self.assertEqual(reader.poll(),[{'a':2}])
            self.assertTrue(reader.at_eof())
            path.write_bytes(b'')
            with self.assertRaisesRegex(RuntimeError,'trial_log_identity_or_bound'):
                reader.poll()

    def test_historical_leaf_rejected(self):
        events=module.dataset(base,HERE.parent/'fixtures/correlation','b'*32,groups=1)
        with tempfile.TemporaryDirectory() as tmp:
            prefix=Path(tmp)
            path=prefix/'logs/archives/archives.json'
            path.parent.mkdir(parents=True)
            value=json.loads(events[12]['text'])
            row={'data':value,'agent':{'id':'000'},'location':base.LOCATION,
                 'rule':{'id':'100293'},'full_log':events[12]['text']}
            path.write_text(json.dumps(row)+'\n')
            obs=module.Observer(base,prefix,events)
            obs.sent_ns[13]=0
            with self.assertRaisesRegex(RuntimeError,'leaf_wrong_scenario'):
                obs.poll()

    def test_private_native_dated_hardlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'current.json'
            path.write_text('{"a":1}\n')
            dated=Path(tmp)/'2026/Oct/archive-14.json'
            dated.parent.mkdir(parents=True)
            os.link(path,dated)
            reader=module.JsonLines(path)
            self.assertEqual(reader.poll(),[{'a':1}])

    def test_foreign_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'private').mkdir()
            path=root/'private/current.json';path.write_text('{}\n')
            os.link(path,root/'outside.json')
            with self.assertRaisesRegex(RuntimeError,'native_log_hardlink_not_private'):
                module.JsonLines(path).poll()

    def test_missing_state_preserves_first_error(self):
        value=module.state_summary([])
        self.assertFalse(value['available'])
        self.assertEqual(value['final_counters'],{})

    def test_numeric_state_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'state'
            path.write_text("# metadata\nevents_received='42'\nevents_dropped='0'\nqueue_usage='0.5'\ntext='sensitive'\ninvalid=NaN\n")
            value=module.native_state(path)['values']
            self.assertEqual(value,{'events_received':42,'events_dropped':0,'queue_usage':.5})

    def test_quantiles(self):
        self.assertEqual(module.quantiles([3,1,2]),{'p50':2,'p95':3,'p99':3,'max':3})
        self.assertIsNone(module.quantiles([]))


if __name__ == '__main__':
    unittest.main()
