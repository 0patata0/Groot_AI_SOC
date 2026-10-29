import importlib.util
from array import array
import json
import tempfile
from unittest.mock import patch
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('evaluation_repro',Path(__file__).parents[1]/'reproduce_evaluation.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RepeatAudit(unittest.TestCase):
    def test_same_adapter_and_mode_are_compared_independently(self):
        rows=[{'adapter':a,'mode':mode,'per_example_loss':v} for a,mode,v in
              [('ref','current',[1.,2.]),('new','current',[8.,9.]),('ref','current',[1.,2.25]),
               ('ref','deterministic',[4.,4.]),('ref','deterministic',[4.,4.])]]
        result={(r['adapter'],r['mode']):r for r in m.compare_repeats(rows)}
        self.assertEqual(result['ref','current']['maximum_repeat_loss_difference'],.25)
        self.assertEqual(result['ref','deterministic']['maximum_repeat_loss_difference'],0.)
        self.assertEqual(result['new','current']['runs'],1)

    def test_nonfinite_empty_and_different_observation_counts_refused(self):
        for values in ([float('nan')],[],[float('inf')]):
            with self.assertRaises(ValueError):m.compare_repeats([{'adapter':'a','mode':'m','per_example_loss':values}])
        with self.assertRaises(ValueError):m.compare_repeats([
            {'adapter':'a','mode':'m','per_example_loss':[1.]},
            {'adapter':'a','mode':'m','per_example_loss':[1.,2.]}])


class PreparationAudit(unittest.TestCase):
    def test_actual_integer_array_storage_has_canonical_fingerprint(self):
        rows=[{'input_ids':array('i',[9,8]),'labels':array('i',[-100,8]),
               'attention_mask':array('b',[1,1]),'record_id':'r'}]
        plain=[{'input_ids':[9,8],'labels':[-100,8],'attention_mask':[1,1],'record_id':'r'}]
        self.assertEqual(m.token_fingerprint(rows),m.token_fingerprint(plain))
        plain[0]['labels'][1]=7
        self.assertNotEqual(m.token_fingerprint(rows),m.token_fingerprint(plain))

    def test_unsupported_metadata_is_not_silently_coerced(self):
        for value in [object(),float('nan'),array('f',[1.]),{1:'non-string key'}]:
            with self.assertRaises(ValueError):m.token_fingerprint([value])

    def test_preparation_failure_is_recorded_and_prior_output_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'new'
            with patch.object(m,'run_evaluation',side_effect=TypeError('preparation failed')):
                with self.assertRaises(TypeError):m.evaluate(Path(temp),output,True)
            report=json.loads((output/'report.json').read_text())
            self.assertEqual(report['status'],'failed')
            self.assertEqual(report['failed_phase'],'preparing')
            self.assertEqual(report['training_updates'],0)
            with self.assertRaises(ValueError):m.evaluate(Path(temp),output)
            self.assertEqual(json.loads((output/'report.json').read_text()),report)


if __name__=='__main__':unittest.main()
