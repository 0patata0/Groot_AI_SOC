import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from register_soc import parameters
from soc_evaluate import select_cases


class CandidateTests(unittest.TestCase):
    def test_runtime_options_preserve_numbers_and_repeated_stops(self):
        value=parameters('temperature 0.6\ndraft_num_predict 2\nstop "<|im_end|>"\nstop "a\\nb"\n')
        self.assertEqual(value,{'temperature':0.6,'draft_num_predict':2,'stop':['<|im_end|>','a\nb']})
        with self.assertRaises(ValueError):parameters('temperature 0.6\ntemperature 0\n')

    def test_full_evaluation_includes_each_test_variant_without_train_or_validation(self):
        cases=[{'id':i,'split':split,'scenario_group':'one'} for i,split in enumerate(['train','test','validation','test'])]
        self.assertEqual([c['id'] for c in select_cases(cases,8)],[1])
        self.assertEqual([c['id'] for c in select_cases(cases,8,all_cases=True)],[1,3])


if __name__=='__main__':unittest.main()
