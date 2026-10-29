import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('training_repro',Path(__file__).parents[1]/'reproduce_training.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class TrainingTrialScope(unittest.TestCase):
    def test_only_profile_and_output_change(self):
        original={'max_steps':2,'max_train_samples':2,'max_eval_samples':8,
                  'gradient_accumulation_steps':1,'smoke_longest_prefixes':True,
                  'seed':42,'learning_rate':5e-7,'gradient_checkpointing':True,'output_dir':'old'}
        updated=m.trial_config(original,Path('/trial'))
        self.assertEqual({k for k in updated if updated[k]!=original.get(k)},
                         {'output_dir','deterministic_training'})
        self.assertEqual(original['output_dir'],'old')
        for key in ('max_steps','max_train_samples','max_eval_samples','gradient_accumulation_steps'):
            wrong={**original,key:99}
            with self.assertRaises(ValueError):m.trial_config(wrong,Path('/trial'))

if __name__=='__main__':unittest.main()
