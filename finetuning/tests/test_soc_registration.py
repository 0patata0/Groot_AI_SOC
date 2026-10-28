import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from register_soc import parameters,verify_runtime,candidate_name
from soc_evaluate import select_cases


class CandidateTests(unittest.TestCase):
    def test_checkpoint_models_have_distinct_names_and_cannot_replace_original(self):
        names={candidate_name(v) for v in ('base','main','v2-step24','v2-step48')}
        self.assertEqual(len(names),4);self.assertNotIn('qwen3.6:35b',names)
        self.assertTrue(candidate_name('v2-step24').endswith('20261028'))
        with self.assertRaises(ValueError):candidate_name('../arbitrary')
    def test_runtime_options_preserve_numbers_and_repeated_stops(self):
        value=parameters('temperature 0.6\ndraft_num_predict 2\nstop "<|im_end|>"\nstop "a\\nb"\n')
        self.assertEqual(value,{'temperature':0.6,'draft_num_predict':2,'stop':['<|im_end|>','a\nb']})
        with self.assertRaises(ValueError):parameters('temperature 0.6\ntemperature 0\n')

    def test_full_evaluation_includes_each_test_variant_without_train_or_validation(self):
        cases=[{'id':i,'split':split,'scenario_group':'one'} for i,split in enumerate(['train','test','validation','test'])]
        self.assertEqual([c['id'] for c in select_cases(cases,8)],[1])
        self.assertEqual([c['id'] for c in select_cases(cases,8,all_cases=True)],[1,3])

    def test_native_hf_template_and_exact_weight_blobs_are_required(self):
        original={'template':'{{ .Prompt }}','parameters':'temperature 1','details':{'runner':'llamacpp'},'capabilities':['tools','vision']}
        files={'text':'sha256:'+'a'*64,'projector':'sha256:'+'b'*64}
        show={**original,'template':'pinned HF Jinja','details':{'runner':'llamacpp','quantization_level':'Q4_K_M'},'projector_info':{'present':True},
              'modelfile':'FROM /models/blobs/sha256-'+'a'*64+'\nFROM /models/blobs/sha256-'+'b'*64+'\n'}
        result=verify_runtime(original,show,'pinned HF Jinja',files)
        self.assertTrue(result['chat_template_matches_hf']);self.assertFalse(result['chat_template_matches_original'])
        for change in [{'template':'different HF'},{'parameters':'temperature 0'},{'capabilities':['tools']},{'modelfile':'FROM unrelated'}]:
            with self.assertRaises(ValueError):verify_runtime(original,{**show,**change},'pinned HF Jinja',files)


if __name__=='__main__':unittest.main()
