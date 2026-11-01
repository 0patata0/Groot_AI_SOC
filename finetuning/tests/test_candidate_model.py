import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import candidate_model as c


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.output=self.root/'main';self.output.mkdir()
        (self.output/'adapter').mkdir();(self.output/'checkpoint-4').mkdir();self.data=self.root/'data';self.data.mkdir()
        for p in (self.output/'adapter/adapter_model.safetensors',self.output/'checkpoint-4/adapter_model.safetensors'):p.write_bytes(b'fixture')
        self.sha=c.digest(self.output/'adapter/adapter_model.safetensors')
        self.base=self.root/'base-manifest.json';self.put(self.base,{'verified':True,'model':'base','revision':'r'})
        provenance={'model':'base','revision':'r','manifest_sha256':c.digest(self.base)}
        for split in ('train','validation','test'):(self.data/(split+'.jsonl')).write_text('{}\n')
        self.put(self.output/'progress.json',{'status':'completed','step':4,'max_steps':4})
        self.put(self.output/'trainer_state.json',{'global_step':4,'max_steps':4})
        self.put(self.output/'eval_results.json',{'eval_loss':0.4})
        self.put(self.output/'tokenization_report.json',{'train':{'kept':1},'validation':{'kept':1}})
        self.put(self.output/'run_manifest.json',{'base_artifact_manifest':provenance,'config':{'base_artifact_manifest':provenance},
            'data':{'sha256':{s:c.digest(self.data/(s+'.jsonl')) for s in ('train','validation','test')},'records':{s:1 for s in ('train','validation','test')}}})

    def put(self,p,v):p.write_text(json.dumps(v))
    def check(self):return c.metadata(self.output,self.base,self.data,self.sha)

    def test_completed_metadata_is_not_a_quality_pass(self):
        result=self.check();self.assertFalse(result['quality_passed']);self.assertFalse(result['automatic_promotion'])

    def test_training_only_and_nonfinite_validation_are_rejected(self):
        self.put(self.output/'progress.json',{'status':'completed_training_validation_pending','step':4,'max_steps':4})
        with self.assertRaises(ValueError):self.check()
        self.put(self.output/'progress.json',{'status':'completed','step':4,'max_steps':4})
        self.put(self.output/'eval_results.json',{'eval_loss':float('nan')})
        with self.assertRaises(ValueError):self.check()

    def test_changed_data_base_or_checkpoint_is_rejected(self):
        for path in (self.data/'test.jsonl',self.base,self.output/'checkpoint-4/adapter_model.safetensors'):
            original=path.read_bytes();path.write_bytes(original+b' ')
            with self.assertRaises(ValueError):self.check()
            path.write_bytes(original)

    def test_missing_token_coverage_is_rejected(self):
        self.put(self.output/'tokenization_report.json',{'train':{'kept':0},'validation':{'kept':1}})
        with self.assertRaises(ValueError):self.check()

    def test_source_notices_and_merged_adapter_are_bound(self):
        receipt={'status':'verified','finite_tensors':380,'lora_pairs':190,'automatic_promotion':False,'model':c.MODEL,'adapter_sha256':'a'*64}
        self.put(self.root/'training-verification.json',receipt)
        with self.assertRaises(ValueError):c.verified_receipt(self.root,{'adapter_sha256':'b'*64})
        notices=self.root/'source-notices';notices.mkdir()
        for name in c.NOTICES:(notices/name).write_text('fixture attribution')
        receipt['source_notices']={n:c.digest(notices/n) for n in c.NOTICES};self.put(self.root/'training-verification.json',receipt)
        self.assertIn('not institutional certification',c.source_notice(self.root))
        conversion={'adapter_sha256':'a'*64,'training_verification_sha256':c.digest(self.root/'training-verification.json')}
        self.assertEqual(c.verify_conversion(self.root,conversion)['adapter_sha256'],'a'*64)
        with self.assertRaises(ValueError):c.verify_conversion(self.root,{**conversion,'adapter_sha256':'b'*64})
        with self.assertRaises(ValueError):c.verify_conversion(self.root,{**conversion,'training_verification_sha256':'0'*64})
        (notices/c.NOTICES[0]).write_text('changed')
        with self.assertRaises(ValueError):c.source_notice(self.root)


if __name__=='__main__':unittest.main()
