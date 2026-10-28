import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from audit_training_provenance import bind_run,check_corpus,source_path

class TrainingProvenanceTests(unittest.TestCase):
    def fixture(self,root):
        folder=root/'data';folder.mkdir();server={};outputs={}
        for split in ('train','validation','test'):
            data=(json.dumps({'id':split})+'\n').encode();name=split+'.jsonl';(folder/name).write_bytes(data);server[name]=hashlib.sha256(data).hexdigest();outputs[split]={'records':1,'sha256':server[name]}
        (folder/'manifest.json').write_text(json.dumps({'outputs':outputs}));return folder,server
    def test_local_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder,server=self.fixture(Path(d));(folder/'train.jsonl').write_text('{}\n')
            with self.assertRaisesRegex(ValueError,'Local manifest'):check_corpus(folder,server)
    def test_server_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            folder,server=self.fixture(Path(d));server['test.jsonl']='0'*64
            with self.assertRaisesRegex(ValueError,'Server corpus'):check_corpus(folder,server)
    def test_run_cannot_claim_a_different_dataset(self):
        checks=[{'path':'finetuning/data/'+s+'.jsonl','records':1,'sha256':'a'*64} for s in ('train','validation','test')]
        run={'config':{'data_dir':'/workspace/data'},'data':{'sha256':{s:'b'*64 for s in ('train','validation','test')},'records':{s:1 for s in ('train','validation','test')}}}
        with self.assertRaisesRegex(ValueError,'Run corpus'):bind_run(run,{'data':checks})
    def test_untrusted_source_paths_are_rejected(self):
        for name in ['/etc/passwd','datasets/processed/ait/../../../secret','elsewhere/a.labeled.jsonl']:
            with self.subTest(name=name),self.assertRaises(ValueError):source_path(Path('/tmp'),name)

if __name__=='__main__':unittest.main()
