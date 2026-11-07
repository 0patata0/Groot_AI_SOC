import importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'finetuning'))
spec=importlib.util.spec_from_file_location('archive_storage',ROOT/'datasets/archive_storage.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class StorageTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.root=Path(self.t.name).resolve();self.repo=self.root/'repo';self.repo.mkdir()
  records={}
  for kind,rel in [('original','datasets/raw/source.bin'),('cleaned','finetuning/data-case/train.jsonl')]:
   p=self.repo/rel;p.parent.mkdir(parents=True);p.write_bytes(b'raw\x00\xff'if kind=='original'else b'{"data":"utf8"}\n')
   records[kind]=[{'member':rel,'source':str(p),'bytes':p.stat().st_size,'sha256':m.digest(p),'remove':True}]
  self.plan=self.root/'plan.json';self.plan.write_text(json.dumps({'schema':'groot-dataset-migration-v1','archives':records}))
  self.stage=self.root/'stage';self.store=self.repo/'datasets/archives'
 def prepared(self):
  m.create(self.plan,self.stage);m.install(self.stage,self.store)
 def test_round_trip_and_exact_cleanup_preserve_unselected(self):
  self.prepared();keep=self.repo/'datasets/raw/keep';keep.write_text('user file')
  with patch.object(m.subprocess,'check_output',return_value=b''):
   r=m.prune(self.plan,self.store,self.repo)
  self.assertEqual(r['removed_exact_files'],2);self.assertTrue(keep.exists())
  m.restore(self.store,self.root/'restore','original')
  self.assertEqual((self.root/'restore/datasets/raw/source.bin').read_bytes(),b'raw\x00\xff')
  self.assertEqual({p.name for p in self.store.iterdir()},{'original.tar.gz','cleaned.tar.gz','catalog.json'})
 def test_changed_source_refuses_all_deletion(self):
  self.prepared();p=self.repo/'datasets/raw/source.bin';p.write_bytes(b'changed')
  with self.assertRaises(ValueError):m.prune(self.plan,self.store,self.repo)
  self.assertTrue((self.repo/'finetuning/data-case/train.jsonl').exists())
 def test_tracked_source_refuses_all_deletion(self):
  self.prepared()
  with patch.object(m.subprocess,'check_output',return_value=b'finetuning/data-case/train.jsonl\0'),self.assertRaises(ValueError):m.prune(self.plan,self.store,self.repo)
  self.assertTrue((self.repo/'datasets/raw/source.bin').exists())
 def test_corrupt_archive_refuses_all_deletion(self):
  self.prepared();p=self.store/'cleaned.tar.gz';p.write_bytes(p.read_bytes()+b'changed')
  with patch.object(m.subprocess,'check_output',return_value=b''),self.assertRaises(ValueError):m.prune(self.plan,self.store,self.repo)
  self.assertTrue((self.repo/'datasets/raw/source.bin').exists())
 def test_existing_store_is_not_overwritten(self):
  self.prepared()
  with self.assertRaises(ValueError):m.install(self.stage,self.store)
if __name__=='__main__':unittest.main()
