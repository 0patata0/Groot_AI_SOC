"""Trace actual accepted backward passes while preserving model kwargs/loss."""
from pathlib import Path
from types import SimpleNamespace
import json,tempfile,unittest
from training_lineage import META,prefix_identity,recorded_trainer
class FakeTrainer:
 state=SimpleNamespace(global_step=12)
 def compute_loss(self,model,inputs,*a,**k):assert META not in inputs;return inputs['loss']
 def prediction_step(self,model,inputs,*a,**k):assert META not in inputs;return inputs['loss']
 def training_step(self,model,inputs,*a,**k):
  if inputs.get('fail'):raise RuntimeError('backward failed')
  return self.compute_loss(model,inputs)
class LineageTests(unittest.TestCase):
 def test_identity_binds_row_and_assistant_turn(self):
  a=prefix_identity({'id':'x','source':'fixture','messages':[1]},2);b=prefix_identity({'id':'x','source':'fixture','messages':[2]},2);c=prefix_identity({'id':'x','source':'fixture','messages':[1]},4);self.assertNotEqual(a['prefix_id'],b['prefix_id']);self.assertNotEqual(a['prefix_id'],c['prefix_id'])
 def test_only_successful_backward_is_recorded_and_metadata_never_reaches_model(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'usage.jsonl';t=recorded_trainer(FakeTrainer,path)();identity=prefix_identity({'id':'x'},2)
   self.assertEqual(t.training_step(None,{'loss':.2,META:[identity]}),.2);row=json.loads(path.read_text());self.assertEqual(row['optimizer_step_before'],12);self.assertEqual(row['prefixes'],[identity]);self.assertNotIn('optimizer_update_completed',row)
   with self.assertRaises(RuntimeError):t.training_step(None,{'fail':True,'loss':.1,META:[identity]})
   self.assertEqual(len(path.read_text().splitlines()),1);self.assertEqual(t.prediction_step(None,{'loss':.3,META:[identity]}),.3)
if __name__=='__main__':unittest.main()
