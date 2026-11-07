import json,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import prepare_operator_release as release
from prepare_operator_run import select_smoke

class AdmissionTests(unittest.TestCase):
 def test_reused_initial_call_id_uses_actual_train_split(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);old=p/'data-joint-sft-20261101-r3';old.mkdir()
   (old/'token-review.json').write_text('{"artifacts":{}}')
   row={'id':'prior-initial-call','source':'prior','messages':[{'role':'assistant','content':'answer'}]}
   for name,values in [('train.candidates.jsonl',[row]),('fallback.candidates.jsonl',[]),('validation.jsonl',[]),('test.jsonl',[])]:release.dump(p/name,values)
   release.dump(p/'token-input.jsonl',[{'split':'train','row':row}])
   (p/'receipt.json').write_text(json.dumps({'input_sha256':'input','max_length':4096,'truncation':False,'weights_loaded':False,'gpu_training_started':False,'artifacts':{},'records':[{'split':'train','id':row['id'],'reason':None,'tokens':17}]}))
   with patch.object(release,'ROOT',p),patch.object(release,'verify_module',return_value={'token_input_sha256':'input','validation_rows':0,'test_rows':0}):
    result=release.admit(p,p/'receipt.json')
   self.assertEqual(result['train_rows'],1);self.assertEqual(result['total_tokens'],17)
 def test_smoke_covers_history_and_both_worst_cases(self):
  largest={'id':'large','messages':[{'role':'user'},{'role':'assistant'}]}
  multi={'id':'tools','messages':[{'role':x}for x in ['assistant','tool','assistant','tool','assistant']]}
  history={'id':'followup','preserve_empty_thinking_history':True,'messages':[{'role':x}for x in ['user','assistant','user','assistant']]}
  self.assertEqual({r['id']for r in select_smoke([largest,multi,history],{'large':4000,'tools':3000,'followup':2000})},{'large','tools','followup'})
 def test_legacy_smoke_remains_two_examples(self):
  rows=[{'id':'a','messages':[{'role':'assistant'}]},{'id':'b','messages':[{'role':x}for x in ['assistant','tool','assistant','tool','assistant']]}]
  self.assertEqual(len(select_smoke(rows,{'a':4000,'b':3000})),2)

if __name__=='__main__':unittest.main()
