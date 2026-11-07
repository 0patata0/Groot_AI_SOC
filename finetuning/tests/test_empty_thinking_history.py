import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import train
from dialogue_encoding import encode_dialogue

class LastUserTemplate:
 # Reproduce the observed Qwen condition: wrappers before last user are removed
 # unless preserve_thinking=True. This fixture is supplemented by real-token tests.
 def apply_chat_template(self,messages,**kwargs):
  last=max(i for i,m in enumerate(messages) if m['role']=='user');out=''
  for i,m in enumerate(messages):
   wrapper='<think>\n\n</think>\n\n' if m['role']=='assistant' and (i>last or kwargs.get('preserve_thinking')) else ''
   out+=m['role']+'\n'+wrapper+m['content']+'\nEND\n'
  return out
 def encode(self,text,**kwargs):return list(text.encode())

def source():
 return {'id':'followup','messages':[{'role':'system','content':'policy'}, {'role':'user','content':'observation'}, {'role':'assistant','content':'first answer'}, {'role':'user','content':'followup'}, {'role':'assistant','content':'final answer'}]}

class HistoryTests(unittest.TestCase):
 def test_original_failure_is_reproduced(self):
  value,reason=encode_dialogue(source(),LastUserTemplate(),4096,train.encode_completion)
  self.assertIsNone(value);self.assertEqual(reason,'conversation_prefix_mismatch')
 def test_opt_in_keeps_both_targets_and_masks_user(self):
  row=source();row['preserve_empty_thinking_history']=True
  encoded,reason=encode_dialogue(row,LastUserTemplate(),4096,train.encode_completion);self.assertIsNone(reason)
  target=bytes(x for x in train.collate_lists([encoded],0)['labels'][0] if x!=-100).decode()
  self.assertIn('first answer',target);self.assertIn('final answer',target)
  self.assertNotIn('observation',target);self.assertNotIn('followup',target);self.assertNotIn('policy',target)
 def test_nonempty_reasoning_refused(self):
  for change in [{'reasoning_content':'hidden details'},{'content':'<think>details</think>answer'}]:
   row=source();row['preserve_empty_thinking_history']=True;row['messages'][2].update(change)
   value,reason=train.encode_completion(row,LastUserTemplate(),4096)
   self.assertIsNone(value);self.assertEqual(reason,'nonempty_reasoning_history_refused')
 def test_truthy_string_refused(self):
  row=source();row['preserve_empty_thinking_history']='true'
  self.assertEqual(train.encode_completion(row,LastUserTemplate(),4096)[1],'invalid_empty_thinking_history_policy')
 def test_default_single_turn_tokenization_unchanged(self):
  row=source();single={**row,'messages':row['messages'][:3]}
  before,_=train.encode_completion(single,LastUserTemplate(),4096)
  single['preserve_empty_thinking_history']=True;after,_=train.encode_completion(single,LastUserTemplate(),4096)
  self.assertEqual(before['input_ids'],after['input_ids'])

if __name__=='__main__':unittest.main()
