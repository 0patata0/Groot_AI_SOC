from pathlib import Path
import sys,json,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dialogue_encoding import encode_dialogue,tokenize_dialogues
from test_train import FakeTokenizer,conversation
import train
class DialogueTests(unittest.TestCase):
 def test_all_assistant_targets_kept_once_and_other_roles_remain_masked(self):
  source=conversation();tok=FakeTokenizer();encoded,reason=encode_dialogue(source,tok,4096,train.encode_completion);self.assertIsNone(reason)
  batch=train.collate_lists([encoded],0);targets=''.join(chr(x) for x in batch['labels'][0] if x!=-100)
  self.assertIn('Earlier assistant',targets);self.assertIn('Final fixture conclusion',targets);self.assertNotIn('Fixture observation',targets);self.assertNotIn('Fixture question',targets);self.assertNotIn('Fixture system',targets);self.assertEqual(encoded['prefix_identity']['supervised_assistant_indices'],[2,4])
 def test_full_row_supervision_equals_union_of_original_turn_targets(self):
  row=conversation();tok=FakeTokenizer();full,_=encode_dialogue(row,tok,4096,train.encode_completion);actual=[x for x in train.collate_lists([full],0)['labels'][0] if x!=-100];expected=[]
  for index,m in enumerate(row['messages']):
   if m['role']=='assistant':
    feature,_=train.encode_completion({**row,'messages':row['messages'][:index+1]},tok,4096);expected.extend(list(feature['input_ids'])[feature['prompt_length']:])
  self.assertEqual(actual,expected)
 def test_call_arguments_and_tool_names_are_supervised_but_result_is_not(self):
  row=conversation();full,_=encode_dialogue(row,FakeTokenizer(),4096,train.encode_completion);text=''.join(chr(x) for x in train.collate_lists([full],0)['labels'][0] if x!=-100);self.assertIn('lookup',text);self.assertNotIn('Fixture observation',text)
 def test_overlength_does_not_drop_only_one_turn_silently(self):
  row=conversation();encoded,reason=encode_dialogue(row,FakeTokenizer(),20,train.encode_completion);self.assertIsNone(encoded);self.assertEqual(reason,'over_max_length')
 def test_stats_distinguish_conversations_from_covered_turns(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'data.jsonl';p.write_text(json.dumps(conversation())+'\n');rows,stats=tokenize_dialogues(p,FakeTokenizer(),4096,0,train.encode_completion);self.assertEqual(stats['kept'],1);self.assertEqual(stats['covered_assistant_turns'],2);train.check_token_coverage(stats,True);stats['covered_assistant_turns']=1
   with self.assertRaisesRegex(ValueError,'excluded'):train.check_token_coverage(stats,True)
if __name__=='__main__':unittest.main()
