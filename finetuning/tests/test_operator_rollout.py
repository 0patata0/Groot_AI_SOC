"""A failed first action must never be repaired with unseen gold observations."""
import copy,json
from pathlib import Path
import unittest
from operator_rollout import replay
from soc_operator_curriculum import make_case
CATALOG=json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.json').read_text())
class RolloutTests(unittest.TestCase):
 def test_correct_sequential_fixture_completes(self):
  c=make_case('service_proposal','validation',0);responses=iter(copy.deepcopy([m for m in c['messages'] if m['role']=='assistant']))
  r=replay(c,CATALOG,lambda m,t:next(responses));self.assertEqual(r['provisional_score'],100);self.assertEqual(r['observed_steps'],3)
 def test_omitted_call_cannot_receive_gold_evidence(self):
  c=make_case('service_proposal','validation',0);seen=[]
  def generate(m,t):seen.append(m);return {'role':'assistant','content':c['messages'][-1]['content']}
  r=replay(c,CATALOG,generate);self.assertEqual(r['provisional_score'],0);self.assertEqual(len(seen),1);self.assertEqual(r['observed_steps'],0);self.assertFalse(any(m['role']=='tool' for m in seen[0]))
 def test_wrong_target_stops_before_gold_observation(self):
  c=make_case('service_proposal','validation',0);wrong=copy.deepcopy(c['messages'][2]);wrong['tool_calls'][0]['function']['arguments']['target']='a:raw-suricata'
  r=replay(c,CATALOG,lambda m,t:wrong);self.assertEqual(r['observed_steps'],0);self.assertIn('unexpected_or_wrong_call',r['issues'])
 def test_equivalent_edit_anchor_is_accepted_when_full_candidate_matches(self):
  c=make_case('rule_proposal','validation',0);rows=copy.deepcopy([m for m in c['messages'] if m['role']=='assistant']);edit=rows[1]['tool_calls'][0]['function']['arguments']['edits'][0];edit.update(old_text='msg:"WEB Lab Typo"',new_text='msg:"WEB Lab Correct"');responses=iter(rows)
  self.assertEqual(replay(c,CATALOG,lambda m,t:next(responses))['provisional_score'],100)
 def test_unmodelled_valid_read_is_unscored_without_gold_injection(self):
  c=make_case('verify_applied','validation',0);row=copy.deepcopy(c['messages'][2]);row['tool_calls'][0]['function']={'name':'mcp__rule_a__get_service_action_target','arguments':{'target':'a:suricata'}}
  r=replay(c,CATALOG,lambda m,t:row);self.assertIsNone(r['provisional_score']);self.assertEqual(r['observed_steps'],0);self.assertIn('unmodelled_read_branch',r['issues'])
 def test_proposal_reason_does_not_need_memorized_reference(self):
  c=make_case('service_proposal','validation',0);rows=copy.deepcopy([m for m in c['messages'] if m['role']=='assistant']);rows[2]['tool_calls'][0]['function']['arguments']['reason']='사용자가 요청한 통제 재시작; 승인 후 IDS 탐지 중단 확인';responses=iter(rows)
  self.assertEqual(replay(c,CATALOG,lambda m,t:next(responses))['provisional_score'],100)
if __name__=='__main__':unittest.main()
