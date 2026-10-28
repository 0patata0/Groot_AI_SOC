"""Reject SOC workflow errors that input-schema validation alone cannot catch."""
import copy,json,shutil,tempfile
from pathlib import Path
import unittest
from soc_operator_curriculum import ROOT,audit,build,make_case,verify_workflow,projections,contract_source
CATALOG=json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.json').read_text())
class OperatorTests(unittest.TestCase):
 def test_portable_projection_sources_work_without_full_infra_checkout(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);target=root/'finetuning/contract_sources';target.mkdir(parents=True)
   for name in ('security-events-mcp.py','system-diagnostics-mcp.py'):
    shutil.copyfile(contract_source(name),target/name)
   self.assertEqual(len(projections(root)),2)
 def test_all_workflows_preserve_bound_observations(self):
  self.assertEqual(audit(build(),CATALOG)['records'],{'train':192,'validation':48,'test':48})
 def test_runtime_cannot_be_replaced_by_systemd_properties(self):
  c=make_case('service_proposal','train',0);c['messages'][3]['content']=json.dumps({'kind':'systemd','properties':{'ActiveState':'active'}})
  with self.assertRaisesRegex(ValueError,'runtime'):verify_workflow(c,CATALOG)
 def test_proposal_cannot_use_a_valid_but_invented_hash(self):
  c=make_case('service_proposal','train',0);c['messages'][6]['tool_calls'][0]['function']['arguments']['base_state_sha256']='f'*64
  c['checks']['expected_calls'][2]['arguments']['base_state_sha256']='f'*64
  with self.assertRaisesRegex(ValueError,'hash'):verify_workflow(c,CATALOG)
 def test_pending_temporary_block_is_already_owned(self):
  c=make_case('containment_pending','train',0);p=json.loads(c['messages'][-2]['content']);p['live_block_state']='absent';c['messages'][-2]['content']=json.dumps(p)
  with self.assertRaisesRegex(ValueError,'retention'):verify_workflow(c,CATALOG)
 def test_pending_service_cannot_be_reported_complete(self):
  c=make_case('service_proposal','train',0);c['messages'][-1]['content']=c['messages'][-1]['content'].replace('아직 적용하지','적용 완료')
  with self.assertRaises(ValueError):verify_workflow(c,CATALOG)
 def test_failure_does_not_become_resolved(self):
  c=make_case('verify_failed','train',0);c['messages'][-1]['content']=c['messages'][-1]['content'].replace('needs_review','resolved')
  with self.assertRaisesRegex(ValueError,'Failed'):verify_workflow(c,CATALOG)
 def test_numeric_ids_cannot_hide_test_leakage(self):
  a=make_case('correlation','train',0);b=make_case('correlation','test',0);b['messages'][1]['content']=a['messages'][1]['content'];b['scenario_group']='renamed';b['template_family']='renamed'
  with self.assertRaisesRegex(ValueError,'overlap'):audit([a,b],CATALOG)
 def test_containment_query_window_matches_actual_arguments(self):
  c=make_case('containment_pending','train',0);self.assertEqual(json.loads(c['messages'][3]['content'])['lookback_minutes'],5)
if __name__=='__main__':unittest.main()
