"""Verify role evidence, dates and live state freshness without network/model use."""
import json,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from prepare_institutional import audit_time,field,live_cases,gap_cases,selected_ait_source
from soc_dataset import validate_case
CATALOG=json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.json').read_text())
class InstitutionalPreparationTests(unittest.TestCase):
 def test_unix_audit_timestamp_has_one_correct_kst_conversion(self):
  self.assertEqual(audit_time('type=USER_AUTH msg=audit(1642999060.603:2226): uid=33'),'2022-01-24T13:37:40.603000+09:00')
  with self.assertRaisesRegex(ValueError,'epoch'):audit_time('Jan 24 04:37:40 no offset; never invent it')
 def test_fields_are_copied_without_guessing_privilege_or_identity(self):
  line='type=USER_AUTH uid=33 acct="jhall" res=success';self.assertEqual(field(line,'acct'),'jhall');self.assertEqual(field(line,'uid'),'33');self.assertEqual(field(line,'pid'),'미기록')
 def test_live_example_calls_runtime_instead_of_memorizing_user_claim(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'snapshot.json';p.write_text(json.dumps({'observation':{'kind':'runtime','target':'a:suricata','observed_at_kst':'2026-10-29T02:44:00+09:00','status':'degraded','codes':['inspection_limit_reached'],'metrics':{'running':True,'rules_loaded':52497}}}))
   for c in live_cases(p):
    row=validate_case(c,CATALOG);self.assertEqual(c['checks']['expected_calls'][0]['arguments'],{'target':'a:suricata'});self.assertIn('다시 조회',c['messages'][-1]['content']);self.assertEqual(row['provenance']['review']['evidence_kind'],'captured_live_observation')
 def test_verified_source_lookup_does_not_depend_on_ad_hoc_retry_folder_names(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);folder=root/'fresh-snapshot';folder.mkdir();(folder/'russellmitchell-range-selected').mkdir();receipt={'status':'verified_selected_members','members':[{'path':'gather/log','sha256':'a'*64}]};(folder/'russellmitchell-range-acquisition.json').write_text(json.dumps(receipt));r,p=selected_ait_source(root,'russellmitchell');self.assertEqual(p.parent,folder)
   other=root/'another';other.mkdir();receipt['members'][0]['sha256']='b'*64;(other/'russellmitchell-range-acquisition.json').write_text(json.dumps(receipt))
   with self.assertRaisesRegex(ValueError,'Ambiguous'):selected_ait_source(root,'russellmitchell')
 def test_unsupported_forensics_cannot_invent_collection_or_new_tools(self):
  for c in gap_cases():
   validate_case(c,CATALOG);self.assertEqual(c['tool_names'],[]);self.assertEqual(c['checks']['expected_calls'],[]);self.assertIn('수집 미완료',c['messages'][-1]['content'])
if __name__=='__main__':unittest.main()
