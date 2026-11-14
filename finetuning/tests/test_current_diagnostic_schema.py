import copy,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from current_diagnostic_schema import NAME,project_for_call
from audit_tools import audit_rows
from prepare_data import check_schema,matches_schema,Reject
from soc_dataset import checked_call_schema

class CurrentSchemaTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tool=next(t for t in json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.20261107.json').read_text())['tools'] if t['name']==NAME)
 def valid(self,args,schema=None):
  try:
   s=checked_call_schema(NAME,schema or self.tool['parameters'],args);check_schema(s,root=True);return matches_schema(args,s)
  except (Reject,ValueError,TypeError):return False
 def test_current_read(self):self.assertTrue(self.valid({'target':'a:systemd'}))
 def test_explicit_history_registered_unit(self):self.assertTrue(self.valid({'target':'b:management','since_kst':'2026-11-07T01:00:00+09:00','until_kst':'2026-11-07T02:00:00+09:00'}))
 def test_unpaired_bounds(self):
  for key in ['since_kst','until_kst']:self.assertFalse(self.valid({'target':'b:management',key:'2026-11-07T01:00:00+09:00'}))
 def test_runtime_history_refused(self):self.assertFalse(self.valid({'target':'a:systemd','since_kst':'x','until_kst':'y'}))
 def test_lookback_history_conflict(self):self.assertFalse(self.valid({'target':'b:management','since_kst':'x','until_kst':'y','lookback_minutes':15}))
 def test_types_limits_and_unknown_properties(self):
  for extra in [{'limit':True},{'limit':51},{'lookback_minutes':0},{'lookback_minutes':241},{'shell':'id'}]:self.assertFalse(self.valid({'target':'a:systemd',**extra}))
 def test_unknown_target(self):self.assertFalse(self.valid({'target':'a:unknown'}))
 def test_unknown_guard_is_not_silently_removed(self):
  schema=copy.deepcopy(self.tool['parameters']);schema['allOf'][0]['not']['required']=['limit']
  self.assertFalse(self.valid({'target':'a:systemd'},schema))
 def test_schema_not_mutated(self):
  before=copy.deepcopy(self.tool);self.valid({'target':'a:systemd'});self.assertEqual(before,self.tool)
 def test_auditor_rejects_invalid_call(self):
  row={'messages':[{'role':'assistant','tool_calls':[{'function':{'name':NAME,'arguments':{'target':'a:systemd','limit':51}}}]}]}
  result=audit_rows([row],{'tools':[self.tool]});self.assertEqual(result['counts']['invalid_or_unchecked_calls'],1)

 def current_schema(self):
  return next(t['parameters'] for t in json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.20261115.json').read_text())['tools'] if t['name']==NAME)
 def test_current_live_guard_keeps_current_and_explicit_history(self):
  schema=self.current_schema()
  self.assertTrue(self.valid({'target':'b:systemd'},schema))
  self.assertTrue(self.valid({'target':'b:management','since_kst':'2026-11-06T01:00:00+09:00','until_kst':'2026-11-06T02:00:00+09:00','view':'journal'},schema))
  for scope in ('errors','all'):
   self.assertTrue(self.valid({'target':'b:management','since_kst':'2026-11-06T01:00:00+09:00','until_kst':'2026-11-06T02:00:00+09:00','view':'journal','journal_scope':scope},schema))
 def test_current_live_view_and_journal_scope_dependencies_are_enforced(self):
  schema=self.current_schema()
  for args in ({'target':'b:management','view':'journal'},
               {'target':'b:management','journal_scope':'unit'},
               {'target':'b:management','view':'journal','since_kst':'x'},
               {'target':'b:management','view':'journal','since_kst':'x','until_kst':'y','lookback_minutes':15},
               {'target':'b:systemd','view':'journal','since_kst':'x','until_kst':'y'}):
   with self.subTest(args=args):self.assertFalse(self.valid(args,schema))
 def test_changed_live_dependencies_or_extra_guard_are_not_stripped(self):
  for index in (2,3):
   schema=self.current_schema();schema['allOf'][index]['then']['required']=['limit']
   self.assertFalse(self.valid({'target':'b:systemd'},schema))
  schema=self.current_schema();schema['allOf'].append({'const':'unknown'})
  self.assertFalse(self.valid({'target':'b:systemd'},schema))
 def test_current_live_schema_is_not_mutated(self):
  schema=self.current_schema();before=copy.deepcopy(schema)
  self.valid({'target':'b:systemd'},schema);self.assertEqual(before,schema)
 def test_live_annotations_are_metadata_but_unknown_or_invalid_fields_refuse(self):
  schema=self.current_schema();schema['properties']['target']['x-capstone-service-labels']={'b:docker':'not a list'}
  self.assertFalse(self.valid({'target':'b:systemd'},schema))
  schema=self.current_schema();schema['properties']['target']['x-unknown-constraint']=True
  self.assertFalse(self.valid({'target':'b:systemd'},schema))

if __name__=='__main__':unittest.main()
