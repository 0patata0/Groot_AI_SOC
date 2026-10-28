import unittest
from institutional_sources import role_tasks
class RoleTests(unittest.TestCase):
 def fixture(self):
  roles=['PD-WRL-001','PD-WRL-003','PD-WRL-007'];return {'documents':[{'version':'2.2.0'}],'elements':[{'element_identifier':r,'element_type':'work_role','title':r} for r in roles]+[{'element_identifier':'T1250','element_type':'task','text':'triage'}], 'relationships':[{'source_element_identifier':r,'dest_element_identifier':'T1250'} for r in roles]}
 def test_only_tasks_bound_to_official_role_are_selected(self):
  value=self.fixture();value['elements'].append({'element_identifier':'T9999','element_type':'task','text':'unbound'});rows=role_tasks(value);self.assertEqual([len(r['tasks']) for r in rows],[1,1,1]);self.assertTrue(all(r['tasks'][0]['element_identifier']=='T1250' for r in rows))
 def test_wrong_version_cannot_be_mixed_with_current_role_ids(self):
  v=self.fixture();v['documents'][0]['version']='1.0.0'
  with self.assertRaisesRegex(ValueError,'version'):role_tasks(v)
 def test_unbound_role_cannot_be_declared_covered(self):
  v=self.fixture();v['relationships']=[]
  with self.assertRaisesRegex(ValueError,'No tasks'):role_tasks(v)
if __name__=='__main__':unittest.main()
