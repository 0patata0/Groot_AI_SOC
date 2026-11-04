import copy
import unittest
import runtime

class ServiceReadSchema(unittest.TestCase):
    def test_runtime_catalog_preserves_waf_and_ids_targets(self):
        original={'type':'object','properties':{'target':{'type':'string','enum':['a:waf','a:suricata','a:chatproxy']}}}
        before=copy.deepcopy(original)
        for q,target in [('지금 WAF 모드 뭐야?','a:waf'),('IDS 실제 가동 상태 조회','a:suricata')]:
            with self.subTest(q=q):
                schema=runtime.service_read_schema(q,original)
                self.assertEqual(schema['properties']['target']['enum'],[target])
                refined=runtime.harness.refine_read_schemas(q,{'mcp__rule_a__get_service_action_target':schema},[])
                self.assertIn(target,refined['mcp__rule_a__get_service_action_target']['properties']['target']['enum'])
        self.assertEqual(original,before)

if __name__=='__main__':unittest.main()
