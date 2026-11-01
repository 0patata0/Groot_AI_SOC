import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from prepare_operator_mcp import isolated_examples, live_answer
from audit_tools import audit_rows


class ExecutionProofTests(unittest.TestCase):
    def test_actual_executor_boundaries_without_subprocess_or_production_calls(self):
        catalog=json.loads((ROOT/'mcp_contract.20261101.json').read_text())
        with mock.patch('subprocess.run',side_effect=AssertionError('External execution forbidden')):
            examples,evidence=isolated_examples(catalog)
        self.assertEqual(len(examples),24)
        self.assertEqual(len(evidence),21)
        for row in evidence:
            if row['scenario']in ('pending','denied','expired','binding_mismatch'):
                self.assertEqual(row['approval_consumes'],0)
            else:self.assertEqual(row['approval_consumes'],1)
            self.assertFalse(row['production_write_performed'])
            self.assertFalse(row['device_engine_test_executed'])
        for row in examples:
            self.assertIn('격리',row['messages'][0]['content'])
            if row['provenance']['scenario']=='recovery_failed':
                self.assertIn('서비스 복구 성공으로 볼 수 없습니다',row['messages'][-1]['content'])
            if row['provenance']['scenario']=='binding_mismatch':
                self.assertIn('이전 승인을 다른 후보에 사용할 수 없습니다',row['messages'][-1]['content'])
        audit=audit_rows(examples,catalog)
        self.assertEqual(audit['counts']['calls'],audit['counts']['schema_valid_calls'])

    def test_partial_rule_list_is_not_reported_as_full_or_runtime_verified(self):
        value={'counts':{'definitions':81,'configured':79,'builtin':70,'custom':11,'excluded':2},
               'rules':[{'id':'910000','origin':'builtin','configuration':'selected'}],
               'returned_count':1,'matched_count':81,'next_offset':1,'duplicate_rule_ids':[],'runtime_load_verified':False}
        answer=live_answer({'result':json.dumps(value),'arguments':{'target':'a:waf','view':'details'},
                            'name':'get_security_rules','at_kst':'2026-11-01T15:00:00+09:00'})
        self.assertIn('1/81',answer)
        self.assertIn('runtime_load_verified는 false',answer)
        self.assertIn('70 | 11 | 2',answer)
        value.pop('runtime_load_verified')
        unknown=live_answer({'result':json.dumps(value),'arguments':{'target':'a:waf','view':'details'},
                            'name':'get_security_rules','at_kst':'2026-11-01T15:00:00+09:00'})
        self.assertIn('runtime_load_verified는 미확인',unknown)


if __name__=='__main__':unittest.main()
