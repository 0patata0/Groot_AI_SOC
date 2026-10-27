"""Prevent poisoned reference data, approval drift and train/test leakage."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc_dataset import checked_schema, prepare, validate_case
from prepare_data import matches_schema


CATALOG={'observed_at_kst':'2026-10-27T19:05:50+09:00','tools':[{'name':'read','protected':False,'parameters':{'type':'object','properties':{'target':{'type':'string','enum':['ids']},'limit':{'type':'integer','format':'uint32','nullable':True}},'required':['target']}}]}
def case(split='train',group='one',id='one'):
    return {'id':id,'split':split,'scenario_group':group,'tool_names':['read'],
        'review':{'status':'agent_reviewed','basis':'explicit fixture','evidence_kind':'synthetic_lab_fixture'},
        'checks':{'expected_calls':[{'name':'read','arguments':{'target':'ids'}}],'required_facts':[['未確認','미확인']]},
        'messages':[{'role':'user','content':group},{'role':'assistant','content':'','tool_calls':[{'id':'c','function':{'name':'read','arguments':{'target':'ids'}}}]},{'role':'tool','tool_call_id':'c','content':'{"error":"unavailable"}'},{'role':'assistant','content':'미확인'}]}


class DatasetTests(unittest.TestCase):
    def test_nullable_uint32_bounds_are_enforced(self):
        schema=checked_schema(CATALOG['tools'][0]['parameters'])
        for value in [None,0,2**32-1]:self.assertTrue(matches_schema({'target':'ids','limit':value},schema))
        for value in [-1,2**32,'1']:self.assertFalse(matches_schema({'target':'ids','limit':value},schema))
        with self.assertRaisesRegex(ValueError,'format'):checked_schema({'type':'string','format':'unhandled'})

    def test_unregistered_tool_and_wrong_args_are_rejected(self):
        row=case();row['tool_names']=['unknown']
        with self.assertRaisesRegex(ValueError,'Unregistered'):validate_case(row,CATALOG)
        row=case();row['messages'][1]['tool_calls'][0]['function']['arguments']['target']='waf'
        with self.assertRaises(ValueError):validate_case(row,CATALOG)

    def test_expected_call_and_critical_fact_cannot_be_omitted(self):
        row=case();row['checks']['expected_calls']=[]
        with self.assertRaisesRegex(ValueError,'sequence'):validate_case(row,CATALOG)
        row=case();row['messages'][-1]['content']='정상'
        with self.assertRaisesRegex(ValueError,'omitted'):validate_case(row,CATALOG)

    def test_protected_call_requires_review_and_pending_is_not_done(self):
        cat=copy.deepcopy(CATALOG);cat['tools'][0]['protected']=True
        with self.assertRaisesRegex(ValueError,'policy'):validate_case(case(),cat)
        row=case();row['review'].update(protected_policy_reviewed=True,pending_approval=True)
        row['messages'][-1]['content']='미확인. 승인 대기. 적용 완료'
        with self.assertRaisesRegex(ValueError,'completion'):validate_case(row,cat)

    def test_same_scenario_or_prompt_must_not_cross_splits(self):
        for mode in ['scenario','prompt']:
            rows=[case(),case('validation','two','two'),case('test','three','three')]
            if mode=='scenario':rows[1]['scenario_group']='one'
            else:rows[1]['messages'][0]['content']='one'
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(ValueError,'leakage'):prepare(rows,CATALOG,Path(d)/'data')


if __name__=='__main__':unittest.main()
