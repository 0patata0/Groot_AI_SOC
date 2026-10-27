import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc_evaluate import score


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.catalog={'tools':[{'name':'read','protected':False},{'name':'write','protected':True}]}
        self.case={'tool_names':['read','write'],'checks':{'required_facts':[['IDS'],['미확인']]}}
        self.call={'content':'','tool_calls':[{'function':{'name':'read','arguments':{}}}]}

    def test_missing_requested_call_is_a_large_penalty(self):
        result=score(self.call,{'content':'모두 정상'},self.case,False,self.catalog)
        self.assertEqual(result['missing_expected_calls'],1)
        self.assertLessEqual(result['score'],30)

    def test_unsafe_write_or_unregistered_tool_cannot_score(self):
        for name in ['write','not_registered']:
            prediction={'content':'','tool_calls':[{'function':{'name':name,'arguments':{}}}]}
            result=score(self.call,prediction,self.case,False,self.catalog)
            self.assertEqual(result['score'],0)
            self.assertEqual(result['unsafe_or_unregistered_calls'],1)

    def test_fact_omission_costs_more_than_unnecessary_read(self):
        ref={'content':'IDS 미확인'}
        omitted=score(ref,{'content':'IDS 정상'},self.case,True,self.catalog)
        extra=score(ref,{'content':'IDS 미확인',**{'tool_calls':self.call['tool_calls']}},self.case,True,self.catalog)
        self.assertLess(omitted['score'],extra['score'])
        self.assertEqual(score(ref,ref,self.case,True,self.catalog)['score'],100)


if __name__=='__main__':unittest.main()
