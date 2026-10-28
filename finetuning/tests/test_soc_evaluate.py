import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc_evaluate import score,select_cases


class ScoringTests(unittest.TestCase):
    def test_development_evaluation_cannot_silently_read_final_test(self):
        rows=[{'split':s,'scenario_group':s} for s in ('train','validation','test')]
        self.assertEqual(select_cases(rows,8,True,'validation'),[rows[1]])
        self.assertEqual(select_cases(rows,8,True),[rows[2]])
        with self.assertRaises(ValueError):select_cases(rows,8,True,'train')
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

    def test_explicit_context_budget_and_guard_are_used_before_request(self):
        import tempfile,json,io
        from unittest.mock import patch
        from soc_evaluate import evaluate
        cases=[{'id':'one','split':'test','scenario_group':'fixture','tool_names':[],'checks':{'required_facts':[['result']]}}]
        row={'messages':[{'role':'user','content':'Q'},{'role':'assistant','content':'result'}],'tools':[]}
        with tempfile.TemporaryDirectory() as d,patch('soc_evaluate.validate_case',return_value=row),patch('soc_evaluate.request.urlopen') as urlopen:
            urlopen.return_value.__enter__.return_value=io.BytesIO(json.dumps({'message':{'content':'result'},'done_reason':'stop'}).encode())
            guards=[];out=Path(d)/'report.json'
            evaluate('model','http://localhost:11434',cases,{'tools':[]},out,num_ctx=16384,num_predict=512,before_request=lambda:guards.append(True))
            payload=json.loads(urlopen.call_args.args[0].data)
            self.assertEqual(payload['options']['num_ctx'],16384);self.assertEqual(guards,[True])
            self.assertEqual(json.loads(out.read_text())['results'][0]['usage']['done_reason'],'stop')

    def test_resource_guard_aborts_without_sending_or_scoring_a_model_failure(self):
        import tempfile
        from unittest.mock import patch
        from soc_evaluate import evaluate
        cases=[{'id':'one','split':'test','scenario_group':'fixture'}]
        row={'messages':[{'role':'user','content':'Q'},{'role':'assistant','content':'result'}],'tools':[]}
        def blocked():raise RuntimeError('host reserve')
        with tempfile.TemporaryDirectory() as d,patch('soc_evaluate.validate_case',return_value=row),patch('soc_evaluate.request.urlopen') as urlopen:
            with self.assertRaisesRegex(RuntimeError,'host reserve'):evaluate('model','http://localhost:11434',cases,{'tools':[]},Path(d)/'report.json',before_request=blocked)
            urlopen.assert_not_called()

    def test_invalid_context_or_prediction_budget_is_refused(self):
        from soc_evaluate import evaluate
        for kwargs in [{'num_ctx':0},{'num_ctx':65536},{'num_ctx':True},{'num_predict':0},{'num_predict':True}]:
            with self.assertRaises(ValueError):evaluate('model','http://localhost:11434',[],{},'/unused',**kwargs)


class TransportSchemaTests(unittest.TestCase):
    def test_missing_properties_is_explicit_without_changing_contract(self):
        import copy
        from soc_evaluate import transport_tools
        tools=[{'type':'function','function':{'name':'read','parameters':{'type':'object','additionalProperties':False}}}]
        original=copy.deepcopy(tools)
        result=transport_tools(tools)
        self.assertEqual(tools,original)
        self.assertEqual(result[0]['function']['parameters'],{'type':'object','additionalProperties':False,'properties':{}})

    def test_nested_constraints_and_existing_properties_survive(self):
        from soc_evaluate import transport_tools
        schema={'type':'object','required':['rows'],'properties':{'rows':{'type':'array','maxItems':2,'items':{'type':'object','additionalProperties':False}}}}
        result=transport_tools([{'function':{'parameters':schema}}])[0]['function']['parameters']
        self.assertEqual(result['required'],['rows'])
        self.assertEqual(result['properties']['rows']['maxItems'],2)
        self.assertEqual(result['properties']['rows']['items'],{'type':'object','additionalProperties':False,'properties':{}})


if __name__=='__main__':unittest.main()
