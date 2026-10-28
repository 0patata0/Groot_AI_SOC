import unittest
from prepare_data import Reject
from prepare_toolace import MARKER,convert,parse_calls,schema
import json

class ToolAceTests(unittest.TestCase):
    def row(self):
        return {'system':'Call tools when needed. '+MARKER+json.dumps([{'name':'Read State','description':'Read','parameters':{'type':'dict','properties':{'id':{'type':'int'}},'required':['id']}}]),'conversations':[{'from':'user','value':'Read ID7'},{'from':'assistant','value':'[Read State(id=7)]'},{'from':'tool','value':json.dumps([{'name':'Read State','results':{'status':'failed'}}])},{'from':'assistant','value':'The query failed.'}]}
    def test_structure_alias_and_source_identity_preserved(self):
        r=convert(self.row(),1);self.assertEqual(r['messages'][1]['content'],'Read ID7');self.assertEqual(r['tools'][0]['function']['parameters']['type'],'object');self.assertEqual(r['messages'][3]['content'],'{"status":"failed"}');self.assertEqual(r['provenance']['source_array_index_1based'],1)
    def test_tool_json_footer_is_format_scaffolding(self):
        r=self.row();r['system']+=' . Return function calls in bracket format.'
        self.assertTrue(convert(r,3)['messages'][2]['tool_calls'])
    def test_executable_arguments_are_rejected(self):
        with self.assertRaises(Reject):parse_calls('[Read State(id=__import__("os"))]',{'Read State':'toolace_x'})
    def test_alias_replacement_does_not_change_quoted_argument(self):
        c=parse_calls('[Read State(note="Read State(id=9)")]',{'Read State':'toolace_x'});self.assertEqual(c[0]['function']['arguments']['note'],'Read State(id=9)')
    def test_ambiguous_parallel_results_are_rejected(self):
        r=self.row();r['conversations'][1]['value']='[Read State(id=7),Read State(id=8)]'
        with self.assertRaisesRegex(Reject,'ambiguous_tool_result'):convert(r,2)
    def test_unknown_function_is_not_learned_as_plain_text(self):
        r=self.row();r['conversations']=[r['conversations'][0],{'from':'assistant','value':'[UnknownAPI(id=7)]'}]
        with self.assertRaises(Reject):convert(r,2)
    def test_wrong_argument_type_is_rejected(self):
        r=self.row();r['conversations'][1]['value']='[Read State(id="seven")]'
        with self.assertRaisesRegex(Reject,'arguments_schema_mismatch'):convert(r,2)
    def test_unknown_schema_constraint_is_not_silently_ignored(self):
        with self.assertRaises(Reject):schema({'type':'dict','customConstraint':'x'})
    def test_missing_response_is_rejected_before_narrative(self):
        r=self.row();del r['conversations'][2]
        with self.assertRaisesRegex(Reject,'missing_tool_result'):convert(r,2)

if __name__=='__main__':unittest.main()
