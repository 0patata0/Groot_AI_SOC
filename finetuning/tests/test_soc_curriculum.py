"""Check evidence/approval preservation and split contamination, without ML or SSH."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from soc_curriculum import audit,build,make_case,verify_evidence
from soc_dataset import prepare,validate_case

CATALOG=json.loads((Path(__file__).resolve().parents[1]/'mcp_contract.json').read_text())


class CurriculumTests(unittest.TestCase):
    def test_new_corpus_has_no_cross_split_wording_or_numeric_only_overlap(self):
        result=audit(build(),CATALOG)
        self.assertEqual(result['records'],{'train':192,'validation':32,'test':32})
        self.assertGreater(result['train_distinct_tools'],7)
        self.assertEqual(result['numeric_only_cross_split_overlap'],0)

    def test_renaming_a_family_cannot_hide_numeric_only_question_leakage(self):
        a=make_case('missing','train',0);b=make_case('missing','test',0)
        a['messages'][1]['content']='요청 123: 그 주소 차단해줘'
        b['messages'][1]['content']='요청 456: 그 주소 차단해줘'
        with self.assertRaisesRegex(ValueError,'Numeric-only'):audit([a,b],CATALOG)

    def test_old_test_questions_cannot_be_copied_into_train(self):
        row=make_case('blocks','train',0);old=copy.deepcopy(row);old['split']='test'
        with self.assertRaisesRegex(ValueError,'Previous test'):audit([row],CATALOG,[old])

    def test_actual_proposal_status_field_is_required(self):
        row=make_case('proposal','train',0)
        response=row['messages'][-2];payload=json.loads(response['content']);payload['state']=payload.pop('status');response['content']=json.dumps(payload)
        with self.assertRaisesRegex(ValueError,'status'):audit([row],CATALOG)

    def test_inventory_kind_matches_the_actual_reader_contract(self):
        row=make_case('rules','train',0);result=json.loads(row['messages'][3]['content'])
        self.assertEqual(result['rule_inventory']['kind'],'waf')
        result['rule_inventory']['kind']='modsecurity';row['messages'][3]['content']=json.dumps(result)
        with self.assertRaisesRegex(ValueError,'inventory kind'):verify_evidence(row)

    def test_no_approval_or_application_is_invented(self):
        row=make_case('proposal','train',0);row['review']['protected_policy_reviewed']=False
        with self.assertRaisesRegex(ValueError,'policy'):validate_case(row,CATALOG)
        row=make_case('proposal','train',0);row['messages'][-1]['content']+=' 적용 완료'
        with self.assertRaisesRegex(ValueError,'completion'):validate_case(row,CATALOG)

    def test_corpus_version_and_wording_lineage_survive_preparation(self):
        with tempfile.TemporaryDirectory() as directory:
            destination=Path(directory)/'data';prepare(build(),CATALOG,destination)
            row=json.loads((destination/'train.jsonl').read_text().splitlines()[0])
            self.assertEqual(row['source'],'soc-reviewed-v2')
            self.assertTrue(row['provenance']['template_family'])

    def test_wrong_agent_id_and_time_results_are_rejected(self):
        row=make_case('ports','train',0);row['messages'][4]['tool_calls'][0]['function']['arguments']['agent_id']='999'
        with self.assertRaisesRegex(ValueError,'identity'):verify_evidence(row)
        row=make_case('elapsed','train',0);result=json.loads(row['messages'][3]['content']);result['differences'][0]['seconds']+=1;row['messages'][3]['content']=json.dumps(result)
        with self.assertRaisesRegex(ValueError,'Time calculation'):verify_evidence(row)

    def test_empty_source_uses_full_candidate_and_xml_comment_stays_valid(self):
        empty=make_case('proposal','train',11)
        self.assertTrue(empty['messages'][4]['tool_calls'][0]['function']['name'].endswith('propose_rule_change'))
        verify_evidence(empty)
        xml=make_case('proposal','train',1);verify_evidence(xml)
        self.assertIn('<!--',xml['messages'][1]['content'])


if __name__=='__main__':unittest.main()
