"""Grammar and execution both refuse an empty displayed peer explanation."""
import asyncio,copy,json,sys,types,unittest
from unittest import mock
import review_channel_worker as worker
import test_review_channel as fixtures

class PeerText(unittest.TestCase):
    def test_actual_synthesis_grammar_rejects_empty_text_and_preserves_existing_bounds(self):
        good={'claims':[{'kind':'agree','text':'실행 상태 일치','source_ref':'a0','missing_field':'','evidence_ref':'e1'}]}
        model,h,report,request,calls=fixtures.Tests().peer_fixture([good]);formats=[]
        class Captured(model):
            def __init__(self,**kw):formats.append(copy.deepcopy(kw['format']));super().__init__(**kw)
        with mock.patch.dict(sys.modules,{'harness':h,'langchain_ollama':types.SimpleNamespace(ChatOllama=Captured)}):
            result=asyncio.run(worker.review_answer({'model':'fixture','base_url':'http://fixture'},request,report))
        schema=formats[0]['properties']['claims']['items']['properties']['text']
        self.assertEqual(schema['minLength'],1);self.assertEqual(schema['maxLength'],400)
        self.assertEqual(result['peer_attempts'],1);self.assertEqual(result['peer_review'],'source_bound_claims')

    def test_runtime_rejects_blank_newline_and_carriage_return_even_without_grammar(self):
        source={'other_agent_answer':'실행 중입니다.'};calls=[{'result':'{"state": "running"}'}]
        for text in ('',' ','\t','\r','\n','설명\r다음','설명\n다음'):
            claim={'kind':'agree','text':text,'other_quote':'실행 중입니다.','call_index':0,'evidence_quote':'"state": "running"'}
            with self.subTest(text=text),self.assertRaisesRegex(ValueError,'peer_claim_text'):
                worker.validate_peer_claims({'claims':[claim]},source,calls)

if __name__=='__main__':unittest.main()
