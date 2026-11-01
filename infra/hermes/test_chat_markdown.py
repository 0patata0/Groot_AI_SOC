import importlib.util
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
from chat_markdown import normalize_tables
import review_channel_policy as policy

TABLE='| 항목 | 상태 |\n|---|---|\n| IDS | 정상 |'

class TableTests(unittest.TestCase):
    def test_live_message_shape_and_idempotence(self):
        text='**확인 내역** (관찰 시각 KST)\n'+TABLE+'\n다음 안내'
        wanted='**확인 내역** (관찰 시각 KST)\n\n'+TABLE+'\n\n다음 안내'
        self.assertEqual(normalize_tables(text),wanted)
        self.assertEqual(normalize_tables(wanted),wanted)

    def test_cells_ids_links_and_escaped_pipes_do_not_change(self):
        table='| 항목 | 값 |\n| :--- | ---: |\n| ID | `a\\|b` [근거](https://example.test/a) |'
        self.assertEqual(normalize_tables('설명\n'+table),'설명\n\n'+table)

    def test_code_fences_quotes_indentation_and_html_preserved(self):
        for text in ('```log\n설명\n'+TABLE+'\n```','~~~~\n설명\n'+TABLE+'\n~~~~',
                     '> 설명\n'+ '\n'.join('> '+l for l in TABLE.splitlines()),
                     '    설명\n'+'\n'.join('    '+l for l in TABLE.splitlines()),
                     '<pre>\n설명\n'+TABLE+'\n</pre>'):
            self.assertEqual(normalize_tables(text),text)

    def test_nested_short_fence_does_not_end_outer_code(self):
        text='````\n```\n설명\n'+TABLE+'\n````\n설명\n'+TABLE
        self.assertEqual(normalize_tables(text),text.rsplit('설명\n',1)[0]+'설명\n\n'+TABLE)

    def test_malformed_and_plain_pipes_not_interpreted_as_table(self):
        for text in ('설명\n| a | b |\n|---|\n| 1 | 2 |','설명\n| a | b |\n| foo | bar |','a | b\n내용'):
            self.assertEqual(normalize_tables(text),text)

    def test_crlf_and_already_valid_tables_preserved(self):
        text='설명\r\n'+TABLE.replace('\n','\r\n')
        self.assertEqual(normalize_tables(text),'설명\r\n\r\n'+TABLE.replace('\n','\r\n'))
        self.assertEqual(normalize_tables(TABLE),TABLE)
        self.assertEqual(normalize_tables('설명\n\n'+TABLE+'\n\n끝'),'설명\n\n'+TABLE+'\n\n끝')

    def test_review_both_roles_and_metadata_preserved(self):
        for engine in ('hermes','ollama'):
            out=policy.render('**확인 내역**\n'+TABLE,{'source_id':'a'*26,'phase':'peer','engine':engine},'https://example.test')
            self.assertIn('**확인 내역**\n\n'+TABLE,out)
            self.assertIn('/_redirect/pl/'+'a'*26,out)
            self.assertIn('교차 검토 · 읽기 전용',out)

    def test_native_final_text_only_without_tool_or_model_call(self):
        spec=importlib.util.spec_from_file_location('table_test_plugin',Path(__file__).parent/'query-completion/__init__.py')
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        message=SimpleNamespace(content='**확인 내역**\n'+TABLE,tool_calls=None)
        original=lambda agent,**kw:kw['assistant_message'].content
        wrapper=module.make_wrapper(original,None,None,None)
        kw={'assistant_message':message,'finish_reason':'stop','user_message':'','messages':[]}
        self.assertEqual(wrapper(SimpleNamespace(platform='mattermost'),**kw),'**확인 내역**\n\n'+TABLE)
        self.assertEqual(message.content,'**확인 내역**\n'+TABLE)
        self.assertEqual(wrapper(SimpleNamespace(platform='terminal'),**kw),message.content)
        message.tool_calls=[{'name':'unchanged'}]
        self.assertEqual(wrapper(SimpleNamespace(platform='mattermost'),**kw),message.content)

if __name__=='__main__':unittest.main()
