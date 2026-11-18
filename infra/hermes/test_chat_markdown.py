import importlib.util
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parent))
from chat_markdown import normalize_tables,labeled_report_tables,public_control_text,split_tables
import review_channel_policy as policy

TABLE='| 항목 | 상태 |\n|---|---|\n| IDS | 정상 |'

class PublicControlTests(unittest.TestCase):
    def test_only_trailing_transport_copy_changes_and_is_idempotent(self):
        body='**판단**\n영향은 미확인입니다.\n\n'+TABLE
        original=body+'\n\nINCIDENT_DISPOSITION: {"assessment":"unresolved"}\nMANAGEMENT_STATUS: needs_review\n'
        self.assertEqual(public_control_text(original),body)
        self.assertEqual(public_control_text(public_control_text(original)),body)
        self.assertIn('INCIDENT_DISPOSITION:',original)

    def test_fenced_quoted_indented_raw_and_comment_examples_are_preserved(self):
        controls='INCIDENT_DISPOSITION: {"assessment":"unresolved"}\nMANAGEMENT_STATUS: needs_review'
        for text in ('```text\n'+controls+'\n```','~~~~\n'+controls,
                     '> '+controls.replace('\n','\n> '),'    '+controls.replace('\n','\n    '),
                     '<pre>\n'+controls,'<div>\n'+controls,'<!--\n'+controls):
            with self.subTest(text=text):self.assertEqual(public_control_text(text),text)

    def test_nested_short_fence_and_controls_in_the_body_are_not_a_footer(self):
        for text in ('````\n```\nMANAGEMENT_STATUS: resolved',
                     'MANAGEMENT_STATUS: resolved\n이것은 문서의 예시입니다.',
                     '설명: MANAGEMENT_STATUS: resolved',r'\MANAGEMENT_STATUS: resolved'):
            self.assertEqual(public_control_text(text),text)

    def test_closed_examples_do_not_hide_a_real_trailing_footer(self):
        body='```text\nMANAGEMENT_STATUS: resolved\n```\n\n'+TABLE
        self.assertEqual(public_control_text(body+'\nMANAGEMENT_STATUS: needs_review'),body)

    def test_crlf_blank_lines_and_single_status_do_not_change_table_cells(self):
        body=TABLE.replace('\n','\r\n')
        self.assertEqual(public_control_text(body+'\r\n\r\nMANAGEMENT_STATUS: needs_review\r\n\r\n'),body)
        self.assertEqual(public_control_text(TABLE+'\n\n'),TABLE+'\n\n')

    def test_native_splitter_removes_controls_before_packing_and_keeps_all_rows(self):
        body='| IP | 결과 |\n| --- | --- |\n'+''.join('| 192.0.2.'+str(i)+' | 관측 |\n' for i in range(20))
        source=body+'\nINCIDENT_DISPOSITION: {"evidence_tools":["mcp__resp__list_blocks"]}\nMANAGEMENT_STATUS: needs_review'
        def fallback(text,max_length,len_fn):return [text]
        parts=split_tables(source,180,fallback=fallback)
        self.assertGreater(len(parts),1)
        for part in parts:
            self.assertLessEqual(len(part),180);self.assertNotIn('MANAGEMENT_STATUS',part);self.assertNotIn('INCIDENT_DISPOSITION',part)
        rows=[l for part in parts for l in part.splitlines() if l.startswith('| 192.0.2.')]
        self.assertEqual(rows,[l for l in body.splitlines() if l.startswith('| 192.0.2.')])

    def test_review_uses_the_common_public_control_filter(self):
        code='```text\nMANAGEMENT_STATUS: resolved\n```'
        text=policy.render(code+'\n\n'+TABLE+'\nMANAGEMENT_STATUS: needs_review',
            {'source_id':'a'*26,'phase':'peer','engine':'hermes'},'https://example.test')
        self.assertIn(code,text);self.assertNotIn('MANAGEMENT_STATUS: needs_review',text)

class LabelledReportTests(unittest.TestCase):
    def test_actual_operation_shape_preserves_values_context_and_decision(self):
        text=('현재 상태를 조회했습니다.\n\n### 변경 절차 재검토\n\n'
              '- **대상 IP**: 192.168.16.232\n- **현재 차단 상태 (`list_blocks`)**: `blocks: []` (확인 없음)\n'
              '- **작업 결과**: expired / result_posted: true\n- **시점 기록 (KST)**:\n'
              '  - 최초 적용 확인 시점: 12:25:47 (~68분 전)\n  - 만료 시각: 12:35:46 (~58분 전)\n'
              '  - 쿨다운 종료: 12:36:46 (~57분 전)\n- **판단**: 해당 변경 절차 확인 완료\n\n'
              '추가 영향은 별도 확인합니다.\nMANAGEMENT_STATUS: resolved')
        out=labeled_report_tables(text)
        self.assertEqual(sum(l.startswith('|') for l in out.splitlines()),9)
        for value in ['192.168.16.232','`blocks: []` (확인 없음)','expired / result_posted: true',
                      '시점 기록 (KST) / 최초 적용 확인 시점','12:25:47 (~68분 전)',
                      '12:35:46 (~58분 전)','12:36:46 (~57분 전)','해당 변경 절차 확인 완료']:
            self.assertIn(value,out)
        self.assertTrue(out.startswith('현재 상태를 조회했습니다.\n\n### 변경 절차 재검토\n\n'))
        self.assertTrue(out.endswith('추가 영향은 별도 확인합니다.\nMANAGEMENT_STATUS: resolved'))
        self.assertEqual(labeled_report_tables(out),out)
        # General chat table normalization alone does not reinterpret lists.
        self.assertEqual(normalize_tables(text),text)

    def test_escaped_pipes_links_code_and_whitespace_values_are_retained(self):
        text='- ID: `x|y`\n- 근거: [source](https://example.test/a) `a\\|b`\n'
        out=labeled_report_tables(text)
        self.assertIn('`x\\|y`',out);self.assertIn('`a\\|b`',out)
        self.assertIn('[source](https://example.test/a)',out)
        self.assertEqual(labeled_report_tables(out),out)

    def test_fences_quotes_html_indentation_and_multiline_lists_stay_byte_exact(self):
        block='- A: one\n- B: two'
        for text in ('```log\n'+block+'\n```','> '+block.replace('\n','\n> '),
                     '    '+block.replace('\n','\n    '),'<div>\n\n'+block+'\n\n</div>',
                     '- A: one\n  continued\n- B: two','- A: one\n- unlabeled',
                     '- A: one\nplain continuation\n- B: two'):
            self.assertEqual(labeled_report_tables(text),text)

    def test_single_empty_or_unowned_nested_labels_are_not_fabricated(self):
        for text in ('- A: one','- A:\n- B: two','- A: one\n  - B: two',
                     '- A:\n    - B: two\n- C: three'):
            self.assertEqual(labeled_report_tables(text),text)

    def test_existing_tables_and_ordered_lists_are_preserved(self):
        text=TABLE+'\n\n- A: one\n- B: two'
        out=labeled_report_tables(text)
        self.assertTrue(out.startswith(TABLE+'\n\n'))
        self.assertIn('| A | one |\n| B | two |',out)
        self.assertEqual(labeled_report_tables(out),out)
        text='1. A: one\n2. B: two'
        self.assertEqual(labeled_report_tables(text),text)

    def test_crlf_and_missing_final_newline(self):
        text='- A: one\r\n- B: two'
        out=labeled_report_tables(text);self.assertNotIn('\n',out.replace('\r\n',''))
        self.assertFalse(out.endswith('\n'));self.assertIn('| B | two |',out)

    def test_root_output_contract_reuses_formatter_without_a_model_or_decision(self):
        import output_contract
        text='- 현재 상태: 미확인\n- 다음 확인: 실제 호스트 조회 필요\n'
        out=output_contract.normalize_tables(text)
        self.assertIn('| 현재 상태 | 미확인 |',out)
        self.assertIn('| 다음 확인 | 실제 호스트 조회 필요 |',out)
        self.assertNotIn('resolved',out)

class TableTests(unittest.TestCase):
    def test_actual_incident_header_without_outer_pipes_is_canonicalized(self):
        text='확인 항목 | 결과·판단 | 근거·범위\n|---|---|---|\n| 사건 | 미확인 | MCP 조회 |'
        wanted='|확인 항목 | 결과·판단 | 근거·범위|\n|---|---|---|\n| 사건 | 미확인 | MCP 조회 |'
        self.assertEqual(normalize_tables(text),wanted)
        self.assertEqual(normalize_tables(wanted),wanted)

    def test_optional_edges_keep_cells_links_and_literal_pipes(self):
        text='A | B\n:--- | ---:\n`x\\|y` | [근거](https://example.test/a)'
        self.assertEqual(normalize_tables(text),'|A | B|\n|:--- | ---:|\n|`x\\|y` | [근거](https://example.test/a)|')

    def test_optional_edge_table_in_code_quote_or_list_is_preserved(self):
        plain='A | B\n--- | ---\n1 | 2'
        for text in ('```markdown\n'+plain+'\n```','\n'.join('    '+l for l in plain.splitlines()),
                     '\n'.join('> '+l for l in plain.splitlines()),'- A | B\n--- | ---'):
            self.assertEqual(normalize_tables(text),text)

    def test_optional_edges_require_real_separator_and_matching_column_count(self):
        for text in ('A | B\n--- | --- | ---\n1 | 2','A | B\nnot | separator'):
            self.assertEqual(normalize_tables(text),text)

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
