"""Transport regressions: complete rows, bounded posts and reversible hooks."""
import asyncio
import hashlib
import importlib
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import chat_markdown as markdown
import gateway_health as health

HEADER='| ID | 근거 |\n|---|---|\n'


def native_stub(text,limit=4096,len_fn=None):
    """Native indicator contract; real installed native path is tested below."""
    measure=len_fn or len
    if measure(text)<=limit:return [text]
    parts=[];body=''
    for char in text:
        if measure(body+char)>max(1,limit-16):
            parts.append(body);body=''
        body+=char
    if body:parts.append(body)
    return [part+f' ({i}/{len(parts)})' for i,part in enumerate(parts,1)]


def rows(count=40):
    return [f'| r{i:03} | `ip saddr @set_{i}` 판정 근거와 포트 |\n' for i in range(count)]


class SplitTests(unittest.TestCase):
    def split(self,text,limit=4000,len_fn=None):
        return markdown.split_tables(text,limit,len_fn,fallback=native_stub)

    def assert_rows(self,chunks,expected,header=HEADER):
        actual=[]
        for chunk in chunks:
            lines=chunk.splitlines(keepends=True)
            for line in lines:
                if line.startswith('| r'):actual.append(line)
            if any(line.startswith('| r') for line in lines):self.assertIn(header,chunk)
        self.assertEqual(actual,expected)

    def test_actual_4000_limit_keeps_every_row_once_and_repeats_header(self):
        expected=rows(180);text='조회 결과\n\n'+HEADER+''.join(expected)+'\n다음 안내'
        chunks=self.split(text)
        self.assertGreater(len(chunks),1)
        self.assertTrue(all(len(chunk)<=4000 for chunk in chunks))
        self.assert_rows(chunks,expected)
        self.assertEqual(sum('조회 결과' in c for c in chunks),1)
        self.assertEqual(sum('다음 안내' in c for c in chunks),1)

    def test_no_table_and_short_table_delegate_exactly(self):
        for text in ('긴 일반 문장 '*1000,HEADER+''.join(rows(2))):
            with patch(__name__+'.native_stub',return_value=['exact native result']) as original:
                self.assertEqual(markdown.split_tables(text,4000,fallback=original),['exact native result'])
                original.assert_called_once_with(text,4000,None)

    def test_short_native_local_report_normalizes_table_boundaries_before_delegation(self):
        table=HEADER+''.join(rows(4))
        original='**확인 내역**\n'+table+'다음 안내'
        chunks=self.split(original)
        self.assertEqual(chunks,['**확인 내역**\n\n'+table+'\n다음 안내'])
        self.assert_rows(chunks,rows(4))
        self.assertEqual(original,'**확인 내역**\n'+table+'다음 안내')

    def test_many_boundaries_lengths_no_rule_omission(self):
        expected=rows(80)
        for limit in (128,199,253,400,999,4000):
            with self.subTest(limit=limit):
                chunks=self.split('설명\n'+HEADER+''.join(expected),limit)
                self.assertTrue(all(len(chunk)<=limit for chunk in chunks))
                self.assert_rows(chunks,expected)

    def test_multiple_tables_remain_separate(self):
        first=rows(24);second=[r.replace('| r','| s',1) for r in rows(30)]
        header2=HEADER.replace('ID','다른 ID')
        chunks=self.split('머리말\n'+HEADER+''.join(first)+'\n중간 설명\n'+header2+''.join(second)+'\n끝',430)
        self.assert_rows(chunks,first)
        all_text=''.join(chunks)
        for row in second:self.assertEqual(all_text.count(row),1)
        for chunk in chunks:
            if '| s' in chunk:self.assertIn(header2,chunk)
        self.assertEqual(all_text.count('중간 설명'),1)
        self.assertEqual(all_text.count('끝'),1)

    def test_escaped_pipes_and_links_unchanged(self):
        expected=[f'| r{i:03} | `a\\|b` [근거](https://example.test/{i}) |\n' for i in range(30)]
        chunks=self.split(HEADER+''.join(expected),350)
        self.assert_rows(chunks,expected)

    def test_crlf_preserved_in_repeated_headers_and_cells(self):
        expected=[r.replace('\n','\r\n') for r in rows(30)]
        header=HEADER.replace('\n','\r\n')
        chunks=self.split(header+''.join(expected),420)
        self.assert_rows(chunks,expected,header)

    def test_fenced_indented_quoted_raw_and_malformed_use_native(self):
        table=HEADER+''.join(rows(40))
        for text in ('```log\n'+table+'```','~~~~\n'+table+'~~~~',
                     '\n'.join('    '+line for line in table.splitlines()),
                     '\n'.join('> '+line for line in table.splitlines()),
                     '<pre>\n'+table+'</pre>',table.replace('|---|---|','|x|x|')):
            self.assertEqual(self.split(text,300),native_stub(text,300))

    def test_oversized_header_or_row_falls_back_without_silently_dropping_text(self):
        for text in (HEADER+'| r000 | '+'x'*900+' |\n', '| '+'x'*700+' | y |\n|---|---|\n| r000 | y |\n'):
            self.assertEqual(self.split(text,300),native_stub(text,300))

    def test_custom_utf16_length_including_emoji(self):
        utf16=lambda value:len(value.encode('utf-16-le'))//2
        expected=[r.replace('근거','🛡️근거') for r in rows(40)]
        chunks=self.split(HEADER+''.join(expected),350,utf16)
        self.assertTrue(all(utf16(c)<=350 for c in chunks))
        self.assert_rows(chunks,expected)

    def test_unexpected_native_contract_uses_complete_original_fallback(self):
        text='prefix '*300+HEADER+''.join(rows(20))
        calls=[]
        def changed(value,limit,len_fn):
            calls.append(value)
            return ['unrecognized1','unrecognized2']
        self.assertEqual(markdown.split_tables(text,300,fallback=changed),['unrecognized1','unrecognized2'])
        self.assertEqual(calls[-1],text)

    def test_existing_indicator_like_cell_text_not_removed(self):
        expected=[r.replace('판정','(1/2) 판정') for r in rows(40)]
        self.assert_rows(self.split(HEADER+''.join(expected),420),expected)

    def test_native_runtime_mixed_fences_and_tables(self):
        try:
            from gateway.platforms.base import BasePlatformAdapter
        except ImportError:self.skipTest('installed native runtime only')
        expected=rows(180)
        text='```log\n'+('code fence content\n'*400)+'```\n\n'+HEADER+''.join(expected)+'\n다음 안내'
        native=BasePlatformAdapter.truncate_message
        chunks=markdown.split_tables(text,4000,fallback=native)
        self.assertTrue(all(len(chunk)<=4000 for chunk in chunks))
        self.assert_rows(chunks,expected)
        for chunk in chunks:self.assertEqual(chunk.count('```')%2,0)


class HookTests(unittest.TestCase):
    def adapter(self,name='MattermostAdapter'):
        return type(name,(),{'truncate_message':staticmethod(native_stub)})()

    def test_instance_only_idempotent_and_unload_restores_descriptor(self):
        adapter=self.adapter();other=self.adapter()
        restore=health.install_table_splitter(adapter,markdown)
        self.assertTrue(callable(restore))
        self.assertIsNone(health.install_table_splitter(adapter,markdown))
        text=HEADER+''.join(rows(200))
        self.assertNotEqual(adapter.truncate_message(text,4000),other.truncate_message(text,4000))
        self.assertNotIn('truncate_message',vars(other))
        restore();restore()
        self.assertNotIn('truncate_message',vars(adapter))
        self.assertEqual(adapter.truncate_message(text,4000),native_stub(text,4000))

    def test_preexisting_instance_callable_restored_and_other_patch_not_overwritten(self):
        adapter=self.adapter();old=lambda *args:['before']
        adapter.truncate_message=old
        restore=health.install_table_splitter(adapter,markdown);restore()
        self.assertIs(adapter.truncate_message,old)
        restore=health.install_table_splitter(adapter,markdown)
        other=lambda *args:['later'];adapter.truncate_message=other;restore()
        self.assertIs(adapter.truncate_message,other)

    def test_non_mattermost_adapter_untouched(self):
        adapter=self.adapter('TelegramAdapter')
        self.assertIsNone(health.install_table_splitter(adapter,markdown))
        self.assertNotIn('truncate_message',vars(adapter))


class ConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_connection_and_plugin_unload_preserve_health_and_splitter(self):
        class Base:
            def _mark_connected(self):return 'native connection result'
            truncate_message=staticmethod(native_stub)
        adapter=type('MattermostAdapter',(Base,),{})()
        adapter._closing=True;adapter._handle_ws_event=lambda value:None
        original=Base._mark_connected
        base_module=ModuleType('gateway.platforms.base');base_module.BasePlatformAdapter=Base
        unload=[];ctx=SimpleNamespace(on_unload=unload.append)
        fake=b'verified adapter source'
        with patch.dict(sys.modules,{'gateway.platforms.base':base_module}),patch.object(Path,'read_bytes',return_value=fake),patch.object(health,'ADAPTER_SHA256',hashlib.sha256(fake).hexdigest()),patch.object(health,'publish'),patch.dict('os.environ',{'HERMES_HOME':'/not-used'}):
            health.install_hermes(ctx,markdown)
            self.assertEqual(adapter._mark_connected(),'native connection result')
            first=adapter.truncate_message
            self.assertEqual(adapter._mark_connected(),'native connection result')
            self.assertIs(first,adapter.truncate_message)
            self.assertEqual(len(unload),1)
            unload[0]()
            await asyncio.sleep(0)
            self.assertIs(Base._mark_connected,original)
            self.assertNotIn('truncate_message',vars(adapter))

    async def test_source_pin_rejection_leaves_connection_unmodified(self):
        original=lambda self:None
        base_module=ModuleType('gateway.platforms.base');base_module.BasePlatformAdapter=type('Base',(),{'_mark_connected':original})
        with patch.dict(sys.modules,{'gateway.platforms.base':base_module}),patch.object(Path,'read_bytes',return_value=b'wrong source'):
            with self.assertRaisesRegex(ValueError,'pin_mismatch'):health.install_hermes(SimpleNamespace(),markdown)
        self.assertIs(base_module.BasePlatformAdapter._mark_connected,original)


if __name__=='__main__':unittest.main()
