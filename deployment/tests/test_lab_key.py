"""Common UTF-8 key contract and read-only/pipe boundaries; synthetic keys only."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lab_key as k


class KeyProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        patcher = patch.object(k, 'ROOT', self.root); patcher.start(); self.addCleanup(patcher.stop)
        self.value = 'Synthetic-common-key!'
        self.config(self.value)

    def config(self, value):
        path = self.root/'siem.json'
        path.write_text(json.dumps({'schema_version':1,'indexer_username':'admin','indexer_password':value}))
        path.chmod(0o600)

    def validate_fixture_file(self, path, limit):
        info=path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode),0o600)
        self.assertLessEqual(info.st_size,limit)

    def test_character_count_is_not_utf8_byte_count(self):
        for value in ('abcd1234', '😀'*8, '한'*256, '😀'*256, 'a'*256, '  abcd  '):
            with self.subTest(kind=len(value.encode())):
                self.assertEqual(k.key(value.encode()),value.encode())
        for value in ('😀'*4, '한'*7, 'a'*7, 'a'*257, '😀'*257):
            with self.subTest(characters=len(value)), self.assertRaises(k.Refused):
                k.key(value.encode())

    def test_invalid_utf8_and_overlong_input_have_safe_specific_errors(self):
        for value, error in ((b'abcdefgh\xff','key_invalid_utf8'),(b'x'*1025,'key_utf8_bytes_exceed_1024'),
                             (b'1234567','key_requires_8_to_256_unicode_characters'),(b'abc\rdefghi','key_carriage_return_not_representable')):
            with self.assertRaisesRegex(k.Refused,error):k.key(value)
        # DEL is accepted by both the SIEM JSON policy and the application; the
        # previous transport-specific ASCII filter rejected it only after apply.
        self.assertEqual(k.key(b'abcdefg\x7f'),b'abcdefg\x7f')

    def test_check_is_read_only_and_never_prints_key_or_digest(self):
        self.config('😀'*8)
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        out=io.StringIO(); err=io.StringIO()
        with patch.object(k.os,'geteuid',return_value=0),patch.object(k,'safe',side_effect=self.validate_fixture_file), \
             contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            self.assertEqual(k.cli(['check']),0)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.iterdir()})
        for private in ('😀'*8,hashlib.sha256(('😀'*8).encode()).hexdigest()):
            self.assertNotIn(private,out.getvalue()+err.getvalue())
        self.assertIn('verified',out.getvalue())

    def test_siem_accepted_short_unicode_key_is_rejected_before_export(self):
        # 4 emoji = 16 bytes, previously accepted by SIEM's byte-only minimum.
        self.config('😀'*4)
        out=io.StringIO();err=io.StringIO()
        with patch.object(k.os,'geteuid',return_value=0),patch.object(k,'safe',side_effect=self.validate_fixture_file), \
             contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            self.assertEqual(k.cli(['check']),1)
        self.assertEqual(out.getvalue(),'')
        self.assertIn('8_to_256_unicode_characters',err.getvalue())
        self.assertNotIn('😀',err.getvalue())

    def test_source_schema_duplicate_keys_and_wrong_types_rejected(self):
        path=self.root/'siem.json'
        for value in ('{"schema_version":1,"schema_version":1}',
                      json.dumps({'schema_version':True,'indexer_username':'admin','indexer_password':self.value}),
                      json.dumps({'schema_version':1,'indexer_username':'other','indexer_password':self.value}),
                      json.dumps({'schema_version':1,'indexer_username':'admin','indexer_password':['private fixture']}),
                      '{"indexer_password": broken private fixture'):
            path.write_text(value)
            with self.subTest(value_type=value[:24]),patch.object(k,'safe',side_effect=self.validate_fixture_file),self.assertRaises(k.Refused):
                k.source_key()

    def test_new_file_roundtrips_terminal_newline_and_unicode_exactly_as_app(self):
        for value in ('😀'*256, '  exact spaces  ', 'line\nending\n'):
            destination=self.root/'lab-admin.key'
            with patch.object(k,'parents_safe'),patch.object(k.os,'fchown'):
                k.receive(value.encode())
            self.assertEqual(destination.read_text(encoding='utf-8').removesuffix('\n'),value)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o600)
            self.assertLessEqual(destination.stat().st_size,1025)
            destination.unlink()

    def test_existing_optional_lf_file_is_idempotent_and_mismatch_is_preserved(self):
        destination=self.root/'lab-admin.key'
        for suffix in (b'',b'\n'):
            original=self.value.encode()+suffix
            destination.write_bytes(original);destination.chmod(0o600)
            with patch.object(k,'safe',side_effect=self.validate_fixture_file):
                k.receive(self.value.encode())
                with self.assertRaisesRegex(k.Refused,'existing_common_key_differs'):
                    k.receive(b'another-synthetic-key')
            self.assertEqual(destination.read_bytes(),original)

    def test_receive_rejects_oversized_pipe_before_creating_file(self):
        stream=SimpleNamespace(buffer=io.BytesIO(b'x'*1025))
        err=io.StringIO();out=io.StringIO()
        with patch.object(k.os,'geteuid',return_value=0),patch.object(k.sys,'stdin',stream), \
             contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            self.assertEqual(k.cli(['receive']),1)
        self.assertFalse((self.root/'lab-admin.key').exists())
        self.assertEqual(out.getvalue(),'')
        self.assertIn('bytes_exceed_1024',err.getvalue())

    def test_export_is_exact_binary_protocol_and_emits_no_status_line(self):
        self.config('Unicode-한글-😀')
        output=SimpleNamespace(buffer=io.BytesIO())
        with patch.object(k.os,'geteuid',return_value=0),patch.object(k,'safe',side_effect=self.validate_fixture_file),patch.object(k.sys,'stdout',output):
            self.assertEqual(k.cli(['export']),0)
        self.assertEqual(output.buffer.getvalue(),'Unicode-한글-😀'.encode())

    def test_failure_never_echoes_private_exception_or_cli_argument(self):
        err=io.StringIO()
        with patch.object(k.os,'geteuid',return_value=0),contextlib.redirect_stderr(err):
            self.assertEqual(k.cli(['secret-used-as-invalid-action']),1)
        self.assertNotIn('secret-used-as-invalid-action',err.getvalue())
        err=io.StringIO()
        with patch.object(k.os,'geteuid',return_value=0),patch.object(k,'source_key',side_effect=OSError('private failure context')),contextlib.redirect_stderr(err):
            self.assertEqual(k.cli(['check']),1)
        self.assertNotIn('private failure context',err.getvalue())

    def test_root_private_file_and_non_writable_parent_contract(self):
        path=Path('/root/fixture/common.key')
        def metadata(candidate):
            if candidate==path:
                return SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_gid=0,st_nlink=1,st_size=20)
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0)
        with patch.object(Path,'lstat',metadata):k.safe(path,1025)
        for field,value in [('st_mode',stat.S_IFREG|0o644),('st_mode',stat.S_IFLNK|0o777),('st_uid',1000),('st_nlink',2),('st_size',1026)]:
            def changed(candidate):
                info=metadata(candidate)
                if candidate==path:setattr(info,field,value)
                return info
            with self.subTest(field=field),patch.object(Path,'lstat',changed),self.assertRaises(k.Refused):k.safe(path,1025)


if __name__=='__main__':unittest.main()
