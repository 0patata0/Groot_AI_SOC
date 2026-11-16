"""Temporary relay preserves normal reader; status cannot turn into control."""
import copy
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('reader_bridge_tested',Path(__file__).with_name('reader_bridge.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
ORIGINAL=b'''import sys,json
def incoming():return sys.stdin.buffer.read(4097)
def main():
 raw=incoming()
 sys.stdout.buffer.write(json.dumps({'preserved_bytes_hex':raw.hex()}).encode())
if __name__=='__main__':main()
'''


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='reader-relay-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'relay.py'
        self.source=m.build(ORIGINAL,hashlib.sha256(ORIGINAL).hexdigest());self.path.write_bytes(self.source)
        self.module=types.ModuleType('isolated_relay');self.module.__file__=str(self.path)
        exec(compile(self.source,'isolated-relay','exec'),self.module.__dict__)
        self.query={'schema':1,'host':'a','release_id':'a'*32}
        self.reply={'schema':1,'kind':'release_status',**self.query,
                    'source_contract_sha256':'d'*64,
                    'observed_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(),
                    'generation':'candidate','phase':'verified','mutation_performed':False,'isolated_filesystem':True,
                    'cache':{'status':'observed','source_filter_policy':'application-severity-v1'},
                    'files':[{'target':p,'sha256':'a'*64,'metadata_matches':True}for p in sorted(m.contract.TARGETS['a'])]}

    def run_reader(self,raw,args=(),env=None):
        e=os.environ.copy();e.pop('SSH_ORIGINAL_COMMAND',None);e['PYTHONDONTWRITEBYTECODE']='1'
        if env:e.update(env)
        return subprocess.run([sys.executable,'-B',str(self.path),*args],input=raw,capture_output=True,env=e,timeout=5)

    def test_normal_eof_snapshot_request_preserved(self):
        r=self.run_reader(b'');self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout),{'preserved_bytes_hex':''})

    def test_all_normal_requests_keep_original_exact_stream(self):
        for raw in (b'{"inventory":{"host":"b","view":"services"}}\n',b'{"journal_scope":"systemd"}',b'{"since":"KST"}',b'  {"view":"history"}  '):
            with self.subTest(raw=raw):
                r=self.run_reader(raw);self.assertEqual(r.returncode,0,r.stderr)
                self.assertEqual(json.loads(r.stdout)['preserved_bytes_hex'],raw.hex())

    def test_arbitrary_command_or_cli_path_cannot_be_selected(self):
        for args,env in ((['--socket','/tmp/socket'],None),([],{'SSH_ORIGINAL_COMMAND':'restart service'})):
            r=self.run_reader(b'',args,env);self.assertEqual(r.returncode,1);self.assertEqual(r.stdout,b'')

    def test_invalid_operator_payload_refused_before_original_main(self):
        for payload in ({'release_status':{'command':'restart'}},{'release_status':dict(self.query,schema=True)},
                        {'release_status':dict(self.query,path='/etc/shadow')}):
            r=self.run_reader(json.dumps(payload).encode());self.assertEqual(r.returncode,1);self.assertEqual(r.stdout,b'')

    def test_original_reader_digest_required(self):
        with self.assertRaisesRegex(ValueError,'original_reader_changed'):m.build(ORIGINAL,'b'*64)

    def test_original_bounds_and_syntax_checked(self):
        for raw in (b'',b'x'*131073,b'not valid python!'):
            with self.assertRaises((ValueError,SyntaxError)):m.build(raw,hashlib.sha256(raw).hexdigest())

    def call_client(self,value=None,query=None,*,peer=None,flags=0,fixture=True,raw=None):
        parent=self.root/'socket';parent.mkdir(exist_ok=True);parent.chmod(0o750)
        path=parent/'reader.sock';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        listener.bind(str(path));self.addCleanup(listener.close);self.addCleanup(path.unlink,missing_ok=True)
        response=json.dumps(value or self.reply).encode() if raw is None else raw
        uid=os.getuid() if peer is None else peer
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*exc):pass
            def settimeout(self,t):pass
            def connect(self,p):pass
            def getsockopt(self,*args):return struct.pack('3i',1,uid,os.getgid())
            def sendall(this,body):self.assertEqual(json.loads(body),query or self.query)
            def recvmsg(self,*args):return response,[],flags,None
        with patch.object(socket,'socket',return_value=Connection()),patch.object(socket,'SO_PEERCRED',17,create=True):
            return self.module._client(query or self.query,_socket_path=path,_peer_uid=os.getuid(),_allow_fixture=fixture)

    def test_bounded_peer_verified_reply(self):
        self.assertEqual(self.call_client(),self.reply)

    def test_foreign_peer_refused(self):
        with self.assertRaisesRegex(ValueError,'status_peer'):self.call_client(peer=os.getuid()+1)

    def test_fixture_witness_cannot_be_accepted_as_live(self):
        with self.assertRaisesRegex(ValueError,'status_read_only'):self.call_client(fixture=False)

    def test_status_reply_identity_and_shape_required(self):
        for change in ({'host':'b'},{'release_id':'b'*32},{'mutation_performed':True},{'schema':True},
                       {'phase':'run_shell'},{'generation':'complete'},{'files':[]},
                       {'observed_at_kst':'2026-11-17T00:00:00+00:00'}):
            value=copy.deepcopy(self.reply);value.update(change)
            with self.subTest(change=change):
                # Each query owns a separate local socket path.
                with self.assertRaises((ValueError,TypeError)):self.call_client(value)
                (self.root/'socket/reader.sock').unlink()

    def test_duplicate_or_oversize_or_truncated_reply_refused(self):
        for raw,flags in ((b'{"schema":1,"schema":1}',0),(b'x'*65537,0),(b'{}',socket.MSG_TRUNC)):
            with self.assertRaises(ValueError):self.call_client(raw=raw,flags=flags)
            (self.root/'socket/reader.sock').unlink()

    def test_status_works_without_loading_diagnostic_library(self):
        # Operator branch never calls the original main/library even if the
        # source cohort is temporarily between generations.
        import io
        original=self.module._base()
        original.incoming=lambda:json.dumps({'release_status':self.query}).encode()
        original.main=lambda:(_ for _ in ()).throw(AssertionError('original main must not run'))
        output=types.SimpleNamespace(buffer=io.BytesIO())
        with patch.object(self.module,'_base',return_value=original),patch.object(self.module,'_client',return_value=self.reply),patch.object(sys,'stdout',output),patch.object(sys,'argv',['relay']):
            self.module.main()
        self.assertEqual(json.loads(output.buffer.getvalue()),self.reply)


if __name__=='__main__':unittest.main()
