"""Linux kernel IPC on a private fixture; no operating paths/ports/services."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import threading
import types
import unittest

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
tests=load('release_status_ipc_fixture','test_release_status.py')
m=tests.m;bridge=load('release_ipc_bridge','reader_bridge.py')


@unittest.skipUnless(sys.platform=='linux' and hasattr(socket,'SO_PEERCRED'),'Linux SO_PEERCRED/SEQPACKET kernel required')
class KernelIPC(unittest.TestCase):
    # Reuse the safe fixture, not its test cases.
    setUp=tests.WitnessTests.setUp


def kernel_roundtrip(self,request,*,trusted=True):
    self.witness.reader_uid=os.getuid() if trusted else os.getuid()+1
    parent=self.root/'ipc';parent.mkdir();parent.chmod(0o750);path=parent/'reader.sock'
    errors=[]
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)as listener:
        listener.bind(str(path));listener.listen(1);listener.settimeout(3)
        def server():
            try:
                client,_=listener.accept()
                with client:m.reply_to(self.witness,client)
            except BaseException as exc:errors.append(type(exc).__name__)
        t=threading.Thread(target=server,daemon=True);t.start()
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)as conn:
                conn.settimeout(3);conn.connect(str(path))
                try:conn.sendall(request);reply=conn.recv(65537)
                except (ConnectionResetError,BrokenPipeError):
                    if trusted:raise
                    # Linux can reset a socket closed with an unread packet;
                    # unauthorized peers are rejected before payload parsing.
                    reply=b'{"status":"peer_closed"}'
        finally:t.join(4)
        self.assertFalse(t.is_alive());self.assertFalse(errors)
    path.unlink();return json.loads(reply)


def test_kernel_peer_verified_query(self):
    self.witness.reader_uid=os.getuid()
    parent=self.root/'ipc';parent.mkdir();parent.chmod(0o750);path=parent/'reader.sock'
    raw=b'def incoming():return b""\ndef main():raise RuntimeError("normal reader unused")\n'
    source=bridge.build(raw,hashlib.sha256(raw).hexdigest());module=types.ModuleType('ipc_client');exec(compile(source,'ipc-client','exec'),module.__dict__)
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)as listener:
        listener.bind(str(path));listener.listen(1);listener.settimeout(3)
        errors=[]
        def serve():
            try:
                client,_=listener.accept()
                with client:m.reply_to(self.witness,client)
            except BaseException as exc:errors.append(type(exc).__name__)
        t=threading.Thread(target=serve,daemon=True);t.start()
        try:value=module._client(self.query,_socket_path=path,_peer_uid=os.getuid(),_allow_fixture=True)
        finally:t.join(4)
        self.assertFalse(t.is_alive());self.assertFalse(errors)
    self.assertEqual(value['generation'],'baseline');self.assertIs(value['mutation_performed'],False)


def test_kernel_wrong_reader_uid(self):
    if os.getuid()==0:self.skipTest('root is explicitly authorized; run this test as an unprivileged UID')
    value=kernel_roundtrip(self,m.canonical(self.query),trusted=False)
    self.assertIn(value.get('status'),('unavailable','peer_closed'));self.assertNotIn('files',value)


def test_kernel_oversized_packet(self):
    value=kernel_roundtrip(self,b'x'*8192)
    self.assertEqual(value.get('status'),'unavailable');self.assertNotIn('files',value)


def test_kernel_duplicate_query(self):
    value=kernel_roundtrip(self,b'{"schema":1,"schema":1,"host":"b","release_id":"'+b'a'*32+b'"}')
    self.assertEqual(value.get('status'),'unavailable');self.assertNotIn('files',value)


for function in (test_kernel_peer_verified_query,test_kernel_wrong_reader_uid,test_kernel_oversized_packet,test_kernel_duplicate_query):
    setattr(KernelIPC,function.__name__,function)


if __name__=='__main__':unittest.main()
