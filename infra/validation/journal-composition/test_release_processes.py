"""Dedicated-account boundaries, pidfd identity and fail-closed drain tests."""
import copy
import importlib.util
from pathlib import Path
import signal
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('release_processes_tested','release_processes.py')
source=load('release_process_fixture','test_release_files.py')


class Backend:
    def __init__(self):
        self.rows={10:{'pid':10,'uid':0,'ppid':1,'start_ticks':1},
                   20:{'pid':20,'uid':77,'ppid':10,'start_ticks':2},
                   21:{'pid':21,'uid':88,'ppid':10,'start_ticks':3},
                   30:{'pid':30,'uid':0,'ppid':10,'start_ticks':4},
                   40:{'pid':40,'uid':1000,'ppid':10,'start_ticks':5}}
        self.sent=[];self.closed=[];self.opened=[];self.reuse=False;self.ignore_term=False;self.new_once=False;self.disappear=False
    def pids(self):return sorted(self.rows)
    def one(self,pid):return copy.deepcopy(self.rows.get(pid))
    def sshd(self,pid):return pid==10
    def open(self,pid):
        self.opened.append(pid)
        if self.reuse:self.rows[pid]['start_ticks']+=100
        if self.disappear:self.rows.pop(pid,None)
        return pid+1000
    def send(self,fd,number):
        pid=fd-1000;self.sent.append((pid,number))
        if pid not in self.rows:raise ProcessLookupError()
        if number==signal.SIGTERM and self.ignore_term:return
        self.rows.pop(pid)
        if self.new_once:self.rows[22]={'pid':22,'uid':77,'ppid':10,'start_ticks':8};self.new_once=False
    def close(self,fd):self.closed.append(fd)


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.helper=source.SourceTransaction(methodName='runTest');self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.fs=self.helper.prepare();self.fs.install_barriers();self.backend=Backend();self.flags={'collection':True,'consumer':True,'mcp':True};self.phase='armed'
        self.controls=types.SimpleNamespace(fenced=lambda key:self.flags[key]);self.journal=types.SimpleNamespace(read=lambda:({'phase':self.phase},'digest'))
        self.readers=m.Readers(self.fs,self.controls,self.journal,77,88,backend=self.backend)

    def test_only_dedicated_ssh_descendants_are_drained(self):
        result=self.readers.drain();self.assertTrue(result['quiesced']);self.assertTrue(result['isolated_filesystem'])
        self.assertEqual({r['pid']for r in result['terminated']},{20,21});self.assertEqual(set(self.backend.rows),{10,30,40})
        self.assertEqual(self.backend.opened,[20,21]);self.assertEqual(self.backend.closed,[1020,1021]);self.assertEqual(result['empty_observations'],3)

    def test_all_fences_are_required_before_any_signal(self):
        for name in self.flags:
            with self.subTest(name=name):
                self.flags[name]=False
                with self.assertRaises(m.Refused):self.readers.drain()
                self.assertEqual(self.backend.sent,[]);self.flags[name]=True

    def test_confirmed_phase_alone_does_not_fence_normal_readers(self):
        self.phase='confirmed'
        with self.assertRaisesRegex(m.Refused,'reader_phase_not_fenced'):self.readers.drain()
        self.assertEqual(self.backend.sent,[])

    def test_source_barrier_bytes_must_match(self):
        row=next(r for r in self.fs.rows if r['target']==source.m.READER);path=self.fs.target(row);path.chmod(0o600);path.write_bytes(b'foreign');path.chmod(row['mode'])
        with self.assertRaisesRegex(m.Refused,'reader_barrier_changed'):self.readers.drain()
        self.assertEqual(self.backend.sent,[])

    def test_orphan_dedicated_process_blocks_entire_snapshot(self):
        self.backend.rows[21]['ppid']=1
        with self.assertRaisesRegex(m.Refused,'reader_not_ssh_descendant'):self.readers.drain()
        self.assertEqual(self.backend.opened,[]);self.assertEqual(self.backend.sent,[])

    def test_changed_or_unavailable_parent_is_not_an_empty_account(self):
        self.backend.rows[21]['ppid']=99
        with self.assertRaisesRegex(m.Refused,'reader_ancestry_unavailable'):self.readers.drain()
        self.assertEqual(self.backend.sent,[])

    def test_other_user_in_ancestry_is_refused(self):
        self.backend.rows[21]['ppid']=40
        with self.assertRaisesRegex(m.Refused,'reader_process_ancestry'):self.readers.drain()
        self.assertEqual(self.backend.sent,[])

    def test_pid_reuse_after_open_never_signals_replacement(self):
        self.backend.reuse=True
        with self.assertRaisesRegex(m.Refused,'reader_pid_reused'):self.readers.drain()
        self.assertEqual(self.backend.sent,[]);self.assertEqual(self.backend.closed,[1020])

    def test_disappeared_process_and_new_connections_are_rechecked(self):
        self.backend.disappear=True;result=self.readers.drain();self.assertTrue(result['quiesced']);self.assertEqual(set(self.backend.rows),{10,30,40})
        self.backend=Backend();self.readers.backend=self.backend;self.backend.new_once=True
        result=self.readers.drain();self.assertEqual({r['pid']for r in result['terminated']},{20,21,22})

    def test_term_ignoring_peer_is_killed_by_same_pidfd(self):
        self.backend.ignore_term=True
        with patch.object(m.time,'monotonic',side_effect=range(30)),patch.object(m.time,'sleep'):
            result=self.readers.drain(timeout=15)
        self.assertTrue(result['quiesced']);self.assertEqual({p for p,s in self.backend.sent if s==signal.SIGKILL},{20,21})

    def test_no_time_budget_cannot_claim_quiesced(self):
        with patch.object(m.time,'monotonic',side_effect=[0,2]):
            with self.assertRaisesRegex(m.Refused,'reader_drain_incomplete'):self.readers.drain(timeout=1)
        self.assertEqual(self.backend.sent,[])

    def test_account_and_fixture_execution_boundaries(self):
        for reader,mcp in ((0,88),(77,0),(77,77),(True,88)):
            with self.assertRaises(m.Refused):m.Readers(self.fs,self.controls,self.journal,reader,mcp,backend=self.backend)
        with self.assertRaisesRegex(m.Refused,'proc_execution_boundary'):m.Readers(self.fs,self.controls,self.journal,77,88)


if __name__=='__main__':unittest.main()
