"""Bound normal-read admission and exact live-reader embedding semantics."""
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('release_reader_tested',Path(__file__).with_name('release_reader.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
ORIGINAL=b'def incoming():return b""\ndef main():pass\n'


class ReaderGate(unittest.TestCase):
    def setUp(self):
        self.sha=hashlib.sha256(ORIGINAL).hexdigest();self.digest='d'*64
        self.source=m.build(ORIGINAL,self.sha,host='b',release_id='a'*32,source_contract_sha256=self.digest)
        self.mod=types.ModuleType('fixture_bound_reader');self.mod.__file__='fixture-bound-reader'
        exec(compile(self.source,'fixture-bound-reader','exec'),self.mod.__dict__)

    def result(self,phase='staged',generation='baseline',policy=None):
        return {'source_contract_sha256':self.digest,'phase':phase,'generation':generation,'cache':{'status':'observed','source_filter_policy':policy}}

    def normal(self,value,raw=b''):
        called=[];original=types.SimpleNamespace(incoming=lambda:raw,main=lambda:called.append(True))
        with patch.object(self.mod,'_base',return_value=original),patch.object(self.mod,'_client',return_value=value),patch.object(sys,'argv',['reader']):
            self.mod.main()
        self.assertEqual(original.incoming(),raw);return called

    def test_stable_baseline_and_confirmed_candidate_admit_normal(self):
        for value in (self.result(),self.result('rolled_back'),self.result('confirmed','candidate','application-severity-v1')):
            with self.subTest(value=value):self.assertEqual(self.normal(value),[True])

    def test_every_intermediate_phase_denies_normal_without_loading_original(self):
        for phase in ('armed','quiesced','backed_up','applying','applied','verified','confirming','rolling_back','failed','unknown'):
            with self.subTest(phase=phase):
                with self.assertRaisesRegex(ValueError,'normal_reads_quiesced'):self.normal(self.result(phase))

    def test_no_false_normal_admission_for_wrong_generation_or_policy(self):
        for value in (self.result('confirmed','baseline'),self.result('confirmed','candidate'),self.result('staged','candidate','application-severity-v1'),self.result('rolled_back','baseline','application-severity-v1')):
            with self.assertRaisesRegex(ValueError,'normal_reads_quiesced'):self.normal(value)

    def test_unknown_cache_and_other_source_contract_deny_normal(self):
        value=self.result();value['cache']['status']='unavailable'
        with self.assertRaisesRegex(ValueError,'normal_reads_quiesced'):self.normal(value)
        value=self.result();value['source_contract_sha256']='e'*64
        with self.assertRaisesRegex(ValueError,'release_source_contract'):self.normal(value)

    def test_raw_normal_input_is_not_rewritten(self):
        self.assertEqual(self.normal(self.result(),b'  {"inventory":{"host":"b"}}\n'),[True])

    def test_witness_failure_denies_normal(self):
        called=[];original=types.SimpleNamespace(incoming=lambda:b'',main=lambda:called.append(True))
        with patch.object(self.mod,'_base',return_value=original),patch.object(self.mod,'_client',side_effect=OSError('witness unavailable')),patch.object(sys,'argv',['reader']):
            with self.assertRaises(OSError):self.mod.main()
        self.assertFalse(called)

    def test_operator_status_still_works_while_normal_is_fenced(self):
        import json
        reply=self.result('applying','mixed');raw=json.dumps({'release_status':{'schema':1,'host':'b','release_id':'a'*32}}).encode()
        original=types.SimpleNamespace(incoming=lambda:raw,main=lambda:(_ for _ in ()).throw(AssertionError('must not call original')))
        out=types.SimpleNamespace(buffer=io.BytesIO())
        with patch.object(self.mod,'_base',return_value=original),patch.object(self.mod,'_client',return_value=reply),patch.object(sys,'stdout',out),patch.object(sys,'argv',['reader']):self.mod.main()
        self.assertEqual(json.loads(out.buffer.getvalue()),reply)

    def test_bound_identity_cannot_expand_into_paths_commands_or_foreign_hosts(self):
        for update in ({'host':'d'},{'release_id':'../escape'},{'source_contract_sha256':'bad'}):
            kwargs={'host':'b','release_id':'a'*32,'source_contract_sha256':self.digest};kwargs.update(update)
            with self.assertRaises(ValueError):m.build(ORIGINAL,self.sha,**kwargs)

    def test_original_source_and_generic_builder_remain_pinned(self):
        with self.assertRaises(ValueError):m.build(ORIGINAL,'e'*64,host='b',release_id='a'*32,source_contract_sha256=self.digest)
        self.assertEqual(hashlib.sha256((m.HERE/'reader_bridge.py').read_bytes()).hexdigest(),m.BASE_SHA)

    def test_confirmed_candidate_uses_the_pinned_normal_protocol_and_baseline_keeps_original(self):
        normal=b'def incoming():return b""\ndef main():pass\n'
        raw=b'{"inventory":{"host":"b"}}';calls=[]
        source=m.build(ORIGINAL,self.sha,host='b',release_id='a'*32,source_contract_sha256=self.digest,
                       normal_reader=normal,normal_reader_sha256=hashlib.sha256(normal).hexdigest())
        mod=types.ModuleType('candidate_protocol');mod.__file__='candidate-protocol'
        exec(compile(source,'candidate-protocol','exec'),mod.__dict__)
        for candidate in (False,True):
            before=types.SimpleNamespace(incoming=lambda:raw,main=lambda:calls.append('before'))
            after=types.SimpleNamespace(main=lambda:calls.append('after'))
            value=self.result('confirmed','candidate','application-severity-v1')if candidate else self.result()
            with patch.object(mod,'_base',return_value=before),patch.object(mod,'_normal_reader',return_value=after),patch.object(mod,'_client',return_value=value),patch.object(sys,'argv',['reader']):mod.main()
            if candidate:self.assertEqual(after.incoming(),raw)
        self.assertEqual(calls,['before','after'])

    def test_changed_normal_protocol_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'normal_reader_digest'):
            m.build(ORIGINAL,self.sha,host='b',release_id='a'*32,source_contract_sha256=self.digest,
                    normal_reader=ORIGINAL,normal_reader_sha256='e'*64)


if __name__=='__main__':unittest.main()
