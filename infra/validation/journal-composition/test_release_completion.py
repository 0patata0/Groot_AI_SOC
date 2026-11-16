"""All-host completion and interrupted cleanup on isolated filesystems.

Real metadata, immutable receipts, SQLite and atomic pointer publication;
service/reader/Docker backends are fixtures, not native operating acceptance.
Synthetic acceptance digests never attest that a real bot test has passed.
"""
import copy
from datetime import timedelta
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('completion_tested','release_completion.py')
fixture=load('completion_lifecycle_fixture','test_release_lifecycle.py')


class Helpers(fixture.helper_fixture.Backend):
    def __init__(self,root):super().__init__();self.root=root
    def __call__(self,args,*,timeout):
        if args[1]=='show':
            name=args[2];fragment=fixture.control_module.RUNNER if '@'in name else name
            path=self.root/'etc/systemd/system'/fragment
            if not path.exists():self.rows[name].update(LoadState='not-found',FragmentPath='',UnitFileState='not-found')
        return super().__call__(args,timeout=timeout)


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.LifecycleTests(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.controllers={}
        for host,n in self.f.nodes.items():
            backend=Helpers(n['files'].root);n['controller'].helpers.runner=backend;n['helper_backend']=backend
            self.controllers[host]=m.Completion(n['controller'])
        self.b=self.controllers['b']

    def candidate(self):self.f.confirmed();self.f.resume();self.accept()

    def baseline(self):
        self.f.step('prepare')
        for n in self.f.nodes.values():n['controller'].execute('rollback')
        self.accept()

    def accept(self):
        for host,completion in self.controllers.items():
            ctl=completion.ctl
            value={'schema':1,'host':host,'release_id':ctl.files.release_id,'plan_sha256':ctl.store.plan,
                'bundle_sha256':m.digest(ctl.store.read('bundle.json')),'outcome':completion.outcome(),
                'at_kst':ctl.clock().isoformat(),'reference':'synthetic-acceptance-no-real-bot-posts',
                'checks':{k:{'status':'passed','evidence_sha256':'d'*64}for k in m.CHECKS}}
            ctl.store.immutable('acceptance.json',value)

    def prepare(self):
        proofs=self.f.proofs()
        for host in 'acb':self.controllers[host].prepare(proofs)

    def decided(self):
        self.prepare();proofs={h:ctl.proof()for h,ctl in self.controllers.items()}
        for ctl in self.controllers.values():ctl.decide(proofs)

    def authorized(self):
        self.decided();proofs={h:ctl.proof()for h,ctl in self.controllers.items()}
        for ctl in self.controllers.values():ctl.authorize(proofs)

    def test_complete_candidate_keeps_original_receipts_and_operating_services(self):
        self.candidate();self.authorized();original={};cache={}
        for host,n in self.f.nodes.items():
            original[host]={p:(n['files'].root/p.lstrip('/')).read_bytes()for p,r in n['controller'].plan['hosts'][host]['protected'].items()if r is not None}
            cache[host]=n['cache'].path.read_bytes();n['backend'].calls=[]
        for host in 'acb':
            ctl=self.controllers[host];ctl.cleanup();value=ctl.current()
            self.assertEqual(value['status'],'verified');self.assertEqual(value['outcome'],'candidate')
            self.assertEqual(len(value['installed']),len(ctl.files.rows));self.assertIsNone(ctl.store.active(absent=True))
            self.assertEqual(ctl.files.root.joinpath('var/lib/capstone-journal-release/current.json').stat().st_mode&0o777,0o600)
            for p,raw in original[host].items():self.assertEqual((ctl.files.root/p.lstrip('/')).read_bytes(),raw)
            self.assertEqual(ctl.ctl.cache.path.read_bytes(),cache[host])
            self.assertFalse(any(args[1]in ('stop','start','update')for args,_ in self.f.nodes[host]['backend'].calls))
        self.assertEqual(self.b.current()['initial_stage'],'prepared_only')
        self.assertTrue(self.f.nodes['b']['backend'].container['running'])

    def test_baseline_noop_completion_restores_only_owned_relays(self):
        self.baseline();self.authorized()
        for ctl in self.controllers.values():
            before=ctl.ctl.cache.path.read_bytes();ctl.cleanup();value=ctl.current()
            self.assertEqual(value['outcome'],'baseline');ctl.files.check('before_sha256')
            self.assertEqual(ctl.ctl.cache.path.read_bytes(),before)

    def test_source_confirmation_alone_is_not_acceptance(self):
        self.f.confirmed();self.f.resume();before=self.f.b.state()
        with self.assertRaisesRegex(ValueError,'operator_acceptance_required'):self.b.prepare(self.f.proofs())
        self.assertEqual(self.f.b.state(),before);self.assertTrue(self.f.nodes['b']['backend'].container['running'])

    def test_unverified_or_missing_acceptance_checks_cannot_prepare(self):
        self.candidate();p=self.b.files.storage/'acceptance.json';value=json.loads(p.read_bytes());value['checks']['mcp']['status']='unverified';p.write_bytes(m.c.canonical(value))
        with self.assertRaisesRegex(ValueError,'acceptance_check_unverified'):self.b.prepare(self.f.proofs())
        value['checks'].pop('mcp');p.write_bytes(m.c.canonical(value))
        with self.assertRaisesRegex(ValueError,'acceptance_checks'):self.b.prepare(self.f.proofs())

    def test_all_hosts_must_record_the_same_decision_before_authorization(self):
        self.candidate();self.prepare();proofs={h:ctl.proof()for h,ctl in self.controllers.items()};self.b.decide(proofs)
        ready={h:ctl.proof()for h,ctl in self.controllers.items()}
        with self.assertRaisesRegex(ValueError,'cleanup_peer_decision'):self.b.authorize(ready)
        self.assertFalse(self.b.ctl.state()['facts'].get('cleanup_authorization_sha256'))

    def test_stale_or_mixed_outcome_peer_proofs_are_refused(self):
        self.candidate();self.prepare();proofs={h:ctl.proof()for h,ctl in self.controllers.items()}
        wrong=copy.deepcopy(proofs);wrong['c']['outcome']='baseline'
        with self.assertRaisesRegex(ValueError,'cleanup_peer_identity'):self.b.decide(wrong)
        wrong=copy.deepcopy(proofs);wrong['c']['at_kst']=(self.b.ctl.clock()-timedelta(seconds=20)).isoformat()
        with self.assertRaisesRegex(ValueError,'cleanup_peer_freshness'):self.b.decide(wrong)

    def test_stopped_original_service_prevents_completion(self):
        self.candidate();self.f.nodes['b']['backend'].container.update(running=False,pid=0)
        with self.assertRaises(ValueError):self.b.prepare(self.f.proofs())
        self.assertFalse(self.b.ctl.state()['facts'].get('completion_prepared'))

    def test_foreign_source_or_pointer_is_refused_before_relay_cleanup(self):
        self.candidate();self.authorized();raw=self.b.files.read_target(next(r for r in self.b.files.rows if r['target']==m.source.READER))[0]
        pointer={**self.b.store.token,'release_id':'f'*32,'bundle_sha256':'a'*64,'receipt_sha256':'b'*64,'runtime_sha256':'c'*64}
        (self.b.store.base/'current.json').write_bytes(m.c.canonical(pointer));(self.b.store.base/'current.json').chmod(0o600)
        with self.assertRaisesRegex(ValueError,'current_pointer_changed'):self.b.cleanup()
        self.assertEqual(self.b.files.read_target(next(r for r in self.b.files.rows if r['target']==m.source.READER))[0],raw)
        self.assertIsNone(self.b.ctl.state()['pending'])

    def test_foreign_control_file_is_not_removed(self):
        self.candidate();self.authorized();p=next(iter(self.b.ctl.controls.docs));path=self.b.files.root/p.relative_to('/');path.write_bytes(b'foreign directive')
        with self.assertRaisesRegex(ValueError,'foreign_control_file'):self.b.cleanup()
        self.assertEqual(path.read_bytes(),b'foreign directive');self.assertFalse(self.b.ctl.state()['facts'].get('helpers_disarmed'))

    def test_partial_document_cleanup_retries_without_stopping_consumers(self):
        self.candidate();self.authorized();real=self.b.ctl.controls.remove;seen=[]
        def interrupted(*args,**kwargs):
            if seen:raise OSError('lost connection after one owned removal')
            value=real(*args,**kwargs);seen.append(True);return value
        with patch.object(self.b.ctl.controls,'remove',side_effect=interrupted):
            with self.assertRaises(OSError):self.b.cleanup()
        self.f.nodes['b']['backend'].calls=[];self.b.ctl.execute('recover');self.b.cleanup();self.b.current()
        self.assertFalse(any(args[1]in ('stop','start','update')for args,_ in self.f.nodes['b']['backend'].calls))

    def test_pointer_published_then_lost_finish_can_resume_after_expiry(self):
        self.candidate();self.authorized()
        with patch.object(self.b.journal,'finish',side_effect=OSError('finish lost')):
            with self.assertRaises(OSError):self.b.cleanup()
        self.assertIsNotNone(self.b.store.current()[0])
        with self.assertRaisesRegex(ValueError,'current_cleanup_incomplete'):self.b.current()
        self.f.offset=timedelta(minutes=20);self.b.cleanup();self.assertEqual(self.b.current()['status'],'verified')

    def test_lost_ownership_release_does_not_repeat_cleanup_mutations(self):
        self.candidate();self.authorized()
        with patch.object(self.b.store,'relinquish',side_effect=OSError('lost ownership release')):
            with self.assertRaises(OSError):self.b.cleanup()
        self.assertTrue(self.b.ctl.state()['facts']['cleanup_complete']);self.f.offset=timedelta(minutes=20)
        with patch.object(self.b.files,'restore_barriers',side_effect=AssertionError('duplicate protected operation')):
            self.b.cleanup()
        self.assertEqual(self.b.current()['status'],'verified')

    def test_lost_prepare_finish_keeps_services_and_original_acceptance_receipt(self):
        self.candidate();before=self.b.store.read('acceptance.json')
        with patch.object(self.b.journal,'finish',side_effect=OSError('finish lost')):
            with self.assertRaises(OSError):self.b.prepare(self.f.proofs())
        self.f.nodes['b']['backend'].calls=[];self.b.ctl.execute('recover');self.b.prepare(self.f.proofs())
        self.assertEqual(self.b.store.read('acceptance.json'),before)
        self.assertFalse(any(args[1]in ('stop','start','update')for args,_ in self.f.nodes['b']['backend'].calls))

    def test_first_cleanup_after_approval_expiry_is_not_started(self):
        self.candidate();self.authorized();self.f.offset=timedelta(minutes=20)
        with self.assertRaisesRegex(ValueError,'approval_expired'):self.b.cleanup()
        self.assertIsNone(self.b.ctl.state()['pending']);self.assertIsNone(self.b.store.current()[0])

    def test_initial_receipt_drift_is_not_silently_repaired(self):
        self.candidate();self.authorized();self.b.cleanup();path=self.b.files.root/'var/lib/capstone-diagnostics/installation/prepared.json';path.write_bytes(b'changed historical receipt')
        with self.assertRaisesRegex(ValueError,'protected_state_changed'):self.b.current()
        self.assertEqual(path.read_bytes(),b'changed historical receipt')

    def test_current_witness_checks_actual_source_and_not_just_saved_hash(self):
        self.candidate();self.authorized();self.b.cleanup()
        row=next(r for r in self.b.files.rows if r['target']not in m.source.BARRIERS['b']and r['after_sha256'])
        path=self.b.files.target(row);path.write_bytes(b'foreign current code')
        with self.assertRaisesRegex(ValueError,'completion_core_changed'):self.b.current()

    def test_new_cache_observations_do_not_invalidate_source_receipt(self):
        self.candidate();self.authorized();self.b.cleanup()
        self.f.nodes['b']['legacy'].mutate('INSERT INTO events VALUES(?,?,?,?)',('after-cleanup',3500001,'example.service','{}'))
        self.assertEqual(self.b.current()['status'],'verified')

    def test_current_pointer_or_completion_receipt_change_is_detected(self):
        self.candidate();self.authorized();self.b.cleanup();p=self.b.store.base/'current.json';old=p.read_bytes()
        value=json.loads(old);value['release_id']='f'*32;p.write_bytes(m.c.canonical(value))
        with self.assertRaisesRegex(ValueError,'current_pointer_changed'):self.b.current()
        p.write_bytes(old);p=self.b.files.storage/'completion.json';value=json.loads(p.read_bytes());value['outcome']='baseline';p.write_bytes(m.c.canonical(value))
        with self.assertRaisesRegex(ValueError,'completion_receipt_changed'):self.b.current()

    def test_lost_decision_record_ack_reuses_the_same_immutable_evidence(self):
        self.candidate();self.prepare();proofs={h:ctl.proof()for h,ctl in self.controllers.items()}
        with patch.object(self.b.journal,'mark',side_effect=OSError('decision ack lost')):
            with self.assertRaises(OSError):self.b.decide(proofs)
        old=self.b.store.read('cleanup-decision.json');self.f.offset=timedelta(minutes=20)
        self.b.decide(proofs);self.assertEqual(self.b.store.read('cleanup-decision.json'),old)
        self.assertEqual(self.b.ctl.state()['facts']['cleanup_decision_sha256'],m.digest(old))

    def test_lost_grant_record_ack_does_not_create_a_second_authorization(self):
        self.candidate();self.decided();proofs={h:ctl.proof()for h,ctl in self.controllers.items()}
        with patch.object(self.b.journal,'mark',side_effect=OSError('grant ack lost')):
            with self.assertRaises(OSError):self.b.authorize(proofs)
        old=self.b.store.read('cleanup-grant.json');self.f.offset=timedelta(minutes=20)
        self.b.authorize(proofs);self.assertEqual(self.b.store.read('cleanup-grant.json'),old)
        self.assertEqual(self.b.ctl.state()['facts']['cleanup_authorization_sha256'],m.digest(old))

    def test_source_drift_is_rejected_before_any_relay_or_unit_removal(self):
        self.candidate();self.authorized();before={p:self.b.ctl.controls.read(p,mode=0o644)[0]for p in self.b.ctl.controls.docs}
        row=next(r for r in self.b.files.rows if r['target']not in m.source.BARRIERS['b']and r['after_sha256']);self.b.files.target(row).write_bytes(b'foreign code')
        with self.assertRaisesRegex(ValueError,'completion_core_changed'):self.b.cleanup()
        self.assertEqual(before,{p:self.b.ctl.controls.read(p,mode=0o644)[0]for p in self.b.ctl.controls.docs})

    def test_a_new_helper_process_cannot_be_hidden_by_a_saved_cleanup_receipt(self):
        self.candidate();self.authorized();self.b.cleanup()
        name=fixture.control_module.WATCH;self.f.nodes['b']['helper_backend'].rows[name].update(ActiveState='active',MainPID='44444')
        with self.assertRaisesRegex(ValueError,'helper_not_stopped'):self.b.current()


if __name__=='__main__':unittest.main()
