"""Immutable artifact and cross-release lock tests on an isolated filesystem."""
import copy
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('release_storage_tested','release_storage.py')
source=load('release_storage_fixture','test_release_files.py')


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.helper=source.SourceTransaction(methodName='runTest');self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.fs=self.helper.prepare();base=self.fs.witness.root/m.c.BASE.relative_to('/');base.chmod(0o700)
        self.store=m.Store(self.fs,'b'*64)

    def test_immutable_artifact_same_bytes_is_noop(self):
        value={'schema':1,'units':{'one':'before'}}
        self.assertTrue(self.store.immutable('baseline.json',value));self.assertFalse(self.store.immutable('baseline.json',copy.deepcopy(value)))
        self.assertEqual(self.store.read('baseline.json'),value)

    def test_different_artifact_is_not_overwritten(self):
        self.store.immutable('baseline.json',{'one':1})
        with self.assertRaisesRegex(m.Refused,'immutable_artifact_changed'):self.store.immutable('baseline.json',{'one':2})
        self.assertEqual(self.store.read('baseline.json'),{'one':1})

    def test_named_operation_receipts_are_bounded(self):
        name='operation-'+'c'*32+'.json';self.store.immutable(name,{'result':'done'})
        self.assertEqual(self.store.read(name),{'result':'done'})
        for name in ('../baseline.json','/etc/shadow','anything.json','operation-'+'c'*31+'.json'):
            with self.assertRaisesRegex(m.Refused,'artifact_name'):self.store.immutable(name,{'result':'done'})

    def test_raw_create_cannot_bypass_artifact_allowlist(self):
        with self.assertRaisesRegex(m.Refused,'artifact_scope'):self.store.create(self.fs.storage/'anything',b'x')
        with self.assertRaisesRegex(m.Refused,'artifact_scope'):self.store.create(self.store.base/'anything',b'x')

    def test_claim_requires_host_lock(self):
        with self.assertRaisesRegex(m.Refused,'host_lock_required'):self.store.claim()
        with self.store.locked():self.store.claim();self.store.require_active()

    def test_same_release_claim_is_idempotent_and_explicit_release(self):
        with self.store.locked():
            self.store.claim();self.store.claim();self.assertEqual(self.store.active(),self.store.token)
            self.store.relinquish();self.assertIsNone(self.store.active(absent=True))

    def test_other_release_cannot_adopt_existing_pointer(self):
        with self.store.locked():self.store.claim()
        other=m.Store(self.fs,'c'*64)
        with other.locked():
            with self.assertRaisesRegex(m.Refused,'another_release_active'):other.claim()
            with self.assertRaisesRegex(m.Refused,'active_release_required'):other.relinquish()

    def test_second_host_lock_is_refused_without_deleting_owner(self):
        other=m.Store(self.fs,'c'*64)
        with self.store.locked():
            self.store.claim()
            with self.assertRaisesRegex(m.Refused,'host_operation_busy'):
                with other.locked():self.fail('entered busy lock')
        with self.store.locked():self.store.require_active()

    def test_nested_lock_and_exception_release(self):
        with self.assertRaisesRegex(RuntimeError,'simulated'):
            with self.store.locked():raise RuntimeError('simulated')
        with self.store.locked():
            with self.assertRaisesRegex(m.Refused,'nested_host_lock'):
                with self.store.locked():pass

    def test_pointer_link_fifo_and_metadata_are_refused(self):
        path=self.store.base/'active.json'
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError,'unsafe_file'):self.store.active()
        path.unlink();path.symlink_to('missing')
        with self.assertRaises(OSError):self.store.active()
        path.unlink()
        with self.store.locked():self.store.claim()
        path.chmod(0o644)
        with self.assertRaisesRegex(m.Refused,'artifact_metadata'):self.store.active()

    def test_artifact_size_and_private_base_are_checked(self):
        with self.assertRaisesRegex(m.Refused,'artifact_bound'):self.store.immutable('baseline.json',{'large':'x'*m.MAX_ARTIFACT})
        self.store.base.chmod(0o755)
        with self.assertRaisesRegex(m.Refused,'global_storage_private'):m.Store(self.fs,'b'*64)

    def test_lock_failure_closes_parent_descriptor(self):
        (self.store.base/'.host.lock').symlink_to('missing')
        for _ in range(3):
            with self.assertRaises(OSError):
                with self.store.locked():pass
        self.assertFalse(self.store.held)

    def pointer(self):
        return {**self.store.token,'bundle_sha256':'d'*64,'receipt_sha256':'e'*64,'runtime_sha256':'f'*64}

    def test_current_pointer_requires_claim_and_exact_release(self):
        value=self.pointer()
        with self.assertRaisesRegex(m.Refused,'active_release_required'):self.store.publish_current(value,None)
        with self.store.locked():
            self.store.claim();self.assertTrue(self.store.publish_current(value,None));self.assertFalse(self.store.publish_current(value,None))
            wrong={**value,'release_id':'f'*32}
            with self.assertRaisesRegex(m.Refused,'current_pointer_release'):self.store.publish_current(wrong,None)

    def test_current_pointer_compare_and_swap_cannot_replace_a_different_generation(self):
        value=self.pointer();path=self.store.base/'current.json';old={**value,'release_id':'f'*32}
        path.write_bytes(m.c.canonical(old));path.chmod(0o600);previous=self.store.current()[1]
        with self.store.locked():
            self.store.claim()
            with self.assertRaisesRegex(m.Refused,'current_pointer_changed'):self.store.publish_current(value,None)
            self.assertEqual(self.store.current()[0],old);self.store.publish_current(value,previous)
        self.assertEqual(self.store.current()[0],value)

    def test_current_pointer_fifo_symlink_and_metadata_are_refused(self):
        path=self.store.base/'current.json';os.mkfifo(path)
        with self.assertRaisesRegex(ValueError,'unsafe_file'):self.store.current()
        path.unlink();path.symlink_to('missing')
        with self.assertRaises(OSError):self.store.current()
        path.unlink();path.write_bytes(m.c.canonical(self.pointer()));path.chmod(0o644)
        with self.assertRaisesRegex(m.Refused,'artifact_metadata'):self.store.current()

    def test_current_pointer_publication_lost_ack_is_idempotent(self):
        real=m.atomic.create
        def lost(*args):real(*args);raise OSError('lost publication acknowledgement')
        with self.store.locked():
            self.store.claim()
            with patch.object(m.atomic,'create',side_effect=lost):
                with self.assertRaises(OSError):self.store.publish_current(self.pointer(),None)
            self.assertFalse(self.store.publish_current(self.pointer(),None))
        self.assertEqual((self.store.base/'current.json').stat().st_nlink,1)

    def test_foreign_pointer_write_during_swap_is_not_overwritten(self):
        value=self.pointer();path=self.store.base/'current.json';old={**value,'release_id':'e'*32}
        path.write_bytes(m.c.canonical(old));path.chmod(0o600);previous=self.store.current()[1]
        real=self.store.current;calls=[]
        def changed():
            calls.append(True)
            if len(calls)==2:path.write_bytes(m.c.canonical({**old,'receipt_sha256':'a'*64}))
            return real()
        with self.store.locked():
            self.store.claim()
            with patch.object(self.store,'current',side_effect=changed):
                with self.assertRaisesRegex(m.Refused,'current_pointer_changed'):self.store.publish_current(value,previous)
        self.assertEqual(real()[0]['receipt_sha256'],'a'*64)


if __name__=='__main__':unittest.main()
