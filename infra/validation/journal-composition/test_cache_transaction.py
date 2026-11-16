"""Isolated operator-cache recovery tests; no operating path/service access."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('journal_cache_transaction', Path(__file__).with_name('cache_transaction.py'))
mod = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(mod)


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='journal-cache-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / mod.CACHE.relative_to('/')
        self.path.parent.mkdir(parents=True)
        self.storage = self.root / 'release/cache'; self.storage.mkdir(parents=True)
        self.storage.chmod(0o700)
        self.make_database()
        self.cache = mod.Cache('b', os.getgid(), self.storage, filesystem_root=self.root)

    def make_database(self):
        db = sqlite3.connect(self.path)
        db.executescript('''CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE events(id TEXT PRIMARY KEY,at_us INTEGER NOT NULL,unit TEXT NOT NULL,error TEXT NOT NULL);
            CREATE INDEX event_window ON events(unit,at_us,id);
            CREATE TABLE windows(since_us INTEGER NOT NULL,until_us INTEGER NOT NULL,truncated INTEGER NOT NULL,
                PRIMARY KEY(since_us,until_us));''')
        db.executemany('INSERT INTO metadata VALUES(?,?)', [('schema','1'),('host','b'),
            ('observed_at_us','2000000'),('retained_since_us','1000000')])
        db.execute('INSERT INTO events VALUES(?,?,?,?)', ('old',1500000,'example.service','{"kind":"journal_error"}'))
        db.execute('INSERT INTO windows VALUES(?,?,?)',(1000000,2000000,0))
        db.commit(); db.close(); self.path.chmod(0o640)

    def mutate(self, sql, values=()):
        db = sqlite3.connect(self.path)
        try:
            db.execute(sql, values); db.commit()
        finally:
            db.close()

    def candidate_publish(self):
        self.mutate('INSERT INTO metadata VALUES(?,?)', ('source_filter_policy',mod.POLICY))
        self.mutate('INSERT INTO events VALUES(?,?,?,?)',('new',2500000,'example.service','{"kind":"application_error"}'))
        self.mutate('DELETE FROM windows')
        self.mutate('INSERT INTO windows VALUES(?,?,?)',(2000000,3000000,0))

    def test_exact_backup_and_logical_fingerprint(self):
        original = self.path.read_bytes(); proof = self.cache.prepare()
        self.assertEqual(original,(self.storage/'before.sqlite3').read_bytes())
        self.assertEqual(proof['counts'],{'metadata':4,'events':1,'windows':1})
        self.assertEqual(proof['sha256'],mod.sha(original))

    def test_restore_preserves_new_policy_observations_first(self):
        baseline=self.path.read_bytes();before=self.cache.prepare();self.candidate_publish()
        candidate=self.path.read_bytes();result=self.cache.restore()
        self.assertTrue(result['changed'] and result['post_preserved'])
        self.assertEqual(self.path.read_bytes(),baseline)
        self.assertEqual((self.storage/'after.sqlite3').read_bytes(),candidate)
        _,after=self.cache.saved('after');self.assertEqual(after['counts']['events'],2)
        self.assertEqual(after['metadata']['source_filter_policy'],mod.POLICY)
        self.assertEqual(result['baseline_sha256'],before['sha256'])
        self.assertEqual(os.stat(self.path).st_mode&0o777,0o640)

    def test_repeated_restore_does_not_overwrite_post_backup(self):
        self.cache.prepare();self.candidate_publish();self.cache.restore()
        after=(self.storage/'after.sqlite3').read_bytes()
        proof=self.cache.restore();self.assertFalse(proof['changed'])
        self.assertTrue(proof['post_preserved'])
        self.assertEqual(proof['post_sha256'],mod.sha(after))
        self.assertEqual(after,(self.storage/'after.sqlite3').read_bytes())

    def test_repeated_restore_refuses_damaged_post_receipt(self):
        self.cache.prepare();self.candidate_publish();self.cache.restore()
        (self.storage/'after.json').write_bytes(b'{}')
        with self.assertRaisesRegex(mod.Refused,'cache_backup_receipt_mismatch'):self.cache.restore()

    def test_repeated_restore_refuses_incomplete_post_backup(self):
        self.cache.prepare();self.candidate_publish();self.cache.restore()
        (self.storage/'after.json').unlink()
        with self.assertRaisesRegex(mod.Refused,'cache_post_backup_incomplete'):self.cache.restore()

    def test_already_baseline_restore_is_noop(self):
        self.cache.prepare();self.assertFalse(self.cache.restore()['changed'])
        self.assertFalse((self.storage/'after.sqlite3').exists())

    def test_prepare_repeat_is_idempotent(self):
        self.assertEqual(self.cache.prepare(),self.cache.prepare())

    def test_fresh_prepare_cannot_capture_new_policy_as_legacy(self):
        self.candidate_publish()
        with self.assertRaisesRegex(mod.Refused,'legacy_baseline_required'):self.cache.prepare()

    def test_old_backup_cannot_be_replaced_by_new_source_data(self):
        self.cache.prepare();before=(self.storage/'before.sqlite3').read_bytes()
        self.mutate('UPDATE metadata SET value=? WHERE key=?',('3000000','observed_at_us'))
        with self.assertRaisesRegex(mod.Refused,'immutable_backup_changed'):self.cache.prepare()
        self.assertEqual(before,(self.storage/'before.sqlite3').read_bytes())

    def test_backup_corruption_is_refused_before_live_mutation(self):
        self.cache.prepare();self.candidate_publish();original=self.path.read_bytes()
        receipt=self.storage/'before.json';receipt.write_bytes(b'{}')
        with self.assertRaisesRegex(mod.Refused,'cache_backup_receipt_mismatch'):self.cache.restore()
        self.assertEqual(original,self.path.read_bytes())

    def test_existing_different_post_image_is_preserved_and_refused(self):
        self.cache.prepare();self.candidate_publish();self.cache.restore()
        old_after=(self.storage/'after.sqlite3').read_bytes()
        self.candidate_publish();self.mutate('INSERT INTO events VALUES(?,?,?,?)',('extra',3500000,'example.service','{}'))
        current=self.path.read_bytes()
        with self.assertRaisesRegex(mod.Refused,'immutable_backup_changed'):self.cache.restore()
        self.assertEqual(old_after,(self.storage/'after.sqlite3').read_bytes());self.assertEqual(current,self.path.read_bytes())

    def test_chat_incident_approval_and_raw_journal_files_are_untouched(self):
        unrelated=[self.root/'state.db',self.root/'queue.sqlite',self.root/'approval.sqlite',self.root/'raw.journal']
        for p in unrelated:p.write_bytes(b'unrelated durable records')
        self.cache.prepare();self.candidate_publish();self.cache.restore()
        for p in unrelated:self.assertEqual(p.read_bytes(),b'unrelated durable records')

    def test_unknown_host_argument(self):
        with self.assertRaisesRegex(mod.Refused,'cache_host_or_group'):
            mod.Cache('d',os.getgid(),self.storage,filesystem_root=self.root)

    def test_boolean_group_argument(self):
        with self.assertRaisesRegex(mod.Refused,'cache_host_or_group'):
            mod.Cache('b',True,self.storage,filesystem_root=self.root)

    def test_different_database_host(self):
        self.mutate('UPDATE metadata SET value=? WHERE key=?',('a','host'))
        with self.assertRaisesRegex(mod.Refused,'cache_host_or_schema'):self.cache.prepare()

    def test_different_schema_version(self):
        self.mutate('UPDATE metadata SET value=? WHERE key=?',('2','schema'))
        with self.assertRaisesRegex(mod.Refused,'cache_host_or_schema'):self.cache.prepare()

    def test_unknown_source_policy(self):
        self.mutate('INSERT INTO metadata VALUES(?,?)',('source_filter_policy','unreviewed-v2'))
        with self.assertRaisesRegex(mod.Refused,'cache_filter_policy'):self.cache.prepare()

    def test_extra_table_is_refused(self):
        self.mutate('CREATE TABLE unexpected(id TEXT)')
        with self.assertRaisesRegex(mod.Refused,'cache_schema_objects'):self.cache.prepare()

    def test_extra_trigger_is_refused(self):
        self.mutate('CREATE TRIGGER unexpected AFTER INSERT ON events BEGIN SELECT 1; END')
        with self.assertRaisesRegex(mod.Refused,'cache_schema_objects'):self.cache.prepare()

    def test_changed_column_shape_is_refused(self):
        self.mutate('ALTER TABLE events ADD COLUMN unknown TEXT')
        with self.assertRaisesRegex(mod.Refused,'cache_schema_columns'):self.cache.prepare()

    def test_invalid_sqlite_file(self):
        self.path.write_bytes(b'invalid database')
        with self.assertRaisesRegex(mod.Refused,'not_sqlite_cache'):self.cache.prepare()

    def test_symbolic_database_link(self):
        other=self.path.with_name('elsewhere');self.path.rename(other);self.path.symlink_to(other)
        with self.assertRaises((OSError,mod.Refused)):self.cache.prepare()

    def test_hard_linked_database(self):
        os.link(self.path,self.path.with_name('alias'))
        with self.assertRaisesRegex(mod.Refused,'unsafe_cache_file'):self.cache.prepare()

    def test_group_writable_parent_directory(self):
        self.path.parent.chmod(0o770)
        with self.assertRaisesRegex(mod.Refused,'untrusted_directory'):self.cache.prepare()

    def test_world_readable_database(self):
        self.path.chmod(0o644)
        with self.assertRaisesRegex(mod.Refused,'cache_file_metadata'):self.cache.prepare()

    def test_group_writable_database(self):
        self.path.chmod(0o660)
        with self.assertRaisesRegex(mod.Refused,'cache_file_metadata'):self.cache.prepare()

    def test_nonprivate_backup_directory(self):
        self.storage.chmod(0o750)
        with self.assertRaisesRegex(mod.Refused,'private_storage_required'):
            mod.Cache('b',os.getgid(),self.storage,filesystem_root=self.root)

    def test_backup_symlink_is_not_followed(self):
        victim=self.root/'victim';victim.write_bytes(b'keep')
        (self.storage/'before.sqlite3').symlink_to(victim)
        with self.assertRaises((OSError,mod.Refused)):self.cache.prepare()
        self.assertEqual(victim.read_bytes(),b'keep')

    def test_storage_symlink_is_refused(self):
        alias=self.root/'alias';alias.symlink_to(self.storage,target_is_directory=True)
        with self.assertRaises(OSError):mod.Cache('b',os.getgid(),alias,filesystem_root=self.root)

    def test_storage_outside_test_root(self):
        with self.assertRaisesRegex(mod.Refused,'storage_path'):
            mod.Cache('b',os.getgid(),Path('/'),filesystem_root=self.root)

    def test_storage_parent_escape(self):
        with self.assertRaisesRegex(mod.Refused,'unsafe_directory'):
            mod.Cache('b',os.getgid(),self.storage/'..'/'cache',filesystem_root=self.root)

    def test_wal_sidecar_refused(self):
        self.path.with_name(self.path.name+'-wal').write_bytes(b'x')
        with self.assertRaisesRegex(mod.Refused,'cache_sidecar_present'):self.cache.prepare()

    def test_shm_sidecar_refused(self):
        self.path.with_name(self.path.name+'-shm').write_bytes(b'x')
        with self.assertRaisesRegex(mod.Refused,'cache_sidecar_present'):self.cache.prepare()

    def test_rollback_journal_sidecar_refused(self):
        self.path.with_name(self.path.name+'-journal').write_bytes(b'x')
        with self.assertRaisesRegex(mod.Refused,'cache_sidecar_present'):self.cache.prepare()

    def test_empty_rollback_journal_still_refused(self):
        self.path.with_name(self.path.name+'-journal').touch()
        with self.assertRaisesRegex(mod.Refused,'cache_sidecar_present'):self.cache.prepare()

    def test_metadata_row_bound(self):
        db=sqlite3.connect(self.path)
        db.executemany('INSERT INTO metadata VALUES(?,?)',[(f'key{i}','x')for i in range(61)])
        db.commit();db.close()
        with self.assertRaisesRegex(mod.Refused,'cache_row_bound'):self.cache.prepare()

    def test_database_byte_bound(self):
        with self.path.open('r+b')as f:f.truncate(mod.MAX_BYTES+1)
        with self.assertRaisesRegex(mod.Refused,'unsafe_cache_file'):self.cache.prepare()

    def test_unknown_backup_name(self):
        with self.assertRaisesRegex(mod.Refused,'fixed_artifact_name'):self.cache.save('../outside',b'x')

    def test_unknown_snapshot_kind(self):
        with self.assertRaisesRegex(mod.Refused,'fixed_snapshot_kind'):self.cache.saved('../outside')

    def test_live_database_change_after_post_backup_refuses_replacement(self):
        self.cache.prepare();self.candidate_publish();original=self.cache.save
        def changed_after_save(name,raw):
            original(name,raw)
            if name=='after.json':self.mutate('INSERT INTO events VALUES(?,?,?,?)',('concurrent',4500000,'example.service','{}'))
        with patch.object(self.cache,'save',changed_after_save):
            with self.assertRaisesRegex(mod.Refused,'cache_changed_before_restore'):self.cache.restore()
        db=sqlite3.connect(self.path);self.assertEqual(db.execute('SELECT count(*)FROM events').fetchone()[0],3);db.close()
        self.assertFalse(list(self.path.parent.glob('.journal-release-*')))


if __name__ == '__main__':
    unittest.main(verbosity=2)
