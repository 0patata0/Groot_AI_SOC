"""Isolated file/SQLite behavior only; no operating paths or service commands."""
import copy
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import file_transaction as tx


class FileTransaction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='status-transaction-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'root'; self.root.mkdir()
        self.store = self.base / 'storage'; self.store.mkdir()
        (self.store / 'candidates').mkdir(); (self.store / 'backups').mkdir()
        self.rows = []; self.before = {}; self.after = {}
        for i, target in enumerate(sorted(tx.TARGETS)):
            old = ('previous source ' + str(i) + '\n').encode()
            new = ('reviewed source ' + str(i) + '\n').encode()
            p = self.root / target.lstrip('/'); p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(old); p.chmod(0o600)
            row = {'target': target, 'before_sha256': tx.sha(old), 'after_sha256': tx.sha(new),
                'uid': os.getuid(), 'gid': os.getgid(), 'mode': 0o600}
            self.rows.append(row); self.before[target] = old; self.after[target] = new
            (self.store / 'candidates' / (row['after_sha256'] + '.data')).write_bytes(new)
        self.transaction = self.make()

    def make(self, rows=None):
        return tx.FileSet(self.rows if rows is None else rows, self.store, filesystem_root=self.root)

    def contents(self):
        return {row['target']: (self.root / row['target'].lstrip('/')).read_bytes() for row in self.rows}

    def test_exact_apply_and_restore_preserve_metadata(self):
        self.transaction.apply(); self.assertEqual(self.contents(), self.after)
        self.assertEqual(self.transaction.restore(), 19)
        self.assertEqual(self.contents(), self.before)
        for row in self.rows:
            self.assertEqual(tx.metadata((self.root / row['target'].lstrip('/')).stat()),
                (row['uid'], row['gid'], row['mode']))

    def test_unused_restore_needs_no_backup_and_is_idempotent(self):
        self.assertEqual(self.transaction.restore(), 0)
        self.transaction.apply(); self.transaction.restore()
        self.assertEqual(self.transaction.restore(), 0)

    def test_reapplying_used_candidate_is_refused(self):
        self.transaction.apply()
        with self.assertRaisesRegex(tx.Refused, 'target_bytes_changed'): self.transaction.apply()
        self.assertEqual(self.contents(), self.after)

    def test_partial_apply_is_recovered_without_a_completion_marker(self):
        original = self.transaction.replace; count = []
        def interrupted(*args):
            if len(count) == 7: raise RuntimeError('simulated interrupted process')
            original(*args); count.append(1)
        with patch.object(self.transaction, 'replace', side_effect=interrupted):
            with self.assertRaises(RuntimeError): self.transaction.apply()
        self.assertEqual(self.transaction.restore(), 7)
        self.assertEqual(self.contents(), self.before)

    def test_unknown_current_bytes_prevent_every_apply_write(self):
        path = self.transaction.target(self.rows[-1]); path.write_bytes(b'other authorized update')
        before = self.contents()
        with self.assertRaisesRegex(tx.Refused, 'target_bytes_changed'): self.transaction.apply()
        self.assertEqual(self.contents(), before)
        self.assertEqual(list((self.store / 'backups').iterdir()), [])

    def test_rollback_never_overwrites_another_update(self):
        self.transaction.apply()
        self.transaction.target(self.rows[-1]).write_bytes(b'another update')
        before = self.contents()
        with self.assertRaisesRegex(tx.Refused, 'target_bytes_changed'): self.transaction.restore()
        self.assertEqual(self.contents(), before)

    def test_corrupt_candidate_is_detected_before_any_backup_or_write(self):
        (self.store / 'candidates' / (self.rows[-1]['after_sha256'] + '.data')).write_bytes(b'bad')
        with self.assertRaisesRegex(tx.Refused, 'stored_bytes_changed'): self.transaction.apply()
        self.assertEqual(self.contents(), self.before)
        self.assertEqual(list((self.store / 'backups').iterdir()), [])

    def test_corrupt_backup_is_detected_before_any_restore_write(self):
        self.transaction.apply()
        (self.store / 'backups' / (self.rows[-1]['before_sha256'] + '.data')).write_bytes(b'bad')
        with self.assertRaisesRegex(tx.Refused, 'stored_bytes_changed'): self.transaction.restore()
        self.assertEqual(self.contents(), self.after)

    def test_backup_is_not_silently_replaced(self):
        (self.store / 'backups' / (self.rows[0]['before_sha256'] + '.data')).write_bytes(b'bad')
        with self.assertRaisesRegex(tx.Refused, 'stored_bytes_changed'): self.transaction.backup()
        self.assertEqual(self.contents(), self.before)

    def test_plan_requires_every_exact_target_once(self):
        for rows in (self.rows[:-1], self.rows + self.rows[:1], [self.rows[0]] * 19):
            with self.assertRaises(tx.Refused): self.make(rows)
        rows = copy.deepcopy(self.rows); rows[-1]['target'] = '/etc/shadow'
        with self.assertRaisesRegex(tx.Refused, 'target_scope'): self.make(rows)

    def test_plan_rejects_traversal_and_extra_execution_fields(self):
        for updates in ({'target': '/opt/../etc/shadow'}, {'command': 'anything'},
                        {'before_sha256': '../other'}, {'mode': 0o777}, {'mode': True}, {'uid': True}):
            rows = copy.deepcopy(self.rows); rows[0].update(updates)
            with self.subTest(updates=updates), self.assertRaises(tx.Refused): self.make(rows)

    def test_external_plan_mutation_does_not_change_frozen_rows(self):
        original = self.rows[0]['target']; self.rows[0]['target'] = '/etc/shadow'
        self.assertEqual(self.transaction.rows[0]['target'], original)

    def test_symlink_target_is_rejected(self):
        path = self.transaction.target(self.rows[0]); other = self.base / 'other'
        other.write_bytes(path.read_bytes()); path.unlink(); path.symlink_to(other)
        with self.assertRaises(OSError): self.transaction.apply()
        self.assertEqual(other.read_bytes(), self.before[self.rows[0]['target']])

    def test_symlink_ancestor_is_rejected(self):
        old = self.root / 'etc'; moved = self.base / 'moved'; old.rename(moved); old.symlink_to(moved)
        with self.assertRaises(OSError): self.transaction.apply()

    def test_hardlink_target_is_rejected(self):
        path = self.transaction.target(self.rows[0]); os.link(path, self.base / 'link')
        with self.assertRaisesRegex(tx.Refused, 'unsafe_file'): self.transaction.apply()

    def test_candidate_and_backup_symlinks_are_rejected(self):
        path = self.store / 'candidates' / (self.rows[0]['after_sha256'] + '.data')
        other = self.base / 'other'; other.write_bytes(path.read_bytes()); path.unlink(); path.symlink_to(other)
        with self.assertRaises(OSError): self.transaction.apply()
        path.unlink(); path.write_bytes(self.after[self.rows[0]['target']]); self.transaction.apply()
        saved = self.store / 'backups' / (self.rows[0]['before_sha256'] + '.data')
        other.write_bytes(saved.read_bytes()); saved.unlink(); saved.symlink_to(other)
        with self.assertRaises(OSError): self.transaction.restore()

    def test_metadata_change_is_rejected(self):
        self.transaction.target(self.rows[0]).chmod(0o644)
        with self.assertRaisesRegex(tx.Refused, 'target_metadata_changed'): self.transaction.apply()

    def test_failed_atomic_rename_leaves_original_and_no_temp(self):
        with patch.object(tx.os, 'replace', side_effect=OSError('simulated replace error')):
            with self.assertRaises(OSError): self.transaction.apply()
        self.assertEqual(self.contents(), self.before)
        self.assertFalse(list(self.root.rglob('.capstone-status-*')))

    def test_late_inode_change_is_refused_and_temp_is_removed(self):
        row = self.rows[0]; path = self.transaction.target(row)
        real_chown = tx.os.fchown
        def swap(*args):
            real_chown(*args)
            other = path.with_suffix('.other'); other.write_bytes(b'another write'); other.chmod(row['mode']); other.replace(path)
        with patch.object(tx.os, 'fchown', side_effect=swap):
            with self.assertRaisesRegex(tx.Refused, 'target_changed_before_replace'):
                self.transaction.replace(row, self.after[row['target']], row['before_sha256'])
        self.assertEqual(path.read_bytes(), b'another write')
        self.assertFalse(list(self.root.rglob('.capstone-status-*')))

    def test_database_records_outside_targets_survive_apply_and_rollback(self):
        path = self.root / 'var/lib/cases.sqlite'; path.parent.mkdir(parents=True)
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE cases(id INTEGER PRIMARY KEY, detail TEXT)')
            db.execute('INSERT INTO cases VALUES(1,"prior")')
        self.transaction.apply()
        with sqlite3.connect(path) as db: db.execute('INSERT INTO cases VALUES(2,"new case after application")')
        self.transaction.restore()
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT * FROM cases ORDER BY id').fetchall(),
                [(1, 'prior'), (2, 'new case after application')])

    def test_write_lease_defers_another_writer_without_changing_records(self):
        path = self.base / 'queue.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('PRAGMA journal_mode=WAL'); db.execute('CREATE TABLE jobs(id PRIMARY KEY,status)')
            db.execute('INSERT INTO jobs VALUES(1,"done")')
        first = sqlite3.connect(path, isolation_level=None, timeout=0)
        second = sqlite3.connect(path, isolation_level=None, timeout=0)
        try:
            first.execute('BEGIN IMMEDIATE')
            self.assertEqual(first.execute('SELECT count(*) FROM jobs WHERE status="running"').fetchone()[0], 0)
            with self.assertRaises(sqlite3.OperationalError): second.execute('INSERT INTO jobs VALUES(2,"running")')
            self.assertEqual(first.total_changes, 0); first.rollback()
            second.execute('INSERT INTO jobs VALUES(2,"running")')
            self.assertEqual(second.execute('SELECT count(*) FROM jobs').fetchone()[0], 2)
        finally:
            first.close(); second.close()


if __name__ == '__main__':
    unittest.main()
