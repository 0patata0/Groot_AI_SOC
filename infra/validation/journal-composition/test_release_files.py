"""Full fixed source footprint, interrupted apply and reader-preserving recovery."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('release_files_tested',Path(__file__).with_name('release_files.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


class SourceTransaction(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='release-files-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def prepare(self,host='b'):
        release='a'*32;rows=[];self.before={};self.after={}
        for target in sorted(m.TARGETS[host]):
            before=None if target in m.contract.OPTIONAL else ('before '+target+'\n').encode()
            after=('candidate '+target+'\n').encode();mode=0o550 if target==m.READER else 0o750 if target==m.MCP_LAUNCHER else 0o644
            row={'target':target,'before_sha256':m.sha(before)if before else None,'after_sha256':m.sha(after),'uid':0,'gid':0,'mode':mode};rows.append(row)
            p=self.root/target.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True)
            if before:p.write_bytes(before);p.chmod(mode)
            self.before[target]=before;self.after[target]=after
        storage=self.root/m.contract.BASE.relative_to('/')/release/host
        for name in ('candidates','backups'):(storage/name).mkdir(parents=True);(storage/name).chmod(0o700)
        storage.chmod(0o700);fs=m.FileSet(host,release,rows,os.getgid(),filesystem_root=self.root)
        for raw in self.after.values():fs.put('candidates',raw)
        self.rows=rows;self.fs=fs;return fs

    def bytes(self):
        return {r['target']:(self.root/r['target'].lstrip('/')).read_bytes()if (self.root/r['target'].lstrip('/')).exists()else None for r in self.rows}

    def barriers_with_baseline_core(self):
        return dict(self.before,**{p:self.after[p]for p in m.BARRIERS[self.fs.host]})

    def test_all_host_footprints_apply_and_exact_restore(self):
        for host in 'abc':
            with self.subTest(host=host):
                fs=self.prepare(host);self.assertEqual(self.bytes(),self.before)
                self.assertEqual(fs.install_barriers(),len(m.BARRIERS[host]));self.assertEqual(self.bytes(),self.barriers_with_baseline_core())
                self.assertEqual(fs.apply(),len(self.rows)-len(m.BARRIERS[host]));self.assertEqual(self.bytes(),self.after)
                fs.restore_core();self.assertEqual(self.bytes(),self.barriers_with_baseline_core())
                self.assertEqual(fs.restore_barriers(),len(m.BARRIERS[host]));self.assertEqual(self.bytes(),self.before)
                # Separate host fixture, with no earlier release directories.
                import shutil
                for p in list(self.root.iterdir()):shutil.rmtree(p)

    def test_reader_backup_is_original_even_after_install(self):
        fs=self.prepare();fs.install_barriers();row=next(r for r in self.rows if r['target']==m.READER)
        self.assertEqual(fs.read_stored('backups',row['before_sha256']),self.before[m.READER])

    def test_final_reader_persists_after_candidate_cleanup_and_repeat_does_not_write(self):
        fs=self.prepare();fs.install_barriers();fs.apply();normal=b'fixed normal reader\n';digest=m.sha(normal)
        fs.finish_barriers(normal,digest)
        self.assertEqual(self.bytes()[m.READER],normal)
        self.assertEqual(self.bytes()[m.MCP_LAUNCHER],self.before[m.MCP_LAUNCHER])
        with patch.object(fs,'replace',side_effect=AssertionError('duplicate finalization write')):
            self.assertEqual(fs.finish_barriers(normal,digest),0)

    def test_changed_final_reader_payload_or_foreign_live_reader_prevents_all_cleanup_writes(self):
        fs=self.prepare();fs.install_barriers();fs.apply();normal=b'fixed normal reader\n';before=self.bytes()
        with self.assertRaisesRegex(ValueError,'normal_reader_payload_changed'):fs.finish_barriers(normal,'a'*64)
        self.assertEqual(self.bytes(),before)
        path=fs.root/m.READER.lstrip('/');path.chmod(0o750);path.write_bytes(b'foreign');path.chmod(0o550)
        before=self.bytes()
        with patch.object(fs,'replace',side_effect=AssertionError('preflight before all writes')):
            with self.assertRaisesRegex(ValueError,'target_bytes_changed'):fs.finish_barriers(normal,m.sha(normal))
        self.assertEqual(self.bytes(),before)

    def test_core_apply_requires_reader_barrier_first(self):
        fs=self.prepare();before=self.bytes()
        with self.assertRaisesRegex(m.Refused,'partial_apply_requires_restore'):fs.apply()
        self.assertEqual(self.bytes(),before)

    def test_second_apply_and_reader_install_do_not_reissue_writes(self):
        fs=self.prepare();fs.install_barriers();self.assertEqual(fs.install_barriers(),0);fs.apply()
        with patch.object(fs,'replace',side_effect=AssertionError('duplicate write')):self.assertEqual(fs.apply(),0)

    def test_repeated_restore_and_cleanup_are_noops(self):
        fs=self.prepare();fs.install_barriers();fs.apply();fs.restore_core();self.assertEqual(fs.restore_core(),0)
        fs.restore_barriers();self.assertEqual(fs.restore_barriers(),0)

    def test_interrupted_apply_restores_core_but_keeps_reader(self):
        fs=self.prepare();fs.install_barriers();real=fs.replace;seen=[]
        def interrupted(row,data,expected):
            if len(seen)==2:raise OSError('simulated process loss')
            real(row,data,expected);seen.append(row['target'])
        with patch.object(fs,'replace',side_effect=interrupted):
            with self.assertRaises(OSError):fs.apply()
        self.assertNotEqual(self.bytes(),self.after)
        with self.assertRaisesRegex(m.Refused,'partial_apply_requires_restore'):fs.apply()
        fs.restore_core();self.assertEqual(self.bytes(),self.barriers_with_baseline_core())

    def test_unknown_source_prevents_any_restore_write(self):
        fs=self.prepare();fs.install_barriers();fs.apply();p=self.root/self.rows[0]['target'].lstrip('/');p.write_bytes(b'unreviewed')
        before=self.bytes()
        with patch.object(fs,'replace',side_effect=AssertionError('must preflight all files')):
            with self.assertRaisesRegex(m.Refused,'target_bytes_changed'):fs.restore_core()
        self.assertEqual(self.bytes(),before)

    def test_damaged_backup_refused_before_restore(self):
        fs=self.prepare();fs.install_barriers();fs.apply();row=next(r for r in self.rows if r['before_sha256'])
        (fs.storage/'backups'/(row['before_sha256']+'.data')).write_bytes(b'damaged');before=self.bytes()
        with self.assertRaisesRegex(m.Refused,'stored_bytes_changed'):fs.restore_core()
        self.assertEqual(self.bytes(),before)

    def test_damaged_candidate_refused_before_reader_install(self):
        fs=self.prepare();row=self.rows[0];(fs.storage/'candidates'/(row['after_sha256']+'.data')).write_bytes(b'damaged')
        with self.assertRaisesRegex(m.Refused,'stored_bytes_changed'):fs.install_barriers()
        self.assertEqual(self.bytes(),self.before)

    def test_original_backups_cannot_be_recaptured_after_install(self):
        fs=self.prepare();fs.install_barriers()
        with self.assertRaisesRegex(m.Refused,'target_bytes_changed'):fs.backup()

    def test_new_file_collision_does_not_overwrite_foreign_file(self):
        fs=self.prepare();fs.install_barriers();row=next(r for r in self.rows if r['before_sha256']is None);p=self.root/row['target'].lstrip('/');real=m.atomic.create
        def collision(parent,src,dst):
            if str(src).startswith('.release-')and dst==p.name:p.write_bytes(b'foreign creator')
            return real(parent,src,dst)
        with patch.object(m.atomic,'create',side_effect=collision):
            with self.assertRaises(FileExistsError):fs.replace(row,self.after[row['target']],None)
        self.assertEqual(p.read_bytes(),b'foreign creator');self.assertFalse(list(p.parent.glob('.release-*')))

    def test_source_link_fifo_and_metadata_are_refused(self):
        fs=self.prepare();row=self.rows[0];p=self.root/row['target'].lstrip('/');raw=p.read_bytes()
        p.unlink();os.mkfifo(p)
        with self.assertRaisesRegex(m.Refused,'unsafe_file'):fs.install_barriers()
        p.unlink();p.write_bytes(raw);os.link(p,p.with_name('alias'))
        with self.assertRaisesRegex(m.Refused,'unsafe_file'):fs.install_barriers()
        p.with_name('alias').unlink();p.chmod(0o600)
        with self.assertRaisesRegex(m.Refused,'target_metadata_changed'):fs.install_barriers()

    def test_candidate_symlink_never_followed(self):
        fs=self.prepare();p=fs.storage/'candidates'/(self.rows[0]['after_sha256']+'.data');p.rename(p.with_name('victim'));p.symlink_to('victim')
        with self.assertRaises(OSError):fs.install_barriers()
        self.assertEqual(self.bytes(),self.before)

    def test_staging_directory_must_remain_private(self):
        fs=self.prepare();(fs.storage/'backups').chmod(0o770)
        with self.assertRaisesRegex(m.Refused,'writable_parent'):fs.install_barriers()

    def test_unapproved_payload_or_target_cannot_be_replaced(self):
        fs=self.prepare();row=self.rows[0]
        with self.assertRaisesRegex(m.Refused,'replacement_not_in_plan'):fs.replace(row,b'unapproved',row['before_sha256'])
        with self.assertRaisesRegex(m.Refused,'file_target'):fs.replace(dict(row,target='/etc/shadow'),b'unapproved',row['before_sha256'])
        self.assertEqual(self.bytes(),self.before)

    def test_staging_can_only_accept_hashes_in_plan(self):
        fs=self.prepare()
        for kind in ('candidates','backups'):
            with self.assertRaisesRegex(m.Refused,'stored_digest_not_in_plan'):fs.put(kind,b'unapproved')
        with self.assertRaisesRegex(m.Refused,'stored_scope'):fs.put('../candidates',b'unapproved')

    def test_payload_sum_is_bounded_before_writes(self):
        fs=self.prepare()
        with patch.object(m,'MAX_TOTAL',4):
            with self.assertRaisesRegex(m.Refused,'payload_total_bound'):fs.install_barriers()
        self.assertEqual(self.bytes(),self.before)

    def test_constructor_rejects_scope_and_metadata_changes(self):
        fs=self.prepare()
        for update in ({'target':'/etc/shadow'},{'mode':0o777},{'uid':True},{'before_sha256':None},{'after_sha256':'bad'}):
            rows=copy.deepcopy(self.rows);next(r for r in rows if r['target']==m.READER).update(update)
            with self.subTest(update=update):
                with self.assertRaises(m.Refused):m.FileSet('b','a'*32,rows,os.getgid(),filesystem_root=self.root)

    def test_shell_launcher_and_unrelated_databases_never_change(self):
        fs=self.prepare();paths=[self.root/'opt/capstone-diagnostics/read-snapshot',self.root/'state.db',self.root/'approval.sqlite',self.root/'events.journal']
        for p in paths:p.write_bytes(b'keep exactly')
        fs.install_barriers();fs.apply();fs.restore_core();fs.restore_barriers()
        for p in paths:self.assertEqual(p.read_bytes(),b'keep exactly')

    def test_new_module_and_unit_absence_restored(self):
        fs=self.prepare();fs.install_barriers();fs.apply()
        self.assertTrue(all((self.root/p.lstrip('/')).exists()for p in m.contract.OPTIONAL));fs.restore_core()
        self.assertTrue(all(not(self.root/p.lstrip('/')).exists()for p in m.contract.OPTIONAL))

    def test_recovery_completes_known_partial_barriers_only(self):
        fs=self.prepare();fs.backup();row=next(r for r in fs.rows if r['target']in m.BARRIERS['b'])
        fs.replace(row,self.after[row['target']],row['before_sha256']);self.assertEqual(fs.complete_barriers(),1)
        self.assertEqual(self.bytes(),self.barriers_with_baseline_core());self.assertEqual(fs.complete_barriers(),0)

    def test_barrier_recovery_cannot_adopt_partial_core_apply(self):
        fs=self.prepare();fs.install_barriers();fs.apply()
        with self.assertRaisesRegex(m.Refused,'barrier_recovery_requires_baseline_core'):fs.complete_barriers()

    def test_barrier_recovery_requires_all_original_backups(self):
        fs=self.prepare();fs.backup();row=next(r for r in fs.rows if r['before_sha256'])
        (fs.storage/'backups'/(row['before_sha256']+'.data')).unlink();before=self.bytes()
        with self.assertRaises(ValueError):fs.complete_barriers()
        self.assertEqual(self.bytes(),before)


if __name__=='__main__':unittest.main()
