"""Isolated source/cohort witness tests; never open operating source paths."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('release_status_tested',Path(__file__).with_name('release_status.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='source-witness-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.release='a'*32
        rows=[]
        for i,target in enumerate(sorted(m.TARGETS['b'])):
            raw=('before %s\n'%target).encode();after=('candidate %s\n'%target).encode()
            row={'target':target,'before_sha256':None if target in m.OPTIONAL else hashlib.sha256(raw).hexdigest(),
                 'after_sha256':hashlib.sha256(after).hexdigest(),'uid':0,'gid':0,'mode':0o644}
            rows.append(row);p=self.root/target.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True)
            if target not in m.OPTIONAL:p.write_bytes(raw);p.chmod(row['mode'])
        self.config={'schema':1,'host':'b','release_id':self.release,'rows':rows,'reader_uid':10001}
        self.witness=m.Witness(self.config,os.getgid(),filesystem_root=self.root)
        self.query={'schema':1,'host':'b','release_id':self.release}
        self.path=self.root/m.CACHE.relative_to('/');self.path.parent.mkdir(parents=True,exist_ok=True)
        db=sqlite3.connect(self.path);db.execute('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        db.executemany('INSERT INTO metadata VALUES(?,?)',[('schema','1'),('host','b')]);db.commit();db.close();self.path.chmod(0o640)
        self.witness.storage.mkdir(parents=True);self.witness.storage.chmod(0o700)

    def mutate(self,sql,args=()):
        db=sqlite3.connect(self.path)
        try:db.execute(sql,args);db.commit()
        finally:db.close()

    def candidate(self):
        for row in self.config['rows']:
            p=self.root/row['target'].lstrip('/');p.write_bytes(('candidate %s\n'%row['target']).encode());p.chmod(row['mode'])

    def phase(self,value):
        p=self.witness.storage/'state.json';p.write_bytes(m.canonical(value));p.chmod(0o600)

    def test_full_baseline_with_expected_absent_native_and_unit(self):
        result=self.witness.answer(self.query)
        self.assertEqual(result['generation'],'baseline');self.assertEqual(len(result['files']),34)
        self.assertTrue(result['isolated_filesystem']);self.assertIs(result['mutation_performed'],False)
        self.assertEqual(result['cache'],{'status':'observed','source_filter_policy':None})

    def test_full_candidate_and_phase(self):
        self.candidate();self.phase({'host':'b','release_id':self.release,'phase':'verified'})
        self.mutate('INSERT INTO metadata VALUES(?,?)',('source_filter_policy','application-severity-v1'))
        result=self.witness.answer(self.query)
        self.assertEqual((result['generation'],result['phase']),('candidate','verified'))
        self.assertEqual(result['cache']['source_filter_policy'],'application-severity-v1')

    def test_partial_replacement_is_mixed_not_candidate(self):
        row=self.config['rows'][0];p=self.root/row['target'].lstrip('/');p.write_bytes(('candidate %s\n'%row['target']).encode())
        self.assertEqual(self.witness.answer(self.query)['generation'],'mixed')

    def test_unknown_source_is_foreign(self):
        p=self.root/self.config['rows'][0]['target'].lstrip('/');p.write_bytes(b'unapproved source')
        self.assertEqual(self.witness.answer(self.query)['generation'],'foreign')

    def test_metadata_drift_is_foreign_even_when_hash_matches(self):
        p=self.root/self.config['rows'][0]['target'].lstrip('/');p.chmod(0o600)
        self.assertEqual(self.witness.answer(self.query)['generation'],'foreign')

    def test_unexpected_missing_required_source_is_refused(self):
        (self.root/self.config['rows'][0]['target'].lstrip('/')).unlink()
        with self.assertRaisesRegex(m.Refused,'required_file_missing'):self.witness.answer(self.query)

    def test_optional_absence_after_nonempty_before_is_not_baseline(self):
        cfg=copy.deepcopy(self.config);next(r for r in cfg['rows']if r['target'] in m.OPTIONAL)['before_sha256']='b'*64
        w=m.Witness(cfg,os.getgid(),filesystem_root=self.root)
        self.assertEqual(w.answer(self.query)['generation'],'foreign')

    def test_source_symlink_is_never_followed(self):
        p=self.root/self.config['rows'][0]['target'].lstrip('/');p.rename(p.with_name('victim'));p.symlink_to('victim')
        with self.assertRaises(OSError):self.witness.answer(self.query)

    def test_source_hardlink_refused(self):
        p=self.root/self.config['rows'][0]['target'].lstrip('/');os.link(p,p.with_name('alias'))
        with self.assertRaisesRegex(m.Refused,'unsafe_file'):self.witness.answer(self.query)

    def test_source_fifo_refused_without_open_wait(self):
        p=self.root/self.config['rows'][0]['target'].lstrip('/');p.unlink();os.mkfifo(p)
        with self.assertRaisesRegex(m.Refused,'unsafe_file'):self.witness.answer(self.query)

    def test_writable_plugin_parent_refused(self):
        (self.root/'opt/hermes-data/plugins').chmod(0o770)
        with self.assertRaisesRegex(m.Refused,'writable_parent'):self.witness.answer(self.query)

    def test_symlink_plugin_parent_refused(self):
        p=self.root/'opt/hermes-data/plugins';p.rename(p.with_name('original'));p.symlink_to('original',target_is_directory=True)
        with self.assertRaises(OSError):self.witness.answer(self.query)

    def test_mid_set_change_is_refused(self):
        read=self.witness.read;first=self.root/self.config['rows'][0]['target'].lstrip('/');calls=[]
        def racing(path,**kw):
            value=read(path,**kw);calls.append(path)
            if len(calls)==2:first.write_bytes(b'changed after first read')
            return value
        with patch.object(self.witness,'read',side_effect=racing):
            with self.assertRaisesRegex(m.Refused,'source_set_changed'):self.witness.answer(self.query)

    def test_normal_witness_does_not_modify_any_bytes_or_metadata(self):
        def tree():
            return {str(p.relative_to(self.root)):(p.read_bytes(),m.stamp(p.stat()))for p in self.root.rglob('*')if p.is_file()}
        before=tree();self.witness.answer(self.query);self.assertEqual(tree(),before)

    def test_cache_with_sidecar_is_unavailable(self):
        for suffix in ('-wal','-shm','-journal'):
            with self.subTest(suffix=suffix):
                p=self.path.with_name(self.path.name+suffix);p.touch()
                self.assertEqual(self.witness.answer(self.query)['cache']['status'],'unavailable');p.unlink()

    def test_cache_policy_unknown_is_unavailable(self):
        self.mutate('INSERT INTO metadata VALUES(?,?)',('source_filter_policy','unknown'))
        self.assertEqual(self.witness.cache()['status'],'unavailable')

    def test_cache_wrong_identity_is_unavailable(self):
        self.mutate('UPDATE metadata SET value=? WHERE key=?',('c','host'))
        self.assertEqual(self.witness.cache()['status'],'unavailable')

    def test_cache_missing_corrupt_or_broad_mode_is_unavailable(self):
        for raw in (b'not sqlite',b''):
            self.path.write_bytes(raw);self.assertEqual(self.witness.cache()['status'],'unavailable')
        self.path.unlink();self.assertEqual(self.witness.cache()['status'],'unavailable')

    def test_cache_world_readable_mode_is_unavailable(self):
        self.path.chmod(0o644);self.assertEqual(self.witness.cache()['status'],'unavailable')
        self.path.chmod(0o640);self.assertEqual(self.witness.cache()['status'],'observed')

    def test_cache_hardlink_is_unavailable(self):
        os.link(self.path,self.path.with_name('alias'));self.assertEqual(self.witness.cache()['status'],'unavailable')

    def test_source_replaced_during_read_is_refused(self):
        first=self.root/self.config['rows'][0]['target'].lstrip('/');original=m.os.stat;changed=[]
        def stat_race(path,*args,**kw):
            if path==first.name and 'dir_fd'in kw and not changed:
                replacement=first.with_name('candidate-replacement');replacement.write_bytes(b'replaced during read');os.replace(replacement,first);changed.append(True)
            return original(path,*args,**kw)
        with patch.object(m.os,'stat',side_effect=stat_race):
            with self.assertRaisesRegex(m.Refused,'file_changed'):self.witness.answer(self.query)

    def test_cache_metadata_size_bound(self):
        db=sqlite3.connect(self.path);db.executemany('INSERT INTO metadata VALUES(?,?)',[(str(i),'value')for i in range(63)]);db.commit();db.close()
        self.assertEqual(self.witness.cache()['status'],'unavailable')

    def test_cache_symlink_refused(self):
        p=self.path.with_name('other');self.path.rename(p);self.path.symlink_to(p)
        self.assertEqual(self.witness.cache()['status'],'unavailable')

    def test_wrong_or_untrusted_phase_remains_unknown(self):
        for value in ({'host':'c','release_id':self.release,'phase':'confirmed'},
                      {'host':'b','release_id':'b'*32,'phase':'confirmed'},
                      {'host':'b','release_id':self.release,'phase':'arbitrary'},{}):
            self.phase(value);self.assertEqual(self.witness.answer(self.query)['phase'],'unknown')
        self.phase({'host':'b','release_id':self.release,'phase':'confirmed'});(self.witness.storage/'state.json').chmod(0o644)
        self.assertEqual(self.witness.answer(self.query)['phase'],'unknown')

    def test_query_cannot_select_another_release_or_host(self):
        for changes in ({'host':'a'},{'release_id':'b'*32},{'schema':True},{'schema':2},{'release_id':'../x'},{'command':'restart'},{'path':'/etc/shadow'}):
            with self.subTest(changes=changes):
                q=dict(self.query,**changes)
                with self.assertRaises(m.Refused):self.witness.answer(q)

    def test_duplicate_json_and_nonfinite_refused(self):
        for raw in (b'{"schema":1,"schema":1}',b'{"schema":NaN}'):
            with self.assertRaises(m.Refused):m.parsed(raw)

    def test_config_cannot_expand_target_set(self):
        for changes in ({'target':'/etc/shadow'},{'target':'/opt/../etc/shadow'},{'target':[]},
                        {'before_sha256':None},{'after_sha256':'invalid'},{'mode':0o777},{'uid':True}):
            cfg=copy.deepcopy(self.config);cfg['rows'][0].update(changes)
            with self.subTest(changes=changes):
                with self.assertRaises(m.Refused):m.Witness(cfg,os.getgid(),filesystem_root=self.root)

    def test_config_duplicate_and_incomplete_target_set(self):
        cfg=copy.deepcopy(self.config);cfg['rows'][-1]=cfg['rows'][0]
        with self.assertRaisesRegex(m.Refused,'target_set'):m.Witness(cfg,os.getgid(),filesystem_root=self.root)
        cfg['rows'].pop()
        with self.assertRaisesRegex(m.Refused,'row_count'):m.Witness(cfg,os.getgid(),filesystem_root=self.root)

    def test_fixture_cannot_start_production_socket(self):
        with self.assertRaisesRegex(m.Refused,'production_server_required'):m.serve(self.witness)


if __name__=='__main__':unittest.main()
