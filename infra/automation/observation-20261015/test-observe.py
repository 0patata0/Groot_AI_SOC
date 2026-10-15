#!/usr/bin/env python3
"""Local synthetic parsing/SQLite fixtures; no Docker/systemd/operating paths."""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('observation', HERE/'observe.py')
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)


class Observation(unittest.TestCase):
    def access(self, **updates):
        value = {'capstone_waf_access_version':'2', 'deployment_binding':'a'*64, 'request_id':'b'*32,
                 'time_iso8601':'2026-10-15T03:20:00+00:00', 'msec':'1792034400.999',
                 'request_time':'0.003', 'source_ip':o.TARGET, 'destination_ip':'172.18.0.2',
                 'source_port':'45123', 'destination_port':'8080', 'http_method':'GET', 'http_status':'200'}
        value.update(updates)
        return json.dumps(value).encode()

    def test_access_v1_v2_same_explicit_clock_contract(self):
        for version in ('1','2'):
            row = o.access_meta(self.access(capstone_waf_access_version=version))
            self.assertEqual(row, {'epoch':1792034400.999, 'target':True, 'version':version})

    def test_access_unsupported_identity_type_or_clock_refused(self):
        for change in ({'capstone_waf_access_version':'3'}, {'capstone_waf_access_version':'2-private'},
                       {'capstone_waf_access_version':2}, {'request_id':'x'*32},
                       {'deployment_binding':'a'*63}, {'source_port':45123}, {'extra':'not allowed'},
                       {'msec':'1792034401.000'}, {'time_iso8601':'2026-10-15T03:20:00'},
                       {'msec':'nan'}):
            with self.subTest(change=tuple(change)):
                with self.assertRaises(o.Refused):
                    o.access_meta(self.access(**change))

    def test_fixed_waf_alias_only_and_canonical_parent_nofollow(self):
        with tempfile.TemporaryDirectory(prefix='capstone-observation-test-') as tmp:
            root = Path(tmp).resolve()
            (root/'etc/modsecurity.d').mkdir(parents=True)
            (root/'opt/owasp-crs/rules').mkdir(parents=True)
            alias = root/'etc/modsecurity.d/owasp-crs'
            alias.symlink_to('/opt/owasp-crs')
            target = root/'opt/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf'
            target.write_bytes(b'synthetic exception')
            real_open = os.open
            def redirected(path, flags, *args, **kwargs):
                if path == Path('/proc/123/root'):
                    path = root
                return real_open(path, flags, *args, **kwargs)
            with mock.patch.object(o.os, 'open', side_effect=redirected):
                result = o.container_sources({'pid':123}, {o.EXCEPTION:o.sha(target.read_bytes())})
                self.assertTrue(result[o.EXCEPTION]['expected_match'])
                for wrong in ('/tmp/elsewhere', '../../opt/owasp-crs'):
                    alias.unlink(); alias.symlink_to(wrong)
                    with self.assertRaises(o.Refused):
                        o.container_sources({'pid':123}, {o.EXCEPTION:'a'*64})
                alias.unlink(); alias.symlink_to('/opt/owasp-crs')
                target.unlink(); (root/'opt/owasp-crs/rules').rmdir()
                (root/'opt/owasp-crs/rules').symlink_to('/tmp')
                with self.assertRaises(OSError):
                    o.container_sources({'pid':123}, {o.EXCEPTION:'a'*64})

    def test_fixed_actual_docker_path_both_hosts(self):
        for host in ('a', 'b'):
            called = []
            def fake_command(argv):
                called.append(argv)
                self.assertEqual(argv[:3], ['/usr/local/bin/docker', 'inspect', '--format'])
                self.assertEqual(argv[-1], o.CIDS[host])
                return json.dumps({'id':o.CIDS[host], 'image':'sha256:'+'a'*64,
                                   'pid':123, 'started_at':'2026-10-15T00:00:00Z', 'running':True}).encode()
            with mock.patch.object(o, 'command', side_effect=fake_command), mock.patch.object(Path, 'read_text', return_value='123 (nginx) '+' '.join(['S']+['0']*18+['987'])):
                result = o.container(host)
            self.assertEqual(result['start_ticks'], '987')
            self.assertEqual(len(called), 1)

    def audit(self, **kw):
        stamp = 1792029600.123
        iso = dt.datetime.fromtimestamp(stamp, dt.timezone.utc).isoformat(timespec='seconds')
        tx = {'unique_id': 'v2:'+'a'*64+':'+'b'*32+':'+str(stamp)+':'+iso,
              'time_stamp': dt.datetime.fromtimestamp(stamp, dt.timezone.utc).strftime('%a %b %d %H:%M:%S %Y'),
              'client_ip': o.TARGET, 'host_ip': '172.18.0.2', 'host_port': 8080,
              'request': {'method': 'GET', 'uri': '/', 'http_version': 1.0, 'headers': {}},
              'messages': [{'details': {'ruleId': '920280'}}]}
        tx.update(kw)
        return json.dumps({'transaction': tx}).encode()

    def test_v2_offset_no_kst_assumption(self):
        row = o.audit_meta(self.audit())
        self.assertEqual(row['epoch'], 1792029600.123)
        self.assertEqual(row['shape'], '10020_audit_shape')

    def test_legacy_naive_excluded(self):
        self.assertIsNone(o.audit_meta(self.audit(unique_id='legacy'))['epoch'])

    def test_clock_conflict_refused(self):
        with self.assertRaises(o.Refused):
            o.audit_meta(self.audit(time_stamp='Thu Oct 15 00:00:00 2026'))

    def test_duplicate_host_not_exception(self):
        raw = self.audit(request={'method':'GET','uri':'/','http_version':1.1,'headers':{'Host':'192.168.16.230'}})
        raw = raw.replace(b'"Host": "192.168.16.230"', b'"Host": "192.168.16.230", "host": "192.168.16.230"')
        self.assertIsNone(o.audit_meta(raw)['shape'])

    def test_framing_or_other_uri_excluded(self):
        for request in ({'method':'GET','uri':'/','http_version':1.0,'headers':{'Content-Length':'0'}},
                        {'method':'GET','uri':'/?x','http_version':1.0,'headers':{}}):
            self.assertIsNone(o.audit_meta(self.audit(request=request))['shape'])

    def test_duplicate_structure_rejected(self):
        raw = self.audit().replace(b'"host_port": 8080', b'"host_port": 8080, "host_port": 8080')
        with self.assertRaises(o.Refused):
            o.audit_meta(raw)

    def test_guard_window_and_whitelist(self):
        cutoff = 1792029600
        raw = b'\n'.join(json.dumps({'__REALTIME_TIMESTAMP':str((cutoff-age)*1000000),'MESSAGE':message}).encode()
                         for age, message in [(10, 'korean_output_guard verdict=filtered chars=10'),
                                              (20000, 'korean_output_guard verdict=retained chars=3'),
                                              (10, 'private user words not emitted')])
        value = o.guard_counts(raw, cutoff)
        self.assertEqual(value['windows']['recent5h']['verdict_counts']['filtered'], 1)
        self.assertEqual(value['windows']['recent5h']['verdict_counts']['retained'], 0)
        self.assertEqual(value['windows']['recent24h']['verdict_counts']['retained'], 1)
        self.assertNotIn('private user', json.dumps(value))

    def test_stored_interval_not_tool_or_next_turn(self):
        rows = [('s','user',100,0),('s','assistant',102,1),('s','assistant',110,0),
                ('s','user',200,0),('s','assistant',205,0),('s','assistant',208,0),
                ('t','assistant',999,0)]
        values, ambiguous = o.stored_intervals(rows)
        self.assertEqual(values, [(110,10),(208,8)])
        self.assertEqual(ambiguous, 1)
        self.assertEqual(o.quantile([10,8], .5), 9)
        self.assertIsNone(o.quantile([], .95))

    def make_db(self, path):
        db = sqlite3.connect(path)
        db.executescript('''CREATE TABLE sessions(id TEXT,source TEXT);
        CREATE TABLE messages(id INTEGER, session_id TEXT,role TEXT,timestamp REAL,tool_calls TEXT,active INTEGER,content TEXT);
        CREATE TABLE delivery_obligations(platform TEXT,state TEXT,created_at REAL);
        INSERT INTO sessions VALUES('secret-session','mattermost');
        INSERT INTO messages VALUES(1,'secret-session','user',1000,NULL,1,'secret-user');
        INSERT INTO messages VALUES(2,'secret-session','assistant',1007,NULL,1,'secret-answer');
        INSERT INTO delivery_obligations VALUES('mattermost','delivered',1007);''')
        db.commit()
        return db

    def test_db_queries_no_content_output(self):
        db = self.make_db(':memory:')
        try:
            value = o.db_metrics(db, 1010)
            self.assertEqual(value['windows']['recent5h']['stored_interval_proxy']['recent3_seconds'], [7])
            self.assertEqual(value['windows']['recent24h']['delivery_obligation_states'], {'delivered':1})
            self.assertNotIn('secret-', json.dumps(value))
        finally:
            db.close()

    @unittest.skipUnless(os.geteuid() == 0, 'root-only private WAL snapshot fixture')
    def test_private_wal_copy_original_unchanged(self):
        with tempfile.TemporaryDirectory(prefix='capstone-observation-test-') as tmp:
            data, scratch = Path(tmp)/'data', Path(tmp)/'scratch'
            data.mkdir(mode=0o700); scratch.mkdir(mode=0o700)
            db = self.make_db(data/'state.db')
            db.execute('PRAGMA journal_mode=WAL')
            db.execute("INSERT INTO messages VALUES(3,'secret-session','user',1008,NULL,1,'wal-secret')")
            db.commit()
            def snapshot():
                return {p.name:(p.stat().st_uid,p.stat().st_gid,p.stat().st_mode,hashlib.sha256(p.read_bytes()).hexdigest()) for p in data.iterdir()}
            before = snapshot()
            try:
                with mock.patch.object(o,'HERMES_ROOT',data), mock.patch.object(o,'SCRATCH',scratch):
                    result = o.private_database(1010)
                self.assertTrue(result['original_files_unchanged'])
                self.assertEqual(before,snapshot())
                self.assertEqual(list(scratch.iterdir()),[])
            finally:
                db.close()

    def test_read_refuses_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory(prefix='capstone-observation-test-') as tmp:
            root = Path(tmp).resolve()
            file = root/'file'; file.write_bytes(b'ok')
            link = root/'link'; link.symlink_to(file)
            fifo = root/'fifo'; os.mkfifo(fifo)
            for path in (link,fifo):
                with self.assertRaises(o.Refused):
                    o.read_file(path)
            self.assertEqual(o.read_file(file)[0], b'ok')


if __name__ == '__main__':
    unittest.main(verbosity=2)
