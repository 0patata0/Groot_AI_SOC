"""Real isolated SQLite and fixed-protocol tests; no journal/SSH/service calls."""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from test_system_diagnostics import d, m, r, load, snapshot, record, NOW

h = load('history_test', 'diagnostic_history.py')
h.core = d
US = 1000000


def event(at, identity='one', unit='apache2.service'):
    return {'record_sha256':hashlib.sha256(identity.encode()).hexdigest(), 'at_us':at * US, 'unit':unit,
            'error':{'at':at, 'priority':3, 'kind':'permission_denied'}}


def query(since=NOW-50000, until=NOW-49000, target='c:apache', limit=20):
    return {'target':target, 'since_kst':h.shown(since * US), 'until_kst':h.shown(until * US), 'limit':limit}


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.tmp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.path = Path(self.tmp) / 'history.sqlite3'
        uid, gid = os.getuid(), os.getgid()
        original_lstat = Path.lstat
        def metadata(path, *a, **kw):
            value = original_lstat(path, *a, **kw)
            if path == self.path:
                return NS(**{name:(0 if name == 'st_uid' else getattr(value,name))
                    for name in ('st_uid','st_gid','st_mode','st_nlink','st_size')})
            return value
        for item in (patch.object(h,'DATABASE',self.path), patch.object(h.grp,'getgrnam',return_value=NS(gr_gid=gid)),
                     patch.object(h.os,'getuid',return_value=0), patch.object(h.os,'geteuid',return_value=0),
                     patch.object(h.os,'fchown'), patch.object(d,'trusted_parents'), patch.object(Path,'lstat',metadata),
                     patch.object(d,'_history',h)):
            self.stack.enter_context(item)
        self.addCleanup(self.stack.close)
        m._queries.clear()

    def publish(self, events=None, since=NOW-86400, until=NOW, clipped=False, host='c'):
        h.publish(host,since*US,until*US,events or [],clipped)

    def test_backfill_adds_missing_info_priority_error_without_rewriting_old_records(self):
        unit='capstone-management.service';raw=record(unit,json.dumps({'status':'failed','error':'controller_already_running'}),ago=49500)
        raw.update(__CURSOR='fixed-fixture-cursor',PRIORITY='6')
        rows,_=h.normalize(d.encode(raw),{unit},(NOW-50000)*US,(NOW-49000)*US)
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['error']['code'],'controller_already_running')
        self.publish([dict(event(NOW-49510,'old',unit),error={'at':NOW-49510,'priority':3,'kind':'journal_error'})],host='b')
        self.publish(rows,host='b');self.publish(rows,host='b')
        args=query(target='b:management');result=h.answer(args,'b',NOW)
        self.assertEqual(result['returned_error_count'],2)
        self.assertEqual(result['recent_errors'][0]['code'],'controller_already_running')
        self.assertEqual(result['recent_errors'][1]['kind'],'journal_error')
        self.assertIs(h.validate_answer(result,args,'b',NOW),result)
        self.assertNotIn('MESSAGE',json.dumps(result));self.assertFalse(result['raw_messages_returned'])

    def test_old_window_is_filtered_before_limit_and_never_becomes_current_health(self):
        rows=[event(NOW-49500,'old')]+[event(NOW-i,str(i)) for i in range(100)]
        self.publish(rows)
        result=h.answer(query(limit=1),'c',NOW)
        self.assertEqual(result['returned_error_count'],1)
        self.assertEqual(result['recent_errors'][0]['record_sha256'],rows[0]['record_sha256'])
        self.assertEqual(result['indexed_error_count'],1)
        self.assertIsNone(result['requested_window_total_count'])
        self.assertNotIn('properties',result)
        self.assertEqual(result['history_coverage']['status'],'scanned_sample')
        self.assertIs(h.validate_answer(result,query(limit=1),'c',NOW),result)

    def test_latest_errors_do_not_displace_older_events_until_explicit_retention(self):
        self.publish([event(NOW-49500,'old')])
        self.publish([event(NOW-i,str(i)) for i in range(200)],since=NOW-14400,until=NOW+1)
        self.assertEqual(h.answer(query(),'c',NOW+1)['indexed_error_count'],1)

    def test_zero_in_unscanned_window_is_explicitly_partial(self):
        self.publish(since=NOW-14400)
        result=h.answer(query(),'c',NOW)
        self.assertEqual(result['returned_error_count'],0)
        self.assertEqual(result['history_coverage']['status'],'partial_or_unavailable')
        self.assertIsNone(result['requested_window_total_count'])

    def test_truncated_scans_and_gaps_are_not_full_window_coverage(self):
        self.publish(since=NOW-50000,until=NOW-49600)
        self.publish(since=NOW-49500,until=NOW-49000)
        self.assertFalse(h.answer(query(),'c',NOW)['history_coverage']['untruncated_requested_window_scanned'])
        self.publish(since=NOW-50000,until=NOW-49000,clipped=True)
        self.assertFalse(h.answer(query(),'c',NOW)['history_coverage']['untruncated_requested_window_scanned'])
        self.publish(since=NOW-49600,until=NOW-49500)
        self.assertTrue(h.answer(query(),'c',NOW)['history_coverage']['untruncated_requested_window_scanned'])

    def test_cursor_dedup_keeps_distinct_events_at_the_same_instant(self):
        a,b=event(NOW-49500,'a'),event(NOW-49500,'b')
        self.publish([a,b]);self.publish([a,b])
        result=h.answer(query(limit=1),'c',NOW)
        self.assertEqual(result['indexed_error_count'],2)
        self.assertTrue(result['has_more'])
        h.validate_answer(result,query(limit=1),'c',NOW)

    def test_conflict_rolls_back_whole_batch(self):
        a=event(NOW-49500,'a');self.publish([a])
        conflict=copy.deepcopy(a);conflict['error']['kind']='not_found'
        with self.assertRaisesRegex(d.DiagnosticError,'cursor_conflict'):
            self.publish([event(NOW-49501,'new'),conflict])
        self.assertEqual(h.answer(query(),'c',NOW)['indexed_error_count'],1)

    def test_stale_history_is_not_current_and_clock_does_not_regress(self):
        self.publish(until=NOW-500)
        self.publish(until=NOW-700)
        result=h.answer(query(),'c',NOW)
        self.assertTrue(result['publisher_stale'])
        self.assertEqual(result['age_seconds'],500)
        h.validate_answer(result,query(),'c',NOW)

    def test_row_cap_moves_retention_boundary_past_all_tied_rows(self):
        rows=[event(NOW-49500,'a'),event(NOW-49500,'b'),event(NOW-49400,'c'),event(NOW-49300,'d')]
        with patch.object(h,'MAX_EVENTS',2):self.publish(rows)
        result=h.answer(query(),'c',NOW)
        self.assertEqual(result['indexed_error_count'],2)
        self.assertFalse(result['history_coverage']['untruncated_requested_window_scanned'])
        retained=result['history_coverage']['retained_since_kst']
        self.publish(since=NOW-14400,until=NOW+1)
        self.assertEqual(h.answer(query(),'c',NOW+1)['history_coverage']['retained_since_kst'],retained)

    def test_readonly_connection_cannot_mutate_cache(self):
        self.publish()
        with self.assertRaisesRegex(d.DiagnosticError,'storage_unavailable'):
            with h.connection() as db:db.execute('DELETE FROM events')

    def test_hardlink_symlink_and_group_writable_file_are_refused(self):
        self.publish()
        alias=Path(self.tmp)/'alias';os.link(self.path,alias)
        with self.assertRaisesRegex(d.DiagnosticError,'file_unsafe'):h.answer(query(),'c',NOW)
        alias.unlink();self.path.chmod(0o660)
        with self.assertRaisesRegex(d.DiagnosticError,'file_unsafe'):h.answer(query(),'c',NOW)
        self.path.chmod(0o640);self.path.rename(alias);self.path.symlink_to(alias)
        with self.assertRaisesRegex(d.DiagnosticError,'file_unsafe'):h.answer(query(),'c',NOW)

    def test_unknown_host_and_target_fail_closed(self):
        self.publish()
        with self.assertRaises(d.DiagnosticError):h.answer(query(),'b',NOW)
        with self.assertRaises(d.DiagnosticError):self.publish(host='b')

    def test_tampered_history_cannot_return_raw_messages(self):
        self.publish([event(NOW-49500)])
        with h.connection(True) as db,db:
            row=db.execute('SELECT id,error FROM events').fetchone();value=json.loads(row[1]);value['MESSAGE']='SECRET'
            db.execute('UPDATE events SET error=? WHERE id=?',(json.dumps(value),row[0]))
        with self.assertRaises(d.DiagnosticError):h.answer(query(),'c',NOW)

    def test_normalizer_preserves_fractional_time_and_only_fixed_error_fields(self):
        raw=record('apache2.service');raw.update(__CURSOR='opaque secret cursor',__REALTIME_TIMESTAMP=str((NOW-49500)*US+123456))
        rows,truncated=h.normalize(d.encode(raw),{'apache2.service'},(NOW-50000)*US,(NOW-49000)*US)
        self.assertEqual(rows[0]['at_us'],(NOW-49500)*US+123456)
        self.assertNotIn(b'NEVER_RETURN',d.encode(rows));self.assertNotIn(b'opaque secret',d.encode(rows))
        self.assertFalse(truncated);self.publish(rows)
        self.assertIn('.123456+09:00',h.answer(query(),'c',NOW)['recent_errors'][0]['observed_at_kst'])

    def test_bad_source_cursor_time_unit_and_priority_are_not_zero_success(self):
        raw=dict(record('apache2.service'),__CURSOR='cursor')
        for field,value in [('__CURSOR',None),('__REALTIME_TIMESTAMP','NaN'),('PRIORITY','7'),('_SYSTEMD_UNIT','ssh.service')]:
            with self.subTest(field=field), self.assertRaises(d.DiagnosticError):
                h.normalize(d.encode(dict(raw,**{field:value})),{'apache2.service'},(NOW-14400)*US,NOW*US)

    def test_regular_collection_reuses_the_same_two_journal_reads(self):
        from test_system_diagnostics import fields
        calls=[];raw=dict(record('apache2.service'),__CURSOR='fresh-cursor')
        def run(argv,maximum,seconds):
            calls.append(argv)
            if argv[0]=='/usr/bin/systemctl':return 0,fields(argv[-1])
            return 0,d.encode(raw) if '--priority=err' in argv else b''
        captured={}
        result=d.collect('service',run,NOW,include_runtime=False,history_output=captured)
        self.assertEqual(len(calls),len(d.PROFILES['service'])+2)
        self.assertEqual(result['units']['c:apache']['error_observations']['count'],1)
        self.assertEqual(len(captured['events']),1)
        h.publish(**captured)
        self.assertEqual(h.answer(query(since=NOW-120,until=NOW),'c',NOW)['indexed_error_count'],1)

    def test_backfill_accepts_only_fixed_role_and_two_fixed_read_filters(self):
        calls=[]
        def run(argv,maximum,seconds):
            calls.append((argv,maximum,seconds));return 0,b''
        with patch.object(d,'bounded_command',run):
            result=h.collect('service',NOW,hours=24)
            with self.assertRaises(d.DiagnosticError):h.collect('service',NOW,hours=25)
        self.assertEqual(len(calls),12)
        for argv,maximum,seconds in calls:
            self.assertEqual(argv[0],'/usr/bin/journalctl')
            since=int(next(a.removeprefix('--since=@') for a in argv if a.startswith('--since=@')))
            until=int(next(a.removeprefix('--until=@') for a in argv if a.startswith('--until=@')))
            self.assertEqual(until-since,14400)
            self.assertEqual((maximum,seconds),(1048576,8))
            self.assertTrue(all(a.removeprefix('--unit=') in d.PROFILES['service'].values() for a in argv if a.startswith('--unit=')))
        self.assertFalse(result['source_truncated'])

    def test_failed_backfill_window_does_not_publish_zero_or_full_coverage(self):
        def run(argv,maximum,seconds):
            if '--since=@'+str(NOW-57600) in argv:raise d.DiagnosticError('command_timeout')
            return 0,b''
        with patch.object(d,'bounded_command',run):result=h.collect('service',NOW,hours=24)
        self.assertEqual(result['failed_window_count'],1)
        self.assertEqual(h.answer(query(),'c',NOW)['history_coverage']['status'],'partial_or_unavailable')
        with patch.object(d,'bounded_command',side_effect=d.DiagnosticError('command_timeout')):
            with self.assertRaisesRegex(d.DiagnosticError,'no_window_available'):h.collect('service',NOW,hours=24)

    def test_reader_history_does_not_require_a_current_snapshot(self):
        self.publish([event(NOW-49500)])
        import io
        output=NS(buffer=io.BytesIO())
        with patch.object(r.sys,'argv',['reader']),patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':''}),patch.object(r,'load_library',return_value=d),patch.object(r,'incoming',return_value=d.encode(query())),patch.object(h.time,'time',return_value=NOW),patch.object(d,'read_snapshot',side_effect=AssertionError('not current')),patch.object(r.sys,'stdout',output),patch.object(r.syslog,'syslog'):
            r.main()
        result=json.loads(output.buffer.getvalue())
        self.assertEqual(result['kind'],'journal_history')
        self.assertEqual(result['returned_error_count'],1)

    def test_bounds_pairs_offsets_runtime_targets_and_injection_are_refused(self):
        base=query()
        variants=[dict(base,limit=True),dict(base,limit=51),dict(base,lookback_minutes=15),dict(base,target='c:systemd'),
            dict(base,target='c:apache;cat /etc/shadow'),dict(base,since_kst=base['since_kst'].replace('+09:00','Z')),
            dict(base,until_kst=base['since_kst']),query(since=NOW-86401,until=NOW),query(until=NOW+1)]
        variants += [{k:v for k,v in base.items() if k != missing} for missing in ('since_kst','until_kst')]
        for value in variants:
            with self.subTest(value=value),self.assertRaises(d.DiagnosticError):h.request(value,NOW)

    def test_router_selects_history_without_current_snapshot(self):
        self.publish([event(NOW-49500,unit='soc-bot.service')],host='b')
        value=query(target='b:soc-bot')
        with patch.object(m.time,'time',return_value=NOW),patch.object(m,'audit'),patch.object(d,'read_snapshot',side_effect=AssertionError('no current read')):
            result=m.query(value)
        self.assertEqual(result['kind'],'journal_history')
        self.assertEqual(result['indexed_error_count'],1)

    def test_remote_history_has_fixed_ssh_no_command_and_bounded_stdin(self):
        self.publish();value=query();result=h.answer(value,'c',NOW)
        with patch.object(m.time,'time',return_value=NOW),patch.object(m,'audit'),patch.object(m,'route_config',return_value={'ssh_port':22,'hosts':{'a':'10.0.0.1','c':'10.0.0.2'}}),patch.object(d,'bounded_command',return_value=(0,d.encode(result))) as run:
            self.assertEqual(m.query(value),result)
        args,kwargs=run.call_args
        self.assertEqual(args[0][-1],'capstone-diagnostics@10.0.0.2')
        self.assertEqual(kwargs,{'input_data':d.encode(value)})
        self.assertEqual(args[1:],(65536,12))
        self.assertNotIn('sudo',args[0])

    def test_response_binding_rejects_wrong_window_host_raw_body_counts_and_scope(self):
        self.publish([event(NOW-49500)]);value=query();result=h.answer(value,'c',NOW)
        for change in ({'host':'a'},{'requested_since_kst':h.shown((NOW-40000)*US)}, {'MESSAGE':'SECRET'},
                       {'mutation_performed':True},{'returned_error_count':0},{'has_more':True},{'publisher_stale':True}):
            with self.subTest(change=change),self.assertRaises(d.DiagnosticError):h.validate_answer(dict(result,**change),value,'c',NOW)

    def test_reader_stdin_empty_eof_and_json_are_distinct_and_bounded(self):
        for payload in (b'',b'{"target":"c:apache"}',b'x'*4097):
            read,write=os.pipe()
            try:
                os.write(write,payload);os.close(write);write=None
                with patch.object(r.sys,'stdin',NS(fileno=lambda:read)):
                    if len(payload)>4096:
                        with self.assertRaisesRegex(ValueError,'input_bound'):r.incoming()
                    else:self.assertEqual(r.incoming(),payload)
            finally:
                os.close(read)
                if write is not None:os.close(write)


if __name__ == '__main__':
    unittest.main()
