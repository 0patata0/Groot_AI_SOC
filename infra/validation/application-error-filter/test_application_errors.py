"""Fixed severity/selection tests; no host, package, network or model calls."""
import copy
import json
import os
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT=Path(os.environ['SOC_APP_ERROR_ROOT']).resolve()
assert (ROOT/'infra/mcp/system_diagnostics.py').is_file()
sys.path.insert(0,str(ROOT/'infra/mcp'))
from test_system_diagnostics import d, NOW, fields
from test_diagnostic_journal import h,j,args,row
from test_diagnostic_journal_native import n,FakeReader,event


class ApplicationErrors(unittest.TestCase):
    def setUp(self):
        for name,value in [('_history',h),('_journal',j)]:
            p=patch.object(d,name,value);p.start();self.addCleanup(p.stop)

    def test_logfmt_levels_keys_case_and_quotes(self):
        for key in ('level','severity','log.level','LEVEL','Level'):
            for level in sorted(d.APPLICATION_ERROR_LEVELS):
                for value in (level,level.upper(),'"'+level+'"',"'"+level+"'"):
                    with self.subTest(key=key,value=value):
                        found=d.application_error('time="sample" '+key+'='+value+' msg="failure detail"')
                        self.assertEqual(found,{'kind':'application_error','format':'logfmt','level':level})

    def test_json_whitespace_case_order_and_escaped_level(self):
        for key in ('level','severity','log.level','LEVEL','Level'):
            for level in ('error','ERROR','critical','fatal','panic'):
                for separators in [(',',':'),(', ',': '),(',\n',' :\t')]:
                    with self.subTest(key=key,level=level,separators=separators):
                        text=json.dumps({'message':'failure','time':'sample',key:level},separators=separators)
                        self.assertEqual(d.application_error(text),{'kind':'application_error','format':'json','level':level.lower()})
        self.assertEqual(d.application_error('{"level":"\\u0065rror"}')['level'],'error')
        for text in ['{"\\u006cevel":"error"}', 'lEvEl=ErRoR msg=failed']:
            self.assertTrue(d.is_error_candidate(text, '6'))

    def test_normal_levels_and_quoted_or_nested_error_markers_are_not_errors(self):
        normal=['level=info msg="level=error"','level=warning msg="HTTP 403"','level=debug msg="error occurred previously"',
            'msg="severity=ERROR"','message="{\\"level\\":\\"error\\"}"',
            '{"level":"info","payload":{"level":"error"}}',
            '{"message":"level=error","payload":{"severity":"fatal"}}',
            'GET /?level=error HTTP/1.1','ordinary error in documentation']
        for text in normal:
            with self.subTest(text=text):
                self.assertIsNone(d.application_error(text))
                self.assertFalse(d.is_error_candidate(text,'6'))

    def test_ambiguous_duplicates_and_invalid_shapes_do_not_declare_severity(self):
        for text in ['level=info level=error','level=error level=error','level=error severity=fatal',
            '{"level":"info","level":"error"}','{"level":"error","LEVEL":"error"}',
            '{"level":true}','{"level":50}','{"level":{"value":"error"}}','["error"]',
            'prefix level=error','level = error','level="error"garbage','level="unterminated',
            'level=error msg="invalid\\q"']:
            with self.subTest(text=text):self.assertIsNone(d.application_error(text))

    def test_input_limits_and_nontext_never_escape(self):
        for text in (None,False,[],{},0,'','x'*16385,'level=error '+'x'*16384):
            with self.subTest(type=type(text).__name__):self.assertIsNone(d.application_error(text))
        self.assertIsNone(d.application_error(' '.join('x'+str(i)+'=v'for i in range(65))+' level=error'))
        self.assertIsNone(d.application_error(json.dumps({'level':'error',**{'x'+str(i):0 for i in range(64)}})))

    def test_prefilter_remains_finite_and_covers_supported_field_spellings(self):
        literals=n.fixed_literals()
        self.assertTrue({x.encode()for x in d.LEGACY_ERROR_LITERALS}<=set(literals))
        for text in ['level=error','LEVEL=ERROR','Severity="fatal"','{"level" :\n "error"}',
                     '{ "log.level"\t:\t"critical" }']:
            self.assertRegex(text,d.ERROR_PATTERN)
            self.assertTrue(d.is_error_candidate(text,'6'))

    def test_classification_is_sanitized_and_retains_legacy_details(self):
        for text in ['level=error msg="sensitive_fixture"','{"severity":"fatal","secret":"sensitive_fixture"}']:
            found=d.classify_message(text,'docker.service',priority=6)
            self.assertEqual(set(found),{'kind','format','level'})
            self.assertNotIn('sensitive_fixture',json.dumps(found))
        self.assertEqual(d.classify_message('PermissionError: detail'),{'kind':'python_exception','exception':'PermissionError'})
        self.assertEqual(d.classify_message('level=error msg="Permission denied"')['kind'],'permission_denied')

    def test_error_schema_rejects_fields_values_and_nonstring_severity(self):
        good={'at':NOW-1,'priority':6,'kind':'application_error','format':'json','level':'error'}
        d.validate_error(good,NOW-10,NOW)
        for change in [{'level':'info'},{'level':True},{'format':'shell'},{'message':'forbidden'},{'command':'sh'}]:
            with self.subTest(change=change),self.assertRaises(d.DiagnosticError):
                d.validate_error({**good,**change},NOW-10,NOW)

    def fixtures(self):
        messages=['time="sample" level=error msg="Handler returned 500"',
                  '{"severity":"fatal","message":"application failure"}',
                  'level=info msg="level=error"','{"level":"info","payload":{"level":"error"}}',
                  'RuntimeError: fixed fixture','ordinary journal error priority','level=debug msg="normal"']
        return [row(m,identity='r'+str(i),at=NOW-100-i,priority='3'if i==5 else'6')for i,m in enumerate(messages)]

    def test_current_collector_and_archived_metadata_share_the_same_classification(self):
        rows=self.fixtures();raw=b'\n'.join(d.encode(x).strip()for x in rows)
        current,_=d.journal_errors(raw,['capstone-management.service'],NOW)
        errors=current['capstone-management.service']
        self.assertEqual(errors['error_observations']['count'],4)
        history,_=h.normalize(raw,{'capstone-management.service'},(NOW-3600)*1000000,NOW*1000000)
        self.assertEqual(len(history),4)
        self.assertEqual(sum(x['error']['kind']=='application_error'for x in history),2)
        self.assertNotIn('sensitive_fixture',d.encode(errors).decode())

    def test_collector_uses_existing_two_bounded_sources_without_permission_expansion(self):
        rows=self.fixtures();calls=[]
        def runner(argv,maximum,seconds):
            calls.append((argv,maximum,seconds))
            if argv[0]=='/usr/bin/systemctl':return 0,fields(argv[-1])
            selected=[x for x in rows if (int(x['PRIORITY'])<=3 if '--priority=err'in argv
                else 4<=int(x['PRIORITY'])<=6 and re.search(d.ERROR_PATTERN,x['MESSAGE']))]
            return 0,b'\n'.join(d.encode(x).strip()for x in selected)
        value=d.collect('siem',runner,NOW)
        self.assertEqual(value['units']['b:management']['error_observations']['count'],4)
        queries=[x for x in calls if x[0][0]=='/usr/bin/journalctl']
        self.assertEqual(len(queries),2)
        self.assertTrue(all(x[1:]==(1048576,8)for x in queries))

    def test_cli_and_native_select_identical_error_rows_on_shared_fixture(self):
        rows=self.fixtures()
        def runner(argv,maximum,seconds):
            selected=[x for x in rows if (int(x['PRIORITY'])<=3 if '--priority=err'in argv
                else 4<=int(x['PRIORITY'])<=6 and re.search(d.ERROR_PATTERN,x['MESSAGE']))]
            return 0,b'\n'.join(d.encode(x).strip()for x in selected)
        cli=j.answer(args(),'b',NOW,runner)
        native_rows=[event(at=int(x['__REALTIME_TIMESTAMP'])//1000000,message=x['MESSAGE'].encode(),
                           priority=x['PRIORITY'].encode(),cursor=x['__CURSOR'])for x in rows]
        native=n.worker({'value':args(),'host':'b'},now=NOW,factory=lambda:FakeReader(native_rows))
        self.assertEqual(cli['returned_entries'],4)
        self.assertEqual(cli['entries'],native['entries'])
        self.assertFalse(cli['has_more']);self.assertFalse(native['source_limited'])

    def test_all_scope_keeps_normal_rows_and_their_source_hashes(self):
        rows=self.fixtures();value=args(journal_scope='all')
        result=j.answer(value,'b',NOW,lambda*a:(0,b'\n'.join(d.encode(x).strip()for x in rows)))
        self.assertEqual(result['returned_entries'],len(rows))
        self.assertEqual({x['record_sha256']for x in result['entries']},
                         {__import__('hashlib').sha256(x['__CURSOR'].encode()).hexdigest()for x in rows})

    def test_broad_prefilter_tail_never_claims_full_untruncated_empty(self):
        normal=[row('level=info msg="normal"',at=NOW-100-i,identity='n'+str(i))for i in range(51)]
        def runner(argv,*unused):return (0,b'')if'--priority=err'in argv else(0,b'\n'.join(d.encode(x).strip()for x in normal))
        result=j.answer(args(limit=50),'b',NOW,runner)
        self.assertEqual(result['returned_entries'],0)
        self.assertTrue(result['has_more'])
        self.assertIsNone(result['requested_window_total_count'])

    def test_native_skips_normal_prefilter_hits_before_the_selected_row_limit(self):
        rows=[event(at=NOW-100-i,message=b'level=info msg="normal"',cursor='n'+str(i))for i in range(60)]
        rows.append(event(at=NOW-200,message=b'level=error msg="failure"',cursor='actual-error'))
        value=args(limit=1)
        result=n.worker({'value':value,'host':'b'},now=NOW,factory=lambda:FakeReader(rows))
        self.assertEqual(len(result['entries']),1)
        self.assertEqual(result['entries'][0]['message_excerpt'],'level=error msg="failure"')
        self.assertFalse(result['source_limited'])

    def test_conflicting_excluded_prefilter_rows_still_refuse_source(self):
        rows=[row('level=info msg="one"'),row('level=info msg="two"')]
        def runner(argv,*unused):return (0,b'')if'--priority=err'in argv else(0,b'\n'.join(d.encode(x).strip()for x in rows))
        with self.assertRaisesRegex(d.DiagnosticError,'journal_cursor_conflict'):
            j.answer(args(),'b',NOW,runner)

    def test_router_input_schema_and_permissions_remain_fixed(self):
        from test_system_diagnostics import m
        with self.assertRaises(d.DiagnosticError):m.arguments({'target':'b:docker','pattern':'level=error'})
        with self.assertRaises(d.DiagnosticError):m.arguments({'target':'b:docker','command':'journalctl'})
        self.assertIsNone(d.application_error('no structured severity'))


from test_diagnostic_history import HistoryTests as CacheFixture, h as cache, event as cache_event, query as cache_query


class PolicyMigration(unittest.TestCase):
    setUp=CacheFixture.setUp
    publish=CacheFixture.publish

    def legacy(self):
        with cache.connection(True) as db,db:
            db.execute("DELETE FROM metadata WHERE key='source_filter_policy'")

    def test_old_unversioned_coverage_is_partial_while_events_remain_readable(self):
        self.publish([cache_event(NOW-49500)])
        self.legacy()
        value=cache.answer(cache_query(),'c',NOW)
        self.assertEqual(value['indexed_error_count'],1)
        self.assertEqual(value['history_coverage']['source_filter_policy'],'legacy-unversioned')
        self.assertFalse(value['history_coverage']['untruncated_requested_window_scanned'])
        cache.validate_answer(value,cache_query(),'c',NOW)

    def test_first_new_policy_publish_resets_only_old_coverage(self):
        old=cache_event(NOW-49500)
        self.publish([old]);self.legacy()
        self.publish(since=NOW-14400)
        value=cache.answer(cache_query(),'c',NOW)
        self.assertEqual(value['indexed_error_count'],1)
        self.assertEqual(value['recent_errors'][0]['record_sha256'],old['record_sha256'])
        self.assertFalse(value['history_coverage']['untruncated_requested_window_scanned'])
        recent=cache.answer(cache_query(since=NOW-1000,until=NOW-1),'c',NOW)
        self.assertTrue(recent['history_coverage']['untruncated_requested_window_scanned'])
        self.assertEqual(recent['history_coverage']['source_filter_policy'],d.ERROR_POLICY_REVISION)

    def test_actual_rescan_can_restore_older_window_coverage(self):
        self.publish();self.legacy();self.publish(since=NOW-14400)
        self.assertFalse(cache.answer(cache_query(),'c',NOW)['history_coverage']['untruncated_requested_window_scanned'])
        self.publish(since=NOW-50000,until=NOW-49000)
        self.assertTrue(cache.answer(cache_query(),'c',NOW)['history_coverage']['untruncated_requested_window_scanned'])

    def test_same_policy_repeated_publish_keeps_windows_and_deduplicates(self):
        self.publish([cache_event(NOW-49500)])
        self.publish(since=NOW-14400);self.publish(since=NOW-14400)
        value=cache.answer(cache_query(),'c',NOW)
        self.assertEqual(value['indexed_error_count'],1)
        self.assertTrue(value['history_coverage']['untruncated_requested_window_scanned'])

    def test_failed_policy_change_rolls_back_coverage_reset_and_events(self):
        original=cache_event(NOW-49500)
        self.publish([original]);self.legacy()
        with cache.connection() as db:before=db.execute('SELECT count(*) FROM windows').fetchone()[0]
        conflict=copy.deepcopy(original);conflict['error']['kind']='not_found'
        with self.assertRaisesRegex(d.DiagnosticError,'history_cursor_conflict'):
            self.publish([conflict])
        with cache.connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM windows').fetchone()[0],before)
            self.assertNotIn('source_filter_policy',dict(db.execute('SELECT key,value FROM metadata')))
        self.assertEqual(cache.answer(cache_query(),'c',NOW)['recent_errors'][0]['kind'],'permission_denied')

    def test_existing_high_priority_generic_record_does_not_change_kind_on_rescan(self):
        at=NOW-49500;unit='apache2.service';cursor='old-generic'
        old=cache_event(at,cursor,unit);old['error']['kind']='journal_error'
        self.publish([old]);self.legacy()
        raw=d.encode({'_SYSTEMD_UNIT':unit,'__CURSOR':cursor,'__REALTIME_TIMESTAMP':str(at*1000000),
                      'PRIORITY':'3','MESSAGE':'level=error msg="application failure"'})
        values,_=cache.normalize(raw,{unit},(NOW-50000)*1000000,(NOW-49000)*1000000)
        self.assertEqual(values[0]['error']['kind'],'journal_error')
        self.publish(values)
        self.assertEqual(cache.answer(cache_query(),'c',NOW)['indexed_error_count'],1)

    def test_forged_full_coverage_for_legacy_policy_is_rejected(self):
        self.publish();value=cache.answer(cache_query(),'c',NOW)
        value['history_coverage']['source_filter_policy']='legacy-unversioned'
        with self.assertRaises(d.DiagnosticError):cache.validate_answer(value,cache_query(),'c',NOW)

    def test_unknown_policy_is_visible_as_partial_not_silent_current_coverage(self):
        self.publish()
        with cache.connection(True) as db,db:
            db.execute("UPDATE metadata SET value='other-policy-v9' WHERE key='source_filter_policy'")
        value=cache.answer(cache_query(),'c',NOW)
        self.assertEqual(value['history_coverage']['source_filter_policy'],'other-policy-v9')
        self.assertFalse(value['history_coverage']['untruncated_requested_window_scanned'])
        cache.validate_answer(value,cache_query(),'c',NOW)


del CacheFixture  # Keep imported old fixtures out of this module's test count.

if __name__=='__main__':unittest.main()
