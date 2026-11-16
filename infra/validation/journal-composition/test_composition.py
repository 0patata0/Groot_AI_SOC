"""Composed backend-to-consumer contracts; no live services, model or network."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(os.environ['SOC_JOURNAL_COMPOSITION_ROOT']).resolve()
sys.path.insert(0,str(ROOT/'infra/mcp'))
sys.path.insert(0,str(ROOT/'infra/hermes'))
from test_diagnostic_journal import d,h,j,m,NOW,args,row
from test_diagnostic_history import HistoryTests as CacheFixture, h as cache, event, query
from test_system_diagnostics import fields

spec=importlib.util.spec_from_file_location('composition_chat_contract',ROOT/'infra/hermes/chat_contract.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


class CacheConsumer(unittest.TestCase):
    setUp=CacheFixture.setUp
    publish=CacheFixture.publish

    def app(self,at=NOW-49500,identity='declared-error',level='error',form='logfmt'):
        value=event(at,identity,'apache2.service')
        value['error']={'at':at,'priority':6,'kind':'application_error','format':form,'level':level}
        return value

    def value(self):
        self.publish([self.app()])
        return cache.answer(query(),'c',NOW)

    def test_archived_application_fields_reach_shared_consumer_and_table(self):
        value=self.value();facts=c.diagnostic_observation_fields(value)
        app=facts['application_error_observations'][0]
        self.assertEqual(app['source_kind'],'journal_history')
        self.assertEqual(app['record_sha256'],value['recent_errors'][0]['record_sha256'])
        text=str(c.diagnostic_evidence_rows({'target':'c:apache',**facts},str))
        self.assertIn('error (logfmt) / 표본 1건',text)
        self.assertIn('공격·원인·현재 영향 확정 아님',text)

    def test_same_level_groups_keep_exact_returned_sample_count(self):
        self.publish([self.app(identity='one'),self.app(NOW-49501,'two')])
        facts=c.diagnostic_observation_fields(cache.answer(query(),'c',NOW))
        text=str(c.diagnostic_evidence_rows({'target':'c:apache',**facts},str))
        self.assertIn('표본 2건',text)
        self.assertEqual(len(facts['application_error_observations']),2)
        self.assertNotIn('전체 2건',text)

    def test_different_severities_and_formats_are_not_merged(self):
        self.publish([self.app(identity='one'),self.app(NOW-49501,'two','fatal','json')])
        facts=c.diagnostic_observation_fields(cache.answer(query(),'c',NOW))
        rows=c.diagnostic_evidence_rows({'target':'c:apache',**facts},str)
        self.assertEqual(sum('앱 선언 오류 수준' in r[0] for r in rows),2)

    def test_current_policy_coverage_is_verified_but_not_health(self):
        facts=c.diagnostic_observation_fields(self.value())
        self.assertTrue(facts['history_current_policy_coverage_verified'])
        self.assertEqual(facts['history_filter_policy'],d.ERROR_POLICY_REVISION)
        text=str(c.diagnostic_evidence_rows({'target':'c:apache',**facts},str))
        self.assertIn('전체 오류/정상 증명 아님',text)

    def test_legacy_database_coverage_stays_partial_and_events_are_visible(self):
        self.value()
        with cache.connection(True) as db,db:
            db.execute("DELETE FROM metadata WHERE key='source_filter_policy'")
        value=cache.answer(query(),'c',NOW);facts=c.diagnostic_observation_fields(value)
        self.assertFalse(facts['history_current_policy_coverage_verified'])
        self.assertEqual(facts['history_filter_policy'],'legacy-unversioned')
        self.assertEqual(len(facts['application_error_observations']),1)

    def test_missing_policy_in_old_backend_is_unreported_and_partial(self):
        value=self.value();value['history_coverage'].pop('source_filter_policy')
        facts=c.diagnostic_observation_fields(value)
        self.assertEqual(facts['history_reported_coverage_status'],'scanned_sample')
        self.assertEqual(facts['history_coverage_status'],'partial_or_unavailable')
        self.assertEqual(facts['history_filter_policy'],'unreported')
        self.assertFalse(facts['history_current_policy_coverage_verified'])

    def test_different_policy_cannot_reuse_full_coverage_marker(self):
        value=self.value();value['history_coverage']['source_filter_policy']='older-policy-v2'
        facts=c.diagnostic_observation_fields(value)
        self.assertFalse(facts['history_current_policy_coverage_verified'])
        self.assertEqual(facts['history_coverage_status'],'partial_or_unavailable')

    def test_current_policy_without_untruncated_flag_is_partial(self):
        value=self.value();value['history_coverage']['untruncated_requested_window_scanned']=False
        self.assertFalse(c.diagnostic_observation_fields(value)['history_current_policy_coverage_verified'])

    def test_invalid_application_fields_do_not_become_display_observations(self):
        original=self.value()
        for change in ({'level':'info'},{'level':True},{'format':'shell'},{'priority':True},
                       {'priority':7},{'priority':3},{'record_sha256':'invalid'},{'observed_at_kst':'invalid'}):
            with self.subTest(change=change):
                value=copy.deepcopy(original);value['recent_errors'][0].update(change)
                self.assertNotIn('application_error_observations',c.diagnostic_observation_fields(value))

    def test_application_history_keeps_requested_period_and_legacy_priorities(self):
        value=self.value();value['recent_errors'][0]['observed_at_kst']=h.shown(NOW*1000000)
        self.assertNotIn('application_error_observations',c.diagnostic_observation_fields(value))
        for priority in (0,3,True):
            app={'at':NOW-1,'priority':priority,'kind':'application_error','format':'logfmt','level':'error'}
            with self.subTest(priority=priority),self.assertRaises(d.DiagnosticError):
                d.validate_error(app,NOW-10,NOW)
        self.assertEqual(d.classify_message('level=error',priority=3)['kind'],'journal_error')

    def test_fine_clock_publication_and_application_policy_both_survive_merge(self):
        self.value()
        clock=cache.QueryClock(NOW,NOW*1000000+750000)
        with cache.connection(True) as db,db:
            db.execute("UPDATE metadata SET value=? WHERE key='observed_at_us'",(str(clock.microseconds+4900000),))
        self.assertEqual(cache.answer(query(),'c',clock)['history_coverage']['source_filter_policy'],d.ERROR_POLICY_REVISION)
        with cache.connection(True) as db,db:
            db.execute("UPDATE metadata SET value=? WHERE key='observed_at_us'",(str(clock.microseconds+5000001),))
        with self.assertRaisesRegex(d.DiagnosticError,'history_future_publication'):
            cache.answer(query(),'c',clock)


class CurrentConsumer(unittest.TestCase):
    def snapshot(self):
        def runner(argv,*unused):
            if argv[0]=='/usr/bin/systemctl':return 0,fields(argv[-1])
            if '--priority=err' in argv:return 0,b''
            return 0,d.encode(row('level=error msg="sample application failure"',at=NOW-60))
        snap=d.collect('siem',runner,NOW)
        with patch.object(m,'library',return_value=d),patch.object(d,'read_snapshot',return_value=snap),patch.object(m.time,'time',return_value=NOW),patch.object(m,'audit'):
            return m.query({'target':'b:management'})

    def test_current_snapshot_uses_actual_sample_time_without_synthetic_cursor_hash(self):
        value=self.snapshot();facts=c.diagnostic_observation_fields(value)
        app=facts['application_error_observations'][0]
        self.assertEqual(app['source_kind'],'sanitized_snapshot_sample')
        self.assertEqual(app['observed_at_kst'],h.shown((NOW-60)*1000000))
        self.assertNotIn('record_sha256',app)
        self.assertNotIn('history_current_policy_coverage_verified',facts)

    def test_current_snapshot_rejects_boolean_future_and_outside_sample_times(self):
        original=self.snapshot()
        for at in (True,NOW+1,NOW-100000000,2**64):
            value=copy.deepcopy(original);value['recent_errors'][0]['at']=at
            with self.subTest(at=at):
                self.assertNotIn('application_error_observations',c.diagnostic_observation_fields(value))

    def test_body_or_nested_severity_is_not_fabricated_by_consumer(self):
        value=self.snapshot();value['recent_errors']=[{'at':NOW-1,'priority':6,'kind':'journal_error',
            'message':'level=error','payload':{'level':'error'}}]
        self.assertNotIn('application_error_observations',c.diagnostic_observation_fields(value))

    def test_source_data_and_shared_role_policy_are_not_mutated(self):
        value=self.snapshot();before=copy.deepcopy(value)
        facts=c.diagnostic_observation_fields(value)
        c.diagnostic_evidence_rows({'target':'b:management',**facts},str)
        self.assertEqual(value,before)
        policy=c.workflow_policy(('soc-investigate',),section='service-investigation')
        self.assertIn('application_error',policy)
        self.assertIn('source_filter_policy',policy)

    def test_host_system_scope_and_schema_extension_are_explicit(self):
        schema=m.tools()[0]['inputSchema'];targets=schema['properties']['target']['enum']
        self.assertTrue({'a:systemd','b:systemd','c:systemd'}<=set(targets))
        for target in ('a:systemd','b:systemd','c:systemd'):
            request={**args(),'target':target}
            self.assertEqual(h.request({k:v for k,v in request.items() if k not in ('view','journal_scope')},NOW,host_journal=True)[0],target)
            with self.assertRaises(d.DiagnosticError):
                h.request({k:v for k,v in request.items() if k not in ('view','journal_scope')},NOW)
        for key in ('command','path','pattern','source_fd'):
            with self.assertRaises(d.DiagnosticError):m.arguments({'target':'b:docker',key:'untrusted'})


del CacheFixture
if __name__=='__main__':unittest.main()
