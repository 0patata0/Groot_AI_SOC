"""Exact query boundaries, real SQLite and unchanged transport/authority contracts."""
from pathlib import Path
import copy,importlib.util,json,os,sys,unittest
from unittest.mock import patch
ROOT=Path(os.environ['SOC_BOUNDARIES_ROOT']).resolve();BASE=Path(os.environ['SOC_BOUNDARIES_BASE']).resolve()
sys.path.insert(0,str(ROOT/'infra/mcp'))
from test_diagnostic_journal import d,h,j,m,NOW,args
import test_diagnostic_history as history_fixture

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module
before=load('prior_history_clock',BASE/'infra/mcp/diagnostic_history.py');before.core=d

class ClockBoundaries(unittest.TestCase):
    def setUp(self):
        self.clean=[]
        for p in (patch.object(d,'_history',h),patch.object(d,'_journal',j),
                  patch.object(h.time,'time',return_value=NOW+.75),
                  patch.object(h.time,'time_ns',return_value=NOW*1000000000+750000999)):
            p.start();self.addCleanup(p.stop)
        m._queries.clear();self.us=NOW*1000000+750000

    def request(self,since=None,until=None):
        return dict(args(),since_kst=h.shown(self.us-1000000 if since is None else since),
            until_kst=h.shown(self.us if until is None else until))

    def test_same_second_past_is_accepted_without_a_future_grace(self):
        value=self.request(until=self.us-250000)
        self.assertEqual(j.request(value)[2],self.us-250000)
        with self.assertRaisesRegex(ValueError,'retention_or_future'):
            before.request({k:v for k,v in value.items() if k!='view'})
        with self.assertRaisesRegex(ValueError,'retention_or_future'):
            j.request(self.request(until=self.us+1))

    def test_retention_boundary_is_exact_not_rounded_to_the_previous_second(self):
        cutoff=self.us-30*86400*1000000
        self.assertEqual(j.request(self.request(since=cutoff,until=cutoff+1))[1],cutoff)
        value=self.request(since=cutoff-1,until=cutoff+1)
        with self.assertRaisesRegex(ValueError,'retention_or_future'):j.request(value)
        self.assertEqual(before.request({k:v for k,v in value.items() if k!='view'})[1],cutoff-1)

    def test_twenty_four_hour_maximum_is_not_rounded_or_extended(self):
        self.assertEqual(j.request(self.request(since=self.us-86400*1000000))[2],self.us)
        with self.assertRaisesRegex(ValueError,'at_most_24_hours'):
            j.request(self.request(since=self.us-86400*1000000-1))

    def test_private_clock_freezes_once_and_explicit_seconds_keep_their_meaning(self):
        with patch.object(h.time,'time_ns',side_effect=[self.us*1000+999,999]) as clock:
            frozen=h.query_clock();self.assertEqual(h.query_clock(frozen),frozen)
            self.assertEqual(j.request(self.request(),frozen)[2],self.us)
            self.assertEqual(clock.call_count,1)
        self.assertEqual(h.query_clock(NOW).microseconds,NOW*1000000)
        with self.assertRaisesRegex(ValueError,'retention_or_future'):j.request(self.request(),NOW)

    def test_no_float_bool_foreign_tuple_or_inconsistent_private_clock(self):
        for value in (True,NOW+.75,(NOW,self.us),[NOW,self.us],h.QueryClock(NOW+1,self.us),h.QueryClock(NOW,float(self.us))):
            with self.subTest(clock_type=type(value).__name__),self.assertRaisesRegex(ValueError,'history_clock_invalid'):
                h.query_clock(value)

    def test_clock_fields_are_never_allowed_in_mcp_or_journal_arguments(self):
        for key,value in (('now',NOW),('clock',[NOW,self.us]),('now_us',self.us),('host_journal',True)):
            with self.subTest(key=key),self.assertRaises(ValueError):j.request(dict(self.request(),**{key:value}))

    def test_all_host_journals_share_clock_without_opening_archived_host_history(self):
        for host in ('a','b','c'):
            value=dict(self.request(),target=host+':systemd')
            with self.subTest(host=host):
                self.assertEqual(j.request(value)[2],self.us)
                with self.assertRaisesRegex(ValueError,'history_unit_target_required'):
                    h.request({k:v for k,v in value.items() if k!='view'})

    def test_cli_and_native_parent_receive_identical_unrounded_interval(self):
        value=self.request();frozen=h.query_clock();commands=[]
        def runner(argv,*unused):commands.append(argv);return 0,b''
        cli=j.answer(value,'b',frozen,runner)
        class Native:
            def answer(self,value,host,now):
                self.now=now
                return j.finish(value,host,now,[],False)
        backend=Native()
        with patch.object(j,'native_library',return_value=backend):native=j.answer(value,'b',frozen)
        self.assertEqual(native,cli);self.assertIs(backend.now,frozen)
        self.assertEqual(cli['observed_at_kst'],h.shown(self.us))
        self.assertEqual(cli['requested_until_kst'],value['until_kst'])
        self.assertIn('--until=@'+str(self.us//1000000)+'.750000',commands[0])
        self.assertIsNone(cli['requested_window_total_count']);self.assertFalse(cli['journal_retention_verified'])

    def test_response_age_and_future_tolerance_are_exact_microseconds(self):
        value=self.request();frozen=h.query_clock();good=j.finish(value,'b',frozen,[],False)
        for delta in (-20000000,5000000):
            changed=dict(good,observed_at_kst=h.shown(self.us+delta))
            self.assertEqual(j.validate_answer(changed,value,'b',frozen),changed)
        for delta in (-20000001,5000001):
            with self.subTest(delta=delta),self.assertRaisesRegex(ValueError,'journal_response_stale'):
                j.validate_answer(dict(good,observed_at_kst=h.shown(self.us+delta)),value,'b',frozen)

    def test_mcp_journal_route_uses_the_precise_input_boundary(self):
        value=self.request();good=j.finish(value,'b',h.query_clock(),[],False)
        with patch.object(j,'query_local',return_value=good) as local,patch.object(m,'audit'):
            self.assertEqual(m.query(value),good);local.assert_called_once_with(value,'b')

    def test_current_snapshot_path_does_not_load_the_history_clock(self):
        with patch.object(d,'history_library',side_effect=AssertionError('not a history request')), \
             patch.object(d,'read_snapshot',side_effect=ValueError('current_probe_reached')):
            with self.assertRaisesRegex(ValueError,'current_probe_reached'):m.query({'target':'b:management'})

    def test_live_sqlite_history_preserves_integer_ages_at_subsecond_now(self):
        fixture=history_fixture.HistoryTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.publish([history_fixture.event(NOW-1)],since=NOW-2,until=NOW)
        local=history_fixture.h;clock=local.query_clock();value=history_fixture.query(since=NOW-2,until=NOW)
        result=local.answer(value,'c',clock)
        self.assertEqual(type(result['age_seconds']),int)
        self.assertEqual(result['returned_error_count'],1)
        self.assertEqual(local.validate_answer(result,value,'c',clock),result)
        self.assertNotIn('clock',result)

    def test_mcp_schema_and_resource_budgets_do_not_gain_a_clock_input(self):
        old=load('prior_mcp_clock',BASE/'infra/mcp/system-diagnostics-mcp.py');old._library=d
        self.assertEqual(m.tools(),old.tools())
        self.assertEqual((j.QUERY_TIMEOUT,j.COMMAND_TIMEOUT,j.LOCAL_RESPONSE_TIMEOUT,j.REMOTE_QUERY_TIMEOUT),(20,12,24,36))

if __name__=='__main__':unittest.main(verbosity=2)
