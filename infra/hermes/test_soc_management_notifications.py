"""Durable report delivery tests. No chat server or model is contacted."""
import json
import tempfile
import unittest
from unittest import mock
import soc_management_controller as m


class Notifications(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1000.0
        self.store = m.Store(self.tmp.name, clock=lambda: self.now)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def start(self, key='incident'):
        with self.store.db:
            cid = self.store.new_case(key)
        case = self.store.db.execute('SELECT * FROM cases WHERE id=?', (cid,)).fetchone()
        trace = m.Trace(self.store, case, self.store.start(case))
        trace.accept({'type':'system','subtype':'init','session_id':case['session_id'] or 'actual-session-123'})
        return trace

    def finish(self, trace, text='관측 표본입니다.\nMANAGEMENT_STATUS: resolved'):
        trace.accept({'type':'tool_use','name':'mcp__resp__list_blocks','input':{}})
        trace.accept({'type':'tool_result','name':'mcp__resp__list_blocks',
                      'output':json.dumps({'blocks':[]})})
        trace.accept({'type':'result','session_id':trace.session_id,'exit_code':0,'text':text})
        return trace.finish(0)

    def report(self):
        return self.store.db.execute('SELECT * FROM report_outbox ORDER BY created,rowid LIMIT 1').fetchone()

    def test_failed_delivery_survives_reopen_and_only_retries_notification(self):
        trace=self.start();self.finish(trace)
        calls=self.store.db.execute('SELECT * FROM tool_calls').fetchall()
        sender=mock.Mock(side_effect=m.ControllerError('report_delivery_failed'))
        self.assertEqual(self.store.flush_report(sender),{'attempted':1,'delivered':False})
        self.assertEqual(self.report()['due'],1060)
        self.assertEqual(self.store.flush_report(sender),{'attempted':0})
        self.store.close();self.store=m.Store(self.tmp.name,clock=lambda:self.now)
        self.now=1060;sender=mock.Mock(return_value=True)
        self.assertEqual(self.store.flush_report(sender),{'attempted':1,'delivered':True})
        self.assertEqual(sender.call_args.kwargs['report_id'],trace.run_id)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM runs').fetchone()[0],1)
        self.assertEqual([tuple(r) for r in self.store.db.execute('SELECT * FROM tool_calls')],[tuple(r) for r in calls])
        self.assertEqual(self.store.flush_report(sender),{'attempted':0})

    def test_backoff_is_capped_and_error_does_not_copy_private_details(self):
        trace=self.start();self.finish(trace)
        for _ in range(10):
            self.now=max(self.now,self.report()['due'])
            self.store.flush_report(mock.Mock(side_effect=m.ControllerError('private webhook token')))
            self.assertLessEqual(self.report()['due']-self.now,3600)
        self.assertEqual(self.report()['last_error'],'report_delivery_failed')
        self.assertNotIn('private webhook',repr(dict(self.report())))

    def test_failure_without_model_text_is_reported_without_resolving_or_rerunning(self):
        trace=self.start();result=trace.finish(124,'model_outer_timeout')
        self.assertFalse(result['completed']);self.assertEqual(result['state'],'outcome_unknown')
        self.assertEqual(result['text'],'')
        row=self.report();self.assertEqual(row['state'],'outcome_unknown')
        self.assertIn('model_outer_timeout',row['text'])
        self.store.flush_report(mock.Mock(return_value=True))
        self.assertEqual(self.store.db.execute('SELECT state FROM cases').fetchone()[0],'outcome_unknown')

    def test_recovery_queues_interruption_once_and_never_backfills_old_cases(self):
        trace=self.start();self.store.recover();self.store.recover()
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM report_outbox').fetchone()[0],1)
        self.assertIn('interrupted_run_requires_review',self.report()['text'])
        with self.store.db:self.store.db.execute('DELETE FROM report_outbox')
        self.store.close();self.store=m.Store(self.tmp.name,clock=lambda:self.now)
        self.store.recover();self.assertIsNone(self.report())

    def test_old_report_cannot_mark_a_newer_run_delivered(self):
        trace=self.start();self.finish(trace);self.now+=1
        newer=self.start();self.finish(newer)
        self.store.flush_report(mock.Mock(return_value=True))
        self.assertEqual(self.store.db.execute('SELECT delivered FROM cases').fetchone()[0],0)
        self.store.flush_report(mock.Mock(return_value=True))
        self.assertEqual(self.store.db.execute('SELECT delivered FROM cases').fetchone()[0],1)

    def test_no_deliver_does_not_send_or_leave_a_later_notification(self):
        self.start('old');self.store.recover()
        old_count=self.store.db.execute('SELECT count(*) FROM report_outbox').fetchone()[0]
        with self.store.reporting(False):
            trace=self.start('new');self.finish(trace)
            sender=mock.Mock();self.assertEqual(self.store.flush_report(sender),{'attempted':0})
            sender.assert_not_called()
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM report_outbox').fetchone()[0],old_count)

    def test_silent_completion_is_acknowledged_but_review_still_notifies(self):
        trace=self.start();self.finish(trace,'[SILENT]\nMANAGEMENT_STATUS: resolved')
        self.store.flush_report(mock.Mock(return_value=False))
        self.assertEqual(self.report()['delivery_state'],'suppressed')

    def test_unknown_failure_details_are_not_sent_to_users(self):
        trace=self.start();trace.finish(1,'private details')
        self.assertNotIn('private details',self.report()['text'])
        self.assertIn('diagnostic_run_incomplete',self.report()['text'])

    def test_one_attempt_per_tick_and_notification_retry_precedes_broker_failure(self):
        trace=self.start();self.finish(trace)
        broker=mock.Mock();broker.get.side_effect=m.ControllerError('broker_unavailable')
        with mock.patch.object(m,'deliver',return_value=True) as sender:
            with self.assertRaises(m.ControllerError):m.once(self.store,broker,'policy')
        sender.assert_called_once()
        self.assertEqual(self.report()['delivery_state'],'sent')

    def test_existing_and_new_reports_share_one_delivery_budget_without_rerunning_model(self):
        old=self.start('old');self.finish(old)
        with self.store.db:self.store.new_case('fresh')
        broker=mock.Mock()
        broker.get.side_effect=lambda path: ({'events':[],'latest_seq':0} if path.startswith('/management/events')
            else {'alerts':[],'total':0,'total_relation':'eq','truncated':False})
        def run(store,case,prompt):
            trace=m.Trace(store,case,store.start(case))
            trace.accept({'type':'system','subtype':'init','session_id':'actual-session-123'})
            return self.finish(trace)
        runner=mock.Mock(side_effect=run)
        with mock.patch.object(m,'deliver',return_value=True) as sender:
            first=m.once(self.store,broker,'policy',runner=runner)
            self.assertEqual(first['pending_reports'],1)
            self.assertEqual(sender.call_count,1)
            second=m.once(self.store,broker,'policy',runner=runner)
            self.assertEqual(second['pending_reports'],0)
            self.assertEqual(sender.call_count,2)
        self.assertEqual(runner.call_count,1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM runs').fetchone()[0],2)

    def test_duplicate_or_nonterminal_status_never_completes_a_case(self):
        for number,text in enumerate(('MANAGEMENT_STATUS: resolved\nMANAGEMENT_STATUS: monitor',
                'MANAGEMENT_STATUS: resolved\n후속 본문','MANAGEMENT_STATUS: bogus\nMANAGEMENT_STATUS: resolved')):
            trace=self.start(str(number));result=self.finish(trace,text)
            self.assertEqual(result['state'],'needs_review')


if __name__=='__main__':unittest.main()
