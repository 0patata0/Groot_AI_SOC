"""Release orchestration with fake services; never executes the operator CLI."""
from unittest.mock import Mock
import copy
import unittest

import release_runtime as runtime


class Flow(unittest.TestCase):
    def actor(self, fail=None, stopped=False):
        actor = Mock()
        actor.stop_started = stopped
        def quiesce(*, emergency):
            if fail == 'busy' and not emergency: raise ValueError('queue busy')
            actor.stop_started = True
        actor.quiesce.side_effect = quiesce
        actor.database_snapshot.return_value = {'private-db': 'unchanged'}
        if fail == 'startup':
            def ready(*, candidate):
                if candidate: raise ValueError('new version not loaded')
            actor.ready.side_effect = ready
        return actor

    def test_success_keeps_rollback_armed_until_verified_commit(self):
        actor = self.actor(); files = Mock()
        self.assertTrue(runtime.execute_apply(actor, files))
        actor.arm_rollback.assert_called_once(); actor.quiesce.assert_called_once_with(emergency=False)
        files.apply.assert_called_once(); files.restore.assert_not_called()
        actor.verify_database_snapshot.assert_called_once_with({'private-db': 'unchanged'})
        actor.ready.assert_called_once_with(candidate=True); actor.mark.assert_called_with('APPLIED')
        actor.disarm.assert_not_called()

    def test_preflight_or_old_source_drift_never_arms_or_stops(self):
        for failure in ('preflight', 'source'):
            actor = self.actor(); files = Mock()
            (actor.preflight if failure == 'preflight' else files.check).side_effect = ValueError('refused')
            with self.assertRaises(ValueError): runtime.execute_apply(actor, files)
            actor.arm_rollback.assert_not_called(); actor.quiesce.assert_not_called(); files.apply.assert_not_called()

    def test_busy_work_is_deferred_without_stopping_or_replacing_files(self):
        actor = self.actor('busy'); files = Mock()
        self.assertFalse(runtime.execute_apply(actor, files))
        actor.quiesce.assert_called_once_with(emergency=False)
        files.apply.assert_not_called(); files.restore.assert_not_called(); actor.resume.assert_not_called()
        actor.resume_timer.assert_called_once(); actor.disarm.assert_called_once()
        self.assertEqual(actor.mark.call_args.args[0], 'DEFERRED')

    def test_timer_failure_never_replaces_or_stops_and_is_reported_as_deferred(self):
        actor = self.actor(); actor.arm_rollback.side_effect = ValueError('timer failed'); files = Mock()
        self.assertFalse(runtime.execute_apply(actor, files))
        actor.quiesce.assert_not_called(); files.apply.assert_not_called()
        actor.resume_timer.assert_called_once(); actor.disarm.assert_called_once()

    def test_partial_replacement_failure_restores_and_verifies_old_sources(self):
        actor = self.actor(); files = Mock(); files.apply.side_effect = OSError('interrupted')
        self.assertFalse(runtime.execute_apply(actor, files))
        self.assertEqual(actor.quiesce.call_count, 2)
        self.assertEqual(actor.quiesce.call_args.kwargs, {'emergency': True})
        files.restore.assert_called_once(); actor.ready.assert_called_once_with(candidate=False)
        self.assertEqual(files.check.call_args.args, (('before_sha256',),))
        self.assertEqual(actor.mark.call_args.args[0], 'APPLY_FAILED_ROLLED_BACK')

    def test_new_version_not_loaded_triggers_old_source_recovery(self):
        actor = self.actor('startup'); files = Mock()
        self.assertFalse(runtime.execute_apply(actor, files))
        files.apply.assert_called_once(); files.restore.assert_called_once()
        self.assertEqual(actor.ready.call_args.kwargs, {'candidate': False})
        actor.disarm.assert_called_once()

    def test_changed_database_during_file_replacement_triggers_recovery(self):
        actor = self.actor(); actor.verify_database_snapshot.side_effect = ValueError('unexpected database change')
        files = Mock(); self.assertFalse(runtime.execute_apply(actor, files))
        files.restore.assert_called_once(); actor.mark.assert_called_with('APPLY_FAILED_ROLLED_BACK', error_type='ValueError')

    def test_failed_restore_cannot_be_marked_successful_or_disarmed(self):
        actor = self.actor('startup'); files = Mock(); files.restore.side_effect = ValueError('other update')
        with self.assertRaises(ValueError): runtime.execute_apply(actor, files)
        self.assertFalse(any(call.args and call.args[0] in ('APPLIED', 'APPLY_FAILED_ROLLED_BACK') for call in actor.mark.call_args_list))
        actor.disarm.assert_not_called()

    def test_committed_release_is_not_rolled_back_by_a_late_timer(self):
        actor = self.actor(); actor.phase.return_value = 'COMMITTED'; files = Mock()
        self.assertFalse(runtime.execute_rollback(actor, files))
        actor.preflight.assert_not_called(); actor.quiesce.assert_not_called(); files.restore.assert_not_called()

    def test_timer_restore_preserves_new_records_and_checks_old_code_before_done(self):
        actor = self.actor(); actor.phase.return_value = 'APPLIED'; files = Mock(); files.restore.return_value = 19
        self.assertTrue(runtime.execute_rollback(actor, files))
        actor.quiesce.assert_called_once_with(emergency=True)
        actor.verify_database_snapshot.assert_called_once_with({'private-db': 'unchanged'})
        files.check.assert_any_call(('before_sha256',))
        actor.mark.assert_called_once_with('ROLLED_BACK', restored_files=19); actor.disarm.assert_called_once()

    def test_other_update_prevents_all_timer_actions(self):
        actor = self.actor(); actor.phase.return_value = 'APPLIED'; files = Mock()
        files.check.side_effect = ValueError('changed by another operator')
        with self.assertRaises(ValueError): runtime.execute_rollback(actor, files)
        actor.quiesce.assert_not_called(); files.restore.assert_not_called(); actor.mark.assert_not_called()

    def test_unrendered_cli_cannot_load_a_root_plan(self):
        from unittest.mock import patch
        with patch.object(runtime.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'unbound_template'):
                runtime.Actor('a' * 64)


class Readiness(unittest.TestCase):
    def setUp(self):
        self.reports = {'review': {'pid': 10, 'process_start_ticks': 100, 'last_poll': 990},
            'ollama': {'pid': 11, 'process_start_ticks': 110, 'checked_at': 990,
                       'websocket_connected': True, 'worker_alive': True}}
        self.identities = {'review': {'pid': 10, 'ticks': 100}, 'ollama': {'pid': 11, 'ticks': 110}}

    def test_current_process_heartbeat_and_socket_are_required(self):
        runtime.validate_chat_health(self.reports, self.identities, 1000, 980)

    def test_stale_or_pid_reused_receipts_are_rejected_for_each_bot(self):
        for engine in ('review', 'ollama'):
            for key, value in (('pid', 9), ('pid', True), ('process_start_ticks', 99),
                               ('process_start_ticks', True)):
                data = copy.deepcopy(self.reports); data[engine][key] = value
                with self.subTest(engine=engine, key=key), self.assertRaises(ValueError):
                    runtime.validate_chat_health(data, self.identities, 1000, 980)

    def test_pre_restart_stale_future_and_invalid_heartbeats_are_rejected(self):
        for engine, key in (('review', 'last_poll'), ('ollama', 'checked_at')):
            for value in (970, 900, 1001, None, True):
                data = copy.deepcopy(self.reports); data[engine][key] = value
                with self.subTest(engine=engine, value=value), self.assertRaises(ValueError):
                    runtime.validate_chat_health(data, self.identities, 1000, 980)

    def test_disconnected_or_dead_ollama_worker_is_not_healthy(self):
        for key in ('websocket_connected', 'worker_alive'):
            data = copy.deepcopy(self.reports); data['ollama'][key] = False
            with self.assertRaises(ValueError): runtime.validate_chat_health(data, self.identities, 1000, 980)


if __name__ == '__main__':
    unittest.main()
