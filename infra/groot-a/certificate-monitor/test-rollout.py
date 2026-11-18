#!/usr/bin/env python3
"""Root/Linux filesystem regressions with simulated service control only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).with_name('rollout.py')


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root required')
class ExactRepair(unittest.TestCase):
    def setUp(self):
        self.owned = Path(tempfile.mkdtemp(prefix='capstone-cert-transaction-test-', dir='/var/lib'))
        self.owned.chmod(0o700)
        self.addCleanup(shutil.rmtree, self.owned)
        spec = importlib.util.spec_from_file_location('cert_change_under_test', SOURCE)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.m.BASE = self.owned / 'changes'
        self.source = self.owned / 'source'
        self.source.mkdir(mode=0o700)
        self.targets = {}
        for name, mode in [('monitor.sh', 0o500), ('capstone-cert-monitor.service', 0o644)]:
            target = self.owned / ('live-' + name)
            old, new = ('old:' + name + '\n').encode(), ('new:' + name + '\n').encode()
            target.write_bytes(old)
            target.chmod(mode)
            candidate = self.source / name
            candidate.write_bytes(new)
            candidate.chmod(0o600)
            self.targets[name] = (target, mode, self.m.digest(old), self.m.digest(new))
        self.m.TARGETS = self.targets
        self.protected = self.owned / 'protected-cert'
        self.protected.write_bytes(b'unchanged-public-certificate\n')
        self.protected.chmod(0o644)
        self.m.PROTECTED = {str(self.protected): self.m.digest(self.protected.read_bytes())}
        self.m.STATUS = self.owned / 'status.json'
        self.calls = []
        self.m.command = self.command
        self.event = {'domain': 'chat.grootlab.duckdns.org', 'probe_status': 'verified', 'reason': 'verified',
                      'certificate_sha256': 'a' * 64, 'served_certificate_sha256': 'a' * 64,
                      'automatic_renewal': False,
                      'observed_at_kst': self.m.datetime.now(self.m.timezone(self.m.timedelta(hours=9))).isoformat()}
        self.m.STATUS.write_text(json.dumps(self.event))
        self.m.STATUS.chmod(0o600)

    def command(self, args, **kwargs):
        self.calls.append(args)
        if args[:3] == ['systemctl', 'show', self.m.SERVICE]:
            if '--property=ActiveState' in args:
                return b'ActiveState=inactive\n'
            return b'Result=success\nExecMainStatus=0\n'
        return b''

    def prepare(self):
        result = self.m.prepare(self.source)
        return Path(result['stage']), result['plan_sha256']

    def phases(self, stage):
        return json.loads((stage / 'state.json').read_text())['phase']

    def assert_originals(self):
        for _, (path, mode, old, _) in self.targets.items():
            self.assertEqual(self.m.digest(self.m.read(path, mode)), old)

    def apply(self):
        stage, plan = self.prepare()
        self.m.mutate(stage, 'apply', plan)
        return stage, plan

    def test_prepare_copies_exact_backups_without_service_command(self):
        stage, plan = self.prepare()
        self.assertEqual(self.phases(stage), 'prepared')
        self.assertEqual(self.m.digest((stage / 'plan.json').read_bytes()), plan)
        self.assertEqual(self.calls, [])
        self.assert_originals()

    def test_wrong_plan_cannot_arm_or_write(self):
        stage, _ = self.prepare()
        with self.assertRaisesRegex(ValueError, 'exact_approval_required'):
            self.m.mutate(stage, 'apply', '0' * 64)
        self.assertEqual(self.calls, [])
        self.assert_originals()

    def test_changed_source_refuses_before_arming(self):
        stage, plan = self.prepare()
        next(iter(self.targets.values()))[0].write_bytes(b'later-edit\n')
        with self.assertRaisesRegex(ValueError, 'operating_source_changed'):
            self.m.mutate(stage, 'apply', plan)
        self.assertEqual(self.calls, [])

    def test_protected_certificate_change_refuses(self):
        stage, plan = self.prepare()
        self.protected.write_bytes(b'later-certificate\n')
        with self.assertRaisesRegex(ValueError, 'protected_file_changed'):
            self.m.mutate(stage, 'apply', plan)
        self.assert_originals()

    def test_failed_timer_creation_leaves_originals(self):
        stage, plan = self.prepare()
        def fail(args, **kwargs):
            if args[0] == 'systemd-run':
                raise ValueError('timer_failed')
            return self.command(args, **kwargs)
        self.m.command = fail
        with self.assertRaisesRegex(ValueError, 'timer_failed'):
            self.m.mutate(stage, 'apply', plan)
        self.assert_originals()
        self.assertEqual(self.phases(stage), 'prepared')

    def test_no_file_write_before_timer_active_and_armed_receipt(self):
        stage, plan = self.prepare()
        original = self.m.write
        def observed(path, raw, mode):
            if path in [value[0] for value in self.targets.values()]:
                self.assertEqual(self.phases(stage), 'armed')
                self.assertTrue(any(args[:2] == ['systemctl', 'is-active'] for args in self.calls))
            return original(path, raw, mode)
        self.m.write = observed
        self.m.mutate(stage, 'apply', plan)
        self.assertEqual(self.phases(stage), 'applied')

    def test_partial_apply_restores_both_originals(self):
        stage, plan = self.prepare()
        original = self.m.write
        second = list(self.targets.values())[1][0]
        def fail_second(path, raw, mode):
            if path == second:
                raise ValueError('simulated_replace_failure')
            return original(path, raw, mode)
        self.m.write = fail_second
        with self.assertRaisesRegex(ValueError, 'simulated_replace_failure'):
            self.m.mutate(stage, 'apply', plan)
        self.m.write = original
        self.assertEqual(self.phases(stage), 'armed')
        self.m.mutate(stage, 'rollback')
        self.assert_originals()
        self.assertEqual(self.phases(stage), 'rolled_back')

    def test_rollback_conflict_checks_all_targets_before_any_restore(self):
        stage, _ = self.apply()
        first, second = [value[0] for value in self.targets.values()]
        first_before = first.read_bytes()
        second.write_bytes(b'foreign-edit\n')
        with self.assertRaisesRegex(ValueError, 'rollback_conflicting_edit'):
            self.m.mutate(stage, 'rollback')
        self.assertEqual(first.read_bytes(), first_before)
        self.assertEqual(second.read_bytes(), b'foreign-edit\n')

    def test_symlink_target_refuses_without_restore(self):
        stage, _ = self.apply()
        first, second = [value[0] for value in self.targets.values()]
        first_before = first.read_bytes()
        second.unlink()
        second.symlink_to(self.protected)
        with self.assertRaisesRegex(ValueError, 'untrusted_file'):
            self.m.mutate(stage, 'rollback')
        self.assertEqual(first.read_bytes(), first_before)
        self.assertEqual(self.protected.read_bytes(), b'unchanged-public-certificate\n')

    def test_changed_controller_refuses(self):
        stage, plan = self.prepare()
        (stage / 'rollout.py').write_bytes(b'not-approved-controller\n')
        with self.assertRaisesRegex(ValueError, 'controller_changed'):
            self.m.mutate(stage, 'apply', plan)
        self.assert_originals()

    def test_old_status_cannot_confirm(self):
        stage, _ = self.apply()
        self.event['observed_at_kst'] = '2000-01-01T00:00:00+09:00'
        self.m.STATUS.write_text(json.dumps(self.event))
        with self.assertRaisesRegex(ValueError, 'observer_status_stale'):
            self.m.mutate(stage, 'confirm')
        self.assertEqual(self.phases(stage), 'applied')

    def test_expired_confirmation_cannot_cancel_rollback(self):
        stage, _ = self.apply()
        state = json.loads((stage / 'state.json').read_text())
        state['armed_epoch'] = time.time() - 301
        self.m.state_write(stage, state)
        self.calls.clear()
        with self.assertRaisesRegex(ValueError, 'confirmation_deadline_expired'):
            self.m.mutate(stage, 'confirm')
        self.assertEqual(self.calls, [])

    def test_confirmation_commits_under_lock_before_timer_cancel(self):
        stage, _ = self.apply()
        def observed(args, **kwargs):
            if args[:2] == ['systemctl', 'stop']:
                self.assertEqual(self.phases(stage), 'confirmed')
            return self.command(args, **kwargs)
        self.m.command = observed
        self.m.mutate(stage, 'confirm')
        self.assertEqual(self.phases(stage), 'confirmed')
        self.calls.clear()
        self.assertFalse(self.m.mutate(stage, 'rollback')['changed'])
        self.assertEqual(self.calls, [])

    def test_rollback_waits_for_lock_instead_of_losing_recovery(self):
        stage, _ = self.apply()
        original = self.m.lock
        with patch.object(self.m, 'lock', wraps=original) as observed:
            self.m.mutate(stage, 'rollback')
        observed.assert_called_once_with(block=True)
        self.assert_originals()


if __name__ == '__main__':
    unittest.main(verbosity=2)
