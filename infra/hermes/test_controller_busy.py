"""Timer overlap is deferred; genuine controller failures remain visible."""
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

import soc_management_controller as m


class ControllerBusyTests(unittest.TestCase):
    def invoke(self, store, prompt, argv=None, **patches):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(m, 'Store', return_value=store))
            stack.enter_context(mock.patch.object(m, 'PROMPT', prompt))
            stack.enter_context(mock.patch.dict(os.environ, {'RULE_BROKER_TOKEN': 'x' * 32}))
            stack.enter_context(mock.patch.object(sys, 'argv', argv or ['controller', '--once', '--no-deliver']))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            for name, replacement in patches.items():
                stack.enter_context(mock.patch.object(m, name, replacement))
            rc = m.main()
        return rc, out.getvalue(), err.getvalue()

    def test_actual_held_lock_defers_without_broker_model_delivery_or_cursor_change(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prompt = root / 'prompt'; prompt.write_text('test')
            owner, contender = m.Store(root), m.Store(root)
            before = '\n'.join(owner.db.iterdump())
            with owner.locked(), mock.patch.object(m.Broker, 'get', side_effect=AssertionError('broker contacted')):
                rc, out, err = self.invoke(contender, prompt)
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out), {'status': 'deferred', 'reason': 'controller_already_running'})
            self.assertEqual(err, '')
            self.assertEqual('\n'.join(owner.db.iterdump()), before)
            owner.close()

    def test_released_lock_allows_next_poll(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); owner = m.Store(root); contender = m.Store(root)
            with owner.locked():
                with self.assertRaises(m.ControllerBusy):
                    with contender.locked():
                        self.fail('duplicate owner')
            with contender.locked():
                contender.set_meta('event_cursor', 42)
                contender.db.commit()
            self.assertEqual(contender.meta('event_cursor'), '42')
            owner.close(); contender.close()

    def test_explicit_review_is_not_acknowledged_when_lock_is_busy(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); prompt = root / 'prompt'; prompt.write_text('test')
            owner, contender = m.Store(root), m.Store(root)
            with owner.locked():
                rc, out, err = self.invoke(contender, prompt,
                    argv=['controller', '--review-case', 'a' * 32, '--review-reason', 'test'])
            self.assertEqual(rc, 1); self.assertEqual(out, '')
            self.assertEqual(json.loads(err), {'status': 'failed', 'error': 'controller_already_running'})
            owner.close()

    def test_genuine_failures_and_same_text_without_busy_type_still_exit_one(self):
        for failure in (m.ControllerError('broker_signature_invalid'),
                        m.ControllerError('controller_already_running'),
                        OSError('disk unavailable'), sqlite3.OperationalError('database locked'),
                        ValueError('invalid configuration')):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as d:
                p = Path(d) / 'prompt'; p.write_text('test')
                store = m.Store(d)
                rc, out, err = self.invoke(store, p, once=mock.Mock(side_effect=failure))
                self.assertEqual(rc, 1); self.assertEqual(out, '')
                self.assertEqual(json.loads(err)['status'], 'failed')

    def test_lock_open_failure_is_not_busy(self):
        with tempfile.TemporaryDirectory() as d:
            store = m.Store(d)
            with mock.patch.object(m.os, 'open', side_effect=PermissionError('denied')):
                with self.assertRaises(PermissionError):
                    with store.locked():
                        self.fail('lock open unexpectedly succeeded')
            store.close()

    def test_non_contention_flock_failure_is_not_busy(self):
        with tempfile.TemporaryDirectory() as d:
            store = m.Store(d)
            with mock.patch.object(m.fcntl, 'flock', side_effect=OSError('unsupported')):
                with self.assertRaises(OSError) as raised:
                    with store.locked():
                        self.fail('lock unexpectedly succeeded')
                self.assertNotIsInstance(raised.exception, m.ControllerBusy)
            store.close()


if __name__ == '__main__':
    unittest.main()
