"""Meaningful boundaries for the read-only deployment checks; stdlib only."""
import datetime
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import hermes_guard_checks as checks


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'cron').mkdir()
        for name in ('config.yaml', '.env', 'SOUL.md', 'cron/jobs.json'):
            (self.root / name).write_text('private-value-never-printed')
        with sqlite3.connect(self.root / 'state.db') as db:
            db.execute('CREATE TABLE session_turn_leases(expires_at REAL)')
        self.now = 1700000000
        self.state = {'gateway_state': 'running', 'active_agents': 0, 'active_work': [],
                      'updated_at': datetime.datetime.fromtimestamp(self.now, datetime.timezone.utc).isoformat()}
        self.write_state()

    def write_state(self):
        (self.root / 'gateway_state.json').write_text(json.dumps(self.state))

    def test_idle_does_not_change_database_and_returns_no_content(self):
        before = (self.root / 'state.db').read_bytes()
        result = checks.idle(self.root, self.now)
        self.assertEqual(result, {'idle': True, 'active_leases': 0, 'heartbeat_age_seconds': 0.0})
        self.assertEqual((self.root / 'state.db').read_bytes(), before)

    def test_fresh_running_state_cannot_bypass_live_lease(self):
        with sqlite3.connect(self.root / 'state.db') as db:
            db.execute('INSERT INTO session_turn_leases VALUES (?)', (self.now + 1,))
        with self.assertRaisesRegex(ValueError, 'active_turn_lease'):
            checks.idle(self.root, self.now)

    def test_stale_future_and_naive_heartbeat_fail_closed(self):
        for stamp in (self.now - 45, self.now + 6, '2023-11-14T22:13:20'):
            with self.subTest(stamp=stamp):
                self.state['updated_at'] = stamp
                self.write_state()
                with self.assertRaises(ValueError):
                    checks.idle(self.root, self.now)

    def test_snapshot_detects_bytes_permissions_and_optional_journal(self):
        before = checks.snapshot(self.root)
        self.assertEqual(before['state.db-wal'], {'exists': False})
        self.assertNotIn('private-value', json.dumps(before))
        (self.root / 'config.yaml').write_text('changed')
        self.assertNotEqual(checks.snapshot(self.root), before)
        self.assertTrue(all('sha256' in v for v in before.values() if v['exists']))

    def test_symlink_refused_even_if_it_points_to_an_expected_regular_file(self):
        (self.root / '.env').unlink()
        (self.root / '.env').symlink_to(self.root / 'config.yaml')
        with self.assertRaisesRegex(ValueError, 'nonregular_file'):
            checks.snapshot(self.root)


if __name__ == '__main__':
    unittest.main()
