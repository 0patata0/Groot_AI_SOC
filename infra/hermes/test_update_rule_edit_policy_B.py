import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('policy_patch', Path(__file__).with_name('update_rule_edit_policy_B.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class PolicyPatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / 'data'
        self.data.mkdir()
        (self.data / 'cron').mkdir()
        (self.data / 'sessions').mkdir()
        self.backup = self.root / 'backups'
        self.backup.mkdir(mode=0o700)
        self.old = m.START + '\nold policy\n' + m.END
        self.new = m.START + '\nnew policy propose_rule_edit\n' + m.END
        self.source = self.root / 'source.md'
        self.source.write_text('source prefix\n' + self.new + '\nsource suffix')
        (self.data / 'SOUL.md').write_text('persona\n' + self.old + '\nother policy')
        jobs = {'jobs': [{'name': 'soc-alert-watch', 'id': 'preserved', 'enabled': True,
                         'prompt': 'Check. ' + m.OLD_CRON + ' propose_service_action. End.'}],
                'updated_at': 'unchanged'}
        (self.data / 'cron/jobs.json').write_text(json.dumps(jobs, indent=2))
        mirror = {'meta': 'version1', 'channel-a': {'session_id': 's1', 'platform': 'mattermost'}}
        (self.data / 'sessions/sessions.json').write_text(json.dumps(mirror))
        db = sqlite3.connect(self.data / 'state.db')
        db.executescript('''
          CREATE TABLE sessions(id TEXT PRIMARY KEY,system_prompt_hash TEXT,system_prompt TEXT,history TEXT);
          CREATE TABLE system_prompts(hash TEXT PRIMARY KEY,prompt TEXT NOT NULL);
          CREATE TABLE gateway_routing(scope TEXT,session_key TEXT,entry_json TEXT,updated_at REAL);
          CREATE TABLE session_turn_leases(conversation_id TEXT PRIMARY KEY,holder TEXT,acquired_at REAL,expires_at REAL);
          CREATE TABLE messages(id INTEGER PRIMARY KEY,message TEXT);
        ''')
        prompt = 'history prompt prefix\n' + self.old + '\nhistory prompt suffix'
        self.old_hash = m.sha(prompt.encode())
        db.execute('INSERT INTO system_prompts VALUES(?,?)', (self.old_hash, prompt))
        db.execute('INSERT INTO sessions VALUES(?,?,NULL,?)', ('s1', self.old_hash, 'unchanged'))
        db.execute('INSERT INTO gateway_routing VALUES(?,?,?,?)',
                   ('/opt/data/sessions', 'channel-a', json.dumps(mirror['channel-a']), 17.0))
        db.execute('INSERT INTO messages VALUES(1,?)', ('tool history and conversation',))
        db.commit()
        db.close()

    def update(self, **kwargs):
        return m.update(self.data, self.source, self.backup,
                        stopped_check=lambda: ('same', 'stopped', 'unchanged'), **kwargs)

    def logical_db(self):
        with sqlite3.connect(self.data / 'state.db') as db:
            return list(db.iterdump())

    def test_preserves_history_and_null_inline_and_old_blob(self):
        old_jobs = (self.data / 'cron/jobs.json').read_bytes()
        old_mirror = (self.data / 'sessions/sessions.json').read_bytes()
        result = self.update()
        self.assertEqual(result['sessions'], 1)
        self.assertTrue(result['unrelated_tables_unchanged'])
        self.assertEqual((self.data / 'SOUL.md').read_text(), 'persona\n' + self.new + '\nother policy')
        self.assertEqual((self.data / 'cron/jobs.json').read_bytes(), old_jobs.replace(m.OLD_CRON.encode(), m.NEW_CRON.encode()))
        self.assertEqual((self.data / 'sessions/sessions.json').read_bytes(), old_mirror)
        with sqlite3.connect(self.data / 'state.db') as db:
            row = db.execute('SELECT system_prompt_hash,system_prompt,history FROM sessions').fetchone()
            self.assertNotEqual(row[0], self.old_hash)
            self.assertEqual(row[1:], (None, 'unchanged'))
            self.assertEqual(db.execute('SELECT count(*) FROM system_prompts').fetchone(), (2,))
            self.assertEqual(db.execute('SELECT message FROM messages').fetchone(), ('tool history and conversation',))
        self.assertEqual(Path(result['backup_dir']).stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in Path(result['backup_dir']).iterdir()))
        # Reapplying the same policy is harmless and does not add more blobs.
        self.update()
        with sqlite3.connect(self.data / 'state.db') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM system_prompts').fetchone(), (2,))

    def test_dry_run_does_not_patch_or_create_backup(self):
        before = self.logical_db()
        soul = (self.data / 'SOUL.md').read_bytes()
        self.assertTrue(self.update(dry_run=True)['dry_run'])
        self.assertEqual(self.logical_db(), before)
        self.assertEqual((self.data / 'SOUL.md').read_bytes(), soul)
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_live_lease_refuses_every_change(self):
        with sqlite3.connect(self.data / 'state.db') as db:
            db.execute('INSERT INTO session_turn_leases VALUES(?,?,?,?)', ('s1', 'agent', 1, 1e20))
        before = self.logical_db()
        with self.assertRaisesRegex(RuntimeError, 'active session lease'):
            self.update()
        self.assertEqual(self.logical_db(), before)
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_mirror_mismatch_refuses_every_change(self):
        (self.data / 'sessions/sessions.json').write_text(json.dumps({'x': {'platform': 'mattermost', 'session_id': 'other'}}))
        with self.assertRaisesRegex(RuntimeError, 'routing and mirror'):
            self.update()
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_file_failure_rolls_back_database_and_prior_file(self):
        before = self.logical_db()
        original = {p: p.read_bytes() for p in (self.data / 'SOUL.md', self.data / 'cron/jobs.json')}
        real_atomic = m.atomic
        calls = 0

        def fail_second(path, data, metadata):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected write failure')
            return real_atomic(path, data, metadata)

        with patch.object(m, 'atomic', side_effect=fail_second):
            with self.assertRaisesRegex(OSError, 'injected'):
                self.update()
        self.assertEqual(self.logical_db(), before)
        self.assertTrue(all(path.read_bytes() == raw for path, raw in original.items()))

    def test_unrelated_trigger_write_aborts(self):
        with sqlite3.connect(self.data / 'state.db') as db:
            db.execute("CREATE TRIGGER forbidden AFTER UPDATE ON sessions BEGIN UPDATE messages SET message='changed'; END")
        before = self.logical_db()
        with self.assertRaisesRegex(RuntimeError, 'unrelated database'):
            self.update()
        self.assertEqual(self.logical_db(), before)

    def test_management_replaces_both_blocks_and_disables_old_cron(self):
        start, end = '<!-- bounded-operations-policy:start -->', '<!-- bounded-operations-policy:end -->'
        old, new = start+'\nold bounded\n'+end, start+'\nLLM decides\n'+end
        self.source.write_text(self.source.read_text() + '\n' + new)
        soul = self.data / 'SOUL.md'
        soul.write_text(soul.read_text() + '\n' + old)
        with sqlite3.connect(self.data / 'state.db') as db:
            prompt = db.execute('SELECT prompt FROM system_prompts').fetchone()[0] + '\n' + old
            digest = m.sha(prompt.encode())
            db.execute('INSERT INTO system_prompts VALUES(?,?)', (digest, prompt))
            db.execute('UPDATE sessions SET system_prompt_hash=?', (digest,))
        prompt_file = self.root / 'prompt'
        prompt_file.write_text('LLM management policy. ' * 10)
        result = self.update(management_prompt=prompt_file)
        self.assertTrue(result['unrelated_tables_unchanged'])
        self.assertIn(new, soul.read_text())
        jobs = json.loads((self.data / 'cron/jobs.json').read_text())['jobs']
        self.assertFalse(jobs[0]['enabled'])
        self.assertEqual(jobs[0]['id'], 'preserved')
        self.assertEqual(jobs[0]['prompt'], prompt_file.read_text())
        with sqlite3.connect(self.data / 'state.db') as db:
            current = db.execute('SELECT p.prompt FROM sessions s JOIN system_prompts p ON p.hash=s.system_prompt_hash').fetchone()[0]
            self.assertIn(new, current)
            self.assertNotIn(old, current)


if __name__ == '__main__':
    unittest.main()
