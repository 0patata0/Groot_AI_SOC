import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ssh_macs', Path(__file__).parents[1] / 'ssh_macs.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
GOOD = ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com']
OTHER = ['port 22', 'usepam yes', 'passwordauthentication yes']


class MacPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='capstone-ssh-macs-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / 'macs.conf'
        for name, value in [('TARGET', self.target), ('BACKUPS', self.root)]:
            p = patch.object(m, name, value)
            p.start(); self.addCleanup(p.stop)
        p = patch.object(m, 'trusted')
        self.trust = p.start(); self.addCleanup(p.stop)
        p = patch.object(m.os, 'fchown')
        p.start(); self.addCleanup(p.stop)

    def test_exact_previous_policy_migrates_and_can_restore_original(self):
        self.target.write_bytes(m.LEGACY_CONTENT)
        self.target.chmod(0o640)
        with patch.object(m, 'check', return_value=(GOOD + [m.EXCLUDED[-1]], GOOD, OTHER)), \
                patch.object(m, 'policy', return_value=(GOOD, OTHER)), patch.object(m, 'run'):
            result = m.install()
            self.assertEqual(self.target.read_bytes(), m.CONTENT)
            self.assertTrue((Path(result['backup']) / 'before.conf').is_file())
            m.rollback(result['backup'])
        self.assertEqual(self.target.read_bytes(), m.LEGACY_CONTENT)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)

    def test_failed_legacy_upgrade_restores_original_bytes(self):
        self.target.write_bytes(m.LEGACY_CONTENT)
        with patch.object(m, 'check', return_value=(GOOD, GOOD, OTHER)), \
                patch.object(m, 'policy', return_value=(GOOD, ['usepam no'])), patch.object(m, 'run'):
            with self.assertRaisesRegex(ValueError, 'include_order'):
                m.install()
        self.assertEqual(self.target.read_bytes(), m.LEGACY_CONTENT)

    def test_legacy_edit_between_snapshot_and_publication_is_preserved(self):
        self.target.write_bytes(m.LEGACY_CONTENT)
        replace = m.replace_exact
        def competing_replace(data, expected, **kwargs):
            self.target.write_text('operator change\n')
            return replace(data, expected, **kwargs)
        with patch.object(m, 'check', return_value=(GOOD, GOOD, OTHER)), \
                patch.object(m, 'replace_exact', side_effect=competing_replace):
            with self.assertRaisesRegex(RuntimeError, 'concurrent_edit'):
                m.install()
        self.assertEqual(self.target.read_text(), 'operator change\n')

    def test_refuses_unowned_file_without_touching_it(self):
        self.target.write_text('MACs hmac-sha2-256\n')
        with self.assertRaisesRegex(ValueError, 'unowned'), patch.object(m, 'run') as run:
            m.install()
        run.assert_not_called()
        self.assertEqual(self.target.read_text(), 'MACs hmac-sha2-256\n')

    def test_does_not_broaden_an_existing_stricter_policy(self):
        with patch.object(m, 'run'), patch.object(m, 'policy', side_effect=[(GOOD[:1], OTHER), (GOOD, OTHER)]):
            with self.assertRaisesRegex(ValueError, 'existing_policy_conflict'):
                m.check()
        self.assertFalse(self.target.exists())

    def test_include_order_override_fails_and_restores_absence(self):
        with patch.object(m, 'check', return_value=(GOOD + list(m.EXCLUDED), GOOD, OTHER)), \
                patch.object(m, 'policy', return_value=(GOOD + ['hmac-sha1'], OTHER)), \
                patch.object(m, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'include_order'):
                m.install()
        self.assertFalse(self.target.exists())
        run.assert_any_call(['/usr/sbin/sshd', '-t'])
        run.assert_any_call(['systemctl', 'reload', 'ssh.service'])

    def test_unrelated_authentication_change_rolls_back(self):
        with patch.object(m, 'check', return_value=(GOOD, GOOD, OTHER)), \
                patch.object(m, 'policy', return_value=(GOOD, ['passwordauthentication no'])), \
                patch.object(m, 'run'):
            with self.assertRaisesRegex(ValueError, 'include_order'):
                m.install()
        self.assertFalse(self.target.exists())

    def test_reload_failure_rolls_back_then_reloads_original(self):
        calls = []
        def run(argv):
            calls.append(argv)
            if argv == ['systemctl', 'reload', 'ssh.service'] and self.target.exists():
                raise RuntimeError('reload_failure')
            return ''
        with patch.object(m, 'check', return_value=(GOOD, GOOD, OTHER)), \
                patch.object(m, 'policy', return_value=(GOOD, OTHER)), \
                patch.object(m, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'reload_failure'):
                m.install()
        self.assertFalse(self.target.exists())
        self.assertEqual(calls.count(['systemctl', 'reload', 'ssh.service']), 2)

    def test_success_is_idempotent_and_requires_a_fresh_connection(self):
        with patch.object(m, 'check', return_value=(GOOD + list(m.EXCLUDED), GOOD, OTHER)), \
                patch.object(m, 'policy', return_value=(GOOD, OTHER)), patch.object(m, 'run') as run:
            result = m.install()
            second = m.install()
        self.assertTrue(result['changed'])
        self.assertTrue(result['fresh_connection_required'])
        self.assertFalse(second['changed'])
        self.assertEqual(self.target.read_bytes(), m.CONTENT)
        self.assertEqual(run.call_args_list.count(unittest.mock.call(['systemctl', 'reload', 'ssh.service'])), 1)
        self.assertTrue((Path(result['backup']) / 'before.json').exists())

    def test_concurrent_destination_is_not_overwritten(self):
        link = m.os.link
        def competing_link(src, dest):
            self.target.write_text('operator file\n')
            return link(src, dest)
        with patch.object(m, 'check', return_value=(GOOD, GOOD, OTHER)), \
                patch.object(m.os, 'link', side_effect=competing_link):
            with self.assertRaises(FileExistsError):
                m.install()
        self.assertEqual(self.target.read_text(), 'operator file\n')

    def test_verification_rejects_effective_override(self):
        self.target.write_bytes(m.CONTENT)
        with patch.object(m, 'run'), patch.object(m, 'policy', side_effect=[(GOOD+['hmac-sha1'], OTHER), (GOOD, OTHER)]):
            with self.assertRaisesRegex(ValueError, 'effective_policy_mismatch'):
                m.verify()

    def test_regular_file_ownership_guard_rejects_symlink(self):
        p = self.root / 'link'
        p.symlink_to('/etc/passwd')
        # Load the original function separately; no privileged filesystem writes.
        clean = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(clean)
        with self.assertRaisesRegex(ValueError, 'untrusted_path'):
            clean.trusted(p)

    def test_all_fresh_roles_use_common_policy_and_pin_source(self):
        root = Path(__file__).parents[1]
        for role in ('security', 'siem', 'service'):
            shell = (root / ('roles/' + role + '.sh')).read_text()
            self.assertIn('deployment/ssh_macs.py', shell)
            for action in ('check', 'install', 'verify'):
                self.assertTrue(('ssh_macs ' + action) in shell or
                                ("ssh_macs.py'),'" + action + "'") in shell or
                                ('ssh_macs.py" ' + action) in shell)
            subprocess.run(['bash', '-n', str(root / ('roles/' + role + '.sh'))], check=True)


if __name__ == '__main__':
    unittest.main()
