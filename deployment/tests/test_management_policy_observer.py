"""Read-only collection must not turn missing/opaque sources into success."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('management_fixed_observer_test', Path(__file__).parents[1] / 'management_policy_observer.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ObserverTests(unittest.TestCase):
    def test_lab_opaque_secrets_never_returned(self):
        selected = m.selected('lab_environment', b'SECRET_VALUE=hidden-opaque-string\nOFFLINE_LABS_ADMIN_CIDRS=192.0.2.1/32\n')
        self.assertNotIn('hidden-opaque-string', json.dumps(selected))
        self.assertEqual(selected['administrator_cidrs'], ['192.0.2.1/32'])

    def test_absent_lab_setting_is_unknown_not_default_loaded(self):
        row = m.selected('lab_environment', b'TOKEN_FILE=/root/key\n')
        self.assertIsNone(row['administrator_cidrs'])
        self.assertEqual(row['default_or_running_value'], 'not_verified')

    def test_unrecognized_wazuh_value_is_hash_only(self):
        result = m.selected('wazuh', b'<ossec_config><global><white_list>opaque-hidden-value</white_list><white_list>^localhost$</white_list></global></ossec_config>')
        self.assertNotIn('opaque-hidden-value', json.dumps(result))
        self.assertEqual(result['white_list'][0], {'unrecognized_value_sha256': m.sha(b'opaque-hidden-value')})

    def test_bad_host_guard_and_unknown_source_refused(self):
        for kind, raw in [('host_guard', b'[]'), ('host_guard', b'{"role":"other"}'), ('arbitrary', b'anything')]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                m.selected(kind, raw)

    def test_fixed_sources_failure_stays_unavailable_without_runtime_or_preparation_claim(self):
        with patch.object(m, 'read_fixed', side_effect=FileNotFoundError), patch.object(m.pwd, 'getpwnam', side_effect=KeyError):
            result = m.observe('c')
        self.assertTrue(all(r['status'] == 'unavailable' for r in result['sources']))
        self.assertFalse(result['runtime_verified'])
        self.assertFalse(result['prepared_or_approved'])
        self.assertEqual(result['operating_changes'], 0)
        self.assertEqual(result['existing_mcp_ssh_accounts'], [])

    def test_role_is_only_fixed_selector(self):
        for host in ('d', '/etc/shadow', 'a;id', None):
            with self.subTest(host=host), self.assertRaises(ValueError):
                m.observe(host)

    def test_symlink_parent_file_and_hardlink_refused(self):
        base = Path('/private/tmp') if Path('/private/tmp').exists() else Path('/tmp')
        with tempfile.TemporaryDirectory(prefix='management-read-', dir=base) as name:
            root = Path(name)
            source = root / 'source'
            source.write_bytes(b'original')
            linked = root / 'link'
            linked.symlink_to(source)
            with self.assertRaises(ValueError):
                m.read_fixed(linked)
            parent = root / 'parent'
            parent.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                m.read_fixed(parent / 'source')
            hard = root / 'hard'
            os.link(source, hard)
            with self.assertRaises(ValueError):
                m.read_fixed(source)

    def test_source_content_is_pinned_and_untrusted_parent_never_certified(self):
        base = Path('/private/tmp') if Path('/private/tmp').exists() else Path('/tmp')
        with tempfile.TemporaryDirectory(prefix='management-read-', dir=base) as name:
            source = Path(name) / 'source'
            source.write_bytes(b'configuration')
            source.chmod(0o600)
            raw, info = m.read_fixed(source)
            self.assertEqual(raw, b'configuration')
            self.assertEqual(info['sha256'], m.sha(raw))
            # /tmp itself is writable; this is an observation, never a grant.
            self.assertFalse(info['trusted_ancestry'])

    def test_wazuh_container_restart_race_refused_and_no_env_inspection(self):
        identity = {'id': 'a' * 64, 'image': 'b' * 64, 'started_at': 'fixed'}
        changed = {**identity, 'id': 'c' * 64}
        original = b'<ossec_config><global><white_list>127.0.0.1</white_list></global></ossec_config>'
        with patch.object(m, 'command', side_effect=[b'wazuh-manager\n', json.dumps(identity).encode(), original, json.dumps(changed).encode()]) as command:
            with self.assertRaisesRegex(ValueError, 'container_changed'):
                m.wazuh_observation()
        self.assertNotIn('.Env', str(command.call_args_list))
        self.assertIn('/var/ossec/etc/ossec.conf', str(command.call_args_list))

    def test_multiple_running_managers_not_guessed(self):
        with patch.object(m, 'command', return_value=b'wazuh-manager\nwazuh-manager-second\n'):
            with self.assertRaisesRegex(ValueError, 'unique_running'):
                m.wazuh_observation()

    def test_docker_uses_fixed_installed_path_and_local_socket_without_ambient_env(self):
        with patch.object(m.shutil, 'which', return_value='/usr/local/bin/docker'), \
                patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'fixed')) as run:
            self.assertEqual(m.command(['docker', 'ps', '--format', '{{.Names}}']), b'fixed')
        self.assertEqual(run.call_args.args[0][:3], ['/usr/local/bin/docker', '--host', 'unix:///var/run/docker.sock'])
        self.assertNotIn('DOCKER_HOST', run.call_args.kwargs['env'])

    def test_exception_diagnostics_do_not_echo_values_or_config_lines(self):
        self.assertEqual(m.error_code(ValueError('management_wazuh_unique_global')), 'management_wazuh_unique_global')
        self.assertEqual(m.error_code(ValueError('secret=opaque-hidden-value')), 'ValueError')


if __name__ == '__main__':
    unittest.main()
