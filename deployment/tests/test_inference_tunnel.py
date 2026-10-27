import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('inference_tunnel', Path(__file__).parents[1] / 'inference_tunnel.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
CONFIG = {'schema': 1, 'remote_host': '192.0.2.40', 'remote_port': 8022,
          'remote_user': 'capstone-inference', 'listen_host': '10.200.10.10',
          'listen_port': 11435, 'host_key': 'ssh-ed25519 ' + 'A' * 68}


class TransportTests(unittest.TestCase):
    def test_rejects_public_wildcard_and_injected_configuration(self):
        cases = [('listen_host', '0.0.0.0'), ('listen_host', '8.8.8.8'),
                 ('remote_host', '127.0.0.1'), ('remote_host', '::1'),
                 ('remote_user', 'root\nProxyCommand evil'), ('remote_port', True),
                 ('listen_port', 80), ('host_key', CONFIG['host_key'] + '\nHost *'),
                 ('schema', True), ('unexpected', 'field')]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises((ValueError, TypeError)):
                m.configuration({**CONFIG, key: value})

    def test_transport_has_one_destination_pin_and_no_password_agent(self):
        payload = m.documents(m.configuration(copy.deepcopy(CONFIG)))
        text = payload[m.SSH].decode()
        self.assertIn('LocalForward 10.200.10.10:11435 127.0.0.1:11434\n', text)
        for line in ('StrictHostKeyChecking yes', 'IdentityAgent none', 'BatchMode yes',
                     'IdentitiesOnly yes', 'PasswordAuthentication no', 'ExitOnForwardFailure yes'):
            self.assertIn(line, text)
        self.assertEqual(text.count('LocalForward'), 1)
        self.assertNotIn('ProxyCommand', text)
        self.assertTrue(payload[m.KNOWN].startswith(b'[192.0.2.40]:8022 ssh-ed25519 '))

    def test_nonlocal_listener_is_rejected_before_installation(self):
        with patch.object(m, 'read'), patch.object(m, 'run', side_effect=[b'ssh-ed25519 AAAA', b'[]']), \
                patch.object(m, 'atomic') as write:
            with self.assertRaisesRegex(ValueError, 'listener_not_local'):
                m.install(CONFIG)
        write.assert_not_called()

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / 'link'
            p.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'untrusted_path'):
                m.read(p)

    def test_existing_unmanaged_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'ssh_config'
            path.write_text('operator owned')
            with patch.object(m, 'check', return_value={path: b'new'}), \
                    patch.object(m, 'RECEIPT', Path(root) / 'receipt'), patch.object(m, 'atomic') as write:
                with self.assertRaisesRegex(ValueError, 'existing_files'):
                    m.install(CONFIG)
            write.assert_not_called()
            self.assertEqual(path.read_text(), 'operator owned')

    def test_existing_configuration_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            receipt = Path(root) / 'receipt'
            receipt.touch()
            old = {**CONFIG, 'remote_port': 2222}
            with patch.object(m, 'RECEIPT', receipt), patch.object(m, 'check'), \
                    patch.object(m, 'read', return_value=json.dumps({'configuration': old}).encode()), \
                    patch.object(m, 'atomic') as write:
                with self.assertRaisesRegex(ValueError, 'configuration_changed'):
                    m.install(CONFIG)
            write.assert_not_called()

    def test_file_drift_refuses_before_network_request(self):
        with patch.object(m, 'check', return_value={m.SSH: b'expected'}), \
                patch.object(m, 'read', return_value=b'changed'), \
                patch.object(m.urllib.request, 'build_opener') as opener:
            with self.assertRaisesRegex(ValueError, 'installed_file_drift'):
                m.verify(CONFIG)
        opener.assert_not_called()

    def test_unavailable_api_cannot_be_reported_verified(self):
        opener = Mock()
        opener.open.side_effect = TimeoutError('synthetic')
        with patch.object(m, 'check', return_value={}), patch.object(m, 'run'), \
                patch.object(m.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(TimeoutError):
                m.verify(CONFIG)


if __name__ == '__main__':
    unittest.main()
