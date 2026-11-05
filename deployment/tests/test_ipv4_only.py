import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ipv4_only', Path(__file__).resolve().parents[1] / 'ipv4_only.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class RecoveryBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'daemon.json'
        self.doc = {'files': {str(self.path): {'exists': True, 'data': base64.b64encode(b'original').decode()}},
                    'written': {str(self.path): [hashlib.sha256(b'intermediate').hexdigest(), hashlib.sha256(b'final').hexdigest()]}}

    def test_original_and_transaction_states_can_recover(self):
        with patch.object(m, 'trusted', side_effect=Path):
            for data in (b'original', b'intermediate', b'final'):
                self.path.write_bytes(data); m.recovery_files_match(self.doc)

    def test_later_operator_edit_blocks_recovery_before_any_command(self):
        self.path.write_bytes(b'new operator settings')
        with patch.object(m, 'trusted', side_effect=Path), patch.object(m, 'run') as run, self.assertRaisesRegex(RuntimeError, 'drift'):
            m.recovery_files_match(self.doc)
        run.assert_not_called()

    def test_missing_original_file_is_not_silently_recreated(self):
        with patch.object(m, 'trusted', side_effect=Path), self.assertRaisesRegex(RuntimeError, 'drift'):
            m.recovery_files_match(self.doc)

    def test_own_new_file_absence_and_expected_content_are_valid(self):
        self.doc['files'][str(self.path)]['exists'] = False
        with patch.object(m, 'trusted', side_effect=Path):
            m.recovery_files_match(self.doc)
            self.path.write_bytes(b'final'); m.recovery_files_match(self.doc)

    def test_duplicate_configuration_key_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'duplicate'):
            json.loads('{"ip6tables":false,"ip6tables":true}', object_pairs_hook=m.unique)

    def test_confirmed_timer_is_noop_without_docker_or_file_changes(self):
        directory = Path(self.tmp.name); (directory / 'confirmed').touch()
        with patch.object(m, 'read_state', return_value=(directory, self.doc)), patch.object(m, 'run') as run:
            self.assertEqual(m.rollback(directory), {'state': 'confirmed_noop'})
        run.assert_not_called()

    def test_manual_recovery_keeps_hash_boundary_after_confirmation(self):
        directory = Path(self.tmp.name); (directory / 'confirmed').touch()
        self.path.write_bytes(b'later operator edit')
        with patch.object(m, 'read_state', return_value=(directory, self.doc)), patch.object(m, 'trusted', side_effect=Path), patch.object(m, 'run') as run, self.assertRaisesRegex(RuntimeError, 'drift'):
            m.rollback(directory, manual=True)
        run.assert_not_called()

class RuntimeBoundaries(unittest.TestCase):
    def test_remaining_ipv6_listener_prevents_success(self):
        s = {'addresses': [], 'routes': [], 'listeners': ['tcp [::]:22'], 'tables': []}
        with patch.object(m, 'snapshot', return_value=s), self.assertRaisesRegex(RuntimeError, 'listeners'):
            m.verify()

    def test_ipv6_docker_table_prevents_success(self):
        s = {'addresses': [], 'routes': [], 'listeners': [], 'tables': [{'family': 'ip6', 'name': 'filter'}]}
        with patch.object(m, 'snapshot', return_value=s), self.assertRaisesRegex(RuntimeError, 'tables'):
            m.verify()

if __name__ == '__main__': unittest.main()
