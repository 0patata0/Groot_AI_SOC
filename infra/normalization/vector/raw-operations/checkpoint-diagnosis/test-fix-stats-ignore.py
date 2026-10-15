#!/usr/bin/env python3
"""Pure candidate and private-file CAS regressions; no service/native calls."""
import copy
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('fix-stats-ignore-a.py')
spec = importlib.util.spec_from_file_location('fixed_cp_cas', SOURCE)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def config():
    return (b'<ossec_config>\n  <localfile>\n    <log_format>json</log_format>\n'
            b'    <location>' + m.ALIAS.encode() + b'</location>\n'
            b'    <only-future-events max-size="2GB">no</only-future-events>\n'
            b'    <ignore type="PCRE2">' + m.IGNORE.encode() + b'</ignore>\n'
            b'  </localfile>\n  <active-response>\n    <disabled>yes</disabled>\n'
            b'    <ca_store>etc/wpk_root.pem</ca_store>\n'
            b'    <ca_verification>yes</ca_verification>\n  </active-response>\n</ossec_config>\n')


class Candidate(unittest.TestCase):
    def test_exact_two_replacements_only(self):
        before = config(); after = m.build_config(before)
        expected = before.replace(b'    <ignore type="PCRE2">' + m.IGNORE.encode() + b'</ignore>\n', b'')
        expected = expected.replace(b'<disabled>yes</disabled>', b'<disabled>no</disabled>')
        self.assertEqual(after, expected)
        self.assertIn(b'<ca_verification>yes</ca_verification>', after)
        self.assertIn(b'<only-future-events max-size="2GB">no</only-future-events>', after)

    def test_already_removed_refused(self):
        with self.assertRaises(m.Refused): m.build_config(m.build_config(config()))

    def test_other_ignore_refused(self):
        with self.assertRaises(m.Refused): m.build_config(config().replace(b'event_type', b'event_KIND'))

    def test_lowercase_type_refused(self):
        with self.assertRaisesRegex(m.Refused, 'exact_stats_ignore_missing'):
            m.build_config(config().replace(b'type="PCRE2"', b'type="pcre2"'))

    def test_duplicate_exact_ignore_refused(self):
        line = b'    <ignore type="PCRE2">' + m.IGNORE.encode() + b'</ignore>\n'
        with self.assertRaises(m.Refused): m.build_config(config().replace(line, line * 2))

    def test_wrong_source_refused(self):
        with self.assertRaises(m.Refused): m.build_config(config().replace(m.ALIAS.encode(), b'/fixture/wrong'))

    def test_crlf_refused(self):
        with self.assertRaises(m.Refused): m.build_config(config().replace(b'\n', b'\r\n'))

    def test_nul_refused(self):
        with self.assertRaises(m.Refused): m.build_config(config() + b'\0')

    def test_ar_already_enabled_refused(self):
        with self.assertRaises(m.Refused): m.build_config(config().replace(b'<disabled>yes</disabled>', b'<disabled>no</disabled>'))

    def test_duplicate_ar_refused(self):
        with self.assertRaises(m.Refused):
            m.build_config(config().replace(b'</ossec_config>', b'<active-response><disabled>yes</disabled></active-response></ossec_config>'))

    def test_other_disabled_flag_preserved(self):
        original = config().replace(b'</ossec_config>', b'<unrelated><disabled>yes</disabled></unrelated></ossec_config>')
        self.assertIn(b'<unrelated><disabled>yes</disabled></unrelated>', m.build_config(original))

    def test_only_revision_and_pin_change(self):
        before = {'engine': 'suricata', 'machine_id': m.MID, 'phase': 'active', 'pending': None,
                  'revision': 6, 'current': {'inode': 123}, 'proof': {'old_closed': None},
                  'source_pins': {'wazuh_config_sha256': m.EXPECTED[str(m.CONF)][0], 'other': 'untouched'}}
        expected = copy.deepcopy(before); expected['revision'] = 7
        expected['source_pins']['wazuh_config_sha256'] = 'a' * 64
        self.assertEqual(m.build_state(m.canonical(before), 'suricata', 'a' * 64), m.canonical(expected))

    def test_pending_state_refused(self):
        v = {'engine': 'suricata', 'machine_id': m.MID, 'phase': 'switch_pending', 'pending': {},
             'revision': 6, 'source_pins': {'wazuh_config_sha256': m.EXPECTED[str(m.CONF)][0]}}
        with self.assertRaises(m.Refused): m.build_state(m.canonical(v), 'suricata', 'a' * 64)

    def test_other_config_pin_refused(self):
        v = {'engine': 'suricata', 'machine_id': m.MID, 'phase': 'active', 'pending': None,
             'revision': 6, 'source_pins': {'wazuh_config_sha256': 'a' * 64}}
        with self.assertRaises(m.Refused): m.build_state(m.canonical(v), 'suricata', 'b' * 64)

    def test_apply_blocked_before_any_action(self):
        with patch.object(m, 'APPLY_REVIEWED', False), patch.object(m, 'command') as command, \
                patch.object(m, 'load_plan') as load:
            with self.assertRaisesRegex(m.Refused, 'apply_review_pending'): m.apply('a' * 64)
            command.assert_not_called(); load.assert_not_called()


class PrivateCAS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='capstone-cp-fix-test.')
        self.root = Path(self.temp.name); self.target = self.root / 'target'
        self.target.write_bytes(b'before\n'); self.target.chmod(0o640)
        self.parent_guard = patch.object(m, 'parents', side_effect=self.private_parent)
        self.parent_guard.start(); self.addCleanup(self.parent_guard.stop); self.addCleanup(self.temp.cleanup)
        m.ATTEMPTED = None; m.COMPLETED.clear()
        self.meta = m.read(self.target)[1]

    def private_parent(self, path):
        self.assertEqual(path, self.root)

    def test_real_atomic_replace_owner_mode_and_bytes(self):
        after = m.replace(self.target, self.meta, b'after\n', os.getuid(), os.getgid(), 0o640)
        self.assertEqual(self.target.read_bytes(), b'after\n')
        self.assertEqual((after['uid'], after['gid'], after['mode']), (os.getuid(), os.getgid(), 0o640))
        self.assertEqual(m.COMPLETED, [str(self.target)]); self.assertIsNone(m.ATTEMPTED)

    def test_changed_source_refused_before_write(self):
        self.target.write_bytes(b'changed\n')
        with self.assertRaises(m.Refused): m.replace(self.target, self.meta, b'after\n', os.getuid(), os.getgid(), 0o640)
        self.assertEqual(self.target.read_bytes(), b'changed\n'); self.assertEqual(m.COMPLETED, [])

    def test_symlink_refused_before_write(self):
        other = self.root / 'other'; other.write_bytes(b'protected\n')
        self.target.unlink(); self.target.symlink_to(other)
        with self.assertRaises(OSError): m.replace(self.target, self.meta, b'after\n', os.getuid(), os.getgid(), 0o640)
        self.assertEqual(other.read_bytes(), b'protected\n')

    def test_after_rename_failure_is_unknown_not_no_change(self):
        with patch.object(m, 'fsync_dir', side_effect=OSError('synthetic-only')):
            with self.assertRaises(OSError): m.replace(self.target, self.meta, b'after\n', os.getuid(), os.getgid(), 0o640)
        self.assertEqual(self.target.read_bytes(), b'after\n')
        self.assertEqual(m.ATTEMPTED, str(self.target)); self.assertEqual(m.COMPLETED, [])

    def test_parent_metadata_change_refused_before_rename(self):
        calls = []
        def check(path):
            self.private_parent(path); calls.append(path)
            if len(calls) == 2: self.root.chmod(0o750)
        with patch.object(m, 'parents', side_effect=check):
            with self.assertRaisesRegex(m.Refused, 'cas_parent_changed'):
                m.replace(self.target, self.meta, b'after\n', os.getuid(), os.getgid(), 0o640)
        self.assertEqual(self.target.read_bytes(), b'before\n')
        self.assertEqual(list(self.root.iterdir()), [self.target]); self.assertEqual(m.COMPLETED, [])


class Ancestors(unittest.TestCase):
    def metadata(self, path, override=None):
        values = (110, 110, stat.S_IFDIR | 0o770) if path == Path('/var/ossec/etc') else (0, 0, stat.S_IFDIR | 0o755)
        if override is not None and path == override[0]: values = override[1:]
        return SimpleNamespace(st_uid=values[0], st_gid=values[1], st_mode=values[2])

    def test_exact_wazuh_directory_exception(self):
        with patch.object(Path, 'lstat', autospec=True, side_effect=self.metadata):
            m.parents(Path('/var/ossec/etc'))

    def test_wazuh_directory_drift_and_symlink_refused(self):
        for uid, gid, mode in ((0, 110, stat.S_IFDIR | 0o770), (110, 111, stat.S_IFDIR | 0o770),
                               (110, 110, stat.S_IFDIR | 0o777), (110, 110, stat.S_IFLNK | 0o770)):
            with self.subTest(uid=uid, gid=gid, mode=mode):
                change = (Path('/var/ossec/etc'), uid, gid, mode)
                with patch.object(Path, 'lstat', autospec=True, side_effect=lambda p: self.metadata(p, change)):
                    with self.assertRaises(m.Refused): m.parents(Path('/var/ossec/etc'))

    def test_other_nonroot_or_group_writable_parent_refused(self):
        for uid, gid, mode in ((110, 110, stat.S_IFDIR | 0o770), (0, 110, stat.S_IFDIR | 0o770)):
            change = (Path('/var/ossec'), uid, gid, mode)
            with patch.object(Path, 'lstat', autospec=True, side_effect=lambda p: self.metadata(p, change)):
                with self.assertRaises(m.Refused): m.parents(Path('/var/ossec/etc'))


class ActiveResponseReadiness(unittest.TestCase):
    def receipt(self):
        return {'schema_version': 1, 'policy': 'capstone-native-containment-ready-v1',
                'machine_id': m.MID, 'agent_id': '001', 'rule_id': '100110',
                'installed_sha256': {path: contract[0] for path, contract in m.AR_FILES.items()},
                'native_tests_passed': True, 'manager_configuration_verified': True,
                'automatic_test_containment_executed': False}

    def test_exact_ready_contract(self):
        value = self.receipt()
        self.assertEqual(m.check_ar_receipt(m.canonical(value)), value)

    def test_not_ready_or_containment_executed_refused(self):
        for key, bad in (('native_tests_passed', False), ('manager_configuration_verified', False),
                         ('automatic_test_containment_executed', True)):
            with self.subTest(key=key):
                value = self.receipt(); value[key] = bad
                with self.assertRaises(m.Refused): m.check_ar_receipt(m.canonical(value))

    def test_wrong_identity_or_broader_rule_refused(self):
        for key, bad in (('machine_id', '0' * 32), ('agent_id', '000'), ('rule_id', '100111')):
            with self.subTest(key=key):
                value = self.receipt(); value[key] = bad
                with self.assertRaises(m.Refused): m.check_ar_receipt(m.canonical(value))

    def test_typed_flags_and_schema_refused(self):
        for key, bad in (('schema_version', True), ('native_tests_passed', 1),
                         ('manager_configuration_verified', 1), ('automatic_test_containment_executed', 0)):
            with self.subTest(key=key):
                value = self.receipt(); value[key] = bad
                with self.assertRaises(m.Refused): m.check_ar_receipt(m.canonical(value))

    def test_exact_installed_sources_required(self):
        for change in ('changed', 'missing', 'extra'):
            with self.subTest(change=change):
                value = self.receipt(); files = value['installed_sha256']; path = next(iter(files))
                if change == 'changed': files[path] = 'a' * 64
                elif change == 'missing': files.pop(path)
                else: files['/unexpected'] = 'a' * 64
                with self.assertRaises(m.Refused): m.check_ar_receipt(m.canonical(value))

    def test_noncanonical_and_extra_keys_refused(self):
        value = self.receipt()
        with self.assertRaises(m.Refused): m.check_ar_receipt(m.canonical(value) + b'\n')
        value['extra'] = True
        with self.assertRaises(m.Refused): m.check_ar_receipt(m.canonical(value))

    def test_ready_hash_required_before_plan_or_mutation(self):
        with patch.object(m, 'APPLY_REVIEWED', True), patch.object(m, 'command') as command, \
                patch.object(m, 'load_plan') as load, patch.object(m, 'read') as read:
            with self.assertRaisesRegex(m.Refused, 'ar_ready_sha_required'): m.apply('a' * 64)
            command.assert_not_called(); load.assert_not_called(); read.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
