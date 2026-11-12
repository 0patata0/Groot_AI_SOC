#!/usr/bin/env python3
"""Pure candidate, plan and private-file CAS regressions; no service/native calls."""
import copy
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'tune-buffer-a.py'
spec = importlib.util.spec_from_file_location('fixed_a_agent_buffer', SOURCE)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ORIGINAL = HERE.parent / 'checkpoint-diagnosis' / 'fix-stats-ignore-a.py'
LOG_PIPELINE = HERE.parents[4] / 'deployment' / 'log_pipeline.py'


def config(queue=b'5000', eps=b'500'):
    return (b'<ossec_config>\n  <client>\n    <server><address>192.0.2.10</address></server>\n  </client>\n'
            b'  <client_buffer>\n    <!-- Agent buffer options -->\n    <disabled>no</disabled>\n'
            b'    <queue_size>' + queue + b'</queue_size>\n    <events_per_second>' + eps + b'</events_per_second>\n'
            b'  </client_buffer>\n  <localfile>\n    <log_format>json</log_format>\n'
            b'    <location>/home/groot_a/capstone/secstack/logs/suricata/eve.json</location>\n  </localfile>\n'
            b'  <active-response>\n    <disabled>no</disabled>\n    <ca_store>etc/wpk_root.pem</ca_store>\n'
            b'  </active-response>\n</ossec_config>\n')


def state(**change):
    value = {'engine': 'suricata', 'machine_id': m.MID, 'phase': 'active', 'pending': None,
             'revision': 152, 'current': {'inode': 123}, 'proof': {'old_closed': None},
             'source_pins': {'wazuh_config_sha256': m.CONF_EXPECTED[0], 'other': 'untouched'}}
    value.update(change)
    return value


class Candidate(unittest.TestCase):
    def test_only_the_two_buffer_values_change(self):
        before = config(); after = m.build_config(before)
        self.assertEqual(after, config(b'100000', b'1000'))
        self.assertIn(b'<!-- Agent buffer options -->', after)
        self.assertIn(b'<disabled>no</disabled>\n    <ca_store>', after)  # active response untouched

    def test_values_within_wazuh_limits(self):
        self.assertLessEqual(int(m.BUFFER_AFTER['queue_size']), 100000)
        self.assertLessEqual(int(m.BUFFER_AFTER['events_per_second']), 1000)
        self.assertGreater(int(m.BUFFER_AFTER['queue_size']), int(m.BUFFER_BEFORE['queue_size']))

    def test_already_tuned_or_unexpected_values_refused(self):
        for bad in (config(b'100000', b'1000'), config(b'20000', b'500'), config(b'5000', b'0')):
            with self.subTest(bad=bad[120:220]), self.assertRaisesRegex(m.Refused, 'client_buffer_value_unexpected'):
                m.build_config(bad)

    def test_missing_duplicate_or_disabled_buffer_refused(self):
        block = config()[config().index(b'  <client_buffer>'):config().index(b'  <localfile>')]
        for bad in (config().replace(block, b''), config().replace(block, block + block),
                    config().replace(b'<disabled>no</disabled>\n    <queue_size>', b'<disabled>yes</disabled>\n    <queue_size>'),
                    config().replace(b'<client_buffer>', b'<client_buffer mode="x">')):
            with self.subTest(bad=bad[60:200]), self.assertRaises(m.Refused):
                m.build_config(bad)

    def test_duplicate_value_element_refused(self):
        with self.assertRaises(m.Refused):
            m.build_config(config().replace(b'<queue_size>5000</queue_size>', b'<queue_size>5000</queue_size><queue_size>5000</queue_size>'))

    def test_framing_refused(self):
        for bad in (config().replace(b'\n', b'\r\n'), config() + b'\0'):
            with self.subTest(bad=bad[-8:]), self.assertRaises(m.Refused):
                m.build_config(bad)

    def test_fresh_install_and_existing_install_use_the_same_values(self):
        text = LOG_PIPELINE.read_text()
        self.assertIn("AGENT_BUFFER = {'queue_size': '100000', 'events_per_second': '1000'}", text)
        self.assertEqual(m.BUFFER_AFTER, {'queue_size': '100000', 'events_per_second': '1000'})


class State(unittest.TestCase):
    def test_only_revision_and_pin_change(self):
        before = state()
        expected = copy.deepcopy(before); expected['revision'] = 153
        expected['source_pins']['wazuh_config_sha256'] = 'a' * 64
        self.assertEqual(m.build_state(m.canonical(before), 'suricata', m.CONF_EXPECTED[0], 'a' * 64), m.canonical(expected))

    def test_pending_wrong_pin_engine_or_noncanonical_refused(self):
        cases = (m.canonical(state(phase='switch_pending', pending={})),
                 m.canonical(state(source_pins={'wazuh_config_sha256': 'b' * 64})),
                 m.canonical(state(machine_id='0' * 32)),
                 m.canonical(state()) + b'\n')
        for raw in cases:
            with self.subTest(raw=raw[:80]), self.assertRaises((m.Refused, ValueError)):
                m.build_state(raw, 'suricata', m.CONF_EXPECTED[0], 'a' * 64)
        with self.assertRaises(m.Refused):
            m.build_state(m.canonical(state()), 'modsecurity', m.CONF_EXPECTED[0], 'a' * 64)


class Gate(unittest.TestCase):
    def test_apply_blocked_before_any_action(self):
        with patch.object(m, 'APPLY_REVIEWED', False), patch.object(m, 'command') as command, \
                patch.object(m, 'load_plan') as load:
            with self.assertRaisesRegex(m.Refused, 'apply_review_pending'): m.apply('a' * 64)
            command.assert_not_called(); load.assert_not_called()

    def test_buffer_values_reader(self):
        self.assertEqual(m.buffer_values(config(b'100000', b'1000')), m.BUFFER_AFTER)
        self.assertEqual(m.buffer_values(config()), m.BUFFER_BEFORE)

    def test_shared_transaction_helpers_match_the_applied_controller(self):
        """The CAS, locking, unit and guard helpers are the 2026-10-15 applied code."""
        original = ORIGINAL.read_text(); ported = SOURCE.read_text()
        for name in ('def parents(', 'def read(', 'def read_relative(', 'def exclusive(', 'def command(',
                     'def unit(', 'def processes(', 'def runtime(', 'def guard(', 'def effective_barrier('):
            start_o = original.index(name); start_p = ported.index(name)
            end_o = original.index('\ndef ', start_o + 1); end_p = ported.index('\ndef ', start_p + 1)
            self.assertEqual(original[start_o:end_o].rstrip(), ported[start_p:end_p].rstrip(), name)
        o = original[original.index('def replace('):original.index('\ndef ', original.index('def replace(') + 1)]
        p = ported[ported.index('def replace('):ported.index('\ndef ', ported.index('def replace(') + 1)]
        self.assertEqual(o.replace("'.stats-ignore-'", "'.agent-buffer-'").rstrip(), p.rstrip())


class AgentState(unittest.TestCase):
    def test_wazuh_owned_run_directory_is_readable_for_status(self):
        # Regression for 2026-11-13 07:08: the strict root-parent reader refused
        # /var/ossec/var/run (wazuh-owned) after the change had been applied.
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'wazuh-agentd.state'
            state.write_text("status='connected'\n")
            with patch.object(m, 'parents', side_effect=AssertionError('strict parent check must not run')):
                m.agent_connected(state)
            state.write_text("status='pending'\n")
            with self.assertRaisesRegex(m.Refused, 'agent_not_connected'): m.agent_connected(state)
            link = Path(directory) / 'link'; link.symlink_to(state)
            with self.assertRaises(OSError): m.agent_connected(link)


class PrivateCAS(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='capstone-agent-buffer-test.')
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

    def test_after_rename_failure_is_unknown_not_no_change(self):
        with patch.object(m, 'fsync_dir', side_effect=OSError('synthetic-only')):
            with self.assertRaises(OSError): m.replace(self.target, self.meta, b'after\n', os.getuid(), os.getgid(), 0o640)
        self.assertEqual(self.target.read_bytes(), b'after\n')
        self.assertEqual(m.ATTEMPTED, str(self.target)); self.assertEqual(m.COMPLETED, [])


class Ancestors(unittest.TestCase):
    def metadata(self, path, override=None):
        values = (110, 110, stat.S_IFDIR | 0o770) if path == Path('/var/ossec/etc') else (0, 0, stat.S_IFDIR | 0o755)
        if override is not None and path == override[0]: values = override[1:]
        return SimpleNamespace(st_uid=values[0], st_gid=values[1], st_mode=values[2])

    def test_exact_wazuh_directory_exception_only(self):
        with patch.object(Path, 'lstat', autospec=True, side_effect=self.metadata):
            m.parents(Path('/var/ossec/etc'))
        change = (Path('/var/ossec'), 110, 110, stat.S_IFDIR | 0o770)
        with patch.object(Path, 'lstat', autospec=True, side_effect=lambda p: self.metadata(p, change)):
            with self.assertRaises(m.Refused): m.parents(Path('/var/ossec/etc'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
