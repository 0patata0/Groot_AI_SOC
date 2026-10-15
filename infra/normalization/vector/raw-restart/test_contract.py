#!/usr/bin/env python3
"""Offline oracles only; no native process, namespace, socket or server access."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name('run-probe-a.py')
probe = types.ModuleType('raw_restart_fixture')
probe.__file__ = str(SOURCE)
exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), probe.__dict__)


class Contract(unittest.TestCase):
    def test_offsets_native_decimal_and_integer(self):
        for value in ('0', '2660', 0, 2660):
            self.assertEqual(probe.offset(value), int(value))

    def test_offsets_reject_coercions(self):
        for value in (True, False, 1.0, -1, '01', '+1', ' 1', '1 ', '１', '1e2', None):
            with self.subTest(value=value), self.assertRaises(probe.Refused):
                probe.offset(value)

    def test_checkpoint_projection(self):
        with tempfile.TemporaryDirectory(prefix='capstone-restart-unit-') as name:
            path = Path(name) / 'state.json'; source = Path(name) / 'reader.json'
            path.write_text(json.dumps({'files': [{'path': str(source), 'offset': '2660', 'hash': 'a' * 40}]}))
            row = probe.checkpoint(path, source)
            self.assertEqual((row['offset'], row['hash']), (2660, 'a' * 40))
            self.assertEqual(row['file_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_checkpoint_missing_or_duplicate_source_rejected(self):
        with tempfile.TemporaryDirectory(prefix='capstone-restart-unit-') as name:
            path = Path(name) / 'state.json'; source = Path(name) / 'reader.json'
            row = {'path': str(source), 'offset': '0', 'hash': 'a' * 40}
            for rows in ([], [row, row]):
                path.write_text(json.dumps({'files': rows}))
                with self.assertRaises(probe.Refused):
                    probe.checkpoint(path, source)

    def test_wire_exact_payload(self):
        source = Path('/private/synthetic.json'); body = b'{"seq":7,"padding":""}'
        sequence, digest = probe.receipt_body(b'1:' + str(source).encode() + b':' + body + b'\0', source, {7: body})
        self.assertEqual(sequence, 7)
        self.assertEqual(digest, hashlib.sha256(body).hexdigest())

    def test_wire_framing_and_semantic_equivalence_rejected(self):
        source = Path('/private/synthetic.json'); body = b'{"seq":7,"padding":""}'
        for wire in (b'1:/other:' + body + b'\0', b'1:' + str(source).encode() + b':' + body,
                     b'1:' + str(source).encode() + b':' + body + b'\0\0',
                     b'1:' + str(source).encode() + b':{"padding":"","seq":7}\0'):
            with self.subTest(wire=wire), self.assertRaises(probe.Refused):
                probe.receipt_body(wire, source, {7: body})

    def test_case_reports_within_case_repeat_and_prior_replay(self):
        item = probe.Profile.__new__(probe.Profile)
        item.name = 'recover'; item.result = {'cases': []}
        item.receipts = [{'sequence': 4}, {'sequence': 4}, {'sequence': 7}, {'sequence': 7}]
        item.owner = types.SimpleNamespace(result={}, save=lambda: None)
        item.case('example', Counter({4: 1}), [7, 8])
        row = item.result['cases'][0]
        self.assertEqual(row['received_counts'], {'4': 1, '7': 2})
        self.assertEqual(row['offline_missing'], [8])
        self.assertEqual(row['duplicate_sequences'], [4, 7])
        self.assertEqual(row['prior_case_replays'], [4])
        self.assertEqual(row['within_case_repeats'], {'7': 2})

    def test_equal_size_distinct_generation_fixture(self):
        item = probe.Profile.__new__(probe.Profile)
        item.name = 'recover'; item.owner = types.SimpleNamespace(run_id='a' * 32); item.expected = {}
        old = b''.join(item.row(n) for n in range(1, 12))
        base = item.row(12) + item.row(13)
        new = item.row(12, 'x' * (len(old) - len(base))) + item.row(13)
        self.assertEqual(len(old), len(new))
        self.assertNotEqual(hashlib.sha1(old).hexdigest(), hashlib.sha1(new).hexdigest())
        self.assertLess(len(new + item.row(14) + item.row(15)), 4096)

    def test_profile_configuration_is_explicit(self):
        text = SOURCE.with_name('wazuh-isolated.sh').read_text()
        self.assertIn("[[ $profile == default ]] || future='<only-future-events max-size=\"2GB\">no</only-future-events>'", text)
        self.assertNotIn('localfile.max-size', text)
        self.assertLess(text.index('mount --make-rprivate /'), text.index('mount --bind "$prefix"'))

    def test_unverified_zombie_launch_group_is_killed_before_reap(self):
        child = types.SimpleNamespace(pid=4321, returncode=None)
        with mock.patch.object(probe, 'process_info', return_value={'start_ticks': 123, 'state': 'Z'}), \
             mock.patch.object(probe.os, 'killpg') as kill, \
             mock.patch.object(probe, 'live_group_members', side_effect=[[4322], []]), \
             mock.patch.object(probe.time, 'sleep'):
            probe.kill_launch_group(child, 123)
        kill.assert_called_once_with(4321, probe.signal.SIGKILL)

    def test_unverified_changed_or_reaped_leader_cannot_signal_group(self):
        for result, ticks in ((None, 124), (0, 123)):
            child = types.SimpleNamespace(pid=4321, returncode=result)
            with mock.patch.object(probe, 'process_info', return_value={'start_ticks': ticks, 'state': 'Z'}), \
                 mock.patch.object(probe.os, 'killpg') as kill:
                with self.assertRaises(probe.Refused):
                    probe.kill_launch_group(child, 123)
                kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
