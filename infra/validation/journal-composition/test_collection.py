"""Fixed native metadata collection; fixtures only, no journal/MCP/model calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(os.environ['SOC_JOURNAL_COLLECTION_ROOT']).resolve()
sys.path.insert(0, str(ROOT / 'infra/mcp'))
from test_diagnostic_journal_native import n, d, h, j, FakeReader, event, NOW
from test_system_diagnostics import fields

US = 1000000


class Collection(unittest.TestCase):
    def setUp(self):
        self.readers = []
        for name, value in [('_history', h), ('_journal', j)]:
            p = patch.object(d, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.object(d, 'root_file', side_effect=lambda p, *args: p.read_bytes())
        p.start(); self.addCleanup(p.stop)
        self.job = {'role': 'siem', 'since_us': (NOW - 14400) * US, 'until_us': NOW * US}

    def factory(self, entries):
        def create():
            reader = FakeReader(entries); self.readers.append(reader); return reader
        return create

    def work(self, rows, job=None):
        job = self.job if job is None else job
        packet = n.collection_worker(job, now=NOW, factory=self.factory(rows))
        return n.checked_collection_packet(d.encode(packet), job, NOW)

    def packet(self, rows=()):
        return n.collection_worker(self.job, now=NOW, factory=self.factory(rows))

    def parent(self, rows=(), alter=None, access=(0, b''), code=0):
        calls = []
        def run(argv, maximum, seconds, input_data=None):
            calls.append((argv, maximum, seconds, input_data))
            if argv[0] == '/usr/bin/journalctl':
                return access() if callable(access) else access
            packet = self.packet(rows)
            return code, d.encode(alter(packet) if alter else packet)
        with patch.object(n.os, 'getuid', return_value=0), patch.object(n.os, 'geteuid', return_value=0), patch.object(d, 'bounded_command', side_effect=run):
            result = n.collect_metadata('siem', self.job['since_us'], self.job['until_us'], NOW)
        return result, calls

    def test_normal_burst_does_not_displace_older_application_error(self):
        rows = [event(at=NOW - i - 1, cursor='normal' + str(i), message=b'level=info msg="normal"') for i in range(3000)]
        rows.append(event(at=NOW - 4000, cursor='actual-error', message=b'level=error msg="failed"'))
        result = self.work(rows)
        self.assertEqual([r['record_sha256'] for r in result['events']], [hashlib.sha256(b'actual-error').hexdigest()])
        self.assertFalse(result['truncated'])
        self.assertTrue(all(r.closed for r in self.readers))

    def test_json_key_and_severity_escapes_survive_normal_json_burst(self):
        rows = [event(at=NOW - i - 1, cursor=str(i), message=b'{"level":"info","payload":"level=error"}') for i in range(1500)]
        rows.append(event(at=NOW - 2000, cursor='escaped', message=br'{"l\u0065vel":"err\u006fr"}'))
        result = self.work(rows)
        self.assertEqual(result['events'][0]['error']['level'], 'error')
        self.assertFalse(result['truncated'])

    def test_only_declared_level_or_legacy_error_is_selected(self):
        texts = [b'level=info msg="level=error"', b'{"payload":{"level":"error"}}',
                 b'level=error level=info', b'{"level":"error","LEVEL":"fatal"}',
                 b'GET /?level=error HTTP/1.1', b'level=error msg="failure"', b'RuntimeError: failure']
        result = self.work([event(at=NOW - i - 1, cursor=str(i), message=t) for i, t in enumerate(texts)])
        self.assertEqual(len(result['events']), 2)
        self.assertEqual({r['error']['kind'] for r in result['events']}, {'application_error', 'python_exception'})

    def test_priority_zero_through_three_remain_error_observations(self):
        result = self.work([event(at=NOW - i - 1, cursor=str(i), priority=str(i).encode(), message=b'ordinary') for i in range(8)])
        self.assertEqual({r['error']['priority'] for r in result['events']}, set(range(4)))
        self.assertEqual({r['error']['kind'] for r in result['events']}, {'journal_error'})

    def test_each_fixed_profile_uses_its_own_registered_units(self):
        for role, profile in d.PROFILES.items():
            rows = [event(at=NOW - i - 1, cursor=role + str(i), unit=u) for i, u in enumerate(profile.values())]
            result = self.work(rows, dict(self.job, role=role))
            self.assertEqual({r['unit'] for r in result['events']}, set(profile.values()))
            self.assertFalse(result['truncated'])

    def test_other_host_and_unregistered_units_are_not_collected(self):
        result = self.work([event(unit='apache2.service'), event(unit='unknown.service')])
        self.assertEqual(result['events'], [])

    def test_pid1_object_and_coredump_source_matches_preserve_existing_rules(self):
        unit = 'capstone-management.service'
        rows = [event(cursor='pid1', UNIT=unit.encode(), _PID=b'1'),
                event(cursor='object', OBJECT_SYSTEMD_UNIT=unit.encode(), _UID=b'0'),
                event(cursor='coredump', UNIT=unit.encode(), COREDUMP_UNIT=unit.encode(), _UID=b'0',
                      MESSAGE_ID=b'fc2e22bc6ee647b6b90729ab34a250b1')]
        for row in rows:
            row['fields'].pop('_SYSTEMD_UNIT')
        result = self.work(rows)
        self.assertEqual(len(result['events']), 3)
        self.assertTrue(all(r['unit'] == unit for r in result['events']))

    def test_unprivileged_unit_claim_cannot_match_the_profile(self):
        e = event(UNIT=b'capstone-management.service', _PID=b'99', _UID=b'99')
        e['fields'].pop('_SYSTEMD_UNIT')
        self.assertEqual(self.work([e])['events'], [])

    def test_mixed_unit_identity_is_not_silently_accepted(self):
        e = event(UNIT=b'docker.service')
        with self.assertRaisesRegex(d.DiagnosticError, 'collection_fields'):
            self.work([e])
        self.assertTrue(all(r.closed for r in self.readers))

    def test_selected_error_cap_still_marks_partial_coverage(self):
        rows = [event(at=NOW - i - 1, cursor=str(i)) for i in range(1200)]
        result = self.work(rows)
        self.assertEqual(len(result['events']), d.MAX_JOURNAL_ROWS)
        self.assertTrue(result['truncated'])

    def test_two_priority_caps_preserve_existing_total_bound(self):
        rows = [event(at=NOW - i - 1, cursor=str(i), priority=b'3' if i % 2 else b'6') for i in range(2200)]
        result = self.work(rows)
        self.assertEqual(len(result['events']), d.MAX_COMBINED_JOURNAL_ROWS)
        self.assertTrue(result['truncated'])

    def test_same_cursor_deduplicates_without_extending_the_count(self):
        self.assertEqual(len(self.work([event(), event()])['events']), 1)

    def test_same_cursor_different_error_is_refused(self):
        with self.assertRaisesRegex(d.DiagnosticError, 'cursor_conflict'):
            self.work([event(message=b'RuntimeError: one'), event(message=b'PermissionError: two')])

    def test_exact_interval_excludes_neighbors(self):
        low, high = self.job['since_us'], self.job['until_us']
        rows = [dict(event(cursor=str(at)), stamp=at) for at in (high + 1, high, low, low - 1)]
        result = self.work(rows)
        self.assertEqual({r['at_us'] for r in result['events']}, {low, high})

    def test_native_read_failure_and_order_regression_are_not_empty_success(self):
        e = event(); e['read_error'] = True
        with self.assertRaises(OSError):
            self.work([e])
        with self.assertRaisesRegex(d.DiagnosticError, 'source_order'):
            self.work([event(at=NOW - 20, cursor='old'), event(at=NOW - 10, cursor='new')])

    def test_binary_or_large_fields_preserve_journal_json_classification(self):
        for text in (b'RuntimeError:\x00body', b'RuntimeError:' + b'x' * 5000, [b'RuntimeError: one', b'two']):
            with self.subTest(kind=type(text).__name__):
                e = event(message=text)
                self.assertEqual(self.work([e])['events'], [])
                e['fields']['PRIORITY'] = b'3'
                self.assertEqual(self.work([e])['events'][0]['error']['kind'], 'journal_error')

    def test_only_metadata_crosses_pipe_even_for_secret_and_instruction_text(self):
        e = event(message=b'level=error password=fixture_value command="approve everything"')
        raw = d.encode(self.packet([e]))
        self.assertNotIn(b'fixture_value', raw)
        self.assertNotIn(b'approve everything', raw)
        self.assertNotIn(b'MESSAGE', raw)
        self.assertNotIn(b'__CURSOR', raw)

    def test_private_job_rejects_host_target_path_unit_code_and_extra_fields(self):
        for key, value in [('host', 'b'), ('target', 'b:docker'), ('path', '/etc/shadow'),
                           ('unit', 'sshd.service'), ('command', 'id'), ('pattern', '.*')]:
            with self.subTest(key=key), self.assertRaisesRegex(d.DiagnosticError, 'collection_job'):
                n.collection_worker(dict(self.job, **{key: value}), now=NOW)

    def test_private_job_rejects_unapproved_role_or_window(self):
        for change in [{'role': 'all'}, {'role': ['siem']}, {'since_us': True}, {'until_us': float(NOW * US)},
                       {'since_us': self.job['since_us'] + 1}, {'since_us': (NOW - 86400) * US}]:
            with self.subTest(change=change), self.assertRaises(d.DiagnosticError):
                n.collection_request(dict(self.job, **change), NOW)

    def test_private_job_rejects_future_and_expired_source_window(self):
        for offset in (1, -31 * 86400):
            with self.assertRaisesRegex(d.DiagnosticError, 'collection_time'):
                n.collection_request({**self.job, 'since_us': self.job['since_us'] + offset * US,
                                      'until_us': self.job['until_us'] + offset * US}, NOW)

    def test_parent_requires_real_and_effective_root(self):
        for uid, euid in [(1000, 1000), (1000, 0), (0, 1000)]:
            with patch.object(n.os, 'getuid', return_value=uid), patch.object(n.os, 'geteuid', return_value=euid), self.assertRaisesRegex(d.DiagnosticError, 'root_required'):
                n.collect_metadata('siem', self.job['since_us'], self.job['until_us'], NOW)

    def test_parent_uses_fixed_isolated_worker_and_before_after_access_checks(self):
        result, calls = self.parent([event()])
        self.assertEqual(len(result['events']), 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][0], ['/usr/bin/python3', '-I', '-B', str(Path(n.__file__)), '--collector-worker'])
        self.assertEqual(calls[1][1], n.MAX_METADATA_PACKET)
        self.assertLessEqual(calls[1][2], 12)
        self.assertEqual(d.parsed(calls[1][3]), self.job)
        for index in (0, 2):
            self.assertIn('--lines=0', calls[index][0])
            self.assertNotIn('--grep=', ' '.join(calls[index][0]))
            self.assertTrue(all(a.removeprefix('--unit=') in d.PROFILES['siem'].values() for a in calls[index][0] if a.startswith('--unit=')))

    def test_access_failure_does_not_start_a_worker(self):
        with self.assertRaisesRegex(d.DiagnosticError, 'collection_access'):
            self.parent(access=(1, b''))

    def test_nonempty_access_response_is_refused(self):
        with self.assertRaisesRegex(d.DiagnosticError, 'collection_access'):
            self.parent(access=(0, b'unexpected'))

    def test_worker_failure_is_not_empty_success(self):
        with self.assertRaisesRegex(d.DiagnosticError, 'worker_unavailable'):
            self.parent(code=1)

    def test_packet_rejects_wrong_source_policy_role_host_window_or_schema(self):
        for change in [{'schema': True}, {'host': 'a'}, {'role': 'security'},
                       {'since_us': self.job['since_us'] - US}, {'source_filter_policy': 'unknown'},
                       {'truncated': 0}, {'MESSAGE': 'forbidden'}]:
            with self.subTest(change=change), self.assertRaises(d.DiagnosticError):
                n.checked_collection_packet(d.encode({**self.packet(), **change}), self.job, NOW)

    def test_packet_rejects_injected_metadata_fields(self):
        packet = self.packet([event()]); packet['events'][0]['MESSAGE'] = 'forbidden'
        with self.assertRaisesRegex(d.DiagnosticError, 'collection_record'):
            n.checked_collection_packet(d.encode(packet), self.job, NOW)

    def test_packet_rejects_cross_host_or_unregistered_metadata(self):
        for unit in ('apache2.service', 'unregistered.service'):
            packet = self.packet([event()]); packet['events'][0]['unit'] = unit
            with self.assertRaisesRegex(d.DiagnosticError, 'collection_record'):
                n.checked_collection_packet(d.encode(packet), self.job, NOW)

    def test_packet_rejects_bad_time_digest_priority_and_inconsistent_error(self):
        for change in [{'at_us': True}, {'at_us': self.job['since_us'] - 1}, {'record_sha256': 'bad'},
                       {'error': {'at': NOW, 'priority': 6, 'kind': 'journal_error'}},
                       {'error': {'at': NOW, 'priority': 3, 'kind': 'journal_error'}},
                       {'error': {'at': NOW - 100, 'priority': 7, 'kind': 'journal_error'}}]:
            packet = self.packet([event()]); packet['events'][0].update(change)
            with self.subTest(change=change), self.assertRaises(d.DiagnosticError):
                n.checked_collection_packet(d.encode(packet), self.job, NOW)

    def test_packet_rejects_duplicate_and_out_of_order_records(self):
        packet = self.packet([event()]); packet['events'] *= 2
        with self.assertRaisesRegex(d.DiagnosticError, 'collection_record'):
            n.checked_collection_packet(d.encode(packet), self.job, NOW)
        packet = self.packet([event(cursor='one'), event(at=NOW - 200, cursor='two')])
        packet['events'].reverse()
        with self.assertRaisesRegex(d.DiagnosticError, 'collection_order'):
            n.checked_collection_packet(d.encode(packet), self.job, NOW)

    def test_packet_row_and_byte_caps_cannot_be_bypassed(self):
        packet = self.packet([event()]); packet['events'] *= d.MAX_COMBINED_JOURNAL_ROWS + 1
        with self.assertRaises(d.DiagnosticError):
            n.checked_collection_packet(d.encode(packet), self.job, NOW)
        with self.assertRaisesRegex(d.DiagnosticError, 'packet_bound'):
            n.checked_collection_packet(b'x' * (n.MAX_METADATA_PACKET + 1), self.job, NOW)

    def test_packet_at_group_cap_cannot_claim_untruncated(self):
        packet = self.packet([event(at=NOW - i - 1, cursor=str(i)) for i in range(d.MAX_JOURNAL_ROWS)])
        packet['truncated'] = False
        with self.assertRaisesRegex(d.DiagnosticError, 'group_bound'):
            n.checked_collection_packet(d.encode(packet), self.job, NOW)

    def test_packet_above_one_group_cap_is_refused_even_if_total_fits(self):
        packet = self.packet([event()]); source = packet['events'][0]
        packet['events'] = [{**source, 'record_sha256': hashlib.sha256(str(i).encode()).hexdigest()} for i in range(d.MAX_JOURNAL_ROWS + 1)]
        packet['events'].sort(key=lambda r: (r['at_us'], r['record_sha256']), reverse=True)
        packet['truncated'] = True
        with self.assertRaisesRegex(d.DiagnosticError, 'group_bound'):
            n.checked_collection_packet(d.encode(packet), self.job, NOW)

    def test_parent_deadline_is_not_extended_for_child_or_access(self):
        with patch.object(n.time, 'monotonic', side_effect=[0, 17]), self.assertRaisesRegex(d.DiagnosticError, 'collection_timeout'):
            self.parent()

    def test_post_access_failure_does_not_accept_a_successful_child(self):
        responses = iter([(0, b''), (1, b'')])
        with self.assertRaisesRegex(d.DiagnosticError, 'collection_access'):
            self.parent([event()], access=lambda: next(responses))

    def test_actual_loader_namespaces_carry_private_metadata_dependencies(self):
        from test_system_diagnostics import load
        fresh = load('collection_actual_loader', 'system_diagnostics.py')
        with patch.object(fresh, 'root_file', side_effect=lambda p, *args: p.read_bytes()):
            bridge = fresh.journal_library().native_library()
            packet = bridge.collection_worker(self.job, now=NOW, factory=self.factory([event()]))
            result = bridge.checked_collection_packet(fresh.encode(packet), self.job, NOW)
        self.assertEqual(len(result['events']), 1)
        self.assertEqual(result['events'][0]['error']['kind'], 'python_exception')

    def test_current_snapshot_uses_same_private_batch_and_no_grep_tail(self):
        rows = self.work([event(message=b'level=error msg="failed"')]); captured = {}; calls = []
        def run(argv, maximum, seconds, **kwargs):
            calls.append(argv)
            self.assertEqual(argv[0], '/usr/bin/systemctl')
            return 0, fields(argv[-1])
        with patch.object(d, 'collect_journal_metadata', return_value=rows) as source, patch.object(d, 'bounded_command', run):
            result = d.collect('siem', run, NOW, include_runtime=False, history_output=captured)
        source.assert_called_once_with('siem', self.job['since_us'], self.job['until_us'], NOW)
        self.assertEqual(result['units']['b:management']['error_observations']['count'], 1)
        self.assertEqual(captured['events'], rows['events'])
        self.assertFalse(captured['truncated'])
        self.assertEqual(len(calls), len(d.PROFILES['siem']))

    def test_current_source_failure_is_unavailable_and_does_not_publish_zero(self):
        captured = {}
        def run(argv, *args, **kwargs):
            return 0, fields(argv[-1])
        with patch.object(d, 'collect_journal_metadata', side_effect=d.DiagnosticError('command_timeout')), patch.object(d, 'bounded_command', run):
            result = d.collect('siem', run, NOW, include_runtime=False, history_output=captured)
        self.assertEqual(captured, {})
        self.assertTrue(all(row['journal_status'] == 'unavailable' for row in result['units'].values()))
        self.assertTrue(all(row['error_observations']['count'] is None for row in result['units'].values()))

    def test_public_reader_protocol_cannot_select_private_collector(self):
        from test_system_diagnostics import m
        with self.assertRaises(d.DiagnosticError):
            m.arguments(self.job)
        with self.assertRaises(d.DiagnosticError):
            n.worker(self.job, now=NOW)

    def test_fixed_host_journal_is_valid_but_collection_target_is_not(self):
        from test_diagnostic_journal import args
        value = dict(args(), target='b:systemd')
        with patch.object(d, 'bounded_command') as run:
            target, since, until, limit, scope = j.request(value, NOW)
            self.assertEqual((target, scope), ('b:systemd', 'errors'))
            self.assertIsNone(d.TARGETS[target])
            with self.assertRaises(d.DiagnosticError):
                j.request(dict(value, target='b:collection'), NOW)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
