#!/usr/bin/env python3
"""No Docker/API/config calls; Linux-only cases signal private fixture children."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audit_load', HERE / 'run-native-b.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
BASE_RAW = (a.PROJECT / 'correlation-diagnosis/run-isolated-b.py').read_bytes()
LOAD_RAW = (a.PROJECT / 'correlation-fix/run-load-b.py').read_bytes()
base = a.module(a.adapted_base(BASE_RAW), a.PROJECT / 'correlation-diagnosis/run-isolated-b.py')
load = a.module(a.adapted_load(LOAD_RAW), a.PROJECT / 'correlation-fix/run-load-b.py')


def good():
    return {'errors': [], 'input_rows': 30000, 'sent_rows': 30000, 'archive_rows': 30000,
            'archive_exact_payloads': True, 'group_leaf_mismatches': [], 'exact_group_expectations': True,
            'alert_writer_drained': True, 'archive_leaf_counts': {'100293': 2000, '100294': 2000},
            'alert_leaf_counts': {'100293': 2000, '100294': 2000}, 'scheduled_eps': 50,
            'scheduled_load_seconds': 600, 'fully_drained_stable_seconds': 10,
            'native_state_summary': {'available': True, 'final_sampled_queues_zero': True,
                                    'last_state_age_seconds': 1,
                                    'final_counters': {'events_received': 30000, 'total_events_decoded': 30000,
                                                       'events_processed': 30000, 'events_dropped': 0}}}


class Contract(unittest.TestCase):
    def test_source_pins(self):
        for rel, sha in a.PINS.items():
            self.assertEqual(hashlib.sha256((a.PROJECT / rel).read_bytes()).hexdigest(), sha)

    def test_adapted_rate_and_bounds(self):
        self.assertEqual((load.GROUPS, load.ROWS_PER_GROUP, load.EPS, load.LOAD_SECONDS, load.TOTAL),
                         (2000, 15, 50, 600, 30000))
        source = a.adapted_load(LOAD_RAW).decode()
        self.assertIn('next_progress = now+30', source)
        self.assertIn("'microburst_period_ms':300", source)
        self.assertEqual(load.LOG_BOUND, 120 * 1024 * 1024)
        # The new controller never invokes historical main() (which runs auto).
        self.assertNotIn('load.main(', (HERE / 'run-native-b.py').read_text())

    def test_frozen_context_drift_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'frozen_patch_context'):
            a.adapted_load(LOAD_RAW.replace(b'next_progress = now+10', b'next_progress = now+20'))

    def test_options_exact(self):
        self.assertEqual(a.parse_options(b'# local\nanalysisd.event_threads=1\nanalysisd.rule_matching_threads=1\nanalysisd.decoder_order_size=1024\n'), a.OPTIONS)

    def test_options_missing_or_wrong(self):
        for change in ('analysisd.decoder_order_size=256', 'analysisd.decoder_order_size=0', ''):
            with self.assertRaises(RuntimeError):
                a.parse_options(('analysisd.event_threads=1\nanalysisd.rule_matching_threads=1\n' + change).encode())

    def test_options_duplicate(self):
        with self.assertRaisesRegex(RuntimeError, 'option_shape'):
            a.parse_options(b'analysisd.event_threads=1\nanalysisd.event_threads=1\nanalysisd.rule_matching_threads=1\nanalysisd.decoder_order_size=1024\n')

    def test_exact_success(self):
        a.exact_result(good())

    def test_send_only_not_success(self):
        result = good(); result['archive_rows'] = 29999
        with self.assertRaises(RuntimeError):
            a.exact_result(result)

    def test_leaf_or_group_gap_not_success(self):
        for key, value in (('alert_leaf_counts', {'100293': 1999, '100294': 2000}),
                           ('group_leaf_mismatches', [{'group': 7, 'actual': 0}]),
                           ('exact_group_expectations', False)):
            result = good(); result[key] = value
            with self.assertRaises(RuntimeError):
                a.exact_result(result)

    def test_drop_or_stale_state_not_success(self):
        result = good(); result['native_state_summary']['final_counters']['events_dropped'] = 1
        with self.assertRaises(RuntimeError):
            a.exact_result(result)
        result = good(); result['native_state_summary']['last_state_age_seconds'] = 9
        with self.assertRaises(RuntimeError):
            a.exact_result(result)

    def test_dataset_independent_groups_and_negatives(self):
        events = load.dataset(base, a.PROJECT / 'fixtures/correlation', '1' * 32, groups=3)
        self.assertEqual(len(events), 45)
        self.assertEqual(len({e['run_id'] for e in events}), 3)
        for group in range(3):
            rows = [json.loads(e['text']) for e in events if e['group'] == group]
            self.assertEqual([r['capstone_validation']['load_sequence'] for r in rows], list(range(group * 15 + 1, group * 15 + 16)))
            self.assertEqual(len([r for r in rows if r['capstone_norm']['correlation_time_class'] == 'historical']), 3)
            duplicate = [r['capstone_norm']['correlation_dedupe_key'] for r in rows
                         if r['capstone_validation']['scenario'] == 'canary-repeat-duplicate']
            self.assertEqual(len(duplicate), 5)
            self.assertEqual(len(set(duplicate)), 1)

    def test_observer_duplicate_archive_refused(self):
        events = load.dataset(base, a.PROJECT / 'fixtures/correlation', '2' * 32, groups=1)
        observer = load.Observer(base, Path('/not-opened'), events)
        event = events[0]
        row = {'full_log': event['text'], 'data': json.loads(event['text']), 'agent': {'id': '000'},
               'location': base.LOCATION, 'rule': {'id': '100291'}}
        class Rows:
            def poll(self):
                return [row, copy.deepcopy(row)]
        observer.archives = Rows(); observer.sent_ns[1] = 1
        with self.assertRaisesRegex(RuntimeError, 'archive_duplicate_or_unsent'):
            observer.poll()

    def test_observer_negative_leaf_refused(self):
        events = load.dataset(base, a.PROJECT / 'fixtures/correlation', '3' * 32, groups=1)
        observer = load.Observer(base, Path('/not-opened'), events)
        event = events[-1]
        row = {'full_log': event['text'], 'data': json.loads(event['text']), 'agent': {'id': '000'},
               'location': base.LOCATION, 'rule': {'id': '100293'}}
        class Rows:
            def poll(self):
                return [row]
        observer.archives = Rows(); observer.sent_ns[15] = 1
        with self.assertRaisesRegex(RuntimeError, 'leaf_wrong_scenario'):
            observer.poll()


@unittest.skipUnless(sys.platform == 'linux', 'Linux /proc and WNOWAIT required')
class ChildCleanup(unittest.TestCase):
    def cleanup_case(self, zombie, missing_initial_ticks=False):
        code = 'import os,time\nif os.fork()==0: time.sleep(60)\nelse: time.sleep(60)\n'
        p = subprocess.Popen([sys.executable, '-B', '-c', code], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        start = base.proc_start(p.pid)
        try:
            import time
            deadline = time.monotonic() + 3
            while len(a.group_members(p.pid)) < 2 and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(len(a.group_members(p.pid)), 2)
            if zombie:
                os.kill(p.pid, signal.SIGKILL)
                os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOWAIT)
            result = a.stop_owned(p, None if missing_initial_ticks else start)
            self.assertTrue(result['direct_child_reaped'])
            self.assertEqual(result['live_process_group_members'], 0)
        finally:
            if p.returncode is None:
                # Our unreaped direct child still reserves this exact process group.
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=3)

    def test_live_leader_and_child(self):
        self.cleanup_case(False)

    def test_zombie_leader_with_live_child(self):
        self.cleanup_case(True)

    def test_missing_initial_start_ticks(self):
        self.cleanup_case(False, missing_initial_ticks=True)


if __name__ == '__main__':
    unittest.main()
