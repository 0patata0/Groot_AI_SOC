"""Offline independent fixture/oracle checks. No HTTP, Docker, or packages."""
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import types
import unittest

ROOT = Path(__file__).resolve().parent
END_MS = 1792026000000


def read_module(path):
    result = types.ModuleType(path.stem.replace('-', '_'))
    result.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), result.__dict__)
    return result


runner = read_module(ROOT / 'run-native-b.py')
fixture = read_module(ROOT / 'fixtures.py')
v2 = read_module(ROOT.parent / 'window-v2/fixtures.py')


def micros(text):
    value = datetime.fromisoformat(text) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (value.days * 86400 + value.seconds) * 1000000 + value.microseconds


def independent_oracle(rows, end_ms):
    end = end_ms * 1000
    selected = []
    for row in rows:
        event = row['data']['capstone_norm']
        if (end - 300000000 <= micros(event['event_time_kst']) <= end
                and end - 360000000 <= micros(row['timestamp']) <= end + 5000000
                and event['correlation_time_class'] == 'fresh'
                and event['correlation_eligible'] == 'true'):
            selected.append(row)
    identities = {}
    for row in selected:
        event = row['data']['capstone_norm']
        key = event['source'], event['correlation_dedupe_key']
        value = micros(event['event_time_kst']), event['correlation_key']
        if key in identities and identities[key] != value:
            return v2.expected(invalid='identity_conflict')
        identities[key] = value
    services = defaultdict(list)
    for (source, key), (stamp, service) in identities.items():
        services[service].append((stamp, source, key))
    repeats = cross = matched = 0
    for events in services.values():
        repeated = crossed = False
        for endpoint, _, _ in events:
            window = {(source, key) for stamp, source, key in events
                      if endpoint - 60000000 <= stamp <= endpoint}
            sources = {source for source, _ in window}
            repeated |= any(sum(source == kind for source, _ in window) >= 5 for kind in sources)
            crossed |= sources == {'suricata', 'nftables'}
        repeats += repeated; cross += crossed; matched += repeated or crossed
    return v2.expected(len(selected), len(identities), len(services), matched, repeats, cross)


class DelayContracts(unittest.TestCase):
    def test_all_twelve_fixtures_against_independent_oracle(self):
        cases = list(fixture.cases(v2, END_MS))
        self.assertEqual(len(cases), 12)
        self.assertEqual(len({name for name, _, _ in cases}), 12)
        for name, rows, expected in cases:
            with self.subTest(case=name):
                self.assertEqual(independent_oracle(rows, END_MS), expected)

    def test_false_duplicate_group_does_not_meet_five_unique(self):
        rows = next(rows for name, rows, _ in fixture.cases(v2, END_MS) if name == 'false_repeat_four_a_one_b')
        self.assertEqual(len(rows), 15)
        result = independent_oracle(rows, END_MS)
        self.assertEqual((result['documents'], result['unique_events'], result['matched_services']), (15, 6, 0))

    def test_exact_three_services_and_five_distinct_events(self):
        rows = fixture.groups(v2, END_MS)
        grouped = defaultdict(set)
        for row in rows:
            n = row['data']['capstone_norm']
            grouped[n['correlation_key']].add(n['correlation_dedupe_key'])
        self.assertEqual(len(grouped), 3)
        self.assertEqual([len(keys) for keys in grouped.values()], [5, 5, 5])

    def test_true_sixty_second_spans_and_timed_expectations(self):
        rows = fixture.span_groups(v2, END_MS)
        for offset in range(0, 15, 5):
            stamps = [micros(r['data']['capstone_norm']['event_time_kst']) for r in rows[offset:offset+5]]
            self.assertEqual(max(stamps) - min(stamps), 60000000)
        self.assertEqual(independent_oracle(rows, END_MS + 130000), v2.expected(15, 15, 3, 3, 3))
        self.assertEqual(independent_oracle(rows, END_MS + 310000), v2.expected())

    def test_identity_conflict_is_unavailable_then_same_originals_match(self):
        rows = fixture.groups(v2, END_MS)
        conflict = deepcopy(rows[0])
        conflict['data']['capstone_norm']['event_time_kst'] = v2.iso_us((END_MS-9000)*1000, kst=True)
        self.assertEqual(independent_oracle(rows + [conflict], END_MS), v2.expected(invalid='identity_conflict'))
        self.assertEqual(independent_oracle(rows, END_MS), v2.expected(15, 15, 3, 3, 3))

    def test_processing_timestamp_is_independent_of_event_time(self):
        recent = fixture.groups(v2, END_MS, event_age_s=1800, processing_age_s=0)
        old = fixture.groups(v2, END_MS, event_age_s=0, processing_age_s=1800)
        self.assertEqual(independent_oracle(recent, END_MS), v2.expected())
        self.assertEqual(independent_oracle(old, END_MS), v2.expected())

    def test_frozen_sources_and_exact_transport_adapter(self):
        for name, wanted in runner.PINS.items():
            raw = (runner.V2/name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), wanted)
        original = (runner.V2/'native-verify-b.py').read_bytes()
        adapted = runner.adapted_transport(original)
        reverse = adapted.decode().replace(
            "indexpaths = {('/' + self.index), '/' + self.index + '/_bulk?refresh=true', '/' + self.index + '/_bulk?refresh=false', '/' + self.index + '/_refresh',",
            "indexpaths = {('/' + self.index), '/' + self.index + '/_bulk?refresh=true',").replace(
            "'--max-time', str(self.http_timeout),", "'--max-time', '40',").replace(
            'timeout=self.process_timeout,', 'timeout=50,')
        self.assertEqual(reverse.encode(), original)
        compile(adapted, 'adapted-native-helper', 'exec')
        with self.assertRaisesRegex(RuntimeError, 'frozen_transport_patch_context'):
            runner.adapted_transport(original.replace(b'timeout=50,', b'timeout=49,'))

    def test_request_extension_denies_wrong_method_or_no_intent(self):
        class Parent:
            def request(self, *args, **kwargs):
                return args, kwargs
        base = types.SimpleNamespace(Native=Parent)
        client = runner.make_client(base)()
        client.deadline = runner.time.monotonic()+30
        for method, path, kw in [('GET', '/test/_refresh', {'mutation': True}),
                                 ('POST', '/test/_refresh', {}),
                                 ('POST', '/test/_bulk?refresh=false', {'mutation': True})]:
            with self.subTest(path=path, method=method):
                with self.assertRaises(RuntimeError):
                    client.request(method, path, **kw)
        client.request('POST', '/test/_refresh', mutation=True)
        self.assertLessEqual(client.http_timeout, 10)
        self.assertLessEqual(client.process_timeout, 12)

    def test_deadline_prevents_additional_request(self):
        class Parent:
            def request(self, *args, **kwargs):
                raise AssertionError('network must not be reached')
        client = runner.make_client(types.SimpleNamespace(Native=Parent))()
        client.deadline = runner.time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'audit_deadline'):
            client.request('GET', '/anything')

    def test_oracle_rejects_normal_empty_as_unavailable(self):
        expected = v2.expected()
        got = {'metric': expected, 'observation_match': False, 'observation_unavailable': True}
        with self.assertRaisesRegex(RuntimeError, 'trigger_did_not_match_oracle'):
            runner.metric_equal(got, expected)

    def test_candidate_scope_and_threshold_unchanged(self):
        candidate = json.loads((runner.V2/'monitor.json').read_text())
        self.assertIs(candidate['enabled'], False)
        self.assertTrue(all(row['query_level_trigger']['actions'] == [] for row in candidate['triggers']))
        source = candidate['inputs'][0]['search']['query']['aggs']['observation']['scripted_metric']['reduce_script']['source']
        self.assertIn('suricata >= 5 || nftables >= 5', source)
        self.assertNotIn('suricata >= 3', source)


if __name__ == '__main__':
    unittest.main()
