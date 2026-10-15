"""Offline policy/oracle checks, not a Painless compiler or native evidence."""
from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import re
import unittest

import build
import fixtures

ROOT = Path(__file__).resolve().parent
END_MS = 1791975600000
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def event_us(doc):
    delta = datetime.fromisoformat(doc['data']['capstone_norm']['event_time_kst']) - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def brute_force_oracle(documents):
    """Small-fixture oracle enumerates endpoint windows; no sorted sliding loop."""
    if len(documents) > 10000:
        return fixtures.expected(invalid='document_limit')
    identities = {}
    for doc in documents:
        row = doc['data']['capstone_norm']
        identity = row['source'], row['correlation_dedupe_key']
        observed = event_us(doc), row['correlation_key']
        if identity in identities and identities[identity] != observed:
            return fixtures.expected(invalid='identity_conflict')
        identities[identity] = observed
    groups = defaultdict(list)
    for (source, key), (stamp, service) in identities.items():
        groups[service].append((stamp, source, key))
    if len(groups) > 100:
        return fixtures.expected(invalid='service_limit')
    repeated = crossed = matched = 0
    for rows in groups.values():
        repeat = cross = False
        for endpoint, _, _ in rows:
            within = {(source, key) for stamp, source, key in rows if endpoint - 60_000_000 <= stamp <= endpoint}
            sources = {source for source, _ in within}
            repeat |= any(sum(source == kind for source, _ in within) >= 5 for kind in sources)
            cross |= sources == {'suricata', 'nftables'}
        repeated += repeat; crossed += cross; matched += repeat or cross
    return fixtures.expected(len(documents), len(identities), len(groups), matched, repeated, crossed)


class WindowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = json.loads((ROOT / 'monitor.json').read_text())
        cls.base = json.loads((ROOT.parent / 'monitor.json').read_text())
        cls.search = cls.monitor['inputs'][0]['search']['query']

    def test_generated_artifacts_and_historical_base_are_exact(self):
        self.assertEqual(hashlib.sha256((ROOT.parent / 'monitor.json').read_bytes()).hexdigest(), build.BASE_SHA256)
        for name, content in build.artifacts().items():
            self.assertEqual((ROOT / name).read_text(), content, name)

    def test_only_time_query_aggregation_and_condition_scripts_change(self):
        actual, original = deepcopy(self.monitor), deepcopy(self.base)
        for doc in (actual, original):
            search = doc['inputs'][0]['search']['query']
            search['aggs'] = None
            filters = search['query']['bool']['filter']
            for row in filters:
                if 'range' in row:
                    row['range']['timestamp'] = None
                if 'script' in row:
                    row['script']['script']['source'] = None
            for trigger in doc['triggers']:
                trigger['query_level_trigger']['condition']['script']['source'] = None
        self.assertEqual(actual, original)
        self.assertIs(self.monitor['enabled'], False)
        for trigger in self.monitor['triggers']:
            self.assertEqual(trigger['query_level_trigger']['actions'], [])

    def test_query_window_and_scalar_guards(self):
        filters = self.search['query']['bool']['filter']
        self.assertIn({'range': {'timestamp': {'gte': 'now-360s', 'lte': 'now+5s'}}}, filters)
        query = (ROOT / 'monitor-query.painless').read_text()
        self.assertIn('eventUs >= endUs - 300000000L', query)
        self.assertIn('instant.getNano() % 1000 != 0', query)
        self.assertIn('doc[field].size() != 1', query)
        self.assertEqual(self.search['size'], 0)
        self.assertFalse(self.search['_source'])
        self.assertEqual(self.search['terminate_after'], 10001)

    def test_scripted_metric_uses_all_four_reviewable_stages(self):
        self.assertEqual(set(self.search['aggs']), {'observation'})
        metric = self.search['aggs']['observation']['scripted_metric']
        self.assertEqual(set(metric), {'params', 'init_script', 'map_script', 'combine_script', 'reduce_script'})
        self.assertEqual(metric['params'], {'period_end': '{{period_end}}'})
        for stage in ('init', 'map', 'combine', 'reduce'):
            self.assertEqual(metric[stage + '_script'], {'lang': 'painless', 'source': (ROOT / ('metric-' + stage + '.painless')).read_text()})
        self.assertNotIn('cardinality', json.dumps(metric))
        self.assertNotRegex(json.dumps(metric), r'params\._source|doc\[.\x27_source|\x22_source\x22\s*:')

    def test_trigger_validation_is_identical_and_metadata_only(self):
        common = (ROOT / 'trigger-common.painless').read_text()
        for name in ('monitor-match.painless', 'monitor-unavailable.painless'):
            self.assertEqual((ROOT / name).read_text().split('// Decision:', 1)[0], common + '\n')
        for guard in ('now - 15000', 'now + 5000', 'shards.total, 64', 'result.hits.total.value, 10000',
                      'metric.documents != result.hits.total.value', 'metric.services, 100',
                      'result.terminated_early != false', "metric.policy != 'event-window-v2'"):
            self.assertIn(guard, common)
        self.assertNotIn('params.', common)
        reduce = (ROOT / 'metric-reduce.painless').read_text()
        self.assertIn("return unavailable('identity_conflict')", reduce)
        self.assertIn("if (shard == null) continue", reduce)
        self.assertIn('> 60000000L', reduce)
        result = reduce[reduce.rindex("return ['policy'"):]
        for raw in ('row[', 'key\'', 'source\'', 'event_time', 'source_ip', 'message'):
            self.assertNotIn(raw, result)

    def test_small_fixture_expectations_match_independent_endpoint_oracle(self):
        count = 0
        for case in fixtures.cases(END_MS):
            if case.get('query_excluded') or len(case['documents']) > 101:
                continue
            with self.subTest(name=case['name']):
                self.assertEqual(brute_force_oracle(case['documents']), case['expected'])
            count += 1
        self.assertGreaterEqual(count, 20)

    def test_arrival_permutation_does_not_change_reference_result(self):
        rng = random.Random(190)
        rows = [fixtures.document(END_MS, i, -100_000_000 + i * 15_000_000) for i in range(5)]
        rows += [fixtures.document(END_MS, 'n', -50_000_000, source='nftables')]
        rows += deepcopy(rows[:2])
        wanted = brute_force_oracle(rows)
        for _ in range(20):
            rng.shuffle(rows)
            self.assertEqual(brute_force_oracle(rows), wanted)

    def test_required_precision_and_bounds_cases_exist(self):
        summary = {case['name']: (len(case['documents']), case['expected']) for case in fixtures.cases(END_MS)}
        for source in ('repeat', 'cross'):
            self.assertTrue(summary[source + '_microsecond_boundary_below'][1]['match'])
            self.assertTrue(summary[source + '_microsecond_boundary_equal'][1]['match'])
            self.assertFalse(summary[source + '_microsecond_boundary_above'][1]['match'])
        self.assertEqual(summary['ten_thousand_distinct_allowed'][0], 10000)
        self.assertEqual(summary['ten_thousand_distinct_allowed'][1]['unique_events'], 10000)
        self.assertEqual(summary['ten_thousand_one_documents_unavailable'][0], 10001)
        self.assertFalse(summary['ten_thousand_one_documents_unavailable'][1]['valid'])
        self.assertFalse(summary['hundred_one_services_unavailable'][1]['valid'])
        self.assertFalse(summary['same_source_key_different_time'][1]['valid'])
        self.assertFalse(summary['same_source_key_different_service'][1]['valid'])

    def test_fixtures_use_documentation_or_benchmark_addresses_without_raw_payload(self):
        for case in fixtures.cases(END_MS):
            for doc in case['documents'][:5]:
                row = doc['data']['capstone_norm']
                self.assertIn(row['source_ip'], ('198.18.0.10', '211.170.162.110'))
                self.assertIn(row['destination_ip'], ('192.0.2.30', '211.170.162.111'))
                self.assertNotIn('full_log', doc)
                self.assertEqual(set(doc), {'timestamp', 'agent', 'location', 'rule', 'data'})


if __name__ == '__main__':
    unittest.main()
