"""Offline artifact/policy checks only; these do not execute Painless or OpenSearch.

Run with the existing system Python and -B. Native synthetic-index validation
is required before a monitor can be enabled; see indexer-native/README.md.
"""
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1] / "indexer-native"


class IndexerMonitorContractTests(unittest.TestCase):
    def setUp(self):
        self.monitor = json.loads((ROOT / "monitor.json").read_text())
        self.search = self.monitor["inputs"][0]["search"]
        self.query = self.search["query"]
        self.filters = self.query["query"]["bool"]["filter"]
        self.triggers = {row["query_level_trigger"]["name"]: row["query_level_trigger"]
                         for row in self.monitor["triggers"]}

    def test_disabled_fixed_query_monitor_has_no_authority_or_destination_changes(self):
        self.assertEqual(set(self.monitor), {"type", "name", "monitor_type", "enabled", "schedule", "inputs", "triggers"})
        self.assertEqual(self.monitor["monitor_type"], "query_level_monitor")
        self.assertIs(self.monitor["enabled"], False)
        self.assertEqual(self.monitor["schedule"], {"period": {"interval": 1, "unit": "MINUTES"}})
        self.assertEqual(len(self.monitor["inputs"]), 1)
        self.assertEqual(self.search["indices"], ["wazuh-alerts-*"])
        self.assertEqual(set(self.triggers), {"observation_match", "observation_unavailable"})
        for trigger in self.triggers.values():
            self.assertEqual(trigger["actions"], [])
            self.assertEqual(trigger["severity"], "5")
            self.assertEqual(set(trigger), {"id", "name", "severity", "condition", "actions"})

    def test_search_returns_aggregates_only_with_explicit_work_bounds(self):
        self.assertEqual(self.query["size"], 0)
        self.assertIs(self.query["_source"], False)
        self.assertEqual(self.query["timeout"], "10s")
        self.assertIs(self.query["track_total_hits"], True)
        self.assertEqual(self.query["terminate_after"], 10001)
        self.assertNotIn("script_fields", self.query)
        self.assertNotIn("top_hits", json.dumps(self.query["aggs"]))

    def test_evidence_provenance_and_processing_time_are_mandatory(self):
        direct = {key: value for row in self.filters if "term" in row for key, value in row["term"].items()}
        self.assertEqual(direct, {
            "agent.id": "001", "location": "/var/log/capstone-vector/evidence/normalized.jsonl",
            "data.capstone_norm.schema_version": "vector-1", "data.capstone_norm.pipeline": "vector",
            "data.capstone_norm.sensor": "groot-sec", "data.capstone_norm.evidence_lane": "indexer-observation-v1",
            "data.capstone_norm.correlation_eligible": "true", "data.capstone_norm.correlation_time_class": "fresh",
            "data.capstone_norm.protected_asset": "false", "data.capstone_norm.correlation_policy": "directional-service-v1",
        })
        self.assertIn({"range": {"timestamp": {"gte": "now-120s", "lte": "now"}}}, self.filters)
        # Empty arrays are decoder-dependent. The checked leaf + producer marker
        # own quality validation; an exists-negation must not silently drop them.
        self.assertNotIn("quality_flags", json.dumps(self.query))
        forbidden = self.query["query"]["bool"]["must_not"]
        self.assertEqual(forbidden, [
            {"terms": {"data.capstone_norm." + key: ["211.170.162.110", "211.170.162.111"]}}
            for key in ("source_ip", "destination_ip")
        ])

    def test_source_leaf_and_action_are_bound_together(self):
        branch = next(row["bool"] for row in self.filters if "bool" in row)
        self.assertEqual(branch["minimum_should_match"], 1)
        self.assertEqual(branch["should"], [
            {"bool": {"filter": [{"term": {"rule.id": "100261"}},
                                 {"term": {"data.capstone_norm.source": "suricata"}},
                                 {"terms": {"data.capstone_norm.action": ["allowed", "observed", "blocked"]}}]}},
            {"bool": {"filter": [{"term": {"rule.id": "100262"}},
                                 {"term": {"data.capstone_norm.source": "nftables"}},
                                 {"term": {"data.capstone_norm.action": "logged_drop"}}]}},
        ])

    def test_exact_terms_separate_source_repetition_from_cross_source_presence(self):
        service = self.query["aggs"]["services"]
        self.assertEqual(service["terms"], {"field": "data.capstone_norm.correlation_key", "size": 101, "order": {"_key": "asc"}})
        sources = service["aggs"]["sources"]
        self.assertEqual(sources["terms"], {"field": "data.capstone_norm.source", "size": 3, "order": {"_key": "asc"}})
        expected = {"terms": {"field": "data.capstone_norm.correlation_dedupe_key", "size": 5, "order": {"_key": "asc"}}}
        self.assertEqual(service["aggs"]["unique_ids"], expected)
        self.assertEqual(sources["aggs"]["unique_ids"], expected)
        self.assertNotIn("cardinality", json.dumps(self.query["aggs"]))

    def test_embedded_scripts_exactly_match_reviewable_source_files(self):
        script = next(row["script"]["script"] for row in self.filters if "script" in row)
        self.assertEqual(script["source"], (ROOT / "monitor-query.painless").read_text())
        self.assertEqual(script["params"]["period_end"], "{{period_end}}")
        self.assertEqual(set(script["params"]), {"period_end", "single_fields"})
        required = {"correlation_key", "correlation_dedupe_key", "source", "sensor", "event_time_kst",
                    "source_ip", "destination_ip", "destination_port", "protocol", "evidence_lane"}
        self.assertTrue(required.issubset(script["params"]["single_fields"]))
        self.assertEqual(len(script["params"]["single_fields"]), len(set(script["params"]["single_fields"])))
        for name, filename in (("observation_match", "monitor-match.painless"),
                               ("observation_unavailable", "monitor-unavailable.painless")):
            self.assertEqual(self.triggers[name]["condition"]["script"],
                             {"lang": "painless", "source": (ROOT / filename).read_text()})

    def test_both_decisions_embed_identical_reviewed_validation_prefix(self):
        match = (ROOT / "monitor-match.painless").read_text()
        unavailable = (ROOT / "monitor-unavailable.painless").read_text()
        self.assertEqual(match.split("// Decision:", 1)[0], unavailable.split("// Decision:", 1)[0])
        prefix = match.split("// Decision:", 1)[0]
        for boundary in ("new Date().getTime()", "ctx.periodEnd.toEpochMilli()", "now + 5000", "now - 15000",
                         "shards.total, 64", "result.hits.total.value, 10000", "services.buckets.size() > 100",
                         "result.terminated_early != false", "services.sum_other_doc_count, 0"):
            self.assertIn(boundary, prefix)
        self.assertNotIn("throw ", prefix)
        self.assertNotIn("params.", prefix)  # no runtime test bypasses/budget overrides
        self.assertIn("source.unique_ids.buckets.size() >= 5", match.split("// Decision:", 1)[1])
        self.assertIn("service.sources.buckets.size() == 2", match.split("// Decision:", 1)[1])


if __name__ == "__main__":
    unittest.main()
