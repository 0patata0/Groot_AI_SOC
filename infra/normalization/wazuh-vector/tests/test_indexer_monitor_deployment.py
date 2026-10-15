"""Offline deployment state-machine tests. No Docker/API/filesystem mutation.

These fixtures exercise our protocol, not OpenSearch's real CAS/serialization.
Run: python3 -B -m unittest discover -s . -p test_indexer_monitor_deployment.py
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1] / "indexer-native"
SPEC = importlib.util.spec_from_file_location("monitor_deployment", ROOT / "deploy-monitor-b.py")
DEPLOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEPLOY)
CANDIDATE = json.loads((ROOT / "monitor.json").read_text())


class MemoryStore:
    def __init__(self):
        self.value = None
        self.writes = []

    def read(self):
        return copy.deepcopy(self.value)

    def write(self, value):
        self.value = copy.deepcopy(value)
        self.writes.append(self.read())


class FakeAPI:
    def __init__(self):
        self.monitor = None
        self.seq = 0
        self.calls = []
        self.duplicates = False
        self.fail_post_reply = False
        self.fail_cas = False
        self.get_changes = False
        self.search_partial = False
        self.query_changed_on_put = False
        self.schema_on_put = None
        self.owner_changed_on_put = False

    def response(self):
        return {"_id": "test-monitor-id", "_seq_no": self.seq, "_primary_term": 1,
                "monitor": copy.deepcopy(self.monitor)}

    def __call__(self, method, path, payload=None, expected=(200,)):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if path == "/_plugins/_alerting/stats":
            return 200, {"_nodes": {"total": 1, "successful": 1, "failed": 0},
                         "nodes": {"private-node-name": {"jobs_info": {
                             "test-monitor-id": {"last_execution_time": 1000, "running_on_time": True}}}}}
        if path.endswith("/_search"):
            rows = [] if self.monitor is None else [{"_id": "test-monitor-id", "_source": self.monitor}]
            if self.duplicates:
                rows += [{"_id": "other-monitor-id", "_source": self.monitor}]
            return 200, {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": int(self.search_partial)},
                         "hits": {"total": {"value": len(rows), "relation": "eq"}, "hits": copy.deepcopy(rows)}}
        if method == "POST":
            self.monitor = copy.deepcopy(payload)
            # Real APIs add fields; binding the trusted POST revision avoids an
            # unsafe allowlist that silently discards unknown query changes.
            self.monitor.update({"schema_version": 0, "last_update_time": 123,
                                 "enabled_time": None, "user": {"name": "admin", "backend_roles": []}})
            if self.fail_post_reply:
                raise DEPLOY.Refused("indexer_request_failed_or_reply_uncertain")
            return 201, self.response()
        if method == "PUT":
            if self.fail_cas:
                raise DEPLOY.Refused("indexer_http_409")
            self.seq += 1
            self.monitor = copy.deepcopy(payload)
            self.monitor.update({"last_update_time": 456, "enabled_time": 456 if payload["enabled"] else None})
            if self.query_changed_on_put:
                self.monitor["inputs"][0]["search"]["query"]["timeout"] = "20s"
            if self.schema_on_put is not None:
                self.monitor["schema_version"] = self.schema_on_put
            if self.owner_changed_on_put:
                self.monitor["user"]["backend_roles"] = ["unexpected-role"]
            return 200, self.response()
        if method == "GET":
            result = self.response()
            if self.get_changes:
                result["_seq_no"] += 1
            return 200, result
        raise AssertionError("unexpected fixture API call")


class MonitorDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()
        self.store = MemoryStore()

    def run_op(self, operation):
        return DEPLOY.operate(operation, self.api, self.store, CANDIDATE)

    def mutations(self):
        return [row for row in self.api.calls if row[0] in ("POST", "PUT", "DELETE")]

    def test_inspect_is_read_only_and_creates_no_state(self):
        self.assertEqual(self.run_op("inspect")["exact_name_count"], 0)
        self.assertEqual(self.store.writes, [])
        self.assertEqual(self.mutations(), [])

    def test_create_records_intent_then_disabled_server_revision(self):
        result = self.run_op("create-disabled")
        self.assertFalse(result["enabled"])
        self.assertEqual(result["actions"], 0)
        self.assertEqual([row["phase"] for row in self.store.writes],
                         ["create_pending", "create_readback_pending", "disabled"])
        self.assertEqual(self.store.value["monitor_sha256"], DEPLOY.digest(self.api.monitor))
        self.assertEqual(self.mutations()[0][2], CANDIDATE)

    def test_idempotent_create_never_reposts(self):
        self.run_op("create-disabled")
        result = self.run_op("create-disabled")
        self.assertFalse(result["changed"])
        self.assertEqual(len(self.mutations()), 1)

    def test_unmanaged_same_name_is_not_adopted_or_overwritten(self):
        self.api.monitor = copy.deepcopy(CANDIDATE)
        with self.assertRaisesRegex(DEPLOY.Refused, "unmanaged_same_name"):
            self.run_op("create-disabled")
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.store.writes, [])

    def test_duplicate_exact_names_refuse_before_mutation(self):
        self.api.monitor = copy.deepcopy(CANDIDATE)
        self.api.duplicates = True
        with self.assertRaisesRegex(DEPLOY.Refused, "duplicate_exact"):
            self.run_op("create-disabled")
        self.assertEqual(self.mutations(), [])

    def test_missing_index_only_specific_404_is_accepted(self):
        def missing(*args, **kwargs):
            return 404, {"error": {"type": "index_not_found_exception", "index": ".opendistro-alerting-config"}}
        self.assertEqual(DEPLOY.exact_names(missing), [])
        def other(*args, **kwargs):
            return 404, {"error": {"type": "not_found", "index": "other"}}
        with self.assertRaisesRegex(DEPLOY.Refused, "unexpected_monitor_search_404"):
            DEPLOY.exact_names(other)

    def test_name_search_partial_response_refuses(self):
        self.api.search_partial = True
        with self.assertRaisesRegex(DEPLOY.Refused, "search_partial"):
            self.run_op("create-disabled")
        self.assertEqual(self.mutations(), [])

    def test_installed_alerting_wrapped_absence_is_exact_index_only(self):
        message = "org.opensearch.index.IndexNotFoundException: no such index [.opendistro-alerting-config]"
        def wrapped(reason):
            return lambda *a, **kw: (404, {"error": {"type": "alerting_exception", "caused_by": {
                "type": "exception", "reason": reason}}})
        self.assertEqual(DEPLOY.exact_names(wrapped(message)), [])
        for changed in (message.replace(".opendistro-alerting-config", ".other"), message + " unexpected", "forbidden"):
            with self.subTest(), self.assertRaisesRegex(DEPLOY.Refused, "unexpected_monitor_search_404"):
                DEPLOY.exact_names(wrapped(changed))

    def test_post_reply_loss_keeps_intent_and_prevents_duplicate_retry(self):
        self.api.fail_post_reply = True
        with self.assertRaisesRegex(DEPLOY.Refused, "reply_uncertain"):
            self.run_op("create-disabled")
        self.assertEqual(self.store.value["phase"], "create_pending")
        with self.assertRaisesRegex(DEPLOY.Refused, "mutation_uncertain"):
            self.run_op("create-disabled")
        self.assertEqual(len(self.mutations()), 1)
        self.assertEqual(self.run_op("inspect")["monitor_ids"], ["test-monitor-id"])

    def test_post_get_revision_difference_stays_pending(self):
        self.api.get_changes = True
        with self.assertRaisesRegex(DEPLOY.Refused, "create_readback_changed"):
            self.run_op("create-disabled")
        self.assertEqual(self.store.value["phase"], "create_readback_pending")

    def test_enable_and_disable_use_exact_revision_and_keep_actions_empty(self):
        self.run_op("create-disabled")
        self.assertTrue(self.run_op("enable")["enabled"])
        self.assertIn("?if_seq_no=0&if_primary_term=1", self.mutations()[-1][1])
        self.assertEqual(self.store.value["phase"], "enabled")
        self.assertFalse(self.run_op("enable")["changed"])
        self.assertFalse(self.run_op("disable")["enabled"])
        self.assertIn("?if_seq_no=1&if_primary_term=1", self.mutations()[-1][1])
        for trigger in self.api.monitor["triggers"]:
            self.assertEqual(trigger["query_level_trigger"]["actions"], [])

    def test_unrelated_server_change_blocks_enable(self):
        self.run_op("create-disabled")
        self.api.monitor["inputs"][0]["search"]["query"]["timeout"] = "20s"
        with self.assertRaisesRegex(DEPLOY.Refused, "monitor_query_semantics_changed"):
            self.run_op("enable")
        self.assertEqual(len(self.mutations()), 1)

    def test_cas_rejection_is_not_blindly_retried(self):
        self.run_op("create-disabled")
        self.api.fail_cas = True
        with self.assertRaisesRegex(DEPLOY.Refused, "409"):
            self.run_op("enable")
        self.assertEqual(self.store.value["phase"], "enable_pending")
        with self.assertRaisesRegex(DEPLOY.Refused, "mutation_uncertain"):
            self.run_op("enable")
        self.assertEqual(len(self.mutations()), 2)

    def test_query_change_during_put_does_not_get_marked_verified(self):
        self.run_op("create-disabled")
        self.api.query_changed_on_put = True
        with self.assertRaisesRegex(DEPLOY.Refused, "monitor_query_semantics_changed"):
            self.run_op("enable")
        self.assertEqual(self.store.value["phase"], "enable_pending")

    def test_only_observed_schema_zero_to_eight_is_allowed(self):
        self.run_op("create-disabled")
        self.api.schema_on_put = 8
        self.assertTrue(self.run_op("enable")["enabled"])
        self.assertEqual(self.api.monitor["schema_version"], 8)
        self.assertFalse(self.run_op("disable")["enabled"])
        self.api.schema_on_put = 9
        with self.assertRaisesRegex(DEPLOY.Refused, "update_config_or_revision_changed"):
            self.run_op("enable")

    def test_schema_migration_never_hides_other_configuration_change(self):
        self.run_op("create-disabled")
        self.api.schema_on_put = 8
        self.api.owner_changed_on_put = True
        with self.assertRaisesRegex(DEPLOY.Refused, "update_config_or_revision_changed"):
            self.run_op("enable")
        self.assertEqual(self.store.value["phase"], "enable_pending")

    def test_actions_cannot_be_added_through_owned_update(self):
        self.run_op("create-disabled")
        self.api.monitor["triggers"][0]["query_level_trigger"]["actions"] = [{"id": "forbidden"}]
        with self.assertRaisesRegex(DEPLOY.Refused, "trigger_or_actions_changed"):
            self.run_op("enable")
        self.assertEqual(len(self.mutations()), 1)

    def test_observe_is_metadata_only_and_not_query_success_ack(self):
        self.run_op("create-disabled")
        self.run_op("enable")
        writes = len(self.store.writes)
        result = self.run_op("observe")
        self.assertEqual(result["scheduler_executions"], [{"last_execution_time": 1000, "running_on_time": True}])
        self.assertFalse(result["proves_query_or_delivery_success"])
        self.assertNotIn("private-node-name", json.dumps(result))
        self.assertEqual(len(self.store.writes), writes)
        self.assertEqual(len(self.mutations()), 2)

    def test_known_server_query_defaults_match_candidate(self):
        monitor = copy.deepcopy(CANDIDATE)
        query = monitor["inputs"][0]["search"]["query"]
        query["track_total_hits"] = 2147483647
        query["aggregations"] = query.pop("aggs")
        def defaults(clause):
            kind, value = next(iter(clause.items()))
            if kind == "bool":
                value.update({"boost": 1.0, "adjust_pure_negative": True})
                if "minimum_should_match" in value:
                    value["minimum_should_match"] = str(value["minimum_should_match"])
                for key in ("filter", "should", "must_not", "must"):
                    for row in value.get(key, []):
                        defaults(row)
            elif kind in ("term", "regexp"):
                for key in list(value):
                    value[key] = {"value": value[key], "boost": 1.0}
                    if kind == "regexp":
                        value[key].update({"flags_value": 255, "max_determinized_states": 10000})
            elif kind == "range":
                for item in value.values():
                    item.update({"from": item.pop("gte"), "to": item.pop("lte"),
                                 "include_lower": True, "include_upper": True, "boost": 1.0})
            else:
                value["boost"] = 1.0
        defaults(query["query"])
        def aggregate_defaults(aggs):
            for row in aggs.values():
                row["terms"].update({"min_doc_count": 1, "shard_min_doc_count": 0,
                                     "show_term_doc_count_error": False})
                if "aggs" in row:
                    row["aggregations"] = row.pop("aggs")
                    aggregate_defaults(row["aggregations"])
        aggregate_defaults(query["aggregations"])
        DEPLOY.validate_monitor(monitor, CANDIDATE, False)

    def test_initial_query_filter_aggregation_and_script_changes_are_rejected(self):
        variants = []
        monitor = copy.deepcopy(CANDIDATE)
        monitor["inputs"][0]["search"]["query"]["query"]["bool"]["filter"].pop(0)
        variants.append(monitor)
        monitor = copy.deepcopy(CANDIDATE)
        monitor["inputs"][0]["search"]["query"]["aggs"]["services"]["terms"]["size"] = 100
        variants.append(monitor)
        monitor = copy.deepcopy(CANDIDATE)
        rows = monitor["inputs"][0]["search"]["query"]["query"]["bool"]["filter"]
        next(row["script"]["script"] for row in rows if "script" in row)["source"] = "return true;"
        variants.append(monitor)
        for monitor in variants:
            with self.subTest(), self.assertRaisesRegex(DEPLOY.Refused, "monitor_query_semantics_changed"):
                DEPLOY.validate_monitor(monitor, CANDIDATE, False)

    def test_unknown_query_and_aggregation_fields_fail_closed(self):
        for key in ("post_filter", "runtime_mappings", "script_fields"):
            monitor = copy.deepcopy(CANDIDATE)
            monitor["inputs"][0]["search"]["query"][key] = {}
            with self.subTest(key=key), self.assertRaisesRegex(DEPLOY.Refused, "unexpected_query_field"):
                DEPLOY.validate_monitor(monitor, CANDIDATE, False)
        monitor = copy.deepcopy(CANDIDATE)
        monitor["inputs"][0]["search"]["query"]["aggs"]["services"]["scripted_metric"] = {"map_script": "x"}
        with self.assertRaisesRegex(DEPLOY.Refused, "unexpected_query_field"):
            DEPLOY.validate_monitor(monitor, CANDIDATE, False)

    def test_strict_json_and_id_validation(self):
        for value in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e309}'):
            with self.assertRaises(DEPLOY.Refused):
                DEPLOY.strict_json(value)
        for value in ("../../monitor", "valid?if_seq_no=3", "", None):
            with self.assertRaises(DEPLOY.Refused):
                DEPLOY.safe_id(value)

    def test_curl_get_never_inherits_operator_stdin(self):
        api = DEPLOY.CurlAPI.__new__(DEPLOY.CurlAPI)
        api.container_id = "a" * 64
        captured = []
        def run(command, **kwargs):
            captured.append(kwargs)
            kwargs["stdout"].write(b'{"ok":true}\n200')
            return type("Result", (), {"returncode": 0})()
        with patch.object(DEPLOY.subprocess, "run", side_effect=run):
            api("GET", DEPLOY.API + "/test-id")
            api("POST", DEPLOY.API, {"enabled": False})
        self.assertEqual(captured[0]["stdin"], DEPLOY.subprocess.DEVNULL)
        self.assertNotIn("input", captured[0])
        self.assertEqual(json.loads(captured[1]["input"]), {"enabled": False})
        self.assertNotIn("stdin", captured[1])


if __name__ == "__main__":
    unittest.main()
