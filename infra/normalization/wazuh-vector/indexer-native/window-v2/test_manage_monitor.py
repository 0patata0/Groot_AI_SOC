#!/usr/bin/env python3
"""Finite mutation-boundary tests; native query tests are separate."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location("manager", ROOT / "manage-monitor-b.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
# Test the current candidate before the production SHA is sealed. This override
# is confined to this test process and never imported by the operator CLI.
m.V2_SHA = hashlib.sha256((ROOT / "monitor.json").read_bytes()).hexdigest()


class Store:
    def __init__(self, value):
        self.value = copy.deepcopy(value)
        self.writes = []

    def write(self, value):
        self.value = copy.deepcopy(value)
        self.writes.append(copy.deepcopy(value))


class API:
    def __init__(self, response):
        self.response = copy.deepcopy(response)
        self.puts = []
        self.tamper = None
        self.uncertain = False
        self.readback_tamper = False

    def __call__(self, method, path, payload=None, expected=(200,)):
        if path.endswith("/_search"):
            return 200, {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
                         "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [
                             {"_id": self.response["_id"], "_source": {"monitor": self.response["monitor"]}}]}}
        if method == "GET":
            result = copy.deepcopy(self.response)
            if self.readback_tamper and self.puts:
                result["_seq_no"] += 1
            return 200, result
        assert method == "PUT"
        assert "if_seq_no=" + str(self.response["_seq_no"]) + "&if_primary_term=1" in path
        self.puts.append(copy.deepcopy(payload))
        if self.uncertain:
            raise TimeoutError("uncertain")
        self.response["monitor"] = copy.deepcopy(payload)
        self.response["monitor"]["last_update_time"] = 2
        self.response["_seq_no"] += 1
        if self.tamper:
            self.tamper(self.response)
        return 200, copy.deepcopy(self.response)


class MutationTests(unittest.TestCase):
    def setUp(self):
        self.registry = m.sources()
        self.v1, candidate = self.registry["v1"]
        monitor = copy.deepcopy(candidate)
        monitor.update(enabled=True, enabled_time=1, last_update_time=1, schema_version=8,
                       user={"name": "test-admin", "roles": ["owned-role"]}, data_sources={"keep": True})
        monitor["triggers"][0]["query_level_trigger"]["future_metadata"] = "preserve"
        response = {"_id": "owned-monitor", "_seq_no": 5, "_primary_term": 1, "monitor": monitor}
        self.state = self.v1.saved_record(response, candidate, True)
        self.api = API(response)
        self.store = Store(self.state)
        self.directory = tempfile.TemporaryDirectory(prefix="capstone-monitor-unit-")
        self.backup_count = 0

    def tearDown(self):
        self.directory.cleanup()

    def backup(self, *args):
        self.backup_count += 1
        path = Path(self.directory.name) / str(self.backup_count)
        path.mkdir(mode=0o700)
        return path

    def run_migration(self, operation="upgrade"):
        return m.migrate(operation, self.api, self.store, self.store.value, self.registry, self.backup)

    def test_upgrade_preserves_identity_permissions_extras(self):
        old = copy.deepcopy(self.api.response["monitor"])
        result = self.run_migration()
        self.assertTrue(result["changed"])
        self.assertEqual(result["monitor_id"], "owned-monitor")
        self.assertTrue(m.unchanged_fields(old, self.api.response["monitor"]))
        self.assertEqual(self.store.value["candidate_sha256"], m.V2_SHA)
        self.assertEqual(self.store.value["phase"], "enabled")
        self.assertEqual(len(self.api.puts), 1)
        self.assertEqual(self.store.writes[0]["phase"], "upgrade_pending")

    def test_same_version_is_verified_noop(self):
        self.run_migration()
        self.assertFalse(self.run_migration()["changed"])
        self.assertEqual(len(self.api.puts), 1)

    def test_rollback_is_cas_same_id(self):
        self.run_migration()
        result = self.run_migration("rollback")
        self.assertEqual(result["after_revision"]["_seq_no"], 7)
        self.assertEqual(result["monitor_id"], "owned-monitor")
        self.assertEqual(self.store.value["candidate_sha256"], m.V1_SHA)

    def test_preexisting_remote_edit_refuses_without_put(self):
        self.api.response["_seq_no"] += 1
        with self.assertRaises(Exception):
            self.run_migration()
        self.assertEqual(self.api.puts, [])

    def test_unrecognized_state_refuses_without_put(self):
        self.store.value["candidate_sha256"] = "unowned"
        with self.assertRaises(Exception):
            self.run_migration()
        self.assertEqual(self.api.puts, [])

    def test_pending_refuses_without_put(self):
        self.store.value["phase"] = "upgrade_pending"
        with self.assertRaises(Exception):
            self.run_migration()
        self.assertEqual(self.api.puts, [])

    def test_uncertain_update_no_retry_or_state_commit(self):
        self.api.uncertain = True
        with self.assertRaises(TimeoutError):
            self.run_migration()
        self.assertEqual(len(self.api.puts), 1)
        self.assertEqual(self.store.value["phase"], "upgrade_pending")

    def test_permission_change_refuses_commit(self):
        self.api.tamper = lambda r: r["monitor"]["user"].update(roles=["changed"])
        with self.assertRaises(Exception):
            self.run_migration()
        self.assertEqual(self.store.value["phase"], "upgrade_pending")

    def test_enabled_time_change_refuses_commit(self):
        self.api.tamper = lambda r: r["monitor"].update(enabled_time=999)
        with self.assertRaises(Exception):
            self.run_migration()
        self.assertEqual(self.store.value["phase"], "upgrade_pending")

    def test_trigger_action_change_refuses_commit(self):
        self.api.tamper = lambda r: r["monitor"]["triggers"][0]["query_level_trigger"].update(actions=[{"id": "bad"}])
        with self.assertRaises(Exception):
            self.run_migration()
        self.assertEqual(self.store.value["phase"], "upgrade_pending")

    def test_changed_readback_leaves_receipt(self):
        self.api.readback_tamper = True
        with self.assertRaises(Exception):
            self.run_migration()
        self.assertEqual(self.store.value["phase"], "upgrade_readback_pending")
        self.assertTrue((Path(self.directory.name) / "1" / "acknowledged-update.json").is_file())

    def test_server_empty_script_defaults_normalize(self):
        current = self.registry["v2"][0]
        aggs = self.registry["v2"][1]["inputs"][0]["search"]["query"]["aggs"]
        modified = copy.deepcopy(aggs)
        for key, value in modified["observation"]["scripted_metric"].items():
            if key.endswith("_script"):
                value["params"] = {}
        self.assertEqual(current.canonical_aggs(aggs), current.canonical_aggs(modified))

    def test_script_params_are_semantic(self):
        current = self.registry["v2"][0]
        aggs = self.registry["v2"][1]["inputs"][0]["search"]["query"]["aggs"]
        modified = copy.deepcopy(aggs)
        modified["observation"]["scripted_metric"]["map_script"]["params"] = {"bypass": True}
        self.assertNotEqual(current.canonical_aggs(aggs), current.canonical_aggs(modified))

    def test_stored_script_unknown_field_refused(self):
        current = self.registry["v2"][0]
        aggs = copy.deepcopy(self.registry["v2"][1]["inputs"][0]["search"]["query"]["aggs"])
        aggs["observation"]["scripted_metric"]["map_script"]["id"] = "arbitrary"
        with self.assertRaises(Exception):
            current.canonical_aggs(aggs)


if __name__ == "__main__":
    unittest.main()
