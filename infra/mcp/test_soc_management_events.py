#!/usr/bin/env python3
"""Real SQLite durability and authenticated broker boundary, no external calls."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("management_soc_test", Path(__file__).with_name("soc_bot.py"))
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)
events = bot._management_module


def incident():
    return {"event_id": "1792030000.123", "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": "001", "rule_id": "100110", "level": 9,
            "src_ip": "192.168.16.2", "location": events.LOCATION}


def index_response():
    return {"timed_out": False, "_shards": {"total": 2, "successful": 2, "failed": 0},
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{
                "_index": "wazuh-alerts-4.x-2026.10.15", "_id": "index-document-real-id",
                "_source": {"id": "1792030000.123", "timestamp": "2026-10-15T05:10:00.123+0000",
                    "location": events.LOCATION, "agent": {"id": "001", "name": "sensor"},
                    "rule": {"id": "100110", "level": 9, "description": "telemetry"},
                    "data": {"src_ip": "192.168.16.2"}}}]}}


class ManagementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="capstone-management-test-", dir="/private/tmp")
        self.root = Path(self.tmp.name)
        self.db = self.root / "events.sqlite3"
        self.env = patch.dict(os.environ, {"SOC_MANAGEMENT_EVENTS_DB": str(self.db)})
        self.env.start()
        self.stderr = patch("sys.stderr", io.StringIO())
        self.stderr.start()
        self.store = events.Outbox()
        self.store.initialize()
        bot.MANAGEMENT_OUTBOX_ERROR = False
        bot.RULE_APPROVALS.clear()
        bot.RULE_NONCES.clear()
        bot.OPERATIONS.records.clear()
        bot.RULE_BROKER_TOKEN = "r" * 48
        bot.BROKER_TOKEN = "b" * 48
        bot.RULE_APPROVERS = frozenset(("operator",))
        bot.RULE_MM_SOURCES = (ipaddress.ip_network("127.0.0.1/32"),)
        bot.MM_WEBHOOK = "https://invalid.test/private-hook-secret"
        self.cards = []
        self.post = patch.object(bot, "post_mm", side_effect=lambda value: (self.cards.append(value) or True, "ok"))
        self.post.start()

    def tearDown(self):
        self.post.stop()
        self.stderr.stop()
        self.env.stop()
        self.tmp.cleanup()

    def request(self, method, path, body=None, signed=True, raw=None, nonce=None):
        handler = object.__new__(bot.Handler)
        handler.path, handler.client_address = path, ("127.0.0.1", 1)
        raw = raw if raw is not None else json.dumps(body).encode() if body is not None else b""
        handler.headers = {"Content-Length": str(len(raw))}
        nonce = nonce or secrets.token_hex(16)
        if signed:
            stamp = str(int(time.time()))
            handler.headers.update({"X-Rule-Timestamp": stamp, "X-Rule-Nonce": nonce,
                "X-Rule-Signature": bot._rule_request_signature(method, path, stamp, nonce, raw)})
        handler.rfile, handler.wfile = io.BytesIO(raw), io.BytesIO()
        with patch.object(handler, "send_response") as status, patch.object(handler, "send_header") as headers, patch.object(handler, "end_headers"):
            getattr(handler, "do_" + method)()
        code = status.call_args.args[0]
        data = handler.wfile.getvalue()
        if signed and code != 401 and len(raw) <= 4096:
            self.assertEqual(dict(call.args for call in headers.call_args_list).get("X-Rule-Response-Signature"),
                             bot._rule_response_signature(nonce, code, data))
        return code, json.loads(data)

    def rule(self):
        diff = "--- old\n+++ new\n-old\n+new\n"
        req = {"target": "a:suricata-local", "base_sha256": "1" * 64, "candidate_sha256": "2" * 64,
               "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(), "diff": diff,
               "requested_by": "hermes", "expires_at": int(time.time()) + 120}
        created, code = bot.rule_change_create(req)
        self.assertEqual(code, 200)
        context = self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"]
        return req, created, context

    def service(self):
        plan = {"action": "reload", "before_observation_sha256": "1" * 64, "policy_sha256": "2" * 64,
                "before_summary": "running", "reason": "request"}
        req = {"request_id": secrets.token_hex(16), "kind": "service", "target": "a:waf", "plan": plan,
               "plan_sha256": bot._operations_module.digest(plan), "expires_at": int(time.time()) + 120,
               "requested_by": "hermes"}
        result, code = bot.OPERATIONS.create(req)
        self.assertEqual(code, 200)
        context = self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"]
        return result, context

    def test_durable_reopen_dedup_and_conflicting_payload(self):
        seq = self.store.append("test:1", "incident", {"value": 1}, now=20)
        self.assertEqual(events.Outbox().append("test:1", "incident", {"value": 1}, now=99), seq)
        self.assertEqual(events.Outbox().read()["events"][0]["at"], 20)
        with self.assertRaisesRegex(events.OutboxError, "conflict"):
            self.store.append("test:1", "incident", {"value": 2})
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    def test_cursor_page_does_not_skip_unreturned_records(self):
        for number in range(3):
            self.store.append("test:%d" % number, "incident", {"value": number})
        first = self.store.read(limit=1)
        self.assertEqual(first["latest_seq"], 3)
        self.assertEqual([row["seq"] for row in self.store.read(after=first["events"][-1]["seq"])["events"]], [2, 3])

    def test_read_missing_does_not_create_database(self):
        self.db.unlink()
        self.assertEqual(self.request("GET", "/management/events")[0], 503)
        self.assertFalse(self.db.exists())

    def test_database_symlink_or_unsafe_parent_is_refused(self):
        other = self.root / "other"
        self.db.rename(other)
        self.db.symlink_to(other)
        with self.assertRaises(events.OutboxError):
            self.store.read()
        self.db.unlink()
        other.rename(self.db)
        self.root.chmod(0o755)
        with self.assertRaises(events.OutboxError):
            self.store.read()
        self.root.chmod(0o700)

    def test_all_management_routes_require_hmac(self):
        for method, path, body in (("GET", "/management/events", None), ("GET", "/management/alerts", None),
                                   ("POST", "/management/incidents", incident())):
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path, body, signed=False)[0], 401)
        self.assertEqual(self.store.read()["latest_seq"], 0)

    def test_query_bounds_and_duplicates_are_rejected(self):
        for path in ("events?limit=101", "events?after=-1", "events?limit=1&limit=2", "events?after=", "events?unknown=1",
                     "alerts?minutes=0", "alerts?limit=501", "alerts?limit=1&limit=2"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", "/management/" + path)[0], 400)

    def test_incident_queue_private_source_and_replay_dedup(self):
        req = incident()
        code, first = self.request("POST", "/management/incidents", req)
        self.assertEqual(code, 200)
        self.assertIs(first["queued"], True)
        self.assertEqual(self.request("POST", "/management/incidents", req)[1], first)
        event = self.request("GET", "/management/events")[1]["events"][0]
        self.assertEqual((event["kind"], event["payload"]), ("incident", req))
        changed = dict(req, src_ip="192.168.16.3")
        self.assertEqual(self.request("POST", "/management/incidents", changed)[0], 409)

    def test_incident_validation_bounds_and_no_token_fields(self):
        base = incident()
        bad = [dict(base, token="secret"), dict(base, level=True), dict(base, rule_id="86601"),
               dict(base, timestamp="2026-01-01T00:00:00Z"), dict(base, timestamp="2026-10-15T01:00:00"),
               dict(base, event_id="x" * 129), dict(base, event_id="hello world"),
               dict(base, location="/tmp/eve.json"), dict(base, src_ip="::1")]
        for req in bad:
            with self.subTest(req=req):
                self.assertEqual(self.request("POST", "/management/incidents", req)[0], 400)
        self.assertEqual(self.store.read()["latest_seq"], 0)

    def test_duplicate_json_and_oversize_body_rejected(self):
        raw = json.dumps(incident()).encode().replace(b'"level": 9', b'"level": 9,"level": 9')
        self.assertEqual(self.request("POST", "/management/incidents", raw=raw)[0], 400)
        self.assertEqual(self.request("POST", "/management/incidents", raw=b" " * 4097)[0], 400)

    def test_hmac_nonce_replay_rejected_without_second_event(self):
        nonce = secrets.token_hex(16)
        req = incident()
        self.assertEqual(self.request("POST", "/management/incidents", req, nonce=nonce)[0], 200)
        self.assertEqual(self.request("POST", "/management/incidents", req, nonce=nonce)[0], 401)
        self.assertEqual(len(self.store.read()["events"]), 1)

    def test_rule_approve_result_events_bound_and_secret_free(self):
        req, created, context = self.rule()
        bot.rule_change_action({"user_id": "operator", "context": context}, "127.0.0.1")
        rid, digest = created["proposal_id"], created["proposal_digest"]
        bot.rule_change_consume(rid, {"proposal_digest": digest})
        result = {"proposal_digest": digest, "status": "applied", "before_sha256": req["base_sha256"],
                  "after_sha256": req["candidate_sha256"], "readback_sha256": req["candidate_sha256"], "detail": "checked"}
        self.assertEqual(bot.rule_change_result(rid, result)[1], 200)
        self.assertEqual(bot.rule_change_result(rid, result)[1], 200)
        rows = self.store.read()["events"]
        self.assertEqual([row["payload"]["event"] for row in rows], ["created", "decision", "consumed", "result"])
        self.assertTrue(all(row["payload"]["proposal_id"] == rid for row in rows))
        text = json.dumps(rows)
        for secret in (context["nonce"], bot.RULE_BROKER_TOKEN, bot.BROKER_TOKEN, bot.MM_WEBHOOK, req["diff"]):
            self.assertNotIn(secret, text)

    def test_rule_denial_and_expiry_are_events_without_execution(self):
        _, created, context = self.rule()
        bot.rule_change_action({"user_id": "operator", "context": dict(context, decision="deny")}, "127.0.0.1")
        _, second, _ = self.rule()
        bot.RULE_APPROVALS[second["proposal_id"]]["expires_at"] = int(time.time()) - 1
        code, body = self.request("GET", "/management/events")
        self.assertEqual(code, 200)
        self.assertEqual([row["payload"]["status"] for row in body["events"]], ["pending", "denied", "pending", "expired"])

    def test_operation_report_error_preserves_actual_outcome(self):
        created, context = self.service()
        bot.OPERATIONS.action({"user_id": "operator", "context": context}, "127.0.0.1")
        oid, digest = created["request_id"], created["proposal_digest"]
        bot.OPERATIONS.consume(oid, {"proposal_digest": digest})
        req = {"proposal_digest": digest, "status": "applied", "after_observation_sha256": "9" * 64, "detail": "checked"}
        with patch.object(bot, "post_mm", return_value=(False, "private response")):
            response, status = bot.OPERATIONS.result(oid, req)
        self.assertEqual((status, response["status"], response["result_status"]), (502, "report_error", "applied"))
        row = self.store.read()["events"][-1]
        self.assertEqual((row["kind"], row["payload"]["status"], row["payload"]["result_status"]), ("operation", "report_error", "applied"))

    def test_operation_denial_expiry_and_post_error_are_retained(self):
        _, context = self.service()
        bot.OPERATIONS.action({"user_id": "operator", "context": dict(context, decision="deny")}, "127.0.0.1")
        second, _ = self.service()
        bot.OPERATIONS.records[second["request_id"]]["expires_at"] = int(time.time()) - 1
        self.assertEqual(self.request("GET", "/management/events")[0], 200)
        rows = self.store.read()["events"]
        self.assertEqual([row["payload"]["status"] for row in rows], ["pending", "denied", "pending", "expired"])
        plan = {"action": "reload", "before_observation_sha256": "1" * 64, "policy_sha256": "2" * 64,
                "before_summary": "running", "reason": "request"}
        req = {"request_id": secrets.token_hex(16), "kind": "service", "target": "a:waf", "plan": plan,
               "plan_sha256": bot._operations_module.digest(plan), "expires_at": int(time.time()) + 120,
               "requested_by": "hermes"}
        with patch.object(bot, "post_mm", return_value=(False, "private response")):
            self.assertEqual(bot.OPERATIONS.create(req)[1], 502)
        self.assertEqual(self.store.read()["events"][-1]["payload"]["event"], "post_error")

    def test_rule_abort_and_failed_result_have_distinct_outcomes(self):
        req, created, context = self.rule()
        bot.rule_change_action({"user_id": "operator", "context": context}, "127.0.0.1")
        abort = {"proposal_digest": created["proposal_digest"], "readback_sha256": req["base_sha256"], "detail": "state changed"}
        self.assertEqual(bot.rule_change_abort(created["proposal_id"], abort)[1], 200)
        self.assertEqual(self.store.read()["events"][-1]["payload"]["result_status"], "not_applied")
        req, created, context = self.rule()
        bot.rule_change_action({"user_id": "operator", "context": context}, "127.0.0.1")
        bot.rule_change_consume(created["proposal_id"], {"proposal_digest": created["proposal_digest"]})
        result = {"proposal_digest": created["proposal_digest"], "status": "recovery_failed", "before_sha256": req["base_sha256"],
                  "after_sha256": req["candidate_sha256"], "readback_sha256": "9" * 64, "detail": "restore failed"}
        with patch.object(bot, "post_mm", return_value=(False, "private response")):
            self.assertEqual(bot.rule_change_result(created["proposal_id"], result)[1], 502)
        row = self.store.read()["events"][-1]["payload"]
        self.assertEqual((row["status"], row["result_status"]), ("report_error", "recovery_failed"))

    def test_missing_outbox_transition_is_latched_not_healthy_empty(self):
        with patch.object(events.Outbox, "append", side_effect=OSError("disk failed")):
            self.rule()
        self.assertTrue(bot.MANAGEMENT_OUTBOX_ERROR)
        self.assertEqual(self.request("GET", "/management/events")[0], 503)
        self.assertEqual(len(bot.RULE_APPROVALS), 1)

    def test_alert_identity_source_time_and_native_id_preserved(self):
        fixture = index_response()
        with patch.object(bot, "idx_search", return_value=fixture) as search:
            code, output = self.request("GET", "/management/alerts?minutes=5&limit=500")
        self.assertEqual(code, 200)
        row = output["alerts"][0]
        self.assertEqual((row["_index"], row["_id"], row["event_id"], row["src_ip"]),
                         ("wazuh-alerts-4.x-2026.10.15", "index-document-real-id", "1792030000.123", "192.168.16.2"))
        self.assertEqual(row["timestamp"], fixture["hits"]["hits"][0]["_source"]["timestamp"])
        self.assertFalse(output["truncated"])
        self.assertEqual(search.call_args.args[1]["sort"], [{"timestamp": "asc"}])
        self.assertEqual(search.call_args.args[1]["query"]["bool"]["filter"], [
            {"range": {"timestamp": {"gte": "now-5m", "lte": "now"}}},
            {"range": {"rule.level": {"gte": 9}}}])

    def test_alert_partial_timeout_or_missing_identity_is_unavailable(self):
        fixtures = []
        failed = index_response(); failed["_shards"]["failed"] = 1; fixtures.append(failed)
        timed = index_response(); timed["timed_out"] = True; fixtures.append(timed)
        identity = index_response(); del identity["hits"]["hits"][0]["_id"]; fixtures.append(identity)
        low_level = index_response(); low_level["hits"]["hits"][0]["_source"]["rule"]["level"] = 8; fixtures.append(low_level)
        for fixture in fixtures:
            with patch.object(bot, "idx_search", return_value=fixture):
                self.assertEqual(self.request("GET", "/management/alerts")[0], 503)

    def test_alert_truncation_is_explicit_and_empty_is_distinct_from_error(self):
        fixture = index_response(); fixture["hits"]["total"]["value"] = 501
        with patch.object(bot, "idx_search", return_value=fixture):
            result = bot.management_alerts()
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total"], 501)
        fixture["hits"] = {"total": {"value": 0, "relation": "eq"}, "hits": []}
        with patch.object(bot, "idx_search", return_value=fixture):
            self.assertEqual(self.request("GET", "/management/alerts")[1]["alerts"], [])
        with patch.object(bot, "idx_search", side_effect=OSError("credential must not leak")):
            code, result = self.request("GET", "/management/alerts")
        self.assertEqual(code, 503)
        self.assertNotIn("credential", json.dumps(result))

    def test_summary_failed_queries_never_report_healthy_or_zero(self):
        with patch.object(bot, "list_agents", return_value=(None, "failed")), patch.object(bot, "agg_alerts", return_value=(None, "failed")), patch.object(bot, "vuln_count", return_value=None):
            result = json.dumps(bot.build_summary(), ensure_ascii=False)
        self.assertIn("조회 실패", result)
        self.assertNotIn("이상 없음", result)
        self.assertNotIn('"value": "0"', result)

    def test_report_telemetry_never_selects_action_from_ip_prefix(self):
        agg = {"total": 1, "rules": [("x", 1)], "src": [("192.168.16.2", 1)], "agent": [("sensor", 1)]}
        row = {"ts": "KST", "id": "100110", "level": 9, "desc": "x", "srcip": "192.168.16.2"}
        with patch.object(bot, "agg_alerts", return_value=(agg, None)), patch.object(bot, "recent_alerts", return_value=([row], None)):
            result = json.dumps(bot.build_report(5), ensure_ascii=False)
        self.assertIn("LLM 관리 에이전트", result)
        self.assertNotIn("자동 차단 보류", result)
        self.assertNotIn("차단 검토", result)
        with patch.object(bot, "agg_alerts", return_value=(agg, None)), patch.object(bot, "recent_alerts", return_value=([], "failed")):
            self.assertIn("error", bot.build_report(5))


if __name__ == "__main__":
    unittest.main()
