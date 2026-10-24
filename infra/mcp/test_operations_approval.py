#!/usr/bin/env python3
"""Approval binding, temporary-containment decisions and authenticated HTTP routes."""
import copy
import importlib.util
import io
import ipaddress
import json
import secrets
import time
import unittest
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("ops_test", Path(__file__).with_name("operations_approval.py"))
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)


def operation(kind="service"):
    expiry = int(time.time()) + 300
    if kind == "service":
        target = "a:waf"
        plan = {"action": "reload", "before_observation_sha256": "1" * 64,
                "before_summary": "container=abc123 running=true health=healthy StartedAt=2026-10-13T00:00:00Z",
                "policy_sha256": "2" * 64, "reason": "승인된 설정을 다시 읽기"}
    else:
        target = "a:incident-ip"
        plan = {"ip": "8.8.4.4", "action": "temporary_block", "temporary_expires_at": expiry,
                "keep_seconds": 3600, "before_observation_sha256": "1" * 64, "evidence_sha256": "3" * 64}
    return {"request_id": secrets.token_hex(16), "kind": kind, "target": target, "plan": plan,
            "plan_sha256": ops.digest(plan), "expires_at": expiry, "requested_by": "hermes"}


class OperationsTest(unittest.TestCase):
    def setUp(self):
        self.cards = []
        self.broker = ops.OperationsBroker(post=self.post, enabled=lambda: True,
            source_ok=lambda peer: peer == "127.0.0.1", approvers=lambda: frozenset(("operator",)),
            action_url=lambda: "http://localhost:8090")

    def post(self, payload):
        self.cards.append(payload)
        return True, "ok"

    def create(self, req=None):
        req = req or operation()
        result, status = self.broker.create(req)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["status"], "pending")
        self.assertTrue(result["posted"])
        return result

    def click(self, decision=None, **changes):
        ctx = dict(self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"])
        if decision:
            ctx["decision"] = decision
        ctx.update(changes)
        return self.broker.action({"user_id": "operator", "context": ctx}, "127.0.0.1")

    def consume(self, created):
        return self.broker.consume(created["operation_id"], {"proposal_digest": created["proposal_digest"]})

    def result(self, created, status="applied", **changes):
        req = {"proposal_digest": created["proposal_digest"], "status": status,
               "after_observation_sha256": "9" * 64, "detail": "실행 후 상태 확인 완료"}
        req.update(changes)
        return self.broker.result(created["operation_id"], req)

    def test_card_kst_preserves_exact_plan_binding_across_date_boundary(self):
        req = operation()
        req['plan']['before_summary'] = 'container=abc; started=2026-10-23T22:03:11.971632878Z; running=True'
        req['plan_sha256'] = ops.digest(req['plan'])
        before = copy.deepcopy(req)
        created = self.create(req)
        text = self.cards[-1]['attachments'][0]['text']
        self.assertIn('2026-10-24T07:03:11.971632+09:00 (KST)', text)
        self.assertNotIn('2026-10-23T22:03', text)
        self.assertEqual(req, before)
        self.assertEqual(created['plan_sha256'], before['plan_sha256'])
        self.assertEqual(self.broker.records[created['request_id']]['plan'], before['plan'])

    def test_service_plan_is_complete_and_observations_are_distinct_from_plan_hash(self):
        req = operation()
        created = self.create(req)
        self.assertEqual(created["operation_id"], req["request_id"])
        self.assertEqual(created["proposal_digest"], ops.digest(req))
        text = self.cards[-1]["attachments"][0]["text"]
        for item in (req["target"], req["plan_sha256"], req["plan"]["before_observation_sha256"],
                     req["plan"]["policy_sha256"], req["plan"]["reason"], "reload"):
            self.assertIn(item, text)
        self.assertIn(ops.display_summary_kst(req["plan"]["before_summary"]), text)
        self.assertIn("예상 변경 후 상태", text)
        self.assertLess(len(text.encode()), 8000)
        self.assertNotIn("nonce", created)
        req["plan"]["action"] = "restart"
        self.assertEqual(self.broker.records[created["operation_id"]]["plan"]["action"], "reload")
        self.assertEqual(self.consume(created)[1], 409)
        self.click()
        self.assertEqual(self.consume(created)[0]["status"], "consumed")
        self.assertEqual(self.consume(created)[1], 409)
        result, code = self.result(created)
        self.assertEqual((code, result["status"]), (200, "applied"))
        self.assertEqual(result["after_observation_sha256"], "9" * 64)
        self.assertNotEqual(result["after_observation_sha256"], result["plan_sha256"])
        count = len(self.cards)
        self.assertEqual(self.result(created)[1], 200)
        self.assertEqual(len(self.cards), count)
        self.assertEqual(self.result(created, detail="changed")[1], 409)

    def test_create_idempotency_rejects_other_plan_and_never_reposts(self):
        req = operation()
        created = self.create(req)
        self.assertEqual(self.broker.create(req), (created, 200))
        self.assertEqual(len(self.cards), 1)
        other = copy.deepcopy(req)
        other["plan"]["action"] = "restart"
        other["plan_sha256"] = ops.digest(other["plan"])
        self.assertEqual(self.broker.create(other)[1], 409)
        with patch.object(ops.time, "time", return_value=req["expires_at"] + 1):
            expired, status = self.broker.create(req)
        self.assertEqual((status, expired["status"]), (200, "expired"))
        self.assertEqual(len(self.cards), 1)

    def test_allowlists_and_exact_schema_reject_arbitrary_operations(self):
        variants = []
        for target, action in (("a:docker", "restart"), ("a:suricata", "reload"),
                               ("b:wazuh-manager", "reload"), ("b:wazuh-dashboard", "reload")):
            req = operation(); req["target"] = target; req["plan"]["action"] = action; variants.append(req)
        req = operation(); req["plan"]["command"] = "id"; variants.append(req)
        req = operation(); req["plan"]["reason"] = "bad\u202e"; variants.append(req)
        req = operation(); req["plan"]["policy_sha256"] = ""; variants.append(req)
        req = operation(); req["expires_at"] = int(time.time()) + 1000; variants.append(req)
        req = operation(); req["status"] = "approved"; variants.append(req)
        for address in ("127.0.0.1", "10.0.0.1", "192.0.2.1", "224.0.0.1", "::1", "0.0.0.0"):
            req = operation("containment"); req["plan"]["ip"] = address; variants.append(req)
        req = operation("containment"); req["plan"]["keep_seconds"] = 86400; variants.append(req)
        req = operation("containment"); del req["plan"]["evidence_sha256"]; variants.append(req)
        req = operation("containment"); req["plan"]["temporary_expires_at"] += 1; variants.append(req)
        for req in variants:
            req["plan_sha256"] = ops.digest(req["plan"])
            with self.subTest(req=req):
                self.assertEqual(self.broker.create(req)[1], 400)
        req = operation(); req["plan_sha256"] = "0" * 64
        self.assertEqual(self.broker.create(req)[1], 400)
        self.assertFalse(self.cards)

    def test_every_supported_service_action_can_be_proposed(self):
        for target, actions in ops.SERVICE_ACTIONS.items():
            for action in actions:
                req = operation(); req["target"] = target; req["plan"]["action"] = action
                req["plan_sha256"] = ops.digest(req["plan"])
                self.create(req)

    def test_callback_binds_kind_nonce_digest_peer_and_named_approver(self):
        created = self.create()
        for change in ({"kind": "containment"}, {"nonce": "0" * 64},
                       {"proposal_digest": "0" * 64}, {"decision": "keep"}):
            self.assertIn("인증", self.click(**change)["ephemeral_text"])
        ctx = self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"]
        for user, peer in (("other", "127.0.0.1"), ("operator", "1.2.3.4")):
            rejected = self.broker.action({"user_id": user, "context": ctx}, peer)
            self.assertNotIn("update", rejected)
        self.assertEqual(self.broker.get(created["operation_id"])[0]["status"], "pending")
        self.click()
        self.assertIn("처리", self.click()["ephemeral_text"])
        self.assertEqual(self.broker.consume(created["operation_id"], {"proposal_digest": "0" * 64})[1], 409)

    def test_failed_or_incomplete_post_is_never_approvable(self):
        req = operation()
        def while_posting(payload):
            self.cards.append(payload)
            self.assertEqual(self.broker.get(req["request_id"])[0]["status"], "posting")
            self.assertEqual(self.broker.create(req)[1], 409)
            self.assertIn("처리", self.click()["ephemeral_text"])
            return False, "secret transport detail"
        self.broker.post = while_posting
        response, code = self.broker.create(req)
        self.assertEqual((code, response["status"]), (502, "error"))
        self.assertNotIn("secret transport detail", str(response))
        self.assertEqual(self.broker.create(req)[1], 502)
        self.assertEqual(len(self.cards), 1)
        self.assertIn("처리", self.click()["ephemeral_text"])

    def test_post_success_after_expiry_is_not_approvable(self):
        req = operation()
        now = [time.time()]
        def late_post(payload):
            self.cards.append(payload)
            now[0] = req["expires_at"] + 1
            return True, "ok"
        self.broker.post = late_post
        with patch.object(ops.time, "time", side_effect=lambda: now[0]):
            response, code = self.broker.create(req)
        self.assertEqual((code, response["status"]), (502, "expired"))
        self.assertEqual(self.consume(response)[1], 409)

    def test_service_denial_and_expiry_never_execute_and_preconsume_abort_reports(self):
        for decision in ("approve", "deny", None):
            created = self.create()
            if decision:
                self.click(decision)
            if decision != "approve":
                self.assertEqual(self.consume(created)[1], 409)
            self.assertEqual(self.result(created, "applied")[1], 409)
            self.assertEqual(self.result(created, "aborted")[0]["status"], "aborted")
            self.assertEqual(self.consume(created)[1], 409)
        req = operation()
        created = self.create(req)
        self.click()
        with patch.object(ops.time, "time", return_value=req["expires_at"] + 1):
            self.assertEqual(self.consume(created)[1], 409)
            self.assertEqual(self.result(created, "aborted")[1], 200)

    def test_containment_keep_release_and_auto_expiry_are_separate_decisions(self):
        for decision in ("keep", "release", "expired"):
            req = operation("containment")
            created = self.create(req)
            text = self.cards[-1]["attachments"][0]["text"]
            for phrase in ("이미 임시 차단", "10분", "60분", req["plan"]["evidence_sha256"]):
                self.assertIn(phrase, text)
            if decision == "expired":
                with patch.object(ops.time, "time", return_value=req["expires_at"] + 1):
                    consumed, code = self.consume(created)
            else:
                self.click(decision)
                consumed, code = self.consume(created)
            self.assertEqual((code, consumed["status"], consumed["consumed_decision"]),
                             (200, "consumed", decision))
            if decision != "keep":
                self.assertEqual(self.result(created, "kept")[1], 409)
            outcome = {"keep": "kept", "release": "released", "expired": "expired"}[decision]
            self.assertEqual(self.result(created, outcome)[1], 200)
        self.assertEqual(self.broker.health()["active_operations"], 0)

    def test_results_retry_identical_payload_only_and_are_bounded(self):
        created = self.create()
        self.click()
        self.consume(created)
        self.broker.post = lambda payload: (False, "secret")
        self.assertEqual(self.result(created)[1], 502)
        self.assertEqual(self.result(created, detail="different")[1], 409)
        self.broker.post = self.post
        self.assertEqual(self.result(created)[0]["result_attempts"], 2)
        self.assertEqual(self.result(created)[0]["result_attempts"], 2)
        second = self.create()
        self.click()
        self.consume(second)
        self.broker.post = lambda payload: (False, "secret")
        self.assertEqual([self.result(second)[1] for _ in range(4)], [502, 502, 502, 429])

    def test_health_tracks_unfinished_work_without_secrets(self):
        created = self.create()
        health = self.broker.health()
        self.assertEqual(health["active_operations"], 1)
        self.assertEqual(health["operation_status_counts"], {"pending": 1})
        self.assertNotIn("nonce", json.dumps(health))
        self.click()
        self.consume(created)
        self.assertEqual(self.broker.health()["operation_status_counts"], {"consumed": 1})
        self.result(created)
        self.assertEqual(self.broker.health()["active_operations"], 0)


class OperationsHttpTest(unittest.TestCase):
    def test_routes_require_hmac_and_callback_cannot_cross_rule_protocol(self):
        spec = importlib.util.spec_from_file_location("ops_soc_test", Path(__file__).with_name("soc_bot.py"))
        bot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bot)
        bot.RULE_BROKER_TOKEN = "r" * 48
        bot.BROKER_TOKEN = "b" * 48
        bot.RULE_APPROVERS = frozenset(("operator",))
        bot.RULE_MM_SOURCES = (ipaddress.ip_network("127.0.0.1/32"),)
        bot.MM_WEBHOOK = "http://invalid.local/webhook"
        cards = []

        def request(method, path, body=None, signed=True, peer="127.0.0.1"):
            handler = object.__new__(bot.Handler)
            handler.path, handler.client_address = path, (peer, 1)
            raw = json.dumps(body).encode() if body is not None else b""
            handler.headers = {"Content-Length": str(len(raw))}
            nonce = secrets.token_hex(16)
            if signed:
                timestamp = str(int(time.time()))
                handler.headers.update({"X-Rule-Timestamp": timestamp, "X-Rule-Nonce": nonce,
                    "X-Rule-Signature": bot._rule_request_signature(method, path, timestamp, nonce, raw)})
            handler.rfile, handler.wfile = io.BytesIO(raw), io.BytesIO()
            with patch.object(handler, "send_response") as response, patch.object(handler, "send_header") as header, \
                    patch.object(handler, "end_headers"):
                getattr(handler, "do_" + method)()
            code = response.call_args.args[0]
            data = handler.wfile.getvalue()
            headers = dict(call.args for call in header.call_args_list)
            if signed and code != 401:
                self.assertEqual(headers.get("X-Rule-Response-Signature"), bot._rule_response_signature(nonce, code, data))
            return code, json.loads(data)

        with patch.object(bot, "post_mm", side_effect=lambda payload: (cards.append(payload) or True, "ok")), \
                patch.object(bot, "_operation_audit"):
            req = operation()
            self.assertEqual(request("POST", "/operations", req, signed=False)[0], 401)
            code, created = request("POST", "/operations", req)
            self.assertEqual(code, 200)
            oid = created["operation_id"]
            self.assertEqual(request("GET", "/operations/" + oid)[1]["status"], "pending")
            health = request("GET", "/operations/health")[1]
            self.assertEqual((health["active_operations"], health["active_rule_changes"]), (1, 0))
            ctx = cards[-1]["attachments"][0]["actions"][0]["integration"]["context"]
            callback = {"user_id": "operator", "context": ctx}
            self.assertNotIn("update", request("POST", "/rule-actions", callback, signed=False)[1])
            self.assertNotIn("update", request("POST", "/operation-actions", callback, signed=False, peer="1.2.3.4")[1])
            self.assertIn("update", request("POST", "/operation-actions", callback, signed=False)[1])
            consume = {"proposal_digest": created["proposal_digest"]}
            self.assertEqual(request("POST", "/operations/" + oid + "/consume", consume, signed=False)[0], 401)
            self.assertEqual(request("POST", "/operations/" + oid + "/consume", consume)[1]["status"], "consumed")
            result = {**consume, "status": "applied", "after_observation_sha256": "9" * 64, "detail": "checked"}
            self.assertEqual(request("POST", "/operations/" + oid + "/result", result)[1]["status"], "applied")
            self.assertEqual(request("GET", "/operations/health")[1]["active_operations"], 0)


if __name__ == "__main__":
    unittest.main()
