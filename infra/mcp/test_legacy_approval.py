#!/usr/bin/env python3
"""Legacy response approvals must bind one explicit action and be consumed once."""
import importlib.util
import io
import ipaddress
import json
import time
import unittest
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("legacy_soc_test", Path(__file__).with_name("soc_bot.py"))
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class LegacyApprovalTest(unittest.TestCase):
    def setUp(self):
        bot.BROKER_TOKEN = "b" * 48
        bot.MM_WEBHOOK = "http://invalid.local/hooks/test"
        bot.MM_ACTION_URL = "http://localhost:8090"
        bot.APPROVERS = ["operator"]
        bot.RULE_MM_SOURCES = (ipaddress.ip_network("127.0.0.1/32"),)
        bot.APPROVALS.clear()
        self.cards = []
        self.post = patch.object(bot, "post_mm", side_effect=lambda payload: (self.cards.append(payload) or True, "ok")).start()

    def tearDown(self):
        patch.stopall()
        bot.APPROVALS.clear()

    @staticmethod
    def req(action="block"):
        return {"action": action, "ip": "8.8.4.4", "minutes": 10 if action == "block" else 0,
                "reason": "운영자 검토", "requested_by": "hermes"}

    def create(self, action="block"):
        rid, posted, detail = bot.approval_create(self.req(action))
        self.assertTrue(posted, detail)
        return rid

    def click(self, *, peer="127.0.0.1", user="operator", **changes):
        ctx = dict(self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"])
        ctx.update(changes)
        return bot.approval_action({"user_id": user, "context": ctx}, peer)

    def test_block_and_unblock_require_separate_exact_single_use_approval(self):
        for action in ("block", "unblock"):
            with self.subTest(action=action):
                rid = self.create(action)
                binding = {"request_id": rid, "action": action, "ip": "8.8.4.4",
                           "minutes": 10 if action == "block" else 0}
                public = bot.approval_decision(rid)
                self.assertEqual((public["action"], public["status"]), (action, "pending"))
                self.assertNotIn("nonce", public)
                self.assertIn(action, self.cards[-1]["attachments"][0]["text"])
                self.assertEqual(bot.approval_consume(binding)[1], 409)
                self.click()
                for field, wrong in (("action", "unblock" if action == "block" else "block"),
                                     ("ip", "1.1.1.1"), ("minutes", 20)):
                    self.assertEqual(bot.approval_consume(dict(binding, **{field: wrong}))[1], 409)
                result, code = bot.approval_consume(binding)
                self.assertEqual((code, result["status"], result["by"]), (200, "consumed", "operator"))
                self.assertEqual(bot.approval_consume(binding)[1], 409)

    def test_empty_approver_or_callback_source_configuration_fails_closed(self):
        for key, value in (("APPROVERS", []), ("RULE_MM_SOURCES", ()), ("MM_WEBHOOK", ""), ("BROKER_TOKEN", "")):
            with self.subTest(key=key), patch.object(bot, key, value):
                self.assertFalse(bot.approval_create(self.req())[1])
                self.assertNotIn("update", bot.approval_action({}, "127.0.0.1"))
        self.assertFalse(self.cards)

    def test_callback_requires_known_decision_named_approver_peer_and_nonce(self):
        rid = self.create()
        for kwargs in ({"decision": "surprise"}, {"peer": "1.2.3.4"}, {"user": "other"},
                       {"nonce": "wrong"}, {"action": "unblock"}):
            self.assertNotIn("update", self.click(**kwargs))
            self.assertEqual(bot.approval_decision(rid)["status"], "pending")
        self.click(decision="deny")
        binding = {"request_id": rid, "action": "block", "ip": "8.8.4.4", "minutes": 10}
        self.assertEqual(bot.approval_consume(binding)[1], 409)

    def test_failed_or_in_progress_post_cannot_be_approved(self):
        def failed(payload):
            self.cards.append(payload)
            rid = payload["attachments"][0]["actions"][0]["integration"]["context"]["req"]
            self.assertEqual(bot.approval_decision(rid)["status"], "posting")
            self.assertNotIn("update", self.click())
            return False, "secret failure"
        with patch.object(bot, "post_mm", side_effect=failed):
            rid, posted, detail = bot.approval_create(self.req())
        self.assertFalse(posted)
        self.assertNotIn("secret failure", detail)
        self.assertEqual(bot.approval_decision(rid)["status"], "error")
        self.assertNotIn("update", self.click())

    def test_approved_and_posting_requests_expire_before_consumption(self):
        rid = self.create()
        self.click()
        rec = bot.APPROVALS[rid]
        with patch.object(bot.time, "time", return_value=rec["ts"] + bot.APPROVAL_TTL):
            self.assertEqual(bot.approval_decision(rid)["status"], "expired")
            self.assertEqual(bot.approval_consume({"request_id": rid, "action": "block",
                                                  "ip": "8.8.4.4", "minutes": 10})[1], 409)

    def test_invalid_durations_fields_and_hidden_text_are_rejected(self):
        variants = [dict(self.req(), minutes=value) for value in (True, "10", 0, -1, 1441)]
        variants += [dict(self.req("unblock"), minutes=1), dict(self.req(), action="shell"),
                     dict(self.req(), reason="bad\u202e"), dict(self.req(), ip="bad"),
                     dict(self.req(), command="id")]
        for req in variants:
            self.assertFalse(bot.approval_create(req)[1])
        req = self.req(); del req["action"]
        rid, posted, _ = bot.approval_create(req)
        self.assertTrue(posted)
        self.assertEqual(bot.approval_decision(rid)["action"], "block")

    def test_http_consume_auth_nonce_removal_and_safe_pending_counts(self):
        def request(method, path, body=None, token=True, peer="127.0.0.1"):
            handler = object.__new__(bot.Handler)
            handler.path, handler.client_address = path, (peer, 1234)
            raw = json.dumps(body).encode() if body is not None else b""
            handler.headers = {"Content-Length": str(len(raw))}
            if token:
                handler.headers["X-Broker-Token"] = bot.BROKER_TOKEN
            handler.rfile, handler.wfile = io.BytesIO(raw), io.BytesIO()
            with patch.object(handler, "send_response") as response, patch.object(handler, "send_header"), \
                    patch.object(handler, "end_headers"):
                getattr(handler, "do_" + method)()
            return response.call_args.args[0], json.loads(handler.wfile.getvalue())
        self.assertEqual(request("POST", "/approval", self.req(), token=False)[0], 401)
        code, created = request("POST", "/approval", self.req("unblock"))
        self.assertEqual(code, 200)
        rid = created["req_id"]
        self.assertEqual(request("GET", "/nonce/" + rid)[0], 404)
        pending = request("GET", "/pending")[1]
        self.assertEqual((pending["active"], pending["status_counts"]), (1, {"pending": 1}))
        self.assertNotIn("nonce", json.dumps(pending))
        ctx = self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"]
        callback = {"user_id": "operator", "context": ctx}
        self.assertNotIn("update", request("POST", "/actions", callback, peer="1.2.3.4")[1])
        self.assertIn("update", request("POST", "/actions", callback)[1])
        binding = {"request_id": rid, "action": "unblock", "ip": "8.8.4.4", "minutes": 0}
        self.assertEqual(request("POST", "/consume", binding, token=False)[0], 401)
        self.assertEqual(request("POST", "/consume", binding)[1]["status"], "consumed")
        self.assertEqual(request("POST", "/consume", binding)[0], 409)


if __name__ == "__main__":
    unittest.main()
