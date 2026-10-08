#!/usr/bin/env python3
"""The rule broker must never grant an unreviewed or different change."""
import hashlib
import importlib.util
import io
import ipaddress
import json
import secrets
import time
import unittest
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("soc_bot_under_test", Path(__file__).with_name("soc_bot.py"))
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


def proposal(diff="--- before\n+++ after\n-old\n+new\n"):
    return {"target": "a:suricata-local",
            "base_sha256": hashlib.sha256(b"old").hexdigest(),
            "candidate_sha256": hashlib.sha256(b"new").hexdigest(),
            "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
            "diff": diff, "requested_by": "hermes", "expires_at": int(time.time()) + 120}


class RuleBrokerTest(unittest.TestCase):
    def setUp(self):
        self.saved = (bot.RULE_BROKER_TOKEN, bot.BROKER_TOKEN, bot.RULE_APPROVERS,
                      bot.MM_WEBHOOK, bot.MM_ACTION_URL, bot.RULE_MM_SOURCES)
        bot.RULE_BROKER_TOKEN = "r" * 48
        bot.BROKER_TOKEN = "b" * 48
        bot.RULE_APPROVERS = frozenset(("allowed-user",))
        bot.MM_WEBHOOK = "http://invalid.local/hooks/test"
        bot.MM_ACTION_URL = "http://localhost:8090"
        bot.RULE_MM_SOURCES = (ipaddress.ip_network("127.0.0.1/32"),)
        bot.RULE_APPROVALS.clear()
        bot.RULE_NONCES.clear()
        self.cards = []
        self.mock_post = patch.object(bot, "post_mm", side_effect=self._post).start()
        self.mock_audit = patch.object(bot, "_rule_audit").start()

    def tearDown(self):
        patch.stopall()
        (bot.RULE_BROKER_TOKEN, bot.BROKER_TOKEN, bot.RULE_APPROVERS,
         bot.MM_WEBHOOK, bot.MM_ACTION_URL, bot.RULE_MM_SOURCES) = self.saved
        bot.RULE_APPROVALS.clear()
        bot.RULE_NONCES.clear()

    def _post(self, payload):
        self.cards.append(payload)
        return True, "ok"

    def _create(self, req=None):
        response, status = bot.rule_change_create(req or proposal())
        self.assertEqual(status, 200, response)
        self.assertTrue(response["posted"])
        return response

    def _click(self, user="allowed-user", decision="approve", peer_ip="127.0.0.1", **context_changes):
        ctx = dict(self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"])
        ctx.update(context_changes)
        ctx["decision"] = decision
        return bot.rule_change_action({"user_id": user, "context": ctx}, peer_ip)

    def test_card_contains_complete_diff_and_hashes(self):
        req = proposal()
        result = self._create(req)
        text = self.cards[-1]["attachments"][0]["text"]
        self.assertIn("\n".join("    " + line for line in req["diff"].split("\n")), text)
        self.assertIn(req["base_sha256"], text)
        self.assertIn(req["candidate_sha256"], text)
        self.assertIn(req["diff_sha256"], text)
        self.assertIn(result["proposal_digest"], text)
        nonce = self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"]["nonce"]
        self.assertNotIn(nonce, text)
        self.assertEqual(result["proposal_digest"], hashlib.sha256(json.dumps(
            req, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest())

    def test_rejects_unconfigured_broker_and_approvers(self):
        bot.RULE_BROKER_TOKEN = ""
        self.assertEqual(bot.rule_change_create(proposal())[1], 503)
        bot.RULE_BROKER_TOKEN = "r" * 48
        bot.RULE_APPROVERS = frozenset()
        self.assertEqual(bot.rule_change_create(proposal())[1], 503)
        bot.RULE_APPROVERS = frozenset(("allowed-user",))
        bot.RULE_MM_SOURCES = ()
        self.assertEqual(bot.rule_change_create(proposal())[1], 503)
        self.assertFalse(self.cards)

    def test_callback_rejects_non_mattermost_tcp_peer(self):
        created = self._create()
        self.assertIn("출처", self._click(peer_ip="10.200.10.10")["ephemeral_text"])
        self.assertEqual(bot.rule_change_decision(created["proposal_id"])["status"], "pending")
        self.assertEqual(bot._rule_source_networks("0.0.0.0/0"), ())
        self.assertEqual(bot._rule_source_networks("not-an-ip"), ())

    def test_rejects_changed_or_ambiguous_proposal(self):
        variants = []
        req = proposal(); req["status"] = "approved"; variants.append(req)
        req = proposal(); req["target"] = "/etc/shadow"; variants.append(req)
        req = proposal(); req["diff_sha256"] = "0" * 64; variants.append(req)
        req = proposal(); req["expires_at"] = int(time.time()) + bot.APPROVAL_TTL + 100; variants.append(req)
        req = proposal("x" * (bot.RULE_DIFF_MAX_BYTES + 1)); variants.append(req)
        req = proposal("--- a\n+++ b\n-old\n+new\u202e\n"); variants.append(req)
        for req in variants:
            with self.subTest(req=req):
                self.assertEqual(bot.rule_change_create(req)[1], 400)
        self.assertFalse(self.cards)

    def test_callback_requires_one_time_confidential_nonce_and_explicit_approver(self):
        result = self._create()
        self.assertNotIn("nonce", bot.rule_change_decision(result["proposal_id"]))
        self.assertIn("권한", self._click(user="other-user")["ephemeral_text"])
        self.assertEqual(bot.rule_change_decision(result["proposal_id"])["status"], "pending")
        self.assertIn("인증", self._click(nonce="wrong")["ephemeral_text"])
        self.assertIn("인증", self._click(proposal_digest="0" * 64)["ephemeral_text"])
        self.assertEqual(bot.rule_change_decision(result["proposal_id"])["status"], "pending")
        success = self._click()
        self.assertIn("승인됨", success["ephemeral_text"])
        self.assertIn("    -old\n    +new", success["update"]["props"]["attachments"][0]["text"])
        self.assertEqual(bot.rule_change_decision(result["proposal_id"])["status"], "approved")
        self.assertIn("처리", self._click()["ephemeral_text"])

    def test_consume_once_and_only_exact_approved_digest(self):
        result = self._create()
        rid, digest = result["proposal_id"], result["proposal_digest"]
        self.assertEqual(bot.rule_change_consume(rid, {"proposal_digest": digest})[1], 409)
        self._click()
        self.assertEqual(bot.rule_change_consume(rid, {"proposal_digest": "0" * 64})[1], 409)
        response, status = bot.rule_change_consume(rid, {"proposal_digest": digest})
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "consumed")
        self.assertEqual(response["proposal_digest"], digest)
        self.assertEqual(bot.rule_change_consume(rid, {"proposal_digest": digest})[1], 409)
        self.assertIn("consumed", [call.args[0] for call in self.mock_audit.call_args_list])

    def test_denial_post_failure_and_expiry_never_consume(self):
        result = self._create()
        self._click(decision="deny")
        self.assertEqual(bot.rule_change_consume(result["proposal_id"],
                                                 {"proposal_digest": result["proposal_digest"]})[1], 409)
        with patch.object(bot, "post_mm", return_value=(False, "secret detail")):
            response, status = bot.rule_change_create(proposal())
        self.assertEqual(status, 502)
        self.assertNotIn("secret detail", str(response))
        result = self._create()
        self._click()
        bot.RULE_APPROVALS[result["proposal_id"]]["expires_at"] = time.time() - 1
        self.assertEqual(bot.rule_change_decision(result["proposal_id"])["status"], "expired")
        self.assertEqual(bot.rule_change_consume(result["proposal_id"],
                                                 {"proposal_digest": result["proposal_digest"]})[1], 409)

    def test_result_posted_once_only_after_consume_with_matching_readback(self):
        req = proposal()
        created = self._create(req)
        rid = created["proposal_id"]
        result = {"proposal_digest": created["proposal_digest"], "status": "applied",
                  "before_sha256": req["base_sha256"], "after_sha256": req["candidate_sha256"],
                  "readback_sha256": req["candidate_sha256"], "detail": "syntax test and reload succeeded"}
        self.assertEqual(bot.rule_change_result(rid, result)[1], 409)
        self._click()
        self.assertEqual(bot.rule_change_result(rid, result)[1], 409)
        bot.rule_change_consume(rid, {"proposal_digest": created["proposal_digest"]})
        for key, wrong in (("proposal_digest", "0" * 64), ("before_sha256", "0" * 64),
                           ("after_sha256", "0" * 64), ("readback_sha256", "0" * 64)):
            with self.subTest(key=key):
                tampered = dict(result, **{key: wrong})
                self.assertEqual(bot.rule_change_result(rid, tampered)[1], 409)
        self.assertEqual(bot.rule_change_result(rid, dict(result, status="ready"))[1], 400)
        self.assertEqual(bot.rule_change_result(rid, dict(result, detail="bad\nline"))[1], 400)
        posted, status = bot.rule_change_result(rid, result)
        self.assertEqual((status, posted["status"], posted["result_posted"]), (200, "applied", True))
        result_card = self.cards[-1]["attachments"][0]["text"]
        self.assertIn(req["diff"].splitlines()[2], result_card)
        self.assertIn(req["candidate_sha256"], result_card)
        self.assertIn("syntax test and reload succeeded", result_card)
        before = len(self.cards)
        same, status = bot.rule_change_result(rid, result)
        self.assertEqual((status, same["status"], len(self.cards)), (200, "applied", before))
        self.assertEqual(bot.rule_change_result(rid, dict(result, detail="different"))[1], 409)

    def test_failed_result_post_retries_identical_payload_only(self):
        req = proposal()
        created = self._create(req)
        rid = created["proposal_id"]
        self._click()
        bot.rule_change_consume(rid, {"proposal_digest": created["proposal_digest"]})
        result = {"proposal_digest": created["proposal_digest"], "status": "rolled_back",
                  "before_sha256": req["base_sha256"], "after_sha256": req["candidate_sha256"],
                  "readback_sha256": req["base_sha256"], "detail": "reload failed; restored original"}
        with patch.object(bot, "post_mm", return_value=(False, "secret detail")):
            response, status = bot.rule_change_result(rid, result)
        self.assertEqual(status, 502)
        self.assertNotIn("secret detail", str(response))
        self.assertEqual(bot.rule_change_decision(rid)["status"], "report_error")
        self.assertEqual(bot.rule_change_result(rid, dict(result, detail="different"))[1], 409)
        posted, status = bot.rule_change_result(rid, result)
        self.assertEqual((status, posted["status"], posted["result_attempts"]), (200, "rolled_back", 2))
        self.assertEqual(bot.rule_change_result(rid, result)[1], 200)
        self.assertEqual(len(self.cards), 2)  # original approval card + one successful result card

    def test_result_post_retry_budget_prevents_unbounded_duplicates(self):
        req = proposal()
        created = self._create(req)
        rid = created["proposal_id"]
        self._click()
        bot.rule_change_consume(rid, {"proposal_digest": created["proposal_digest"]})
        result = {"proposal_digest": created["proposal_digest"], "status": "failed",
                  "before_sha256": req["base_sha256"], "after_sha256": req["candidate_sha256"],
                  "readback_sha256": req["base_sha256"], "detail": "preflight syntax check failed"}
        with patch.object(bot, "post_mm", return_value=(False, "temporary failure")) as post:
            self.assertEqual([bot.rule_change_result(rid, result)[1] for _ in range(3)], [502, 502, 502])
            self.assertEqual(post.call_count, 3)
        self.assertEqual(bot.rule_change_result(rid, result)[1], 429)
        self.assertEqual(bot.rule_change_decision(rid)["result_attempts"], 3)

    def test_abort_only_approved_unconsumed_proposal_and_post_once(self):
        req = proposal()
        created = self._create(req)
        rid = created["proposal_id"]
        abort = {"proposal_digest": created["proposal_digest"],
                 "readback_sha256": req["base_sha256"], "detail": "live base changed before consume"}
        self.assertEqual(bot.rule_change_abort(rid, abort)[1], 409)
        self._click()
        before_cards = len(self.cards)
        result, status = bot.rule_change_abort(rid, abort)
        self.assertEqual((status, result["status"], result["result_posted"]), (200, "aborted", True))
        self.assertEqual(result["result_status"], "not_applied")
        self.assertEqual(len(self.cards), before_cards + 1)
        self.assertIn("미적용", self.cards[-1]["attachments"][0]["text"])
        self.assertIn(req["diff"].splitlines()[2], self.cards[-1]["attachments"][0]["text"])
        self.assertEqual(bot.rule_change_abort(rid, abort)[1], 200)
        self.assertEqual(len(self.cards), before_cards + 1)
        self.assertEqual(bot.rule_change_abort(rid, dict(abort, detail="changed"))[1], 409)
        self.assertEqual(bot.rule_change_consume(rid, {"proposal_digest": created["proposal_digest"]})[1], 409)
        created2 = self._create(req)
        self._click()
        bot.rule_change_consume(created2["proposal_id"], {"proposal_digest": created2["proposal_digest"]})
        self.assertEqual(bot.rule_change_abort(created2["proposal_id"],
                                               dict(abort, proposal_digest=created2["proposal_digest"]))[1], 409)

    def test_abort_card_failure_retries_same_payload_only(self):
        req = proposal()
        created = self._create(req)
        self._click()
        rid = created["proposal_id"]
        abort = {"proposal_digest": created["proposal_digest"],
                 "readback_sha256": req["base_sha256"], "detail": "mount drift"}
        with patch.object(bot, "post_mm", return_value=(False, "temporary failure")) as post:
            self.assertEqual([bot.rule_change_abort(rid, abort)[1] for _ in range(3)], [502, 502, 502])
            self.assertEqual(post.call_count, 3)
        self.assertEqual(bot.rule_change_abort(rid, abort)[1], 429)
        self.assertEqual(bot.rule_change_abort(rid, dict(abort, detail="other"))[1], 409)

    def test_http_routes_require_hmac_and_sign_every_response(self):
        # Call the request handler directly: the CI sandbox does not permit bind(2).
        def request(method, path, body=None, signed=False, nonce=None,
                    peer_ip="127.0.0.1", extra_headers=None):
            handler = object.__new__(bot.Handler)
            handler.path = path
            handler.client_address = (peer_ip, 12345)
            data = json.dumps(body).encode() if body is not None else b""
            handler.headers = {"Content-Length": str(len(data))}
            handler.headers.update(extra_headers or {})
            if signed:
                nonce = nonce or secrets.token_hex(16)
                timestamp = str(int(time.time()))
                handler.headers.update({
                    "X-Rule-Timestamp": timestamp,
                    "X-Rule-Nonce": nonce,
                    "X-Rule-Signature": bot._rule_request_signature(method, path, timestamp, nonce, data),
                })
            handler.rfile, handler.wfile = io.BytesIO(data), io.BytesIO()
            with patch.object(handler, "send_response") as response, \
                 patch.object(handler, "send_header") as send_header, \
                 patch.object(handler, "end_headers"):
                getattr(handler, "do_" + method)()
            status = response.call_args.args[0]
            raw = handler.wfile.getvalue()
            headers = dict(call.args for call in send_header.call_args_list)
            if signed and status not in (401, 503):
                self.assertEqual(headers.get("X-Rule-Response-Signature"),
                                 bot._rule_response_signature(nonce, status, raw))
            return status, json.loads(raw), headers
        self.assertEqual(request("POST", "/rule-changes", proposal())[0], 401)
        self.assertEqual(request("POST", "/rule-changes", proposal(),
                                 extra_headers={"X-Rule-Broker-Token": bot.RULE_BROKER_TOKEN})[0], 401)
        status, health, _ = request("GET", "/rule-changes/health", signed=True)
        self.assertEqual((status, health["status"]), (200, "ready"))
        status, created, _ = request("POST", "/rule-changes", proposal(), signed=True)
        self.assertEqual(status, 200)
        rid = created["proposal_id"]
        self.assertEqual(request("GET", "/rule-changes/" + rid,
                                 signed=True)[1]["status"], "pending")
        callback = {"user_id": "allowed-user", "context": dict(
            self.cards[-1]["attachments"][0]["actions"][0]["integration"]["context"])}
        status, rejected, _ = request("POST", "/rule-actions", callback, peer_ip="10.200.10.10",
                                      extra_headers={"X-Forwarded-For": "127.0.0.1"})
        self.assertEqual(status, 200)
        self.assertIn("출처", rejected["ephemeral_text"])
        self.assertEqual(bot.rule_change_decision(rid)["status"], "pending")
        self._click()
        status, consumed, _ = request("POST", "/rule-changes/" + rid + "/consume",
                                      {"proposal_digest": created["proposal_digest"]}, signed=True)
        self.assertEqual((status, consumed["status"]), (200, "consumed"))
        req = proposal()
        result = {"proposal_digest": created["proposal_digest"], "status": "applied",
                  "before_sha256": req["base_sha256"], "after_sha256": req["candidate_sha256"],
                  "readback_sha256": req["candidate_sha256"], "detail": "reload succeeded"}
        self.assertEqual(request("POST", "/rule-changes/" + rid + "/result", result)[0], 401)
        status, reported, _ = request("POST", "/rule-changes/" + rid + "/result", result,
                                      signed=True)
        self.assertEqual((status, reported["status"], reported["result_posted"]),
                         (200, "applied", True))

    def test_hmac_tamper_replay_and_clock_skew_are_rejected(self):
        request_body = json.dumps(proposal()).encode()
        nonce = secrets.token_hex(16)
        timestamp = str(int(time.time()))
        signature = bot._rule_request_signature("POST", "/rule-changes", timestamp, nonce, request_body)
        handler = object.__new__(bot.Handler)
        handler.path = "/rule-changes"
        handler.headers = {"X-Rule-Timestamp": timestamp, "X-Rule-Nonce": nonce,
                           "X-Rule-Signature": signature}
        with patch.object(handler, "_json") as rejected:
            self.assertFalse(handler._rule_auth("POST", request_body + b" "))
            self.assertEqual(rejected.call_args.args[1], 401)
            self.assertTrue(handler._rule_auth("POST", request_body))
            self.assertFalse(handler._rule_auth("POST", request_body))
            self.assertEqual(rejected.call_args.args[1], 401)
        handler2 = object.__new__(bot.Handler)
        handler2.path = "/rule-changes"
        old = str(int(time.time()) - 300)
        handler2.headers = {"X-Rule-Timestamp": old, "X-Rule-Nonce": secrets.token_hex(16),
                            "X-Rule-Signature": bot._rule_request_signature("POST", "/rule-changes", old,
                                                                              secrets.token_hex(16), request_body)}
        with patch.object(handler2, "_json") as rejected:
            self.assertFalse(handler2._rule_auth("POST", request_body))
            self.assertEqual(rejected.call_args.args[1], 401)


if __name__ == "__main__":
    unittest.main()
