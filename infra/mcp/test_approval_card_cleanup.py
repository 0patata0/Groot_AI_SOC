#!/usr/bin/env python3
"""Only exact unanswered request cards may be cleared, preserving every reply."""
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cleanup = load("card_cleanup_test", "approval_card_cleanup.py")
bot = load("card_cleanup_broker_test", "soc_bot.py")
ops = load("card_cleanup_ops_test", "operations_approval.py")
BOT, CHANNEL, POST = "b" * 26, "c" * 26, "p" * 26
RID, NONCE = "1" * 32, "2" * 48


class FakeRest:
    bot_id, channel_id = BOT, CHANNEL

    def __init__(self):
        self.calls, self.posts, self.identity_checks = [], {}, 0
        self.failure, self.identity_failure = None, None
        self.thread_override, self.after_get, self.after_put = None, None, None

    def verify_identity(self):
        self.identity_checks += 1
        if self.identity_failure:
            raise self.identity_failure

    def request(self, method, path, body=None, absent=False):
        self.calls.append((method, path, copy.deepcopy(body)))
        if self.failure and method == self.failure[0]:
            raise self.failure[1]
        if method == "POST":
            post = {"id": POST, "user_id": BOT, "root_id": "", "delete_at": 0,
                    "reply_count": 0, **copy.deepcopy(body)}
            self.posts[POST] = post
            return copy.deepcopy(post)
        if method == "DELETE":
            raise AssertionError("DELETE must never be called")
        if method == "PUT":
            if not path.endswith("/patch"):
                raise AssertionError("only partial updates are allowed")
            self.posts[POST].update(copy.deepcopy(body))
            if self.after_put:
                self.after_put(self)
            return self.read_post()
        if "/thread?" in path:
            if self.thread_override is not None:
                return copy.deepcopy(self.thread_override)
            return {"order": [POST], "posts": {POST: self.read_post()}, "has_next": False}
        post = self.read_post() if POST in self.posts else None
        if self.after_get:
            self.after_get(self)
        return post

    def read_post(self):
        post = copy.deepcopy(self.posts[POST])
        # Real Mattermost hides the callback URL and secret context on GET.
        attachments = post["props"].get("attachments")
        for attachment in attachments if isinstance(attachments, list) else []:
            if not isinstance(attachment, dict):
                continue
            for action in attachment.get("actions", []):
                action.pop("integration", None)
        return post


class CleanupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="capstone-card-test-", dir="/private/tmp")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cards.sqlite3"
        self.client = FakeRest()
        self.manager = cleanup.CardCleanup(self.client, cleanup.Ledger(self.path))
        self.expires = int(time.time()) + 120
        self.rec = {"nonce": NONCE, "status": "pending", "by": "", "proposal_digest": "3" * 64}
        self.payload = {"attachments": [{"title": "승인 요청", "text": "정확한 후보", "color": "#ffcc00",
            "actions": [{"id": "approve", "name": "승인", "style": "good",
              "integration": {"url": "http://callback.invalid", "context": {"nonce": NONCE}}}]}]}

    def create(self, kind="rule", rid=RID):
        self.assertEqual(self.manager.post(kind, rid, self.rec, self.payload, self.expires), (True, "ok"))
        self.assertTrue(self.manager.pending(kind, rid))
        return self.manager.ledger.row(kind + ":" + rid)

    def row(self, kind="rule", rid=RID):
        return self.manager.ledger.row(kind + ":" + rid)

    def changes(self):
        self.assertFalse(any(call[0] == "DELETE" for call in self.client.calls))
        return [call for call in self.client.calls if call[0] == "PUT"]

    def run_expiry(self):
        return self.manager.cleanup_once(self.expires)

    def test_idle_and_unexpired_make_no_network_calls(self):
        self.assertEqual(self.manager.cleanup_once(), [])
        self.assertEqual(self.client.identity_checks, 0)
        self.create()
        before = (len(self.client.calls), self.client.identity_checks)
        self.assertEqual(self.manager.cleanup_once(self.expires - 1), [])
        self.assertEqual((len(self.client.calls), self.client.identity_checks), before)

    def test_exact_pending_card_cleared_at_deadline_and_audit_kept(self):
        self.create()
        self.assertTrue(self.manager.expire("rule", RID, self.rec))
        self.assertEqual(self.run_expiry(), ["cleaned"])
        self.assertEqual(self.row()["state"], "cleaned")
        self.assertEqual(len(self.changes()), 1)
        self.assertEqual(self.manager.cleanup_once(self.expires + 60), [])
        conn = self.manager.ledger.connect()
        try:
            self.assertGreaterEqual(conn.execute("SELECT count(*) FROM audit").fetchone()[0], 5)
        finally:
            conn.close()

    def test_restart_cleans_durable_pending_but_does_not_restore_approval(self):
        self.create()
        restored = cleanup.CardCleanup(self.client, cleanup.Ledger(self.path))
        self.assertEqual(restored.cleanup_once(self.expires), ["cleaned"])
        self.assertFalse(hasattr(restored, "records"))

    def test_decision_is_durably_protected_before_expiry_and_after_restart(self):
        self.create()
        self.assertTrue(self.manager.protect("rule", RID, {"post_id": POST, "channel_id": CHANNEL}))
        self.assertFalse(self.manager.expire("rule", RID, {**self.rec, "status": "approved", "by": "operator"}))
        restored = cleanup.CardCleanup(self.client, cleanup.Ledger(self.path))
        self.assertEqual(restored.cleanup_once(self.expires), [])
        self.assertEqual(self.changes(), [])

    def test_callback_bound_to_exact_post_and_channel(self):
        self.create()
        for body in ({}, {"post_id": "x" * 26, "channel_id": CHANNEL}, {"post_id": POST, "channel_id": "x" * 26}):
            with self.subTest(body=body):
                self.assertFalse(self.manager.protect("rule", RID, body))
                self.assertEqual(self.row()["state"], "pending")

    def test_old_untracked_webhook_is_never_a_cleanup_target(self):
        self.assertTrue(self.manager.protect("rule", RID, {"post_id": POST, "channel_id": CHANNEL}))
        self.assertFalse(self.manager.expire("rule", RID, self.rec))
        self.assertEqual(self.run_expiry(), [])
        self.assertEqual(self.client.calls, [])

    def test_every_evidence_of_decision_consumption_or_result_excludes_expiry(self):
        self.create()
        for field, value in (("status", "approved"), ("status", "denied"), ("by", "operator"),
            ("decision", "deny"), ("consumed_decision", "keep"), ("result_posted", True),
            ("result_status", "failed"), ("result_digest", "a"), ("result_request_digest", "a"), ("consumed_ts", 1)):
            with self.subTest(field=field, value=value):
                self.assertFalse(self.manager.expire("rule", RID, {**self.rec, field: value}))
        self.assertEqual(self.row()["state"], "pending")

    def test_consume_and_result_protection_excludes_deletion(self):
        self.create()
        self.assertTrue(self.manager.protect("rule", RID))
        self.assertTrue(self.manager.protect("rule", RID))
        self.assertEqual(self.run_expiry(), [])

    def test_cleaned_expiry_can_still_report_without_recreating_card(self):
        self.create()
        self.run_expiry()
        self.assertTrue(self.manager.protect("rule", RID, allow_absent=True))
        self.assertFalse(self.manager.protect("rule", RID, {"post_id": POST, "channel_id": CHANNEL}))

    def test_cleanup_claim_prevents_late_approval(self):
        self.create()
        self.assertTrue(self.manager.ledger.transition("rule:" + RID, ("pending",), "cleaning"))
        self.assertFalse(self.manager.protect("rule", RID, {"post_id": POST, "channel_id": CHANNEL}))

    def test_no_secret_or_complete_card_stored_in_ledger(self):
        self.create()
        raw = self.path.read_bytes()
        self.assertNotIn(NONCE.encode(), raw)
        self.assertNotIn(b"callback.invalid", raw)
        self.assertNotIn("정확한 후보".encode(), raw)
        self.assertIn(hashlib.sha256(NONCE.encode()).hexdigest().encode(), raw)

    def test_unbound_posting_and_bound_card_never_auto_clean(self):
        self.manager.post("rule", RID, self.rec, self.payload, self.expires)
        self.assertEqual(self.row()["state"], "bound")
        self.assertEqual(self.run_expiry(), [])
        self.manager.ledger.transition("rule:" + RID, ("bound",), "posting")
        self.assertEqual(self.run_expiry(), [])

    def test_failed_or_uncertain_post_never_becomes_pending_and_no_repost(self):
        self.client.failure = ("POST", cleanup.CleanupError("transport_unavailable", True))
        with self.assertRaises(cleanup.CleanupError):
            self.manager.post("rule", RID, self.rec, self.payload, self.expires)
        self.assertEqual(self.row()["state"], "posting")
        self.assertFalse(self.manager.pending("rule", RID))
        self.assertEqual(self.run_expiry(), [])
        self.client.failure = None
        with self.assertRaises(Exception):
            self.manager.post("rule", RID, self.rec, self.payload, self.expires)
        self.assertEqual(sum(call[0] == "POST" for call in self.client.calls), 1)

    def test_author_channel_root_content_or_binding_change_preserves_card(self):
        for field, value in (("user_id", "x" * 26), ("channel_id", "x" * 26), ("root_id", "x" * 26),
                              ("message", "관리자가 추가한 내용"), ("delete_at", None)):
            with self.subTest(field=field):
                self.setUp()
                self.create()
                self.client.posts[POST][field] = value
                self.assertEqual(self.run_expiry(), ["live_card_binding_mismatch"])
                self.assertEqual(self.changes(), [])
                self.assertEqual(self.row()["state"], "protected")

    def test_binding_digest_nonce_or_visible_actions_change_preserves_card(self):
        self.create()
        self.client.posts[POST]["props"]["capstone_approval"]["nonce_sha256"] = "0" * 64
        self.assertEqual(self.run_expiry(), ["live_card_binding_mismatch"])
        self.assertEqual(self.changes(), [])

    def test_existing_and_concurrent_replies_are_preserved_without_thread_access(self):
        self.create()
        reply = "r" * 26
        self.client.posts[POST]["reply_count"] = 1
        self.client.posts[reply] = {"id": reply, "root_id": POST, "message": "운영자 댓글", "delete_at": 0}
        original = copy.deepcopy(self.client.posts[reply])
        self.client.after_get = lambda client: client.posts[POST].update(reply_count=2)
        self.assertEqual(self.run_expiry(), ["cleaned"])
        self.assertEqual(self.client.posts[reply], original)
        self.assertEqual(self.client.posts[POST]["reply_count"], 2)
        self.assertFalse(any("/thread" in call[1] for call in self.client.calls))
        self.assertEqual(self.client.posts[POST]["message"], cleanup.EXPIRED_MESSAGE)
        self.assertEqual(self.client.posts[POST]["props"]["attachments"], [])

    def test_every_other_prop_and_root_metadata_are_preserved(self):
        self.create()
        self.client.posts[POST]["props"]["custom_metadata"] = {"owner_note": "유지"}
        self.client.posts[POST]["is_pinned"] = True
        self.client.posts[POST]["file_ids"] = ["f" * 26]
        binding = copy.deepcopy(self.client.posts[POST]["props"]["capstone_approval"])
        self.assertEqual(self.run_expiry(), ["cleaned"])
        post = self.client.posts[POST]
        self.assertEqual(post["props"]["custom_metadata"], {"owner_note": "유지"})
        self.assertEqual(post["props"]["capstone_approval"], binding)
        self.assertTrue(post["is_pinned"])
        self.assertEqual(post["file_ids"], ["f" * 26])
        self.assertEqual(set(self.changes()[0][2]), {"message", "props"})

    def test_successful_put_with_lost_response_is_idempotently_recognized(self):
        self.create()
        self.client.posts[POST]["message"] = cleanup.EXPIRED_MESSAGE
        self.client.posts[POST]["props"]["attachments"] = []
        self.assertEqual(self.run_expiry(), ["already_cleaned"])
        self.assertEqual(self.changes(), [])

    @staticmethod
    def normalize_empty_attachments(client, mode):
        props = client.posts[POST]["props"]
        if mode == "missing":
            props.pop("attachments", None)
        else:
            props["attachments"] = None

    def test_put_accepts_null_or_missing_empty_attachments(self):
        for mode in ("null", "missing"):
            with self.subTest(mode=mode):
                self.setUp()
                self.create()
                self.client.after_put = lambda client: self.normalize_empty_attachments(client, mode)
                self.assertEqual(self.run_expiry(), ["cleaned"])
                self.assertEqual(self.row()["state"], "cleaned")
                self.assertEqual(len(self.changes()), 1)
                self.assertEqual(self.client.posts[POST]["message"], cleanup.EXPIRED_MESSAGE)
                self.assertEqual(self.manager.cleanup_once(self.expires + 1), [])
                self.assertEqual(len(self.changes()), 1)

    def test_put_rejects_unrelated_props_changed_removed_or_added(self):
        for change in ("changed", "removed", "added"):
            with self.subTest(change=change):
                self.setUp()
                self.create()
                self.client.posts[POST]["props"]["custom_metadata"] = {"owner_note": "preserve"}

                def mutate(client):
                    self.normalize_empty_attachments(client, "null")
                    props = client.posts[POST]["props"]
                    if change == "removed":
                        props.pop("custom_metadata")
                    elif change == "added":
                        props["unexpected_metadata"] = True
                    else:
                        props["custom_metadata"]["owner_note"] = "changed"

                self.client.after_put = mutate
                self.assertEqual(self.run_expiry(), ["cleanup_readback_mismatch"])
                self.assertEqual(self.row()["state"], "protected")
                self.assertEqual(len(self.changes()), 1)

    def test_put_rejects_invalid_or_remaining_attachments(self):
        for value in ({}, "", False, 0, [{"text": "old card", "actions": [{"id": "approve"}]}]):
            with self.subTest(value=value):
                self.setUp()
                self.create()
                self.client.after_put = lambda client: client.posts[POST]["props"].update(attachments=copy.deepcopy(value))
                self.assertEqual(self.run_expiry(), ["cleanup_readback_mismatch"])
                self.assertEqual(self.row()["state"], "protected")

    def test_lost_put_response_with_null_or_missing_attachments_does_not_rewrite(self):
        for mode in ("null", "missing"):
            with self.subTest(mode=mode):
                self.setUp()
                self.create()

                def lose_response(client):
                    self.normalize_empty_attachments(client, mode)
                    raise cleanup.CleanupError("transport_unavailable", True)

                self.client.after_put = lose_response
                self.assertEqual(self.run_expiry(), ["transport_unavailable"])
                self.assertEqual(self.row()["state"], "retry")
                self.assertEqual(len(self.changes()), 1)
                self.client.after_put = None
                self.assertEqual(self.manager.cleanup_once(self.row()["next_attempt"]), ["already_cleaned"])
                self.assertEqual(self.row()["state"], "cleaned")
                self.assertEqual(len(self.changes()), 1)

    def test_expired_message_with_invalid_attachments_is_not_already_cleaned(self):
        for value in ({}, "", False, 0, [{"text": "old card", "actions": [{"id": "approve"}]}]):
            with self.subTest(value=value):
                self.setUp()
                self.create()
                self.client.posts[POST]["message"] = cleanup.EXPIRED_MESSAGE
                self.client.posts[POST]["props"]["attachments"] = copy.deepcopy(value)
                outcomes = self.run_expiry()
                self.assertNotIn("already_cleaned", outcomes)
                self.assertNotIn("cleaned", outcomes)
                self.assertEqual(self.row()["state"], "protected")
                self.assertEqual(self.changes(), [])

    def test_empty_normalized_attachments_require_exact_expired_message(self):
        for mode in ("null", "missing"):
            with self.subTest(mode=mode):
                self.setUp()
                self.create()
                self.normalize_empty_attachments(self.client, mode)
                self.client.posts[POST]["message"] = "다른 내용"
                outcomes = self.run_expiry()
                self.assertNotIn("already_cleaned", outcomes)
                self.assertNotIn("cleaned", outcomes)
                self.assertEqual(self.row()["state"], "protected")
                self.assertEqual(self.changes(), [])

    def test_absent_post_completes_without_delete(self):
        self.create()
        self.client.posts.clear()
        self.assertEqual(self.run_expiry(), ["already_absent"])
        self.assertEqual(self.changes(), [])

    def test_retryable_failure_backoff_is_bounded_and_never_reposts(self):
        self.create()
        self.client.failure = ("PUT", cleanup.CleanupError("http_503", True))
        now = self.expires
        for attempt in range(1, cleanup.MAX_ATTEMPTS + 1):
            self.assertEqual(self.manager.cleanup_once(now), ["http_503"])
            row = self.row()
            self.assertEqual(row["attempts"], attempt)
            if attempt < cleanup.MAX_ATTEMPTS:
                self.assertEqual(row["state"], "retry")
                self.assertEqual(self.manager.cleanup_once(row["next_attempt"] - 1), [])
                now = row["next_attempt"]
            else:
                self.assertEqual(row["state"], "protected")
        self.assertEqual(sum(call[0] == "POST" for call in self.client.calls), 1)

    def test_permission_and_identity_failure_permanently_preserves_candidate(self):
        self.create()
        self.client.identity_failure = cleanup.CleanupError("http_403")
        self.assertEqual(self.run_expiry(), ["http_403"])
        self.assertEqual(self.row()["state"], "protected")
        self.assertEqual(self.changes(), [])

    def test_identity_transport_failure_retries_claim_without_five_minute_stall(self):
        self.create()
        self.client.identity_failure = cleanup.CleanupError("transport_unavailable", True)
        self.assertEqual(self.run_expiry(), ["transport_unavailable"])
        self.assertEqual(self.row()["state"], "retry")
        self.assertLess(self.row()["next_attempt"], self.expires + 300)

    def test_crash_during_final_attempt_becomes_audited_preservation(self):
        self.create()
        conn = self.manager.ledger.connect()
        try:
            with conn:
                conn.execute("UPDATE cards SET state='cleaning',attempts=?,next_attempt=?", (cleanup.MAX_ATTEMPTS, self.expires))
        finally:
            conn.close()
        self.assertEqual(self.run_expiry(), ["restart_retry_limit"])
        self.assertEqual(self.row()["state"], "protected")
        self.assertEqual(self.changes(), [])

    def test_unsafe_ledger_permissions_and_symlinks_fail_closed(self):
        self.create()
        os.chmod(self.path, 0o644)
        with self.assertRaisesRegex(cleanup.CleanupError, "ledger_file_permissions"):
            self.run_expiry()
        os.chmod(self.path, 0o600)
        link = self.path.parent / "symlink.sqlite3"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(cleanup.CleanupError, "ledger_file_permissions"):
            cleanup.Ledger(link).connect()
        os.chmod(self.path.parent, 0o755)
        try:
            with self.assertRaisesRegex(cleanup.CleanupError, "ledger_parent_permissions"):
                self.run_expiry()
        finally:
            os.chmod(self.path.parent, 0o700)

    def test_disabled_configuration_never_reads_credentials_or_database(self):
        self.assertIsNone(cleanup.configured({}))

    def test_invalid_identity_expiry_nonce_and_configuration_are_rejected(self):
        for kind, rid, rec, expiry in (("result", RID, self.rec, self.expires),
            ("rule", "../post", self.rec, self.expires), ("rule", RID, {"nonce": "bad"}, self.expires),
            ("rule", RID, self.rec, int(time.time()) - 1)):
            with self.subTest(kind=kind, rid=rid):
                with self.assertRaises(cleanup.CleanupError):
                    self.manager.post(kind, rid, rec, self.payload, expiry)
        with self.assertRaises(cleanup.CleanupError):
            cleanup.RestClient("https://user:pass@example.invalid", "token", BOT, CHANNEL)


class BrokerIntegrationTest(unittest.TestCase):
    setUp = CleanupTest.setUp
    row = CleanupTest.row
    run_expiry = CleanupTest.run_expiry
    def test_rule_decision_requires_exact_rest_card_and_survives_expiry(self):
        values = {"RULE_BROKER_TOKEN": "r" * 48, "BROKER_TOKEN": "b" * 48,
                  "RULE_APPROVERS": frozenset(("operator",)), "MM_WEBHOOK": "http://invalid/hooks/test",
                  "MM_ACTION_URL": "http://localhost:8090", "RULE_MM_SOURCES": (ipaddress.ip_network("127.0.0.1/32"),),
                  "CARD_CLEANUP": self.manager, "CARD_CLEANUP_ERROR": False}
        bot.RULE_APPROVALS.clear()
        bot.RULE_NONCES.clear()
        self.addCleanup(bot.RULE_APPROVALS.clear)
        self.addCleanup(bot.RULE_NONCES.clear)
        diff = "--- before\n+++ after\n-old\n+new\n"
        request = {"target": "a:suricata-local", "base_sha256": "1" * 64, "candidate_sha256": "2" * 64,
            "diff_sha256": hashlib.sha256(diff.encode()).hexdigest(), "diff": diff,
            "requested_by": "hermes", "expires_at": self.expires}
        with patch.multiple(bot, **values), patch.object(bot, "_rule_audit"), patch.object(bot, "post_mm", return_value=(True, "ok")):
            result, code = bot.rule_change_create(request)
            self.assertEqual(code, 200, result)
            rid = result["proposal_id"]
            context = self.client.posts[POST]["props"]["attachments"][0]["actions"][0]["integration"]["context"]
            body = {"user_id": "operator", "post_id": "x" * 26, "channel_id": CHANNEL, "context": context}
            bot.rule_change_action(body, "127.0.0.1")
            self.assertEqual(bot.RULE_APPROVALS[rid]["status"], "pending")
            self.assertEqual(self.row(rid=rid)["state"], "pending")
            body["post_id"] = POST
            bot.rule_change_action(body, "127.0.0.1")
            self.assertEqual(bot.RULE_APPROVALS[rid]["status"], "approved")
            self.assertEqual(self.row(rid=rid)["state"], "protected")
            with patch.object(bot.time, "time", return_value=self.expires + 1):
                bot._rule_expire_locked()
            self.assertEqual(self.run_expiry(), [])

    def test_operations_card_denial_protected_without_a_separate_result_post(self):
        reports = []
        broker = ops.OperationsBroker(post=lambda payload: (reports.append(payload) is None, "ok"),
            enabled=lambda: True, source_ok=lambda peer: peer == "127.0.0.1",
            approvers=lambda: frozenset(("operator",)), action_url=lambda: "http://localhost:8090",
            post_card=lambda rec, payload: self.manager.post("operation", rec["request_id"], rec, payload, rec["expires_at"]),
            card_state=lambda event, rec, body=None: (self.manager.pending("operation", rec["request_id"]) if event == "pending" else
              self.manager.expire("operation", rec["request_id"], rec) if event == "expire" else
              self.manager.protect("operation", rec["request_id"], body, allow_absent=event == "protect")))
        plan = {"action": "reload", "before_observation_sha256": "1" * 64, "before_summary": "running=true",
                "policy_sha256": "2" * 64, "reason": "검증"}
        req = {"request_id": RID, "kind": "service", "target": "a:waf", "plan": plan,
               "plan_sha256": ops.digest(plan), "expires_at": self.expires, "requested_by": "hermes"}
        created, code = broker.create(req)
        self.assertEqual(code, 200, created)
        ctx = self.client.posts[POST]["props"]["attachments"][0]["actions"][1]["integration"]["context"]
        body = {"user_id": "operator", "post_id": POST, "channel_id": "x" * 26, "context": ctx}
        broker.action(body, "127.0.0.1")
        self.assertEqual(broker.records[RID]["status"], "pending")
        body["channel_id"] = CHANNEL
        broker.action(body, "127.0.0.1")
        self.assertEqual(broker.records[RID]["status"], "denied")
        self.assertEqual(self.row("operation")["state"], "protected")
        self.assertEqual(self.run_expiry(), [])
        self.assertEqual(reports, [])

    def test_rule_decision_not_accepted_when_durable_protection_fails(self):
        with patch.object(bot, "CARD_CLEANUP", self.manager), patch.object(bot, "CARD_CLEANUP_ERROR", False):
            with patch.object(self.manager, "protect", side_effect=OSError("fake secret value")), patch.object(bot, "print") as logged:
                self.assertFalse(bot._card_event("decision", "rule", RID, self.rec, {}))
                self.assertNotIn("fake secret", str(logged.call_args))


class RestBoundsTest(unittest.TestCase):
    class Response:
        status = 200
        fp = None
        def __init__(self, chunks):
            self.chunks = iter(chunks)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read1(self, count):
            return next(self.chunks, b"")

    def client(self, response):
        client = cleanup.RestClient("http://127.0.0.1:8065", "fake-test-token", BOT, CHANNEL)
        client.opener.open = lambda request, timeout: response
        return client

    def test_json_response_and_body_limit(self):
        client = self.client(self.Response([b'{"status":', b'"OK"}']))
        self.assertEqual(client.request("GET", "/users/me"), {"status": "OK"})
        with self.assertRaisesRegex(cleanup.CleanupError, "request_too_large"):
            client.request("POST", "/posts", {"message": "x" * cleanup.MAX_BYTES})

    def test_response_limit(self):
        client = self.client(self.Response([b"x" * (cleanup.MAX_BYTES + 1)]))
        with self.assertRaisesRegex(cleanup.CleanupError, "response_too_large"):
            client.request("GET", "/users/me")

    def test_trickle_response_has_cumulative_deadline(self):
        client = self.client(self.Response([b"{", b" ", b" ", b"}"]))
        with patch.object(cleanup.time, "monotonic", side_effect=[100, 100, 102, 104, 106]):
            with self.assertRaisesRegex(cleanup.CleanupError, "response_deadline"):
                client.request("GET", "/users/me")

    def test_delete_method_redirects_and_admin_identity_are_refused(self):
        with self.assertRaisesRegex(cleanup.CleanupError, "unsupported_http_method"):
            self.client(self.Response([])).request("DELETE", "/posts/" + POST)
        self.assertIsNone(cleanup._NoRedirect().redirect_request(None, None, None, None, None, None))
        client = self.client(self.Response([json.dumps({"id": BOT, "is_bot": True, "delete_at": 0,
                            "roles": "system_user system_admin"}).encode()]))
        with self.assertRaisesRegex(cleanup.CleanupError, "bot_identity_mismatch"):
            client.verify_identity()


if __name__ == "__main__":
    unittest.main()
