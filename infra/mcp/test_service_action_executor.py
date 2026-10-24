#!/usr/bin/env python3
"""Offline executor-to-real-broker approval and bounded service action tests."""
import copy
import contextlib
from datetime import datetime, timezone
from importlib.machinery import SourceFileLoader
from itertools import count
import json
import io
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).parent
helper = SourceFileLoader("service_test_helper", str(HERE / "rule_change_executor.py")).load_module()
service = SourceFileLoader("service_test_executor", str(HERE / "service_action_executor.py")).load_module()
operations = SourceFileLoader("service_test_broker", str(HERE / "operations_approval.py")).load_module()


class BrokerAdapter:
    def __init__(self):
        self.cards = []
        self.consumes = 0
        self.lose_create = False
        self.lose_consume = False
        self.fail_get = False
        self.fail_result = False
        self.mutate_response = None
        self.broker = operations.OperationsBroker(post=self.post, enabled=lambda: True,
            source_ok=lambda peer: peer == "127.0.0.1", approvers=lambda: frozenset(("operator",)),
            action_url=lambda: "http://localhost:8090")

    def post(self, payload):
        self.cards.append(copy.deepcopy(payload))
        return True, "posted"

    def request(self, method, path, body=None):
        if path == "/operations":
            out, code = self.broker.create(body)
            if self.lose_create:
                self.lose_create = False
                raise helper.RuleChangeError("lost create response")
        else:
            rid = path.split("/")[2]
            if method == "GET":
                if self.fail_get:
                    raise helper.RuleChangeError("broker offline")
                out, code = self.broker.get(rid)
            elif path.endswith("/consume"):
                out, code = self.broker.consume(rid, body)
                if code == 200:
                    self.consumes += 1
                if self.lose_consume:
                    self.lose_consume = False
                    raise helper.RuleChangeError("lost consume response")
            elif path.endswith("/result"):
                if self.fail_result:
                    raise helper.RuleChangeError("result unavailable")
                out, code = self.broker.result(rid, body)
            else:
                raise AssertionError(path)
        if code != 200:
            raise helper.RuleChangeError("broker rejected request")
        if self.mutate_response:
            out = self.mutate_response(copy.deepcopy(out))
        return out

    def decide(self, rid, choice="approve"):
        card = next(card for card in self.cards if
                    card["attachments"][0].get("actions", [{}])[0].get("integration", {}).get("context", {}).get("operation_id") == rid)
        context = copy.deepcopy(card["attachments"][0]["actions"][0]["integration"]["context"])
        context["decision"] = choice
        return self.broker.action({"user_id": "operator", "context": context}, "127.0.0.1")


class FakeBackend:
    def __init__(self, now):
        self.now = now
        self.observation = {"container_id": "a" * 64, "image_id": "sha256:" + "b" * 64,
                            "started_at": datetime.fromtimestamp(now - 100, timezone.utc).isoformat(),
                            "config_sha256": "c" * 64, "files_sha256": "d" * 64,
                            "running": True, "health": "healthy", "oom_killed": False,
                            "nginx_config_sha256": "e" * 64,
                            "nginx_master_pid": 10, "nginx_worker_pids": [11, 12]}
        self.actions = []
        self.fail_dispatch = False
        self.fail_preflight = False
        self.fail_verify = False
        self.preflight_drift = False
        self.service = None

    def observe(self, target):
        return copy.deepcopy(self.observation)

    def preflight(self, target, before):
        if self.fail_preflight:
            raise helper.RuleChangeError("bad config")
        if self.preflight_drift:
            self.observation["config_sha256"] = "f" * 64

    def dispatch(self, target, action, before):
        # The real durable record must precede the one mutating call.
        states = [json.loads(p.read_text())["status"] for p in self.service.state_dir.glob("*.json")]
        assert "executing" in states
        self.actions.append((target, action))
        if self.fail_dispatch:
            raise helper.RuleChangeError("command failed")
        if action == "restart":
            self.observation["started_at"] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        self.observation["nginx_worker_pids"] = [13, 14]

    def verify(self, target, action, before, dispatched_at):
        if self.fail_verify:
            raise helper.RuleChangeError("not ready")
        return self.observe(target)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = time.time()
        self.broker = BrokerAdapter()
        self.engine = helper.Engine("a", self.broker, Path(self.tmp.name).resolve() / "state", clock=lambda: self.now)
        self.backend = FakeBackend(self.now)
        self.svc = service.ServiceActionService(self.engine, self.backend)
        self.backend.service = self.svc
        self.reader = mock.patch.object(self.engine, "get_target", return_value={"runtime": {"container_id": "a" * 64, "rule_source_path": "/rules/all.rules"}})
        self.reader.start()
        self.addCleanup(self.reader.stop)

    def test_read_source_evidence_never_changes_approval_state_hash(self):
        result = self.svc.get_target('a:suricata')
        self.assertEqual(result['rule_source_evidence']['rule_source_path'], '/rules/all.rules')
        self.assertEqual(result['base_state_sha256'], service.digest(result['observation']))
        with mock.patch.object(self.engine, 'get_target', side_effect=helper.RuleChangeError('read unavailable')):
            unavailable = self.svc.get_target('a:suricata')
        self.assertEqual(unavailable['rule_source_evidence']['status'], 'unavailable')
        self.assertEqual(unavailable['base_state_sha256'], result['base_state_sha256'])

    def tearDown(self):
        self.tmp.cleanup()

    def propose(self, target="a:waf", action="reload"):
        base = self.svc.get_target(target)["base_state_sha256"]
        return self.svc.propose(target, action, base, "사용자가 요청한 서비스 작업")

    def test_exact_allowlist_and_host_boundary(self):
        for target, action in [("a:suricata", "reload"), ("a:docker", "restart"),
                               ("b:wazuh-manager", "restart"), ("a:waf", "stop"),
                               ("a:waf;id", "restart"), ("a:waf", ["restart"])]:
            with self.subTest(target=target, action=action), self.assertRaises((helper.RuleChangeError, TypeError)):
                self.svc.propose(target, action, "0" * 64, "request")
        self.assertFalse(self.broker.cards)
        self.assertFalse(self.backend.actions)

    def test_read_and_propose_never_execute_and_review_contains_before(self):
        proposal = self.propose()
        self.assertEqual(proposal["status"], "pending")
        self.assertEqual(self.svc.worker_once()[0]["status"], "pending")
        self.assertFalse(self.backend.actions)
        card = self.broker.cards[0]["attachments"][0]["text"]
        self.assertIn(operations.display_summary_kst(self.backend.observation["started_at"]), card)
        self.assertIn("예상 변경 후 상태", card)
        self.assertIn("a:waf", card)
        self.assertEqual(self.broker.consumes, 0)

    def test_actual_broker_approval_exactly_once_and_result_hash_is_observation(self):
        proposal = self.propose()
        rid = proposal["request_id"]
        self.broker.decide(rid)
        result = self.svc.worker_once()[0]
        self.assertEqual(result["status"], "applied")
        self.assertEqual(self.backend.actions, [("a:waf", "reload")])
        self.assertEqual(self.broker.consumes, 1)
        self.assertTrue(result["result_posted"])
        status = self.svc.status(rid)
        self.assertEqual(status["after_observation_sha256"], service.digest(self.backend.observation))
        self.assertNotEqual(status["after_observation_sha256"], status["plan_sha256"])
        self.svc.worker_once()
        self.assertEqual(len(self.backend.actions), 1)

    def test_duplicate_request_and_lost_post_response_reuse_exact_id(self):
        self.broker.lose_create = True
        with self.assertRaisesRegex(helper.RuleChangeError, "lost create"):
            self.propose()
        rid = next(self.svc.state_dir.glob("*.json")).stem
        repeated = self.propose()
        self.assertEqual(repeated["request_id"], rid)
        self.assertEqual(self.propose()["request_id"], rid)
        self.assertEqual(len(self.broker.cards), 1)
        self.assertFalse(self.backend.actions)

    def test_denied_and_expired_never_consume(self):
        first = self.propose()
        self.broker.decide(first["request_id"], "deny")
        self.assertEqual(self.svc.worker_once()[0]["status"], "denied")
        second = self.propose()
        self.broker.broker.records[second["request_id"]]["expires_at"] = int(time.time()) - 1
        # The signed expiry mismatch also fails closed instead of trusting it.
        self.svc.worker_once()
        self.assertFalse(self.backend.actions)
        self.assertEqual(self.broker.consumes, 0)

    def test_stale_state_and_preflight_drift_abort_before_consume(self):
        proposal = self.propose()
        self.broker.decide(proposal["request_id"])
        self.backend.observation["files_sha256"] = "f" * 64
        result = self.svc.worker_once()[0]
        self.assertEqual(result["status"], "aborted")
        self.assertTrue(result["result_posted"])
        self.assertEqual(self.broker.consumes, 0)
        self.assertFalse(self.backend.actions)

    def test_invalid_preflight_does_not_post_or_dispatch(self):
        self.backend.fail_preflight = True
        with self.assertRaises(helper.RuleChangeError):
            self.propose()
        self.assertFalse(self.broker.cards)
        self.backend.fail_preflight = False
        self.backend.preflight_drift = True
        with self.assertRaisesRegex(helper.RuleChangeError, "during preflight"):
            self.propose()
        self.assertFalse(self.broker.cards)

    def test_failure_never_escalates_reload_to_restart_or_retries(self):
        proposal = self.propose()
        self.broker.decide(proposal["request_id"])
        self.backend.fail_dispatch = True
        self.assertEqual(self.svc.worker_once()[0]["status"], "failed")
        self.svc.worker_once()
        self.assertEqual(self.backend.actions, [("a:waf", "reload")])
        self.assertEqual(self.broker.consumes, 1)

    def test_failed_health_never_reports_applied(self):
        proposal = self.propose()
        self.broker.decide(proposal["request_id"])
        self.backend.fail_verify = True
        with mock.patch.object(service.time, "monotonic", side_effect=count(0, 200)), mock.patch.object(service.time, "sleep"):
            self.assertEqual(self.svc.worker_once()[0]["status"], "failed")
        self.assertEqual(len(self.backend.actions), 1)

    def test_lost_consume_response_never_dispatches_or_reconsumes(self):
        proposal = self.propose()
        self.broker.decide(proposal["request_id"])
        self.broker.lose_consume = True
        self.assertEqual(self.svc.worker_once()[0]["status"], "prepared")
        self.assertEqual(self.svc.worker_once()[0]["status"], "failed")
        self.assertFalse(self.backend.actions)
        self.assertEqual(self.broker.consumes, 1)

    def test_broker_restart_does_not_leave_expired_local_pending_or_prepared(self):
        proposal = self.propose()
        rid = proposal["request_id"]
        self.broker.broker.records.clear()
        self.now += 601
        self.assertEqual(self.svc.worker_once()[0]["status"], "expired")
        self.assertFalse(self.backend.actions)
        record = self.svc._load(rid)
        record["status"] = "prepared"
        self.svc._save(record)
        self.assertEqual(self.svc.worker_once()[0]["status"], "failed")
        self.assertFalse(self.backend.actions)
        self.assertEqual(self.broker.consumes, 0)

    def test_interrupted_durable_dispatch_is_not_replayed(self):
        proposal = self.propose()
        rid = proposal["request_id"]
        self.broker.decide(rid)
        self.broker.request("POST", "/operations/" + rid + "/consume", {"proposal_digest": proposal["proposal_digest"]})
        record = self.svc._load(rid)
        record["status"] = "executing"
        self.svc._save(record)
        self.assertEqual(self.svc.worker_once()[0]["status"], "failed")
        self.assertFalse(self.backend.actions)
        self.assertIn("uncertain", self.svc.status(rid)["result"])

    def test_result_outage_retries_reporting_only(self):
        proposal = self.propose()
        self.broker.decide(proposal["request_id"])
        self.broker.fail_result = True
        self.assertFalse(self.svc.worker_once()[0]["result_posted"])
        self.broker.fail_result = False
        self.svc.worker_once()
        self.assertTrue(self.svc.status(proposal["request_id"])["result_posted"])
        self.assertEqual(len(self.backend.actions), 1)

    def test_broker_kind_swap_and_state_tamper_fail_closed(self):
        proposal = self.propose()
        rid = proposal["request_id"]
        self.broker.decide(rid)
        self.broker.mutate_response = lambda out: dict(out, kind="containment")
        self.svc.worker_once()
        self.assertFalse(self.backend.actions)
        self.broker.mutate_response = None
        record = self.svc._load(rid)
        record["action"] = "restart"
        self.svc._save(record)
        self.svc.worker_once()
        self.assertEqual(self.broker.consumes, 0)

    def test_root_dispatch_hook_status_and_no_cwd_extension_import(self):
        proposal = self.propose()
        with mock.patch.object(helper, "_operation_services", return_value=[self.svc]):
            self.assertEqual(helper._operation_status(self.engine, proposal["request_id"])["request_id"], proposal["request_id"])
        with self.assertRaises(helper.RuleChangeError):
            helper._load_extension("os")
        unsafe = Path(self.tmp.name) / "unsafe"
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        with mock.patch.object(helper, "EXTENSION_DIR", unsafe), mock.patch.dict(helper._EXTENSIONS, {}, clear=True):
            with self.assertRaises(helper.RuleChangeError):
                helper._load_extension("service_action_executor")

    def test_worker_reconciles_containment_before_slow_rules_and_service_actions(self):
        order = []
        ordinary = mock.Mock()
        ordinary.worker_once.side_effect = lambda: order.append("service") or []
        containment = mock.Mock()
        containment.worker_once.side_effect = lambda: order.append("containment") or []
        with mock.patch.object(helper.os, "geteuid", return_value=0), \
                mock.patch.object(helper, "_secure_config", return_value=("a", self.broker)), \
                mock.patch.object(helper, "Engine", return_value=self.engine), \
                mock.patch.object(helper, "_operation_services", return_value=[ordinary, containment]), \
                mock.patch.object(self.engine, "worker_once", side_effect=lambda: order.append("rules") or []), \
                contextlib.redirect_stdout(io.StringIO()):
            helper.main(["--once"])
        self.assertEqual(order, ["containment", "rules", "service"])

    def test_real_verifier_rejects_same_generation_config_drift_and_unhealthy(self):
        backend = service.ServiceBackend(self.engine)
        before = copy.deepcopy(self.backend.observation)
        with mock.patch.object(backend, "observe", return_value=before):
            with self.assertRaisesRegex(helper.RuleChangeError, "worker generation"):
                backend.verify("a:waf", "reload", before, self.now)
        after = dict(before, nginx_worker_pids=[13], files_sha256="f" * 64)
        with mock.patch.object(backend, "observe", return_value=after):
            with self.assertRaisesRegex(helper.RuleChangeError, "configuration changed"):
                backend.verify("a:waf", "reload", before, self.now)
        after = dict(before, nginx_worker_pids=[13], health="unhealthy")
        with mock.patch.object(backend, "observe", return_value=after), mock.patch.object(backend, "_http_probe"):
            with self.assertRaisesRegex(helper.RuleChangeError, "Docker health"):
                backend.verify("a:waf", "reload", before, self.now)


if __name__ == "__main__":
    unittest.main()
