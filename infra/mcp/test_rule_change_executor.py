#!/usr/bin/env python3
"""Focused, offline safety tests for the approval-bound rule executor."""

from importlib.machinery import SourceFileLoader
from email.message import Message
import hashlib
import hmac
import io
import ipaddress
import json
from pathlib import Path
import tempfile
import time
import unittest
from urllib.parse import urlparse


MOD = SourceFileLoader("rule_change_executor", str(Path(__file__).with_name("rule_change_executor.py"))).load_module()


def digest(data):
    return hashlib.sha256(data).hexdigest()


class FakeBroker:
    def __init__(self):
        self.rows = {}
        self.fail_get = False
        self.fail_result_once = False
        self.fail_abort_once = False
        self.consumes = 0
        self.results = []
        self.aborts = []

    def request(self, method, path, body=None):
        if method == "POST" and path == "/rule-changes":
            rid = "%016x" % (len(self.rows) + 1)
            row = dict(body)
            row.update({"proposal_id": rid, "proposal_digest": MOD.proposal_digest(body),
                        "status": "pending", "by": ""})
            self.rows[rid] = row
            return {"proposal_id": rid, "proposal_digest": row["proposal_digest"],
                    "expires_at": row["expires_at"], "posted": True}
        rid = path.split("/")[2]
        row = self.rows[rid]
        if method == "GET":
            if self.fail_get:
                raise MOD.RuleChangeError("broker down")
            return dict(row)
        if method == "POST" and path.endswith("/consume"):
            assert row["status"] == "approved"
            assert body == {"proposal_digest": row["proposal_digest"]}
            self.consumes += 1
            row["status"] = "consumed"
            return {"status": "consumed", "proposal_digest": row["proposal_digest"]}
        if method == "POST" and path.endswith("/abort"):
            if self.fail_abort_once:
                self.fail_abort_once = False
                raise MOD.RuleChangeError("abort card unavailable")
            assert row["status"] in ("approved", "aborted")
            assert body["proposal_digest"] == row["proposal_digest"]
            row["status"] = "aborted"
            self.aborts.append(dict(body))
            return {"status": "aborted", "result_posted": True,
                    "readback_sha256": body["readback_sha256"]}
        if method == "POST" and path.endswith("/result"):
            if self.fail_result_once:
                self.fail_result_once = False
                raise MOD.RuleChangeError("result card unavailable")
            assert row["status"] == "consumed"
            self.results.append(dict(body))
            return {"status": body["status"], "result_posted": True,
                    "readback_sha256": body["readback_sha256"]}
        raise AssertionError((method, path))


class FakeRunner:
    def __init__(self, spec):
        self.spec = spec
        self.commands = []
        self.fail_on = None
        self.healthy = True
        self.remote_inode = None

    def call(self, argv, timeout=30):
        self.commands.append(argv)
        text = " ".join(argv)
        if self.fail_on and self.fail_on in text:
            raise MOD.RuleChangeError("simulated service validation failure")
        spec = self.spec
        if argv[1] == "inspect":
            info = {"State": {"Running": True, "Health": {"Status": "healthy" if self.healthy else "unhealthy"}},
                    "Mounts": [{"Source": spec["mount_source"], "Destination": spec["mount_dest"],
                                "RW": spec["kind"] == "wazuh"}],
                    "Config": {"Env": ["MODSEC_RULE_ENGINE=DetectionOnly"], "Cmd": ["-i", "ens192", "-S", "/rules/all.rules"]}}
            return json.dumps([info]).encode()
        if argv[1] == "exec" and "sha256sum" in argv:
            path = spec["all_path"] if spec["kind"] == "suricata" else spec["path"]
            return (digest(Path(path).read_bytes()) + "  " + argv[-1] + "\n").encode()
        if argv[1] == "exec" and "stat" in argv:
            return (str(self.remote_inode if self.remote_inode is not None else Path(spec["path"]).stat().st_ino) + "\n").encode()
        if argv[1] == "exec" and any(part.endswith("wazuh-control") for part in argv):
            return b"wazuh-analysisd is running\nwazuh-remoted is running\nwazuh-db is running\n"
        if argv[1] == "exec" and "suricata" in argv and "-T" in argv:
            assert Path(spec["all_path"]).parent.joinpath(Path(argv[-1]).name).exists()
        return b"ok\n"


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.broker = FakeBroker()

    def tearDown(self):
        self.tmp.cleanup()

    def engine(self, kind):
        root = self.base / kind
        root.mkdir()
        if kind == "waf":
            target = "a:modsecurity-custom"
            current = b"SecRuleEngine DetectionOnly\nSecRule ARGS \"@rx old\" \"id:10100,phase:1,log\"\n"
            spec = {"host": "a", "kind": kind, "path": str(root / "GROOT_A_WAF.conf"),
                    "container": "waf", "container_path": "/etc/custom.conf",
                    "mount_source": str(root / "GROOT_A_WAF.conf"), "mount_dest": "/etc/custom.conf", "impact": "WAF reload"}
        elif kind == "suricata":
            target = "a:suricata-local"
            current = b"alert tcp any any -> any any (msg:\"old\"; sid:1000001; rev:1;)\n"
            spec = {"host": "a", "kind": kind, "path": str(root / "GROOT_A_local.rules"),
                    "et_path": str(root / "suricata.rules"), "all_path": str(root / "all.rules"),
                    "container": "suricata", "container_path": "/rules/all.rules",
                    "mount_source": str(root), "mount_dest": "/rules", "impact": "Suricata reload"}
            (root / "suricata.rules").write_bytes(b"alert tcp any any -> any any (msg:\"ET\"; sid:2000000; rev:1;)\n")
            (root / "all.rules").write_bytes((root / "suricata.rules").read_bytes() + current)
        else:
            target = "b:wazuh-local-rules"
            current = b'<group name="x,"><rule id="100100" level="3"><description>old</description></rule></group>\n'
            spec = {"host": "b", "kind": kind, "path": str(root / "local_rules.xml"),
                    "container": "single-node-wazuh.manager-1", "container_path": "/var/ossec/etc/rules/local_rules.xml",
                    "mount_source": str(root), "mount_dest": "/var/ossec/etc", "impact": "Wazuh restart"}
        Path(spec["path"]).write_bytes(current)
        runner = FakeRunner(spec)
        engine = MOD.Engine(spec["host"], self.broker, self.base / (kind + "-state"),
                            targets={target: spec}, runner=runner, clock=lambda: 1000)
        return engine, runner, target, current

    def candidate(self, kind):
        if kind == "waf":
            return 'SecRuleEngine DetectionOnly\nSecRule ARGS "@rx new" "id:10100,phase:1,log"\n'
        if kind == "suricata":
            return 'alert tcp any any -> any any (msg:"new"; sid:1000001; rev:2;)\n'
        return '<group name="x,"><rule id="100100" level="4"><description>new</description></rule></group>\n'

    def propose(self, engine, target, current, kind):
        return engine.propose(target, digest(current), self.candidate(kind), "user requested adjustment")

    def test_get_and_stale_base_rejection(self):
        engine, _, target, current = self.engine("waf")
        got = engine.get_target(target)
        self.assertEqual(got["content"], current.decode())
        self.assertEqual(got["sha256"], digest(current))
        with self.assertRaisesRegex(MOD.RuleChangeError, "changed since it was read"):
            engine.propose(target, "0" * 64, self.candidate("waf"), "requested")
        self.assertEqual(self.broker.rows, {})

    def test_read_only_check_creates_no_state_directory(self):
        engine, runner, target, _ = self.engine("waf")
        other_state = self.base / "not-created"
        check = MOD.Engine("a", self.broker, other_state, targets={target: engine.targets[target]},
                           runner=runner, clock=lambda: 1000, read_only=True)
        self.assertIn(target, check.check()["targets"])
        self.assertFalse(other_state.exists())

    def test_target_parent_symlink_rejected(self):
        engine, runner, target, _ = self.engine("waf")
        alias = self.base / "alias"
        alias.symlink_to(Path(engine.targets[target]["path"]).parent, target_is_directory=True)
        spec = dict(engine.targets[target], path=str(alias / "GROOT_A_WAF.conf"),
                    mount_source=str(alias / "GROOT_A_WAF.conf"))
        runner.spec = spec
        engine.targets[target] = spec
        with self.assertRaisesRegex(MOD.RuleChangeError, "parent path"):
            engine.get_target(target)

    def test_waf_stale_file_bind_inode_rejected(self):
        engine, runner, target, _ = self.engine("waf")
        runner.remote_inode = 1
        with self.assertRaisesRegex(MOD.RuleChangeError, "bind mount"):
            engine.get_target(target)

    def test_pending_and_denied_never_write(self):
        engine, _, target, current = self.engine("waf")
        proposal = self.propose(engine, target, current, "waf")
        self.assertEqual(engine.worker_once()[0]["status"], "pending")
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)
        self.broker.rows[proposal["proposal_id"]]["status"] = "denied"
        self.assertEqual(engine.worker_once()[0]["status"], "denied")
        self.assertEqual(self.broker.consumes, 0)

    def test_broker_outage_fails_closed(self):
        engine, _, target, current = self.engine("waf")
        self.propose(engine, target, current, "waf")
        self.broker.fail_get = True
        self.assertEqual(engine.worker_once()[0]["status"], "pending")
        self.assertEqual(self.broker.consumes, 0)
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def test_waf_approval_one_use_inode_and_result(self):
        engine, _, target, current = self.engine("waf")
        proposal = self.propose(engine, target, current, "waf")
        path = Path(engine.targets[target]["path"])
        inode = path.stat().st_ino
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.broker.rows[proposal["proposal_id"]]["by"] = "operator"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(path.read_text(), self.candidate("waf"))
        self.assertEqual(self.broker.consumes, 1)
        self.assertEqual(self.broker.results[0]["readback_sha256"], digest(self.candidate("waf").encode()))
        self.assertEqual(engine.worker_once(), [])
        self.assertEqual(self.broker.consumes, 1)

    def test_suricata_staged_validation_and_combined_reload(self):
        engine, runner, target, current = self.engine("suricata")
        proposal = self.propose(engine, target, current, "suricata")
        self.assertIn("staged", proposal["validation"])
        self.assertEqual(Path(engine.targets[target]["all_path"]).read_bytes(),
                         Path(engine.targets[target]["et_path"]).read_bytes() + current)
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        spec = engine.targets[target]
        self.assertEqual(Path(spec["all_path"]).read_bytes(), Path(spec["et_path"]).read_bytes() + self.candidate("suricata").encode())
        self.assertTrue(any("reload-rules" in cmd for cmd in runner.commands))

    def test_wazuh_restart_checks_processes(self):
        engine, runner, target, current = self.engine("wazuh")
        proposal = self.propose(engine, target, current, "wazuh")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertTrue(any(any(part.endswith("wazuh-analysisd") for part in cmd) for cmd in runner.commands))
        self.assertTrue(any(any(part.endswith("wazuh-control") for part in cmd) for cmd in runner.commands))
        self.assertTrue(any(cmd[1] == "restart" for cmd in runner.commands))

    def test_base_drift_after_approval_rejected_before_consume(self):
        engine, _, target, current = self.engine("waf")
        proposal = self.propose(engine, target, current, "waf")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        Path(engine.targets[target]["path"]).write_text("SecRuleEngine DetectionOnly\n# unrelated live edit\n")
        self.assertEqual(engine.worker_once()[0]["status"], "aborted")
        self.assertEqual(self.broker.consumes, 0)
        self.assertEqual(len(self.broker.aborts), 1)

    def test_preconsume_abort_card_retry_never_consumes(self):
        engine, _, target, current = self.engine("waf")
        proposal = self.propose(engine, target, current, "waf")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        Path(engine.targets[target]["path"]).write_text("SecRuleEngine DetectionOnly\n# drift\n")
        self.broker.fail_abort_once = True
        self.assertEqual(engine.worker_once()[0]["status"], "abort_pending")
        self.assertEqual(engine.worker_once()[0]["status"], "aborted")
        self.assertEqual(self.broker.consumes, 0)
        self.assertEqual(len(self.broker.aborts), 1)

    def test_service_validation_failure_restores_and_reports(self):
        engine, runner, target, current = self.engine("waf")
        proposal = self.propose(engine, target, current, "waf")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        # Fail once on candidate validation, then allow restore validation.
        original_call = runner.call
        failed = [False]
        def fail_once(argv, timeout=30):
            if "nginx" in argv and "-t" in argv and not failed[0]:
                failed[0] = True
                raise MOD.RuleChangeError("bad nginx candidate")
            return original_call(argv, timeout)
        runner.call = fail_once
        self.assertEqual(engine.worker_once()[0]["status"], "rolled_back")
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)
        self.assertEqual(self.broker.results[0]["status"], "rolled_back")
        self.assertEqual(self.broker.results[0]["readback_sha256"], digest(current))

    def test_result_post_retry_never_reapplies(self):
        engine, _, target, current = self.engine("waf")
        proposal = self.propose(engine, target, current, "waf")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.broker.fail_result_once = True
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertEqual(self.broker.results, [])
        self.assertEqual(engine.worker_once(), [])
        self.assertEqual(len(self.broker.results), 1)
        self.assertEqual(self.broker.consumes, 1)

    def test_reject_mode_escalation(self):
        for kind, candidate in (("waf", "SecRuleEngine DetectionOnly\nSecRule ARGS @rx x \"ctl:ruleEngine=On\"\n"),
                                ("suricata", 'drop tcp any any -> any any (msg:"x"; sid:1000001; rev:1;)\n')):
            with self.subTest(kind=kind):
                with self.assertRaises(MOD.RuleChangeError):
                    MOD._validate_candidate(kind, candidate)

    def test_hmac_broker_authenticates_both_directions_without_bearer_header(self):
        key = "k" * 40
        broker = MOD.Broker("http://10.200.10.10:8090", key)
        class Response:
            status = 200
            def __init__(self, nonce, valid):
                self.body = b'{"status":"ready"}'
                msg = ("v1\n%s\n200\n%s" % (nonce, digest(self.body))).encode()
                self.headers = {"X-Rule-Response-Signature": hmac.new(key.encode(), msg, hashlib.sha256).hexdigest() if valid else "0" * 64}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n): return self.body
        class Opener:
            valid = True
            def open(self, request, timeout):
                nonce = request.get_header("X-rule-nonce")
                timestamp = request.get_header("X-rule-timestamp")
                signature = request.get_header("X-rule-signature")
                self_test.assertIsNone(request.get_header("X-rule-broker-token"))
                body = request.data or b""
                msg = ("v1\n%s\n%s\n%s\n%s\n%s" % (request.get_method(), "/rule-changes/health", timestamp, nonce, digest(body))).encode()
                self_test.assertEqual(signature, hmac.new(key.encode(), msg, hashlib.sha256).hexdigest())
                return Response(nonce, self.valid)
        self_test = self
        opener = Opener()
        broker.opener = opener
        self.assertTrue(broker.health())
        opener.valid = False
        with self.assertRaisesRegex(MOD.RuleChangeError, "signature invalid"):
            broker.health()

    def test_real_broker_handler_wire_contract_without_socket(self):
        bot = SourceFileLoader("rule_wire_soc_bot", str(Path(__file__).with_name("soc_bot.py"))).load_module()
        bot.RULE_BROKER_TOKEN = "z" * 40
        bot.BROKER_TOKEN = "y" * 40
        bot.RULE_APPROVERS = ["operator-id"]
        bot.RULE_MM_SOURCES = [ipaddress.ip_network("127.0.0.1/32")]
        bot.MM_WEBHOOK = "http://unused.invalid"
        bot.MM_ACTION_URL = "http://127.0.0.1:8090"
        bot.post_mm = lambda _payload: (True, "posted")
        bot.RULE_APPROVALS.clear()
        bot.RULE_NONCES.clear()

        class Response:
            def __init__(self, raw):
                head, self.body = raw.split(b"\r\n\r\n", 1)
                lines = head.decode("ascii").split("\r\n")
                self.status = int(lines[0].split()[1])
                self.headers = Message()
                for line in lines[1:]:
                    if line:
                        key, value = line.split(":", 1)
                        self.headers[key] = value.strip()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, n): return self.body[:n]

        class Opener:
            def __init__(self): self.last_request = None
            def open(self, request, timeout):
                self.last_request = request
                handler = bot.Handler.__new__(bot.Handler)
                handler.path = urlparse(request.full_url).path
                handler.command = request.get_method()
                handler.request_version = "HTTP/1.1"
                handler.requestline = "%s %s HTTP/1.1" % (handler.command, handler.path)
                handler.client_address = ("127.0.0.1", 50000)
                handler.headers = Message()
                for key, value in request.header_items():
                    handler.headers[key] = value
                body = request.data or b""
                handler.headers["Content-Length"] = str(len(body))
                handler.rfile = io.BytesIO(body)
                handler.wfile = io.BytesIO()
                if handler.command == "GET":
                    handler.do_GET()
                else:
                    handler.do_POST()
                return Response(handler.wfile.getvalue())

        broker = MOD.Broker("http://127.0.0.1:8090", bot.RULE_BROKER_TOKEN)
        opener = Opener()
        broker.opener = opener
        self.assertTrue(broker.health())
        replay = opener.open(opener.last_request, timeout=1)
        self.assertEqual(replay.status, 401)  # same nonce cannot authenticate twice
        diff_text = "--- before\n+++ after\n@@ -1 +1 @@\n-old\n+new\n"
        payload = {"target": "a:modsecurity-custom", "base_sha256": "0" * 64,
                   "candidate_sha256": "1" * 64, "diff_sha256": digest(diff_text.encode()),
                   "diff": diff_text, "requested_by": "hermes-rule-change",
                   "expires_at": int(time.time()) + 300}
        created = broker.request("POST", "/rule-changes", payload)
        self.assertTrue(created["posted"])
        rid = created["proposal_id"]
        self.assertEqual(broker.request("GET", "/rule-changes/" + rid)["status"], "pending")
        self.assertEqual(created["proposal_digest"], MOD.proposal_digest(payload))
        bot.RULE_APPROVALS[rid]["status"] = "approved"
        bot.RULE_APPROVALS[rid]["by"] = "operator"
        aborted = broker.request("POST", "/rule-changes/" + rid + "/abort", {
            "proposal_digest": created["proposal_digest"], "readback_sha256": payload["base_sha256"],
            "detail": "live base changed; rule was not applied"})
        self.assertEqual(aborted["status"], "aborted")
        self.assertTrue(aborted["result_posted"])


if __name__ == "__main__":
    unittest.main()
