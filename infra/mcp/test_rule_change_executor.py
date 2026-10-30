#!/usr/bin/env python3
"""Focused, offline safety tests for the approval-bound rule executor."""

from importlib.machinery import SourceFileLoader
from email.message import Message
from datetime import datetime, timezone
import hashlib
import hmac
import io
import ipaddress
from itertools import count
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import urlparse


MOD = SourceFileLoader("rule_change_executor", str(Path(__file__).with_name("rule_change_executor.py"))).load_module()
ET_MARKER = ('alert tcp 192.168.16.230 any -> 211.170.162.110 11434 ( \\\n'
             ' msg:"GROOT-LOCAL observed Ollama API transport marker (noalert)"; \\\n'
             ' flow:to_server,established; flowbits:set,groot_llm_api; flowbits:noalert; sid:1000000; rev:1;)\n')
ET_MARKER_DUAL = ET_MARKER.replace('211.170.162.110', '[211.170.162.110,211.170.162.111]').replace('sid:1000000; rev:1;', 'sid:1000000; rev:2;')
ET_SOURCE = ('alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET one"; flow:established,to_server; content:"needle-one"; sid:2034806; rev:2;)\n'
             'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET two"; flow:established,to_server; content:"needle-two"; gid:1; sid:2034802; rev:2;)\n')
ET_GUARDED = ET_SOURCE.replace('; sid:', '; flowbits:isnotset,groot_llm_api; sid:').replace('rev:2;', 'rev:3;')


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
        self.running = True
        self.restart_count = 0
        self.container_id = "a" * 64
        self.started_at = "1970-01-01T00:16:39+00:00"
        self.active_rules = Path(spec["all_path"]).read_bytes() if spec["kind"] == "suricata" else b""
        self.socket_replies = {}

    def call(self, argv, timeout=30):
        self.commands.append(argv)
        text = " ".join(argv)
        if self.fail_on and self.fail_on in text:
            raise MOD.RuleChangeError("simulated service validation failure")
        spec = self.spec
        if argv[1] == "inspect":
            info = {"Id": self.container_id,
                    "State": {"Running": self.running, "StartedAt": self.started_at,
                              "OOMKilled": False, "Restarting": False,
                              "Health": {"Status": "healthy" if self.healthy else "unhealthy"}},
                    "Mounts": [{"Source": spec["mount_source"], "Destination": spec["mount_dest"],
                                "RW": spec["kind"] == "wazuh"}],
                    "Config": {"Env": ["MODSEC_RULE_ENGINE=DetectionOnly"], "Cmd": ["-i", "ens192", "-S", "/rules/all.rules"]}}
            return json.dumps([info]).encode()
        if argv[1] == "restart":
            self.restart_count += 1
            self.running = True
            self.started_at = datetime.fromtimestamp(1000 + self.restart_count, timezone.utc).isoformat()
            if spec["kind"] == "suricata":
                self.active_rules = Path(spec["all_path"]).read_bytes()
            return (spec["container"] + "\n").encode()
        if "suricatasc" in argv:
            if argv[-1] in self.socket_replies:
                return self.socket_replies[argv[-1]]
            if argv[-1] == "ruleset-stats":
                row = {"id": 0, "rules_loaded": self.active_rules.count(b"sid:"), "rules_failed": 0, "rules_skipped": 0}
            elif argv[-1] == "ruleset-reload-time":
                row = {"id": 0, "last_reload": self.started_at}
            else:
                raise AssertionError("unexpected Suricata socket mutation: " + argv[-1])
            return json.dumps({"return": "OK", "message": [row]}).encode()
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
                    "mount_source": str(root), "mount_dest": "/rules", "impact": MOD.TARGETS[target]["impact"]}
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

    def max_waf_comment(self, character):
        prefix = "SecRuleEngine DetectionOnly\n# "
        remaining = MOD.MAX_CANDIDATE - len(prefix.encode("utf-8")) - 1
        copies, padding = divmod(remaining, len(character.encode("utf-8")))
        return prefix + character * copies + " " * padding + "\n"

    def test_literal_edit_uses_existing_approval_apply_and_readback_on_all_targets(self):
        for kind in ("waf", "suricata", "wazuh"):
            with self.subTest(kind=kind):
                engine, runner, target, current = self.engine(kind)
                expected = current.replace(b"old", "새 값".encode("utf-8"))
                proposal = engine.propose_edit(target, digest(current),
                    [{"old_text": "old", "new_text": "새 값"}], "literal change")
                rid = proposal["proposal_id"]
                path = Path(engine.targets[target]["path"])
                inode = path.stat().st_ino
                record = engine._load(rid)
                self.assertNotIn("diff", proposal)
                self.assertNotIn("candidate_content", proposal)
                self.assertTrue(proposal["review_posted"])
                self.assertEqual(proposal["edit_count"], 1)
                self.assertEqual(proposal["review_location"], "Mattermost approval channel")
                self.assertEqual(proposal["before_sha256"], digest(current))
                self.assertEqual(proposal["after_sha256"], digest(expected))
                self.assertEqual(proposal["candidate_utf8_bytes"], len(expected))
                self.assertEqual(record["candidate_content"].encode("utf-8"), expected)
                self.assertEqual(proposal["diff_sha256"], digest(record["payload"]["diff"].encode("utf-8")))
                self.assertEqual(proposal["diff_utf8_bytes"], len(record["payload"]["diff"].encode("utf-8")))
                self.assertEqual(proposal["proposal_digest"], MOD.proposal_digest(record["payload"]))
                self.assertEqual(self.broker.rows[rid]["diff"], record["payload"]["diff"])
                self.assertEqual(engine.worker_once()[0]["status"], "pending")
                self.assertEqual(path.read_bytes(), current)
                consumed = self.broker.consumes
                self.broker.rows[rid]["status"] = "approved"
                self.assertEqual(engine.worker_once()[0]["status"], "applied")
                self.assertEqual(path.read_bytes(), expected)
                if kind == "waf":
                    self.assertEqual(path.stat().st_ino, inode)
                if kind == "suricata":
                    self.assertIn("staged", proposal["validation"])
                    self.assertEqual(runner.active_rules,
                                     Path(engine.targets[target]["et_path"]).read_bytes() + expected)
                    self.assertFalse(list(path.parent.glob(".rule-change-probe-*")))
                self.assertEqual(self.broker.results[-1]["readback_sha256"], digest(expected))
                self.assertEqual(engine.worker_once(), [])
                self.assertEqual(self.broker.consumes, consumed + 1)

    def test_literal_edits_preserve_utf8_whitespace_lf_and_original_order(self):
        engine, _, target, current = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        before = "# 보존\t줄\n".encode() + current + "# 끝\t공백 \n\n".encode()
        path.write_bytes(before)
        edits = [{"old_text": "# 끝", "new_text": "# 마감"},
                 {"old_text": "@rx old", "new_text": "@rx 새값"},
                 {"old_text": "SecRuleEngine", "new_text": "# 추가\nSecRuleEngine"}]
        proposal = engine.propose_edit(target, digest(before), edits, "UTF-8 preservation")
        expected = before.replace("# 끝".encode(), "# 마감".encode()).replace(
            b"@rx old", "@rx 새값".encode()).replace(b"SecRuleEngine", "# 추가\nSecRuleEngine".encode())
        candidate = engine._load(proposal["proposal_id"])["candidate_content"].encode()
        self.assertEqual(candidate, expected)
        self.assertTrue(candidate.endswith("\t공백 \n\n".encode()))
        self.assertEqual(path.read_bytes(), before)

    def test_literal_edit_rejects_missing_ambiguous_overlapping_and_sequential_matches(self):
        engine, _, target, current = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        current += b"# aaa\n"
        path.write_bytes(current)
        cases = [
            ([{"old_text": "absent", "new_text": "new"}], "absent"),
            ([{"old_text": "aa", "new_text": "b"}], "exactly once"),  # Overlapping aa in aaa.
            ([{"old_text": "old", "new_text": "one"}, {"old_text": "old", "new_text": "two"}], "overlap"),
            ([{"old_text": "@rx old", "new_text": "one"}, {"old_text": "rx ol", "new_text": "two"}], "overlap"),
            ([{"old_text": "old", "new_text": "inserted"},
              {"old_text": "inserted", "new_text": "sequential"}], "absent"),
            ([{"old_text": "@rx o", "new_text": "@rx "},
              {"old_text": "ld", "new_text": "old"}], "identical"),
        ]
        for edits, error in cases:
            with self.subTest(edits=edits), mock.patch.object(engine, "_candidate_preflight") as preflight:
                with self.assertRaisesRegex(MOD.RuleChangeError, error):
                    engine.propose_edit(target, digest(current), edits, "must reject")
                preflight.assert_not_called()
                self.assertEqual(path.read_bytes(), current)
                self.assertFalse(self.broker.rows)
                self.assertFalse(list(engine.state_dir.glob("*.json")))

    def test_literal_edits_never_search_replacement_text_and_allow_adjacent_ranges(self):
        engine, _, target, current = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        current += b"# beta\n"
        path.write_bytes(current)
        edits = [{"old_text": "old", "new_text": "beta"},
                 {"old_text": "beta", "new_text": "gamma"},
                 {"old_text": "id:10100", "new_text": "id:10101"},
                 {"old_text": ",phase:1", "new_text": ",phase:2"}]
        proposal = engine.propose_edit(target, digest(current), edits, "simultaneous literals")
        expected = current.replace(b"old", b"beta").replace(b"# beta", b"# gamma").replace(
            b"id:10100,phase:1", b"id:10101,phase:2")
        self.assertEqual(engine._load(proposal["proposal_id"])["candidate_content"].encode(), expected)

    def test_literal_edit_input_contract_rejects_invalid_data_before_live_reads(self):
        engine, _, target, current = self.engine("waf")
        valid = {"old_text": "old", "new_text": "new"}
        invalid = [None, {}, (), [], [valid] * 17, ["not an edit"],
                   [{"old_text": "old"}], [dict(valid, path="/tmp/escape")],
                   [{"old_text": "", "new_text": "new"}],
                   [{"old_text": True, "new_text": "new"}],
                   [{"old_text": "old", "new_text": None}],
                   [{"old_text": "old", "new_text": "old"}],
                   [{"old_text": "old", "new_text": "\ud800"}],
                   [{"old_text": "old", "new_text": "가" * (MOD.MAX_EDIT_TEXT // 3)}]]
        with mock.patch.object(engine, "_snapshot") as snapshot:
            for edits in invalid:
                with self.subTest(edits=repr(edits)[:100]), self.assertRaises(MOD.RuleChangeError):
                    engine.propose_edit(target, digest(current), edits, "bad edit input")
            snapshot.assert_not_called()
        self.assertFalse(self.broker.rows)

    def test_literal_edit_count_and_utf8_byte_budget_boundaries(self):
        engine, _, target, current = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        before = current + b"".join(("# anchor-%02d\n" % i).encode() for i in range(16))
        path.write_bytes(before)
        edits = [{"old_text": "anchor-%02d" % i, "new_text": "changed-%02d" % i} for i in range(16)]
        self.assertEqual(engine.propose_edit(target, digest(before), edits, "sixteen edits")["edit_count"], 16)
        replacement = "x" * (MOD.MAX_EDIT_TEXT - len("old"))
        self.assertEqual(len("old".encode()) + len(replacement.encode()), MOD.MAX_EDIT_TEXT)
        self.assertEqual(engine.propose_edit(target, digest(before),
            [{"old_text": "old", "new_text": replacement}], "at byte limit")["status"], "pending")
        with self.assertRaisesRegex(MOD.RuleChangeError, "64 KiB"):
            engine.propose_edit(target, digest(before),
                [{"old_text": "old", "new_text": replacement + "x"}], "over byte limit")
        self.assertEqual(len(self.broker.rows), 2)

    def test_literal_edit_stale_base_unknown_target_and_wrong_host_fail_before_assembly(self):
        engine, _, target, current = self.engine("waf")
        edits = [{"old_text": "old", "new_text": "new"}]
        with mock.patch.object(MOD, "_edit_candidate") as assemble:
            with self.assertRaisesRegex(MOD.RuleChangeError, "changed since it was read"):
                engine.propose_edit(target, "0" * 64, edits, "stale")
            with self.assertRaisesRegex(MOD.RuleChangeError, "SHA-256"):
                engine.propose_edit(target, "bad", edits, "invalid hash")
            with self.assertRaises(MOD.RuleChangeError):
                engine.propose_edit("/tmp/not-allowed", digest(current), edits, "bad target")
            engine.host = "b"
            with self.assertRaises(MOD.RuleChangeError):
                engine.propose_edit(target, digest(current), edits, "wrong host")
            assemble.assert_not_called()
        self.assertFalse(self.broker.rows)

    def test_literal_edit_assembled_candidate_keeps_size_mode_and_newline_guards(self):
        engine, _, target, current = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        edits = [
            [{"old_text": "DetectionOnly", "new_text": "On"}],
            [{"old_text": "old", "new_text": "bad\x00"}],
            [{"old_text": "old", "new_text": "bad\r"}],
            [{"old_text": "old", "new_text": "bad\u202e"}],
            [{"old_text": 'phase:1,log"\n', "new_text": 'phase:1,log"'}],
            [{"old_text": current.decode(), "new_text": ""}],
        ]
        for change in edits:
            with self.subTest(change=change), mock.patch.object(engine, "_candidate_preflight") as preflight:
                with self.assertRaises(MOD.RuleChangeError):
                    engine.propose_edit(target, digest(current), change, "reject invalid final file")
                preflight.assert_not_called()
        maximum = self.max_waf_comment("가").encode()
        path.write_bytes(maximum)
        with self.assertRaisesRegex(MOD.RuleChangeError, "<=128 KiB"):
            engine.propose_edit(target, digest(maximum),
                [{"old_text": "SecRuleEngine", "new_text": "# extra\nSecRuleEngine"}], "final file too large")
        self.assertEqual(path.read_bytes(), maximum)
        self.assertFalse(self.broker.rows)

    def test_literal_edit_large_diff_uses_same_candidate_digest_and_complete_review(self):
        engine, _, target, _ = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        before = self.max_waf_comment("가")
        unique = "한번만찾을표식"
        before = before[:before.index("# ") + 2] + unique + before[before.index("# ") + 2 + len(unique):]
        path.write_bytes(before.encode())
        expected = before.replace(unique, "바뀐표식")
        full = engine.propose(target, digest(before.encode()), expected, "same exact change")
        edit = engine.propose_edit(target, digest(before.encode()),
            [{"old_text": unique, "new_text": "바뀐표식"}], "same exact change")
        self.assertGreater(edit["diff_utf8_bytes"], 256 * 1024)
        self.assertLess(edit["diff_utf8_bytes"], MOD.MAX_DIFF)
        self.assertLess(len(json.dumps(edit, ensure_ascii=False).encode()), 4096)
        complete = self.broker.rows[full["proposal_id"]]
        compact = self.broker.rows[edit["proposal_id"]]
        for key in ("diff", "base_sha256", "candidate_sha256", "diff_sha256", "proposal_digest"):
            self.assertEqual(complete[key], compact[key])
        self.assertNotIn("diff", edit)
        self.assertEqual(path.read_bytes(), before.encode())

    def test_literal_edit_failed_preflight_or_broker_never_saves_or_applies(self):
        engine, runner, target, current = self.engine("suricata")
        edits = [{"old_text": "old", "new_text": "new"}]
        runner.fail_on = " -T "
        with self.assertRaisesRegex(MOD.RuleChangeError, "validation failure"):
            engine.propose_edit(target, digest(current), edits, "preflight fails")
        self.assertFalse(list(Path(engine.targets[target]["path"]).parent.glob(".rule-change-probe-*")))
        runner.fail_on = None
        with mock.patch.object(self.broker, "request", side_effect=MOD.RuleChangeError("broker unavailable")):
            with self.assertRaisesRegex(MOD.RuleChangeError, "broker unavailable"):
                engine.propose_edit(target, digest(current), edits, "broker fails")
        with mock.patch.object(self.broker, "request", return_value={"posted": False}):
            with self.assertRaisesRegex(MOD.RuleChangeError, "valid approval card"):
                engine.propose_edit(target, digest(current), edits, "review not posted")
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)
        self.assertEqual(runner.restart_count, 0)
        self.assertFalse(list(engine.state_dir.glob("*.json")))
        self.assertFalse(self.broker.rows)

    def test_literal_edit_keeps_suricata_and_wazuh_engine_guards(self):
        cases = [("suricata", {"old_text": "alert", "new_text": "drop"}),
                 ("wazuh", {"old_text": "</group>",
                            "new_text": "<active-response>unexpected</active-response></group>"})]
        for kind, edit in cases:
            with self.subTest(kind=kind):
                engine, _, target, current = self.engine(kind)
                with mock.patch.object(engine, "_candidate_preflight") as preflight:
                    with self.assertRaises(MOD.RuleChangeError):
                        engine.propose_edit(target, digest(current), [edit], "must reject escalation")
                    preflight.assert_not_called()
                self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)
                self.assertFalse(self.broker.rows)

    def test_wazuh_bare_comment_is_rejected_before_card_or_engine_actions(self):
        engine, runner, target, current = self.engine('wazuh')
        for candidate in ('# audit\n' + current.decode(),
                          current.decode().replace('</group>', '</group># audit'),
                          current.decode().replace('<rule ', '# audit\n<rule ')):
            with self.subTest(candidate=candidate), mock.patch.object(engine, '_candidate_preflight') as preflight:
                with self.assertRaisesRegex(MOD.RuleChangeError, 'Wazuh comments must use XML syntax'):
                    engine.propose(target, digest(current), candidate, 'comment validation')
                preflight.assert_not_called()
                self.assertFalse(self.broker.rows)
                self.assertFalse(list(engine.state_dir.glob('*.json')))
                self.assertEqual(Path(engine.targets[target]['path']).read_bytes(), current)
        valid = '<!-- audit -->\n' + current.decode().replace('old', '# literal description')
        self.assertEqual(MOD._validate_candidate('wazuh', valid), valid.encode())
        with self.assertRaisesRegex(MOD.RuleChangeError, 'Wazuh comments must use XML syntax'):
            engine.propose_edit(target, digest(current), [{'old_text': current.decode(),
                'new_text': '# audit\n' + current.decode()}], 'comment validation')
        self.assertEqual(runner.restart_count, 0)

    def test_literal_edit_keeps_fixed_et_flowbit_guard(self):
        engine, runner, target, _, candidate, et = self.et_engine()
        spec = engine.targets[target]
        current = candidate.encode()
        Path(spec["path"]).write_bytes(current)
        Path(spec["all_path"]).write_bytes(et + current)
        runner.active_rules = et + current
        mutations = [{"old_text": "192.168.16.230", "new_text": "any"},
                     {"old_text": "needle-one", "new_text": "weakened"}]
        for edit in mutations:
            with self.subTest(edit=edit), self.assertRaises(MOD.RuleChangeError):
                engine.propose_edit(target, digest(current), [edit], "cannot weaken ET exception")
            self.assertFalse(list(Path(spec["path"]).parent.glob(".rule-change-probe-*")))
        self.assertEqual(Path(spec["path"]).read_bytes(), current)
        self.assertEqual(Path(spec["all_path"]).read_bytes(), et + current)
        self.assertFalse(self.broker.rows)

    def test_literal_edit_broker_binding_and_saved_candidate_tampering_fail_closed(self):
        engine, _, target, current = self.engine("waf")
        edits = [{"old_text": "old", "new_text": "new"}]
        request = self.broker.request

        def incorrect_binding(method, path, body=None):
            answer = request(method, path, body)
            return dict(answer, proposal_digest="0" * 64)

        with mock.patch.object(self.broker, "request", side_effect=incorrect_binding):
            with self.assertRaisesRegex(MOD.RuleChangeError, "binding mismatch"):
                engine.propose_edit(target, digest(current), edits, "invalid broker reply")
        self.assertFalse(list(engine.state_dir.glob("*.json")))
        proposal = engine.propose_edit(target, digest(current), edits, "valid proposal")
        rid = proposal["proposal_id"]
        self.broker.rows[rid]["status"] = "approved"
        record = engine._load(rid)
        record["candidate_content"] = record["candidate_content"].replace("new", "unreviewed")
        engine._save(record)
        self.assertEqual(engine.worker_once()[0]["status"], "pending")
        self.assertIn("candidate content changed", engine._load(rid)["result"])
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)
        self.assertEqual(self.broker.consumes, 0)

    def test_literal_edit_apply_failure_uses_existing_rollback(self):
        engine, runner, target, current = self.engine("suricata")
        proposal = engine.propose_edit(target, digest(current),
            [{"old_text": "old", "new_text": "new"}], "rollback trial")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        runner.fail_on = "-T -S /rules/all.rules"
        self.assertEqual(engine.worker_once()[0]["status"], "rolled_back")
        spec = engine.targets[target]
        self.assertEqual(Path(spec["path"]).read_bytes(), current)
        self.assertEqual(Path(spec["all_path"]).read_bytes(), Path(spec["et_path"]).read_bytes() + current)
        self.assertEqual(self.broker.results[-1]["status"], "rolled_back")
        self.assertEqual(self.broker.results[-1]["readback_sha256"], digest(current))
        self.assertEqual(self.broker.consumes, 1)
        self.assertEqual(engine.worker_once(), [])
        self.assertEqual(self.broker.consumes, 1)

    def test_literal_edit_denied_and_drifted_proposals_do_not_apply(self):
        engine, _, target, current = self.engine("waf")
        edits = [{"old_text": "old", "new_text": "new"}]
        denied = engine.propose_edit(target, digest(current), edits, "deny this")
        self.broker.rows[denied["proposal_id"]]["status"] = "denied"
        self.assertEqual(engine.worker_once()[0]["status"], "denied")
        changed = engine.propose_edit(target, digest(current), edits, "stale after review")
        self.broker.rows[changed["proposal_id"]]["status"] = "approved"
        path = Path(engine.targets[target]["path"])
        drifted = current + b"# concurrent operator change\n"
        path.write_bytes(drifted)
        self.assertEqual(engine.worker_once()[0]["status"], "aborted")
        self.assertEqual(path.read_bytes(), drifted)
        self.assertEqual(self.broker.consumes, 0)

    def test_literal_edit_stdin_dispatch_requires_exact_keys_and_fixed_operation(self):
        engine, _, target, current = self.engine("waf")
        request = {"operation": "propose-edit", "target": target, "base_sha256": digest(current),
                   "edits": [{"old_text": "old", "new_text": "new"}], "reason": "dispatch"}
        for extra in ({"candidate_content": "untrusted"}, {"approved": True}, {"command": "whoami"}):
            with self.subTest(extra=extra), mock.patch.object(MOD.os, "geteuid", return_value=0), \
                    mock.patch.object(MOD, "_secure_config", return_value=("a", self.broker)), \
                    mock.patch.object(MOD, "Engine", return_value=engine), \
                    mock.patch.object(MOD.sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(dict(request, **extra)).encode()))):
                with self.assertRaisesRegex(MOD.RuleChangeError, "unsupported operation or arguments"):
                    MOD.main([])
        stdout = io.StringIO()
        with mock.patch.object(MOD.os, "geteuid", return_value=0), \
                mock.patch.object(MOD, "_secure_config", return_value=("a", self.broker)), \
                mock.patch.object(MOD, "Engine", return_value=engine), \
                mock.patch.object(MOD.sys, "stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))), \
                mock.patch.object(MOD.sys, "stdout", stdout):
            MOD.main([])
        response = json.loads(stdout.getvalue())
        self.assertEqual(response["status"], "pending")
        self.assertTrue(response["review_posted"])
        self.assertNotIn("diff", response)
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def test_full_size_korean_replacement_survives_state_reload_and_one_use_approval(self):
        engine, _, target, _ = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        before = self.max_waf_comment("가")
        candidate = self.max_waf_comment("나")
        path.write_text(before, encoding="utf-8")
        current = engine.get_target(target)
        self.assertEqual(len(candidate.encode("utf-8")), 128 * 1024)
        self.assertEqual(current["limits"]["max_candidate_utf8_bytes"], 128 * 1024)
        proposal = engine.propose(target, current["sha256"], candidate, "전체 한국어 룰 주석 변경")
        rid = proposal["proposal_id"]
        raw_diff = proposal["diff"].encode("utf-8")
        self.assertGreater(len(raw_diff), 256 * 1024)
        self.assertLess(len(raw_diff), MOD.MAX_DIFF)
        self.assertGreater(engine._record_path(rid).stat().st_size, 256 * 1024)
        record = engine._load(rid)
        self.assertEqual(record["payload"]["diff"], proposal["diff"])
        self.assertEqual(record["payload"]["diff_sha256"], digest(raw_diff))
        self.assertEqual(record["proposal_digest"], MOD.proposal_digest(record["payload"]))
        self.assertIn("-# " + before.split("# ", 1)[1], proposal["diff"])
        self.assertIn("+# " + candidate.split("# ", 1)[1], proposal["diff"])
        self.assertEqual(proposal["limits"], current["limits"])
        self.assertEqual(engine.worker_once()[0]["status"], "pending")
        self.assertEqual(path.read_text(encoding="utf-8"), before)
        self.assertEqual(self.broker.consumes, 0)
        inode = path.stat().st_ino
        self.broker.rows[rid]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertEqual(path.read_text(encoding="utf-8"), candidate)
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(self.broker.results[0]["readback_sha256"], digest(candidate.encode("utf-8")))
        self.assertEqual(engine.worker_once(), [])
        self.assertEqual(self.broker.consumes, 1)

    def test_full_size_escaped_content_fits_request_and_durable_state_limits(self):
        engine, _, target, _ = self.engine("waf")
        path = Path(engine.targets[target]["path"])
        before = self.max_waf_comment('"')
        candidate = self.max_waf_comment("\\")
        path.write_text(before, encoding="utf-8")
        request = {"operation": "propose", "target": target,
                   "base_sha256": digest(before.encode()), "candidate_content": candidate,
                   "reason": "replace quoted and escaped comments"}
        serialized = json.dumps(request, ensure_ascii=False).encode("utf-8")
        self.assertGreater(len(serialized), 256 * 1024)
        self.assertLess(len(serialized), MOD.MAX_REQUEST)
        proposal = engine.propose(target, request["base_sha256"], candidate, request["reason"])
        state_path = engine._record_path(proposal["proposal_id"])
        self.assertGreater(state_path.stat().st_size, 256 * 1024)
        self.assertLess(state_path.stat().st_size, MOD.MAX_STATE)
        self.assertEqual(engine._load(proposal["proposal_id"])["candidate_content"], candidate)
        self.assertEqual(engine.status(proposal["proposal_id"])["approval_status"], "pending")
        self.assertEqual(path.read_text(encoding="utf-8"), before)

    def test_large_transport_does_not_raise_candidate_file_limit(self):
        engine, _, target, current = self.engine("waf")
        candidate = self.max_waf_comment("가") + "\n"
        self.assertEqual(len(candidate.encode("utf-8")), 128 * 1024 + 1)
        with self.assertRaisesRegex(MOD.RuleChangeError, "<=128 KiB"):
            engine.propose(target, digest(current), candidate, "oversized file")
        self.assertFalse(self.broker.rows)
        self.assertFalse(list(engine.state_dir.glob("*.json")))
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def test_large_diff_tampering_remains_bound_to_broker_approval(self):
        engine, _, target, current = self.engine("waf")
        proposal = engine.propose(target, digest(current), self.max_waf_comment("나"), "large proposal")
        rid = proposal["proposal_id"]
        original = engine._record_path(rid).read_bytes()
        self.broker.rows[rid]["status"] = "approved"
        for rehash_local in (False, True):
            with self.subTest(rehash_local=rehash_local):
                record = json.loads(original)
                record["payload"]["diff"] += "+# changed after review\n"
                if rehash_local:
                    record["payload"]["diff_sha256"] = digest(record["payload"]["diff"].encode())
                    record["proposal_digest"] = MOD.proposal_digest(record["payload"])
                engine._save(record)
                self.assertEqual(engine.worker_once()[0]["status"], "pending")
                self.assertIn("binding mismatch", engine._load(rid)["result"])
                self.assertEqual(self.broker.consumes, 0)
                self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def et_engine(self):
        engine, runner, target, current = self.engine("suricata")
        spec = engine.targets[target]
        et = Path(spec["et_path"]).read_bytes() + ET_SOURCE.encode()
        Path(spec["et_path"]).write_bytes(et)
        Path(spec["all_path"]).write_bytes(et + current)
        runner.active_rules = et + current
        candidate = current.decode() + ET_MARKER + ET_GUARDED
        return engine, runner, target, current, candidate, et

    def test_et_exact_overrides_approved_apply_and_removal(self):
        engine, runner, target, current, candidate, et = self.et_engine()
        proposal = engine.propose(target, digest(current), candidate, "two exact ET exceptions")
        self.assertEqual(self.broker.consumes, 0)
        self.assertEqual(runner.restart_count, 0)
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        spec = engine.targets[target]
        self.assertEqual(runner.active_rules, et + candidate.encode())
        self.assertEqual(Path(spec["et_path"]).read_bytes(), et)
        got = engine.get_target(target)  # Existing snapshots/read API work with overrides.
        remove = engine.propose(target, got["sha256"], current.decode(), "remove ET exceptions")
        self.broker.rows[remove["proposal_id"]]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertEqual(runner.active_rules, et + current)
        self.assertEqual(Path(spec["all_path"]).read_bytes(), et + current)
        self.assertEqual(runner.restart_count, 2)

    def test_et_marker_endpoint_transition_requires_matching_revision_and_approval(self):
        engine, runner, target, _, initial, et = self.et_engine()
        spec = engine.targets[target]
        current = initial.encode()
        Path(spec["path"]).write_bytes(current)
        Path(spec["all_path"]).write_bytes(et + current)
        runner.active_rules = et + current
        ip_edit = {"old_text": "211.170.162.110", "new_text": "[211.170.162.110,211.170.162.111]"}
        rev_edit = {"old_text": "sid:1000000; rev:1;", "new_text": "sid:1000000; rev:2;"}
        for edit in (ip_edit, rev_edit):
            with self.subTest(incomplete_transition=edit), self.assertRaisesRegex(MOD.RuleChangeError, "marker profile"):
                engine.propose_edit(target, digest(current), [edit], "incomplete endpoint transition")
        self.assertFalse(self.broker.rows)
        for old_marker, new_marker in ((ET_MARKER, ET_MARKER_DUAL), (ET_MARKER_DUAL, ET_MARKER)):
            with self.subTest(destination=new_marker.split()[5]):
                expected = current.replace(old_marker.encode(), new_marker.encode())
                proposal = engine.propose_edit(target, digest(current),
                    [{"old_text": old_marker, "new_text": new_marker}], "selected DGX endpoint profile")
                rid = proposal["proposal_id"]
                self.assertEqual(proposal["after_sha256"], digest(expected))
                self.assertEqual(engine.worker_once()[0]["status"], "pending")
                self.assertEqual(Path(spec["path"]).read_bytes(), current)
                self.assertEqual(runner.active_rules, et + current)
                self.broker.rows[rid]["status"] = "approved"
                self.assertEqual(engine.worker_once()[0]["status"], "applied")
                self.assertEqual(Path(spec["path"]).read_bytes(), expected)
                self.assertEqual(Path(spec["all_path"]).read_bytes(), et + expected)
                self.assertEqual(Path(spec["et_path"]).read_bytes(), et)
                self.assertEqual(runner.active_rules, et + expected)
                self.assertEqual(self.broker.results[-1]["readback_sha256"], digest(expected))
                self.assertEqual(engine.worker_once(), [])
                current = expected
        self.assertEqual(current, initial.encode())
        self.assertEqual(self.broker.consumes, 2)
        self.assertEqual(runner.restart_count, 2)

    def test_et_marker_profiles_reject_address_expansion_arbitrary_revisions_and_option_changes(self):
        engine, _, target, current, candidate, _ = self.et_engine()
        candidate = candidate.replace(ET_MARKER, ET_MARKER_DUAL)
        mutations = [ET_MARKER_DUAL.replace("[211.170.162.110,211.170.162.111]", address) for address in (
            "211.170.162.110", "211.170.162.111", "211.170.162.112", "211.170.162.111/32", "211.170.162.0/24",
            "[211.170.162.111,211.170.162.110]", "[211.170.162.110, 211.170.162.111]",
            "[211.170.162.110 ,211.170.162.111]", "[211.170.162.110,211.170.162.111,211.170.162.112]",
            "[211.170.162.110,211.170.162.111/32]", "any", "!211.170.162.110")]
        mutations += [ET_MARKER_DUAL.replace("sid:1000000; rev:2;", "sid:1000000; rev:%s;" % rev)
                      for rev in ("0", "1", "3", "02", "4294967295")]
        mutations += [ET_MARKER_DUAL.replace("192.168.16.230", "192.168.16.231"),
                      ET_MARKER_DUAL.replace("192.168.16.230", "any"),
                      ET_MARKER_DUAL.replace(" -> ", " <> "),
                      ET_MARKER_DUAL.replace("11434 (", "any ("),
                      ET_MARKER_DUAL.replace("11434 (", "[11434,443] ("),
                      ET_MARKER_DUAL.replace("to_server,established", "to_client,established"),
                      ET_MARKER_DUAL.replace("flowbits:noalert; ", ""),
                      ET_MARKER_DUAL.replace("flowbits:set", "flowbits:toggle"),
                      ET_MARKER_DUAL.replace("flowbits:noalert; sid:1000000;", "sid:1000000; flowbits:noalert;"),
                      ET_MARKER_DUAL.replace("sid:1000000;", "gid:1; sid:1000000;"),
                      ET_MARKER_DUAL.replace("transport marker", "changed marker"),
                      ET_MARKER_DUAL + ET_MARKER]
        for marker in mutations:
            with self.subTest(marker=marker), self.assertRaises(MOD.RuleChangeError):
                engine.propose(target, digest(current), candidate.replace(ET_MARKER_DUAL, marker), "reject broad profile")
        self.assertFalse(self.broker.rows)
        self.assertFalse(list(engine.state_dir.glob("*.json")))
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def test_dual_endpoint_marker_preserves_exact_et_override_and_single_writer_guards(self):
        engine, _, target, current, candidate, _ = self.et_engine()
        candidate = candidate.replace(ET_MARKER, ET_MARKER_DUAL)
        mutations = [candidate.replace("needle-one", "weakened"),
                     candidate.replace("flowbits:isnotset", "flowbits:isset"),
                     candidate.replace("; flowbits:isnotset,groot_llm_api", ""),
                     candidate.replace("rev:3;", "rev:4;"),
                     candidate.replace("gid:1;", "gid:2;"),
                     candidate.replace("; sid:2034806", "; flowbits:noalert; sid:2034806"),
                     candidate.replace("; sid:2034806", "; \\\nsid:2034806")]
        for operation in ("set", "unset", "toggle"):
            mutations.append(candidate + 'alert tcp any any -> any any (flowbits:%s,groot_llm_api; sid:1000002; rev:1;)\n' % operation)
        for changed in mutations:
            with self.subTest(mutation=mutations.index(changed)), self.assertRaises(MOD.RuleChangeError):
                engine.propose(target, digest(current), changed, "preserve upstream and private bit")
        self.assertFalse(self.broker.rows)
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def test_et_override_rejects_weakened_or_noncanonical_rule(self):
        engine, _, target, current, candidate, _ = self.et_engine()
        mutations = [candidate.replace("2034806", "2034809"),
                     candidate.replace("needle-one", "weakened"),
                     candidate.replace("flowbits:isnotset", "flowbits:isset"),
                     candidate.replace("; flowbits:isnotset,groot_llm_api", ""),
                     candidate.replace("rev:3;", "rev:4;"),
                     candidate.replace("gid:1;", "gid:2;"),
                     candidate.replace("; sid:2034806", "; flowbits:noalert; sid:2034806"),
                     candidate.replace("; sid:2034806", "; \\\nsid:2034806"),
                     candidate.replace('msg:"ET one"', 'msg:"ET changed"')]
        for changed in mutations:
            with self.subTest(candidate=mutations.index(changed)):
                with self.assertRaises(MOD.RuleChangeError):
                    engine.propose(target, digest(current), changed, "must reject")
        self.assertEqual(self.broker.rows, {})

    def test_et_override_pins_marker_and_single_bit_writer(self):
        engine, _, target, current, candidate, _ = self.et_engine()
        mutations = [candidate.replace("192.168.16.230", "any"), candidate.replace("11434 (", "any ("),
                     candidate.replace("to_server,established", "established"),
                     candidate.replace("sid:1000000; rev:1", "sid:1000000; rev:2"),
                     candidate.replace(ET_MARKER, ""), candidate.replace(ET_MARKER, " " + ET_MARKER),
                     candidate.replace(ET_MARKER, "\t" + ET_MARKER),
                     candidate.replace(ET_MARKER, "\\\n " + ET_MARKER),
                     candidate.replace(ET_MARKER, "\\\n\t" + ET_MARKER)]
        for operation in ("set", "unset", "toggle"):
            mutations.append(candidate + 'alert tcp any any -> any any (flowbits:%s,groot_llm_api; sid:1000002; rev:1;)\n' % operation)
        for changed in mutations:
            with self.assertRaises(MOD.RuleChangeError):
                engine.propose(target, digest(current), changed, "must reject marker change")
        self.assertEqual(self.broker.rows, {})

    def test_et_quoted_option_text_is_not_an_option_and_subset_is_valid(self):
        engine, _, target, current, _, et = self.et_engine()
        spec = engine.targets[target]
        # This third ET signature mentions a target SID/bit inside msg only.
        et += b'alert tcp any any -> any any (msg:"sid:2034806; rev:9; flowbits:set,groot_llm_api;"; sid:2000001; rev:1;)\n'
        Path(spec["et_path"]).write_bytes(et)
        Path(spec["all_path"]).write_bytes(et + current)
        candidate = current.decode() + ET_MARKER + ET_GUARDED.splitlines(keepends=True)[0]
        candidate += 'alert tcp any any -> any any (msg:"sid:2034802; rev:9; flowbits:set,groot_llm_api;"; pcre:"/a;sid:9999999;\\\"b/"; sid:1000002; rev:1;)\n'
        self.assertEqual(engine.propose(target, digest(current), candidate, "one exact exception")["status"], "pending")
        with self.assertRaises(MOD.RuleChangeError):
            MOD._validate_candidate("suricata", 'alert tcp any any -> any any (msg:"sid:1000001;";)\n')

    def test_et_requires_unique_upstream_and_rejects_drift_before_consume(self):
        engine, runner, target, current, candidate, et = self.et_engine()
        spec = engine.targets[target]
        for changed in (et + ET_SOURCE.splitlines(keepends=True)[0].encode(),
                        et.replace(ET_SOURCE.splitlines(keepends=True)[1].encode(), b"")):
            Path(spec["et_path"]).write_bytes(changed)
            Path(spec["all_path"]).write_bytes(changed + current)
            with self.assertRaises(MOD.RuleChangeError):
                engine.propose(target, digest(current), candidate, "ambiguous upstream")
        Path(spec["et_path"]).write_bytes(et)
        Path(spec["all_path"]).write_bytes(et + current)
        proposal = engine.propose(target, digest(current), candidate, "valid before ET drift")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        changed = et.replace(b"needle-one", b"new-upstream")
        Path(spec["et_path"]).write_bytes(changed)
        Path(spec["all_path"]).write_bytes(changed + current)
        self.assertEqual(engine.worker_once()[0]["status"], "aborted")
        self.assertEqual(self.broker.consumes, 0)
        self.assertEqual(runner.restart_count, 0)

    def test_et_override_revalidation_precedes_consume(self):
        engine, _, target, current, candidate, _ = self.et_engine()
        proposal = engine.propose(target, digest(current), candidate, "valid staged exception")
        record = engine._load(proposal["proposal_id"])
        record["candidate_content"] = candidate.replace("needle-one", "changed")
        with self.assertRaises(MOD.RuleChangeError):
            engine._apply_approved(record)
        self.assertEqual(self.broker.consumes, 0)
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def test_et_override_failed_apply_restores_exact_original_combined_rules(self):
        engine, runner, target, current, candidate, et = self.et_engine()
        proposal = engine.propose(target, digest(current), candidate, "rollback verification")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        runner.fail_on = "-T -S /rules/all.rules"
        self.assertEqual(engine.worker_once()[0]["status"], "rolled_back")
        spec = engine.targets[target]
        self.assertEqual(Path(spec["path"]).read_bytes(), current)
        self.assertEqual(Path(spec["all_path"]).read_bytes(), et + current)
        self.assertEqual(Path(spec["et_path"]).read_bytes(), et)
        self.assertEqual(runner.active_rules, et + current)
        self.assertEqual(self.broker.results[0]["readback_sha256"], digest(current))

    def test_get_and_stale_base_rejection(self):
        engine, _, target, current = self.engine("waf")
        got = engine.get_target(target)
        self.assertEqual(got["content"], current.decode())
        self.assertEqual(got["sha256"], digest(current))
        with self.assertRaisesRegex(MOD.RuleChangeError, "changed since it was read"):
            engine.propose(target, "0" * 64, self.candidate("waf"), "requested")
        self.assertEqual(self.broker.rows, {})

    def test_suricata_read_exposes_current_source_without_changing_approval_runtime(self):
        engine, runner, target, current = self.engine("suricata")
        spec = engine.targets[target]
        bound_before = engine._inspect(spec)
        result = engine.get_target(target)
        self.assertEqual(result['runtime']['rule_source_path'], '/rules/all.rules')
        self.assertTrue(result['runtime']['combined_is_exact_et_plus_local'])
        self.assertEqual(result['runtime']['combined_sha256'], result['related_hashes']['all_sha256'])
        self.assertEqual(result['runtime']['observed_at'], 1000)
        self.assertFalse(result['rule_inventory']['runtime_load_verified'])
        self.assertEqual(engine._inspect(spec), bound_before)
        self.assertNotIn('rule_source_path', bound_before)
        self.assertFalse(any(c[1] == 'restart' for c in runner.commands))

    def test_suricata_rejects_wrong_or_duplicate_rule_source_argument(self):
        engine, runner, target, current = self.engine("suricata")
        original = runner.call
        for command in (['-S', '/rules/suricata.rules', '/rules/all.rules'],
                        ['-S', '/rules/all.rules', '-S', '/rules/all.rules'], ['-S']):
            def changed(argv, timeout=30):
                data = original(argv, timeout)
                if argv[1] == 'inspect':
                    rows = json.loads(data)
                    rows[0]['Config']['Cmd'] = command
                    return json.dumps(rows).encode()
                return data
            with mock.patch.object(runner, 'call', side_effect=changed), self.assertRaises(MOD.RuleChangeError):
                engine.get_target(target)

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

    def test_suricata_staged_validation_and_combined_restart(self):
        engine, runner, target, current = self.engine("suricata")
        proposal = self.propose(engine, target, current, "suricata")
        self.assertIn("staged", proposal["validation"])
        self.assertEqual(Path(engine.targets[target]["all_path"]).read_bytes(),
                         Path(engine.targets[target]["et_path"]).read_bytes() + current)
        self.assertEqual(engine.worker_once()[0]["status"], "pending")
        self.assertEqual(runner.restart_count, 0)
        self.assertIn("detection pauses briefly", proposal["diff"])
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        spec = engine.targets[target]
        self.assertEqual(Path(spec["all_path"]).read_bytes(), Path(spec["et_path"]).read_bytes() + self.candidate("suricata").encode())
        self.assertEqual(runner.active_rules, Path(spec["all_path"]).read_bytes())
        self.assertEqual(runner.restart_count, 1)
        self.assertFalse(any("reload-rules" in cmd for cmd in runner.commands))
        self.assertTrue(any("ruleset-stats" in cmd for cmd in runner.commands))
        self.assertTrue(any("ruleset-reload-time" in cmd for cmd in runner.commands))
        self.assertEqual(engine.worker_once(), [])
        self.assertEqual(runner.restart_count, 1)

    def test_suricata_nok_with_successful_exit_rolls_back_runtime_and_files(self):
        engine, runner, target, current = self.engine("suricata")
        proposal = self.propose(engine, target, current, "suricata")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        original_call = runner.call

        def nok_candidate(argv, timeout=30):
            if "ruleset-stats" in argv and runner.restart_count == 1:
                return b'{"return":"NOK","message":"runtime rejected request"}'
            return original_call(argv, timeout)

        runner.call = nok_candidate
        with mock.patch.object(MOD.time, "monotonic", side_effect=count()), mock.patch.object(MOD.time, "sleep"):
            self.assertEqual(engine.worker_once()[0]["status"], "rolled_back")
        spec = engine.targets[target]
        self.assertEqual(runner.restart_count, 2)
        self.assertEqual(Path(spec["path"]).read_bytes(), current)
        self.assertEqual(runner.active_rules, Path(spec["et_path"]).read_bytes() + current)
        self.assertEqual(self.broker.results[0]["readback_sha256"], digest(current))

    def test_suricata_restart_failure_can_recover_stopped_container(self):
        engine, runner, target, current = self.engine("suricata")
        proposal = self.propose(engine, target, current, "suricata")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        original_call = runner.call
        attempts = []

        def fail_first_restart(argv, timeout=30):
            if argv[1] == "restart":
                attempts.append(argv)
                if len(attempts) == 1:
                    runner.running = False
                    raise MOD.RuleChangeError("restart failed after stop")
            return original_call(argv, timeout)

        runner.call = fail_first_restart
        self.assertEqual(engine.worker_once()[0]["status"], "rolled_back")
        self.assertEqual(len(attempts), 2)
        self.assertTrue(runner.running)
        self.assertEqual(runner.active_rules, Path(engine.targets[target]["et_path"]).read_bytes() + current)

    def test_suricata_restart_and_recovery_failure_is_not_success(self):
        engine, runner, target, current = self.engine("suricata")
        proposal = self.propose(engine, target, current, "suricata")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        runner.fail_on = " restart "
        self.assertEqual(engine.worker_once()[0]["status"], "recovery_failed")
        self.assertEqual(self.broker.results[0]["status"], "recovery_failed")
        self.assertEqual(Path(engine.targets[target]["path"]).read_bytes(), current)

    def test_suricata_runtime_rejects_bad_counts_and_timestamps(self):
        engine, runner, target, _ = self.engine("suricata")
        for changed in ({"rules_failed": 1}, {"rules_loaded": 0}, {"rules_skipped": -1},
                        {"rules_skipped": 1}, {"rules_loaded": True}):
            with self.subTest(changed=changed):
                row = dict(id=0, rules_loaded=2, rules_failed=0, rules_skipped=0)
                row.update(changed)
                runner.socket_replies["ruleset-stats"] = json.dumps({"return": "OK", "message": [row]}).encode()
                with mock.patch.object(MOD.time, "monotonic", side_effect=count()), mock.patch.object(MOD.time, "sleep"):
                    with self.assertRaisesRegex(MOD.RuleChangeError, "absent, failed, skipped or malformed"):
                        engine._restart_suricata(engine.targets[target])
        runner.socket_replies.clear()
        for value in ("1970-01-01T00:00:00+00:00", "1970-01-01T00:16:45", "not-a-time"):
            with self.subTest(timestamp=value):
                runner.socket_replies["ruleset-reload-time"] = json.dumps({"return": "OK", "message": [{"id": 0, "last_reload": value}]}).encode()
                with mock.patch.object(MOD.time, "monotonic", side_effect=count()), mock.patch.object(MOD.time, "sleep"):
                    with self.assertRaises(MOD.RuleChangeError):
                        engine._restart_suricata(engine.targets[target])

    def test_suricata_socket_rejects_malformed_or_multiple_tenants(self):
        engine, runner, _, _ = self.engine("suricata")
        for raw in (b"not-json", b'{"return":"OK","message":[]}',
                    b'{"return":"OK","message":[{"id":0},{"id":1}]}',
                    b'{"return":"OK","message":[{"id":true}]}'):
            with self.subTest(raw=raw):
                runner.socket_replies["ruleset-stats"] = raw
                with self.assertRaises(MOD.RuleChangeError):
                    engine._suricata_socket("ruleset-stats", 1)

    def test_suricata_waits_for_socket_initialization(self):
        engine, runner, target, current = self.engine("suricata")
        proposal = self.propose(engine, target, current, "suricata")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        original_call = runner.call
        attempts = []

        def starting_socket(argv, timeout=30):
            if "ruleset-stats" in argv:
                attempts.append(argv)
                if len(attempts) == 1:
                    raise MOD.RuleChangeError("socket not ready")
            return original_call(argv, timeout)

        runner.call = starting_socket
        with mock.patch.object(MOD.time, "monotonic", side_effect=count()), mock.patch.object(MOD.time, "sleep"):
            self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertEqual(len(attempts), 2)
        self.assertEqual(runner.restart_count, 1)

    def test_suricata_runtime_rejects_recreated_or_unrestarted_container(self):
        engine, runner, target, _ = self.engine("suricata")
        original_call = runner.call
        for mutation in ("identity", "start_time"):
            with self.subTest(mutation=mutation):
                def wrong_restart(argv, timeout=30):
                    started_at = runner.started_at
                    reply = original_call(argv, timeout)
                    if argv[1] == "restart":
                        if mutation == "identity":
                            runner.container_id = "b" * 64
                        else:
                            runner.started_at = started_at
                    return reply
                runner.call = wrong_restart
                with mock.patch.object(MOD.time, "monotonic", side_effect=count()), mock.patch.object(MOD.time, "sleep"):
                    with self.assertRaisesRegex(MOD.RuleChangeError, "restart was not observed"):
                        engine._restart_suricata(engine.targets[target])

    def test_wazuh_restart_checks_processes(self):
        engine, runner, target, current = self.engine("wazuh")
        proposal = self.propose(engine, target, current, "wazuh")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertTrue(any(any(part.endswith("wazuh-analysisd") for part in cmd) for cmd in runner.commands))
        self.assertTrue(any(any(part.endswith("wazuh-control") for part in cmd) for cmd in runner.commands))
        self.assertTrue(any(cmd[1] == "restart" for cmd in runner.commands))

    def test_wazuh_status_exit_one_with_disabled_optional_daemons(self):
        output = (b"wazuh-clusterd not running...\nwazuh-maild not running...\n"
                  b"wazuh-analysisd is running...\nwazuh-remoted is running...\nwazuh-db is running...\n")
        command = [MOD.DOCKER, "exec", "manager", "/var/ossec/bin/wazuh-control", "status"]
        runner = MOD.Runner()
        with mock.patch.object(MOD.subprocess, "run", return_value=mock.Mock(returncode=1, stdout=output)):
            self.assertEqual(runner.call(command), output)
            for changed in (command[:-1] + ["restart"],
                            [MOD.DOCKER, "exec", "manager", "/bin/sh", "status"],
                            [MOD.DOCKER, "restart", "manager"], command + ["extra"]):
                with self.subTest(command=changed), self.assertRaises(MOD.RuleChangeError):
                    runner.call(changed)
        for code in (2, 125, -9):
            with self.subTest(code=code), mock.patch.object(MOD.subprocess, "run", return_value=mock.Mock(returncode=code, stdout=output)):
                with self.assertRaises(MOD.RuleChangeError):
                    runner.call(command)

    def test_approved_wazuh_edit_does_not_roll_back_for_disabled_optional_daemons(self):
        engine, runner, target, current = self.engine("wazuh")
        original = runner.call
        output = (b"wazuh-clusterd not running...\nwazuh-analysisd is running...\n"
                  b"wazuh-remoted is running...\nwazuh-db is running...\n")
        def live_status(argv, timeout=30):
            if "/var/ossec/bin/wazuh-control" in argv:
                with mock.patch.object(MOD.subprocess, "run", return_value=mock.Mock(returncode=1, stdout=output)):
                    return MOD.Runner().call(argv, timeout)
            return original(argv, timeout)
        runner.call = live_status
        proposal = self.propose(engine, target, current, "wazuh")
        self.broker.rows[proposal["proposal_id"]]["status"] = "approved"
        self.assertEqual(engine.worker_once()[0]["status"], "applied")
        self.assertEqual(self.broker.consumes, 1)
        self.assertEqual(runner.restart_count, 1)
        self.assertEqual(Path(engine.targets[target]["path"]).read_text(), self.candidate("wazuh"))

    def test_wazuh_required_process_status_is_exact_and_unambiguous(self):
        healthy = "wazuh-analysisd is running...\nwazuh-remoted is running...\nwazuh-db is running...\n"
        self.assertTrue(MOD._wazuh_core_ready(healthy))
        self.assertTrue(MOD._wazuh_core_ready(healthy.replace("...", "")))
        for process in ("wazuh-analysisd", "wazuh-remoted", "wazuh-db"):
            line = process + " is running...\n"
            for bad in (healthy.replace(line, ""), healthy.replace(line, process + " not running...\n"),
                        healthy.replace(line, "stale: " + line), healthy + line,
                        healthy + process + " not running...\n", healthy.replace(line, process + " is running... stale\n")):
                with self.subTest(process=process, status=bad):
                    self.assertFalse(MOD._wazuh_core_ready(bad))
                    with mock.patch.object(MOD.subprocess, "run", return_value=mock.Mock(returncode=1, stdout=bad.encode())):
                        with self.assertRaises(MOD.RuleChangeError):
                            MOD.Runner().call([MOD.DOCKER, "exec", "manager", "/var/ossec/bin/wazuh-control", "status"])

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

    def test_status_keeps_execution_pending_separate_from_broker_decision(self):
        engine, runner, target, current = self.engine("waf")
        proposal = self.propose(engine, target, current, "waf")
        rid = proposal['proposal_id']
        saved = engine._record_path(rid).read_bytes()
        commands = list(runner.commands)
        engine.read_only = True
        for decision in ('pending', 'approved', 'denied', 'expired', 'consumed'):
            self.broker.rows[rid]['status'] = decision
            out = engine.status(rid)
            self.assertEqual((out['status'], out['approval_status']), ('pending', decision))
            self.assertEqual(out['approval_status_source'], 'broker_lookup')
            self.assertIsNone(out['approval_consumed'])
            self.assertEqual(out['observed_at_kst'], '1970-01-01T09:16:40+09:00')
        self.broker.fail_get = True
        self.assertEqual(engine.status(rid)['approval_status'], 'unavailable')
        self.assertEqual(engine._record_path(rid).read_bytes(), saved)
        self.assertEqual(runner.commands, commands)
        self.assertEqual(self.broker.consumes, 0)

    def test_status_preserves_historical_hash_and_delivery_retry_after_current_drift(self):
        engine, runner, target, current = self.engine('waf')
        rid = self.propose(engine, target, current, 'waf')['proposal_id']
        self.broker.rows[rid]['status'] = 'approved'
        self.broker.fail_result_once = True
        engine.worker_once()
        historical = digest(self.candidate('waf').encode())
        Path(engine.targets[target]['path']).write_bytes(current + b'# later change\n')
        saved = engine._record_path(rid).read_bytes()
        out = engine.status(rid)
        self.assertEqual(out['approval_status'], 'consumed')
        self.assertTrue(out['approval_consumed'])
        self.assertFalse(out['result_posted'])
        self.assertEqual(out['result_delivery'], {'status':'retry_pending', 'retry_reexecutes_change':False})
        self.assertEqual(out['recorded_result']['readback_sha256'], historical)
        self.assertFalse(out['current_file_checked'])
        self.assertEqual(engine._record_path(rid).read_bytes(), saved)
        commands = list(runner.commands)
        engine.worker_once()
        self.assertEqual(engine.status(rid)['result_delivery']['status'], 'confirmed')
        self.assertEqual(runner.commands, commands)
        self.assertEqual(self.broker.consumes, 1)

    def test_status_does_not_infer_recovery_or_missing_legacy_approval(self):
        engine, _, target, current = self.engine('waf')
        rid = self.propose(engine, target, current, 'waf')['proposal_id']
        record = engine._load(rid)
        for status in ('applied','rolled_back','recovery_failed','failed','denied','expired'):
            record['status'] = status
            engine._save(record)
            out = engine.status(rid)
            self.assertEqual(out['status'], status)
            self.assertIsNone(out['approval_consumed'])
            self.assertIsNone(out['result_posted'])
            self.assertEqual(out['approval_status'], status if status in ('denied','expired') else 'unknown')
            self.assertEqual(out['result_delivery']['status'], 'not_recorded')
            self.assertNotIn('recorded_result', out)

    def test_status_preserves_abort_delivery_and_prepared_uncertainty(self):
        engine, _, target, current = self.engine('waf')
        rid = self.propose(engine, target, current, 'waf')['proposal_id']
        record = engine._load(rid)
        for status, delivery in [('abort_pending','abort_pending'),('abort_report_error','abort_report_error'),('aborted','abort_confirmed')]:
            record['status'] = status; engine._save(record)
            self.assertEqual(engine.status(rid)['result_delivery']['status'], delivery)
        record['status'] = 'prepared'; engine._save(record)
        self.broker.rows[rid]['status'] = 'consumed'
        out = engine.status(rid)
        self.assertEqual((out['status'],out['approval_status']), ('prepared','consumed'))
        self.assertIsNone(out['approval_consumed'])

    def test_reject_mode_escalation(self):
        for kind, candidate in (("waf", "SecRuleEngine DetectionOnly\nSecRule ARGS @rx x \"ctl:ruleEngine=On\"\n"),
                                ("suricata", 'drop tcp any any -> any any (msg:"x"; sid:1000001; rev:1;)\n')):
            with self.subTest(kind=kind):
                with self.assertRaises(MOD.RuleChangeError):
                    MOD._validate_candidate(kind, candidate)

    def test_hmac_broker_authenticates_both_directions_without_bearer_header(self):
        key = "k" * 40
        broker = MOD.Broker("https://10.200.10.10:8445", key)
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
            def __init__(self):
                self.last_request = None
                self.timeouts = []
            def open(self, request, timeout):
                self.last_request = request
                self.timeouts.append(timeout)
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
        self.assertEqual(opener.timeouts[-1], 12)
        replay = opener.open(opener.last_request, timeout=1)
        self.assertEqual(replay.status, 401)  # same nonce cannot authenticate twice
        diff_text = "--- before\n+++ after\n@@ -1 +1 @@\n-old\n+new\n"
        payload = {"target": "a:modsecurity-custom", "base_sha256": "0" * 64,
                   "candidate_sha256": "1" * 64, "diff_sha256": digest(diff_text.encode()),
                   "diff": diff_text, "requested_by": "hermes-rule-change",
                   "expires_at": int(time.time()) + 300}
        created = broker.request("POST", "/rule-changes", payload)
        self.assertTrue(created["posted"])
        self.assertEqual(opener.timeouts[-1], 120)
        rid = created["proposal_id"]
        self.assertEqual(broker.request("GET", "/rule-changes/" + rid)["status"], "pending")
        self.assertEqual(opener.timeouts[-1], 12)
        self.assertEqual(created["proposal_digest"], MOD.proposal_digest(payload))
        bot.RULE_APPROVALS[rid]["status"] = "approved"
        bot.RULE_APPROVALS[rid]["by"] = "operator"
        aborted = broker.request("POST", "/rule-changes/" + rid + "/abort", {
            "proposal_digest": created["proposal_digest"], "readback_sha256": payload["base_sha256"],
            "detail": "live base changed; rule was not applied"})
        self.assertEqual(aborted["status"], "aborted")
        self.assertTrue(aborted["result_posted"])


class BrokerTransportBoundary(unittest.TestCase):
    def test_cross_host_plaintext_is_refused(self):
        with self.assertRaises(MOD.RuleChangeError): MOD.Broker('http://10.200.10.10:8090','x'*48)

    def test_redirects_are_refused_without_forwarding_headers(self):
        with self.assertRaises(MOD.RuleChangeError): MOD.NoBrokerRedirect().redirect_request(None,None,None,None,None,None)


if __name__ == "__main__":
    unittest.main()
