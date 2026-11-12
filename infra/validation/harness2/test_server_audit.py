"""Isolated stdlib tests, using the actual pinned official core and full source.

Run: python3 -B -m unittest discover -s infra/validation/harness2 -p test_server_audit.py -v
Fixtures/reports live only in TemporaryDirectory outside the project. No service,
network, subprocess, model, package install, credentials or source execution.
"""

import copy
from datetime import datetime, timedelta
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("server_audit_under_test", HERE / "server_audit.py")
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)
ROOT = HERE.parents[2]
NOW = datetime(2026, 11, 9, 3, 0, 0, tzinfo=audit.KST)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vendor = ROOT / "G_Harness2"
        lock = HERE / "framework.lock.json"
        if not vendor.is_dir() or not lock.is_file():
            raise unittest.SkipTest("Actual read-only official checkout/lock unavailable")
        cls.lock = json.loads(lock.read_bytes())
        cls.official = {}
        for relative, expected in cls.lock["files"].items():
            raw = (vendor / relative).read_bytes()
            if {"sha256": digest(raw), "size": len(raw)} != expected:
                raise AssertionError("Local official checkout differs from pin: " + relative)
            cls.official[relative] = raw

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="capstone-server-audit-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.vendor = self.base / "vendor" / audit.PINNED_COMMIT
        for relative, raw in self.official.items():
            path = self.vendor / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)
        self.reports = self.base / "reports"
        self.reports.mkdir(mode=0o700)
        self.context_path = self.base / "context.json"
        self.paths = {}
        for key in audit.default_component_paths():
            path = self.base / "sources" / key
            path.parent.mkdir(parents=True, exist_ok=True)
            relative = key.split("/", 1)[1]
            if relative == "systemprompt.md":
                raw = ("Load " + " ".join(audit.SKILLS) + " when appropriate.\n").encode()
            elif relative.startswith("scripts/"):
                # ast.parse + official compile must NEVER execute this body.
                raw = b"raise RuntimeError('source code must never run')\n"
            else:
                name = relative.split("/")[1]
                body = " ".join(name.replace("-", "_") + str(n) for n in range(10))
                raw = self.skill(name, body)
            path.write_bytes(raw)
            path.chmod(0o600)
            self.paths[key] = str(path)
        self.originals = audit.default_component_paths()
        self.config = audit.build_config(self.vendor, self.lock["files"], reports_dir=self.reports,
            component_paths=self.paths, context_path=self.context_path,
            collector_facts={"component_sources": self.originals,
                             "configuration_paths": ["/etc/test/config.json"]})
        self.policy = audit.FilePolicy(os.getuid(), allow_sticky_ancestors=True)
        self.context = self.context_document()
        self.write_context()

    @staticmethod
    def skill(name, body):
        return (f"---\nname: {name}\ndescription: inspect {name} procedures\n---\n{body}\n").encode()

    def context_document(self):
        catalog = [{"server": "soc", "name": "read", "alias": "mcp__soc__read",
                    "schema_sha256": "a" * 64}]
        doc = {"schema": 1, "status": "observed", "observed_at_kst": NOW.isoformat(),
               "model": "configured-test-model", "access_mode": "read-only", "catalog": catalog,
               "catalog_sha256": digest(json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()),
               "configuration_sha256": {"/etc/test/config.json": "b" * 64},
               "model_calls": 0, "tool_calls": 0, "chat_posts": 0, "protected_calls": 0,
               "error_code": None, "schema_observation": "names and hashes only",
               "model_observation": "configured identity; inference untested",
               "source_observations": {}}
        for key, filename in self.paths.items():
            raw = Path(filename).read_bytes()
            doc["source_observations"][key] = {
                "path": self.originals[key], "status": "observed", "sha256": digest(raw),
                "size": len(raw), "uid": 995, "gid": 986, "mode": "0o640",
                "observed_at_kst": NOW.isoformat()}
        return doc

    def write_context(self):
        self.context_path.write_text(json.dumps(self.context))
        self.context_path.chmod(0o600)

    def change(self, key, raw, *, refresh=True):
        Path(self.paths[key]).write_bytes(raw)
        if refresh:
            item = self.context["source_observations"][key]
            item.update(sha256=digest(raw), size=len(raw))
            self.write_context()

    def run_audit(self, **kwargs):
        return audit.run_audit(self.config, policy=self.policy, now=kwargs.pop("now", NOW), **kwargs)

    def test_actual_full_official_core_and_source_immutability(self):
        before = {path: (Path(path).read_bytes(), Path(path).stat().st_mtime_ns) for path in self.paths.values()}
        fake = types.ModuleType("harness2.core.tree")
        fake.validate = mock.Mock(side_effect=AssertionError("ambient core used"))
        with mock.patch.dict(sys.modules, {"harness2.core.tree": fake}):
            result = self.run_audit(origin="scheduled")
        report = result["report"]
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["scope"], "structural checks")
        self.assertEqual(report["framework"]["files"], self.lock["files"])
        self.assertEqual(report["framework"]["status"], "verified")
        self.assertEqual(len(report["sources"]), 47)
        self.assertEqual(len(report["framework_diffs"]), 3)
        self.assertTrue(all(s["census"]["skills"] == 5 for s in report["surfaces"].values()))
        self.assertEqual(report["source_snapshot"]["status"], "verified")
        self.assertEqual(report["source_snapshot"]["components"]["native/systemprompt.md"]["uid"], 995)
        self.assertFalse(report["automatic_adoption"])
        self.assertEqual(report["source_writes"], 0)
        self.assertEqual(before, {p: (Path(p).read_bytes(), Path(p).stat().st_mtime_ns) for p in before})
        self.assertFalse(any(self.base.rglob("__pycache__")))
        self.assertFalse(any(name.startswith("_capstone_harness2_") for name in sys.modules))
        fake.validate.assert_not_called()
        latest = audit.get_latest(self.reports, policy=self.policy)
        self.assertEqual(latest["sha256"], result["sha256"])
        self.assertEqual(latest["origin"], "scheduled")
        self.assertEqual(digest((self.reports / result["report_file"]).read_bytes()), result["sha256"])

    def test_pure_builder_and_validator_detach_inputs(self):
        with mock.patch.object(audit.os, "open", side_effect=AssertionError("I/O forbidden")):
            detached = audit.validate_config(self.config)
        detached["component_paths"]["native/systemprompt.md"] = "/different"
        self.assertNotEqual(detached, self.config)
        self.assertEqual(self.config["framework"]["manifest_sha256"], audit.PINNED_MANIFEST_SHA256)

    def test_untrusted_commit_manifest_and_partial_source_rejected(self):
        for field, value in (("commit", "0" * 40), ("manifest_sha256", "0" * 64)):
            with self.subTest(field=field):
                config = copy.deepcopy(self.config)
                config["framework"][field] = value
                with self.assertRaises(audit.AuditError):
                    audit.validate_config(config)
        files = {k: v for k, v in self.lock["files"].items() if k.startswith("harness2/core/")}
        with self.assertRaises(audit.AuditError):
            audit.build_config(self.vendor, files)

    def test_component_set_paths_alias_and_overlap_rejected(self):
        for mutation in (
            lambda c: c["component_paths"].pop("native/systemprompt.md"),
            lambda c: c["component_paths"].update({"model-chosen.py": "/tmp/model.py"}),
            lambda c: c["component_paths"].update({"native/systemprompt.md": "/safe/../escape"}),
            lambda c: c["component_paths"].update({"native/systemprompt.md": c["component_paths"]["sdk/systemprompt.md"]}),
            lambda c: c.update(reports_dir=c["framework"]["root"] + "/reports"),
            lambda c: c.update(reports_dir=str(self.base / "sources")),
        ):
            config = copy.deepcopy(self.config)
            mutation(config)
            with self.assertRaises(audit.AuditError):
                audit.validate_config(config)

    def test_invalid_origins_never_create_reports(self):
        for origin in ("daily", "scheduled; rm", "model", "MANUAL", "", None, {}):
            with self.subTest(origin=origin), self.assertRaises(audit.AuditError):
                self.run_audit(origin=origin)
        self.assertEqual(list(self.reports.iterdir()), [])

    def test_official_missing_trigger_fails_without_synthetic_repair(self):
        self.change("native/systemprompt.md", b"No workflow names are present.\n")
        report = self.run_audit()["report"]
        self.assertEqual(report["surfaces"]["native"]["status"], "findings")
        self.assertEqual(report["status"], "findings")
        self.assertTrue(any(d["kind"] == "review_structural_findings" for d in report["review_drafts"]))

    ROUTER = ("MARKERS={\n" + "".join(f"    '{n}':'X',\n" for n in
              ("soc-query", "soc-investigate", "soc-change", "soc-recover")) + "}\n"
              "raise RuntimeError('router code must never run')\n")

    def test_code_routed_skills_projected_from_router_markers_only(self):
        # Model-facing text names only soc-output; the router literally loads the rest.
        self.change("native/systemprompt.md", b"Always apply soc-output.\n")
        self.change("native/scripts/workflow_contract.py", self.ROUTER.encode())
        report = self.run_audit()["report"]
        native = report["surfaces"]["native"]
        self.assertEqual(native["status"], "passed")
        self.assertEqual(native["routing_projection"],
                         {"source": "scripts/workflow_contract.py",
                          "skills": ["soc-change", "soc-investigate", "soc-query", "soc-recover"]})
        self.assertNotIn("native/routing_index.md", report["sources"])
        self.assertEqual(Path(self.paths["native/systemprompt.md"]).read_bytes(), b"Always apply soc-output.\n")

    def test_skill_absent_from_router_is_still_untriggered_and_classified(self):
        self.change("native/systemprompt.md", b"Always apply soc-output.\n")
        self.change("native/scripts/workflow_contract.py",
                    self.ROUTER.replace("    'soc-recover':'X',\n", "").encode())
        report = self.run_audit()["report"]
        native = report["surfaces"]["native"]
        self.assertEqual(native["status"], "findings")
        self.assertEqual(native["finding_kinds"], [{"kind": "untriggered_skill", "skill": "soc-recover"}])
        self.assertEqual(native["unclassified_findings"], 0)

    def test_router_markers_require_literal_dict(self):
        tree = {"scripts/workflow_contract.py": "MARKERS=dict(soc_query='X')\nOTHER={'soc-query':'X'}\n"}
        self.assertEqual(audit._code_routed_skills(tree), [])
        self.assertEqual(audit._code_routed_skills({}), [])
        tree = {"scripts/workflow_contract.py": "MARKERS={'soc-query':'X', 'Bad Name':'Y', 1:'Z'}\n"}
        self.assertEqual(audit._code_routed_skills(tree), ["soc-query"])

    def test_cross_copy_drift_and_official_diff_are_exact(self):
        key = "sdk/skills/soc-query/SKILL.md"
        raw = self.skill("soc-query", "Different investigation evidence for this copy.")
        self.change(key, raw)
        report = self.run_audit()["report"]
        entry = next(x for x in report["cross_copy_skills"] if x["skill"] == "soc-query")
        self.assertEqual(entry["status"], "drift")
        self.assertEqual(entry["copies"][key], digest(raw))
        diff = next(x for x in report["framework_diffs"] if x["before"] == "native" and x["after"] == "sdk")
        self.assertIn("skills/soc-query/SKILL.md", diff["diff"]["modified"])
        self.assertEqual(report["status"], "findings")
        self.assertTrue(all(d["requires_approval"] and not d["apply"] for d in report["review_drafts"]))

    def test_bounded_duplicate_candidates_never_merge(self):
        for key in self.paths:
            if "/skills/" in key:
                self.change(key, self.skill(key.split("/")[2], "alpha bravo charlie delta echo foxtrot"))
        report = self.run_audit()["report"]
        duplicates = report["duplicates"]
        self.assertEqual(len(duplicates["candidates"]), audit.MAX_DUPLICATE_CANDIDATES)
        self.assertLessEqual(duplicates["pairs_compared"], audit.MAX_DUPLICATE_PAIRS)
        self.assertTrue(duplicates["truncated"])
        self.assertFalse(duplicates["automatic_merge"])
        self.assertEqual(report["source_writes"], 0)

    def test_large_skills_explicitly_skipped_by_duplicate_scan(self):
        self.change("sdk/skills/soc-query/SKILL.md", self.skill("soc-query", "word " * 7000))
        result = self.run_audit()["report"]["duplicates"]
        self.assertTrue(result["truncated"])
        self.assertEqual(result["skipped_large_components"], ["sdk/skills/soc-query/SKILL.md"])

    def test_invalid_python_utf8_frontmatter_and_empty_inputs_are_not_passes(self):
        cases = [
            ("sdk/scripts/runtime.py", b"def broken(:\n", "python_parse_failed"),
            ("sdk/systemprompt.md", b"\xff", "source_not_utf8"),
            ("sdk/systemprompt.md", b"", "empty_component"),
            ("sdk/systemprompt.md", b"nul\x00", "source_contains_nul"),
            ("sdk/skills/soc-query/SKILL.md", b"description: deceiving\nname: soc-query\n", "skill_frontmatter_missing"),
            ("sdk/skills/soc-query/SKILL.md", b"---\nname: soc-query\ndescription: |\n  folded\n---\n", "unsupported_skill_scalar"),
        ]
        for i, (key, raw, code) in enumerate(cases):
            with self.subTest(code=code):
                original = Path(self.paths[key]).read_bytes()
                self.change(key, raw)
                report = self.run_audit(now=NOW + timedelta(microseconds=i))["report"]
                self.assertEqual(report["sources"][key]["error_code"], code)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["review_drafts"], [])
                self.change(key, original)

    def test_missing_component_and_size_limit(self):
        key = "sdk/scripts/runtime.py"
        path = Path(self.paths[key])
        path.unlink()
        report = self.run_audit()["report"]
        self.assertEqual(report["sources"][key]["error_code"], "missing_file")
        self.assertEqual(report["status"], "incomplete")
        path.write_bytes(b"#" * (audit.MAX_SOURCE + 1))
        report = self.run_audit(now=NOW + timedelta(microseconds=1))["report"]
        self.assertEqual(report["sources"][key]["error_code"], "file_size_limit")

    def test_symlink_file_and_parent_cannot_escape(self):
        key = "sdk/scripts/runtime.py"
        path = Path(self.paths[key])
        path.unlink()
        path.symlink_to(Path(self.paths["native/scripts/harness.py"]))
        self.assertEqual(self.run_audit()["report"]["status"], "incomplete")
        parent = self.base / "sources" / "native"
        target = parent.with_name("elsewhere")
        parent.rename(target)
        parent.symlink_to(target, target_is_directory=True)
        report = self.run_audit(now=NOW + timedelta(microseconds=1))["report"]
        self.assertEqual(report["sources"]["native/systemprompt.md"]["status"], "incomplete")

    def test_fifo_hardlink_writable_and_untrusted_owner_rejected(self):
        path = self.base / "special"
        os.mkfifo(path)
        with self.assertRaisesRegex(audit.AuditError, "not_regular_file"):
            audit._read(str(path), 100, self.policy)
        path.unlink()
        os.link(self.paths["sdk/scripts/runtime.py"], path)
        with self.assertRaisesRegex(audit.AuditError, "hardlink_rejected"):
            audit._read(str(path), 100, self.policy)
        path.unlink()
        path.write_bytes(b"safe")
        path.chmod(0o666)
        with self.assertRaisesRegex(audit.AuditError, "writable_by_others"):
            audit._read(str(path), 100, self.policy)
        with self.assertRaises(audit.AuditError):
            audit._read(str(path), 100, audit.FilePolicy(os.getuid() + 10000, True))

    def test_vendor_changed_missing_extra_and_symlink_are_not_imported(self):
        path = self.vendor / "harness2/core/tree.py"
        original = path.read_bytes()
        path.write_bytes(b"raise RuntimeError('untrusted vendor executed')\n")
        with mock.patch.object(audit, "_official_tree", side_effect=AssertionError("must not import")):
            report = self.run_audit()["report"]
        self.assertEqual(report["framework"]["error_code"], "framework_source_mismatch")
        path.write_bytes(original)
        path.unlink()
        report = self.run_audit(now=NOW + timedelta(microseconds=1))["report"]
        self.assertEqual(report["framework"]["status"], "incomplete")
        path.write_bytes(original)
        extra = self.vendor / "unlisted.py"
        extra.write_text("pass\n")
        report = self.run_audit(now=NOW + timedelta(microseconds=2))["report"]
        self.assertEqual(report["framework"]["error_code"], "unlisted_framework_file")
        extra.unlink()
        path.unlink()
        path.symlink_to(self.paths["sdk/scripts/runtime.py"])
        self.assertEqual(self.run_audit(now=NOW + timedelta(microseconds=3))["report"]["status"], "incomplete")

    def test_context_unavailable_with_none_counters_is_incomplete(self):
        self.context.update(status="unavailable", model=None, catalog=[], catalog_sha256=None,
                            error_code="discovery_unavailable", **{k: None for k in
                            ("model_calls", "tool_calls", "chat_posts", "protected_calls")})
        self.write_context()
        report = self.run_audit()["report"]
        self.assertEqual(report["context"]["error_code"], "context_unavailable")
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["draft_status"], "withheld_incomplete_evidence")
        self.assertEqual(report["review_drafts"], [])

    def test_context_age_future_timezone_and_missing(self):
        for i, value in enumerate((NOW - timedelta(seconds=181), NOW + timedelta(seconds=1), NOW.replace(tzinfo=None))):
            with self.subTest(value=value):
                self.context["observed_at_kst"] = value.isoformat()
                self.write_context()
                report = self.run_audit(now=NOW + timedelta(microseconds=i))["report"]
                self.assertEqual(report["context"]["status"], "incomplete")
                self.assertEqual(report["status"], "incomplete")
        self.context_path.unlink()
        report = self.run_audit(now=NOW + timedelta(microseconds=10))["report"]
        self.assertEqual(report["context"]["error_code"], "missing_file")

    def test_context_catalog_tamper_and_nonzero_bool_counters(self):
        baseline = copy.deepcopy(self.context)
        for i, update in enumerate(({"catalog_sha256": "0" * 64}, {"model_calls": 1}, {"tool_calls": False})):
            self.context = copy.deepcopy(baseline)
            self.context.update(update)
            self.write_context()
            report = self.run_audit(now=NOW + timedelta(microseconds=i))["report"]
            self.assertEqual(report["context"]["status"], "incomplete")

    def test_source_observation_mismatch_stale_missing_and_wrong_origin(self):
        baseline = copy.deepcopy(self.context)
        key = "native/systemprompt.md"
        for i, update in enumerate(({"sha256": "0" * 64}, {"size": 1}, {"path": "/different"},
                                   {"status": "unavailable"},
                                   {"observed_at_kst": (NOW - timedelta(seconds=181)).isoformat()})):
            self.context = copy.deepcopy(baseline)
            self.context["source_observations"][key].update(update)
            self.write_context()
            report = self.run_audit(now=NOW + timedelta(microseconds=i))["report"]
            self.assertEqual(report["source_snapshot"]["status"], "incomplete")
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["review_drafts"], [])
        self.context = baseline
        del self.context["source_observations"][key]
        self.write_context()
        report = self.run_audit(now=NOW + timedelta(microseconds=20))["report"]
        self.assertEqual(report["source_snapshot"]["error_code"], "source_snapshot_ids_mismatch")

    def test_old_snapshot_cannot_borrow_fresh_context(self):
        self.change("native/systemprompt.md", b"modified snapshot\n", refresh=False)
        report = self.run_audit()["report"]
        self.assertEqual(report["source_snapshot"]["error_code"], "source_snapshot_hash_mismatch")
        self.assertEqual(report["status"], "incomplete")

    def test_report_versions_latest_atomic_and_older_completion(self):
        first = self.run_audit(now=NOW + timedelta(seconds=2))
        old = self.run_audit(now=NOW + timedelta(seconds=1))
        self.assertEqual(audit.get_latest(self.reports, policy=self.policy)["sha256"], first["sha256"])
        self.assertTrue((self.reports / old["report_file"]).is_file())
        previous = (self.reports / "latest.json").read_bytes()
        replace = audit.os.replace
        def fail_pointer(src, dest, **kwargs):
            if dest == "latest.json":
                raise OSError("simulated crash before atomic pointer replace")
            return replace(src, dest, **kwargs)
        with mock.patch.object(audit.os, "replace", side_effect=fail_pointer), self.assertRaises(OSError):
            self.run_audit(now=NOW + timedelta(seconds=3))
        self.assertEqual((self.reports / "latest.json").read_bytes(), previous)
        self.assertFalse(list(self.reports.glob(".audit-*.tmp")))
        self.assertEqual(audit.get_latest(self.reports, policy=self.policy)["sha256"], first["sha256"])

    def test_latest_is_readonly_and_detects_tamper_traversal_and_symlink(self):
        result = self.run_audit()
        all_files = {p: p.read_bytes() for p in self.reports.iterdir()}
        audit.get_latest(self.reports, policy=self.policy)
        self.assertEqual(all_files, {p: p.read_bytes() for p in self.reports.iterdir()})
        report = self.reports / result["report_file"]
        report.write_bytes(report.read_bytes() + b" ")
        with self.assertRaisesRegex(audit.AuditError, "report_hash_mismatch"):
            audit.get_latest(self.reports, policy=self.policy)
        pointer_path = self.reports / "latest.json"
        pointer = json.loads(pointer_path.read_bytes())
        pointer["report"] = "../context.json"
        pointer_path.write_text(json.dumps(pointer))
        with self.assertRaises(audit.AuditError):
            audit.get_latest(self.reports, policy=self.policy)
        pointer_path.unlink()
        pointer_path.symlink_to(self.context_path)
        with self.assertRaises(OSError):
            audit.get_latest(self.reports, policy=self.policy)
        with self.assertRaises(OSError):
            self.run_audit(now=NOW + timedelta(seconds=1))

    def test_report_directory_symlink_or_insecure_permissions_rejected(self):
        alias = self.base / "report-link"
        alias.symlink_to(self.reports, target_is_directory=True)
        self.config["reports_dir"] = str(alias)
        with self.assertRaises(OSError):
            self.run_audit()
        self.config["reports_dir"] = str(self.reports)
        self.reports.chmod(0o777)
        with self.assertRaises(audit.AuditError):
            self.run_audit()

    def test_json_duplicate_keys_nonfinite_and_config_size_limits(self):
        for raw in (b'{"schema_version":1,"schema_version":2}', b'{"value":NaN}', b'\xff'):
            with self.assertRaises(audit.AuditError):
                audit._decode_json(raw)
        self.config["collector_facts"]["huge"] = "x" * audit.MAX_CONFIG
        with self.assertRaises(audit.AuditError):
            audit.validate_config(self.config)

    def test_cli_fixed_paths_and_persisted_status_exit_zero(self):
        for origin in ("manual", "scheduled"):
            for status_value in ("passed", "findings", "incomplete"):
                with mock.patch.object(audit, "_read", return_value=json.dumps(self.config).encode()) as read:
                    with mock.patch.object(audit, "run_audit", return_value={
                        "report": {"scope": "structural checks", "status": status_value},
                        "report_file": "stored.json", "sha256": "a" * 64}) as run:
                        with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                            self.assertEqual(audit.main([origin]), 0)
                        self.assertEqual(json.loads(output.getvalue())["status"], status_value)
                        self.assertEqual(read.call_args.args[0], audit.CONFIG_PATH)
                        self.assertEqual(run.call_args.args[1], origin)
        with mock.patch.object(audit, "_read", side_effect=PermissionError), mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(audit.main(["manual"]), 2)
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            for argv in ([], ["manual", "--config", "/tmp/model.json"], ["daily"], ["scheduled", "/tmp/path"]):
                with self.assertRaises(SystemExit) as raised:
                    audit.main(argv)
                self.assertEqual(raised.exception.code, 2)

    def test_cli_latest_is_readonly_summary_and_never_starts_an_audit(self):
        summary = {"scope": "structural checks", "status": "passed", "origin": "scheduled",
                   "observed_at_kst": "2026-11-12T03:00:00+09:00", "schema_version": 1,
                   "report_file": "r.json", "sha256": "a" * 64, "automatic_adoption": False,
                   "operational_changes_require_approval": True}
        with mock.patch.object(audit, "get_latest", return_value=summary) as latest, \
                mock.patch.object(audit, "run_audit") as run, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(audit.main(["--latest"]), 0)
        self.assertEqual(json.loads(output.getvalue()), summary)
        latest.assert_called_once_with()
        run.assert_not_called()
        # A missing/corrupt stored report surfaces as incomplete, never passed.
        with mock.patch.object(audit, "get_latest", side_effect=audit.AuditError("invalid_latest_pointer")), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(audit.main(["--latest"]), 2)
        failed = json.loads(output.getvalue())
        self.assertEqual(failed["status"], "incomplete")
        self.assertEqual(failed["error_code"], "invalid_latest_pointer")
        # --latest never takes an origin, and a bare run still requires a mode.
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            for argv in (["--latest", "scheduled"], ["--latest", "manual"]):
                with self.assertRaises(SystemExit) as raised:
                    audit.main(argv)
                self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
