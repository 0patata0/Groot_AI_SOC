"""Offline installer security boundaries; no root, systemd, network or runners."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("harness_maintenance", REPO / "deployment/harness_maintenance.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
OFFICIAL_LOCK = (REPO / "infra/validation/harness2/framework.lock.json").read_bytes()


def archive(entries, suffix=b""):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as out:
        for item in entries:
            if isinstance(item, tuple):
                name, content = item
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o644
            else:
                info, content = item, b""
            out.addfile(info, io.BytesIO(content))
    return gzip.compress(buffer.getvalue() + suffix, mtime=0)


def manifest(raw, contents):
    value = {k: v for k, v in json.loads(OFFICIAL_LOCK).items() if k != "files"}
    value.update(archive_sha256=m.sha(raw), archive_size=len(raw),
                 files={name: {"sha256": m.sha(data), "size": len(data)} for name, data in contents.items()})
    return m.canonical(value)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.contents = {"LICENSE": b"Apache fixture\n", "harness2/core/tree.py": b"def validate(): pass\n"}
        self.raw = archive(list(self.contents.items()))
        self.lock = manifest(self.raw, self.contents)

    def checked(self, raw=None, contents=None):
        raw = self.raw if raw is None else raw
        lock = manifest(raw, self.contents if contents is None else contents)
        with patch.object(m, "MANIFEST_SHA256", m.sha(lock)):
            return m.checked_archive(raw, lock)

    def test_real_lock_pin_and_exact_official_identity(self):
        value = m.checked_manifest(OFFICIAL_LOCK)
        self.assertEqual(value["commit"], m.COMMIT)
        self.assertEqual(len(value["files"]), 140)
        self.assertEqual(value["archive_size"], 7102702)
        self.assertEqual(value["python"], ">=3.12,<3.14")

    def test_lock_bytes_are_pinned_even_for_whitespace_changes(self):
        with self.assertRaisesRegex(ValueError, "manifest_pin"):
            m.checked_manifest(OFFICIAL_LOCK + b" ")

    def test_manifest_rejects_wrong_commit_and_duplicate_json_keys(self):
        value = json.loads(self.lock)
        value["commit"] = "a" * 40
        for raw in (m.canonical(value), self.lock.replace(b'"schema":1', b'"schema":1,"schema":1')):
            with patch.object(m, "MANIFEST_SHA256", m.sha(raw)), self.assertRaises(ValueError):
                m.checked_manifest(raw)

    def test_manifest_rejects_bool_size_and_file_parent_collision(self):
        for change in (lambda v: v["files"]["LICENSE"].update(size=True),
                       lambda v: v["files"].update({"harness2": {"size": 0, "sha256": m.sha(b"")}})):
            value = json.loads(self.lock)
            change(value)
            raw = m.canonical(value)
            with patch.object(m, "MANIFEST_SHA256", m.sha(raw)), self.assertRaises(ValueError):
                m.checked_manifest(raw)

    def test_complete_archive_preserves_every_original_byte(self):
        self.assertEqual(self.checked(), self.contents)

    def test_archive_size_and_hash_are_checked_before_decompression(self):
        with patch.object(m, "MANIFEST_SHA256", m.sha(self.lock)):
            for raw in (self.raw[:-1], self.raw[:-1] + bytes([self.raw[-1] ^ 1])):
                with self.assertRaisesRegex(ValueError, "archive_integrity"):
                    m.checked_archive(raw, self.lock)

    def test_traversal_absolute_and_noncanonical_paths_are_rejected(self):
        for name in ("/tmp/pwn", "../pwn", "harness2/../../pwn", "./LICENSE", "a//b", "a\\b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.checked(archive([(name, b"x")]))

    def test_symlink_hardlink_devices_fifo_and_directories_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.DIRTYPE):
            member = tarfile.TarInfo("LICENSE")
            member.type = kind
            member.mode = 0o644
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "/etc/elsewhere"
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "archive_member_type"):
                self.checked(archive([member]))

    def test_missing_extra_duplicate_unsorted_and_wrong_bytes_are_rejected(self):
        entries = list(self.contents.items())
        variants = [entries[:-1], entries + [("unexpected", b"x")],
                    entries + entries[:1], list(reversed(entries)),
                    [("LICENSE", b"X" * len(self.contents["LICENSE"]))] + entries[1:],
                    [("LICENSE", b"x")] + entries[1:]]
        for rows in variants:
            with self.subTest(rows=[n for n, _ in rows]), self.assertRaises(ValueError):
                self.checked(archive(rows))

    def test_modes_sparse_metadata_and_pax_traversal_are_rejected(self):
        for mode, pax in ((0o4755, {}), (0o644, {"GNU.sparse.name": "bad"}),
                          (0o644, {"path": "../LICENSE"})):
            item = tarfile.TarInfo("LICENSE")
            item.mode = mode
            item.pax_headers = pax
            with self.subTest(mode=mode, pax=pax), self.assertRaises(ValueError):
                self.checked(archive([item]))

    def test_gzip_concatenation_tar_trailing_data_and_bombs_are_rejected(self):
        for raw in (self.raw + gzip.compress(b"extra", mtime=0),
                    archive(list(self.contents.items()), b"hidden tar data"), b"not gzip"):
            with self.assertRaises(ValueError):
                self.checked(raw)
        raw = gzip.compress(b"\0" * (8 * 1024 * 1024 + 2048), mtime=0)
        with patch.object(m, "MAX_EXPANDED", 1024), self.assertRaisesRegex(ValueError, "archive_compression"):
            self.checked(raw)

    def test_failed_archive_validation_makes_no_extraction_writes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, "_mkdir") as mkdir:
            with self.assertRaises(ValueError):
                m.extract_archive(b"bad", OFFICIAL_LOCK, Path(tmp) / "vendor")
            mkdir.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()), [])


class ConfigAndBundleTests(unittest.TestCase):
    def sources(self):
        return {"server_audit.py": b"raise RuntimeError('must not be imported')\n",
                "server_context.py": b"raise RuntimeError('must not be imported')\n",
                "framework.lock.json": OFFICIAL_LOCK}

    def test_config_is_schema_neutral_copied_and_has_no_io(self):
        config = {"future_core_field": {"source": "/opt/capstone/siem/hermes-data", "items": [1, None, True]}}
        original = copy.deepcopy(config)
        with patch.object(m, "_run") as run:
            checked = m.configuration(config)
        run.assert_not_called()
        config["future_core_field"]["items"].append(2)
        self.assertEqual(checked, original)

    def test_config_rejects_non_json_nonfinite_oversize_depth_and_cycles(self):
        cycle = {}; cycle["loop"] = cycle
        values = [[], {1: "bad"}, {"bad": Path("/tmp")}, {"bad": float("nan")},
                  {"bad": float("inf")}, {"bad": "x" * 65537}, {"bad": "\0"}, cycle]
        for value in values:
            with self.subTest(type=type(value)), self.assertRaises(ValueError):
                m.configuration(value)

    def test_source_bundle_decodes_without_executing_runners(self):
        self.assertEqual(m.checked_source_bundle(m.encoded_source_bundle(self.sources())), self.sources())

    def test_current_core_pure_config_interface_accepts_parent_layout_mapping(self):
        raw = (REPO / "infra/validation/harness2/server_audit.py").read_bytes()
        validator = m._core_validator(raw)
        config = validator.__globals__["build_config"](str(m.VENDOR), json.loads(OFFICIAL_LOCK)["files"])
        self.assertEqual(m._checked_core_config(config, validator), config)
        self.assertNotIn("_capstone_harness2_install_core", __import__("sys").modules)

    def test_source_bundle_rejects_unknown_files_bad_base64_hash_and_syntax(self):
        bundle = m.encoded_source_bundle(self.sources())
        for mutate in (lambda b: b["files"].update({"../bad.py": {}}),
                       lambda b: b["files"]["server_audit.py"].update(content_b64="!!"),
                       lambda b: b["files"]["server_audit.py"].update(sha256="a" * 64)):
            value = copy.deepcopy(bundle); mutate(value)
            with self.assertRaises(ValueError): m.checked_source_bundle(value)
        sources = self.sources(); sources["server_audit.py"] = b"def invalid(\n"
        with self.assertRaises(SyntaxError): m.encoded_source_bundle(sources)

    def test_root_trust_rejects_symlinks_and_unprivileged_owned_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "source"; path.write_bytes(b"example")
            link = Path(tmp) / "link"; link.symlink_to(path)
            with self.assertRaises(ValueError): m._trusted(link)
            if os.getuid() != 0:
                with self.assertRaises(ValueError): m._trusted(path)


class UnitsTests(unittest.TestCase):
    def test_schedule_is_fixed_03_kst_with_no_boot_or_catchup_run(self):
        timer = m.unit_documents()[m.TIMER].decode()
        self.assertIn("OnCalendar=*-*-* 03:00:00 Asia/Seoul\n", timer)
        self.assertIn("Persistent=false\n", timer)
        self.assertNotIn("OnBoot", timer)
        self.assertNotIn("OnUnit", timer)
        self.assertIn("RandomizedDelaySec=0\n", timer)

    def test_audit_waits_for_collector_and_has_only_report_write_access(self):
        unit = m.unit_documents()[m.SERVICE].decode()
        self.assertIn("Requires=" + m.CONTEXT_SERVICE + "\n", unit)
        self.assertIn("After=" + m.CONTEXT_SERVICE + "\n", unit)
        self.assertIn("PrivateNetwork=yes\n", unit)
        self.assertIn("ProtectSystem=strict\n", unit)
        self.assertIn("@network-io", unit)
        self.assertEqual([s for s in unit.splitlines() if s.startswith("ReadWritePaths=")],
                         ["ReadWritePaths=" + str(m.REPORTS)])
        self.assertIn("ReadOnlyPaths=/tmp /var/tmp\n", unit)

    def test_collector_is_fixed_root_wrapper_with_only_state_writes(self):
        unit = m.unit_documents()[m.CONTEXT_SERVICE].decode()
        # Default root identity: explicit User=/Group= with NoNewPrivileges broke
        # runuser setuid() on B (2026-11-10 live failure), so neither is set.
        self.assertNotIn("User=", unit)
        self.assertNotIn("Group=", unit)
        self.assertIn("PrivateNetwork=no\n", unit)
        self.assertEqual([s for s in unit.splitlines() if s.startswith("ReadWritePaths=")],
                         ["ReadWritePaths=" + str(m.STATE)])
        self.assertIn("ReadOnlyPaths=" + str(m.REPORTS) + "\n", unit)
        self.assertIn("CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH\n", unit)
        self.assertNotIn("CAP_DAC_OVERRIDE", unit)
        self.assertNotIn("@privileged", unit)  # runuser must be allowed to drop identity
        self.assertIn("NoNewPrivileges=yes\n", unit)
        self.assertNotIn("EnvironmentFile", unit)
        self.assertNotIn("--config", unit)
        self.assertNotIn("--output", unit)
        self.assertIn("/server_context.py\n", unit)

    def test_interpreter_cannot_inject_unit_directives(self):
        for python in ("/tmp/python", "/usr/bin/python3\nUser=root", "python3"):
            with self.assertRaises(ValueError): m.unit_documents(python)
        self.assertIn(b"/usr/bin/python3.13 -I -B", m.unit_documents("/usr/bin/python3.13")[m.SERVICE])

    def test_python_versions_fail_closed_outside_312_and_313(self):
        with patch.object(m, "_trusted"), patch.object(Path, "is_symlink", return_value=False):
            for version in ("3.11", "3.14", "3.13\nextra"):
                with patch.object(m, "_run", return_value=version), self.assertRaisesRegex(ValueError, "python_version"):
                    m._python_check("/usr/bin/python3")
            for version in ("3.12", "3.13"):
                with patch.object(m, "_run", return_value=version): m._python_check("/usr/bin/python3")


class InstallationTests(unittest.TestCase):
    """Exercise actual files, hashes and permissions; substitute only root/OS edges."""
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.base = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        paths = {"ROOT": self.base / "opt/harness", "ETC": self.base / "etc/harness",
                 "STATE": self.base / "var/state", "UNIT_DIR": self.base / "etc/units"}
        for p in paths.values(): p.parent.mkdir(parents=True, exist_ok=True)
        paths["UNIT_DIR"].mkdir()
        paths.update(VENDOR=paths["ROOT"] / "vendor" / m.COMMIT, CONFIG=paths["ETC"] / "audit.json",
                     LOCK=paths["ETC"] / "framework.lock.json", RECEIPT=paths["ETC"] / "installation.json",
                     REPORTS=paths["STATE"] / "reports", CONTEXT=paths["STATE"] / "context.json",
                     SNAPSHOTS=paths["STATE"] / "sources")
        for name, value in paths.items(): self.stack.enter_context(patch.object(m, name, value))
        self.contents = {"LICENSE": b"fixture", "harness2/core/tree.py": b"# fixture\n"}
        self.raw = archive(list(self.contents.items())); self.lock = manifest(self.raw, self.contents)
        self.stack.enter_context(patch.object(m, "MANIFEST_SHA256", m.sha(self.lock)))
        self.bundle = m.encoded_source_bundle({"framework.lock.json": self.lock,
            "server_audit.py": b"def _validate_config(value): return value\n",
            "server_context.py": b"raise AssertionError('collector must not execute')\n"})
        self.artifact = self.base / m.ARCHIVE_NAME; self.artifact.write_bytes(self.raw)
        self.config = {"core_schema_not_assumed": {"root": "/opt/capstone/siem/hermes-data"}}
        self.stack.enter_context(patch.object(m, "_root"))
        self.stack.enter_context(patch.object(m, "_python_check"))
        self.stack.enter_context(patch.object(m, "_context_account", return_value=SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())))
        self.stack.enter_context(patch.object(m.os, "chown"))
        self.stack.enter_context(patch.object(m.os, "fchown"))
        self.stack.enter_context(patch.object(m, "_trusted", side_effect=self.trusted))
        self.stack.enter_context(patch.object(m, "_read", side_effect=self.read))
        self.stack.enter_context(patch.object(m, "_metadata", side_effect=self.metadata))
        self.run = self.stack.enter_context(patch.object(m, "_run"))

    def trusted(self, path, directory=False):
        path = Path(path)
        for p in (path, *path.parents):
            if not p.is_relative_to(self.base): break
            meta = p.lstat()
            m.need(not stat.S_ISLNK(meta.st_mode) and not meta.st_mode & 0o022, "test_unsafe_path")
            if p != path or directory: m.need(stat.S_ISDIR(meta.st_mode), "test_directory")
            else: m.need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, "test_regular")
        return path

    def read(self, path, limit=m.MAX_SOURCE):
        path = self.trusted(path)
        raw = path.read_bytes(); m.need(len(raw) <= limit, "test_size")
        return raw

    def metadata(self, path, mode, uid=0, gid=0):
        meta = path.lstat()
        m.need(not stat.S_ISLNK(meta.st_mode) and stat.S_IMODE(meta.st_mode) == mode, "test_permissions")
        return meta

    def prepare(self):
        return m.prepare(self.artifact, audit_config=self.config, files=self.bundle)

    def test_prerequisite_check_has_no_writes_or_commands(self):
        before = set(self.base.rglob("*"))
        with patch.object(m, "_context_account", side_effect=AssertionError("fresh account not installed yet")):
            result = m.check(self.artifact, audit_config=self.config, files=self.bundle)
        self.assertEqual(result["status"], "prerequisites_checked")
        self.assertEqual(set(self.base.rglob("*")), before)
        self.run.assert_not_called()

    def test_prepare_extracts_all_bytes_but_never_operates_services(self):
        result = self.prepare()
        self.assertEqual(result["status"], "prepared_verified")
        for name, data in self.contents.items(): self.assertEqual((m.VENDOR / name).read_bytes(), data)
        self.assertEqual(m.CONTEXT.read_bytes(), b"")
        self.assertEqual(m.CONFIG.stat().st_mode & 0o777, 0o600)
        self.assertEqual(m.REPORTS.stat().st_mode & 0o777, 0o700)
        self.assertEqual(m.SNAPSHOTS.stat().st_mode & 0o777, 0o700)
        self.assertEqual(m.STATE.stat().st_mode & 0o777, 0o755)
        self.run.assert_not_called()

    def test_repeat_prepare_only_verifies_and_preserves_context_reports(self):
        self.prepare()
        m.CONTEXT.write_text('{"sanitized":true}')
        (m.REPORTS / "retained.json").write_text("{}")
        before = {str(p): (p.stat().st_ino, p.read_bytes()) for p in self.base.rglob("*") if p.is_file()}
        self.prepare()
        after = {str(p): (p.stat().st_ino, p.read_bytes()) for p in self.base.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.run.assert_not_called()

    def test_prepare_refuses_unmanaged_namespace_and_wrong_artifact_name(self):
        m.ROOT.mkdir()
        with self.assertRaisesRegex(ValueError, "unmanaged_namespace_exists"): self.prepare()
        self.assertEqual(list(m.ROOT.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "offline_archive_filename"):
            m.prepare(self.artifact.with_name("other.tar.gz"), audit_config=self.config, files=self.bundle)

    def test_sources_can_be_read_from_root_controlled_staged_path(self):
        source = self.base / "source"
        target = source / "infra/validation/harness2"; target.mkdir(parents=True)
        for name, raw in m.checked_source_bundle(self.bundle).items(): (target / name).write_bytes(raw)
        self.assertEqual(m.source_bundle(source), self.bundle)
        m.prepare(self.artifact, audit_config=self.config, source_root=source)
        self.run.assert_not_called()

    def test_installed_vendor_drift_missing_file_and_extra_file_are_rejected(self):
        self.prepare(); path = m.VENDOR / "LICENSE"
        path.write_bytes(b"drift")
        with self.assertRaisesRegex(ValueError, "installed_vendor_hash"): m.verify()
        path.unlink()
        with self.assertRaisesRegex(ValueError, "installed_vendor_missing"): m.verify()
        path.write_bytes(self.contents["LICENSE"])
        (m.VENDOR / "extra").write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "unexpected_vendor_file"): m.verify()

    def test_source_or_config_change_requires_separate_update_not_overwrite(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "requested_config_changed"):
            m.prepare(self.artifact, audit_config={"new": True}, files=self.bundle)
        (m.ROOT / "server_audit.py").write_bytes(b"# drift\n")
        with self.assertRaisesRegex(ValueError, "installed_runner_hash"): self.prepare()
        self.assertEqual((m.ROOT / "server_audit.py").read_bytes(), b"# drift\n")

    def test_context_links_and_writable_parent_are_rejected(self):
        self.prepare(); m.CONTEXT.unlink(); m.CONTEXT.symlink_to(m.CONFIG)
        with self.assertRaises(ValueError): m.verify()
        m.CONTEXT.unlink(); os.link(m.CONFIG, m.CONTEXT)
        with self.assertRaises(ValueError): m.verify()
        m.CONTEXT.unlink(); m.CONTEXT.write_bytes(b""); m.CONTEXT.chmod(0o600)
        m.STATE.chmod(0o777)
        with self.assertRaises(ValueError): m.verify()

    def test_unit_changes_and_vendor_symlink_cannot_pass_verification(self):
        self.prepare(); unit = m.UNIT_DIR / m.SERVICE
        raw = unit.read_bytes(); unit.write_bytes(raw.replace(b"PrivateNetwork=yes", b"PrivateNetwork=no"))
        with self.assertRaisesRegex(ValueError, "installed_unit_changed"): m.verify()
        unit.write_bytes(raw)
        target = m.VENDOR / "LICENSE"; target.unlink(); target.symlink_to(self.artifact)
        with self.assertRaises(ValueError): m.verify()

    def test_activation_requires_core_validation_before_systemctl(self):
        self.prepare()
        for validator in (False, lambda _: {"changed": True}, Mock(side_effect=ValueError("core_invalid"))):
            with self.assertRaises(ValueError): m.activate(config_check=validator)
        self.run.assert_not_called()

    def systemctl(self, argv):
        if "show" in argv:
            return "LoadState=loaded\nFragmentPath=" + str(m.UNIT_DIR / argv[2]) + "\nDropInPaths="
        if "is-enabled" in argv: return "enabled"
        if "is-active" in argv: return "active"
        return ""

    def test_activation_enables_only_timer_and_does_not_claim_audit_success(self):
        self.prepare(); self.run.side_effect = self.systemctl
        result = m.activate(config_check=m.configuration)
        self.assertEqual(result["status"], "timer_active")
        self.assertFalse(result["audit_execution_verified"])
        calls = [c.args[0] for c in self.run.call_args_list]
        self.assertIn(["/usr/bin/systemctl", "enable", "--now", m.TIMER], calls)
        self.assertFalse(any("start" in c for c in calls))

    def test_systemd_dropin_blocks_activation_before_enable(self):
        self.prepare()
        self.run.side_effect = lambda argv: self.systemctl(argv) + ("/etc/override.conf" if "show" in argv else "")
        with self.assertRaisesRegex(ValueError, "unit_override_or_load_failure"):
            m.activate(config_check=m.configuration)
        self.assertFalse(any("enable" in c.args[0] for c in self.run.call_args_list))

    def test_cli_prepare_only_uses_fixed_bundle_filename_and_does_not_activate(self):
        source = self.base / "source"
        target = source / "infra/validation/harness2"; target.mkdir(parents=True)
        for name, raw in m.checked_source_bundle(self.bundle).items(): (target / name).write_bytes(raw)
        (self.base / "audit.json").write_bytes(m.canonical(self.config))
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(m.main(["install", "--source-root", str(source), "--bundle", str(self.base),
                                     "--prepare-only"]), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "prepared_verified")
        self.assertNotIn("future_core", output.getvalue())
        self.run.assert_not_called()

    def test_cli_install_activates_and_verify_requires_active_timer(self):
        source = self.base / "source"
        target = source / "infra/validation/harness2"; target.mkdir(parents=True)
        for name, raw in m.checked_source_bundle(self.bundle).items(): (target / name).write_bytes(raw)
        (self.base / "audit.json").write_bytes(m.canonical(self.config))
        self.run.side_effect = self.systemctl
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            m.main(["install", "--source-root", str(source), "--bundle", str(self.base)])
        self.assertEqual(json.loads(output.getvalue())["status"], "timer_active")
        with patch("sys.stdout", new_callable=io.StringIO):
            m.main(["verify", "--source-root", str(source), "--bundle", str(self.base)])
        self.run.side_effect = lambda argv: "inactive" if "is-active" in argv else self.systemctl(argv)
        with self.assertRaisesRegex(ValueError, "timer_not_active"):
            m.main(["verify", "--source-root", str(source), "--bundle", str(self.base)])


if __name__ == "__main__":
    unittest.main()
