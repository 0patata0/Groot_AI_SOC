"""Type/ownership boundaries, with no daemon, network or third-party packages."""
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import broker as B
import manifest as M


LEGACY = {"cve_id": "CVE-2021-44228", "software": "Log4j", "vulnerable_version": "2.14.1",
          "image_tag": "groot-labs/log4shell:2.14.1",
          "image_id": "sha256:6534536682a48754c4ffd98f8d7fadec20180b15dae361c14e0a672f57e73d36",
          "host_port": 18081, "container_port": 8080, "path": "/log4shell/"}
EXTERNAL = {"type": "existing-http", "cve_id": "LAB-DVWA", "software": "DVWA",
            "vulnerable_version": "training application", "path": "/dvwa/"}
CLI = {"type": "local-cli", "cve_id": "CVE-2021-3156", "software": "sudo",
       "vulnerable_version": "isolated lab"}
TERMINALS = [{"type": "managed-terminal", "cve_id": identifier, "software": lab,
              "vulnerable_version": "isolated lab"} for identifier, lab in M.TERMINAL_LABS.items()]


class CatalogTypes(unittest.TestCase):
    def test_legacy_contract_hash_and_labels_are_unchanged(self):
        implicit = M.validate_manifest([LEGACY])[0]
        explicit = M.validate_manifest([dict(LEGACY, type="managed-http")])[0]
        expected_hash = "dc8c76c6dffe09d3128e6c0dcfea787a63b32fe08734131d0bc7af0eebe6e33f"
        self.assertEqual(implicit, explicit)
        self.assertEqual(B.runtime_hash(implicit), expected_hash)
        self.assertEqual(B.labels_for(implicit), {
            "io.capstone.offline-labs": "1", "io.capstone.offline-labs.cve": "CVE-2021-44228",
            "io.capstone.offline-labs.image": LEGACY["image_id"],
            "io.capstone.offline-labs.contract": expected_hash})
        self.assertEqual(B.create_args(implicit), B.create_args(explicit))
        self.assertEqual(B.name_for(implicit), "offline-lab-cve-2021-44228")

    def test_three_types_validate_without_inventing_images_or_cves(self):
        rows = M.validate_manifest([LEGACY, EXTERNAL, CLI])
        self.assertEqual([x["type"] for x in rows], ["managed-http", "existing-http", "local-cli"])
        self.assertNotIn("image_id", rows[1])
        self.assertNotIn("path", rows[2])
        self.assertEqual(rows[1]["cve_id"], "LAB-DVWA")

    def test_types_cannot_smuggle_runtime_targets_or_options(self):
        bad = [dict(LEGACY, type="container"), dict(LEGACY, type=[]),
               dict(LEGACY, cve_id="LAB-DVWA"), dict(EXTERNAL, cve_id="LAB-OTHER"),
               dict(EXTERNAL, cve_id="CVE-2021-44228"), dict(CLI, cve_id="LAB-DVWA")]
        for row in (EXTERNAL, CLI):
            for key, value in (("image_id", LEGACY["image_id"]), ("host_port", 80),
                               ("container_port", 80), ("container_name", "existing"),
                               ("health_url", "http://127.0.0.1/"), ("command", "id")):
                bad.append(dict(row, **{key: value}))
        bad.append(dict(CLI, path="/shell"))
        for row in bad:
            with self.subTest(row=row), self.assertRaises(M.ManifestError):
                M.validate_manifest([row])

    def test_duplicate_ids_are_rejected_across_types(self):
        with self.assertRaises(M.ManifestError):
            M.validate_manifest([LEGACY, dict(CLI, cve_id=LEGACY["cve_id"])])

    def test_terminal_targets_are_fixed_without_catalog_execution_options(self):
        rows = M.validate_manifest(TERMINALS)
        self.assertEqual([row["cve_id"] for row in rows], list(M.TERMINAL_LABS))
        for row in rows:
            self.assertNotIn("image_id", row)
            self.assertNotIn("path", row)
            for key, value in (("image_id", LEGACY["image_id"]), ("command", "sh"),
                               ("socket", "/tmp/control.sock"), ("lab", "sudo"),
                               ("path", "/terminal/"), ("host_port", 18084), ("container_port", 6379),
                               ("user", "0:0"), ("container_id", "a" * 64)):
                with self.subTest(cve=row['cve_id'], key=key), self.assertRaises(M.ManifestError):
                    M.validate_manifest([dict(row, **{key: value})])
        with self.assertRaises(M.ManifestError):
            M.validate_manifest([dict(TERMINALS[0], cve_id="CVE-2022-9999")])

    def test_catalog_has_three_http_three_terminal_including_rootless_sudo(self):
        rows = M.load_manifest(Path(__file__).with_name("cve_list.json"))
        self.assertEqual(len(rows), 6)
        self.assertEqual([row["cve_id"] for row in rows if row["type"] == "managed-terminal"],
                         list(M.TERMINAL_LABS))
        self.assertEqual([row["cve_id"] for row in rows if row["type"] == "local-cli"], [])
        self.assertEqual(next(row for row in rows if row["cve_id"] == "CVE-2021-3156")["type"], "managed-terminal")
        self.assertEqual(len([row for row in rows if row["type"] == "managed-http"]), 3)


class LegacyReadOnlyTypes(unittest.TestCase):
    def setUp(self):
        self.docker = mock.Mock()
        self.receipts = mock.Mock()
        # Explicit legacy fixture; production sudo is now managed-terminal.
        # Any receipt access by external/CLI paths would fail this test.
        type(self.receipts).records = mock.PropertyMock(side_effect=AssertionError("receipt access"))
        self.reader = mock.Mock(return_value={"status": "ready", "verification": "environment_only",
                                              "checked_at": 1000, "expires_at": 1600})
        self.broker = B.Broker(M.validate_manifest([EXTERNAL, CLI]), self.docker, self.receipts,
                               nonweb_reader=self.reader)
        self.broker.safety = mock.Mock()

    def test_external_status_does_not_inspect_adopt_or_probe(self):
        result = self.broker.handle({"action": "status", "cve_id": "LAB-DVWA"})
        self.assertTrue(result["ok"])
        row = result["labs"]["LAB-DVWA"]
        self.assertEqual(row["status"], "external")
        self.assertEqual(row["verification"], "managed_externally")
        self.assertFalse(row["managed"])
        self.assertIsNone(row["url"])
        self.assertEqual(self.docker.mock_calls, [])
        self.assertEqual(self.receipts.mock_calls, [])
        self.reader.assert_not_called()

    def test_cli_status_only_reads_environment_attestation(self):
        result = self.broker.handle({"action": "status", "cve_id": "CVE-2021-3156"})
        row = result["labs"]["CVE-2021-3156"]
        self.assertEqual(row["status"], "ready")
        self.assertEqual(row["verification"], "environment_only")
        self.assertFalse(row["attack_tested"])
        self.assertFalse(row["host_scenario_verified"])
        self.assertIsNone(row["url"])
        self.reader.assert_called_once_with("CVE-2021-3156")
        self.assertEqual(self.docker.mock_calls, [])
        self.assertEqual(self.receipts.mock_calls, [])

    def test_deploy_and_stop_refuse_before_safety_or_any_backend_access(self):
        for identifier, error in (("LAB-DVWA", "external_lab_managed_separately"),
                                   ("CVE-2021-3156", "local_cli_managed_separately")):
            for action in ("deploy", "stop"):
                self.assertEqual(self.broker.handle({"action": action, "cve_id": identifier}),
                                 {"ok": False, "error": error})
        self.broker.safety.assert_not_called()
        self.reader.assert_not_called()
        self.assertEqual(self.docker.mock_calls, [])
        self.assertEqual(self.receipts.mock_calls, [])


class NonwebStatus(unittest.TestCase):
    def document(self):
        return {"schema": 1, "checked_at": 1000, "expires_at": 1600,
                "labs": {"CVE-2021-3156": {"status": "ready"}}}

    def test_time_bounds_and_stale_results_never_claim_ready(self):
        self.assertEqual(B.nonweb_status_document(self.document(), "CVE-2021-3156", 1599)["status"], "ready")
        stale = B.nonweb_status_document(self.document(), "CVE-2021-3156", 1600)
        self.assertEqual((stale["status"], stale["verification"]), ("needs_setup", "expired"))
        for field, value in (("checked_at", True), ("expires_at", 1601),
                             ("expires_at", 1000), ("checked_at", 0)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                B.nonweb_status_document(dict(self.document(), **{field: value}), "CVE-2021-3156", 1200)
        with self.assertRaises(ValueError):
            B.nonweb_status_document(self.document(), "CVE-2021-3156", 999)

    def test_schema_cannot_attest_attack_or_add_execution_instructions(self):
        for mutation in ({"schema": True}, {"command": "sudo"},
                         {"labs": {"LAB-DVWA": {"status": "ready"}}},
                         {"labs": {"CVE-2021-3156": {"status": "running"}}},
                         {"labs": {"CVE-2021-3156": {"status": "ready", "attack_tested": True}}}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                B.nonweb_status_document(dict(self.document(), **mutation), "CVE-2021-3156", 1200)
        missing = B.nonweb_status_document(self.document(), "CVE-2022-1234", 1200)
        self.assertEqual((missing["status"], missing["verification"]), ("needs_setup", "missing"))

    def test_only_private_root_regular_single_link_file_is_accepted(self):
        good = {"st_mode": stat.S_IFREG | 0o600, "st_uid": 0, "st_gid": 0, "st_nlink": 1, "st_size": 120}
        B.validate_nonweb_file(SimpleNamespace(**good))
        for field, value in (("st_uid", 1000), ("st_gid", 1000), ("st_mode", stat.S_IFREG | 0o640),
                             ("st_mode", stat.S_IFREG | 0o666), ("st_mode", stat.S_IFDIR | 0o600),
                             ("st_nlink", 2), ("st_size", B.NONWEB_MAX_BYTES + 1), ("st_size", 0)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                B.validate_nonweb_file(SimpleNamespace(**dict(good, **{field: value})))

    def test_file_reader_rejects_symlink_duplicate_json_and_malformed_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_text(json.dumps(self.document()))
            path.chmod(0o600)
            native_fstat = os.fstat
            def root_stat(fd):
                info = native_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0,
                                       st_nlink=info.st_nlink, st_size=info.st_size)
            # Emulate root-owned metadata without requiring root on the test host.
            with mock.patch.object(B, "trusted_path"), mock.patch.object(B.os, "fstat", side_effect=root_stat):
                self.assertEqual(B.read_nonweb_status("CVE-2021-3156", path, 1200)["status"], "ready")
                link = Path(directory) / "linked.json"
                link.symlink_to(path)
                self.assertEqual(B.read_nonweb_status("CVE-2021-3156", link, 1200)["verification"], "invalid")
                for raw in ('{"schema":1,"schema":1}', '{', '[' * 1500 + ']' * 1500):
                    path.write_text(raw)
                    self.assertEqual(B.read_nonweb_status("CVE-2021-3156", path, 1200)["verification"], "invalid")
                self.assertEqual(B.read_nonweb_status("CVE-2021-3156", path.with_name("missing"), 1200)["verification"], "missing")
            with mock.patch.object(B, "trusted_path", side_effect=M.ManifestError("untrusted parent")):
                self.assertEqual(B.read_nonweb_status("CVE-2021-3156", path, 1200)["verification"], "invalid")


if __name__ == "__main__":
    unittest.main()
