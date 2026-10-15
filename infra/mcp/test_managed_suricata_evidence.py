#!/usr/bin/env python3
"""Synthetic file/JSON-only checks; no helper, nft, Docker, network or messages."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import incident_containment as containment
import managed_suricata_evidence as reader
from test_incident_containment import event, NOW, PUBLIC
import wazuh_containment_ar as ar

BOOT = "a" * 32


class ManagedEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.state = self.root / "state" / "state.json"
        self.state.parent.mkdir(mode=0o700)
        self.base = self.root / "raw"
        self.managed = self.base / "capstone-managed"
        self.managed.mkdir(parents=True)
        self.managed.chmod(0o711)
        self.gen = self.managed / "generation-0000000001.jsonl"
        self.gen.write_bytes(b"".join(reader.canonical(event(n)) for n in (1, 2, 3)))
        self.gen.chmod(0o644)
        os.link(self.gen, self.managed / "active.jsonl")
        os.link(self.gen, self.base / "eve.json")
        s = self.gen.stat()
        self.pins = {}
        shas = {k: "b" * 64 for k in ("container_id", "engine_config_sha256", "producer_format_sha256")}
        for key in reader.PINS:
            p = self.root / key
            p.write_bytes(key.encode())
            p.chmod(0o660 if key == "wazuh_config_sha256" else 0o600)
            self.pins[key] = p
            shas[key] = hashlib.sha256(p.read_bytes()).hexdigest()
        self.obj = {"schema_version": 1, "policy": "capstone-raw-operations-v1", "engine": "suricata",
                    "machine_id": reader.MID, "boot_id": BOOT, "revision": 6, "phase": "active",
                    "current": {"basename": self.gen.name, "number": 1, "device": s.st_dev,
                                "inode": s.st_ino, "writer_config_sha256": shas["engine_config_sha256"]},
                    "pending": None, "proof": {"old_closed": None, "publish_guard": None, "readers_drained": None},
                    "source_pins": shas}
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        self.state.write_bytes(reader.canonical(self.obj)); self.state.chmod(0o600)

    def scan(self):
        return reader._events(self.state, self.base, self.pins, BOOT,
                              root_uid=os.geteuid(), root_gid=os.getegid(),
                              sensor_uid=os.geteuid(), sensor_gid=os.getegid(),
                              trusted_state_ancestors=False)

    def test_three_links_current_success_and_same_existing_policy(self):
        rows, proof = self.scan()
        result = containment.validated_evidence(rows, PUBLIC, NOW)
        self.assertEqual(result["independent_flows"], 3)
        self.assertEqual(proof["link_count"], 3)
        self.assertFalse(proof["older_generations_scanned"])

    def test_legacy_reader_rejects_same_three_links(self):
        with self.assertRaises(containment.ContainmentError):
            containment.read_evidence(PUBLIC, NOW, self.base / "eve.json")

    def test_fourth_link_refused(self):
        os.link(self.gen, self.root / "extra")
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_missing_alias_refused(self):
        (self.base / "eve.json").unlink()
        with self.assertRaises(OSError): self.scan()

    def test_wrong_alias_inode_refused(self):
        (self.base / "eve.json").unlink(); (self.base / "eve.json").write_bytes(b"{}\n")
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_alias_symlink_refused(self):
        (self.base / "eve.json").unlink(); (self.base / "eve.json").symlink_to(self.gen)
        with self.assertRaises(OSError): self.scan()

    def test_state_symlink_refused(self):
        target = self.state.with_name("target")
        self.state.rename(target); self.state.symlink_to(target)
        with self.assertRaises(OSError): self.scan()

    def test_extra_state_link_refused(self):
        os.link(self.state, self.root / "state-extra")
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_noncanonical_state_refused(self):
        self.state.write_text(json.dumps(self.obj))
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_duplicate_state_key_refused(self):
        self.state.write_bytes(reader.canonical(self.obj).replace(b'{', b'{"phase":"active",', 1))
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_invalid_state_variants(self):
        original = copy.deepcopy(self.obj)
        for update in ({"phase": "switch_pending"}, {"boot_id": "c"*32}, {"revision": True},
                       {"schema_version": True}, {"machine_id": "d"*32}, {"extra": 1},
                       {"pending": {}}, {"engine": "modsecurity"}):
            with self.subTest(update=update):
                self.obj = {**copy.deepcopy(original), **update}; self.save()
                with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_path_traversal_generation_refused(self):
        self.obj["current"]["basename"] = "../eve.json"; self.save()
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_bool_inode_refused(self):
        self.obj["current"]["inode"] = True; self.save()
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_config_drift_refused(self):
        self.pins["vector_env_sha256"].write_bytes(b"changed")
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_writer_pin_drift_refused(self):
        self.obj["current"]["writer_config_sha256"] = "f"*64; self.save()
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_publish_fragment_refused(self):
        (self.managed / ".publish-link").symlink_to("absent")
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_generation_mode_refused(self):
        self.gen.chmod(0o666)
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_partial_trailing_line_not_evidence(self):
        with self.gen.open("ab") as f: f.write(reader.canonical(event(4)).rstrip(b"\n"))
        rows, proof = self.scan()
        self.assertEqual(len(rows), 3)
        self.assertLess(proof["complete_lines_bytes"], proof["snapshot_end"])

    def test_duplicate_json_row_not_evidence(self):
        self.gen.write_bytes(reader.canonical(event(1)).replace(b'{', b'{"flow_id":99,', 1))
        self.assertEqual(self.scan()[0], [])

    def test_fixed_prefix_change_refused(self):
        original = os.pread
        count = 0
        def changed(fd, size, offset):
            nonlocal count
            count += 1
            data = original(fd, size, offset)
            return b"x" + data[1:] if count == 2 else data
        with mock.patch.object(reader.os, "pread", side_effect=changed):
            with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_append_after_snapshot_allowed_without_new_bytes(self):
        original = os.pread
        count = 0
        def appended(fd, size, offset):
            nonlocal count
            count += 1
            if count == 2:
                with self.gen.open("ab") as out: out.write(reader.canonical(event(4)))
            return original(fd, size, offset)
        with mock.patch.object(reader.os, "pread", side_effect=appended): rows, proof = self.scan()
        self.assertEqual(len(rows), 3)
        self.assertLess(proof["snapshot_end"], self.gen.stat().st_size)

    def test_record_budget_refused(self):
        self.gen.write_bytes(b"{}\n" * (reader.MAX_ROWS + 1))
        with self.assertRaises(reader.EvidenceUnavailable): self.scan()

    def test_tail_discards_initial_fragment(self):
        with mock.patch.object(reader, "MAX_BYTES", 400): rows, proof = self.scan()
        self.assertGreater(proof["snapshot_start"], 0)
        self.assertLess(len(rows), 3)


def ar_event():
    return {"version": 1, "origin": {"name": "groot-sec", "module": "wazuh-execd"}, "command": "add",
            "parameters": {"extra_args": [], "program": ar.PROGRAM, "alert": {
                "timestamp": event(1)["timestamp"], "agent": {"id": "001"},
                "rule": {"id": "100110", "level": 9}, "location": ar.LOCATION, "data": event(1)}}}


class NativeAdapter(unittest.TestCase):
    def test_managed_root_selects_new_reader_only(self):
        with mock.patch.object(containment, "MANAGED_ROOT", Path(__file__)), \
             mock.patch.object(containment, "_managed_evidence", return_value={"synthetic": True}) as call:
            self.assertEqual(containment.read_evidence(PUBLIC, NOW), {"synthetic": True})
            call.assert_called_once_with(PUBLIC, NOW)

    def test_managed_reader_failure_never_legacy_fallback(self):
        with mock.patch.object(containment, "MANAGED_ROOT", Path(__file__)), \
             mock.patch.object(containment, "_managed_evidence", side_effect=containment.ContainmentError("denied")), \
             mock.patch.object(containment.os, "open") as opened:
            with self.assertRaises(containment.ContainmentError): containment.read_evidence(PUBLIC, NOW)
            opened.assert_not_called()

    def test_add_maps_only_incident_registration(self):
        result = ar.request(reader.canonical(ar_event()), NOW)
        self.assertEqual(set(result), {"operation", "incident"})
        self.assertEqual(result["operation"], "submit-incident")
        self.assertEqual(result["incident"]["src_ip"], PUBLIC)

    def test_wrong_envelopes(self):
        for field, value in (("command", "delete"), ("version", True), ("extra", 1)):
            obj = ar_event(); obj[field] = value
            with self.subTest(field=field), self.assertRaises(ar.Refused):
                ar.request(reader.canonical(obj), NOW)

    def test_wrong_source_selectors(self):
        changes = [("agent", {"id": "002"}), ("rule", {"id": "100111", "level": 9}),
                   ("rule", {"id": "100110", "level": 10}), ("location", "/tmp/fake"),
                   ("timestamp", "2001-01-01T00:00:00+00:00"),
                   ("timestamp", "2026-10-13T05:00:00")]
        for key, value in changes:
            obj = ar_event(); obj["parameters"]["alert"][key] = value
            with self.subTest(key=key), self.assertRaises(ar.Refused):
                ar.request(reader.canonical(obj), NOW)

    def test_no_extra_args_or_program(self):
        for key, value in (("extra_args", ["-c", "anything"]), ("program", "/bin/sh")):
            obj = ar_event(); obj["parameters"][key] = value
            with self.subTest(key=key), self.assertRaises(ar.Refused):
                ar.request(reader.canonical(obj), NOW)

    def test_protected_ips_still_register_for_investigation(self):
        for source in ("211.170.162.111", "8.8.8.8", "10.1.2.3", "127.0.0.1"):
            obj = ar_event(); obj["parameters"]["alert"]["data"]["src_ip"] = source
            with self.subTest(source=source):
                result = ar.request(reader.canonical(obj), NOW)
                self.assertEqual(result["incident"]["src_ip"], source)
                self.assertEqual(result["operation"], "submit-incident")

    def test_invalid_ipv4_refused(self):
        for source in ("::1", "93.184.216.034", "not an IP"):
            obj = ar_event(); obj["parameters"]["alert"]["data"]["src_ip"] = source
            with self.subTest(source=source), self.assertRaises(ar.Refused):
                ar.request(reader.canonical(obj), NOW)

    def test_severity_bool_and_stats_refused(self):
        obj = ar_event(); obj["parameters"]["alert"]["data"]["alert"]["severity"] = True
        with self.assertRaises(ar.Refused): ar.request(reader.canonical(obj), NOW)
        obj = ar_event(); obj["parameters"]["alert"]["data"]["event_type"] = "stats"
        with self.assertRaises(ar.Refused): ar.request(reader.canonical(obj), NOW)

    def test_native_string_severity_allowed(self):
        obj = ar_event(); obj["parameters"]["alert"]["data"]["alert"]["severity"] = "1"
        self.assertEqual(ar.request(reader.canonical(obj), NOW)["incident"]["src_ip"], PUBLIC)

    def test_native_event_id_preserved_and_duplicate_stable(self):
        obj = ar_event(); obj["parameters"]["alert"]["id"] = "1792033200.1234"
        first = ar.request(reader.canonical(obj), NOW)
        self.assertEqual(first["incident"]["event_id"], "1792033200.1234")
        self.assertEqual(first, ar.request(reader.canonical(obj), NOW + 1))

    def test_fallback_id_stable_by_fields_and_flow(self):
        obj = ar_event()
        first = ar.request(reader.canonical(obj), NOW)
        self.assertRegex(first["incident"]["event_id"], r"^sha256:[0-9a-f]{64}$")
        obj["parameters"]["alert"]["description"] = "untrusted instruction must not change identity"
        obj["parameters"]["alert"]["data"]["flow_id"] = str(obj["parameters"]["alert"]["data"]["flow_id"])
        self.assertEqual(first, ar.request(reader.canonical(obj), NOW))
        obj["parameters"]["alert"]["data"]["flow_id"] = 9999
        self.assertNotEqual(first["incident"]["event_id"], ar.request(reader.canonical(obj), NOW)["incident"]["event_id"])

    def test_invalid_ids_refused(self):
        for value in (None, True, "", "x" * 129, "id\ncommand", "${jndi:x}"):
            obj = ar_event(); obj["parameters"]["alert"]["id"] = value
            with self.subTest(value=value), self.assertRaises(ar.Refused):
                ar.request(reader.canonical(obj), NOW)
        for value in (None, True, -1, 2**64, "bad"):
            obj = ar_event(); obj["parameters"]["alert"]["data"]["flow_id"] = value
            with self.subTest(value=value), self.assertRaises(ar.Refused):
                ar.request(reader.canonical(obj), NOW)

    def test_dispatch_refuses_containment_before_starting_helper(self):
        for payload in ({"operation": "contain-ip", "ip": PUBLIC, "reason": "native alert"},
                        {"operation": "submit-incident", "incident": {}, "approved": True}):
            with self.subTest(payload=payload), mock.patch.object(ar, "helper_metadata") as metadata, \
                    mock.patch.object(ar.subprocess, "Popen") as process, self.assertRaises(ar.Refused):
                ar.dispatch(payload)
            metadata.assert_not_called()
            process.assert_not_called()

    def test_malformed_bounded_input(self):
        good = reader.canonical(ar_event())
        for raw in (b"", b"{}", good + good, b"x"*(ar.MAX_INPUT+1),
                    good.replace(b'{', b'{"version":1,', 1), b"{\0}\n", b"[]\n"):
            with self.subTest(size=len(raw)), self.assertRaises(ar.Refused): ar.request(raw, NOW)


if __name__ == "__main__":
    unittest.main()
