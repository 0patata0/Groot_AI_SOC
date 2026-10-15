#!/usr/bin/env python3
"""Synthetic-only containment tests: no SSH, network, nft, service or message I/O."""
import contextlib
import copy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import incident_containment as c
from operations_approval import OperationsBroker


NOW = 1791867600
PUBLIC = "93.184.216.34"


def event(fid, **updates):
    e = {"event_type": "alert", "timestamp": datetime.fromtimestamp(NOW - 20, timezone.utc).isoformat(),
         "flow_id": fid, "src_ip": PUBLIC, "dest_ip": "192.168.16.230", "dest_port": 8080,
         "proto": "TCP", "app_proto": "http", "in_iface": "ens192", "direction": "to_server",
         "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "src_ip": PUBLIC, "dest_ip": "192.168.16.230"},
         "alert": {"signature_id": 1000030, "severity": 1, "category": "Attempted Administrator Privilege Gain"}}
    e.update(updates)
    return e


class FakeBackend:
    def __init__(self, engine):
        self.engine = engine
        self.entries = {}
        self.creates = 0
        self.retains = 0
        self.releases = 0
        self.protected = set()

    @contextlib.contextmanager
    def locked(self):
        yield

    def check_protected(self, ip):
        c.checked_ip(ip)
        if ip in self.protected:
            raise c.ContainmentError("live protected")

    def snapshot(self, ip):
        e = self.entries.get(ip)
        if e and e.get("deadline", NOW + 99999) <= self.engine.now:
            del self.entries[ip]
        e = self.entries.get(ip)
        return {"ip": ip, "set_handle": 7, "element": copy.deepcopy(e)}

    def create(self, record):
        self.check_protected(record["ip"])
        if self.snapshot(record["ip"])["element"]:
            raise c.ContainmentError("occupied")
        self.entries[record["ip"]] = {"val": record["ip"], "comment": c.NftBackend.tag(record), "deadline": record["owned_deadline"]}
        self.creates += 1
        return self.snapshot(record["ip"])

    def release(self, record):
        e = self.snapshot(record["ip"])["element"]
        if e and e["comment"] != c.NftBackend.tag(record):
            raise c.ContainmentError("not owned")
        self.entries.pop(record["ip"], None)
        self.releases += 1
        return self.snapshot(record["ip"])

    def retain(self, record, deadline):
        self.check_protected(record["ip"])
        e = self.snapshot(record["ip"])["element"]
        if e and e["comment"] == c.NftBackend.tag(record, deadline):
            return self.snapshot(record["ip"])
        if not e or e["comment"] != c.NftBackend.tag(record):
            raise c.ContainmentError("not owned")
        if deadline <= self.engine.now:
            raise c.ContainmentError("expired")
        self.entries[record["ip"]] = {"val": record["ip"], "comment": c.NftBackend.tag(record, deadline), "deadline": deadline}
        self.retains += 1
        return self.snapshot(record["ip"])


class FakeBroker:
    def __init__(self, engine):
        self.engine = engine
        self.cards = []
        self.unavailable = False
        self.post_success = True
        self.actual = OperationsBroker(post=self.post, enabled=lambda: True,
            source_ok=lambda peer: peer == "172.19.0.2", approvers=lambda: {"admin"},
            action_url=lambda: "http://172.19.0.1:8090")

    def post(self, card):
        self.cards.append(card)
        return self.post_success, "synthetic"

    def health(self):
        if self.unavailable:
            raise c.ContainmentError("offline")
        return True

    def request(self, method, path, body=None):
        self.health()
        with mock.patch("operations_approval.time.time", return_value=self.engine.now):
            if path == "/operations":
                reply, code = self.actual.create(body)
            else:
                rid = path.split("/")[2]
                if method == "GET":
                    reply, code = self.actual.get(rid)
                elif path.endswith("/consume"):
                    reply, code = self.actual.consume(rid, body)
                elif path.endswith("/result"):
                    reply, code = self.actual.result(rid, body)
                else:
                    raise AssertionError(path)
        if code != 200:
            raise c.ContainmentError("broker rejection: %s" % reply.get("error"))
        return reply

    def decide(self, rid, decision):
        rec = self.actual.records[rid]
        body = {"user_id": "admin", "context": {"operation_id": rid, "kind": "containment",
            "nonce": rec["nonce"], "proposal_digest": rec["proposal_digest"], "decision": decision}}
        with mock.patch("operations_approval.time.time", return_value=self.engine.now):
            return self.actual.action(body, "172.19.0.2")


class Engine:
    host = "a"
    def __init__(self, path):
        self.state_dir = Path(path)
        self.now = NOW
        self.broker = FakeBroker(self)
    def clock(self):
        return self.now
    @contextlib.contextmanager
    def locked(self):
        yield


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = Engine(self.tmp.name)
        self.backend = FakeBackend(self.engine)
        self.service = c.ContainmentService(self.engine, self.backend,
            lambda ip, now: c.validated_evidence([event(i, src_ip=ip) for i in (1, 2, 3)], ip, now))
    def tearDown(self):
        self.tmp.cleanup()
    def propose(self):
        return self.service.propose(PUBLIC, "repeated inbound exploit alerts")
    def test_independent_flow_required(self):
        with self.assertRaises(c.ContainmentError):
            c.validated_evidence([event(1), event(1), event(1)], PUBLIC, NOW)
    def test_evidence_checks_fail_closed(self):
        changes = [{"src_ip": "192.168.16.230"}, {"dest_ip": "8.8.8.8"}, {"in_iface": "ens160"},
            {"proto": "UDP"}, {"direction": "to_client"}, {"app_proto": "unknown"}, {"flow": {}},
            {"timestamp": "2026-10-13T00:00:00"}, {"timestamp": "2020-01-01T00:00:00+00:00"},
            {"alert": {"signature_id": 2034806, "severity": 1, "category": "Attempted Administrator Privilege Gain"}},
            {"alert": {"signature_id": 1000030, "severity": 2, "category": "Attempted Administrator Privilege Gain"}}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(c.ContainmentError):
                c.validated_evidence([event(i, **change) for i in (1, 2, 3)], PUBLIC, NOW)
    def test_protected_and_nonpublic_rejected(self):
        for ip in ["10.1.2.3", "192.168.16.4", "172.20.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "100.64.1.1", "211.170.162.110", "211.170.162.111", "8.8.8.8", "::1", "93.184.216.034", "1.2.3.4;flush ruleset"]:
            with self.subTest(ip=ip), self.assertRaises(c.ContainmentError):
                self.service.propose(ip, "test")
        self.assertEqual(self.backend.creates, 0)
    def test_actual_broker_contract_and_evidence_binding(self):
        r = self.propose()
        self.assertEqual(r["status"], "pending")
        rec = self.service._load(r["request_id"])
        self.assertEqual(rec["payload"]["plan"]["evidence_sha256"], c.digest(rec["evidence"]))
        self.assertEqual(self.engine.broker.actual.records[r["request_id"]]["proposal_digest"], rec["proposal_digest"])
    def test_duplicate_never_extends_ttl(self):
        first = self.propose()
        self.engine.now += 120
        again = self.propose()
        self.assertTrue(again["duplicate"])
        self.assertEqual(first["owned_deadline"], again["owned_deadline"])
        self.assertEqual(self.backend.creates, 1)
        self.assertEqual(len(self.engine.broker.cards), 1)
    def test_manual_block_preserved(self):
        self.backend.entries[PUBLIC] = {"val": PUBLIC, "comment": "operator", "deadline": NOW + 10000}
        with self.assertRaises(c.ContainmentError): self.propose()
        self.assertEqual(self.backend.entries[PUBLIC]["comment"], "operator")
        self.assertEqual(self.backend.releases, 0)
    def test_live_protection_before_mutation(self):
        self.backend.protected.add(PUBLIC)
        with self.assertRaises(c.ContainmentError): self.propose()
        self.assertEqual(self.backend.creates, 0)
    def test_health_failure_prevents_mutation(self):
        self.engine.broker.unavailable = True
        with self.assertRaises(c.ContainmentError): self.propose()
        self.assertEqual(self.backend.creates, 0)
    def test_post_failure_releases(self):
        self.engine.broker.post_success = False
        with self.assertRaises(c.ContainmentError): self.propose()
        self.assertNotIn(PUBLIC, self.backend.entries)
        self.assertEqual(self.backend.creates, 1)
        self.assertEqual(self.backend.releases, 1)
    def test_wrong_digest_releases(self):
        request = self.engine.broker.request
        def corrupt(method, path, body=None):
            r = request(method, path, body)
            if path == "/operations": r["proposal_digest"] = "0" * 64
            return r
        self.engine.broker.request = corrupt
        with self.assertRaises(c.ContainmentError): self.propose()
        self.assertNotIn(PUBLIC, self.backend.entries)
    def test_release_decision_consumed_once(self):
        r = self.propose()
        self.engine.broker.decide(r["request_id"], "release")
        self.service.worker_once()
        s = self.service.status(r["request_id"])
        self.assertEqual(s["status"], "released")
        self.assertTrue(s["result_posted"])
        self.assertNotIn(PUBLIC, self.backend.entries)
        self.service.worker_once()
        self.assertEqual(self.backend.releases, 1)
    def test_keep_exact_approval_time_then_no_refresh(self):
        r = self.propose()
        self.engine.now += 45
        self.engine.broker.decide(r["request_id"], "keep")
        self.engine.now += 20
        self.service.worker_once()
        self.assertEqual(self.service.status(r["request_id"])["owned_deadline"], NOW + 45 + 3600)
        self.engine.now += 300
        self.service.worker_once()
        self.assertEqual(self.backend.retains, 1)
        self.assertEqual(self.backend.entries[PUBLIC]["deadline"], NOW + 45 + 3600)
    def test_expiry_releases_even_broker_offline(self):
        r = self.propose()
        self.engine.now += 601
        self.engine.broker.unavailable = True
        self.service.worker_once()
        self.assertEqual(self.service.status(r["request_id"])["status"], "expired")
        self.assertNotIn(PUBLIC, self.backend.entries)
    def test_expiry_broker_recovery_retries_only_acknowledgement(self):
        r = self.propose()
        self.engine.now += 601
        self.engine.broker.unavailable = True
        self.service.worker_once()
        releases = self.backend.releases
        self.assertFalse(self.service.status(r["request_id"])["result_posted"])
        self.engine.broker.unavailable = False
        self.service.worker_once()
        self.assertTrue(self.service.status(r["request_id"])["result_posted"])
        self.assertEqual(self.backend.releases, releases)
        self.assertEqual(self.backend.retains, 0)
    def test_expiry_consume_response_loss_reconciles_without_firewall_write(self):
        r = self.propose()
        self.engine.now += 601
        request = self.engine.broker.request
        first = [True]
        def lose(method, path, body=None):
            result = request(method, path, body)
            if path.endswith("/consume") and first[0]:
                first[0] = False
                raise c.ContainmentError("lost response")
            return result
        self.engine.broker.request = lose
        self.service.worker_once()
        releases = self.backend.releases
        self.service.worker_once()
        self.assertTrue(self.service.status(r["request_id"])["result_posted"])
        self.assertEqual(self.backend.releases, releases)
    def test_expiry_posts_actual_broker_result(self):
        r = self.propose()
        self.engine.now += 600
        self.service.worker_once()
        self.assertTrue(self.service.status(r["request_id"])["result_posted"])
    def test_manual_replacement_not_deleted(self):
        r = self.propose()
        self.backend.entries[PUBLIC] = {"val": PUBLIC, "comment": "operator", "deadline": NOW + 10000}
        self.engine.broker.decide(r["request_id"], "release")
        self.service.worker_once()
        self.assertEqual(self.service.status(r["request_id"])["status"], "ownership_lost")
        self.assertEqual(self.backend.entries[PUBLIC]["comment"], "operator")
    def test_cooldown_after_release(self):
        r = self.propose()
        self.engine.broker.decide(r["request_id"], "release")
        self.service.worker_once()
        self.engine.now += 60
        with self.assertRaises(c.ContainmentError): self.propose()
    def test_interrupted_create_releases_without_new_card(self):
        r = self.propose()
        rec = self.service._load(r["request_id"])
        rec["status"] = "awaiting_card"
        self.service._save(rec)
        self.service.worker_once()
        self.assertNotIn(PUBLIC, self.backend.entries)
        self.assertEqual(len(self.engine.broker.cards), 1)
    def test_consumption_lost_does_not_extend(self):
        r = self.propose()
        self.engine.broker.decide(r["request_id"], "keep")
        rec = self.service._load(r["request_id"])
        self.engine.broker.request("POST", "/operations/%s/consume" % r["request_id"], {"proposal_digest": rec["proposal_digest"]})
        self.service.worker_once()
        self.assertEqual(self.backend.retains, 0)
        self.assertNotIn(PUBLIC, self.backend.entries)
    def test_retention_recovery_recognizes_applied_deadline(self):
        r = self.propose()
        rec = self.service._load(r["request_id"])
        rec.update(status="keeping", keep_deadline=NOW + 3600, consumed=True)
        self.backend.retain(rec, rec["keep_deadline"])
        self.service._save(rec)
        self.engine.now += 30
        self.service.worker_once()
        self.assertEqual(self.backend.retains, 1)
        self.assertEqual(self.service.status(r["request_id"])["owned_deadline"], NOW + 3600)
    def test_kept_deadline_updates_local_status_without_extension(self):
        r = self.propose()
        self.engine.broker.decide(r["request_id"], "keep")
        self.service.worker_once()
        self.engine.now += 3601
        self.service.worker_once()
        self.assertEqual(self.service.status(r["request_id"])["status"], "expired")
        self.assertNotIn(PUBLIC, self.backend.entries)
        self.assertEqual(self.backend.retains, 1)
    def test_no_cross_host_operation(self):
        self.engine.host = "b"
        with self.assertRaises(c.ContainmentError): self.propose()
        self.assertEqual(self.service.worker_once(), [])
    def test_no_reason_control_characters(self):
        for reason in ["", "x\ny", "a" * 1001]:
            with self.assertRaises(c.ContainmentError): self.service.propose(PUBLIC, reason)
    def test_status_reads_live_owned_entry_without_mutation(self):
        r = self.propose()
        before = (self.backend.creates, self.backend.retains, self.backend.releases)
        state = self.service.status(r["request_id"])
        self.assertEqual(state["live_block_state"], "owned")
        self.assertEqual(state["live_owned_deadline"], NOW + 600)
        self.assertEqual(state["status_source"], "persistent_workflow")
        self.assertEqual(before, (self.backend.creates, self.backend.retains, self.backend.releases))
    def test_status_distinguishes_kept_record_from_absent_live_entry(self):
        r = self.propose()
        self.engine.broker.decide(r["request_id"], "keep")
        self.service.worker_once()
        self.backend.entries.pop(PUBLIC)
        state = self.service.status(r["request_id"])
        self.assertEqual(state["status"], "kept")
        self.assertEqual(state["live_block_state"], "absent")
        self.assertIsNone(state["live_owned_deadline"])
    def test_status_foreign_manual_replacement_not_owned(self):
        r = self.propose()
        self.backend.entries[PUBLIC] = {"val": PUBLIC, "comment": "operator", "deadline": NOW + 10000}
        state = self.service.status(r["request_id"])
        self.assertEqual(state["live_block_state"], "foreign")
        self.assertIsNone(state["live_owned_deadline"])
        self.assertEqual(self.backend.releases, 0)
    def test_status_unavailable_does_not_claim_blocking(self):
        r = self.propose()
        with mock.patch.object(self.backend, "snapshot", side_effect=c.ContainmentError("nft unavailable")):
            state = self.service.status(r["request_id"])
        self.assertEqual(state["live_block_state"], "unavailable")
        self.assertIsNone(state["live_observation_sha256"])
    def test_secure_state_file_symlink_refused(self):
        r = self.propose()
        path = self.service._path(r["request_id"])
        target = path.with_suffix(".old")
        path.rename(target); path.symlink_to(target)
        with self.assertRaises(OSError): self.service.status(r["request_id"])
    def test_ipv4_network_expression_validation(self):
        ip = c.ipaddress.IPv4Address(PUBLIC)
        self.assertTrue(c._contains({"prefix": {"addr": "93.184.216.0", "len": 24}}, ip))
        self.assertTrue(c._contains({"range": ["93.184.216.30", "93.184.216.40"]}, ip))
        with self.assertRaises(c.ContainmentError): c._contains({"unknown": "anything"}, ip)


class NativeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.record = {"request_id": "a" * 32, "ip": PUBLIC, "owned_deadline": NOW + 600}
        self.engine = mock.Mock()
        self.engine.clock.return_value = NOW
        self.backend = c.NftBackend(self.engine)
        self.backend.check_protected = mock.Mock()
    def encoded(self, element):
        return json.dumps({"nftables": [{"set": {"name": "agent_block", "family": "inet", "table": "capstone_fw", "type": "ipv4_addr", "flags": ["timeout"], "handle": 7, "elem": [] if element is None else [{"elem": element}]}}]}).encode()
    def element(self, deadline=None):
        return {"val": PUBLIC, "comment": self.backend.tag(self.record, deadline), "expires": 599}
    def test_create_is_exclusive_and_fixed_set(self):
        self.engine.runner.call.side_effect = [self.encoded(None), b"", self.encoded(self.element()), b""]
        self.backend.create(self.record)
        calls = [x.args[0] for x in self.engine.runner.call.call_args_list]
        mutations = [x for x in calls if x[0] == c.NFT and x[1] != "-j"]
        self.assertEqual(mutations, [[c.NFT, 'create element inet capstone_fw agent_block { %s timeout 600s comment "contain:%s:%d" }' % (PUBLIC, "a" * 32, NOW + 600)]])
    def test_existing_entry_cannot_be_replaced_on_create(self):
        self.engine.runner.call.return_value = self.encoded({"val": PUBLIC, "comment": "manual"})
        with self.assertRaises(c.ContainmentError): self.backend.create(self.record)
        self.assertEqual(self.engine.runner.call.call_count, 1)
    def test_nat_reload_lost_comment_never_deleted(self):
        self.engine.runner.call.return_value = self.encoded({"val": PUBLIC, "expires": 500})
        with self.assertRaises(c.ContainmentError): self.backend.release(self.record)
        self.assertEqual(self.engine.runner.call.call_count, 1)
    def test_retention_is_single_atomic_fixed_set_transaction(self):
        deadline = NOW + 3550
        self.engine.runner.call.side_effect = [self.encoded(self.element()), b"", self.encoded(self.element(deadline)), b""]
        self.backend.retain(self.record, deadline)
        calls = [x.args[0] for x in self.engine.runner.call.call_args_list]
        mutations = [x for x in calls if x[0] == c.NFT and x[1] != "-j"]
        self.assertEqual(len(mutations), 1)
        command = mutations[0][1]
        self.assertTrue(command.startswith("delete element inet capstone_fw agent_block { %s }; create element inet capstone_fw agent_block" % PUBLIC))
        self.assertIn("timeout 3550s", command)
        self.assertIn('comment "contain:%s:%d"' % ("a" * 32, deadline), command)
    def test_retention_replay_uses_absolute_owned_tag_without_mutation(self):
        deadline = NOW + 3550
        self.engine.runner.call.return_value = self.encoded(self.element(deadline))
        self.backend.retain(self.record, deadline)
        self.assertEqual(self.engine.runner.call.call_count, 1)
    def test_absent_after_reboot_never_recreated_by_retention(self):
        self.engine.runner.call.return_value = self.encoded(None)
        with self.assertRaises(c.ContainmentError): self.backend.retain(self.record, NOW + 3600)
        self.assertEqual(self.engine.runner.call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
