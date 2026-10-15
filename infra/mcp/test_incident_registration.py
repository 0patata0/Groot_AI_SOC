#!/usr/bin/env python3
"""AR registration boundaries: no real helper, broker, engine, nft or messages."""
from datetime import datetime, timezone
import copy
import hashlib
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest import mock

import rule_change_executor as executor
import rule_change_mcp as mcp
import wazuh_containment_ar as ar

NOW = datetime(2026, 10, 15, 5, 0, tzinfo=timezone.utc).timestamp()


def incident():
    return {"event_id": "1792033200.1234", "timestamp": "2026-10-15T14:00:00+09:00",
            "agent_id": "001", "rule_id": "100110", "level": 9,
            "src_ip": "10.200.10.20", "location": executor.INCIDENT_LOCATION}


class QueueBroker:
    def __init__(self):
        self.rows, self.calls = {}, []

    def request(self, method, path, body):
        if (method, path) != ("POST", "/management/incidents"):
            raise AssertionError("registration attempted another broker operation")
        self.calls.append(copy.deepcopy(body))
        identity = {k: body[k] for k in ("event_id", "agent_id", "rule_id", "location")}
        key = "incident:" + hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if key in self.rows and self.rows[key][0] != body:
            raise executor.RuleChangeError("identity conflict")
        self.rows.setdefault(key, (copy.deepcopy(body), len(self.rows) + 1))
        return {"queued": True, "event_key": key, "seq": self.rows[key][1]}


class IncidentRegistration(unittest.TestCase):
    def setUp(self):
        self.broker = QueueBroker()
        self.stack = __import__("contextlib").ExitStack()
        self.stack.enter_context(mock.patch.object(executor.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(mock.patch.object(executor.time, "time", return_value=NOW))
        self.addCleanup(self.stack.close)

    def submit(self, value=None, host="a"):
        return executor._submit_incident(host, self.broker, incident() if value is None else value)

    def dispatch(self, payload, sudo_user=None):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        stdout = io.StringIO()
        with mock.patch.object(executor, "_secure_config", return_value=("a", self.broker)), \
                mock.patch.object(executor, "Engine", side_effect=AssertionError("registration instantiated rule engine")), \
                mock.patch.object(executor, "_load_extension", side_effect=AssertionError("registration loaded operation executor")), \
                mock.patch.object(executor.subprocess, "run", side_effect=AssertionError("registration ran command")), \
                mock.patch.object(executor.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw))), \
                mock.patch.object(executor.sys, "stdout", stdout):
            if sudo_user is not None:
                os.environ["SUDO_USER"] = sudo_user
            executor.main([])
        return json.loads(stdout.getvalue())

    def test_helper_dispatch_only_registers_and_duplicate_has_same_receipt(self):
        row = incident()
        native = {"version": 1, "origin": {"name": "groot-sec", "module": "wazuh-execd"},
                  "command": "add", "parameters": {"extra_args": [], "program": ar.PROGRAM,
                  "alert": {"id": row["event_id"], "timestamp": row["timestamp"],
                            "agent": {"id": "001"}, "rule": {"id": "100110", "level": 9},
                            "location": ar.LOCATION, "data": {"event_type": "alert",
                            "src_ip": row["src_ip"], "alert": {"severity": 1}, "flow_id": 1234}}}}
        payload = ar.request(json.dumps(native).encode() + b"\n", NOW)
        first = self.dispatch(payload)
        self.assertEqual(first, self.dispatch(payload))
        self.assertTrue(first["queued"])
        self.assertEqual(len(self.broker.rows), 1)
        self.assertEqual(self.broker.calls, [incident(), incident()])

    def test_protected_and_private_addresses_are_evidence(self):
        for ip in ("211.170.162.111", "10.200.10.1", "192.168.16.230", "127.0.0.1", "8.8.8.8"):
            self.broker = QueueBroker()
            with self.subTest(ip=ip):
                self.assertTrue(self.submit(dict(incident(), src_ip=ip))["queued"])

    def test_direct_root_only_never_mcp_sudo_identity(self):
        for user in ("rulechg", "hermes", "root", ""):
            with self.subTest(user=user), mock.patch.dict(os.environ, {"SUDO_USER": user}), \
                    self.assertRaisesRegex(executor.RuleChangeError, "direct root"):
                self.submit()
        with self.assertRaises(executor.RuleChangeError):
            self.submit(host="b")
        self.assertEqual(self.broker.calls, [])

    def test_unprivileged_direct_call_refused(self):
        with mock.patch.object(executor.os, "geteuid", return_value=999), self.assertRaises(executor.RuleChangeError):
            self.submit()
        self.assertEqual(self.broker.calls, [])

    def test_exact_fields_and_source_binding(self):
        samples = [dict(incident(), approved=True), dict(incident(), requested_by="hermes"),
                   dict(incident(), agent_id="002"), dict(incident(), rule_id="100111"),
                   dict(incident(), level=True), dict(incident(), level=10),
                   dict(incident(), location="/tmp/alert"), dict(incident(), event_id="x\ncommand"),
                   dict(incident(), src_ip="::1"), dict(incident(), src_ip="10.00.0.1")]
        missing = incident(); del missing["event_id"]; samples.append(missing)
        for sample in samples:
            with self.subTest(sample=sample), self.assertRaises(executor.RuleChangeError):
                self.submit(sample)
        self.assertEqual(self.broker.calls, [])

    def test_time_window_and_naive_timestamps_refused(self):
        for offset in (-301, 3):
            sample = dict(incident(), timestamp=datetime.fromtimestamp(NOW + offset, timezone.utc).isoformat())
            with self.subTest(offset=offset), self.assertRaises(executor.RuleChangeError):
                self.submit(sample)
        for value in ("2026-10-15T05:00:00", "not a timestamp", None, 123):
            with self.subTest(value=value), self.assertRaises(executor.RuleChangeError):
                self.submit(dict(incident(), timestamp=value))
        self.assertEqual(self.broker.calls, [])

    def test_unsupported_envelope_and_duplicate_fields_refused_without_engine(self):
        for value in ({"operation": "submit-incident", "incident": incident(), "ip": "1.1.1.1"},
                      b'{"operation":"submit-incident","operation":"contain-ip","incident":{}}',
                      b'{"operation":"submit-incident","incident":{"level":9,"level":10}}'):
            with self.subTest(value=value), self.assertRaises(executor.RuleChangeError):
                self.dispatch(value)
        self.assertEqual(self.broker.calls, [])

    def test_queue_outage_and_invalid_receipt_fail_closed(self):
        for value in ({"queued": False, "event_key": "incident:" + "0"*64, "seq": 1},
                      {"queued": True, "event_key": "wrong", "seq": 1},
                      {"queued": True, "event_key": "wrong", "seq": True}):
            with mock.patch.object(self.broker, "request", return_value=value), self.assertRaises(executor.RuleChangeError):
                self.submit()
        with mock.patch.object(self.broker, "request", side_effect=executor.RuleChangeError("unavailable")), \
                self.assertRaises(executor.RuleChangeError):
            self.submit()

    def test_registration_not_exposed_by_mcp(self):
        self.assertNotIn("submit-incident", {tool["name"] for tool in mcp.TOOLS})
        with mock.patch.object(mcp, "_call_helper") as helper:
            result = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": "submit-incident", "arguments": {"incident": incident()}}})
            self.assertEqual(result["error"]["code"], -32602)
            helper.assert_not_called()

    def test_old_native_direct_containment_refused_but_mcp_attributed(self):
        payload = {"operation": "contain-ip", "ip": "93.184.216.34", "reason": "LLM evidence judgment"}
        extension = mock.Mock()
        extension.ContainmentService.return_value.propose.return_value = {"request_id": "a" * 32}
        for sudo_user, allowed in ((None, False), ("rulechg", True)):
            raw = io.BytesIO(json.dumps(payload).encode())
            with self.subTest(sudo_user=sudo_user), mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(executor, "_secure_config", return_value=("a", self.broker)), \
                    mock.patch.object(executor, "Engine", return_value=SimpleNamespace(host="a")), \
                    mock.patch.object(executor, "_load_extension", return_value=extension) as load, \
                    mock.patch.object(executor.sys, "stdin", SimpleNamespace(buffer=raw)), \
                    mock.patch.object(executor.sys, "stdout", io.StringIO()):
                if sudo_user:
                    os.environ["SUDO_USER"] = sudo_user
                if allowed:
                    executor.main([])
                    extension.ContainmentService.return_value.propose.assert_called_once_with(
                        payload["ip"], payload["reason"], requested_by="hermes-mcp")
                else:
                    with self.assertRaisesRegex(executor.RuleChangeError, "restricted MCP"):
                        executor.main([])
                    load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
