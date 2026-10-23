"""Terminal routing boundaries; no Docker, subprocesses or network connections."""
import copy
import json
import socket
import stat
import struct
import unittest
from types import SimpleNamespace
from unittest import mock

import broker as B
import manifest as M

REDIS = "CVE-2022-0543"
SAMBA = "CVE-2017-7494"
SUDO = "CVE-2021-3156"
UNKNOWN = "CVE-2022-9999"
CID = "a" * 64


def response(cve=REDIS, status="running"):
    return {"ok": True, "schema": 1, "lab": M.TERMINAL_LABS[cve], "cve_id": cve,
            "status": status, "verification": "environment_only", "image_present": True,
            "container_id": None if status == "not_deployed" else CID}


class TerminalResponse(unittest.TestCase):
    def test_public_result_contains_only_short_id_and_fixed_same_origin_url(self):
        for cve in (REDIS, SAMBA, SUDO):
            with self.subTest(cve=cve):
                result = B.terminal_result(response(cve), cve)
                self.assertEqual(result["container_id"], CID[:12])
                self.assertEqual(result["url"], "/log4shell/terminal/" + cve + "/")
                self.assertTrue(result["deployment_allowed"])
                self.assertFalse(result["attack_tested"])
                self.assertFalse(result["host_scenario_verified"])
                self.assertNotIn("lab", result)
                self.assertNotIn("socket", result)
                self.assertNotIn("exec_user", result)

    def test_absent_image_or_runtime_error_blocks_start_and_terminal_open(self):
        for change in ({"image_present": False}, {"status": "error"}):
            self.assertFalse(B.terminal_result(dict(response(), **change), REDIS)["deployment_allowed"])
        self.assertEqual(B.terminal_result(response(status="not_deployed"), REDIS)["status"], "not_deployed")

    def test_wrong_target_shape_and_extra_fields_are_rejected(self):
        for change in ({"lab": "samba"}, {"cve_id": SAMBA}, {"schema": True}, {"schema": 2},
                       {"ok": 1}, {"image_present": "true"}, {"verification": "attack_confirmed"},
                       {"status": []}, {"status": "ready"}, {"container_id": "a" * 12},
                       {"container_id": None}, {"url": "https://untrusted.invalid"}, {"command": "sh"}):
            with self.subTest(change=change), self.assertRaises(B.BrokerError):
                B.terminal_result(dict(response(), **change), REDIS)
        with self.assertRaises(B.BrokerError):
            B.terminal_result(response(), UNKNOWN)
        with self.assertRaises(B.BrokerError):
            B.terminal_result(dict(response(status="not_deployed"), container_id=CID), REDIS)

    def test_remote_error_is_never_reflected(self):
        for code in ("private diagnostic", {"secret": "value"}, None):
            with self.assertRaises(B.BrokerError) as caught:
                B.terminal_result({"ok": False, "error": code}, REDIS)
            self.assertEqual(caught.exception.code, "terminal_operation_failed")
        with self.assertRaises(B.BrokerError) as caught:
            B.terminal_result({"ok": False, "error": "operation_in_progress"}, REDIS)
        self.assertEqual(caught.exception.code, "operation_in_progress")


class TerminalRPC(unittest.TestCase):
    def setUp(self):
        self.connection = mock.MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.connection.getsockopt.return_value = struct.pack("3i", 42, 0, 0)
        self.connection.recv.return_value = json.dumps(response()).encode() + b"\n"
        for patcher in (mock.patch.object(B, "trusted_path"),
                        mock.patch.object(B.Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_uid=0)),
                        mock.patch.object(B.socket, "socket", return_value=self.connection),
                        mock.patch.object(B.socket, "SO_PEERCRED", 17, create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_fixed_socket_payload_and_action_deadlines(self):
        for cve in (REDIS, SAMBA, SUDO):
            for action, timeout in (("status", 65), ("deploy", 225), ("stop", 65)):
                self.connection.reset_mock()
                self.connection.recv.return_value = json.dumps(response(cve)).encode() + b"\n"
                B.terminal_request(action, cve)
                self.connection.connect.assert_called_once_with("/run/capstone-nonweb-labs/control.sock")
                self.connection.settimeout.assert_called_once_with(timeout)
                payload = json.loads(self.connection.sendall.call_args.args[0])
                self.assertEqual(payload, {"action": action, "lab": M.TERMINAL_LABS[cve]})

    def test_unknown_action_or_target_never_connects(self):
        for action, cve in (("exec", REDIS), ("status", UNKNOWN), ("deploy", "redis")):
            with self.assertRaises(B.BrokerError):
                B.terminal_request(action, cve)
        self.connection.connect.assert_not_called()

    def test_root_peer_and_safe_socket_are_required_before_sending(self):
        self.connection.getsockopt.return_value = struct.pack("3i", 42, 1000, 1000)
        with self.assertRaises(B.BrokerError):
            B.terminal_request("status", REDIS)
        self.connection.sendall.assert_not_called()
        for mode, uid in ((stat.S_IFREG | 0o600, 0), (stat.S_IFSOCK | 0o666, 0),
                          (stat.S_IFSOCK | 0o660, 1000), (stat.S_IFLNK | 0o600, 0)):
            with mock.patch.object(B.Path, "lstat", return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                with self.assertRaises(B.BrokerError):
                    B.terminal_request("status", REDIS)

    def test_frame_is_bounded_single_json_and_duplicate_key_free(self):
        good = json.dumps(response()).encode()
        for data in (b"", b"x" * (B.TERMINAL_MAX_BYTES + 1), good + b"\n{}\n",
                     good + b"\ntrailing", b'{"ok":true,"ok":false}\n', b"\xff\n"):
            self.connection.recv.return_value = data
            with self.subTest(data=data[:40]), self.assertRaises(B.BrokerError):
                B.terminal_request("status", REDIS)


class TerminalDispatch(unittest.TestCase):
    def setUp(self):
        self.labs = M.validate_manifest([
            {"type": "managed-terminal", "cve_id": cve, "software": lab, "vulnerable_version": "fixture"}
            for cve, lab in M.TERMINAL_LABS.items()])
        self.docker, self.receipts, self.guard, self.sudo_reader = (mock.Mock() for _ in range(4))
        self.rpc = mock.Mock(side_effect=lambda action, cve: B.terminal_result(response(cve), cve))
        self.broker = B.Broker(self.labs, self.docker, self.receipts, self.guard, self.sudo_reader, self.rpc)

    def test_deploy_stop_only_reach_fixed_terminal_service(self):
        for cve in (REDIS, SAMBA, SUDO):
            for action in ("deploy", "stop"):
                self.assertTrue(self.broker.handle({"action": action, "cve_id": cve})["ok"])
                self.rpc.assert_called_with(action, cve)
        self.assertEqual(self.docker.mock_calls, [])
        self.assertEqual(self.receipts.mock_calls, [])
        self.guard.assert_not_called()
        self.sudo_reader.assert_not_called()

    def test_http_guard_failure_does_not_hide_independent_terminal_status(self):
        self.broker.safety = mock.Mock(side_effect=B.BrokerError("egress_guard_unverified"))
        result = self.broker.handle({"action": "status"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["deployment_allowed"])
        self.assertTrue(result["labs"][REDIS]["deployment_allowed"])
        self.assertEqual(result["labs"][SAMBA]["status"], "running")
        self.assertEqual(result["labs"][SUDO]["status"], "running")
        self.assertEqual(self.docker.mock_calls, [])
        self.assertEqual(self.receipts.mock_calls, [])
        self.sudo_reader.assert_not_called()

    def test_one_runtime_failure_preserves_other_lab_and_disables_failed_lab(self):
        self.broker.safety = mock.Mock()
        def rpc(action, cve):
            if cve == REDIS:
                raise B.BrokerError("terminal_unavailable")
            return B.terminal_result(response(cve), cve)
        self.rpc.side_effect = rpc
        result = self.broker.handle({"action": "status"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["labs"][REDIS]["status"], "error")
        self.assertFalse(result["labs"][REDIS]["deployment_allowed"])
        self.assertEqual(result["labs"][SAMBA]["status"], "running")
        self.assertEqual(result["labs"][SUDO]["status"], "running")

    def test_sudo_status_is_independent_of_legacy_ready_receipt(self):
        self.broker.safety = mock.Mock()
        self.sudo_reader.side_effect = AssertionError("legacy CLI receipt is not web runtime status")
        self.rpc.side_effect = lambda action, cve: B.terminal_result(response(cve, "stopped"), cve)
        result = self.broker.handle({"action": "status", "cve_id": SUDO})
        self.assertTrue(result["ok"])
        self.assertEqual(result["labs"][SUDO]["status"], "stopped")
        self.assertTrue(result["labs"][SUDO]["image_present"])
        self.rpc.assert_called_once_with("status", SUDO)
        self.assertEqual(self.docker.mock_calls, [])
        self.assertEqual(self.receipts.mock_calls, [])
        self.sudo_reader.assert_not_called()

    def test_user_cannot_select_shell_command_image_or_foreign_lab(self):
        for request in ({"action": "exec", "cve_id": REDIS},
                        {"action": "deploy", "cve_id": REDIS, "command": "sh"},
                        {"action": "deploy", "cve_id": UNKNOWN},
                        {"action": "deploy", "cve_id": REDIS, "image_id": "sha256:" + "a" * 64},
                        {"action": "deploy", "cve_id": SUDO, "uid": 0},
                        {"action": "stop", "cve_id": SUDO, "container_id": CID},
                        {"action": "deploy", "cve_id": SUDO, "socket": "/var/run/docker.sock"}):
            self.assertFalse(self.broker.handle(request)["ok"])
        self.rpc.assert_not_called()


if __name__ == "__main__":
    unittest.main()
