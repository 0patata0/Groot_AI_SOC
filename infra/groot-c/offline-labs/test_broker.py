#!/usr/bin/env python3
"""Offline broker regression tests; no Docker daemon, root or packages required."""
import copy
import json
import socket
import struct
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

import broker as B
import manifest as M

IMAGE = "sha256:" + "a" * 64
CONTAINER = "b" * 64
RAW_LAB = {"cve_id": "CVE-2021-44228", "software": "Example Java lab", "vulnerable_version": "2.14.1",
           "image_tag": "example/offline-java:2.14.1", "image_id": IMAGE, "host_port": 18081, "container_port": 8080}


def network():
    return {"Name": B.NETWORK, "Driver": "bridge", "Scope": "local", "Internal": False, "EnableIPv6": False,
            "Labels": {B.LABEL: "1"}, "Options": {"com.docker.network.bridge.name": "br-offline-labs",
                                                   "com.docker.network.bridge.enable_icc": "false"}}


def image():
    return {"Id": IMAGE, "Os": "linux", "Config": {"Cmd": ["/app/run"], "Entrypoint": None,
            "Env": ["PATH=/usr/bin:/bin"], "WorkingDir": "/app", "Volumes": None,
            "Labels": {"org.opencontainers.image.title": "offline fixture"}}}


def container(lab, source):
    labels = dict(source["Config"]["Labels"])
    labels.update(B.labels_for(lab))
    ports = {str(lab["container_port"]) + "/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(lab["host_port"])}]}
    return {"Id": CONTAINER, "Name": "/" + B.name_for(lab), "Image": IMAGE,
            "Config": {"Image": IMAGE, "Labels": labels, "User": "65532:65532", "Cmd": ["/app/run"],
                       "Entrypoint": None, "Env": ["PATH=/usr/bin:/bin"], "WorkingDir": "/app", "Healthcheck": {"Test": ["NONE"]}},
            "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "AutoRemove": False, "NetworkMode": B.NETWORK,
                           "IpcMode": "private", "PidMode": "", "UTSMode": "", "CgroupnsMode": "private",
                           "Memory": 536870912, "MemorySwap": 536870912, "NanoCpus": 1000000000, "PidsLimit": 128,
                           "Dns": ["127.0.0.1"], "Tmpfs": {"/tmp": B.TMPFS}, "CapDrop": ["ALL"], "CapAdd": None,
                           "SecurityOpt": ["no-new-privileges:true"], "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                           "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}},
                           "PortBindings": ports}, "Mounts": [],
            "NetworkSettings": {"Networks": {B.NETWORK: {}}, "Ports": copy.deepcopy(ports)},
            "State": {"Running": False, "Paused": False, "Dead": False, "Restarting": False}}


class MemoryReceipts:
    def __init__(self):
        self.records = {}

    def register(self, lab, container_id):
        self.records[lab["cve_id"]] = {"container_id": container_id, "image_id": lab["image_id"],
                                       "runtime_sha256": B.runtime_hash(lab)}


class FakeDocker:
    def __init__(self, lab, receipts):
        self.lab, self.receipts = lab, receipts
        self.network, self.image, self.container = network(), image(), None
        self.commands = []

    def inspect(self, kind, identifier):
        if kind == "network":
            return copy.deepcopy(self.network)
        if kind == "image":
            return copy.deepcopy(self.image)
        if kind == "container" and self.container and identifier in (B.name_for(self.lab), self.container["Id"]):
            return copy.deepcopy(self.container)
        return None

    def run(self, args):
        self.commands.append(args)
        if args[:2] == ["container", "create"]:
            self.container = container(self.lab, self.image)
            return CONTAINER
        if args[:2] == ["container", "start"]:
            assert self.receipts.records[self.lab["cve_id"]]["container_id"] == args[2], "receipt must precede start"
            self.container["State"]["Running"] = True
            return CONTAINER
        if args[:2] == ["container", "stop"]:
            self.container["State"]["Running"] = False
            return CONTAINER
        raise AssertionError("Unexpected Docker command")


class Manifest(unittest.TestCase):
    def test_defaults_and_low_internal_port(self):
        raw = dict(RAW_LAB, container_port=80)
        lab = M.validate_manifest([raw])[0]
        self.assertEqual(lab["path"], "/")
        self.assertEqual(lab["description"], "")
        self.assertEqual(lab["container_port"], 80)

    def test_manifest_rejects_bad_inputs(self):
        bad = [dict(RAW_LAB, host_port=443), dict(RAW_LAB, host_port=True), dict(RAW_LAB, container_port=0),
               dict(RAW_LAB, image_tag="--privileged"), dict(RAW_LAB, image_id="sha256:" + "g" * 64),
               dict(RAW_LAB, cve_id="CVE-2021-44228;id"), dict(RAW_LAB, path="/../secret"),
               dict(RAW_LAB, path="//example.com"), dict(RAW_LAB, command="/bin/sh"),
               dict(RAW_LAB, description="x" * 601), dict(RAW_LAB, software="hello\nworld")]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(M.ManifestError):
                M.validate_manifest([raw])
        with self.assertRaises(M.ManifestError):
            M.validate_manifest([RAW_LAB, dict(RAW_LAB)])
        with self.assertRaises(M.ManifestError):
            M.validate_manifest([RAW_LAB, dict(RAW_LAB, cve_id="CVE-2022-1234")])


class Broker(unittest.TestCase):
    def setUp(self):
        self.lab = M.validate_manifest([RAW_LAB])[0]
        self.receipts = MemoryReceipts()
        self.docker = FakeDocker(self.lab, self.receipts)
        self.guard = mock.Mock()
        self.broker = B.Broker([self.lab], self.docker, self.receipts, self.guard)

    def call(self, action):
        return self.broker.handle({"action": action, "cve_id": self.lab["cve_id"]})

    def managed(self, running=True):
        self.docker.container = container(self.lab, self.docker.image)
        self.docker.container["State"]["Running"] = running
        self.receipts.register(self.lab, CONTAINER)

    def test_status_before_deployment_has_no_mutations(self):
        result = self.broker.handle({"action": "status"})
        self.assertTrue(result["ok"])
        self.assertTrue(result["deployment_allowed"])
        self.assertIsNone(result["safety_error"])
        lab = result["labs"][self.lab["cve_id"]]
        self.assertEqual(lab["status"], "not_deployed")
        self.assertTrue(lab["image_present"])
        self.assertEqual(lab["url"], "http://127.0.0.1:18081/")
        self.assertEqual(self.docker.commands, [])

    def test_deploy_registers_before_start_and_is_idempotent(self):
        self.assertEqual(self.call("deploy")["lab"]["status"], "running")
        args = self.docker.commands[0]
        for required in ("--pull=never", "--read-only", "--cap-drop=ALL", "--no-healthcheck", "127.0.0.1", "65532:65532"):
            self.assertIn(required, args)
        self.assertEqual(args[-1], IMAGE)
        self.assertEqual(self.guard.call_count, 2)
        previous = copy.deepcopy(self.docker.commands)
        self.assertTrue(self.call("deploy")["ok"])
        self.assertEqual(self.docker.commands, previous)

    def test_stop_is_non_destructive_and_guard_failure_does_not_block_it(self):
        self.managed()
        self.guard.side_effect = RuntimeError("guard unavailable")
        self.assertEqual(self.call("stop")["lab"]["status"], "stopped")
        self.assertEqual(self.docker.commands, [["container", "stop", CONTAINER]])
        self.assertIn(self.lab["cve_id"], self.receipts.records)
        self.assertTrue(self.call("stop")["ok"])
        self.assertEqual(len(self.docker.commands), 1)

    def test_missing_or_retagged_or_volume_image_never_creates(self):
        for candidate in (None, dict(image(), Id="sha256:" + "c" * 64),
                          dict(image(), Config=dict(image()["Config"], Volumes={"/data": {}}))):
            with self.subTest(candidate=candidate):
                self.docker.image = candidate
                self.assertEqual(self.call("deploy"), {"ok": False, "error": "pinned_image_unavailable"})
                self.assertEqual(self.docker.commands, [])

    def test_foreign_container_is_never_adopted_started_or_stopped(self):
        self.docker.container = container(self.lab, self.docker.image)
        for action in ("deploy", "stop"):
            self.assertEqual(self.call(action), {"ok": False, "error": "foreign_container_conflict"})
        self.assertEqual(self.call("status")["labs"][self.lab["cve_id"]]["status"], "conflict")
        self.assertEqual(self.docker.commands, [])

    def test_receipt_full_id_prevents_same_name_replacement(self):
        self.managed(False)
        self.docker.container["Id"] = "d" * 64
        self.assertEqual(self.call("deploy"), {"ok": False, "error": "foreign_container_conflict"})
        self.assertEqual(self.docker.commands, [])

    def test_runtime_changes_block_restart_and_stop(self):
        changes = (("ReadonlyRootfs", False), ("Privileged", True), ("Dns", ["8.8.8.8"]),
                   ("NetworkMode", "host"), ("CapAdd", ["SYS_ADMIN"]), ("Memory", 0),
                   ("Binds", ["/:/host"]), ("RestartPolicy", {"Name": "always", "MaximumRetryCount": 0}),
                   ("PortBindings", {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18081"}]}))
        for key, value in changes:
            with self.subTest(key=key):
                self.managed(False)
                self.docker.container["HostConfig"][key] = value
                self.assertFalse(self.call("deploy")["ok"])
                self.assertFalse(self.call("stop")["ok"])
                self.assertEqual(self.docker.commands, [])

    def test_command_environment_and_extra_network_are_rejected(self):
        for section, key, value in (("Config", "Cmd", ["/bin/sh"]), ("Config", "Env", ["LD_PRELOAD=/tmp/evil"]),
                                    ("NetworkSettings", "Networks", {B.NETWORK: {}, "bridge": {}})):
            with self.subTest(key=key):
                self.managed(False)
                self.docker.container[section][key] = value
                self.assertFalse(self.call("deploy")["ok"])
                self.assertEqual(self.docker.commands, [])

    def test_running_container_must_have_actual_loopback_port_binding(self):
        self.managed()
        self.docker.container["NetworkSettings"]["Ports"] = None
        self.assertEqual(self.call("status")["labs"][self.lab["cve_id"]]["status"], "conflict")
        self.assertEqual(self.call("stop"), {"ok": False, "error": "container_port_mismatch"})
        self.assertEqual(self.docker.commands, [])

    def test_guard_and_network_contract_gate_deploy(self):
        self.guard.side_effect = RuntimeError("private diagnostic")
        self.assertEqual(self.call("deploy"), {"ok": False, "error": "egress_guard_unverified"})
        self.guard.side_effect = None
        self.docker.network["Options"]["com.docker.network.bridge.enable_icc"] = "true"
        self.assertEqual(self.call("deploy"), {"ok": False, "error": "network_contract_mismatch"})
        self.assertEqual(self.docker.commands, [])

    def test_status_preserves_managed_stop_when_guard_is_broken(self):
        self.managed()
        self.guard.side_effect = RuntimeError("guard unavailable")
        result = self.call("status")
        self.assertTrue(result["ok"])
        self.assertFalse(result["deployment_allowed"])
        self.assertEqual(result["safety_error"], "egress_guard_unverified")
        self.assertEqual(result["labs"][self.lab["cve_id"]]["status"], "running")
        self.assertFalse(self.call("deploy")["ok"])
        self.assertEqual(self.call("stop")["lab"]["status"], "stopped")

    def test_status_preserves_inventory_when_network_contract_is_broken(self):
        self.managed()
        self.docker.network["Options"]["com.docker.network.bridge.enable_icc"] = "true"
        result = self.call("status")
        self.assertTrue(result["ok"])
        self.assertFalse(result["deployment_allowed"])
        self.assertEqual(result["safety_error"], "network_contract_mismatch")
        self.assertEqual(result["labs"][self.lab["cve_id"]]["status"], "running")
        self.assertFalse(self.call("deploy")["ok"])
        self.assertEqual(self.call("stop")["lab"]["status"], "stopped")

    def test_stopped_container_is_validated_before_restart(self):
        self.managed(False)
        self.assertEqual(self.call("deploy")["lab"]["status"], "running")
        self.assertEqual(self.docker.commands, [["container", "start", CONTAINER]])

    def test_unregistered_inputs_cannot_reach_docker_mutation(self):
        for request in ({"action": "exec", "cve_id": self.lab["cve_id"]}, {"action": ["deploy"]},
                        {"action": "deploy", "cve_id": "CVE-2021-9999"},
                        {"action": "deploy", "cve_id": self.lab["cve_id"], "command": "id"}, {"action": "deploy"}):
            self.assertFalse(self.broker.handle(request)["ok"])
        self.assertEqual(self.docker.commands, [])


class Protocol(unittest.TestCase):
    def test_bounded_single_json_frame(self):
        self.assertEqual(B.parse_request(b'{"action":"status"}\n'), {"action": "status"})
        for frame in (b'{"action":"status"}', b'{}\n{}\n', b'x' * 4096 + b'\n',
                      b'{"action":"status","action":"deploy"}\n', b'\xff\n', b'[' * 1500 + b']' * 1500 + b'\n'):
            with self.subTest(frame=frame[:70]), self.assertRaises(B.BrokerError):
                B.parse_request(frame)

    def test_peer_uid_and_primary_gid_are_both_checked(self):
        with mock.patch.object(socket, "SO_PEERCRED", 17, create=True):
            for uid, gid, expected in ((0, 0, True), (1234, 1234, True), (1234, 999, False), (999, 1234, False)):
                peer = SimpleNamespace(getsockopt=lambda *args, u=uid, g=gid: struct.pack("3i", 999, u, g))
                self.assertEqual(B.authorized_peer(peer, 1234, 1234), expected)

    def test_docker_errors_hide_stderr_and_clear_environment(self):
        completed = SimpleNamespace(returncode=1, stdout="", stderr="private-secret-token")
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            with self.assertRaises(B.BrokerError) as failure:
                B.Docker().run(["container", "start", CONTAINER])
            self.assertEqual(str(failure.exception), "docker_operation_failed")
            args, kwargs = run.call_args
            self.assertEqual(args[0][:3], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"])
            self.assertNotIn("DOCKER_HOST", kwargs["env"])
            self.assertEqual(kwargs["env"]["HOME"], "/nonexistent")


if __name__ == "__main__":
    unittest.main()
