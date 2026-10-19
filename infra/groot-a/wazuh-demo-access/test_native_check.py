#!/usr/bin/env python3
"""Offline invariants for the native, disposable Nginx fixture."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


R, N = load("render"), load("native_check")


class NativeFixture(unittest.TestCase):
    def test_diagnostics_are_bounded_and_drop_control_characters(self):
        self.assertEqual(N.diagnostic("before\x00\r\n" + "x" * 5000),
                         {"text": "x" * 4096, "truncated": True})
        self.assertEqual(N.diagnostic("nginx: syntax ok\n"),
                         {"text": "nginx: syntax ok\n", "truncated": False})

    def test_only_syntax_fixture_receives_chown_capability(self):
        runner = N.Fixture("/usr/bin/docker", "sha256:" + "a" * 64)
        commands = []
        runner.dock = lambda args, **kwargs: commands.append(args)
        runner.inspect = lambda name: {
            "Image": runner.image, "Config": {"Labels": {N.LABEL: runner.token}},
            "HostConfig": {"NetworkMode": "none", "PortBindings": {}},
        }
        runner.create("syntax", [(Path("/fixture"), "/candidate")], "0:0", ["-t"])
        runner.create("guard", [(Path("/fixture"), "/candidate")], "65532:65532", ["-g", "daemon off;"])
        for index, args in enumerate(commands):
            self.assertIn("--cap-drop=ALL", args)
            self.assertIn("--network=none", args)
            self.assertIn("--read-only", args)
            self.assertIn("type=bind,src=/fixture,dst=/candidate,readonly", args)
            self.assertEqual([part for part in args if part.startswith("--cap-add")],
                             ["--cap-add=CHOWN"] if index == 0 else [])

    def test_projection_changes_only_fixture_paths(self):
        original, _ = R.render((HERE.parent / "chatproxy.nginx.conf").read_bytes())
        projected = N.syntax_projection(original)
        self.assertNotIn(b"/etc/nginx/tls/", projected)
        self.assertEqual(projected.replace(b"/fixture-tls/", b"/etc/nginx/tls/").replace(
            b"/candidate/wazuh-vpn-window.allow.conf", b"/etc/nginx/tls/wazuh-vpn-window.allow.conf"), original)
        self.assertIn(R.global_guard().encode(), projected)

    def test_fixture_changes_only_two_guard_inputs(self):
        expected = R.global_guard().replace("$remote_addr", "$http_x_test_remote").replace(
            "$time_iso8601", "$http_x_test_time").encode()
        fixture = N.guard_fixture(R)
        self.assertIn(expected, fixture)
        self.assertNotIn(b"$remote_addr", fixture)
        self.assertNotIn(b"$time_iso8601", fixture)
        self.assertIn(b"listen 127.0.0.1:18080;", fixture)

    def test_boundary_expectations_match_renderer(self):
        self.assertEqual(len(N.CASES), 12)
        for name, address, timestamp, expected in N.CASES:
            with self.subTest(name=name):
                self.assertEqual(403 if R.window_denies(address, timestamp) else 204, expected)

    def test_cleanup_never_removes_foreign_container(self):
        runner = N.Fixture("/usr/bin/docker", "sha256:" + "a" * 64)
        runner.names = ["fixture"]
        commands = []

        def dock(args, **kwargs):
            commands.append(args)
            return SimpleNamespace(returncode=0, stdout=json.dumps([
                {"Image": runner.image, "Config": {"Labels": {N.LABEL: "someone_else"}}}
            ]), stderr="")

        runner.dock = dock
        self.assertEqual(runner.cleanup(), ["fixture"])
        self.assertEqual(commands, [["container", "inspect", "fixture"]])

    def test_cleanup_verifies_removal_of_owned_container(self):
        runner = N.Fixture("/usr/bin/docker", "sha256:" + "a" * 64)
        runner.names = ["fixture"]
        responses = iter((
            SimpleNamespace(returncode=0, stdout=json.dumps([
                {"Image": runner.image, "Config": {"Labels": {N.LABEL: runner.token}}}
            ]), stderr=""),
            SimpleNamespace(returncode=0, stdout="fixture", stderr=""),
            SimpleNamespace(returncode=1, stdout="", stderr="Error: No such object: fixture"),
        ))
        commands = []

        def dock(args, **kwargs):
            commands.append(args)
            return next(responses)

        runner.dock = dock
        self.assertEqual(runner.cleanup(), [])
        self.assertEqual(commands[1], ["container", "rm", "--force", "fixture"])
        self.assertEqual(commands[2], ["container", "inspect", "fixture"])


if __name__ == "__main__":
    unittest.main()
