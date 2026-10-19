#!/usr/bin/env python3
"""Offline rendering, expiry boundaries and close-only regression tests."""
import copy
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


R, C = module("render"), module("close")


class Window(unittest.TestCase):
    def test_approved_boundaries(self):
        for timestamp in ("2026-10-19T00:00:00+00:00", "2026-10-19T23:59:59+00:00",
                          "2026-10-20T00:00:00+00:00", "2026-10-20T13:59:59+00:00",
                          "2026-10-20T14:00:00+00:00", "2026-10-20T14:58:59+00:00"):
            with self.subTest(timestamp=timestamp):
                self.assertFalse(R.window_denies("192.168.15.7", timestamp))

    def test_expiry_timezone_and_malformed_fail_closed(self):
        for timestamp in ("2026-10-18T23:59:59+00:00", "2026-10-20T14:59:00+00:00",
                          "2026-10-20T14:59:59+00:00", "2026-10-20T15:00:00+00:00",
                          "2026-10-21T00:00:00+00:00", "2027-10-19T00:00:00+00:00",
                          "2026-10-19T00:00:00+09:00", "2026-10-19T00:00:00Z",
                          "2026-10-19T24:00:00+00:00", "2026-10-20T14:58:60+00:00", ""):
            with self.subTest(timestamp=timestamp):
                self.assertTrue(R.window_denies("192.168.15.7", timestamp))

    def test_every_minute_on_expiry_day(self):
        for hour in range(24):
            for minute in range(60):
                timestamp = "2026-10-20T%02d:%02d:00+00:00" % (hour, minute)
                self.assertEqual(R.window_denies("192.168.15.99", timestamp), (hour, minute) >= (14, 59))

    def test_other_sources_use_original_access_rules(self):
        for address in ("192.168.10.1", "192.168.12.1", "192.168.16.1", "10.200.10.1", "8.8.8.8", "::1"):
            self.assertFalse(R.window_denies(address, "2026-10-21T00:00:00+00:00"))

    def test_render_preserves_other_server_blocks(self):
        base = (HERE.parent / "chatproxy.nginx.conf").read_bytes()
        candidate, state = R.render(base)
        original, changed = base.decode(), candidate.decode()
        start = original.index("    server {\n        listen 8443 ssl;\n        server_name " + R.DOMAIN)
        end = original.index("    # Log4Shell", start)
        without_global = changed.replace(R.global_guard(), "", 1)
        candidate_end = without_global.index("    # Log4Shell", start)
        self.assertEqual(original[:start], without_global[:start])
        self.assertEqual(original[end:], without_global[candidate_end:])
        target = without_global[start:candidate_end]
        self.assertIn("if ($capstone_wazuh_demo_deny) { return 403; }", target)
        self.assertEqual(target.count("wazuh-vpn-window.allow.conf"), 1)
        self.assertNotIn("/tls/wazuhduck.", target)
        self.assertIn("/tls/chatduck.crt", target)
        self.assertEqual(re.findall(r'"~([^"\n]+)" 1;', changed), list(R.TIME_PATTERNS))
        self.assertEqual(state["active_config_sha256"], R.digest(candidate))
        C.validate_state(state)

    def test_changed_baseline_refused(self):
        base = (HERE.parent / "chatproxy.nginx.conf").read_bytes()
        with self.assertRaises(ValueError): R.render(base + b"\n")

    def test_state_cannot_redirect_close_target(self):
        _, state = R.render((HERE.parent / "chatproxy.nginx.conf").read_bytes())
        for key, value in (("include", "/etc/passwd"), ("vpn_cidr", "0.0.0.0/0"),
                           ("container_id", "0" * 64), ("expires_utc", "2027-01-01T00:00:00Z")):
            altered = copy.deepcopy(state); altered[key] = value
            with self.assertRaises(ValueError): C.validate_state(altered)

    def test_close_is_idempotent_and_never_reopens(self):
        with tempfile.TemporaryDirectory(prefix="wazuh-demo-test-") as temporary:
            target = Path(temporary) / "allow.conf"
            target.write_bytes(C.ACTIVE)
            C.close_include(target, C.ACTIVE)
            self.assertEqual(target.read_bytes(), C.CLOSED)
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            C.close_include(target, C.CLOSED)
            self.assertEqual(target.read_bytes(), C.CLOSED)
            self.assertEqual(list(Path(temporary).iterdir()), [target])
            with self.assertRaises(ValueError): C.close_include(target, b"allow all;\n")

    def test_timer_matches_exact_approved_deadline(self):
        timer = (HERE / "capstone-wazuh-demo-close.timer").read_text()
        for setting in ("OnCalendar=2026-10-20 14:59:00 UTC", "Persistent=true", "AccuracySec=1s", "RandomizedDelaySec=0"):
            self.assertIn(setting, timer)


if __name__ == "__main__":
    unittest.main()
