"""No network/root/service/Docker operations: real policy engines + fake I/O."""
import ast
import base64
import copy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

DEPLOYMENT = Path(__file__).resolve().parents[1]
ROOT = DEPLOYMENT.parent
sys.path.insert(0, str(DEPLOYMENT))
import soc_management as install
import soc_runtime as runtime
import soc_agent_block as response


def profile(role="a"):
    names = ["capstone-security-waf", "capstone-security-suricata"] if role == "a" else [
        "capstone-wazuh-manager", "capstone-wazuh-dashboard", "capstone-hermes", "capstone-mattermost"]
    return {"schema": 1, "role": role, "root": "/opt/capstone", "security_host": "10.42.0.1",
            "siem_host": "10.42.0.10", "service_host": "10.42.0.20", "agent_id": "007", "interface": "enp2s0",
            "machine_id": "a" * 32, "docker": "/usr/bin/docker", "hermes_uid": 991, "hermes_gid": 992,
            "manager_etc": "/var/lib/docker/volumes/capstone-siem_wazuh_etc/_data", "dashboard_rw": True,
            "protected_ips": ["10.42.0.1", "10.42.0.10", "10.42.0.20", "211.170.162.111"],
            "admin_protected_cidrs": ["93.184.216.0/24"], "waf_port": 8080,
            "container_ids": {name: str(i) * 64 for i, name in enumerate(names, 1)}}


def source(name):
    directory = "infra/hermes" if name.startswith("soc_management_") and name != "soc_management_events.py" else "infra/mcp"
    return (ROOT / directory / name).read_bytes()


def rendered(name, role="a"):
    p = profile(role)
    gate = runtime.render("soc_management_run.py", source("soc_management_run.py"), p) if name == "soc_management_controller.py" else None
    return runtime.render(name, source(name), p, gate)


def module(name, role="a"):
    m = types.ModuleType("synthetic_" + name.replace(".", "_")); m.__file__ = str(ROOT / "infra/mcp" / name)
    sys.modules[m.__name__] = m
    exec(compile(rendered(name, role), m.__file__, "exec"), m.__dict__)
    return m


class BindingTests(unittest.TestCase):
    def test_fresh_mcp_schemas_have_exclusive_roles_and_no_legacy_chatproxy(self):
        for host in ('a', 'b'):
            m = module('rule_change_mcp.py', host)
            reads, writes = m.tool_list('read', host), m.tool_list('write', host)
            self.assertEqual(len(reads), 4)
            self.assertEqual(len(writes), 4 if host == 'a' else 3)
            self.assertFalse({t['name'] for t in reads} & {t['name'] for t in writes})
            for tool in reads + writes:
                targets = tool['inputSchema']['properties'].get('target', {}).get('enum', [])
                self.assertTrue(all(t.startswith(host + ':') and t != 'a:chatproxy' for t in targets))

    def test_rule_targets_are_host_specific_and_full_ids(self):
        for role, count in (("a", 2), ("b", 1)):
            m = module("rule_change_executor.py", role)
            self.assertEqual(len(m.TARGETS), count)
            for value in m.TARGETS.values():
                self.assertEqual(value["host"], role)
                self.assertIn(value["container"], profile(role)["container_ids"].values())
            self.assertEqual(m.DOCKER, "/usr/local/libexec/capstone-soc-docker")

    def test_container_position_changes_without_changing_engine_kind(self):
        tree = ast.parse(rendered("rule_change_executor.py"))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.List) and len(n.elts) > 3 and
                 isinstance(n.elts[0], ast.Name) and n.elts[0].id == "DOCKER" and
                 isinstance(n.elts[1], ast.Constant) and n.elts[1].value == "exec"]
        self.assertTrue(any(isinstance(n.elts[2], ast.Constant) and n.elts[2].value == "2" * 64 and
                            isinstance(n.elts[3], ast.Constant) and n.elts[3].value == "suricata" for n in calls))
        self.assertFalse(any(isinstance(n.elts[2], ast.Constant) and n.elts[2].value in ("waf", "suricata") for n in calls))

    def test_candidate_guards_and_exact_edits_remain_original(self):
        before = ast.parse(source("rule_change_executor.py")); after = ast.parse(rendered("rule_change_executor.py"))
        for name in ("_validate_candidate", "_validated_edits", "_unique_request", "_approval_payload_digest"):
            old = [n for n in ast.walk(before) if isinstance(n, ast.FunctionDef) and n.name == name]
            new = [n for n in ast.walk(after) if isinstance(n, ast.FunctionDef) and n.name == name]
            if old:
                self.assertEqual(ast.dump(old[0], include_attributes=False), ast.dump(new[0], include_attributes=False), name)
        m = module("rule_change_executor.py")
        with self.assertRaises(m.RuleChangeError):
            m._validate_candidate("waf", "SecRuleEngine On\n")
        with self.assertRaises(m.RuleChangeError):
            m._validate_candidate("suricata", 'drop tcp any any -> any any (sid:1000001; rev:1;)\n')

    def test_service_profiles_bind_names_and_full_ids_no_new_edge_target(self):
        for role in ("a", "b"):
            m = module("service_action_executor.py", role)
            self.assertNotIn("a:chatproxy", m.PROFILES)
            for value in m.PROFILES.values():
                self.assertEqual(value["expected_id"], profile(role)["container_ids"][value["container"]])
                self.assertNotIn("create", value["actions"])
        tree = ast.parse(rendered("service_action_executor.py"))
        self.assertIn("expected_id", ast.dump(tree))

    def test_identity_profile_rejects_malleable_scope(self):
        for key, value in (("docker", "/tmp/docker"), ("root", "/tmp/root"), ("agent_id", "000"),
                           ("admin_protected_cidrs", ["0.0.0.0/0"]), ("container_ids", {}),
                           ("hermes_uid", 0), ("interface", "eth0;id")):
            p = profile(); p[key] = value
            with self.subTest(key=key), self.assertRaises((runtime.Refused, ValueError)):
                runtime.validate_profile(p)

    def test_controller_gate_is_embedded_not_from_writable_home(self):
        m = module("soc_management_controller.py", "b")
        command = m.command_for({"mode": "verify", "session_id": None})
        self.assertNotIn("/opt/data/management-code/run.py", command)
        self.assertIn("-I", command); self.assertIn("-B", command)
        self.assertIn("991:992", command); self.assertIn("3" * 64, command)
        embedded = command[command.index("-c") + 1]
        self.assertIn("management_tool_not_allowed", embedded)
        self.assertIn("991", embedded)

    def test_management_gate_excludes_general_powers_and_verify_writes(self):
        m = module("soc_management_run.py", "b")
        for mode in ("manage", "verify"):
            for name in ("terminal", "docker", "mcp__resp__block_ip", "mcp__resp__unblock_ip", "write_file"):
                self.assertFalse(m.allowed(name, mode))
        self.assertTrue(m.allowed("mcp__rule_write_a__temporarily_contain_ip", "manage"))
        self.assertFalse(m.allowed("mcp__rule_write_a__temporarily_contain_ip", "verify"))
        self.assertFalse(m.allowed("mcp__rule_write_b__temporarily_contain_ip", "manage"))

    def test_root_response_rejects_oversized_stdio_before_dispatch(self):
        m = module("response-mcp.py")
        with mock.patch.object(m.sys, "stdin", io.StringIO("x" * (1048576 + 2))), mock.patch.object(m, "handle") as handle, \
             mock.patch.object(m, "log"):
            m.main()
        handle.assert_not_called()

    def test_managed_reader_keeps_native_provenance_contract(self):
        m = module("managed_suricata_evidence.py")
        self.assertEqual(str(m.BASE), "/opt/capstone/security/logs/suricata")
        self.assertEqual(m.MID, "a" * 32)
        self.assertEqual(str(m.STATE), "/var/lib/capstone-raw-operations/suricata/state.json")
        text = rendered("managed_suricata_evidence.py").decode()
        self.assertIn("managed_links_not_exact", text)
        self.assertIn("no legacy fallback", rendered("incident_containment.py").decode())


class RenderedInvestigationBoundaryTests(unittest.TestCase):
    def finish(self, disposition, tool_kind=None):
        controller = module("soc_management_controller.py", "b")
        with tempfile.TemporaryDirectory(prefix="rendered-investigation-") as directory:
            store = controller.Store(directory, clock=lambda: 1000.0)
            try:
                case_id = store.new_case("synthetic-investigation")
                case = store.next_case()
                trace = controller.Trace(store, case, store.start(case))
                trace.accept({"type": "system", "subtype": "init", "session_id": "rendered-fixture"})
                if tool_kind:
                    if tool_kind == "read":
                        name = "mcp__system_diagnostics__get_system_diagnostics"
                        arguments = {"target": "c:apache"}
                        payload = {"status": "observed", "target": "c:apache"}
                    else:
                        name = "mcp__rule_write_a__propose_rule_edit"
                        arguments = {"target": "a:modsecurity-custom"}
                        payload = {"proposal_id": "e" * 32, "status": "pending", **arguments}
                    trace.accept({"type": "tool_use", "name": name, "input": arguments})
                    trace.accept({"type": "tool_result", "name": name, "is_error": False,
                                  "output": json.dumps({"content": [{"type": "text", "text": json.dumps(payload)}],
                                                        "isError": False})})
                trace.accept({"type": "result", "session_id": trace.session_id, "exit_code": 0,
                              "text": "합성 조사 결과\nMANAGEMENT_STATUS: " + disposition})
                result = trace.finish(0)
                row = store.db.execute("SELECT state,detail FROM cases WHERE id=?", (case_id,)).fetchone()
                return result, tuple(row), store.db.execute("SELECT count(*) FROM tool_calls").fetchone()[0]
            finally:
                store.close()

    def test_rendered_manage_cannot_resolve_or_monitor_without_a_read(self):
        for disposition in ("resolved", "monitor"):
            with self.subTest(disposition=disposition):
                result, saved, calls = self.finish(disposition)
                self.assertTrue(result["completed"])
                self.assertEqual(result["state"], "needs_review")
                self.assertEqual(saved, ("needs_review", "live_investigation_missing"))
                self.assertEqual(calls, 0)

    def test_rendered_successful_read_and_pending_approval_paths_are_preserved(self):
        for tool_kind, expected in (("read", "completed"), ("pending", "waiting_approval")):
            with self.subTest(tool_kind=tool_kind):
                result, saved, calls = self.finish("resolved", tool_kind)
                self.assertEqual(result["state"], expected)
                self.assertEqual(saved[0], expected)
                self.assertEqual(calls, 1)


class ContainmentTests(unittest.TestCase):
    def nft_fixture(self):
        p = profile()
        elements = [{"prefix": {"addr": str(n.network_address), "len": n.prefixlen}}
                    for n in runtime.protected_networks(p["protected_ips"], p["admin_protected_cidrs"])]
        rows = [{"table": {"family": "inet", "name": "capstone_fw", "handle": 9}},
                {"set": {"family": "inet", "table": "capstone_fw", "name": "never_block", "type": "ipv4_addr", "flags": ["interval"], "elem": elements}},
                {"set": {"family": "inet", "table": "capstone_fw", "name": "agent_block", "type": "ipv4_addr", "flags": ["timeout"]}}]
        match = lambda name: {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@" + name}}
        for name in ("input", "forward"):
            rows += [{"chain": {"family": "inet", "table": "capstone_fw", "name": name, "type": "filter", "hook": name, "prio": -6, "policy": "accept"}},
                     {"rule": {"family": "inet", "table": "capstone_fw", "chain": name, "expr": [match("never_block"), {"accept": None}]}},
                     {"rule": {"family": "inet", "table": "capstone_fw", "chain": name, "expr": [match("agent_block"), {"log": {"prefix": "GROOT-FW BLOCK "}}, {"drop": None}]}}]
        return {"nftables": rows}

    def test_live_firewall_requires_admin_elements_and_drop_order(self):
        p = profile(); value = self.nft_fixture()
        self.assertTrue(runtime.verify_firewall(value, p["protected_ips"], p["admin_protected_cidrs"]))
        wrong = copy.deepcopy(value)
        wrong["nftables"][1]["set"]["elem"] = [e for e in wrong["nftables"][1]["set"]["elem"] if e["prefix"]["addr"] != "93.184.216.0"]
        with self.assertRaises(runtime.Refused):
            runtime.verify_firewall(wrong, p["protected_ips"], p["admin_protected_cidrs"])
        for replacement in ({"accept": None}, {"return": None}):
            wrong = copy.deepcopy(value); wrong["nftables"][5]["rule"]["expr"][-1] = replacement
            with self.assertRaises(runtime.Refused):
                runtime.verify_firewall(wrong, p["protected_ips"], p["admin_protected_cidrs"])

    def test_live_firewall_rejects_priority_and_rule_order_drift(self):
        p = profile()
        wrong = self.nft_fixture(); wrong["nftables"][3]["chain"]["prio"] = 99
        with self.assertRaises(runtime.Refused):
            runtime.verify_firewall(wrong, p["protected_ips"], p["admin_protected_cidrs"])
        wrong = self.nft_fixture(); wrong["nftables"][4], wrong["nftables"][5] = wrong["nftables"][5], wrong["nftables"][4]
        with self.assertRaises(runtime.Refused):
            runtime.verify_firewall(wrong, p["protected_ips"], p["admin_protected_cidrs"])

    def test_admin_network_and_original_protection_are_union(self):
        m = module("incident_containment.py")
        for ip in ("10.42.0.20", "127.0.0.1", "211.170.162.110", "93.184.216.17"):
            with self.subTest(ip=ip), self.assertRaises(m.ContainmentError):
                m.checked_ip(ip)
        self.assertEqual(str(m.checked_ip("151.101.1.69")), "151.101.1.69")
        self.assertEqual((m.TEMP_SECONDS, m.KEEP_SECONDS), (600, 3600))

    def test_new_sensor_evidence_requires_three_real_flows(self):
        m = module("incident_containment.py"); now = 1792700000; ip = "151.101.1.69"
        def event(fid):
            return {"event_type": "alert", "timestamp": datetime.fromtimestamp(now - 10, timezone.utc).isoformat(),
                    "flow_id": fid, "src_ip": ip, "dest_ip": "10.42.0.20", "dest_port": 8080,
                    "proto": "TCP", "app_proto": "http", "in_iface": "enp2s0", "direction": "to_server",
                    "flow": {"pkts_toserver": 3, "pkts_toclient": 2, "src_ip": ip, "dest_ip": "10.42.0.20"},
                    "alert": {"signature_id": 1000030, "severity": 1, "category": "Web Application Attack"}}
        rows = [event(i) for i in (1, 2, 3)]
        self.assertTrue(m.validated_evidence(rows, ip, now))
        for invalid in ([rows[0]] * 3, [dict(e, in_iface="ens192") for e in rows],
                        [dict(e, timestamp="2000-01-01T00:00:00+00:00") for e in rows]):
            with self.assertRaises(m.ContainmentError):
                m.validated_evidence(invalid, ip, now)

    def test_native_AR_is_new_agent_bound_registration_only(self):
        m = module("wazuh_containment_ar.py"); now = 1792700000
        alert = {"agent": {"id": "007"}, "rule": {"id": "100110", "level": 9},
                 "location": "/opt/capstone/security/logs/suricata/eve.json",
                 "timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat(), "id": "1.2",
                 "data": {"event_type": "alert", "alert": {"severity": 1}, "src_ip": "10.42.0.20"}}
        request = {"version": 1, "origin": {"name": "fixture", "module": "wazuh-execd"}, "command": "add",
                   "parameters": {"extra_args": [], "alert": alert, "program": m.PROGRAM}}
        result = m.request(install.canonical(request), now)
        self.assertEqual(result["operation"], "submit-incident")
        alert["agent"]["id"] = "001"
        with self.assertRaises(m.Refused):
            m.request(install.canonical(request), now)

    def test_firewall_keeps_defaults_and_collapses_networks_without_expansion(self):
        text = runtime.firewall(profile()["protected_ips"], ["93.184.216.0/24"]).decode()
        self.assertIn("93.184.216.0/24", text)
        self.assertIn("10.0.0.0/8", text)
        self.assertIn("flags timeout", text)
        self.assertEqual(text.count('log prefix "GROOT-FW BLOCK " drop'), 2)
        self.assertNotIn("flush", text)
        with self.assertRaises(runtime.Refused):
            runtime.firewall([], ["0.0.0.0/0"])

    def test_response_root_helper_rejects_general_commands_and_refresh_syntax(self):
        for args in (["flush"], ["add", "1.2.3.4", "121m", "test"], ["del", "1.2.3.4", "10m", "test"],
                     ["add", "1.2.3.4", "10m", "$(id)"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                response.arguments(args)
        self.assertEqual(response.arguments(["add", "1.2.3.4", "10m", "case:123"]), ("add", "1.2.3.4", 600))


class BootstrapTests(unittest.TestCase):
    def test_agent_multi_root_patch_changes_only_disabled_flag(self):
        original = b'<ossec_config><client><server><address>10.42.0.10</address></server><disable-active-response>yes</disable-active-response></client></ossec_config>\n<ossec_config><localfile><location>/raw/eve.json</location></localfile></ossec_config>\n'
        self.assertEqual(runtime.agent_ar(original), original.replace(b">yes<", b">no<"))
        for raw in (original + original, original.replace(b">yes<", b">no<"), b"<ossec_config/>"):
            with self.assertRaises(runtime.Refused):
                runtime.agent_ar(raw)

    def test_manager_AR_is_exact_rule_agent_no_OR_conditions(self):
        original = b"<ossec_config><global/></ossec_config>\n<ossec_config><auth/></ossec_config>\n"
        result = runtime.manager_ar(original, "007")
        self.assertTrue(result.startswith(original))
        self.assertIn(b"<agent_id>007</agent_id><rules_id>100110</rules_id>", result)
        self.assertNotIn(b"<level>", result); self.assertNotIn(b"<rules_group>", result)
        with self.assertRaises(runtime.Refused):
            runtime.manager_ar(result, "007")

    def test_agent_verifier_allows_later_log_stanzas_not_disabled_AR(self):
        original = b'<ossec_config><client><disable-active-response>no</disable-active-response></client></ossec_config>'
        logs = b'<ossec_config><localfile><location>/new/normalized.jsonl</location></localfile></ossec_config>'
        self.assertTrue(runtime.verify_agent_ar(original + logs))
        with self.assertRaises(runtime.Refused):
            runtime.verify_agent_ar(original.replace(b">no<", b">yes<") + logs)

    def test_configuration_is_private_canonical_and_admin_blank_is_zero(self):
        env = {"CAPSTONE_SOURCE": str(ROOT), "SECURITY_HOST": "10.42.0.1", "SIEM_HOST": "10.42.0.10",
               "SERVICE_HOST": "10.42.0.20", "LLM_BASE_URL": "http://211.170.162.111:11434/v1"}
        s = install.settings(env)
        self.assertEqual(s["admin_protected_cidrs"], [])
        self.assertIn("211.170.162.111", s["protected_ips"])
        for extra in ({"ADMIN_PROTECTED_CIDRS": "0.0.0.0/0"}, {"ADMIN_PROTECTED_CIDRS": "93.184.216.1/24"},
                      {"LLM_BASE_URL": "https://model.example/v1"}):
            with self.assertRaises((runtime.Refused, ValueError)):
                install.settings(dict(env, **extra))

    def test_stream_binds_hosts_admin_networks_distinct_keys_and_agent(self):
        s = {"hosts": {"SECURITY_HOST": "10.42.0.1", "SIEM_HOST": "10.42.0.10", "SERVICE_HOST": "10.42.0.20"},
             "protected_ips": profile()["protected_ips"], "admin_protected_cidrs": [], "interface": "auto", "ssh_port": 22}
        key = "ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + b"x" * 32).decode()
        obj = dict(s, schema=1, agent_id="007", rule_token="a" * 64, response_token="b" * 64,
                   public_key=key, readonly_public_key="ssh-ed25519 " + base64.b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + b"y" * 32).decode(), siem_host_key=key, hermes_uid=991, hermes_gid=992)
        self.assertEqual(install.validate_stream(obj, s), obj)
        for fields in ({"readonly_public_key": key}, {"response_token": "a" * 64}, {"admin_protected_cidrs": ["1.0.0.0/8"]}, {"agent_id": "000"}):
            with self.assertRaises(runtime.Refused):
                install.validate_stream(dict(obj, **fields), s)

    def test_response_unprivileged_sudo_grant_does_not_expose_agent_block(self):
        text = (DEPLOYMENT / "soc_management.py").read_text()
        self.assertNotIn("NOPASSWD: /usr/local/sbin/agent_block", text)
        self.assertIn('sudo_program + \' ""', text)
        self.assertIn("env_reset", text); self.assertIn("!setenv", text)

    def test_repeated_completed_prepare_verifies_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "siem.json").write_text("{}")
            with mock.patch.object(install, "STATE", root), mock.patch.object(install, "verify") as verify, \
                 mock.patch.object(install, "run") as run, mock.patch.object(install, "request") as request:
                result = install.prepare_siem({})
            verify.assert_called_once_with({}, "siem"); run.assert_not_called(); request.assert_not_called()
            self.assertEqual(result["mutations"], 0)


class WazuhMirrorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.addCleanup(self.temp.cleanup)
        self.m = module("rule_change_executor.py", "b")
        self.live = self.root / "live.xml"; self.startup = self.root / "startup.xml"
        self.before = b'<group name="fixture"><rule id="100110" level="9"><description>Before</description></rule></group>\n'
        self.after = self.before.replace(b"Before", b"After")
        self.live.write_bytes(self.before); self.startup.write_bytes(self.before)
        spec = copy.deepcopy(self.m.TARGETS["b:wazuh-local-rules"])
        spec.update(path=str(self.live), startup_path=str(self.startup))
        self.spec = spec
        def call(argv, timeout=30):
            if "sha256sum" in argv:
                return (self.m.sha256(self.live.read_bytes()) + "  fixture\n").encode()
            if "wazuh-analysisd" in argv:
                self.assertEqual(self.live.read_bytes(), self.after)
                self.assertEqual(self.startup.read_bytes(), self.after)
            if "restart" in argv:
                self.live.write_bytes(self.startup.read_bytes())
            return b""
        self.runner = types.SimpleNamespace(call=mock.Mock(side_effect=call))
        self.engine = self.m.Engine("b", object(), self.root / "state", {"b:wazuh-local-rules": spec}, self.runner)
        self.engine._inspect = mock.Mock(return_value={}); self.engine._wait_wazuh_manager = mock.Mock()
        current, meta, aux = self.engine._snapshot(spec)
        self.record = {"proposal_id": "a" * 32, "payload": {"target": "b:wazuh-local-rules", "base_sha256": self.m.sha256(current)},
                       "aux": aux, "base_file": {"inode": meta.st_ino}}
        self.engine._backup(self.record, "primary", str(self.live))

    def test_approved_candidate_survives_restart_and_keeps_startup_inode(self):
        inode = self.startup.stat().st_ino
        self.engine._service_apply(self.spec, self.record, self.after)
        self.assertEqual(self.live.read_bytes(), self.after)
        self.assertEqual(self.startup.read_bytes(), self.after)
        self.assertEqual(self.startup.stat().st_ino, inode)

    def test_startup_drift_is_rejected_before_any_dispatch(self):
        self.startup.write_bytes(b"changed")
        self.runner.call.reset_mock()
        with self.assertRaises(self.m.RuleChangeError):
            self.engine._service_apply(self.spec, self.record, self.after)
        self.runner.call.assert_not_called()
        self.assertEqual(self.live.read_bytes(), self.before)

    def test_engine_failure_restores_both_exact_originals(self):
        self.engine._service_apply(self.spec, self.record, self.after)
        self.engine._restore(self.record, self.spec)
        self.assertEqual(self.live.read_bytes(), self.before)
        self.assertEqual(self.startup.read_bytes(), self.before)
        self.engine._verify_restored(self.record, self.spec)


if __name__ == "__main__":
    unittest.main()
