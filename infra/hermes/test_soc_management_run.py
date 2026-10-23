#!/usr/bin/env python3
"""Offline boundary checks; fake Hermes/MCP only, no model, SSH or commands."""
import asyncio
import contextlib
import copy
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

import soc_management_controller as controller

spec = importlib.util.spec_from_file_location("soc_management_run", Path(__file__).with_name("soc_management_run.py"))
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)


def definition(name):
    return {"type": "function", "function": {"name": name, "parameters": {"type": "object"}}}


READ_NAMES = ["mcp__wazuh_ro__get_wazuh_agents", "mcp__wazuh_ro__search_wazuh_manager_logs",
              "mcp__security_events__search_suricata_alerts", "mcp__security_events__search_modsecurity_alerts",
              "mcp__rule_a__get_rule_change_target", "mcp__rule_b__get_rule_change_status",
              "mcp__rule_b__get_service_action_target", "mcp__rule_a__get_operation_status",
              "mcp__resp__list_blocks", "mcp__system_diagnostics__get_system_diagnostics"]
WRITE_NAMES = ["mcp__rule_a__propose_rule_edit", "mcp__rule_b__propose_rule_change",
               "mcp__rule_a__propose_service_action", "mcp__rule_a__temporarily_contain_ip"]
FORBIDDEN_NAMES = ["terminal", "execute_code", "run_command", "ssh", "sudo", "docker",
                   "mcp__resp__block_ip", "mcp__resp__unblock_ip", "mcp__rule_b__temporarily_contain_ip",
                   "mcp__rule_a__submit-incident", "mcp__wazuh_ro__run_command",
                   "mcp__security_events__block_ip", "mcp__unknown__get_rule_change_target",
                   "mcp__system_diagnostics__restart_service", "mcp__system_diagnostics__journalctl",
                   "mcp__rule_a__get_system_diagnostics"]


class Harness:
    def __init__(self, tools=None):
        self.initial_tools = [definition(n) for n in READ_NAMES + WRITE_NAMES + FORBIDDEN_NAMES] if tools is None else tools
        self.dispatches, self.wire_calls, self.emissions, self.progresses = [], [], [], []
        self.guard_turns, self.guard_evidence, self.guard_inputs = [], [], []
        self.model_calls = 0
        self.discovery_count = 0
        self.discovery_callback = None
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        harness = self

        def dispatch(name, args, **kwargs):
            harness.dispatches.append((name, args, kwargs))
            return {"ok": True}

        self.registry = types.SimpleNamespace(dispatch=dispatch)

        class ClientSession:
            def __init__(self, content=None, failure=None):
                self.content = content or []
                self.failure = failure

            async def call_tool(self, name, arguments=None, *args, **kwargs):
                harness.wire_calls.append((name, arguments, args, kwargs))
                if self.failure:
                    raise self.failure
                return types.SimpleNamespace(content=self.content)

        class AIAgent:
            def __init__(self, model="synthetic", **kwargs):
                self.tools = copy.deepcopy(harness.initial_tools)
                self.valid_tool_names = {t["function"]["name"] for t in self.tools}

            def call_model(self):
                harness.model_calls += 1
                return [tool["function"]["name"] for tool in self.tools]

        class Emitter:
            def emit_result(self, result, session_id="", exit_code=0):
                harness.emissions.append((copy.deepcopy(result), session_id, exit_code))
                return "native-emitter-result"

            def on_tool_progress(self, event_type, tool_name=None, preview=None, args=None, **kwargs):
                harness.progresses.append((event_type, tool_name, preview, copy.deepcopy(args), copy.deepcopy(kwargs)))
                if event_type == "tool.completed":
                    # Installed native emitter caps audit output at 5,000 chars.
                    self._emit({"type": "tool_result", "name": tool_name,
                                "output": str(kwargs.get("result", ""))[:5000],
                                "tool_call_id": kwargs.get("tool_call_id"),
                                "is_error": kwargs.get("is_error", False)})
                return "native-progress-result"

        async def guard_text(text):
            harness.guard_inputs.append(text)
            return text.replace("以下步骤", "다음 단계")

        self.ClientSession, self.AIAgent, self.Emitter = ClientSession, AIAgent, Emitter
        self.guard = types.ModuleType("capstone_korean_output_guard")
        self.guard.begin_turn = self.guard_turns.append
        self.guard.set_turn_evidence = lambda evidence: self.guard_evidence.append(copy.deepcopy(evidence))
        self.guard.guard_text = guard_text

    def discover(self):
        self.discovery_count += 1
        if self.discovery_callback:
            self.discovery_callback(self)

    def run(self, callback, mode="manage", uid=995, gid=986, euid=None, egid=None, home="/opt/data/management", argv=None):
        def module(name, **attributes):
            result = types.ModuleType(name)
            result.__dict__.update(attributes)
            return result

        modules = {"tools": module("tools", __path__=[]),
                   "tools.registry": module("tools.registry", registry=self.registry),
                   "tools.mcp_tool": module("tools.mcp_tool", discover_mcp_tools=self.discover),
                   "mcp": module("mcp", ClientSession=self.ClientSession),
                   "run_agent": module("run_agent", AIAgent=self.AIAgent),
                   "hermes_cli": module("hermes_cli", __path__=[]),
                   "hermes_cli.stream_json": module("hermes_cli.stream_json", StreamJsonEmitter=self.Emitter),
                   "hermes_cli.main": module("hermes_cli.main", main=lambda: callback(self)),
                   "capstone_korean_output_guard": self.guard}
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, modules))
            stack.enter_context(mock.patch.dict(os.environ, {"CAPSTONE_MANAGEMENT_MODE": mode, "HERMES_HOME": home}, clear=True))
            stack.enter_context(mock.patch.object(os, "getuid", return_value=uid))
            stack.enter_context(mock.patch.object(os, "getgid", return_value=gid))
            stack.enter_context(mock.patch.object(os, "geteuid", return_value=uid if euid is None else euid))
            stack.enter_context(mock.patch.object(os, "getegid", return_value=gid if egid is None else egid))
            stack.enter_context(mock.patch.object(sys, "argv", argv or ["soc_management_run.py", "chat", "-q", "synthetic incident"]))
            stack.enter_context(mock.patch.object(sys, "path", list(sys.path)))
            stack.enter_context(mock.patch.object(sys, "stdout", self.stdout))
            stack.enter_context(mock.patch.object(sys, "stderr", self.stderr))
            wrapper.main()


class ManagementWrapper(unittest.TestCase):
    def test_management_model_sees_only_allowed_tools(self):
        def check(h):
            names = h.AIAgent().call_model()
            self.assertEqual(set(names), set(READ_NAMES + WRITE_NAMES))
            self.assertFalse(set(names) & set(FORBIDDEN_NAMES))
        h = Harness(); h.run(check)
        self.assertEqual(h.model_calls, 1)
        self.assertEqual(h.discovery_count, 1)

    def test_native_constructor_signature_remains_visible(self):
        def check(h):
            self.assertIn("model", inspect.signature(h.AIAgent.__init__).parameters)
            self.assertEqual(set(h.AIAgent(model="synthetic").call_model()), set(READ_NAMES + WRITE_NAMES))
        Harness().run(check)

    def test_dispatch_and_wire_gates_installed_before_discovery(self):
        h = Harness()
        def discovery(h):
            with self.assertRaises(PermissionError):
                h.registry.dispatch("terminal", {})
            with self.assertRaises(PermissionError):
                asyncio.run(h.ClientSession().call_tool("block_ip", {}))
        h.discovery_callback = discovery
        h.run(lambda h: self.assertEqual(h.discovery_count, 1))
        self.assertEqual(h.dispatches, [])
        self.assertEqual(h.wire_calls, [])

    def test_verification_model_sees_only_reads_before_model_call(self):
        def check(h):
            agent = h.AIAgent()
            self.assertEqual(agent.valid_tool_names, set(READ_NAMES))
            self.assertEqual(set(agent.call_model()), set(READ_NAMES))
        h = Harness(); h.run(check, "verify")
        self.assertEqual(h.model_calls, 1)

    def test_no_allowed_tools_fails_before_model_call(self):
        h = Harness([definition("terminal"), definition("mcp__resp__block_ip")])
        with self.assertRaisesRegex(RuntimeError, "tools_unavailable"):
            h.run(lambda h: h.AIAgent().call_model())
        self.assertEqual(h.model_calls, 0)

    def test_dispatch_forbidden_tools_never_reach_native_dispatch(self):
        def check(h):
            for name in FORBIDDEN_NAMES:
                with self.subTest(name=name), self.assertRaisesRegex(PermissionError, "tool_not_allowed"):
                    h.registry.dispatch(name, {"command": "sudo docker anything"})
        h = Harness(); h.run(check)
        self.assertEqual(h.dispatches, [])

    def test_dispatch_manage_forwards_soc_proposal_without_elevating_arguments(self):
        arguments = {"target": "a:suricata-local", "base_sha256": "a" * 64,
                     "edits": [{"old_text": "synthetic", "new_text": "candidate"}], "reason": "evidence"}
        def check(h):
            self.assertEqual(h.registry.dispatch(WRITE_NAMES[0], arguments, call_id="call-1"), {"ok": True})
        h = Harness(); h.run(check)
        self.assertEqual(h.dispatches, [(WRITE_NAMES[0], arguments, {"call_id": "call-1"})])

    def test_verify_dispatch_refuses_every_write(self):
        def check(h):
            for name in WRITE_NAMES:
                with self.subTest(name=name), self.assertRaises(PermissionError):
                    h.registry.dispatch(name, {})
        h = Harness(); h.run(check, "verify")
        self.assertEqual(h.dispatches, [])

    def test_resume_reenabled_toolsets_cannot_bypass_both_runtime_gates(self):
        def check(h):
            agent = h.AIAgent()
            # Simulate a resume loader replacing both filtered registries.
            agent.tools = [definition(n) for n in WRITE_NAMES + FORBIDDEN_NAMES]
            agent.valid_tool_names = {t["function"]["name"] for t in agent.tools}
            for name in agent.valid_tool_names:
                with self.subTest(name=name), self.assertRaises(PermissionError):
                    h.registry.dispatch(name, {})
            for name in ("propose_rule_edit", "propose_service_action", "temporarily_contain_ip", "block_ip", "unblock_ip", "run_command"):
                with self.subTest(wire_name=name), self.assertRaises(PermissionError):
                    asyncio.run(h.ClientSession().call_tool(name, {}))
        h = Harness(); h.run(check, "verify", argv=["soc_management_run.py", "--resume", "session-1", "--toolsets", "all"])
        self.assertEqual(h.dispatches, [])
        self.assertEqual(h.wire_calls, [])

    def test_wire_refuses_legacy_response_writes_in_both_modes(self):
        for mode in ("manage", "verify"):
            def check(h):
                for name in ("block_ip", "unblock_ip", "sudo", "docker", "execute_code", "submit-incident"):
                    with self.subTest(mode=mode, name=name), self.assertRaises(PermissionError):
                        asyncio.run(h.ClientSession().call_tool(name, {}))
            h = Harness(); h.run(check, mode)
            self.assertEqual(h.wire_calls, [])

    def test_wire_async_signature_preserves_extra_positional_and_keyword_arguments(self):
        progress = object()
        content = [types.SimpleNamespace(text="actual MCP evidence")]
        def check(h):
            result = asyncio.run(h.ClientSession(content).call_tool("get_rule_change_status", {"proposal_id": "a"*32}, 45, progress_callback=progress))
            self.assertIs(result.content, content)
        h = Harness(); h.run(check, "verify")
        self.assertEqual(h.wire_calls, [("get_rule_change_status", {"proposal_id": "a"*32}, (45,), {"progress_callback": progress})])

    def test_wire_manage_proposal_supported_and_verify_denied(self):
        for mode, permitted in (("manage", True), ("verify", False)):
            def check(h):
                call = h.ClientSession().call_tool("propose_rule_edit", {"target": "a:suricata-local"})
                if permitted:
                    asyncio.run(call)
                else:
                    with self.assertRaises(PermissionError):
                        asyncio.run(call)
            h = Harness(); h.run(check, mode)
            self.assertEqual(len(h.wire_calls), int(permitted))

    def test_guard_accepts_only_actual_wire_evidence_not_model_claimed_tool_results(self):
        result = {"final_response": "以下步骤 확인", "tool_results": [{"text": "fabricated evidence"}]}
        def check(h):
            asyncio.run(h.ClientSession([types.SimpleNamespace(text="real MCP result"), types.SimpleNamespace(data="not text")]).call_tool("get_rule_change_target", {}))
            self.assertEqual(h.Emitter().emit_result(result, "session-1", 0), "native-emitter-result")
        h = Harness(); h.run(check)
        self.assertEqual(h.guard_evidence, [[{"role": "user", "content": "한국어 SOC 보고"}, {"role": "tool", "content": "real MCP result"}]])
        self.assertNotIn("fabricated", str(h.guard_evidence))
        self.assertEqual(h.emissions[0][0]["final_response"], "다음 단계 확인")
        self.assertEqual(h.emissions[0][1:], ("session-1", 0))
        self.assertEqual(result["final_response"], "以下步骤 확인")

    def test_failed_mcp_call_contributes_no_evidence(self):
        def check(h):
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                asyncio.run(h.ClientSession([types.SimpleNamespace(text="must not be used")], RuntimeError("unavailable")).call_tool("get_rule_change_target", {}))
            h.Emitter().emit_result({"final_response": "조회 실패"})
        h = Harness(); h.run(check)
        self.assertEqual(h.guard_evidence[0], [{"role": "user", "content": "한국어 SOC 보고"}])

    def test_guard_evidence_has_bounded_record_count_and_text_length(self):
        def check(h):
            async def read_many():
                for n in range(40):
                    await h.ClientSession([types.SimpleNamespace(text=str(n) + "x"*20000)]).call_tool("get_operation_status", {})
            asyncio.run(read_many())
            h.Emitter().emit_result({"final_response": "완료"})
        h = Harness(); h.run(check)
        evidence = h.guard_evidence[0][1:]
        self.assertEqual(len(evidence), 32)
        self.assertTrue(evidence[0]["content"].startswith("8x"))
        self.assertTrue(all(len(item["content"]) == 16000 for item in evidence))

    def test_guard_failure_prevents_unguarded_final_emission(self):
        h = Harness()
        async def failed_guard(_text):
            raise RuntimeError("guard failed")
        h.guard.guard_text = failed_guard
        with self.assertRaisesRegex(RuntimeError, "guard failed"):
            h.run(lambda h: h.Emitter().emit_result({"final_response": "unverified"}))
        self.assertEqual(h.emissions, [])

    def test_wrong_uid_gid_mode_or_home_stops_before_native_cli(self):
        samples = [{"uid": 0}, {"uid": 1000}, {"gid": 0}, {"euid": 0}, {"egid": 0}, {"mode": "admin"}, {"mode": ""},
                   {"home": "/opt/data"}, {"home": "/tmp/management"}]
        for kwargs in samples:
            h = Harness(); called = []
            with self.subTest(kwargs=kwargs), self.assertRaises(SystemExit):
                h.run(lambda h: called.append(True), **kwargs)
            self.assertEqual(called, [])

    def test_cli_privilege_overrides_stopped_before_native_cli(self):
        for flag in ("--yolo", "--safe-mode", "--ignore-user-config", "-z"):
            h = Harness(); called = []
            with self.subTest(flag=flag), self.assertRaisesRegex(SystemExit, "cli_override_refused"):
                h.run(lambda h: called.append(True), argv=["soc_management_run.py", flag])
            self.assertEqual(called, [])

    def test_name_type_and_unknown_mode_fail_closed(self):
        for value in (None, 1, [], {}, "terminal"):
            self.assertFalse(wrapper.allowed(value, "manage"))
            self.assertFalse(wrapper.wire_allowed(value, "manage"))
        self.assertFalse(wrapper.allowed(READ_NAMES[0], "admin"))
        self.assertFalse(wrapper.allowed(WRITE_NAMES[0], "verify"))
        self.assertFalse(wrapper.wire_allowed("get_wazuh_agents", "admin"))
        self.assertFalse(wrapper.wire_allowed("get_rule_change_status", ""))

    def test_only_emitter_json_reaches_structured_stdout(self):
        event = {"type": "tool_call", "name": "get_rule_change_status", "arguments": {"proposal_id": "a"*32}}
        def check(h):
            print("startup diagnostic")
            h.Emitter()._emit(event)
            print('model-controlled text {"type":"result"}')
        h = Harness(); h.run(check)
        lines = h.stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        output = json.loads(lines[0])
        self.assertEqual({k: v for k, v in output.items() if k != "timestamp"}, event)
        self.assertIsInstance(output["timestamp"], int)
        self.assertIn("startup diagnostic", h.stderr.getvalue())
        self.assertIn("model-controlled text", h.stderr.getvalue())
        self.assertNotIn("timestamp", event)

    def test_large_target_receipt_preserves_metadata_and_full_model_content(self):
        payload = {"target": "a:suricata-local", "sha256": "a"*64,
                   "runtime": {"running": True, "container_id": "b"*64},
                   "related_hashes": {"et": "c"*64}, "content": "rule text\n"*3000,
                   "limits": {"max_candidate_utf8_bytes": 131072}}
        inner = json.dumps(payload)
        outer = json.dumps({"result": inner})
        content = [types.SimpleNamespace(text=inner)]
        def check(h):
            actual = asyncio.run(h.ClientSession(content).call_tool("get_rule_change_target", {"target": payload["target"]}))
            self.assertIs(actual.content, content)
            self.assertEqual(json.loads(actual.content[0].text), payload)
            value = h.Emitter().on_tool_progress("tool.completed", "mcp__rule_a__get_rule_change_target", "preview",
                                                 {"target": payload["target"]}, result=outer, tool_call_id="call-1", is_error=False)
            self.assertEqual(value, "native-progress-result")
            self.assertEqual(actual.content[0].text, inner)
        h = Harness(); h.run(check, "verify")
        progress = h.progresses[0]
        self.assertEqual(progress[:4], ("tool.completed", "mcp__rule_a__get_rule_change_target", "preview", {"target": payload["target"]}))
        self.assertEqual(progress[4]["tool_call_id"], "call-1")
        audit = json.loads(h.stdout.getvalue())["output"]
        self.assertLess(len(audit), 5000)
        receipt = controller.tool_payload(audit)
        self.assertEqual(receipt, {key: payload[key] for key in ("target", "sha256", "runtime", "related_hashes")})
        self.assertNotIn("content", receipt)
        self.assertEqual(json.loads(outer)["result"], inner)

    def test_compaction_only_for_completed_rule_target_reads(self):
        payload = {"target": "a:suricata-local", "sha256": "a"*64,
                   "runtime": {"running": True}, "content": "x"*6000}
        outer = json.dumps({"result": json.dumps(payload)})
        def check(h):
            for kind, name in (("tool.started", "mcp__rule_a__get_rule_change_target"),
                               ("tool.completed", "mcp__rule_b__get_service_action_target"),
                               ("tool.completed", "mcp__rule_a__propose_rule_edit")):
                h.Emitter().on_tool_progress(kind, name, result=outer)
        h = Harness(); h.run(check)
        self.assertTrue(all(progress[4]["result"] == outer for progress in h.progresses))

    def test_malformed_target_results_unchanged(self):
        samples = ["not JSON", "[]", json.dumps({"result": "broken inner JSON"}),
                   json.dumps({"result": json.dumps([])}),
                   json.dumps({"result": json.dumps({"target": "a:suricata-local", "sha256": "a"*64})}),
                   json.dumps({"other": "value"}), None]
        for value in samples:
            with self.subTest(value=value):
                self.assertEqual(wrapper.compact_target_receipt(value), value)

    def test_error_envelopes_cannot_become_success_receipts(self):
        payload = {"target": "a:suricata-local", "sha256": "a"*64, "runtime": {"running": False}}
        samples = [json.dumps({"result": json.dumps(payload), "isError": True}),
                   json.dumps({"result": json.dumps(payload), "error": "failed"}),
                   json.dumps({"result": json.dumps(dict(payload, error="failed"))}),
                   json.dumps({"result": json.dumps(dict(payload, isError=True))})]
        for value in samples:
            with self.subTest(value=value):
                compacted = wrapper.compact_target_receipt(value)
                self.assertEqual(compacted, value)
                self.assertTrue(controller.tool_failed(compacted))
                self.assertIsNone(controller.tool_payload(compacted))

    def test_oversized_metadata_still_fails_closed_at_native_cap(self):
        payload = {"target": "a:suricata-local", "sha256": "a"*64,
                   "runtime": {"running": True, "diagnostic": "x"*6000}, "content": "some rules"}
        outer = json.dumps({"result": json.dumps(payload)})
        def check(h):
            h.Emitter().on_tool_progress("tool.completed", "mcp__rule_a__get_rule_change_target", result=outer)
        h = Harness(); h.run(check, "verify")
        output = json.loads(h.stdout.getvalue())["output"]
        self.assertEqual(len(output), 5000)
        self.assertIsNone(controller.tool_payload(output))


if __name__ == "__main__":
    unittest.main()
