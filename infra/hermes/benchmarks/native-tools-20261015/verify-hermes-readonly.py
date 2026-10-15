#!/usr/bin/env python3
"""One private Hermes conversation; exactly one allowed read, no chat delivery.

The operator supplies an isolated HERMES_HOME/cwd and captures its private files.
This never installs packages, changes the live configuration, or starts a gateway.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
import time
import traceback

NAME = "mcp__rule_a__get_service_action_target"
BARE_NAME = "get_service_action_target"
ARGS = {"target": "a:waf"}
URL = "http://211.170.162.111:11434/v1"
MODEL = "qwen3.6:35b"


class ProbeStop(BaseException):
    pass


def need(condition, code):
    if not condition:
        raise ProbeStop(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            need(key not in result, "duplicate_json_key")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=pairs)


def file_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def write_new(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def private_paths():
    need(os.getuid() == 995 and os.getgid() == 986, "service_uid_gid_required")
    home = Path(os.environ.get("HERMES_HOME", ""))
    cwd = Path.cwd()
    need(home.is_absolute() and re.fullmatch(r"/tmp/capstone-[A-Za-z0-9_-]+/home", str(home)),
         "private_home_required")
    need(cwd == home.parent / "work", "private_cwd_required")
    for path in (home.parent, home, cwd):
        value = path.lstat()
        need(stat.S_ISDIR(value.st_mode) and (value.st_uid, value.st_gid) == (995, 986)
             and stat.S_IMODE(value.st_mode) == 0o700, "private_directory_metadata")
    need(home.resolve() == home and cwd.resolve() == cwd, "private_path_symlink")
    need(not any((home / name).exists() or (home / name).is_symlink()
                 for name in (".env", "state.db", "state.db-wal", "state.db-shm",
                              "readonly-runtime.log", "readonly-verification.json",
                              "readonly-final-response.txt")), "private_home_not_fresh")
    for name in ("HERMES_YOLO_MODE", "HERMES_ACCEPT_HOOKS"):
        need(os.environ.get(name, "").lower() not in {"1", "true", "yes", "on"},
             "approval_bypass_environment")
    config = home / "config.yaml"
    value = config.lstat()
    need(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid in (0, 995)
         and value.st_gid in (0, 986) and stat.S_IMODE(value.st_mode) == 0o600
         and 0 < value.st_size <= 65536, "private_config_metadata")
    fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(65537)
        need(file_identity(os.fstat(handle.fileno())) == file_identity(value), "private_config_changed")
    return home, cwd, raw


def service_result(value):
    need(isinstance(value, str) and len(value.encode()) <= 262144, "dispatch_result_shape")
    envelope = strict_json(value)
    need(isinstance(envelope, dict) and set(envelope) == {"result"}
         and isinstance(envelope["result"], str), "dispatch_result_envelope")
    data = strict_json(envelope["result"])
    need(isinstance(data, dict) and data.get("target") == "a:waf" and "error" not in data
         and isinstance(data.get("observation"), dict)
         and data["observation"].get("running") is True
         and isinstance(data.get("allowed_actions"), list)
         and re.fullmatch(r"[0-9a-f]{64}", data.get("base_state_sha256", "")) is not None,
         "readonly_observation_failed")


def main():
    started = time.monotonic()
    report = {"status": "failed", "phase": "preflight", "dispatch_attempts": 0,
              "mcp_wire_attempts": 0, "denied_dispatches": 0, "denied_wire_calls": 0,
              "mcp_dispatch_seconds": 0.0, "mcp_wire_seconds": 0.0,
              "chat_posts": 0, "operating_config_changed": False,
              "model_api_seconds": None, "language_guard_checked": False}
    home = agent = registry = session_type = original_dispatch = original_call = mcp_shutdown = None
    public_fd = os.dup(1)
    old_handlers = {}
    try:
        home, cwd, raw = private_paths()
        logfd = os.open(home / "readonly-runtime.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.dup2(logfd, 1)
        os.dup2(logfd, 2)
        os.close(logfd)
        os.umask(0o077)
        def interrupted(signum, _frame):
            raise ProbeStop("bounded_timeout" if signum == signal.SIGALRM else "interrupted")
        for signum in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            old_handlers[signum] = signal.signal(signum, interrupted)
        signal.alarm(180)
        import yaml
        config = yaml.safe_load(raw)
        need(isinstance(config, dict) and set(config.get("mcp_servers", {})) == {"rule-a"}, "one_mcp_server_required")
        server = config["mcp_servers"]["rule-a"]
        need(server.get("command") in ("ssh", "/usr/bin/ssh")
             and server.get("args") == ["-T", "-F", "/opt/data/home/.ssh/config", "rule-a"]
             and server.get("env") == {"HOME": "/opt/data/home"}
             and server.get("enabled", True) is True
             and server.get("tools") == {"include": [BARE_NAME], "resources": False, "prompts": False}
             and server.get("supports_parallel_tool_calls") is False, "readonly_mcp_config_required")
        need(config.get("model", {}).get("base_url") == URL
             and config.get("model", {}).get("default") == MODEL
             and config.get("model", {}).get("provider") == "custom", "fixed_model_required")
        need(config.get("tools", {}).get("tool_search", {}).get("enabled") is False,
             "tool_search_must_be_disabled")
        report["config_sha256"] = hashlib.sha256(raw).hexdigest()
        report["phase"] = "imports_and_discovery"
        from tools.registry import registry
        from mcp import ClientSession
        session_type = ClientSession
        original_dispatch = registry.dispatch
        original_call = ClientSession.call_tool
        signature = inspect.signature(original_dispatch)
        parameters = signature.parameters
        need(list(parameters) == ["name", "args", "scope", "kwargs"]
             and parameters["scope"].kind == inspect.Parameter.KEYWORD_ONLY
             and parameters["kwargs"].kind == inspect.Parameter.VAR_KEYWORD
             and not inspect.iscoroutinefunction(original_dispatch), "dispatch_signature_changed")
        wire_signature = inspect.signature(original_call)
        need(inspect.iscoroutinefunction(original_call)
             and list(wire_signature.parameters)[:3] == ["self", "name", "arguments"],
             "mcp_signature_changed")
        lock = threading.Lock()
        def gated_dispatch(name, args, **kwargs):
            with lock:
                if name != NAME or type(args) is not dict or args != ARGS or report["dispatch_attempts"] != 0:
                    report["denied_dispatches"] += 1
                    raise ProbeStop("unexpected_or_repeated_dispatch")
                report["dispatch_attempts"] += 1
            tick = time.monotonic()
            try:
                value = original_dispatch(name, args, **kwargs)
                service_result(value)
                report["readonly_observation_verified"] = True
                return value
            finally:
                report["mcp_dispatch_seconds"] += time.monotonic() - tick
        async def gated_wire(self, *args, **kwargs):
            bound = wire_signature.bind(self, *args, **kwargs)
            with lock:
                if (bound.arguments.get("name") != BARE_NAME or type(bound.arguments.get("arguments")) is not dict
                        or bound.arguments["arguments"] != ARGS or report["mcp_wire_attempts"] != 0):
                    report["denied_wire_calls"] += 1
                    raise ProbeStop("unexpected_or_repeated_wire_call")
                report["mcp_wire_attempts"] += 1
            tick = time.monotonic()
            try:
                return await original_call(self, *args, **kwargs)
            finally:
                report["mcp_wire_seconds"] += time.monotonic() - tick
        registry.dispatch = gated_dispatch
        ClientSession.call_tool = gated_wire
        from tools.mcp_tool import discover_mcp_tools, shutdown_mcp_servers
        mcp_shutdown = shutdown_mcp_servers
        discover_mcp_tools()
        from run_agent import AIAgent
        report["phase"] = "agent_initialization"
        agent = AIAgent(provider="custom", base_url=URL, model=MODEL, api_mode="chat_completions",
                        api_key="not-needed", enabled_toolsets=["mcp-rule-a"],
                        max_iterations=2, max_tokens=2048, reasoning_config={"enabled": False},
                        skip_context_files=True, skip_memory=True, skip_background_review=True,
                        session_db=None, save_trajectories=False, quiet_mode=True, cwd=str(cwd),
                        fallback_model=None)
        need(isinstance(agent.tools, list) and len(agent.tools) == 1
             and agent.tools[0].get("type") == "function"
             and agent.tools[0].get("function", {}).get("name") == NAME
             and agent.valid_tool_names == {NAME}, "agent_tool_allowlist_mismatch")
        schema = agent.tools[0]["function"]["parameters"]
        need(schema.get("type") == "object" and schema.get("additionalProperties") is False
             and schema.get("required") == ["target"] and set(schema.get("properties", {})) == {"target"}
             and schema["properties"]["target"].get("type") == "string"
             and "a:waf" in schema["properties"]["target"].get("enum", []), "agent_tool_schema_mismatch")
        report["tool_name"] = NAME
        report["model_facing_tools"] = 1
        report["tool_schema_sha256"] = hashlib.sha256(canonical(agent.tools).encode()).hexdigest()
        report["initialization_seconds"] = time.monotonic() - started
        report["phase"] = "conversation"
        tick = time.monotonic()
        result = agent.run_conversation(
            user_message="A WAF의 현재 상태를 읽기 전용 도구로 한 번 조회하고 결과를 짧게 한국어로 알려주세요. 변경하거나 재시작하지 마세요.",
            system_message="지정된 읽기 도구를 정확히 한 번 호출하세요. 도구 결과를 받은 뒤 관측 결과만 짧게 한국어로 답하세요. 다른 동작을 수행하지 마세요.",
            conversation_history=[])
        report["conversation_seconds"] = time.monotonic() - tick
        need(isinstance(result, dict), "conversation_result_shape")
        final = result.get("final_response")
        if isinstance(final, str):
            need(len(final.encode()) <= 65536, "final_response_too_large")
            write_new(home / "readonly-final-response.txt", final.encode())
            report["final_response_characters"] = len(final)
            report["final_response_sha256"] = hashlib.sha256(final.encode()).hexdigest()
        for key in ("api_calls", "input_tokens", "output_tokens", "total_tokens"):
            value = result.get(key)
            report[key] = value if type(value) is int and value >= 0 else None
        need(type(result.get("api_calls")) is int and 1 <= result["api_calls"] <= 2, "model_call_budget_or_counter")
        need(result.get("completed") is True and not result.get("failed") and not result.get("partial")
             and not result.get("interrupted"), "conversation_incomplete")
        need(report["dispatch_attempts"] == report["mcp_wire_attempts"] == 1
             and report["denied_dispatches"] == report["denied_wire_calls"] == 0
             and report.get("readonly_observation_verified") is True, "one_verified_read_required")
        need(isinstance(final, str) and bool(final.strip()), "final_response_missing")
        need((home / "config.yaml").read_bytes() == raw, "private_config_changed")
        report["status"] = "passed"
        report["phase"] = "complete"
    except BaseException as exc:
        report["failure_code"] = str(exc) if isinstance(exc, ProbeStop) else "unexpected_exception"
        report["failure_type"] = type(exc).__name__
        report["failure_frames"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                                    for frame in traceback.extract_tb(exc.__traceback__)[-8:]]
    finally:
        try:
            if agent is not None:
                signal.alarm(15)
                agent.close()
            report["agent_closed"] = agent is not None
        except BaseException as exc:
            report["status"] = "failed"
            report["cleanup_failure_type"] = type(exc).__name__
        try:
            if mcp_shutdown is not None:
                signal.alarm(15)
                mcp_shutdown()
                report["mcp_shutdown_completed"] = True
        except BaseException as exc:
            report["status"] = "failed"
            report["mcp_shutdown_failure_type"] = type(exc).__name__
        if registry is not None and original_dispatch is not None:
            registry.dispatch = original_dispatch
        if session_type is not None and original_call is not None:
            session_type.call_tool = original_call
        signal.alarm(0)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        report["total_seconds"] = time.monotonic() - started
        payload = (canonical(report) + "\n").encode()
        if home is not None:
            try:
                write_new(home / "readonly-verification.json", payload)
            except BaseException:
                report["status"] = "failed"
                report["receipt_write_failed"] = True
                payload = (canonical(report) + "\n").encode()
        os.write(public_fd, payload)
        os.close(public_fd)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
