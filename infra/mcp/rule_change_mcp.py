#!/usr/bin/env python3
"""Restricted stdio MCP frontend for approved rule changes.

This process runs as an unprivileged forced-command SSH user.  The only
privileged operation it can request is the root-owned rule_change_executor
helper, with one JSON object on stdin.  The helper owns the allowlist, broker
credential, backups, and service controls; MCP arguments never become paths or
shell commands.
"""

import json
import subprocess
import sys

PROTOCOL = "2025-06-18"
SUPPORTED = {"2024-11-05", "2025-03-26", PROTOCOL}
HELPER = "/usr/local/sbin/rule-change-executor"
MAX_INPUT = 256 * 1024

TOOLS = [
    {
        "name": "get_rule_change_target",
        "description": "Read the complete current content, SHA-256, and runtime state of one fixed local rule target.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {"target": {"type": "string", "enum": ["a:modsecurity-custom", "a:suricata-local", "b:wazuh-local-rules"]}},
            "required": ["target"],
        },
        "annotations": {"title": "Read local rule target", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "propose_rule_change",
        "description": "Show the exact before/after diff and request a one-time operator approval. Does not apply a rule.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "target": {"type": "string", "enum": ["a:modsecurity-custom", "a:suricata-local", "b:wazuh-local-rules"]},
                "base_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$", "description": "SHA-256 returned by get_rule_change_target"},
                "candidate_content": {"type": "string", "description": "Complete replacement content of the selected local rule file"},
                "reason": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            "required": ["target", "base_sha256", "candidate_content", "reason"],
        },
        "annotations": {"title": "Propose rule change", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    },
    {
        "name": "get_rule_change_status",
        "description": "Read a proposal status. A separate privileged worker applies the exact approved change once.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {"proposal_id": {"type": "string", "pattern": "^[0-9a-f]{16,64}$"}},
            "required": ["proposal_id"],
        },
        "annotations": {"title": "Check rule change", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
]


def _result(data, error=False):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, sort_keys=True)}], "isError": error}


def _call_helper(payload):
    request = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(request) > MAX_INPUT:
        return _result({"error": "request too large"}, True)
    try:
        proc = subprocess.run(
            ["/usr/bin/sudo", "-n", HELPER], input=request, capture_output=True,
            timeout=240 if payload.get("operation") == "propose" else 45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _result({"error": "rule-change helper unavailable"}, True)
    if len(proc.stdout) > MAX_INPUT:
        return _result({"error": "rule-change helper response too large"}, True)
    try:
        data = json.loads(proc.stdout)
    except (UnicodeDecodeError, ValueError):
        return _result({"error": "invalid helper response"}, True)
    if not isinstance(data, dict):
        return _result({"error": "invalid helper response"}, True)
    if proc.returncode and not (isinstance(data, dict) and isinstance(data.get("error"), str)):
        return _result({"error": "rule-change helper rejected the request"}, True)
    return _result(data, bool(data.get("error")))


def handle(message):
    if not isinstance(message, dict):
        return None
    mid, method = message.get("id"), message.get("method")
    if method == "initialize":
        requested = (message.get("params") or {}).get("protocolVersion")
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": requested if requested in SUPPORTED else PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "capstone-rule-change-mcp", "version": "0.1.0"},
        }}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = message.get("params") or {}
        name, args = params.get("name"), params.get("arguments")
        if not isinstance(args, dict):
            return {"jsonrpc": "2.0", "id": mid, "result": _result({"error": "arguments must be an object"}, True)}
        if name == "get_rule_change_target":
            if set(args) != {"target"}:
                result = _result({"error": "required/unsupported arguments"}, True)
            else:
                result = _call_helper({"operation": "get", **args})
        elif name == "propose_rule_change":
            if set(args) != {"target", "base_sha256", "candidate_content", "reason"}:
                result = _result({"error": "required/unsupported arguments"}, True)
            else:
                result = _call_helper({"operation": "propose", **args})
        elif name == "get_rule_change_status":
            if set(args) != {"proposal_id"}:
                result = _result({"error": "required/unsupported arguments"}, True)
            else:
                result = _call_helper({"operation": "status", **args})
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}
    if mid is None:
        return None
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}


def main():
    for line in sys.stdin.buffer:
        if len(line) > MAX_INPUT:
            continue
        try:
            reply = handle(json.loads(line))
        except (UnicodeDecodeError, ValueError, TypeError):
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
