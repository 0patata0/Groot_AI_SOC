#!/usr/bin/env python3
"""Restricted stdio MCP frontend for approved rule changes.

This process runs as an unprivileged forced-command SSH user.  The only
privileged operation it can request is the root-owned rule_change_executor
helper, with one JSON object on stdin.  The helper owns the allowlist, broker
credential, backups, and service controls; MCP arguments never become paths or
shell commands.
"""

import json
import copy
import subprocess
import sys

PROTOCOL = "2025-06-18"
SUPPORTED = {"2024-11-05", "2025-03-26", PROTOCOL}
HELPER = "/usr/local/sbin/rule-change-executor"
MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
READ_TOOLS = frozenset({"get_rule_change_target", "get_rule_change_status",
                        "get_service_action_target", "get_operation_status"})

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
        "name": "propose_rule_edit",
        "description": "Preferred for small or localized rule changes: submit only exact text replacements, not the whole file. The server checks the current SHA-256, reconstructs the complete candidate, validates it, and posts the full diff for one operator approval. Each old_text must occur exactly once in the original file; edits must not overlap. All edits refer to the original, never another edit's output. To insert, replace a unique existing anchor with the anchor plus the new text. To delete, use an empty new_text. Returns compact approval metadata; the full diff is already posted to Mattermost. Does not apply before approval.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "target": {"type": "string", "enum": ["a:modsecurity-custom", "a:suricata-local", "b:wazuh-local-rules"]},
                "base_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$", "description": "Copy the exact SHA-256 returned by get_rule_change_target"},
                "edits": {
                    "type": "array", "minItems": 1, "maxItems": 16,
                    "description": "Exact original-text replacements; combined old_text and new_text must fit 64 KiB UTF-8. Final reconstructed file must fit 128 KiB.",
                    "items": {
                        "type": "object", "additionalProperties": False,
                        "properties": {
                            "old_text": {"type": "string", "minLength": 1, "description": "A nonempty unique literal excerpt from the original file, preserving all whitespace and newlines"},
                            "new_text": {"type": "string", "description": "Exact replacement; keep the anchor when inserting, or empty to delete"},
                        },
                        "required": ["old_text", "new_text"],
                    },
                },
                "reason": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            "required": ["target", "base_sha256", "edits", "reason"],
        },
        "annotations": {"title": "Propose exact rule edits", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False},
    },
    {
        "name": "propose_rule_change",
        "description": "For intentional whole-file rewrites only; prefer propose_rule_edit for localized changes to avoid regenerating unchanged rules. Submit the complete candidate file (up to 128 KiB UTF-8) and request one operator approval for that exact change. Large diffs are automatically shown in multiple review messages before a single approval card. Do not split the rule change merely because its diff exceeds 8 KiB. Does not apply a rule before approval.",
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


SERVICE_TARGETS = ["a:waf", "a:suricata", "a:chatproxy", "b:wazuh-manager", "b:wazuh-dashboard"]
TOOLS.extend([
    {
        "name": "get_service_action_target",
        "description": "Read the current state and allowed restart/reload actions of one fixed service. Package installation and container creation/configuration are unsupported.",
        "inputSchema": {"type": "object", "additionalProperties": False,
                        "properties": {"target": {"type": "string", "enum": SERVICE_TARGETS}}, "required": ["target"]},
        "annotations": {"title": "Read allowed service", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "propose_service_action",
        "description": "Request operator approval for a fixed restart/reload action, bound to the current service state. A worker executes once after approval and verifies the result. No arbitrary commands, package installation, or container configuration changes.",
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
            "target": {"type": "string", "enum": SERVICE_TARGETS},
            "action": {"type": "string", "enum": ["restart", "reload"]},
            "base_state_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "reason": {"type": "string", "minLength": 1, "maxLength": 200}},
            "required": ["target", "action", "base_state_sha256", "reason"]},
        "annotations": {"title": "Propose service action", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False},
    },
    {
        "name": "temporarily_contain_ip",
        "description": "On rule-a only, temporarily block a public external attacker IPv4 for 10 minutes if server-verified recent Suricata attack evidence meets the fixed threshold. Immediately ask the operator to keep it for 60 minutes or request release. Protected/private/management/DGX and active SSH addresses are refused. Repeated requests never extend the expiry. This is the only pre-approved emergency action; no rule or service changes occur.",
        "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
            "ip": {"type": "string"}, "reason": {"type": "string", "minLength": 1, "maxLength": 200}},
            "required": ["ip", "reason"]},
        "annotations": {"title": "Temporary evidence-checked containment", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
    },
    {
        "name": "get_operation_status",
        "description": "Read the approval, execution, verification, and expiry state of a service action or temporary containment by request_id.",
        "inputSchema": {"type": "object", "additionalProperties": False,
                        "properties": {"request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"}}, "required": ["request_id"]},
        "annotations": {"title": "Read operation status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
])


def _result(data, error=False):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, sort_keys=True)}], "isError": error}


def tool_list(access, host):
    """One owner per operation; fixed host scopes are also enforced by root."""
    if access not in {"read", "write"} or host not in {"a", "b"}:
        raise ValueError("invalid fixed MCP role")
    result = []
    for original in TOOLS:
        if (original["name"] in READ_TOOLS) != (access == "read"):
            continue
        if original["name"] == "temporarily_contain_ip" and host != "a":
            continue
        tool = copy.deepcopy(original)
        target = tool["inputSchema"]["properties"].get("target")
        if target:
            target["enum"] = [x for x in target["enum"] if x.startswith(host + ":")]
        result.append(tool)
    return result


def _call_helper(payload, readonly=False):
    request = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(request) > MAX_INPUT:
        return _result({"error": "request too large"}, True)
    try:
        proc = subprocess.run(
            ["/usr/bin/sudo", "-n", HELPER] + (["--read-only"] if readonly else []), input=request, capture_output=True,
            timeout=360 if payload.get("operation") in {"propose", "propose-edit", "service-propose", "contain-ip", "service-get"} else 45, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _result({"error": "rule-change helper unavailable"}, True)
    if len(proc.stdout) > MAX_OUTPUT:
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


def handle(message, access="write", host="a"):
    if not isinstance(message, dict):
        return None
    mid, method = message.get("id"), message.get("method")
    if method == "initialize":
        requested = (message.get("params") or {}).get("protocolVersion")
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": requested if requested in SUPPORTED else PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "capstone-rule-" + access + "-mcp", "version": "0.4.0"},
        }}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": tool_list(access, host)}}
    if method == "tools/call":
        params = message.get("params") or {}
        name, args = params.get("name"), params.get("arguments")
        advertised = {tool["name"]: tool for tool in tool_list(access, host)}
        if name not in advertised:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool for this role"}}
        if not isinstance(args, dict):
            return {"jsonrpc": "2.0", "id": mid, "result": _result({"error": "arguments must be an object"}, True)}
        target = advertised[name]["inputSchema"]["properties"].get("target")
        if target and args.get("target") not in target["enum"]:
            return {"jsonrpc": "2.0", "id": mid, "result": _result({"error": "target is not allowlisted on this host"}, True)}
        call_helper = lambda payload: _call_helper(payload, readonly=(access == "read"))
        if name == "get_rule_change_target":
            if set(args) != {"target"}:
                result = _result({"error": "required/unsupported arguments"}, True)
            else:
                result = call_helper({"operation": "get", **args})
        elif name == "propose_rule_edit":
            if set(args) != {"target", "base_sha256", "edits", "reason"}:
                result = _result({"error": "required/unsupported arguments"}, True)
            else:
                result = call_helper({"operation": "propose-edit", **args})
        elif name == "propose_rule_change":
            if set(args) != {"target", "base_sha256", "candidate_content", "reason"}:
                result = _result({"error": "required/unsupported arguments"}, True)
            else:
                result = call_helper({"operation": "propose", **args})
        elif name == "get_rule_change_status":
            if set(args) != {"proposal_id"}:
                result = _result({"error": "required/unsupported arguments"}, True)
            else:
                result = call_helper({"operation": "status", **args})
        elif name in {"get_service_action_target", "propose_service_action", "temporarily_contain_ip", "get_operation_status"}:
            operation, required = {
                "get_service_action_target": ("service-get", {"target"}),
                "propose_service_action": ("service-propose", {"target", "action", "base_state_sha256", "reason"}),
                "temporarily_contain_ip": ("contain-ip", {"ip", "reason"}),
                "get_operation_status": ("operation-status", {"request_id"}),
            }[name]
            result = call_helper({"operation": operation, **args}) if set(args) == required else _result({"error": "required/unsupported arguments"}, True)
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}
    if mid is None:
        return None
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}


def main():
    from pathlib import Path
    # Wrappers are root-owned forced commands. SSH_ORIGINAL_COMMAND is ignored.
    if sys.argv[1:] not in ([], ["--read-only"]):
        raise SystemExit(2)
    access = "read" if sys.argv[1:] == ["--read-only"] else "write"
    host = Path("/opt/rule-change/mcp-host").read_text().strip()
    tool_list(access, host)
    for line in sys.stdin.buffer:
        if len(line) > MAX_INPUT:
            continue
        try:
            reply = handle(json.loads(line), access, host)
        except (UnicodeDecodeError, ValueError, TypeError):
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
