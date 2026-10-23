#!/usr/bin/env python3
"""capstone 응답(차단) MCP 서버 — Groot_A에서 실행. stdio JSON-RPC(표준 라이브러리만, 오프라인).

에이전트(Claude Code / Hermes 등)는 `ssh -T groot-resp` 로 이 서버를 stdio MCP 로 띄운다(A의 sshd forced command).
자격증명은 A의 root 전용 설정에만 있다. resp는 인자 없는 root MCP 진입점만 sudo 실행하며
하위 helper를 직접 실행할 수 없다. 이 서버가 승인을 확인한 뒤 고정 private helper를 호출한다.
읽기 서버(B의 mcp-server-wazuh)와 분리 = 최소권한. 정책 엔진(TTL 상한·reason 필수·flush 미노출)은 여기.

툴:
  block_ip(ip, minutes=10, reason)   -> agent_block add ip <minutes>m <reason>   (minutes 1..RESP_MAX_MINUTES)
  unblock_ip(ip, reason="manual")     -> agent_block del ip - <reason>
  list_blocks()                       -> agent_block list

주의: stdout 은 JSON-RPC 채널 — 진단은 전부 stderr. 성공/실패는 tool result 의 isError 로.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

try:
    import notifier  # /opt/resp/notifier.py (same dir); optional
except Exception:
    notifier = None

PROTOCOL = "2025-06-18"
SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
SUDO = "/usr/bin/sudo"
AGENT_BLOCK = os.environ.get("RESP_AGENT_BLOCK", "/usr/local/sbin/agent_block")


def _envint(name, default):
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


MAX_MINUTES = max(1, _envint("RESP_MAX_MINUTES", 120))   # 자동 대응 상한(분). A의 agent_block 은 24h 까지 허용하지만 정책은 더 보수적.
DEF_MINUTES = min(max(1, _envint("RESP_DEFAULT_MINUTES", 10)), MAX_MINUTES)
MAX_RPC_CHARS = 65536
REASON_RE = re.compile(r"[^A-Za-z0-9._:/-]+")
IPRE = re.compile(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$")

TOOLS = [
    {
        "name": "block_ip",
        "description": "Block a source IPv4 at the Groot_A gateway firewall for a limited time (nftables agent_block set). "
                       "Requires operator approval and refuses protected/management addresses and IPs with an active SSH session. Use for external attacker IPs seen in Wazuh alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "attacker IPv4, e.g. 203.0.113.7"},
                "minutes": {"type": "integer", "description": "block duration in minutes (1..%d, default %d)" % (MAX_MINUTES, DEF_MINUTES)},
                "reason": {"type": "string", "description": "why (e.g. Wazuh alert id / rule id). Required for audit."},
            },
            "required": ["ip", "reason"],
        },
        # 쓰기·파괴적: 승인 브로커 설정과 운영자 승인(Mattermost 버튼)이 반드시 필요하다.
        "annotations": {"title": "Block IP (operator approval required)", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
    },
    {
        "name": "unblock_ip",
        "description": "Request operator approval to remove a previously blocked IPv4 from the Groot_A firewall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["ip"],
        },
        "annotations": {"title": "Unblock IP", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "list_blocks",
        "description": "List currently blocked IPv4 addresses and their remaining time (seconds).",
        "inputSchema": {"type": "object", "properties": {}},
        # 읽기 전용 표시 → Hermes 의 untrusted 신뢰 게이트에서 승인 없이 호출 가능.
        "annotations": {"title": "List blocks", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
]

# --- Tier 2 승인 브로커(B soc_bot) — 차단은 운영자 승인 후에만. env 는 run-response.sh 가 /etc/resp/hitl.env 에서 source ---
BROKER_URL = os.environ.get("RESP_BROKER_URL", "").rstrip("/")       # 예: http://10.200.10.10:8090
BROKER_TOKEN = os.environ.get("RESP_BROKER_TOKEN", "")
APPROVAL_TIMEOUT = max(30, _envint("RESP_APPROVAL_TIMEOUT", 600))    # 초. Hermes 쪽 MCP tool timeout 보다 작아야 함
APPROVAL_POLL = max(2, _envint("RESP_APPROVAL_POLL", 5))


def log(*a):
    print("response-mcp:", *a, file=sys.stderr, flush=True)


def run_agent_block(args):
    """sudo -n agent_block <args>. returns (exit_code, stdout, stderr)."""
    cmd = [SUDO, "-n", AGENT_BLOCK] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "agent_block timed out"
    except Exception as e:
        return 1, "", "exec failed: %s" % e


def tool_text(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


EXIT_MEANING = {0: "ok", 1: "agent_block internal (not root / fw sets missing / sudo denied)", 2: "invalid argument",
                3: "rejected (protected IP or active SSH session)", 4: "firewall error", 124: "timeout"}


def norm_reason(reason, default=""):
    reason = REASON_RE.sub("_", str(reason).strip())[:64]
    return reason or default


def notify_event(ev):
    """알림 채널로 best-effort 푸시(백엔드는 env, 기본 none). stdout 은 절대 건드리지 않음(로그는 stderr)."""
    be = os.environ.get("RESP_NOTIFY_BACKEND", "none")
    if not notifier or be in ("", "none"):
        return
    try:
        ok, detail = notifier.send(be, ev)
        if not ok:
            log("notify(%s) failed:" % be, detail)
    except Exception as e:
        log("notify error:", e)


def _broker(method, path, body=None):
    req = urllib.request.Request(BROKER_URL + path, data=(json.dumps(body).encode() if body is not None else None), method=method,
                                 headers={"Content-Type": "application/json", "X-Broker-Token": BROKER_TOKEN})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def request_approval(ip, minutes, reason, action="block"):
    """Wait for a bound operator decision and consume it once. Always fail closed."""
    if not BROKER_URL or not BROKER_TOKEN:
        return "error", "approval broker is not configured"
    if action not in {"block", "unblock"} or (action == "unblock" and minutes != 0):
        return "error", "invalid approval action"
    identity = {"action": action, "ip": ip, "minutes": minutes}
    try:
        r = _broker("POST", "/approval", {**identity, "reason": reason, "requested_by": "hermes"})
    except Exception:
        return "error", "approval broker unavailable"
    if not isinstance(r, dict):
        return "error", "invalid approval response"
    rid = r.get("req_id")
    if not isinstance(rid, str) or not re.fullmatch(r"[0-9a-f]{16}", rid) or not r.get("posted"):
        return "error", "approval card was not posted"
    log("approval requested id=%s action=%s (waiting up to %ds)" % (rid, action, APPROVAL_TIMEOUT))
    deadline = time.monotonic() + APPROVAL_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(APPROVAL_POLL)
        try:
            d = _broker("GET", "/decision/%s" % rid)
        except Exception:
            continue
        if not isinstance(d, dict) or any(d.get(k) != v for k, v in identity.items()) or d.get("req_id") != rid:
            return "error", "approval identity mismatch"
        st = d.get("status")
        if st in {"denied", "expired"}:
            return st, d.get("by", "")
        if st == "approved":
            if not isinstance(d.get("by"), str) or not d["by"]:
                return "error", "missing approving operator"
            try:
                consumed = _broker("POST", "/consume", {"request_id": rid, **identity})
            except Exception:
                return "error", "approval could not be consumed"
            if (not isinstance(consumed, dict) or consumed.get("status") != "consumed"
                    or consumed.get("req_id") != rid or consumed.get("by") != d["by"]
                    or any(consumed.get(k) != v for k, v in identity.items())):
                return "error", "invalid approval consumption"
            return "approved", d["by"]
        if st not in {"pending", "posting"}:
            return "error", "approval is not executable"
    return "expired", "approval wait timed out"


def call_tool(name, args):
    if name == "block_ip":
        ip = str(args.get("ip", "")).strip()
        reason = str(args.get("reason", "")).strip()
        if not IPRE.match(ip):
            return tool_text("Invalid IPv4: %r" % ip, True)
        if not reason:
            return tool_text("reason is required (for audit)", True)
        reason = norm_reason(reason, "mcp")
        minutes = args.get("minutes", DEF_MINUTES)
        try:
            minutes = int(minutes)
        except (TypeError, ValueError):
            return tool_text("minutes must be an integer", True)
        if not (1 <= minutes <= MAX_MINUTES):
            return tool_text("minutes out of range (1..%d)" % MAX_MINUTES, True)
        # Tier 2: 지정 승인자의 일회성 승인 없이는 실행하지 않는다.
        st, who = request_approval(ip, minutes, reason)
        if st == "denied":
            notify_event({"kind": "rejected", "action": "block", "ip": ip, "reason": "operator_denied", "by": who})
            return tool_text("block_ip DENIED by operator %s - NOT executed" % who, True)
        if st != "approved":
            notify_event({"kind": "rejected", "action": "block", "ip": ip, "reason": "approval_%s" % st, "detail": who})
            return tool_text("block_ip NOT executed: approval %s (%s). Ask the operator and retry only if they confirm." % (st, who), True)
        approved_by = who
        rc, out, err = run_agent_block(["add", ip, "%dm" % minutes, reason])
        if rc == 0:
            notify_event({"kind": "block", "ip": ip, "minutes": minutes, "reason": reason, "by": "mcp", "approved_by": approved_by})
            return tool_text("BLOCKED %s for %dm (approved by %s; %s)" % (ip, minutes, approved_by, out or "ok"))
        if rc == 3:
            notify_event({"kind": "rejected", "action": "block", "ip": ip, "reason": "protected_or_active_session"})
        return tool_text("block_ip failed: %s [%s] %s" % (EXIT_MEANING.get(rc, "error %d" % rc), rc, err or out), True)
    if name == "unblock_ip":
        ip = str(args.get("ip", "")).strip()
        reason = norm_reason(args.get("reason", "manual"), "manual")
        if not IPRE.match(ip):
            return tool_text("Invalid IPv4: %r" % ip, True)
        st, who = request_approval(ip, 0, reason, action="unblock")
        if st != "approved":
            return tool_text("unblock_ip NOT executed: approval %s (%s)" % (st, who), True)
        rc, out, err = run_agent_block(["del", ip, "-", reason])
        if rc == 0:
            notify_event({"kind": "unblock", "ip": ip, "reason": reason})
            return tool_text("UNBLOCKED %s (%s)" % (ip, out or "ok"))
        return tool_text("unblock_ip failed: %s [%s] %s" % (EXIT_MEANING.get(rc, "error %d" % rc), rc, err or out), True)
    if name == "list_blocks":
        rc, out, err = run_agent_block(["list"])
        if rc == 0:
            return tool_text(out if out else "(no active blocks)")
        return tool_text("list_blocks failed: %s [%s] %s" % (EXIT_MEANING.get(rc, "error %d" % rc), rc, err), True)
    return None  # unknown tool


def reply(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def handle(msg):
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        req_ver = ((msg.get("params") or {}).get("protocolVersion"))
        ver = req_ver if req_ver in SUPPORTED_PROTOCOLS else PROTOCOL
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": ver,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "capstone-response-mcp", "version": "1.1.0"},
        }}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None  # notification, no reply
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        res = call_tool(name, args)
        if res is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool: %s" % name}}
        return {"jsonrpc": "2.0", "id": mid, "result": res}
    if mid is None:
        return None  # unknown notification
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found: %s" % method}}


def main():
    log("started (agent_block=%s, max=%dm)" % (AGENT_BLOCK, MAX_MINUTES))
    while True:
        line = sys.stdin.readline(MAX_RPC_CHARS + 1)
        if not line:
            break
        if len(line) > MAX_RPC_CHARS:
            log("request exceeds bounded protocol input; closing")
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log("bad json on stdin:", e)
            continue
        if not isinstance(msg, dict):
            log("non-object JSON on stdin, ignoring")
            continue
        try:
            out = handle(msg)
        except Exception as e:
            log("handler error:", e)
            out = {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None, "error": {"code": -32603, "message": "internal error"}}
        if out is not None:
            reply(out)
    log("stdin closed, exiting")


if __name__ == "__main__":
    main()
