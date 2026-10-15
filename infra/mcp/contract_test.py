#!/usr/bin/env python3
"""AI와 무관한 MCP 서버 계약 테스트 (stdio). 표준 라이브러리만 사용.

서버를 명령으로 띄우고 JSON-RPC로 initialize -> notifications/initialized -> tools/list -> tools/call 을 수행한다.
어떤 에이전트 런타임(Claude Code / Hermes / 커스텀)을 붙이기 전에 "서버 자체"를 검증하는 용도.
클라이언트 호스트에는 자격증명이 없다(서버가 B에서 env 로 가진다).

사용:
  python3 contract_test.py                                   # 기본: ssh -T groot-mcp
  python3 contract_test.py --cmd "ssh -T groot-mcp-direct"
  python3 contract_test.py --tool get_wazuh_alert_summary --args '{"limit": 5}'
  python3 contract_test.py --tool get_wazuh_agents --args '{"status":"active"}'
종료코드 0 = 계약 통과.
"""
import argparse, json, queue, shlex, subprocess, sys, threading, time

PROTOCOL = "2025-06-18"


def start(cmd):
    p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    q = queue.Queue()
    def pump(stream, tag):
        for raw in iter(stream.readline, b""):
            q.put((tag, raw.decode("utf-8", "replace").rstrip("\n")))
        q.put((tag, None))
    threading.Thread(target=pump, args=(p.stdout, "out"), daemon=True).start()
    threading.Thread(target=pump, args=(p.stderr, "err"), daemon=True).start()
    return p, q


def send(p, obj):
    p.stdin.write((json.dumps(obj) + "\n").encode())
    p.stdin.flush()


def wait_for(q, want_id, timeout, stderr_lines, violations):
    """want_id 응답을 기다린다. stdout의 비-JSON 줄은 계약 위반으로 기록."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            tag, line = q.get(timeout=0.5)
        except queue.Empty:
            continue
        if line is None:
            if tag == "out":
                raise RuntimeError("server closed stdout before answering id=%s" % want_id)
            continue
        if tag == "err":
            stderr_lines.append(line)
            continue
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            violations.append(line[:200])
            continue
        if msg.get("id") == want_id:
            return msg
        # 알림/다른 id 는 무시
    raise TimeoutError("no response for id=%s within %ss" % (want_id, timeout))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", default="ssh -T groot-mcp", help="MCP 서버를 stdio 로 띄우는 명령")
    ap.add_argument("--tool", default="get_wazuh_alert_summary")
    ap.add_argument("--args", default='{"limit": 5}', help="tools/call arguments (JSON)")
    ap.add_argument("--timeout", type=float, default=60)
    a = ap.parse_args()

    ok = True
    stderr_lines, violations = [], []
    print("== start: %s" % a.cmd)
    p, q = start(a.cmd)
    try:
        send(p, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "capstone-contract-test", "version": "1"}}})
        r = wait_for(q, 1, a.timeout, stderr_lines, violations)
        res = r.get("result") or {}
        print("== initialize: server=%s protocol=%s caps=%s" % (res.get("serverInfo"), res.get("protocolVersion"), list((res.get("capabilities") or {}).keys())))
        if "result" not in r:
            ok = False; print("   !! initialize error:", r.get("error"))
        if res.get("protocolVersion") not in ("2024-11-05", "2025-03-26", "2025-06-18"):
            ok = False; print("   !! unexpected protocolVersion:", res.get("protocolVersion"))
        send(p, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        send(p, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        r = wait_for(q, 2, a.timeout, stderr_lines, violations)
        tools = (r.get("result") or {}).get("tools") or []
        print("== tools/list: %d tools" % len(tools))
        for t in tools:
            schema = t.get("inputSchema") or {}
            props = list((schema.get("properties") or {}).keys())
            req = schema.get("required") or []
            print("   - %-36s args=%s%s" % (t["name"], props, (" required=%s" % req) if req else ""))
        if not tools:
            ok = False; print("   !! no tools:", r.get("error"))
        names = {t["name"] for t in tools}
        if a.tool not in names:
            ok = False; print("   !! requested tool not offered:", a.tool)

        send(p, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": a.tool, "arguments": json.loads(a.args)}})
        r = wait_for(q, 3, a.timeout, stderr_lines, violations)
        if "error" in r:
            ok = False; print("== tools/call %s: RPC error %s" % (a.tool, r["error"]))
        else:
            res = r["result"]
            texts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
            body = "\n".join(texts)
            print("== tools/call %s: isError=%s, %d chars" % (a.tool, res.get("isError", False), len(body)))
            print("\n".join("   | " + l for l in body.splitlines()[:25]))
            if res.get("isError"):
                ok = False
            elif body.lstrip().lower().startswith(("error", "failed")):
                ok = False; print("   !! tool returned error text without isError")
    except Exception as e:
        ok = False; print("!! exception:", e)
    finally:
        try: p.stdin.close()
        except Exception: pass
        try: p.wait(timeout=5)
        except Exception: p.kill()

    if violations:
        ok = False
        print("== CONTRACT VIOLATION: %d non-JSON line(s) on stdout (logs must go to stderr):" % len(violations))
        for v in violations[:5]: print("   ", v)
    if stderr_lines:
        print("== stderr (%d lines, last 5):" % len(stderr_lines))
        for l in stderr_lines[-5:]: print("   ", l[:200])
    print("== RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
