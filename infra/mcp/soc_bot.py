#!/usr/bin/env python3
"""capstone SOC 챗봇 — Mattermost 연결. 표준 라이브러리만(오프라인). Groot_B 에서 실행.

두 가지 모드:
  report [minutes]   최근 경보를 조사해 인시던트 보고서를 MM 채널에 게시(incoming webhook). "에이전트 보고".
  serve              MM 슬래시 명령(/soc ...)을 받는 HTTP 서버. 사용자가 채팅에서 SOC 에이전트와 직접 상호작용.

읽기 전용(mcp-ro 계정)으로 Wazuh 인덱서(경보/취약점) + API(에이전트) 조회. 차단 등 대응은 응답 MCP(groot-resp)로 분리 유지.
설정은 env(soc_bot.env, 0640): IDX_*, WAPI_*, MM_WEBHOOK, SLASH_TOKEN, LISTEN. 비밀은 repo 에 두지 않음.
슬래시 명령: /soc help | alerts [분] | agents | vulns [agentId] | status | report [분]
"""
import json, os, ssl, sys, urllib.request, urllib.parse, time
from http.server import BaseHTTPRequestHandler, HTTPServer

CTX = ssl._create_unverified_context()   # 자체서명 인덱서/API
IDX = os.environ.get("IDX", "https://127.0.0.1:9200")
IDX_USER = os.environ.get("IDX_USER") or os.environ.get("WAZUH_INDEXER_USERNAME", "mcp-ro")
IDX_PASS = os.environ.get("IDX_PASS") or os.environ.get("WAZUH_INDEXER_PASSWORD", "")
WAPI = os.environ.get("WAPI", "https://127.0.0.1:55000")
WAPI_USER = os.environ.get("WAPI_USER") or os.environ.get("WAZUH_API_USERNAME", "mcp-ro")
WAPI_PASS = os.environ.get("WAPI_PASS") or os.environ.get("WAZUH_API_PASSWORD", "")
MM_WEBHOOK = os.environ.get("MM_WEBHOOK", "")
SLASH_TOKEN = os.environ.get("SLASH_TOKEN", "")
LISTEN = os.environ.get("LISTEN", "127.0.0.1:8090")


def _req(url, user=None, pw=None, data=None, headers=None, method=None):
    h = dict(headers or {})
    if user is not None:
        import base64
        h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    return urllib.request.urlopen(r, timeout=15, context=CTX)


def idx_search(index, body):
    return json.load(_req("%s/%s/_search" % (IDX, index), IDX_USER, IDX_PASS,
                          data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"))


def wapi_token():
    return _req("%s/security/user/authenticate?raw=true" % WAPI, WAPI_USER, WAPI_PASS, method="POST").read().decode()


def recent_alerts(minutes=15, min_level=5, size=200):
    body = {"size": size, "sort": [{"timestamp": "desc"}],
            "query": {"bool": {"filter": [
                {"range": {"timestamp": {"gte": "now-%dm" % minutes}}},
                {"range": {"rule.level": {"gte": min_level}}}]}}}
    try:
        hits = idx_search("wazuh-alerts-*", body)["hits"]["hits"]
    except Exception as e:
        return [], "인덱서 조회 실패: %s" % e
    rows = []
    for h in hits:
        s = h["_source"]; r = s.get("rule", {}); d = s.get("data", {})
        rows.append({"ts": s.get("timestamp", "")[11:19], "id": r.get("id"), "level": r.get("level"),
                     "desc": r.get("description", ""), "agent": s.get("agent", {}).get("name", ""),
                     "srcip": d.get("srcip") or (d.get("transaction") or {}).get("client_ip", ""),
                     "groups": r.get("groups", [])})
    return rows, None


def agg_alerts(minutes=15, min_level=5):
    body = {"size": 0, "query": {"bool": {"filter": [
        {"range": {"timestamp": {"gte": "now-%dm" % minutes}}},
        {"range": {"rule.level": {"gte": min_level}}}]}},
        "aggs": {"rules": {"terms": {"field": "rule.description", "size": 8}},
                 "src": {"terms": {"field": "data.srcip", "size": 8}},
                 "agent": {"terms": {"field": "agent.name", "size": 8}},
                 "total": {"value_count": {"field": "rule.id"}}}}
    try:
        a = idx_search("wazuh-alerts-*", body)["aggregations"]
    except Exception as e:
        return None, str(e)
    return {"total": a["total"]["value"],
            "rules": [(b["key"], b["doc_count"]) for b in a["rules"]["buckets"]],
            "src": [(b["key"], b["doc_count"]) for b in a["src"]["buckets"]],
            "agent": [(b["key"], b["doc_count"]) for b in a["agent"]["buckets"]]}, None


def list_agents():
    try:
        tk = wapi_token()
        d = json.load(_req("%s/agents?select=name,ip,status,version,os.name&limit=20" % WAPI,
                           headers={"Authorization": "Bearer " + tk}))["data"]["affected_items"]
        return [(x.get("id"), x.get("name"), x.get("status"), (x.get("os") or {}).get("name", ""), x.get("version", "")) for x in d], None
    except Exception as e:
        return None, str(e)


def vulns(agent="002", size=8):
    body = {"size": size, "sort": [{"vulnerability.severity": "desc"}],
            "query": {"bool": {"filter": [{"term": {"agent.name": "groot-web" if agent in ("002", "groot-web") else agent}}]}}}
    try:
        hits = idx_search("wazuh-states-vulnerabilities-*", body)["hits"]["hits"]
    except Exception as e:
        return None, str(e)
    return [(h["_source"].get("vulnerability", {}).get("id", "?"),
             h["_source"].get("vulnerability", {}).get("severity", "?"),
             (h["_source"].get("package", {}) or {}).get("name", "")) for h in hits], None


def post_mm(payload):
    if not MM_WEBHOOK:
        return False, "MM_WEBHOOK unset"
    try:
        _req(MM_WEBHOOK, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        return True, "ok"
    except Exception as e:
        return False, str(e)


def build_report(minutes):
    agg, err = agg_alerts(minutes)
    if err or not agg:
        return {"username": "SOC-Agent", "text": "인시던트 보고 생성 실패: %s" % (err or "no data")}
    rows, _ = recent_alerts(minutes, size=5)
    fields = []
    if agg["rules"]:
        fields.append({"short": False, "title": "탐지 규칙(상위)", "value": "\n".join("• %s — %d건" % (k, v) for k, v in agg["rules"])})
    if agg["src"]:
        fields.append({"short": True, "title": "공격 출처 IP", "value": "\n".join("%s (%d)" % (k, v) for k, v in agg["src"]) or "-"})
    if agg["agent"]:
        fields.append({"short": True, "title": "영향 자산", "value": "\n".join("%s (%d)" % (k, v) for k, v in agg["agent"]) or "-"})
    sample = "\n".join("`%s` id=%s lv%s %s [%s]" % (r["ts"], r["id"], r["level"], r["desc"][:50], r["srcip"]) for r in rows[:5])
    # 대응 판단(정책): 출처가 내부/관리 대역이면 자동차단 보류
    srcs = [k for k, _ in agg["src"]]
    internal = [s for s in srcs if s.startswith(("10.", "192.168.16.", "192.168.15."))]
    resp = ("자동 차단 보류: 출처(%s)가 내부/관리 대역(never_block) — 분석가 확인 요망." % ", ".join(internal)) if internal \
        else "권고: 외부 출처 → 응답도구로 차단 검토(`agent_block`/응답 MCP)."
    text = ("**조사 요약** (최근 %d분, level>=5 경보 %d건)\n%s\n\n**대응**: %s" % (minutes, agg["total"], sample, resp))
    return {"username": "SOC-Agent",
            "attachments": [{"color": "#d24b4b", "title": "🔴 SOC 인시던트 보고", "text": text, "fields": fields,
                             "footer": "capstone SOC agent", "ts": int(time.time())}]}


# ---- serve (Mattermost slash command) ----
def handle_slash(text):
    parts = (text or "").split()
    cmd = parts[0].lower() if parts else "help"
    arg = parts[1] if len(parts) > 1 else None
    if cmd in ("help", ""):
        return "ephemeral", ("**/soc** 명령: `alerts [분]` 최근 경보 · `agents` 에이전트 · `vulns [id]` 취약점 · "
                             "`status` 요약 · `report [분]` 채널에 인시던트 보고 게시")
    if cmd == "alerts":
        m = int(arg) if (arg and arg.isdigit()) else 15
        agg, err = agg_alerts(m)
        if err or not agg:
            return "ephemeral", "경보 조회 실패: %s" % (err or "no data")
        lines = ["**최근 %d분 경보** (level>=5, 총 %d건)" % (m, agg["total"])]
        lines += ["• %s — %d" % (k, v) for k, v in agg["rules"][:6]] or ["(없음)"]
        if agg["src"]: lines.append("출처: " + ", ".join("%s(%d)" % (k, v) for k, v in agg["src"][:5]))
        return "in_channel", "\n".join(lines)
    if cmd == "agents":
        ag, err = list_agents()
        if err: return "ephemeral", "에이전트 조회 실패: %s" % err
        return "in_channel", "**에이전트**\n" + "\n".join("• %s %s [%s] %s" % (i, n, st, os_) for i, n, st, os_, v in ag)
    if cmd == "vulns":
        v, err = vulns(arg or "002")
        if err: return "ephemeral", "취약점 조회 실패: %s" % err
        return "in_channel", "**취약점(%s) 상위**\n" % (arg or "groot-web") + "\n".join("• %s [%s] %s" % (c, sev, pk) for c, sev, pk in v[:8])
    if cmd == "status":
        ag, _ = list_agents(); agg, _ = agg_alerts(60)
        act = sum(1 for x in (ag or []) if x[2] == "active")
        return "in_channel", "**SOC 상태**: 에이전트 %d/%d active · 최근60분 경보 %d건" % (act, len(ag or []), (agg or {}).get("total", 0))
    if cmd == "report":
        m = int(arg) if (arg and arg.isdigit()) else 15
        ok, d = post_mm(build_report(m))
        return "ephemeral", ("인시던트 보고를 채널에 게시했습니다." if ok else "보고 게시 실패: %s" % d)
    return "ephemeral", "알 수 없는 명령: %s (`/soc help`)" % cmd


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); raw = self.rfile.read(n).decode()
        form = urllib.parse.parse_qs(raw)
        token = (form.get("token", [""])[0])
        if SLASH_TOKEN and token != SLASH_TOKEN:
            return self._json({"response_type": "ephemeral", "text": "unauthorized"}, 401)
        rtype, text = handle_slash(form.get("text", [""])[0])
        self._json({"response_type": rtype, "text": text})


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "help"
    if mode == "report":
        m = int(sys.argv[2]) if len(sys.argv) > 2 else 15
        ok, d = post_mm(build_report(m)); print("report posted:" if ok else "failed:", d); sys.exit(0 if ok else 1)
    if mode == "serve":
        host, port = LISTEN.split(":"); srv = HTTPServer((host, int(port)), Handler)
        print("soc_bot serve on %s" % LISTEN, file=sys.stderr); srv.serve_forever()
    print(__doc__)


if __name__ == "__main__":
    main()
