#!/usr/bin/env python3
"""capstone SOC 챗봇 — Mattermost 연결. 표준 라이브러리만(오프라인). Groot_B 에서 실행.

두 가지 모드:
  report [minutes]   최근 경보를 조사해 인시던트 보고서를 MM 채널에 게시(incoming webhook). "에이전트 보고".
  serve              MM 슬래시 명령(/soc ...)을 받는 HTTP 서버. 사용자가 채팅에서 SOC 에이전트와 직접 상호작용.

읽기 전용(mcp-ro 계정)으로 Wazuh 인덱서(경보/취약점) + API(에이전트) 조회. 차단 등 대응은 응답 MCP(groot-resp)로 분리 유지.
설정은 env(soc_bot.env, 0640): IDX_*, WAPI_*, MM_WEBHOOK, SLASH_TOKEN, LISTEN. 비밀은 repo 에 두지 않음.
슬래시 명령: /soc help | alerts [분] | agents | vulns [agentId] | status | report [분]

Tier 2 승인 브로커(2026-09-28): 응답 MCP 서버(A)가 차단 전에 여기로 승인을 요청하면 Mattermost 에 [승인][거부] 버튼 카드를 게시하고,
운영자가 누르면 MM 이 /actions 로 콜백 → 결정 저장 → 응답 서버가 /decision/<id> 를 폴링해 실행/중단. 무인 실행(Hermes cron)에서도 사람 승인이 붙는다.
  POST /approval   (X-Broker-Token)   {ip, minutes, reason, requested_by} → {req_id}
  POST /actions    (MM 버튼 콜백; 요청별 nonce 검증 + APPROVERS 검사)
  GET  /decision/<req_id> (X-Broker-Token) → {status: pending|approved|denied|expired, by}
  GET  /recent?minutes=&level= (X-Read-Token) → 최신 경보 지문(Hermes cron --monitor-script 용; 새 경보가 생길 때만 바뀜)
"""
import json, os, ssl, sys, urllib.request, urllib.parse, time, secrets, threading
from datetime import datetime, timedelta, timezone
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
# --- Tier 2 승인 브로커 / 모니터 지문 ---
BROKER_TOKEN = os.environ.get("BROKER_TOKEN", "")            # 응답 서버(A) ↔ 브로커 공유 비밀 (헤더 X-Broker-Token)
READ_TOKEN = os.environ.get("READ_TOKEN", "")                # /recent 읽기 토큰 (Hermes 모니터 스크립트, 헤더 X-Read-Token)
APPROVERS = [x for x in os.environ.get("APPROVERS", "").split(",") if x]   # 버튼 클릭 허용 MM user id 목록(빈값=누구나)
MM_ACTION_URL = os.environ.get("MM_ACTION_URL", "http://172.19.0.1:8090")  # MM(컨테이너)→브로커 콜백 베이스(SSRF allowlist 에 있어야 함)
APPROVAL_TTL = int(os.environ.get("APPROVAL_TTL", "900"))    # 승인 대기 상한(초). 지나면 expired = 미실행
APPROVALS = {}                                               # req_id → 레코드 (메모리; 재시작 시 대기 중 요청은 소멸=미실행)
_LOCK = threading.Lock()
KST = timezone(timedelta(hours=9), "KST")


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


def _alert_time_kst(value):
    """Wazuh 경보의 절대 시각을 보고서 표시용 KST로 변환한다."""
    if not value:
        return "시각 없음"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S KST")
    except ValueError:
        return "시각 형식 확인 필요"


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
        rows.append({"ts": _alert_time_kst(s.get("timestamp", "")), "id": r.get("id"), "level": r.get("level"),
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


def vuln_count(agent="groot-web"):
    try:
        r = json.load(_req("%s/wazuh-states-vulnerabilities-*/_count?q=agent.name:%s" % (IDX, agent), IDX_USER, IDX_PASS))
        return r.get("count")
    except Exception:
        return None


def build_summary(hours=12):
    """정기 상태 요약 — 이상 없어도 항상 payload 반환(정상이면 초록)."""
    mins = hours * 60
    ag, _ = list_agents()
    act = sum(1 for x in (ag or []) if x[2] == "active"); tot = len(ag or [])
    disc = [x[1] for x in (ag or []) if x[2] != "active"]
    agg, _ = agg_alerts(mins, min_level=5)
    total = (agg or {}).get("total", 0)
    vc = vuln_count("groot-web")
    if total == 0 and not disc:
        color, status = "#28a745", "🟢 이상 없음"
    elif total >= 20 or disc:
        color, status = "#d24b4b", "🔴 주의"
    else:
        color, status = "#e0a800", "🟡 관찰"
    fields = [{"short": True, "title": "에이전트", "value": "%d/%d active%s" % (act, tot, (" ⚠%s" % ",".join(disc)) if disc else "")},
              {"short": True, "title": "경보(level≥5, %dh)" % hours, "value": str(total)}]
    if agg and agg.get("rules"):
        fields.append({"short": False, "title": "상위 규칙", "value": "\n".join("• %s — %d" % (k, v) for k, v in agg["rules"][:5])})
    if agg and agg.get("src"):
        fields.append({"short": True, "title": "출처 IP", "value": "\n".join("%s(%d)" % (k, v) for k, v in agg["src"][:5]) or "-"})
    if vc is not None:
        fields.append({"short": True, "title": "취약점(groot-web)", "value": str(vc)})
    text = "정기 상태 요약 — %s. 최근 %dh: level≥5 경보 %d건. %s" % (
        status, hours, total, "추가 조치 없음(정상)" if (total == 0 and not disc) else "상세: 대시보드 / `/soc alerts`")
    return {"username": "SOC-Agent", "attachments": [{"color": color, "title": "%s · SOC 정기 상태 요약" % status,
            "text": text, "fields": fields, "footer": "capstone SOC agent (정기)", "ts": int(time.time())}]}


def post_mm(payload):
    if not MM_WEBHOOK:
        return False, "MM_WEBHOOK unset"
    try:
        _req(MM_WEBHOOK, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        return True, "ok"
    except Exception as e:
        return False, str(e)


def build_report(minutes):
    """payload dict | None(조용: 경보 0 → 게시 안 함) | {'error':...}"""
    agg, err = agg_alerts(minutes)
    if err:
        return {"error": err}
    if not agg or agg.get("total", 0) == 0:
        return None
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


# ---- Tier 2 승인 브로커 ----
def _expire_locked():
    now = time.time()
    for r in APPROVALS.values():
        if r["status"] == "pending" and now - r["ts"] > APPROVAL_TTL:
            r["status"] = "expired"


def approval_create(req):
    """응답 서버 호출: MM 에 [승인][거부] 버튼 카드 게시. (req_id, posted_ok, detail)"""
    rid, nonce = secrets.token_hex(8), secrets.token_hex(16)
    ip = str(req.get("ip", ""))[:45]; reason = str(req.get("reason", ""))[:80]; by = str(req.get("requested_by", "agent"))[:40]
    try:
        minutes = int(req.get("minutes", 10))
    except (TypeError, ValueError):
        minutes = 10
    rec = {"ip": ip, "minutes": minutes, "reason": reason, "requested_by": by, "nonce": nonce, "status": "pending", "by": "", "ts": time.time()}
    with _LOCK:
        _expire_locked(); APPROVALS[rid] = rec
    def act(name, decision, style):
        return {"id": decision, "name": name, "style": style,
                "integration": {"url": MM_ACTION_URL + "/actions", "context": {"req": rid, "nonce": nonce, "decision": decision}}}
    text = ("에이전트(**%s**)가 **%s** 를 **%d분** 차단하려 합니다.\n사유: `%s`\n요청 id `%s` · %d분 내 응답 없으면 자동 거부(미실행)"
            % (by, ip, minutes, reason, rid, APPROVAL_TTL // 60))
    payload = {"username": "SOC-Agent", "attachments": [{"color": "#e0a800", "title": "⚠️ 차단 승인 요청 (HITL Tier 2)", "text": text,
               "actions": [act("승인", "approve", "primary"), act("거부", "deny", "danger")], "footer": "capstone SOC HITL", "ts": int(time.time())}]}
    ok, d = post_mm(payload)
    if not ok:
        with _LOCK:
            rec["status"], rec["by"] = "error", d
    return rid, ok, d


def approval_action(body):
    """MM 버튼 클릭 콜백. 응답 = 원 카드 갱신(update) + 클릭자에게만 보이는 안내(ephemeral_text)."""
    ctx = body.get("context") or {}
    rid, decision = str(ctx.get("req", "")), str(ctx.get("decision", ""))
    uid, uname = str(body.get("user_id", "")), str(body.get("user_name", ""))
    with _LOCK:
        _expire_locked(); rec = APPROVALS.get(rid)
        if not rec or rec.get("nonce") != ctx.get("nonce"):
            return {"ephemeral_text": "알 수 없거나 만료된 승인 요청입니다."}
        if APPROVERS and uid not in APPROVERS:
            return {"ephemeral_text": "승인 권한이 없는 계정입니다 (@%s)." % uname}
        if rec["status"] != "pending":
            return {"ephemeral_text": "이미 처리됨: %s (by %s)" % (rec["status"], rec["by"])}
        rec["status"] = "approved" if decision == "approve" else "denied"
        rec["by"] = uname or uid; rec["decided_ts"] = time.time(); st = rec["status"]
    label = "✅ 승인됨" if st == "approved" else "❌ 거부됨"
    props = {"attachments": [{"color": "#28a745" if st == "approved" else "#d24b4b",
             "title": "%s · %s 차단 %d분" % (label, rec["ip"], rec["minutes"]),
             "text": "결정: **%s** by @%s · 사유 `%s` · id `%s`" % (st, rec["by"], rec["reason"], rid),
             "footer": "capstone SOC HITL", "ts": int(time.time())}]}
    return {"update": {"message": "", "props": props}, "ephemeral_text": "%s 처리했습니다." % label}


def approval_decision(rid):
    with _LOCK:
        _expire_locked(); rec = APPROVALS.get(rid)
        if not rec:
            return None
        return {"req_id": rid, "status": rec["status"], "by": rec["by"], "ip": rec["ip"], "minutes": rec["minutes"]}


def recent_fingerprint(minutes=60, min_level=10, n=5):
    """Hermes cron --monitor-script 용 지문: 최신 n건(level>=min_level, 최근 minutes분)만, 절대 타임스탬프로.
    새 경보가 생길 때만 바이트가 바뀐다(오래된 경보가 창을 벗어나도 최신 n건은 그대로)."""
    body = {"size": n, "sort": [{"timestamp": "desc"}, {"rule.id": "desc"}],
            "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-%dm" % minutes}}},
                                          {"range": {"rule.level": {"gte": min_level}}}]}}}
    try:
        hits = idx_search("wazuh-alerts-*", body)["hits"]["hits"]
    except Exception as e:
        return {"error": str(e)}
    out = []
    for h in hits:
        s = h["_source"]; r = s.get("rule", {}); d = s.get("data", {})
        out.append({"ts": s.get("timestamp", ""), "id": r.get("id"), "level": r.get("level"), "agent": s.get("agent", {}).get("name", ""),
                    "srcip": d.get("srcip") or (d.get("transaction") or {}).get("client_ip", ""), "desc": r.get("description", "")[:60]})
    return {"latest": out}


# ---- serve (Mattermost slash command) ----
def handle_slash(text):
    parts = (text or "").split()
    cmd = parts[0].lower() if parts else "help"
    arg = parts[1] if len(parts) > 1 else None
    if cmd in ("help", ""):
        return "ephemeral", ("**/soc** 명령: `alerts [분]` 최근 경보 · `agents` 에이전트 · `vulns [id]` 취약점 · "
                             "`status` 한줄 요약 · `report [분]` 인시던트 보고 게시 · `summary [시간]` 정기 상태요약 게시")
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
    if cmd == "summary":
        h = int(arg) if (arg and arg.isdigit()) else 12
        ok, d = post_mm(build_summary(h))
        return "ephemeral", ("정기 상태 요약을 채널에 게시했습니다." if ok else "요약 게시 실패: %s" % d)
    if cmd == "report":
        m = int(arg) if (arg and arg.isdigit()) else 15
        rep = build_report(m)
        if rep is None:
            return "ephemeral", "최근 %d분 인시던트 없음 — 게시하지 않음." % m
        if "error" in rep:
            return "ephemeral", "보고 생성 실패: %s" % rep["error"]
        ok, d = post_mm(rep)
        return "ephemeral", ("인시던트 보고를 채널에 게시했습니다." if ok else "보고 게시 실패: %s" % d)
    return "ephemeral", "알 수 없는 명령: %s (`/soc help`)" % cmd


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(min(n, 1 << 20)).decode() if n else ""
    def _tok_ok(self, header, expected):
        return bool(expected) and self.headers.get(header, "") == expected
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path.startswith("/decision/"):
            if not self._tok_ok("X-Broker-Token", BROKER_TOKEN):
                return self._json({"error": "unauthorized"}, 401)
            d = approval_decision(u.path.rsplit("/", 1)[1])
            return self._json(d or {"error": "not found"}, 200 if d else 404)
        if u.path == "/pending":                        # 대기 중 승인 요청 목록 (브로커 토큰)
            if not self._tok_ok("X-Broker-Token", BROKER_TOKEN):
                return self._json({"error": "unauthorized"}, 401)
            with _LOCK:
                _expire_locked()
                pend = [{"req_id": k, "ip": v["ip"], "minutes": v["minutes"], "reason": v["reason"], "age_s": int(time.time() - v["ts"])}
                        for k, v in APPROVALS.items() if v["status"] == "pending"]
            return self._json({"pending": pend})
        if u.path.startswith("/nonce/"):                # 자동 검증용: 요청 생성자(브로커 토큰 보유)만 nonce 조회 가능
            if not self._tok_ok("X-Broker-Token", BROKER_TOKEN):
                return self._json({"error": "unauthorized"}, 401)
            with _LOCK:
                rec = APPROVALS.get(u.path.rsplit("/", 1)[1])
            return self._json({"nonce": rec["nonce"]} if rec else {"error": "not found"}, 200 if rec else 404)
        if u.path == "/recent":
            if not self._tok_ok("X-Read-Token", READ_TOKEN):
                return self._json({"error": "unauthorized"}, 401)
            try:
                m = int(q.get("minutes", ["60"])[0]); lv = int(q.get("level", ["10"])[0])
            except ValueError:
                return self._json({"error": "bad query"}, 400)
            return self._json(recent_fingerprint(m, lv))
        return self._json({"error": "not found"}, 404)
    def do_POST(self):
        u = urllib.parse.urlparse(self.path); raw = self._body()
        if u.path == "/approval":                       # 응답 서버(A) → 승인 카드 생성
            if not self._tok_ok("X-Broker-Token", BROKER_TOKEN):
                return self._json({"error": "unauthorized"}, 401)
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            rid, ok, d = approval_create(req)
            return self._json({"req_id": rid, "posted": ok, "detail": d}, 200 if ok else 502)
        if u.path == "/actions":                        # Mattermost 버튼 클릭 콜백(JSON)
            try:
                body = json.loads(raw or "{}")
            except ValueError:
                return self._json({"ephemeral_text": "bad request"}, 400)
            return self._json(approval_action(body if isinstance(body, dict) else {}))
        form = urllib.parse.parse_qs(raw)               # 슬래시 명령 /soc (form-urlencoded)
        token = (form.get("token", [""])[0])
        if SLASH_TOKEN and token != SLASH_TOKEN:
            return self._json({"response_type": "ephemeral", "text": "unauthorized"}, 401)
        rtype, text = handle_slash(form.get("text", [""])[0])
        self._json({"response_type": rtype, "text": text})


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "help"
    if mode == "report":
        m = int(sys.argv[2]) if len(sys.argv) > 2 else 15
        rep = build_report(m)
        if rep is None:
            print("no incidents in last %dm; nothing posted" % m); sys.exit(0)   # 주기 실행 시 조용하면 스킵
        if "error" in rep:
            print("report error:", rep["error"]); sys.exit(1)
        ok, d = post_mm(rep); print("report posted:" if ok else "failed:", d); sys.exit(0 if ok else 1)
    if mode == "summary":
        h = int(sys.argv[2]) if len(sys.argv) > 2 else 12
        ok, d = post_mm(build_summary(h)); print("summary posted:" if ok else "failed:", d); sys.exit(0 if ok else 1)
    if mode == "serve":
        host, port = LISTEN.split(":"); srv = HTTPServer((host, int(port)), Handler)
        print("soc_bot serve on %s" % LISTEN, file=sys.stderr); srv.serve_forever()
    print(__doc__)


if __name__ == "__main__":
    main()
