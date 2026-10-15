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

룰 변경 승인은 위의 IP 차단 경로와 독립적이다. RULE_BROKER_TOKEN(32자 이상, BROKER_TOKEN과 다른 값),
APPROVERS 또는 RULE_APPROVERS, RULE_MM_SOURCE_CIDRS(Mattermost 서버 TCP peer IP/CIDR)가 모두 필수다.
미설정/오설정이면 룰 변경 경로는 fail-closed다. 승인 요청은 대상/기준·후보 해시/전체 diff/만료시각을
고정하고, Mattermost 비공개 context nonce·승인자 ID·TCP peer 출처를 확인한 뒤 1회만 소비된다.
승인 상태는 메모리에만 있어 soc-bot 재시작 시 대기/승인 요청이 사라지며 실행기는 미승인으로 중단한다.
  GET  /rule-changes/health            (요청·응답 HMAC) → 인증된 브로커 준비 상태
  POST /rule-changes                   (요청·응답 HMAC) → 제안/승인 카드
  GET  /rule-changes/<proposal_id>     (요청·응답 HMAC) → 결정 상태와 바인딩 해시
  POST /rule-changes/<id>/consume      (요청·응답 HMAC) → 승인 1회 소비
  POST /rule-changes/<id>/result       (요청·응답 HMAC) → 적용 결과 카드 1회 게시
  POST /rule-changes/<id>/abort        (HMAC) → 승인됐지만 소비 전 검증 실패 시 미적용 카드
  POST /rule-actions                   (Mattermost callback; 출처 + 비공개 nonce 확인)
"""
import hashlib, hmac, ipaddress, json, os, re, ssl, sys, unicodedata, urllib.request, urllib.parse, time, secrets, threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
APPROVERS = [x.strip() for x in os.environ.get("APPROVERS", "").split(",") if x.strip()]  # Empty disables approval.
MM_ACTION_URL = os.environ.get("MM_ACTION_URL", "http://172.19.0.1:8090")  # MM(컨테이너)→브로커 콜백 베이스(SSRF allowlist 에 있어야 함)
APPROVAL_TTL = int(os.environ.get("APPROVAL_TTL", "900"))    # 승인 대기 상한(초). 지나면 expired = 미실행
APPROVALS = {}                                               # req_id → 레코드 (메모리; 재시작 시 대기 중 요청은 소멸=미실행)
# 규칙 변경 브로커는 기존 IP 차단 승인과 자격·상태·콜백을 분리한다.
# 토큰/명시적 승인자 중 하나라도 없으면 이 API는 열리지 않는다.
RULE_BROKER_TOKEN = os.environ.get("RULE_BROKER_TOKEN", "")
RULE_APPROVERS = frozenset(x.strip() for x in os.environ.get("RULE_APPROVERS", os.environ.get("APPROVERS", "")).split(",") if x.strip())
def _rule_source_networks(raw):
    if not raw.strip():
        return ()
    try:
        networks = tuple(ipaddress.ip_network(x.strip(), strict=False) for x in raw.split(","))
    except ValueError:
        return ()
    # A wildcard source cannot authenticate a Mattermost callback.
    return networks if all(n.prefixlen > 0 for n in networks) else ()


RULE_MM_SOURCES = _rule_source_networks(os.environ.get("RULE_MM_SOURCE_CIDRS", ""))
RULE_TARGETS = frozenset(("a:modsecurity-custom", "a:suricata-local", "b:wazuh-local-rules"))
RULE_APPROVALS = {}
RULE_NONCES = {}                # authenticated request nonce → arrival time; replay cache
RULE_DIFF_MAX_BYTES = 512 * 1024  # Complete diff; large reviews are posted in numbered parts.
RULE_REVIEW_PART_MAX_BYTES = 8 * 1024  # Bound both raw UTF-8 and the indented display.
RULE_CARD_MAX_CHARS = 12_000
RULE_POST_MAX_SECONDS = 90
RULE_CREATE_BODY_MAX_BYTES = 4 * 1024 * 1024  # Includes JSON escaping of a 512 KiB diff.
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
    """명시된 offset으로만 KST 표시를 만들고, 시간대 없는 시각은 추정하지 않는다."""
    if not value:
        return "시각 없음"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return "%s (시간대 확인 필요)" % dt.isoformat(sep=" ")
        return dt.astimezone(KST).strftime("%Y-%m-%d %H:%M:%S" + (".%f" if dt.microsecond else "") + " KST")
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
    for rid, r in list(APPROVALS.items()):
        if r["status"] in ("posting", "pending", "approved") and now - r["ts"] >= APPROVAL_TTL:
            r["status"] = "expired"
        if r["status"] not in ("posting", "pending", "approved") and now - r["ts"] > APPROVAL_TTL + 3600:
            del APPROVALS[rid]


def _legacy_approval_enabled():
    return bool(BROKER_TOKEN and APPROVERS and RULE_MM_SOURCES and MM_WEBHOOK and MM_ACTION_URL)


def _approval_public(rid, rec):
    return {"req_id": rid, "request_id": rid, "status": rec["status"], "by": rec["by"],
            "action": rec["action"], "ip": rec["ip"], "minutes": rec["minutes"]}


def approval_create(req):
    """응답 서버 호출: MM 에 [승인][거부] 버튼 카드 게시. (req_id, posted_ok, detail)"""
    if not _legacy_approval_enabled():
        return "", False, "approval is not configured"
    if not isinstance(req, dict) or set(req) - {"ip", "minutes", "reason", "requested_by", "action"}:
        return "", False, "invalid approval fields"
    action = req.get("action", "block")
    ip, minutes = req.get("ip"), req.get("minutes", 10)
    reason, by = req.get("reason", ""), req.get("requested_by", "agent")
    try:
        address = ipaddress.ip_address(ip)
        if (not isinstance(ip, str) or str(address) != ip or action not in ("block", "unblock") or
                type(minutes) is not int or (not 1 <= minutes <= 1440 if action == "block" else minutes != 0) or
                not isinstance(reason, str) or not 1 <= len(reason) <= 200 or
                any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in reason) or
                not isinstance(by, str) or not re.fullmatch(r"[a-zA-Z0-9_.:@-]{1,80}", by)):
            return "", False, "invalid approval action, IP, duration or reason"
    except (ValueError, TypeError):
        return "", False, "invalid approval IP"
    rid, nonce = secrets.token_hex(8), secrets.token_hex(16)
    rec = {"action": action, "ip": ip, "minutes": minutes, "reason": reason, "requested_by": by,
           "nonce": nonce, "status": "posting", "by": "", "ts": time.time()}
    with _LOCK:
        _expire_locked()
        if sum(r["status"] in ("posting", "pending", "approved") for r in APPROVALS.values()) >= 64:
            return "", False, "too many active approvals"
        APPROVALS[rid] = rec
    def act(name, decision, style):
        return {"id": decision, "name": name, "style": style,
                "integration": {"url": MM_ACTION_URL + "/actions", "context": {
                    "req": rid, "nonce": nonce, "decision": decision, "action": action}}}
    operation = "%d분 차단" % minutes if action == "block" else "차단 해제"
    text = ("에이전트 `%s`가 `%s`에 %s 작업을 요청했습니다.\n작업: `%s`\n사유:\n\n    %s\n\n"
            "요청 id `%s` · %d분 내 응답 없으면 미실행. 이 IP의 해당 작업 한 번만 승인합니다." %
            (by, ip, operation, action, reason, rid, APPROVAL_TTL // 60))
    payload = {"username": "SOC-Agent", "attachments": [{"color": "#e0a800", "title": "⚠️ %s 승인 요청 (HITL Tier 2)" % operation, "text": text,
               "actions": [act("승인", "approve", "primary"), act("거부", "deny", "danger")], "footer": "capstone SOC HITL", "ts": int(time.time())}]}
    posted, _ = post_mm(payload)
    with _LOCK:
        _expire_locked()
        if rec["status"] == "posting":
            rec["status"] = "pending" if posted else "error"
        ok = posted and rec["status"] == "pending"
    return rid, ok, "ok" if ok else "approval card failed or expired; approval is disabled"


def approval_action(body, peer_ip):
    """MM 버튼 클릭 콜백. 응답 = 원 카드 갱신(update) + 클릭자에게만 보이는 안내(ephemeral_text)."""
    if not _legacy_approval_enabled() or not _rule_source_ok(peer_ip) or not isinstance(body, dict):
        return {"ephemeral_text": "승인 설정 또는 콜백 출처가 허용되지 않았습니다."}
    ctx = body.get("context")
    if not isinstance(ctx, dict):
        return {"ephemeral_text": "유효하지 않은 승인 요청입니다."}
    rid, decision, uid = ctx.get("req"), ctx.get("decision"), body.get("user_id")
    if not isinstance(rid, str) or decision not in ("approve", "deny") or not isinstance(uid, str) or uid not in APPROVERS:
        return {"ephemeral_text": "승인 권한 또는 결정 값이 유효하지 않습니다."}
    with _LOCK:
        _expire_locked(); rec = APPROVALS.get(rid)
        if (not rec or not isinstance(ctx.get("nonce"), str) or
                not secrets.compare_digest(rec["nonce"], ctx["nonce"]) or ctx.get("action") != rec["action"]):
            return {"ephemeral_text": "알 수 없거나 만료된 승인 요청입니다."}
        if rec["status"] != "pending":
            return {"ephemeral_text": "이미 처리됨: %s (by %s)" % (rec["status"], rec["by"])}
        rec["status"] = "approved" if decision == "approve" else "denied"
        rec["by"] = uid; rec["decided_ts"] = time.time(); st = rec["status"]
    label = "✅ 승인됨" if st == "approved" else "❌ 거부됨"
    props = {"attachments": [{"color": "#28a745" if st == "approved" else "#d24b4b",
             "title": "%s · %s %s" % (label, rec["ip"], rec["action"]),
             "text": "결정: `%s` · 승인자 ID: `%s` · 작업: `%s` · 기간: %d분\n사유:\n\n    %s\n\n요청 ID: `%s`" %
                     (st, rec["by"], rec["action"], rec["minutes"], rec["reason"], rid),
             "footer": "capstone SOC HITL", "ts": int(time.time())}]}
    return {"update": {"message": "", "props": props}, "ephemeral_text": "%s 처리했습니다." % label}


def approval_decision(rid):
    with _LOCK:
        _expire_locked(); rec = APPROVALS.get(rid)
        if not rec:
            return None
        return _approval_public(rid, rec)


def approval_consume(req):
    if not _legacy_approval_enabled():
        return {"error": "approval is not configured"}, 503
    if not isinstance(req, dict) or set(req) != {"request_id", "action", "ip", "minutes"} or \
            not isinstance(req.get("request_id"), str) or type(req.get("minutes")) is not int:
        return {"error": "invalid approval consume fields"}, 400
    with _LOCK:
        _expire_locked()
        rid = req["request_id"]
        rec = APPROVALS.get(rid)
        if not rec:
            return {"error": "approval not found"}, 404
        if rec["status"] != "approved" or any(req[key] != rec[key] for key in ("action", "ip", "minutes")):
            return {"error": "approval is not approved or binding differs"}, 409
        rec["status"] = "consumed"
        rec["consumed_ts"] = time.time()
        return _approval_public(rid, rec), 200


# ---- 승인형 보안 룰 변경: 변경 바이트의 해시와 표시된 전체 diff에 결속 ----
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUESTER = re.compile(r"^[a-zA-Z0-9_.:@-]{1,80}$")
_RULE_FIELDS = frozenset(("target", "base_sha256", "candidate_sha256", "diff_sha256",
                          "diff", "requested_by", "expires_at"))


def _rule_enabled():
    return bool(len(RULE_BROKER_TOKEN) >= 32 and RULE_BROKER_TOKEN != BROKER_TOKEN
                and RULE_APPROVERS and RULE_MM_SOURCES and MM_WEBHOOK and MM_ACTION_URL)


def _rule_source_ok(peer_ip):
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    return any(peer in source for source in RULE_MM_SOURCES)


def _rule_request_signature(method, path, timestamp, nonce, body):
    """Authenticate exact HTTP request bytes; the shared key never travels on the wire."""
    signed = ("v1\n%s\n%s\n%s\n%s\n%s" %
              (method, path, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode("ascii")
    return hmac.new(RULE_BROKER_TOKEN.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def _rule_response_signature(nonce, status, body):
    signed = ("v1\n%s\n%d\n%s" % (nonce, status, hashlib.sha256(body).hexdigest())).encode("ascii")
    return hmac.new(RULE_BROKER_TOKEN.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def _rule_audit(event, rid, rec):
    """Metadata only; stderr is captured by the soc-bot systemd journal."""
    row = {"event": event, "proposal_id": rid, "target": rec["target"],
           "proposal_digest": rec["proposal_digest"], "status": rec["status"],
           "approver_id": rec["by"], "at": int(time.time())}
    print("rule_change_audit " + json.dumps(row, sort_keys=True), file=sys.stderr, flush=True)


def _rule_expire_locked():
    now = time.time()
    for rid, rec in list(RULE_APPROVALS.items()):
        if rec["status"] in ("posting", "pending", "approved") and now >= rec["expires_at"]:
            rec["status"] = "expired"
            rec["decided_ts"] = now
            _rule_audit("expired", rid, rec)
        if rec["status"] not in ("posting", "pending") and now - rec.get("decided_ts", rec["expires_at"]) > 3600:
            del RULE_APPROVALS[rid]
    # Decisions also go to the service journal; cap transient in-memory state.
    if len(RULE_APPROVALS) > 256:
        terminal = sorted(((rid, rec) for rid, rec in RULE_APPROVALS.items()
                           if rec["status"] not in ("posting", "pending")),
                          key=lambda item: item[1].get("decided_ts", item[1]["ts"]))
        for rid, _ in terminal[:len(RULE_APPROVALS) - 256]:
            del RULE_APPROVALS[rid]


def _rule_validate(req):
    """Only immutable, bounded proposal data is accepted; status is never client-supplied."""
    if not isinstance(req, dict) or set(req) != _RULE_FIELDS:
        raise ValueError("invalid proposal fields")
    target = req["target"]
    if not isinstance(target, str) or target not in RULE_TARGETS:
        raise ValueError("target is not allowlisted")
    for key in ("base_sha256", "candidate_sha256", "diff_sha256"):
        if not isinstance(req[key], str) or not _SHA256.fullmatch(req[key]):
            raise ValueError("invalid SHA-256")
    diff = req["diff"]
    if not isinstance(diff, str) or not diff or len(diff.encode("utf-8")) > RULE_DIFF_MAX_BYTES:
        raise ValueError("diff is empty or too large")
    if any(c not in "\n\t" and unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in diff):
        raise ValueError("diff contains hidden or bidi control characters")
    if hashlib.sha256(diff.encode("utf-8")).hexdigest() != req["diff_sha256"]:
        raise ValueError("diff SHA-256 mismatch")
    if req["base_sha256"] == req["candidate_sha256"]:
        raise ValueError("candidate is unchanged")
    by = req["requested_by"]
    if not isinstance(by, str) or not _REQUESTER.fullmatch(by):
        raise ValueError("invalid requester")
    expiry = req["expires_at"]
    if type(expiry) is not int or not (time.time() < expiry <= time.time() + min(APPROVAL_TTL, 900)):
        raise ValueError("invalid expiry")
    canonical = json.dumps(req, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _rule_public(rid, rec):
    return {"proposal_id": rid, "status": rec["status"], "proposal_digest": rec["proposal_digest"],
            "target": rec["target"], "base_sha256": rec["base_sha256"],
            "candidate_sha256": rec["candidate_sha256"], "diff_sha256": rec["diff_sha256"],
            "expires_at": rec["expires_at"], "by": rec["by"],
            "review_parts": rec.get("review_parts", 0),
            "review_parts_posted": rec.get("review_parts_posted", 0),
            "result_posted": rec.get("result_posted", False),
            "result_status": rec.get("result_status", ""),
            "result_attempts": rec.get("result_attempts", 0),
            "readback_sha256": rec.get("readback_sha256", "")}


def _rule_diff_display(diff):
    return "\n".join("    " + line for line in diff.split("\n"))


def _rule_review_parts(diff):
    """Losslessly split at UTF-8 character boundaries, preferring complete lines.

    Byte ranges and individual hashes identify fragments of a long physical line;
    no newline or other content is inserted into the original review fragments.
    """
    parts = []
    start = cursor = 0
    last_newline = 0
    display_bytes = 4
    while cursor < len(diff):
        char = diff[cursor]
        cost = len(char.encode("utf-8")) + (4 if char == "\n" else 0)
        if display_bytes + cost > RULE_REVIEW_PART_MAX_BYTES:
            end = last_newline if last_newline > start else cursor
            parts.append(diff[start:end])
            start = cursor = end
            last_newline = end
            display_bytes = 4
            continue
        display_bytes += cost
        cursor += 1
        if char == "\n":
            last_newline = cursor
    if start < len(diff):
        parts.append(diff[start:])
    return parts


def _rule_card_fits(text):
    return len(text) <= RULE_CARD_MAX_CHARS and len(text.encode("utf-8")) <= RULE_CARD_MAX_CHARS


def rule_change_create(req):
    """Return (public record, HTTP status). A failed post never produces an approvable proposal."""
    if not _rule_enabled():
        return {"error": "rule approval is not configured"}, 503
    try:
        digest = _rule_validate(req)
    except (ValueError, UnicodeError) as e:
        return {"error": str(e)}, 400
    rid, nonce = secrets.token_hex(16), secrets.token_hex(32)
    rec = dict(req, proposal_digest=digest, nonce=nonce, status="posting", by="", ts=time.time(),
               review_parts=0, review_parts_posted=0)
    expiry_kst = datetime.fromtimestamp(req["expires_at"], KST).strftime("%Y-%m-%d %H:%M:%S KST")
    header = ("요청자: `%s`\n대상: `%s`\n변경 전 SHA-256: `%s`\n변경 후 SHA-256: `%s`\n"
                 "Diff SHA-256: `%s`\n제안 SHA-256: `%s`\n만료: `%s`\n요청 ID: `%s`\n"
                 "라이브 구문 검사와 재로드 검증은 승인 후 적용 단계에서 수행됩니다." %
              (req["requested_by"], req["target"], req["base_sha256"], req["candidate_sha256"],
               req["diff_sha256"], digest, expiry_kst, rid))
    card_text = header + "\n\n변경 영향·사유 및 전후 전체 diff:\n\n" + _rule_diff_display(req["diff"])
    parts = []
    if len(req["diff"].encode("utf-8")) > RULE_REVIEW_PART_MAX_BYTES or not _rule_card_fits(card_text):
        parts = _rule_review_parts(req["diff"])
        rec["review_parts"] = len(parts)
        card_text = (header + "\n\n전체 변경 내용은 같은 요청 ID와 Diff SHA-256이 표시된 검토 메시지 "
                     "1/%d ~ %d/%d에 순서대로 게시했습니다. 모든 부분을 확인한 뒤 이 카드에서 "
                     "전체 변경 한 건을 승인하거나 거부하세요. 일부만 승인할 수 없습니다.\n"
                     "전체 diff: %d UTF-8 bytes. 각 부분의 byte 범위는 시작 포함·끝 제외이며, "
                     "긴 줄은 여러 부분에 이어질 수 있습니다." %
                     (len(parts), len(parts), len(parts), len(req["diff"].encode("utf-8"))))
    if not _rule_card_fits(card_text):
        return {"error": "approval card too large to display completely"}, 400
    rec["card_text"] = card_text
    def action(name, decision, style):
        return {"id": decision, "name": name, "style": style,
                "integration": {"url": MM_ACTION_URL + "/rule-actions",
                                "context": {"proposal_id": rid, "nonce": nonce, "decision": decision,
                                            "proposal_digest": digest}}}
    payload = {"username": "SOC-Agent", "attachments": [{
        "color": "#e0a800", "title": "⚠️ 보안 룰 변경 승인 요청", "text": card_text,
        "actions": [action("승인", "approve", "primary"), action("거부", "deny", "danger")],
        "footer": "capstone SOC rule change HITL", "ts": int(time.time())}]}
    with _LOCK:
        _rule_expire_locked()
        if sum(r["status"] in ("posting", "pending") for r in RULE_APPROVALS.values()) >= 64:
            return {"error": "too many pending proposals"}, 429
        RULE_APPROVALS[rid] = rec
    deadline = time.monotonic() + RULE_POST_MAX_SECONDS

    def ready_to_post():
        with _LOCK:
            _rule_expire_locked()
            if rec["status"] != "posting":
                return False
            if time.monotonic() >= deadline:
                rec["status"] = "error"
                rec["decided_ts"] = time.time()
                _rule_audit("post_timeout", rid, rec)
                return False
            return True

    def failed_post():
        with _LOCK:
            if rec["status"] == "posting":
                rec["status"] = "error"
                rec["decided_ts"] = time.time()
                _rule_audit("post_error", rid, rec)
        return {"error": "complete review and approval card were not posted; approval is disabled"}, 502

    offset = 0
    for index, part in enumerate(parts, 1):
        raw = part.encode("utf-8")
        end = offset + len(raw)
        review_text = (header + "\n\n검토 부분: %d/%d\n원문 UTF-8 byte 범위: [%d, %d)\n"
                       "부분 SHA-256: `%s`\n전체 변경을 검토한 뒤 마지막 승인 카드에서 결정하세요.\n\n%s" %
                       (index, len(parts), offset, end, hashlib.sha256(raw).hexdigest(),
                        _rule_diff_display(part)))
        if not _rule_card_fits(review_text) or not ready_to_post():
            return failed_post()
        review_payload = {"username": "SOC-Agent", "attachments": [{
            "color": "#e0a800", "title": "보안 룰 변경 검토 · %d/%d" % (index, len(parts)),
            "text": review_text, "footer": "capstone SOC rule change HITL", "ts": int(time.time())}]}
        posted, _ = post_mm(review_payload)
        if not posted or not ready_to_post():
            return failed_post()
        with _LOCK:
            rec["review_parts_posted"] = index
        offset = end
    if not ready_to_post():
        return failed_post()
    posted, _ = post_mm(payload)
    if not posted or not ready_to_post():
        return failed_post()
    with _LOCK:
        # Recheck while holding the lock so a concurrent expiry cannot resurrect a proposal.
        _rule_expire_locked()
        if rec["status"] != "posting" or time.monotonic() >= deadline:
            if rec["status"] == "posting":
                rec["status"] = "error"
                rec["decided_ts"] = time.time()
                _rule_audit("post_timeout", rid, rec)
            return {"error": "proposal expired or review posting timed out; approval is disabled"}, 502
        rec["status"] = "pending"
        _rule_audit("created", rid, rec)
    return {"proposal_id": rid, "proposal_digest": digest, "expires_at": req["expires_at"],
            "posted": True, "review_parts": len(parts)}, 200


def rule_change_action(body, peer_ip):
    """Mattermost sends confidential context and authenticated clicker's user_id."""
    if not _rule_enabled() or not isinstance(body, dict):
        return {"ephemeral_text": "룰 승인 기능이 설정되지 않았습니다."}
    if not _rule_source_ok(peer_ip):
        return {"ephemeral_text": "허용되지 않은 콜백 출처입니다."}
    ctx = body.get("context")
    if not isinstance(ctx, dict):
        return {"ephemeral_text": "유효하지 않은 승인 요청입니다."}
    rid = ctx.get("proposal_id")
    decision = ctx.get("decision")
    uid = body.get("user_id")
    if not isinstance(rid, str) or decision not in ("approve", "deny") or not isinstance(uid, str) or uid not in RULE_APPROVERS:
        return {"ephemeral_text": "승인 권한이 없거나 요청이 유효하지 않습니다."}
    with _LOCK:
        _rule_expire_locked()
        rec = RULE_APPROVALS.get(rid)
        if not rec or rec["status"] != "pending":
            return {"ephemeral_text": "처리되었거나 만료된 요청입니다."}
        nonce, digest = ctx.get("nonce"), ctx.get("proposal_digest")
        if not isinstance(nonce, str) or not isinstance(digest, str) or \
                not secrets.compare_digest(nonce, rec["nonce"]) or \
                not secrets.compare_digest(digest, rec["proposal_digest"]):
            return {"ephemeral_text": "인증되지 않은 승인 요청입니다."}
        rec["status"] = "approved" if decision == "approve" else "denied"
        rec["by"] = uid
        rec["decided_ts"] = time.time()
        st = rec["status"]
        _rule_audit("decision", rid, rec)
    label = "✅ 승인됨" if st == "approved" else "❌ 거부됨"
    return {"update": {"message": "", "props": {"attachments": [{
        "color": "#28a745" if st == "approved" else "#d24b4b",
        "title": "%s · %s" % (label, rec["target"]),
        "text": rec["card_text"] + "\n\n결정: `%s` · 승인자 ID: `%s`" % (st, uid),
        "footer": "capstone SOC rule change HITL", "ts": int(time.time())}]}},
            "ephemeral_text": "%s 처리했습니다." % label}


def rule_change_decision(rid):
    with _LOCK:
        _rule_expire_locked()
        rec = RULE_APPROVALS.get(rid)
        return _rule_public(rid, rec) if rec else None


def rule_change_consume(rid, req):
    if not isinstance(req, dict) or set(req) != {"proposal_digest"} or \
            not isinstance(req.get("proposal_digest"), str):
        return {"error": "invalid consume request"}, 400
    with _LOCK:
        _rule_expire_locked()
        rec = RULE_APPROVALS.get(rid)
        if not rec:
            return {"error": "proposal not found"}, 404
        if rec["status"] != "approved":
            return {"error": "proposal is not approved"}, 409
        if not secrets.compare_digest(req["proposal_digest"], rec["proposal_digest"]):
            return {"error": "proposal digest mismatch"}, 409
        rec["status"] = "consumed"
        rec["decided_ts"] = time.time()
        _rule_audit("consumed", rid, rec)
        return _rule_public(rid, rec), 200


def rule_change_abort(rid, req):
    """End an approved but unconsumed proposal and report that no rule was applied."""
    fields = {"proposal_digest", "readback_sha256", "detail"}
    if not isinstance(req, dict) or set(req) != fields or \
            not isinstance(req["proposal_digest"], str) or \
            not isinstance(req["readback_sha256"], str) or not _SHA256.fullmatch(req["readback_sha256"]):
        return {"error": "invalid abort fields"}, 400
    detail = req["detail"]
    if not isinstance(detail, str) or not 1 <= len(detail) <= 200 or \
            any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in detail):
        return {"error": "invalid abort detail"}, 400
    digest = hashlib.sha256(json.dumps(
        req, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    with _LOCK:
        _rule_expire_locked()
        rec = RULE_APPROVALS.get(rid)
        if not rec:
            return {"error": "proposal not found"}, 404
        if not secrets.compare_digest(req["proposal_digest"], rec["proposal_digest"]):
            return {"error": "proposal digest mismatch"}, 409
        prior = rec.get("abort_request_digest")
        if prior and not secrets.compare_digest(prior, digest):
            return {"error": "abort differs from first report"}, 409
        if rec.get("result_posted") and rec["status"] == "aborted":
            return _rule_public(rid, rec), 200
        if rec["status"] not in ("approved", "expired", "abort_report_error") or not rec["by"]:
            return {"error": "proposal was not approved or approval was consumed"}, 409
        if rec.get("result_attempts", 0) >= 3:
            return {"error": "abort card retries exhausted"}, 429
        rec["status"] = "abort_reporting"
        rec["abort_request_digest"] = digest
        rec["result_attempts"] = rec.get("result_attempts", 0) + 1
        rec["result_status"] = "not_applied"
        rec["readback_sha256"] = req["readback_sha256"]
        rec["result_posted"] = False
        rec["decided_ts"] = time.time()
    body = (rec["card_text"] + "\n\n승인자 ID: `%s`\n적용 결과: `미적용`\n실제 읽기 SHA-256: `%s`\n"
            "미적용 사유:\n    %s" % (rec["by"], req["readback_sha256"], detail))
    payload = {"username": "SOC-Agent", "attachments": [{
        "color": "#d24b4b", "title": "보안 룰 변경 미적용 · %s" % rec["target"],
        "text": body, "footer": "capstone SOC rule change HITL", "ts": int(time.time())}]}
    posted, _ = post_mm(payload)
    with _LOCK:
        rec["status"] = "aborted" if posted else "abort_report_error"
        rec["result_posted"] = posted
        rec["decided_ts"] = time.time()
        _rule_audit("aborted" if posted else "abort_post_error", rid, rec)
        public = _rule_public(rid, rec)
    if not posted:
        return {"error": "abort card was not posted", **public}, 502
    return public, 200


def rule_change_result(rid, req):
    """Post one result; failed posts may retry the *identical* payload at most three times."""
    fields = {"proposal_digest", "status", "before_sha256", "after_sha256", "readback_sha256", "detail"}
    if not isinstance(req, dict) or set(req) != fields or \
            req["status"] not in ("applied", "rolled_back", "recovery_failed", "failed"):
        return {"error": "invalid result fields"}, 400
    detail = req["detail"]
    try:
        detail_size = len(detail.encode("utf-8")) if isinstance(detail, str) else 0
    except UnicodeError:
        detail_size = 0
    if not isinstance(detail, str) or not detail or len(detail) > 200 or detail_size == 0 or detail_size > 500 or \
            any(ord(c) < 32 for c in detail):
        return {"error": "invalid result detail"}, 400
    if not isinstance(req["readback_sha256"], str) or not _SHA256.fullmatch(req["readback_sha256"]):
        return {"error": "invalid readback SHA-256"}, 400
    result_digest = hashlib.sha256(json.dumps(
        req, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    with _LOCK:
        _rule_expire_locked()
        rec = RULE_APPROVALS.get(rid)
        if not rec:
            return {"error": "proposal not found"}, 404
        for provided, stored in ((req["proposal_digest"], rec["proposal_digest"]),
                                 (req["before_sha256"], rec["base_sha256"]),
                                 (req["after_sha256"], rec["candidate_sha256"])):
            if not isinstance(provided, str) or not secrets.compare_digest(provided, stored):
                return {"error": "result does not match approved proposal"}, 409
        if (req["status"] == "applied" and req["readback_sha256"] != rec["candidate_sha256"]) or \
                (req["status"] == "rolled_back" and req["readback_sha256"] != rec["base_sha256"]):
            return {"error": "readback does not match claimed outcome"}, 409
        prior_digest = rec.get("result_request_digest")
        if prior_digest and not secrets.compare_digest(prior_digest, result_digest):
            return {"error": "result differs from the first report"}, 409
        if rec.get("result_posted"):
            return _rule_public(rid, rec), 200  # idempotent; no second Mattermost card
        if rec["status"] not in ("consumed", "report_error"):
            return {"error": "approval not consumed or result is in progress"}, 409
        if rec.get("result_attempts", 0) >= 3:
            return {"error": "result card retries exhausted"}, 429
        rec["status"] = "reporting"   # reserve the one result slot before external post
        rec["result_request_digest"] = result_digest
        rec["result_attempts"] = rec.get("result_attempts", 0) + 1
        rec["result_status"] = req["status"]
        rec["readback_sha256"] = req["readback_sha256"]
        rec["result_posted"] = False
        rec["decided_ts"] = time.time()
    result_text = (rec["card_text"] + "\n\n승인자 ID: `%s`\n적용 결과: `%s`\n실제 읽기 SHA-256: `%s`\n"
                   "검증·재로드 결과:\n    %s" % (rec["by"], req["status"], req["readback_sha256"], detail))
    payload = {"username": "SOC-Agent", "attachments": [{
        "color": "#28a745" if req["status"] == "applied" else "#d24b4b",
        "title": "보안 룰 변경 결과 · %s" % rec["target"], "text": result_text,
        "footer": "capstone SOC rule change HITL", "ts": int(time.time())}]}
    posted, _ = post_mm(payload)
    with _LOCK:
        rec["status"] = req["status"] if posted else "report_error"
        rec["result_posted"] = posted
        rec["decided_ts"] = time.time()
        _rule_audit("result" if posted else "result_post_error", rid, rec)
        public = _rule_public(rid, rec)
    if not posted:
        return {"error": "result card was not posted", **public}, 502
    return public, 200


def recent_fingerprint(minutes=60, min_level=10, n=5):
    """Hermes cron --monitor-script 용 지문: 최신 n건(level>=min_level, 최근 minutes분)만, 절대 타임스탬프로.
    ts는 모니터 캐시용 원본을 유지하고, ts_kst는 사용자 표시용이다."""
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
        out.append({"ts": s.get("timestamp", ""), "ts_kst": _alert_time_kst(s.get("timestamp", "")),
                    "id": r.get("id"), "level": r.get("level"), "agent": s.get("agent", {}).get("name", ""),
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


def _operation_audit(event, rec):
    row = {"event": event, "operation_id": rec["request_id"], "kind": rec["kind"],
           "target": rec["target"], "proposal_digest": rec["proposal_digest"],
           "status": rec["status"], "approver_id": rec["by"], "at": int(time.time())}
    print("operation_approval_audit " + json.dumps(row, sort_keys=True), file=sys.stderr, flush=True)


# Load only the adjacent deployed module, independent of the caller's import path.
import importlib.util as _import_util
_operations_spec = _import_util.spec_from_file_location(
    "capstone_operations_approval", os.path.join(os.path.dirname(os.path.abspath(__file__)), "operations_approval.py"))
_operations_module = _import_util.module_from_spec(_operations_spec)
_operations_spec.loader.exec_module(_operations_module)
OPERATIONS = _operations_module.OperationsBroker(
    post=lambda payload: post_mm(payload), enabled=_rule_enabled, source_ok=_rule_source_ok,
    approvers=lambda: RULE_APPROVERS, action_url=lambda: MM_ACTION_URL, audit=_operation_audit)


def _rule_health_counts():
    with _LOCK:
        _rule_expire_locked()
        _expire_locked()
        counts = {}
        active = ("posting", "pending", "approved", "consumed", "reporting", "report_error",
                  "abort_reporting", "abort_report_error")
        for rec in RULE_APPROVALS.values():
            counts[rec["status"]] = counts.get(rec["status"], 0) + 1
        legacy_counts = {}
        for rec in APPROVALS.values():
            legacy_counts[rec["status"]] = legacy_counts.get(rec["status"], 0) + 1
        return {"active_rule_changes": sum(counts.get(status, 0) for status in active),
                "rule_status_counts": counts, "legacy_approval_status_counts": legacy_counts,
                "active_legacy_approvals": sum(legacy_counts.get(status, 0) for status in ("posting", "pending", "approved"))}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def setup(self):
        super().setup()
        self.connection.settimeout(10)
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        if getattr(self, "_rule_nonce", None):
            self.send_header("X-Rule-Response-Signature", _rule_response_signature(self._rule_nonce, code, b))
        self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        limit = RULE_CREATE_BODY_MAX_BYTES if urllib.parse.urlparse(self.path).path == "/rule-changes" else 1 << 20
        if not 0 <= n <= limit:
            raise ValueError("invalid request length")
        self._request_body_bytes = self.rfile.read(n) if n else b""
        if len(self._request_body_bytes) != n:
            raise ValueError("incomplete request body")
        return self._request_body_bytes.decode()
    def _tok_ok(self, header, expected):
        return bool(expected) and secrets.compare_digest(self.headers.get(header, ""), expected)
    def _rule_auth(self, method, body=b""):
        if not _rule_enabled():
            self._json({"error": "rule approval is not configured"}, 503)
            return False
        timestamp = self.headers.get("X-Rule-Timestamp", "")
        nonce = self.headers.get("X-Rule-Nonce", "")
        signature = self.headers.get("X-Rule-Signature", "")
        if (self.headers.get("X-Rule-Broker-Token") or
                not re.fullmatch(r"[0-9]{10,12}", timestamp) or
                not re.fullmatch(r"[0-9a-f]{32}", nonce) or
                not re.fullmatch(r"[0-9a-f]{64}", signature) or
                abs(time.time() - int(timestamp)) > 60):
            self._json({"error": "unauthorized"}, 401)
            return False
        expected = _rule_request_signature(method, self.path, timestamp, nonce, body)
        if not secrets.compare_digest(signature, expected):
            self._json({"error": "unauthorized"}, 401)
            return False
        with _LOCK:
            now = time.time()
            for old_nonce, seen_at in list(RULE_NONCES.items()):
                if now - seen_at > 120:
                    del RULE_NONCES[old_nonce]
            if nonce in RULE_NONCES or len(RULE_NONCES) >= 4096:
                self._json({"error": "replayed or saturated request"}, 401)
                return False
            RULE_NONCES[nonce] = now
        self._rule_nonce = nonce
        return True
    def do_GET(self):
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == "/rule-changes/health":
            if not self._rule_auth("GET"):
                return
            return self._json({"status": "ready", "approval_configured": True, **_rule_health_counts()})
        if u.path == "/operations/health":
            if not self._rule_auth("GET"):
                return
            return self._json({**OPERATIONS.health(), **_rule_health_counts()})
        if re.fullmatch(r"/operations/[0-9a-f]{32}", u.path):
            if not self._rule_auth("GET"):
                return
            response, status = OPERATIONS.get(u.path.rsplit("/", 1)[1])
            return self._json(response, status)
        if re.fullmatch(r"/rule-changes/[0-9a-f]{32}", u.path):
            if not self._rule_auth("GET"):
                return
            d = rule_change_decision(u.path.rsplit("/", 1)[1])
            return self._json(d or {"error": "not found"}, 200 if d else 404)
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
                counts = {}
                for rec in APPROVALS.values():
                    counts[rec["status"]] = counts.get(rec["status"], 0) + 1
            return self._json({"pending": pend, "status_counts": counts,
                               "active": sum(counts.get(status, 0) for status in ("posting", "pending", "approved"))})
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
        u = urllib.parse.urlparse(self.path)
        try:
            raw = self._body()
        except (ValueError, TimeoutError):
            return self._json({"error": "invalid or incomplete request body"}, 400)
        if u.path == "/operations" or re.fullmatch(r"/operations/[0-9a-f]{32}/(?:consume|result)", u.path):
            if not self._rule_auth("POST", self._request_body_bytes):
                return
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            if u.path == "/operations":
                response, status = OPERATIONS.create(req)
            else:
                oid, operation = u.path.split("/")[2:]
                response, status = getattr(OPERATIONS, operation)(oid, req)
            return self._json(response, status)
        if u.path == "/operation-actions":
            try:
                body = json.loads(raw or "{}")
            except ValueError:
                return self._json({"ephemeral_text": "bad request"}, 400)
            return self._json(OPERATIONS.action(body, self.client_address[0]))
        if u.path == "/rule-changes":
            if not self._rule_auth("POST", self._request_body_bytes):
                return
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            response, status = rule_change_create(req)
            return self._json(response, status)
        if re.fullmatch(r"/rule-changes/[0-9a-f]{32}/consume", u.path):
            if not self._rule_auth("POST", self._request_body_bytes):
                return
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            response, status = rule_change_consume(u.path.split("/")[2], req)
            return self._json(response, status)
        if re.fullmatch(r"/rule-changes/[0-9a-f]{32}/abort", u.path):
            if not self._rule_auth("POST", self._request_body_bytes):
                return
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            response, status = rule_change_abort(u.path.split("/")[2], req)
            return self._json(response, status)
        if re.fullmatch(r"/rule-changes/[0-9a-f]{32}/result", u.path):
            if not self._rule_auth("POST", self._request_body_bytes):
                return
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            response, status = rule_change_result(u.path.split("/")[2], req)
            return self._json(response, status)
        if u.path == "/rule-actions":
            try:
                body = json.loads(raw or "{}")
            except ValueError:
                return self._json({"ephemeral_text": "bad request"}, 400)
            return self._json(rule_change_action(body, self.client_address[0]))
        if u.path == "/approval":                       # 응답 서버(A) → 승인 카드 생성
            if not self._tok_ok("X-Broker-Token", BROKER_TOKEN):
                return self._json({"error": "unauthorized"}, 401)
            if not _legacy_approval_enabled():
                return self._json({"error": "approval is not configured"}, 503)
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            rid, ok, d = approval_create(req)
            status = 200 if ok else (502 if rid else (429 if d == "too many active approvals" else 400))
            return self._json({"req_id": rid, "posted": ok, "detail": d}, status)
        if u.path == "/consume":
            if not self._tok_ok("X-Broker-Token", BROKER_TOKEN):
                return self._json({"error": "unauthorized"}, 401)
            try:
                req = json.loads(raw or "{}")
            except ValueError:
                return self._json({"error": "bad json"}, 400)
            response, status = approval_consume(req)
            return self._json(response, status)
        if u.path == "/actions":                        # Mattermost 버튼 클릭 콜백(JSON)
            try:
                body = json.loads(raw or "{}")
            except ValueError:
                return self._json({"ephemeral_text": "bad request"}, 400)
            return self._json(approval_action(body, self.client_address[0]))
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
        host, port = LISTEN.split(":"); srv = ThreadingHTTPServer((host, int(port)), Handler)
        print("soc_bot serve on %s" % LISTEN, file=sys.stderr); srv.serve_forever()
    print(__doc__)


if __name__ == "__main__":
    main()
