#!/usr/bin/env python3
"""Read-only MCP view of indexed security alerts and stored SCA scans on Groot_B.

Uses the existing mcp-ro Indexer credentials from /etc/mcp/wazuh-ro.env. Only
the fixed wazuh-alerts-* index is queried, so events not yet indexed by Wazuh
cannot appear. Results use KST (+09:00) ISO 8601 timestamps. Raw logs,
ModSecurity messages, header values, query strings and request bodies are never
returned. Bounded DNS questions and HTTP paths are untrusted investigation
context; opaque transaction/User-Agent hashes support correlation, not identity.
"""

import base64
import hashlib
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
import re
import ssl
import sys
import urllib.request
from urllib.parse import urlsplit


PROTOCOL = "2025-06-18"
SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", PROTOCOL}
INDEX = "wazuh-alerts-*"
MAX_LOOKBACK_MINUTES = 1440
MAX_LIMIT = 50
MAX_SCAN = 250
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
RULE_ID_RE = re.compile(r"^[0-9]{1,10}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
KST = timezone(timedelta(hours=9))

COMMON_FIELDS = ["timestamp", "agent.name", "rule.id", "rule.level"]
SURICATA_FIELDS = COMMON_FIELDS + [
    "data.src_ip", "data.srcip", "data.dest_ip", "data.dest_port", "data.proto",
    "data.alert.signature_id", "data.alert.signature", "data.alert.category", "data.alert.severity",
    "data.dns.type", "data.dns.queries.rrname", "data.dns.queries.rrtype",
    "data.dns.rrname", "data.dns.rrtype",
]
WAF_FIELDS = COMMON_FIELDS + [
    "data.transaction.client_ip", "data.transaction.request.method",
    "data.transaction.response.http_code", "data.transaction.producer.secrules_engine",
    "data.transaction.messages",  # examined only in memory to extract numeric rule IDs
    "data.transaction.unique_id", "data.transaction.request.uri",
    "data.transaction.request.headers.User-Agent",  # hashed, never returned verbatim
]

TOOLS = [
    {
        "name": "search_suricata_alerts",
        "description": "Search Suricata alerts already indexed by Wazuh, not live raw EVE. limit must be 1..50 (default 10). Includes bounded untrusted DNS questions when present, exact KST window, and unknown full-window total. A domain or signature alone does not establish malicious/benign intent.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "until_kst": {"type": "string", "description": "Optional historical window end, ISO8601 with +09:00. At most 90 days old, never future; lookback_minutes still limits the window to 24 hours."},
                "lookback_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_LOOKBACK_MINUTES, "default": 60},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": 10},
                "source_ip": {"type": "string", "description": "Exact source IPv4 or IPv6 address"},
                "signature_id": {"type": "string", "pattern": "^[0-9]{1,10}$", "description": "Exact sensor Suricata SID, NOT a Wazuh correlation rule ID"},
            },
        },
        "annotations": {"title": "Search Suricata alerts", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "search_modsecurity_alerts",
        "description": "Search ModSecurity alerts already indexed by Wazuh, not raw audit logs. limit must be 1..50 (default 10). Includes untrusted HTTP paths without query strings and opaque transaction/User-Agent hashes. Paths and hash matches are correlation context, not authenticated identity or permission. Returns exact KST window and unknown full-window total.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "until_kst": {"type": "string", "description": "Optional historical window end, ISO8601 with +09:00. At most 90 days old, never future; lookback_minutes still limits the window to 24 hours."},
                "lookback_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_LOOKBACK_MINUTES, "default": 60},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": 10},
                "source_ip": {"type": "string", "description": "Exact source IPv4 or IPv6 address"},
                "rule_id": {"type": "string", "pattern": "^[0-9]{1,10}$", "description": "Exact sensor ModSecurity/CRS rule ID, NOT a Wazuh correlation rule ID"},
            },
        },
        "annotations": {"title": "Search ModSecurity alerts", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
]

TOOLS.append({
    "name": "get_wazuh_sca_checks",
    "description": "Read an agent's latest stored Wazuh SCA scan. Without policy_id lists policies; with policy_id returns up to 50 checks, or the exact check_ids (at most 20), or title_contains (up to 50 matches), from at most 500 scanned rows. This does not start a new scan or inspect live sshd/kernel settings. Read scan_end_kst and scan_age_seconds; passed is a historical scan result, not proof of current security.",
    "inputSchema": {"type": "object", "additionalProperties": False,
        "properties": {
            "agent_id": {"type": "string", "pattern": "^[0-9]{3,8}$"},
            "policy_id": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"},
            "title_contains": {"type": "string", "minLength": 3, "maxLength": 120, "description": "Case-insensitive title substring, e.g. GSSAPIAuthentication. Requires policy_id; cannot combine with check_ids."},
            "check_ids": {"type": "array", "minItems": 1, "maxItems": 20, "uniqueItems": True,
                "items": {"type": "integer", "minimum": 1, "maximum": 2147483647}},
        }, "required": ["agent_id"]},
    "annotations": {"title": "Read Wazuh SCA checks", "readOnlyHint": True,
        "destructiveHint": False, "idempotentHint": True},
})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_sca_args(args):
    if not isinstance(args, dict) or set(args) - {"agent_id", "policy_id", "check_ids", "title_contains"}:
        raise ValueError("invalid SCA arguments")
    if not isinstance(args.get("agent_id"), str) or not re.fullmatch(r"[0-9]{3,8}", args["agent_id"]):
        raise ValueError("agent_id must contain 3 to 8 digits")
    if "policy_id" in args and (not isinstance(args["policy_id"], str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args["policy_id"])):
        raise ValueError("invalid policy_id")
    if "title_contains" in args:
        value=args["title_contains"]
        if ("policy_id" not in args or "check_ids" in args or not isinstance(value,str)
                or not 3 <= len(value.strip()) <= 120 or CONTROL_RE.search(value)):
            raise ValueError("title_contains requires policy_id and 3..120 plain-text characters; no check_ids")
    if "check_ids" in args:
        ids = args["check_ids"]
        if ("policy_id" not in args or not isinstance(ids, list) or not 1 <= len(ids) <= 20 or
                any(type(i) is not int or not 1 <= i <= 2147483647 for i in ids) or len(set(ids)) != len(ids)):
            raise ValueError("check_ids requires policy_id and 1 to 20 unique positive integer IDs")
    return dict(args)


def sca_api_reader():
    """The existing mcp-ro account, fixed API resources, no redirects/proxy/credential logging."""
    host = os.environ.get("WAZUH_API_HOST", "127.0.0.1")
    port = int(os.environ.get("WAZUH_API_PORT", "55000"))
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host) or not 1 <= port <= 65535:
        raise RuntimeError("invalid Wazuh API configuration")
    username, password = os.environ.get("WAZUH_API_USERNAME", ""), os.environ.get("WAZUH_API_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("Wazuh API read-only credentials unavailable")
    base = "https://%s:%d" % (host, port)
    context = ssl.create_default_context() if os.environ.get("WAZUH_VERIFY_SSL", "true").lower() == "true" else ssl._create_unverified_context()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def request(path, headers, method="GET"):
        with opener.open(urllib.request.Request(base + path, headers=headers, method=method), timeout=12) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("SCA response limit exceeded")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("error") != 0:
            raise RuntimeError("Wazuh API response unavailable")
        return _obj(value.get("data"))

    basic = base64.b64encode((username + ":" + password).encode()).decode("ascii")
    authenticated = request("/security/user/authenticate", {"Authorization": "Basic " + basic}, "POST")
    token = authenticated.get("token")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,16384}", token):
        raise RuntimeError("Wazuh API authentication unavailable")

    def read(agent_id, policy_id=None, limit=50):
        # Defense in depth even for internal callers; never accept raw paths or DSL.
        validate_sca_args({"agent_id": agent_id, **({"policy_id": policy_id} if policy_id is not None else {})})
        if limit not in (50, 500):
            raise ValueError("invalid SCA scan bound")
        path = "/sca/" + agent_id
        if policy_id is not None:
            path += "/checks/" + policy_id
        data = request(path + "?limit=" + str(limit), {"Authorization": "Bearer " + token})
        rows, total = data.get("affected_items"), data.get("total_affected_items")
        if (data.get("total_failed_items") != 0 or not isinstance(rows, list) or len(rows) > limit
                or not all(isinstance(row, dict) for row in rows) or type(total) is not int or total < len(rows)):
            raise RuntimeError("SCA partial or invalid API response")
        return rows, total
    return read


def sca_scan_time(value):
    """Missing offsets stay unknown; do not assume SCA's timezone."""
    if not isinstance(value, str) or len(value) > 64:
        return ""
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return instant.astimezone(KST).isoformat() if instant.tzinfo is not None else ""
    except (ValueError, OverflowError):
        return ""


def sca_checks(args):
    params = validate_sca_args(args)
    read = sca_api_reader()
    policies, total = read(params["agent_id"])
    now = datetime.now(KST)
    projected = []
    for row in policies:
        end = sca_scan_time(row.get("end_scan"))
        projected.append({"policy_id": _scalar(row.get("policy_id"), 128), "name": _scalar(row.get("name")),
            "scan_start_kst": sca_scan_time(row.get("start_scan")), "scan_end_kst": end,
            "scan_age_seconds": int((now - datetime.fromisoformat(end)).total_seconds()) if end else None,
            **{key: row[key] if type(row.get(key)) is int and row[key] >= 0 else None
               for key in ("pass", "fail", "invalid", "total_checks", "score")}})
    out = {"source": "wazuh_sca", "source_scope": "last_stored_sca_scan", "agent_id": params["agent_id"],
        "queried_at_kst": now.isoformat(), "policies": projected, "policy_total": total,
        "policies_truncated": total > len(policies), "untrusted_evidence": True,
        "evidence_scope_ko": "Wazuh에 저장된 마지막 SCA 점검 결과입니다. 새 스캔이나 현재 호스트 설정 직접 조회가 아닙니다. "
            "scan_end_kst·경과와 잘림/누락을 확인하세요. 통과는 당시 해당 점검의 결과이며 전체 보안 정상이나 공격 부재를 뜻하지 않습니다."}
    if "policy_id" not in params:
        return out
    selected = [p for p in policies if p.get("policy_id") == params["policy_id"]]
    if len(selected) != 1:
        raise ValueError("policy_id was not uniquely present in the returned agent policies")
    limit = 500 if "check_ids" in params or "title_contains" in params else 50
    checks, count = read(params["agent_id"], params["policy_id"], limit)
    after, _ = read(params["agent_id"])
    latest = [p for p in after if p.get("policy_id") == params["policy_id"]]
    # Never combine counts/time from one scan with checks returned during its replacement.
    if len(latest) != 1 or any(latest[0].get(k) != selected[0].get(k) for k in
            ("start_scan", "end_scan", "hash_file", "pass", "fail", "invalid", "total_checks")):
        raise RuntimeError("SCA scan changed during read; retry required")
    requested = params.get("check_ids")
    title_query = params.get("title_contains", "").strip().casefold()
    title_matches = 0
    rows = []
    for check in checks:
        cid = check.get("id")
        if type(cid) is not int or cid <= 0:
            raise RuntimeError("SCA check identity unavailable")
        if requested is not None and cid not in requested:
            continue
        if title_query:
            if title_query not in _scalar(check.get("title"), 240).casefold():
                continue
            title_matches += 1
            if len(rows) >= 50:
                continue
        rows.append({"check_id": cid, "title": _scalar(check.get("title"), 240),
            "result": _scalar(check.get("result"), 40), "reason": _scalar(check.get("reason"), 320),
            "description": _scalar(check.get("description"), 480)})
    if len({r["check_id"] for r in rows}) != len(rows):
        raise RuntimeError("duplicate SCA check identity")
    out.update(policy_id=params["policy_id"], checks=rows, returned_count=len(rows), scanned_count=len(checks),
        policy_check_total=count, scan_capped=count > len(checks),
        missing_requested_check_ids=sorted(set(requested or []) - {r["check_id"] for r in rows}))
    if title_query:
        out.update(title_contains=params["title_contains"], matched_within_scan=title_matches,
            matches_truncated=title_matches > len(rows))
    return out


def _scalar(value, max_chars=160):
    if value is None or isinstance(value, (dict, list, bool)):
        return ""
    return CONTROL_RE.sub(" ", str(value))[:max_chars]


def _obj(value):
    return value if isinstance(value, dict) else {}


def _kst_timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return ""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    # Wazuh normally supplies an offset. If absent, treat the Indexer timestamp
    # as UTC rather than inheriting the host's local timezone.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(KST).isoformat()


def _positive_int(value, name, default, maximum):
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise ValueError("%s must be an integer between 1 and %d" % (name, maximum))
    return value


def validate_args(kind, args):
    if not isinstance(args, dict):
        raise ValueError("arguments must be an object")
    allowed = {"lookback_minutes", "limit", "source_ip", "until_kst"}
    id_key = "signature_id" if kind == "suricata" else "rule_id"
    allowed.add(id_key)
    unknown = set(args) - allowed
    if unknown:
        raise ValueError("unsupported argument: %s" % sorted(unknown)[0])
    out = {
        "lookback_minutes": _positive_int(args.get("lookback_minutes"), "lookback_minutes", 60, MAX_LOOKBACK_MINUTES),
        "limit": _positive_int(args.get("limit"), "limit", 10, MAX_LIMIT),
    }
    if "until_kst" in args:
        value = args["until_kst"]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+09:00", value):
            raise ValueError("until_kst requires an ISO8601 timestamp with +09:00")
        try:
            out["until_kst"] = datetime.fromisoformat(value).isoformat()
        except ValueError:
            raise ValueError("invalid until_kst timestamp") from None
    if "source_ip" in args:
        try:
            if not isinstance(args["source_ip"], str):
                raise ValueError()
            out["source_ip"] = str(ipaddress.ip_address(args["source_ip"]))
        except ValueError:
            raise ValueError("source_ip must be an IPv4 or IPv6 address") from None
    if id_key in args:
        value = args[id_key]
        if not isinstance(value, str) or not RULE_ID_RE.fullmatch(value):
            raise ValueError("%s must contain 1 to 10 digits" % id_key)
        out[id_key] = value
    return out


def build_query(kind, args, at=None):
    """Construct a fixed, bounded DSL; callers never supply an index or query."""
    label = "suricata" if kind == "suricata" else "modsecurity"
    identity = [
        {"term": {"rule.groups": label}},
        {"term": {"data.capstone.source": label}},
        {"exists": {"field": "data.alert.signature_id" if kind == "suricata" else "data.transaction.producer.modsecurity"}},
    ]
    at = at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise ValueError("timezone required for query window")
    if "until_kst" in args:
        end = datetime.fromisoformat(args["until_kst"])
        if not at - timedelta(days=90) <= end <= at:
            raise ValueError("until_kst must be in the past 90 days")
        at = end
    filters = [
        {"range": {"timestamp": {"gte": (at - timedelta(minutes=args["lookback_minutes"])).isoformat(),
                                  "lte": at.isoformat()}}},
        {"bool": {"should": identity, "minimum_should_match": 1}},
    ]
    if "source_ip" in args:
        fields = ("data.src_ip", "data.srcip") if kind == "suricata" else ("data.transaction.client_ip",)
        filters.append({"bool": {"should": [{"term": {field: args["source_ip"]}} for field in fields], "minimum_should_match": 1}})
    if kind == "suricata" and "signature_id" in args:
        filters.append({"term": {"data.alert.signature_id": args["signature_id"]}})
    # A WAF rule ID may live in Wazuh's string-flattened messages array. Avoid
    # a mapping-dependent text query; inspect a capped set and filter exact IDs.
    scan_size = MAX_SCAN if kind == "modsecurity" and "rule_id" in args else args["limit"]
    return {
        "size": scan_size,
        "track_total_hits": False,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": {"includes": SURICATA_FIELDS if kind == "suricata" else WAF_FIELDS},
        "query": {"bool": {"filter": filters}},
    }


def indexer_search(query):
    host = os.environ.get("WAZUH_INDEXER_HOST", "127.0.0.1")
    port_text = os.environ.get("WAZUH_INDEXER_PORT", "9200")
    username = os.environ.get("WAZUH_INDEXER_USERNAME", "")
    password = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("Indexer read-only credentials are unavailable")
    # The endpoint comes only from B's environment, never from MCP arguments.
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", host) or ":" in host:
        raise RuntimeError("Invalid Indexer host configuration")
    try:
        port = int(port_text)
    except ValueError:
        raise RuntimeError("Invalid Indexer port configuration") from None
    if not 1 <= port <= 65535:
        raise RuntimeError("Invalid Indexer port configuration")
    endpoint = "https://%s:%d/%s/_search" % (host, port, INDEX)
    credential = base64.b64encode((username + ":" + password).encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        endpoint, data=json.dumps(query, separators=(",", ":")).encode("utf-8"), method="POST",
        headers={"Authorization": "Basic " + credential, "Content-Type": "application/json"},
    )
    context = ssl.create_default_context() if os.environ.get("WAZUH_VERIFY_SSL", "true").lower() == "true" else ssl._create_unverified_context()
    # Ignore ambient proxy variables: mcp-ro credentials belong only to the
    # configured Indexer, not an inherited HTTPS_PROXY endpoint.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=12) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise RuntimeError("Indexer result exceeded response limit")
    return json.loads(body)


def extract_waf_rule_ids(messages):
    """Handle both ModSecurity JSON arrays and Wazuh's flattened string."""
    found = []

    def add(value):
        token = _scalar(value, 16)
        if RULE_ID_RE.fullmatch(token) and token not in found:
            found.append(token)

    if isinstance(messages, list):
        for message in messages:
            details = _obj(_obj(message).get("details"))
            add(details.get("ruleId"))
            add(_obj(message).get("ruleId"))
    elif isinstance(messages, dict):
        add(_obj(messages.get("details")).get("ruleId"))
        add(messages.get("ruleId"))
    elif isinstance(messages, str):
        try:
            parsed = json.loads(messages)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return extract_waf_rule_ids(parsed)
        # Free-form text can contain attacker-controlled ruleId-looking text.
        # Only structured messages (or a valid JSON serialization of them)
        # identify an actual WAF rule.
    return found


def dns_questions(value):
    dns = _obj(value)
    rows = dns.get("queries")
    if not isinstance(rows, list):
        rows = [dns] if "rrname" in dns else []
    questions = []
    incomplete = len(rows) > 16
    for row in rows[:16]:
        row = _obj(row)
        name, kind = row.get("rrname"), row.get("rrtype")
        if (not isinstance(name, str) or not 1 <= len(name) <= 253
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                or not isinstance(kind, str) or not re.fullmatch(r"[A-Z0-9]{1,16}", kind)):
            incomplete = True
            continue
        questions.append({"name": name, "type": kind})
    return {"dns_questions": questions, "dns_questions_incomplete": incomplete,
            "dns_message_type": dns.get("type") if dns.get("type") in ("request", "response", "query", "answer") else ""}


def opaque_hash(value):
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 4096:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def http_context(transaction):
    request = _obj(transaction.get("request"))
    uri = request.get("uri")
    path, incomplete, query_omitted = "", False, False
    if isinstance(uri, str) and uri:
        query_omitted = "?" in uri or "#" in uri
        if len(uri) > 8192 or CONTROL_RE.search(uri):
            incomplete = True
        else:
            try:
                # Preserve dot/encoded segments. Do not decode or normalize evidence.
                if uri.startswith("/"):
                    path = re.split(r"[?#]", uri, maxsplit=1)[0]
                else:
                    parsed = urlsplit(uri)
                    if parsed.scheme not in ("http", "https") or not parsed.netloc:
                        raise ValueError()
                    path = parsed.path
                incomplete = len(path) > 512
                path = path[:512]
            except ValueError:
                incomplete = True
    elif uri is not None:
        incomplete = True
    headers = _obj(request.get("headers"))
    return {"request_path": path, "request_path_incomplete": incomplete,
            "request_query_omitted": query_omitted,
            "transaction_id_sha256": opaque_hash(transaction.get("unique_id")),
            "user_agent_sha256": opaque_hash(headers.get("User-Agent"))}


def summarize_suricata(source):
    data = _obj(source.get("data"))
    alert = _obj(data.get("alert"))
    rule = _obj(source.get("rule"))
    return {
        "timestamp": _kst_timestamp(source.get("timestamp")),
        "agent": _scalar(_obj(source.get("agent")).get("name"), 80),
        "source_ip": _scalar(data.get("src_ip") or data.get("srcip"), 64),
        "destination_ip": _scalar(data.get("dest_ip"), 64),
        "destination_port": _scalar(data.get("dest_port"), 8),
        "protocol": _scalar(data.get("proto"), 16),
        "signature_id": _scalar(alert.get("signature_id"), 16),
        "signature": _scalar(alert.get("signature"), 160),
        "category": _scalar(alert.get("category"), 80),
        "severity": _scalar(alert.get("severity"), 8),
        "wazuh_rule_id": _scalar(rule.get("id"), 16),
        "wazuh_level": _scalar(rule.get("level"), 8),
        **dns_questions(data.get("dns")),
    }


def summarize_modsecurity(source):
    transaction = _obj(_obj(source.get("data")).get("transaction"))
    rule = _obj(source.get("rule"))
    return {
        "timestamp": _kst_timestamp(source.get("timestamp")),
        "agent": _scalar(_obj(source.get("agent")).get("name"), 80),
        "source_ip": _scalar(transaction.get("client_ip"), 64),
        "method": _scalar(_obj(transaction.get("request")).get("method"), 16),
        "http_status": _scalar(_obj(transaction.get("response")).get("http_code"), 8),
        "engine": _scalar(_obj(transaction.get("producer")).get("secrules_engine"), 24),
        "waf_rule_ids": extract_waf_rule_ids(transaction.get("messages"))[:20],
        "wazuh_rule_id": _scalar(rule.get("id"), 16),
        "wazuh_level": _scalar(rule.get("level"), 8),
        **http_context(transaction),
    }


def search(kind, args):
    params = validate_args(kind, args)
    query = build_query(kind, params)
    result = indexer_search(query)
    hits = _obj(result.get("hits")).get("hits")
    if not isinstance(hits, list):
        raise RuntimeError("Indexer returned an unexpected response")
    rows = []
    for hit in hits:
        source = _obj(_obj(hit).get("_source"))
        row = summarize_suricata(source) if kind == "suricata" else summarize_modsecurity(source)
        if kind == "modsecurity" and "rule_id" in params and params["rule_id"] not in row["waf_rule_ids"]:
            # Search against all extracted IDs, even if display is capped.
            transaction = _obj(_obj(source.get("data")).get("transaction"))
            if params["rule_id"] not in extract_waf_rule_ids(transaction.get("messages")):
                continue
        rows.append(row)
        if len(rows) >= params["limit"]:
            break
    return {
        "source": kind, "lookback_minutes": params["lookback_minutes"],
        "requested_since_kst": _kst_timestamp(query["query"]["bool"]["filter"][0]["range"]["timestamp"]["gte"]),
        "requested_until_kst": _kst_timestamp(query["query"]["bool"]["filter"][0]["range"]["timestamp"]["lte"]),
        "returned_count": len(rows), "indexed_window_total_count": None,
        "source_scope": "wazuh_indexed_alerts", "untrusted_evidence": True,
        "evidence_scope_ko": "색인된 경보의 제한된 반환 표본입니다. 원시 센서 로그 직접 조회가 아니며 수집·색인 지연/누락이 가능합니다. "
            "반환0건은 이 검색 표본0건을 뜻하고 전체 공격/경보 부재나 정상 판정을 입증하지 않습니다. 요청 구간 전체 건수는 미확인입니다.",
        "limit": params["limit"], "scanned": len(hits),
        "scan_capped": len(hits) >= query["size"],
        "alerts": rows,
    }


def tool_text(value, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": is_error}


def call_tool(name, args):
    kind = {"search_suricata_alerts": "suricata", "search_modsecurity_alerts": "modsecurity"}.get(name) if isinstance(name, str) else None
    if kind is None and name != "get_wazuh_sca_checks":
        return None
    try:
        return tool_text(sca_checks(args) if name == "get_wazuh_sca_checks" else search(kind, args))
    except ValueError as exc:
        return tool_text({"error": str(exc)}, True)
    except Exception as exc:
        # Do not expose HTTP errors, endpoints, raw responses or credentials.
        print("security-events-mcp: query failed (%s)" % type(exc).__name__, file=sys.stderr)
        return tool_text({"error": "Read-only query failed; check server logs"}, True)


def handle(message):
    mid = message.get("id")
    method = message.get("method")
    if method == "initialize":
        requested = _obj(message.get("params")).get("protocolVersion")
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": requested if isinstance(requested, str) and requested in SUPPORTED_PROTOCOLS else PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "capstone-security-events-mcp", "version": "1.1.0"},
        }}
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = _obj(message.get("params"))
        result = call_tool(params.get("name"), params.get("arguments", {}))
        if result is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}
    if mid is None:
        return None
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}


def main():
    for line in sys.stdin:
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                continue
            response = handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            print("security-events-mcp: protocol error (%s)" % type(exc).__name__, file=sys.stderr)


if __name__ == "__main__":
    main()
