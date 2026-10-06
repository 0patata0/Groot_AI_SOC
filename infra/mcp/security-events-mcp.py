#!/usr/bin/env python3
"""Read-only MCP view of Suricata and ModSecurity Wazuh alerts on Groot_B.

Uses the existing mcp-ro Indexer credentials from /etc/mcp/wazuh-ro.env. Only
the fixed wazuh-alerts-* index is queried, so events not yet indexed by Wazuh
cannot appear. Results use KST (+09:00) ISO 8601 timestamps. Raw logs,
ModSecurity messages, headers, and request bodies are never returned.
"""

import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
import re
import ssl
import sys
import urllib.request


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
]
WAF_FIELDS = COMMON_FIELDS + [
    "data.transaction.client_ip", "data.transaction.request.method",
    "data.transaction.response.http_code", "data.transaction.producer.secrules_engine",
    "data.transaction.messages",  # examined only in memory to extract numeric rule IDs
]

TOOLS = [
    {
        "name": "search_suricata_alerts",
        "description": "Search recent Suricata IDS alerts already indexed by Wazuh (not live raw EVE). Returns bounded summaries with KST timestamps.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "lookback_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_LOOKBACK_MINUTES, "default": 60},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": 10},
                "source_ip": {"type": "string", "description": "Exact source IPv4 or IPv6 address"},
                "signature_id": {"type": "string", "pattern": "^[0-9]{1,10}$", "description": "Exact Suricata SID"},
            },
        },
        "annotations": {"title": "Search Suricata alerts", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
    {
        "name": "search_modsecurity_alerts",
        "description": "Search recent ModSecurity WAF alerts already indexed by Wazuh (not live raw audit logs). Returns safe metadata, numeric WAF rule IDs, and KST timestamps.",
        "inputSchema": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "lookback_minutes": {"type": "integer", "minimum": 1, "maximum": MAX_LOOKBACK_MINUTES, "default": 60},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "default": 10},
                "source_ip": {"type": "string", "description": "Exact source IPv4 or IPv6 address"},
                "rule_id": {"type": "string", "pattern": "^[0-9]{1,10}$", "description": "Exact ModSecurity/CRS rule ID"},
            },
        },
        "annotations": {"title": "Search ModSecurity alerts", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
    },
]


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
    allowed = {"lookback_minutes", "limit", "source_ip"}
    id_key = "signature_id" if kind == "suricata" else "rule_id"
    allowed.add(id_key)
    unknown = set(args) - allowed
    if unknown:
        raise ValueError("unsupported argument: %s" % sorted(unknown)[0])
    out = {
        "lookback_minutes": _positive_int(args.get("lookback_minutes"), "lookback_minutes", 60, MAX_LOOKBACK_MINUTES),
        "limit": _positive_int(args.get("limit"), "limit", 10, MAX_LIMIT),
    }
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


def build_query(kind, args):
    """Construct a fixed, bounded DSL; callers never supply an index or query."""
    label = "suricata" if kind == "suricata" else "modsecurity"
    identity = [
        {"term": {"rule.groups": label}},
        {"term": {"data.capstone.source": label}},
        {"exists": {"field": "data.alert.signature_id" if kind == "suricata" else "data.transaction.producer.modsecurity"}},
    ]
    filters = [
        {"range": {"timestamp": {"gte": "now-%dm" % args["lookback_minutes"]}}},
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
        "limit": params["limit"], "scanned": len(hits),
        "scan_capped": len(hits) >= query["size"],
        "alerts": rows,
    }


def tool_text(value, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": is_error}


def call_tool(name, args):
    kind = {"search_suricata_alerts": "suricata", "search_modsecurity_alerts": "modsecurity"}.get(name) if isinstance(name, str) else None
    if kind is None:
        return None
    try:
        return tool_text(search(kind, args))
    except ValueError as exc:
        return tool_text({"error": str(exc)}, True)
    except Exception as exc:
        # Do not expose HTTP errors, endpoints, raw responses or credentials.
        print("security-events-mcp: query failed (%s)" % type(exc).__name__, file=sys.stderr)
        return tool_text({"error": "Indexer query failed; check server logs"}, True)


def handle(message):
    mid = message.get("id")
    method = message.get("method")
    if method == "initialize":
        requested = _obj(message.get("params")).get("protocolVersion")
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": requested if isinstance(requested, str) and requested in SUPPORTED_PROTOCOLS else PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "capstone-security-events-mcp", "version": "1.0.0"},
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
