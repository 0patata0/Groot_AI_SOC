#!/usr/bin/env python3
"""Generate/check offline HTTP response threshold fixtures; sends no packets.

Only the observed SID 1000002 revision 1 block is eligible for the candidate.
Use a fresh isolated Suricata process per mode. Do not load the fixture control
rule into production. The PCAPs contain synthetic reserved addresses only.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct

SUPPORT = Path(__file__).resolve().parents[2] / 'mcp/validate_llm_flow_exception.py'
spec = importlib.util.spec_from_file_location('http404_packet_support', SUPPORT)
packet_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet_support)

SID = 1000002
CONTROL_SID = 1000998
CONTROL_RULE = ('alert http any any -> any any (msg:"OFFLINE ONLY HTTP404 transaction control"; '
                'flow:established,to_server; http.uri; content:"/soc-404-fixture/"; '
                'sid:1000998; rev:1;)\n')
OLD = '''# High-rate 404 path enumeration (directory brute force) from one source.
alert http any any -> any any ( \\
    msg:"GROOT-LOCAL S1 directory/content brute force (many requests, scanner cadence)"; \\
    flow:to_server,established; \\
    http.uri; content:"/"; \\
    threshold:type threshold, track by_src, count 40, seconds 10; \\
    classtype:attempted-recon; \\
    metadata:mitre_technique_id T1595.003, groot_scenario S1, groot_layer ips; \\
    sid:1000002; rev:1;)'''
NEW = '''# Count actual 404 responses per receiving client, not every HTTP request.
# The wire source is the responding server. target:src_ip preserves that fact
# and identifies alert.source as the requesting client / alert.target as server.
# This is an enumeration signal, not proof that all failures are malicious.
alert http any any -> any any ( \\
    msg:"GROOT-LOCAL S1 HTTP 404 response burst to one client (40 per 10s, enumeration signal)"; \\
    flow:to_client,established; \\
    http.stat_code; content:"404"; bsize:3; \\
    threshold:type threshold, track by_dst, count 40, seconds 10; \\
    classtype:attempted-recon; target:src_ip; \\
    metadata:mitre_technique_id T1595.003, groot_scenario S1, groot_layer ips; \\
    sid:1000002; rev:2;)'''


def candidate(original):
    if original.count(OLD) != 1:
        raise ValueError('exact observed revision-1 block required')
    return original.replace(OLD, NEW, 1)


class TimedCapture(packet_support.Capture):
    def __init__(self):
        super().__init__()
        self.times = []
        self.current_us = 0

    def append(self, *args):
        super().append(*args)
        self.times.append(self.current_us)
        self.current_us += 100

    def bytes(self):
        result = bytearray(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for raw, total_us in zip(self.packets, self.times):
            sec, usec = divmod(total_us, 1000000)
            result.extend(struct.pack('<IIII', 1793696400 + sec, usec, len(raw), len(raw)))
            result.extend(raw)
        return bytes(result)


def definitions():
    return [
        ('normal_200', [200] * 80, 1, 1, .1, False, False, False, 2, 0),
        ('normal_308', [308] * 80, 1, 1, .1, False, False, False, 2, 0),
        ('denied_403', [403] * 80, 1, 1, .1, False, False, False, 2, 0),
        ('missing_39', [404] * 39, 1, 1, .1, False, False, False, 0, 0),
        ('missing_40', [404] * 40, 1, 1, .1, False, False, False, 1, 1),
        ('missing_80', [404] * 80, 1, 1, .1, False, False, False, 2, 2),
        ('mixed_below_threshold', [404] * 39 + [200] * 61, 1, 1, .05, False, False, False, 2, 0),
        ('two_clients_20_each', [404] * 40, 2, 1, .1, False, False, False, 0, 0),
        ('one_client_two_servers', [404] * 40, 1, 2, .1, False, False, False, 1, 1),
        ('slow_404', [404] * 40, 1, 1, .4, False, False, False, 0, 0),
        ('segmented_status_404', [404] * 40, 1, 1, .1, True, False, False, 1, 1),
        ('retransmitted_39', [404] * 39, 1, 1, .1, False, True, False, 0, 0),
        ('keepalive_404', [404] * 40, 1, 1, .1, False, False, True, 1, 1),
        ('request_mentions_404', [200] * 60, 1, 1, .1, False, False, False, 1, 0),
    ]


def build():
    cap, cases = TimedCapture(), []
    for index, definition in enumerate(definitions()):
        name, statuses, clients, servers, interval, split, retrans, keepalive, old, new = definition
        base_us = index * 60000000
        client_ips = ['198.51.100.' + str(index * 2 + n + 1) for n in range(clients)]
        server_ips = ['203.0.113.' + str(n + 10) for n in range(servers)]
        conn = None
        for n, status in enumerate(statuses):
            cap.current_us = base_us + int(n * interval * 1000000)
            if conn is None or not keepalive:
                conn = packet_support.Connection(cap, client_ips[n % clients], server_ips[n % servers], 40000 + n, 80)
            suffix = 'literal-404-text-' if name == 'request_mentions_404' else 'item-'
            request = (f'GET /soc-404-fixture/{suffix}{n} HTTP/1.1\r\n'
                       'Host: offline.example.invalid\r\nUser-Agent: Mozilla/5.0\r\n'
                       'Connection: keep-alive\r\n\r\n').encode()
            conn.send(True, [request])
            reply = (f'HTTP/1.1 {status} Status\r\nContent-Length: 2\r\n'
                     'Connection: keep-alive\r\n\r\nOK').encode()
            chunks = [reply[:10], reply[10:]] if split else [reply]
            if retrans:
                # Two identical wire responses with the same sequence number
                # must represent one transaction for threshold accounting.
                conn.emit(False, 0x18, reply)
            conn.send(False, chunks)
            if not keepalive:
                conn.close()
        if keepalive:
            conn.close()
        cases.append({'id': name, 'client_ips': client_ips, 'server_ips': server_ips,
                      'requests': len(statuses), 'baseline_alerts': old, 'candidate_alerts': new})
    raw = cap.bytes()
    return raw, {'schema_version': 1, 'pcap_sha256': hashlib.sha256(raw).hexdigest(),
                 'packets': len(cap.packets), 'cases': cases,
                 'control_rule_sha256': hashlib.sha256(CONTROL_RULE.encode()).hexdigest()}


def generate(output, original):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    raw, manifest = build()
    (output / 'traffic.pcap').write_bytes(raw)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'baseline.rules').write_text(original + '\n' + CONTROL_RULE)
    (output / 'candidate.rules').write_text(candidate(original) + '\n' + CONTROL_RULE)
    (output / 'candidate-local.rules').write_text(candidate(original))
    return manifest


def check(output, eve, mode):
    output = Path(output)
    raw, expected = build()
    manifest = json.loads((output / 'manifest.json').read_text())
    if manifest != expected or (output / 'traffic.pcap').read_bytes() != raw:
        raise ValueError('fixture differs from deterministic definition')
    wanted_key = mode + '_alerts'
    if wanted_key not in ('baseline_alerts', 'candidate_alerts'):
        raise ValueError('unknown mode')
    lookup = {ip: c for c in manifest['cases'] for ip in c['client_ips']}
    seen = {c['id']: {'control': 0, 'alerts': 0} for c in manifest['cases']}
    unknown, identity_errors = [], []
    for line in Path(eve).read_text().splitlines():
        event = json.loads(line)
        if event.get('event_type') != 'alert':
            continue
        alert = event['alert']
        sid = alert.get('signature_id')
        if sid not in (SID, CONTROL_SID):
            unknown.append(sid)
            continue
        client_ip = event.get('src_ip') if mode == 'baseline' or sid == CONTROL_SID else event.get('dest_ip')
        if client_ip not in lookup:
            raise ValueError('alert has unexpected client identity')
        case = lookup[client_ip]
        seen[case['id']]['control' if sid == CONTROL_SID else 'alerts'] += 1
        if mode == 'candidate' and sid == SID:
            source, target = alert.get('source', {}), alert.get('target', {})
            if (source.get('ip') != client_ip or target.get('ip') != event.get('src_ip') or
                    event.get('src_ip') not in case['server_ips']):
                identity_errors.append(case['id'])
    rows = []
    for case in manifest['cases']:
        value = seen[case['id']]
        rows.append({'case': case['id'], 'observed_alerts': value['alerts'],
                     'expected_alerts': case[wanted_key], 'observed_control': value['control'],
                     'expected_control': case['requests'],
                     'pass': value['alerts'] == case[wanted_key] and value['control'] == case['requests']})
    return {'mode': mode, 'pass': all(x['pass'] for x in rows) and not unknown and not identity_errors,
            'cases': rows, 'unknown_sids': unknown, 'identity_errors': identity_errors,
            'pcap_sha256': manifest['pcap_sha256'], 'packets': manifest['packets']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('generate', 'check'))
    parser.add_argument('--output', required=True)
    parser.add_argument('--local-rules')
    parser.add_argument('--eve')
    parser.add_argument('--mode', choices=('baseline', 'candidate'))
    args = parser.parse_args()
    if args.action == 'generate':
        result = generate(args.output, Path(args.local_rules).read_text())
    else:
        result = check(args.output, args.eve, args.mode)
    print(json.dumps(result, indent=2))
    if args.action == 'check' and not result['pass']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
