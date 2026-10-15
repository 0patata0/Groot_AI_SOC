#!/usr/bin/env python3
"""Offline regression for extending the six-SID exception .110 -> [.110,.111].

This utility writes packet files or reads offline EVE only. It sends no packets,
does not call Docker/Suricata, and never changes rules or reloads the live sensor.
The two historical exception validators are imported without modifying them.

Construct TWO isolated replay rule files in this order:
  baseline.rules = current original ET 2034806/2034802 + CURRENT approved local
                   rules (.110 marker, all six guarded SIDs) + control.rules
  candidate.rules = same original ET pair + candidate local rules (one marker
                    for exactly [.110,.111], same six guards) + control.rules
The duplicate ET SIDs intentionally exercise higher-revision override selection.
Use the sensor's actual Suricata version and configuration; fixture HOME_NET is
[10.200.10.0/24,192.168.16.230/32]. Do not put the control rule into live rules.
Separately syntax-test the FULL current ET + candidate with Suricata -T.

  python3 -B validate_dgx_endpoint_transition.py generate --output-dir /tmp/dgx-fixture
  # For each mode: use a NEW isolated /tmp/dgx-MODE output directory.
  suricata -c /etc/suricata/suricata.yaml --runmode single \\
      --set unix-command.enabled=no --set stats.enabled=yes \\
      -r /tmp/dgx-fixture/traffic.pcap -S /tmp/baseline.rules -l /tmp/dgx-baseline
  python3 -B validate_dgx_endpoint_transition.py check --mode baseline \\
      --manifest /tmp/dgx-fixture/manifest.json --eve /tmp/dgx-baseline/eve.json
  # Repeat the isolated replay/check with candidate.rules and --mode candidate.

Checks compare exact SID sets per TCP direction, not alert counts. Other rules
from the full ET set must not be included in these isolated replays. This test
does not establish live traffic attribution, authentication, actual reload, or
long-term false-positive rates. Non-API cases expose the transport-only scope.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

import validate_et_llm_exception as et
from validate_llm_flow_exception import (
    A_IP, BENIGN_BODY, Capture, Connection, checksum, response, split_inside, tuple_key,
)

OLD_DGX = '211.170.162.110'
NEW_DGX = '211.170.162.111'
SELECTED_SIDS = sorted(et.ET_SIDS + et.LOCAL_EXCEPTION_SIDS)
CONTROL_RULE = et.CONTROL_RULE
STYLES = ('single', 'split', 'keepalive', 'sse', 'uri', 'header', 'non_api')


def expected_policy(client, server, port, style, endpoints):
    exempt = client == A_IP and server in endpoints and port == 11434
    benign = style == 'benign'
    # Both rule files ALREADY contain all six guarded signatures. The old ET
    # validator's original baseline (ET exceptions absent) must not be used.
    expected = et.policy(benign, exempt, et.in_home_net(client), style, candidate=True)
    response_sids = set(expected['required_response_sids'])
    request_sids = (set(expected['required_request_sids']) |
                    (set(expected['required_sids']) - response_sids))
    return {'exception_scope': exempt,
            'expected_request_sids': sorted(request_sids),
            'expected_response_sids': sorted(response_sids),
            'forbidden_sids': sorted(set(expected['forbidden_sids'])),
            'no_alerts': benign}


def build_capture():
    capture, cases = Capture(), []
    definitions = []
    for label, address in (('former_dgx', OLD_DGX), ('new_dgx', NEW_DGX)):
        for style in STYLES:
            definitions.append((label + '_' + style, A_IP, address, 11434, style))
    definitions.extend([
        ('new_dgx_other_port', A_IP, NEW_DGX, 8080, 'single'),
        ('former_dgx_other_port', A_IP, OLD_DGX, 8080, 'single'),
        ('other_home_client_to_new_dgx', '10.200.10.10', NEW_DGX, 11434, 'single'),
        ('other_nonhome_client_to_new_dgx', '192.168.16.231', NEW_DGX, 11434, 'single'),
        ('unapproved_dgx', A_IP, '211.170.162.112', 11434, 'single'),
        ('other_external_destination', A_IP, '198.51.100.10', 11434, 'single'),
        ('home_to_internal_et_applies', A_IP, '10.200.10.20', 8080, 'single'),
        ('new_dgx_initiated_to_a', NEW_DGX, A_IP, 8080, 'single'),
        ('former_dgx_initiated_to_a', OLD_DGX, A_IP, 8080, 'single'),
        ('external_to_internal', '198.51.100.50', '10.200.10.20', 8080, 'single'),
        ('benign_new_dgx', A_IP, NEW_DGX, 11434, 'benign'),
        ('benign_former_dgx', A_IP, OLD_DGX, 11434, 'benign'),
        ('benign_web', '198.51.100.50', A_IP, 8080, 'benign'),
    ])
    for index, (name, client, server, port, style) in enumerate(definitions):
        source_port = 43000 + index
        conn = Connection(capture, client, server, source_port, port)
        benign = style == 'benign'
        if style == 'keepalive':
            conn.send(True, [et.request(BENIGN_BODY)])
            conn.send(False, [response(b'Hello\n')])
        request = et.request(BENIGN_BODY if benign else et.ATTACK_BODY, style)
        if style == 'split':
            boundary = request.index(b'\r\n\r\n') + 4
            chunks = [request[:boundary], *split_inside(request[boundary:], b'${jndi:', 4)]
        else:
            chunks = [request]
        conn.send(True, chunks)
        reply = response(b'Hello\n' if benign else (et.SSE_TEXT if style == 'sse' else et.REPLY_TEXT),
                         sse=style == 'sse')
        conn.send(False, split_inside(reply, b'${jndi:', 4) if style == 'sse' else [reply])
        conn.close()
        cases.append({'id': name, 'client_ip': client, 'client_port': source_port,
                      'server_ip': server, 'server_port': port, 'style': style,
                      'original_et_header_applies': et.in_home_net(client),
                      'baseline': expected_policy(client, server, port, style, (OLD_DGX,)),
                      'candidate': expected_policy(client, server, port, style, (OLD_DGX, NEW_DGX))})
    raw = capture.bytes()
    manifest = {
        'schema_version': 1, 'purpose': 'offline six-SID exact two-DGX endpoint exception expansion',
        'baseline_endpoints': [OLD_DGX], 'candidate_endpoints': [OLD_DGX, NEW_DGX],
        'home_net': et.HOME_NET, 'selected_sids': SELECTED_SIDS,
        'pcap': {'path': 'traffic.pcap', 'sha256': hashlib.sha256(raw).hexdigest(),
                 'packets': len(capture.packets)},
        'control_rules': {'path': 'control.rules', 'sid': et.CONTROL_SID,
                          'sha256': hashlib.sha256(CONTROL_RULE.encode()).hexdigest()},
        'cases': cases,
    }
    return raw, manifest


def generate(output_dir):
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise ValueError('output directory exists; choose a new isolated path')
    raw, manifest = build_capture()
    output_dir.mkdir(parents=True)
    (output_dir / 'traffic.pcap').write_bytes(raw)
    (output_dir / 'control.rules').write_text(CONTROL_RULE, encoding='utf-8')
    (output_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return {'generated': str(output_dir), 'cases': len(manifest['cases']),
            'packets': manifest['pcap']['packets'], 'pcap_sha256': manifest['pcap']['sha256']}


def check(manifest_path, eve_path, mode):
    if mode not in ('baseline', 'candidate'):
        raise ValueError('unknown check mode')
    manifest_path, eve_path = Path(manifest_path), Path(eve_path)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    _, expected = build_capture()
    if manifest != expected:
        raise ValueError('manifest differs from deterministic endpoint transition fixture')
    for name in ('pcap', 'control_rules'):
        artifact = manifest[name]
        raw = (manifest_path.parent / artifact['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != artifact['sha256']:
            raise ValueError('fixture artifact checksum mismatch: ' + name)
    lookup, seen = {}, {}
    for case in manifest['cases']:
        seen[case['id']] = {'request': set(), 'response': set()}
        for reverse in (False, True):
            key = tuple_key(case, reverse)
            if key in lookup:
                raise ValueError('duplicate fixture connection tuple')
            lookup[key] = (case['id'], 'response' if reverse else 'request')
    unexpected = 0
    with eve_path.open(encoding='utf-8') as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError('non-object EVE event at line %d' % number)
            if event.get('event_type') != 'alert':
                continue
            try:
                key = (event['src_ip'], int(event['src_port']), event['dest_ip'], int(event['dest_port']))
                sid = int(event['alert']['signature_id'])
            except (KeyError, ValueError, TypeError) as exc:
                raise ValueError('invalid alert tuple/SID at line %d' % number) from exc
            if key not in lookup:
                unexpected += 1
                continue
            name, direction = lookup[key]
            seen[name][direction].add(sid)
    results, failures = [], []
    for case in manifest['cases']:
        observed, expected = seen[case['id']], case[mode]
        row = {'case': case['id'], 'pass': True}
        for direction in ('request', 'response'):
            wanted = set(expected['expected_' + direction + '_sids'])
            actual = observed[direction]
            missing, extra = sorted(wanted - actual), sorted(actual - wanted)
            row['observed_' + direction + '_sids'] = sorted(actual)
            row['missing_' + direction + '_sids'] = missing
            row['unexpected_' + direction + '_sids'] = extra
            if missing or extra:
                row['pass'] = False
        if not row['pass']:
            failures.append(case['id'])
        results.append(row)
    if unexpected:
        failures.append('unexpected_alert_flows')
    return {'mode': mode, 'pass': not failures, 'failures': failures, 'cases': results,
            'unexpected_alert_count': unexpected, 'pcap_sha256': manifest['pcap']['sha256'],
            'eve_sha256': hashlib.sha256(eve_path.read_bytes()).hexdigest()}


def synthetic_events(manifest, mode):
    events = []
    for case in manifest['cases']:
        for reverse, direction in ((False, 'request'), (True, 'response')):
            src, sport, dst, dport = tuple_key(case, reverse)
            for sid in case[mode]['expected_' + direction + '_sids']:
                events.append({'event_type': 'alert', 'src_ip': src, 'src_port': sport,
                               'dest_ip': dst, 'dest_port': dport, 'alert': {'signature_id': sid}})
    return events


def write_events(path, events):
    path.write_text(''.join(json.dumps(event) + '\n' for event in events), encoding='utf-8')


def selftest():
    raw, manifest = build_capture()
    assert (raw, manifest) == build_capture()
    assert len(manifest['cases']) == 27
    cases = {case['id']: case for case in manifest['cases']}
    for label in ('former_dgx', 'new_dgx'):
        for style in STYLES:
            case = cases[label + '_' + style]
            for mode in ('baseline', 'candidate'):
                exempt = label == 'former_dgx' or mode == 'candidate'
                if exempt:
                    assert not set(SELECTED_SIDS) & set(case[mode]['expected_request_sids'])
                    assert case[mode]['expected_response_sids'] == []
                else:
                    assert set(SELECTED_SIDS) <= set(case[mode]['expected_request_sids'])
                    assert case[mode]['expected_response_sids'] == [1000070, 1000071]
                assert et.CONTROL_SID in case[mode]['expected_request_sids']
    for mode in ('baseline', 'candidate'):
        assert set(SELECTED_SIDS) <= set(cases['unapproved_dgx'][mode]['expected_request_sids'])
    assert 1000030 in cases['new_dgx_uri']['candidate']['expected_request_sids']
    assert 1000031 in cases['new_dgx_header']['candidate']['expected_request_sids']
    cursor, packets = 24, 0
    while cursor < len(raw):
        _, _, caplen, wirelen = struct.unpack_from('<IIII', raw, cursor)
        assert caplen == wirelen
        data = raw[cursor + 16:cursor + 16 + caplen]
        ip, tcp = data[14:34], data[34:]
        assert checksum(ip) == 0
        assert checksum(ip[12:20] + struct.pack('!BBH', 0, 6, len(tcp)) + tcp) == 0
        cursor += 16 + caplen
        packets += 1
    assert cursor == len(raw) and packets == manifest['pcap']['packets']
    with tempfile.TemporaryDirectory(prefix='soc-dgx-transition-selftest-') as temp:
        fixture = Path(temp) / 'fixture'
        generate(fixture)
        manifest_path, eve = fixture / 'manifest.json', Path(temp) / 'eve.json'
        for mode in ('baseline', 'candidate'):
            events = synthetic_events(manifest, mode)
            write_events(eve, events)
            assert check(manifest_path, eve, mode)['pass']
            assert not check(manifest_path, eve, 'candidate' if mode == 'baseline' else 'baseline')['pass']
            # Missing one required observation must not pass.
            write_events(eve, events[1:])
            assert not check(manifest_path, eve, mode)['pass']
            # Any alert for the no-alert marker, including a known flow, fails.
            contaminated = dict(events[0], alert={'signature_id': 1000000})
            write_events(eve, events + [contaminated])
            assert not check(manifest_path, eve, mode)['pass']
            contaminated = dict(events[0], src_ip='203.0.113.253')
            write_events(eve, events + [contaminated])
            assert not check(manifest_path, eve, mode)['pass']
        write_events(eve, [])
        assert not check(manifest_path, eve, 'candidate')['pass']
        original_manifest = manifest_path.read_bytes()
        bad = json.loads(original_manifest)
        bad['cases'][0]['candidate']['expected_request_sids'] = []
        manifest_path.write_text(json.dumps(bad))
        try:
            check(manifest_path, eve, 'candidate')
        except ValueError:
            pass
        else:
            raise AssertionError('tampered expectation accepted')
        manifest_path.write_bytes(original_manifest)
        (fixture / 'traffic.pcap').write_bytes(raw + b'X')
        try:
            check(manifest_path, eve, 'candidate')
        except ValueError:
            pass
        else:
            raise AssertionError('tampered capture accepted')
    return {'selftest': 'PASS', 'cases': len(cases), 'packets': packets,
            'pcap_sha256': manifest['pcap']['sha256'],
            'checks': ['deterministic bytes', 'IPv4/TCP checksums', 'both endpoints and all seven styles',
                       '110 exception preserved, 111 added, 112 remains detected',
                       'six SID transition and directional exact sets', 'old/new mode interchange rejected',
                       'missing/extra/unknown-flow alerts rejected', 'empty EVE rejected',
                       'tampered manifest and PCAP rejected'],
            'suricata_replay': 'not performed by selftest'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    generate_parser = sub.add_parser('generate')
    generate_parser.add_argument('--output-dir', required=True)
    check_parser = sub.add_parser('check')
    check_parser.add_argument('--manifest', required=True)
    check_parser.add_argument('--eve', required=True)
    check_parser.add_argument('--mode', required=True, choices=('baseline', 'candidate'))
    check_parser.add_argument('--report', help='optional new JSON report; never overwrite')
    sub.add_parser('selftest')
    args = parser.parse_args(argv)
    try:
        if args.command == 'generate':
            result = generate(args.output_dir)
        elif args.command == 'selftest':
            result = selftest()
        else:
            result = check(args.manifest, args.eve, args.mode)
            if args.report:
                with Path(args.report).open('x', encoding='utf-8') as output:
                    output.write(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
        return 1 if result.get('pass') is False else 0
    except (OSError, ValueError, AssertionError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
