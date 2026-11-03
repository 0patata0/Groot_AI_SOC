#!/usr/bin/env python3
"""Bounded 97:3 live HTTP experiment from Kali232 to the approved lab only.

Normal GET / requests come from two newly imported Wireshark captures. The
three web attack controls reuse previously reviewed, read-only lab samples;
malware C2 captures are tested separately offline, not sent to C2 endpoints.
"""
import collections
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import time
from zoneinfo import ZoneInfo

ROOT = Path('/home/att/Desktop/PCAP/public-20261103')
SOURCE = '192.168.16.232'
TARGET = '192.168.16.230'


def now():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat(timespec='milliseconds')


def main():
    assert Path.home() == Path('/home/att')
    os.umask(0o077)
    work = ROOT / 'web-mixed-r1'
    work.mkdir(mode=0o700, exist_ok=False)
    imported = json.loads((ROOT / 'import-result.json').read_text())
    normals = []
    for name in ('wireshark-http-chunked', 'wireshark-http-jpegs'):
        item = next(x for x in imported['captures'] if x['case'] == name)
        pcap = ROOT / 'imported' / item['path']
        assert hashlib.sha256(pcap.read_bytes()).hexdigest() == item['sha256']
        r = subprocess.run(['tshark', '-n', '-r', str(pcap), '-Y', 'frame.number == 4',
                            '-T', 'fields', '-e', 'http.request.method', '-e', 'http.request.uri',
                            '-e', 'http.user_agent'], capture_output=True, text=True, check=True, timeout=10)
        method, uri, ua = r.stdout.rstrip('\n').split('\t')
        assert method == 'GET' and uri == '/' and '\r' not in ua and '\n' not in ua
        normals.append({'case_id': name, 'frame': 4, 'pcap_sha256': item['sha256'],
                        'user_agent': ua, 'original_uri_sha256': hashlib.sha256(uri.encode()).hexdigest()})
    old = json.loads(Path('/home/att/.local/state/capstone-web-eval/20261103-r1/expanded-manifest.json').read_text())
    attacks = [next(c for c in old['cases'] if c['case_id'] == name)
               for name in ('sqli-1', 'traversal-1', 'xss-1')]
    for case in attacks:
        assert case['method'] == 'GET' and case['host'] == 'dvwa.grootlab.duckdns.org'
        pcap = Path('/home/att/Desktop/PCAP') / case['source']
        assert hashlib.sha256(pcap.read_bytes()).hexdigest() == case['pcap_sha256']
    manifest = {'run_id': 'public-pcap-20261103-kali232-web-mixed-r1',
                'normal_count': 97, 'attack_count': 3, 'attack_positions': [98, 99, 100],
                'normal_sources': normals, 'attack_controls': attacks,
                'source_ip': SOURCE, 'connect_ip': TARGET, 'connect_port': 80,
                'transform': 'new TCP connection; original GET / mapped to lab mount; lab Host only; no cookies/auth/body'}
    (work / 'manifest-private.json').write_text(json.dumps(manifest, indent=2))
    rows, start, begin = [], time.monotonic(), now()
    for i in range(1, 101):
        attack = i >= 98
        case = attacks[i - 98] if attack else normals[(i - 1) % len(normals)]
        host = 'dvwa.grootlab.duckdns.org' if attack or i % 2 else 'log4shell.grootlab.duckdns.org'
        uri = case['uri'] if attack else ('/dvwa/' if i % 2 else '/log4shell/')
        conn = http.client.HTTPConnection(TARGET, 80, timeout=2, source_address=(SOURCE, 0))
        row = {'seq': i, 'case_id': case['case_id'], 'label': 'attack-control' if attack else 'normal-control',
               'at_kst': now(), 'uri_sha256': hashlib.sha256(uri.encode()).hexdigest(),
               'connected': False, 'sent': False, 'status': None}
        try:
            conn.connect()
            row.update(connected=True, local_endpoint=conn.sock.getsockname(), peer_endpoint=conn.sock.getpeername())
            conn.putrequest('GET', uri, skip_host=True, skip_accept_encoding=True)
            conn.putheader('Host', host)
            conn.putheader('User-Agent', case['user_agent'])
            conn.putheader('X-SOC-Test-ID', manifest['run_id'] + '/' + str(i))
            conn.putheader('Connection', 'close')
            conn.endheaders()
            row['sent'] = True
            response = conn.getresponse()
            row['status'] = response.status
            row['response_prefix_sha256'] = hashlib.sha256(response.read(8192)).hexdigest()
        except (OSError, http.client.HTTPException) as exc:
            row['error_type'] = type(exc).__name__
        finally:
            conn.close()
        rows.append(row)
        with (work / 'results.jsonl').open('a') as f:
            f.write(json.dumps(row) + '\n')
        delay = (0.25 if i <= 97 else 0.08)
        time.sleep(delay)
    summary = {'run_id': manifest['run_id'], 'started_kst': begin, 'ended_kst': now(),
               'attempted': len(rows), 'normal_sent': sum(x['sent'] for x in rows[:97]),
               'attack_sent': sum(x['sent'] for x in rows[97:]),
               'normal_statuses': dict(collections.Counter(str(x['status']) for x in rows[:97])),
               'attack_results': rows[97:], 'elapsed_s': round(time.monotonic() - start, 3),
               'results_sha256': hashlib.sha256((work / 'results.jsonl').read_bytes()).hexdigest(),
               'normal_sources': [{k: v for k, v in x.items() if k != 'user_agent'} for x in normals],
               'attack_sources': [{k: c[k] for k in ('case_id', 'family', 'source', 'pcap_sha256', 'frame')} for c in attacks]}
    (work / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
