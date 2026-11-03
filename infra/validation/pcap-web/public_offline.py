#!/usr/bin/env python3
"""Read imported captures on Kali232; one bounded Suricata process per PCAP.

Offline results assess signatures against historical packet content, not live
routing, FW enforcement, WAF behavior or the bots' incident conclusions.
"""
import argparse
import collections
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time
from zoneinfo import ZoneInfo


def now():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 ** 2, 1536 * 1024 ** 2))
    resource.setrlimit(resource.RLIMIT_CPU, (100, 105))
    os.nice(10)


def run(root, config):
    assert str(root) == '/home/att/Desktop/PCAP/public-20261103'
    imported = json.loads((root / 'import-result.json').read_text())
    tool = root / 'tools/suricata-8.0.6'
    work = root / 'offline-r1'
    work.mkdir(mode=0o700, exist_ok=False)
    cfg = work / 'suricata.yaml'
    cfg.write_text(config)
    rows = []
    started = time.monotonic()
    for capture in imported['captures']:
        if time.monotonic() - started > 1100:
            raise TimeoutError('whole experiment deadline')
        output = work / capture['case']
        output.mkdir(mode=0o700)
        pcap = root / 'imported' / capture['path']
        assert hashlib.sha256(pcap.read_bytes()).hexdigest() == capture['sha256']
        row = {'case': capture['case'], 'started_kst': now(),
               'pcap_sha256': capture['sha256'], 'bytes': capture['bytes']}
        fields = ['frame.number', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
                  'http.request.method', 'http.host', 'http.request.uri', 'http.user_agent']
        args = ['tshark', '-n', '-r', str(pcap), '-Y', 'http.request', '-T', 'fields']
        for field in fields:
            args += ['-e', field]
        with (output / 'http-private.tsv').open('x') as f:
            r = subprocess.run(args, stdout=f, stderr=subprocess.PIPE, text=True, timeout=40)
        row['tshark_rc'] = r.returncode
        row['http_requests'] = sum(1 for _ in (output / 'http-private.tsv').open())
        args = [str(tool / 'lib64/ld-linux-x86-64.so.2'), '--library-path', str(tool / 'lib64'),
                str(tool / 'usr/bin/suricata'), '-c', str(cfg), '--runmode', 'single',
                '-k', 'none', '-S', str(tool / 'rules/all.rules'), '-r', str(pcap),
                '-l', str(output)]
        begin = time.monotonic()
        try:
            with (output / 'stdout.log').open('x') as out, (output / 'stderr.log').open('x') as err:
                r = subprocess.run(args, stdout=out, stderr=err, timeout=115, preexec_fn=limits)
            row['engine_rc'] = r.returncode
        except subprocess.TimeoutExpired:
            row['engine_rc'] = 'timeout'
        row['elapsed_s'] = round(time.monotonic() - begin, 3)
        types, signatures, categories, counters = collections.Counter(), {}, collections.Counter(), {}
        eve = output / 'eve.json'
        if eve.exists():
            with eve.open() as f:
                for line in f:
                    event = json.loads(line)
                    types[event.get('event_type')] += 1
                    if event.get('event_type') == 'stats':
                        counters = event['stats']
                    if event.get('event_type') != 'alert':
                        continue
                    a = event['alert']
                    key = str(a['signature_id'])
                    signatures.setdefault(key, {'signature': a['signature'], 'category': a['category'],
                                                'severity': a['severity'], 'count': 0})['count'] += 1
                    categories[a['category']] += 1
        row.update(ended_kst=now(), event_counts=dict(types), signatures=signatures,
                   categories=dict(categories), decoder=counters.get('decoder', {}),
                   eve_sha256=hashlib.sha256(eve.read_bytes()).hexdigest() if eve.exists() else None)
        if row['engine_rc'] != 0:
            row['diagnostic_tail'] = (output / 'stdout.log').read_text()[-3000:] + (output / 'stderr.log').read_text()[-1000:]
        rows.append(row)
        (work / 'progress.json').write_text(json.dumps({'at_kst': now(), 'rows': rows}, indent=2))
    result = {'schema': 1, 'source_ip': '192.168.16.232', 'mode': 'offline-no-transmission',
              'config_sha256': hashlib.sha256(cfg.read_bytes()).hexdigest(),
              'rule_sha256': hashlib.sha256((tool / 'rules/all.rules').read_bytes()).hexdigest(),
              'checksum_validation': 'disabled for capture offload compatibility; not live configuration',
              'home_net': 'capture private networks; differs from production CLI HOME_NET',
              'rows': rows, 'ended_kst': now(), 'elapsed_s': round(time.monotonic() - started, 3)}
    with (work / 'result.json').open('x') as f:
        json.dump(result, f, indent=2)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(run(Path(args.root), Path(args.config).read_text())))
