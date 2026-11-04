#!/usr/bin/env python3
"""Offline-only overlap fixtures. No packet transmission or live rule edit.

The candidate is tied to the observed ET source SHA. It removes seven aliases
only after comparing every matching/action option, preserving flowbit effects.
Metadata aliases still need review before any operational change.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import struct

BASE = Path(__file__).resolve().parents[2] / 'mcp'


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, BASE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


inventory = module('overlap_rule_inventory', 'security_rule_inventory.py')
packets = module('overlap_packet_support', 'validate_llm_flow_exception.py')
ET_SHA = 'f11a97da8db542030b5767860eb7e5c4d5045d57385baf5b1cca6ff540faef97'
PAIRS = [(2031294,2031293),(2014493,2013684),(2022484,2022949),
         (2009486,2016471),(2047884,2045358),(2016534,2016535),(2066629,2066625)]
ALL_IDS = {x for pair in PAIRS for x in pair}
REMOVE = {pair[1] for pair in PAIRS}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def condition(line):
    options = inventory.suricata_options(line)
    return (line[:line.index(b'(')].split(),
            [(k,v) for k,v in options if k not in (b'sid',b'msg',b'rev',b'metadata',b'reference')])


def candidate(raw):
    if sha(raw) != ET_SHA:
        raise ValueError('reviewed_ET_source_SHA_required')
    records = {}
    lines = raw.splitlines(keepends=True)
    for index,line in enumerate(lines):
        if line.lstrip().startswith(b'#') or not line.strip():
            continue
        match = re.search(rb'\bsid:\s*([0-9]+)\s*;',line)
        if match and int(match[1]) in ALL_IDS:
            sid = int(match[1])
            if sid in records:
                raise ValueError('candidate_SID_not_unique')
            records[sid] = (index,line.strip())
    if set(records) != ALL_IDS:
        raise ValueError('all_reviewed_pairs_required')
    for keep,remove in PAIRS:
        if condition(records[keep][1]) != condition(records[remove][1]):
            raise ValueError('different_detection_or_action')
    indices = {records[sid][0] for sid in REMOVE}
    return b''.join(line for index,line in enumerate(lines) if index not in indices)


def udp(source,destination,payload,index):
    a,b = ipaddress.IPv4Address(source).packed,ipaddress.IPv4Address(destination).packed
    datagram = struct.pack('!HHHH',42000+index,53,8+len(payload),0)+payload
    pseudo = a+b+struct.pack('!BBH',0,17,len(datagram))
    value = packets.checksum(pseudo+datagram) or 65535
    datagram = datagram[:6]+struct.pack('!H',value)+datagram[8:]
    ip = struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(datagram),index,0,64,17,0,a,b)
    ip = ip[:10]+struct.pack('!H',packets.checksum(ip))+ip[12:]
    return bytes.fromhex('0200000000020200000000010800')+ip+datagram


def build():
    capture = packets.Capture()
    cases = []
    names = ['fireeye_response','dynamic_DNS_host','rig_response','apt_user_agent',
             'raspberry_DNS','MSIL_uri','maskgram_headers']
    for index,(keep,remove) in enumerate(PAIRS):
        for positive in (True,False):
            n = len(cases)+1
            home,external = '198.18.0.'+str(n),'203.0.113.'+str(n)
            case = {'id':names[index]+('_positive' if positive else '_negative'),
                    'home':home,'external':external,'expected':([keep,remove] if positive else [])}
            cases.append(case)
            if index == 4:
                domain = 'w0.pm' if positive else 'w0.pn'
                question = b''.join(bytes([len(x)])+x.encode() for x in domain.split('.'))+b'\0\0\1\0\1'
                message = struct.pack('!HHHHHH',n,0x100,1,0,0,0)+question
                capture.packets.append(udp(home,external,message,n))
                continue
            connection = packets.Connection(capture,home,external,41000+n,80)
            host = 'offline.dtdns.net' if index==1 and positive else 'offline.example.invalid'
            uri = '/features/get/new/mac/fixture' if index==5 else '/fixture'
            method = 'POST' if index==6 else 'GET'
            headers = ['Host: '+host]
            if index==3:
                headers.append('User-Agent: Windows+NT+'+('5' if positive else '6')+'.1')
            if index==5 and not positive:
                headers.append('User-Agent: ordinary-fixture')
            if index==6:
                headers += ['User-Agent: Client/1.0','X-Filename: fixture','X-Browser-Type: fixture']
                if not positive: headers.append('X-Extra: breaks-adjacency')
                headers += ['X-Profile-Name: fixture','Content-Length: 7']
            request = (method+' '+uri+' HTTP/1.1\r\n'+'\r\n'.join(headers)+'\r\n\r\n').encode()
            if index==6: request += b'fixture'
            connection.send(True,[request])
            if index==0:
                body = b'{"meta":{},"status":"OK","saved":"1","starttime":17656184060,"id":"","vims":{"dtc":"fixture"}}'
                if not positive:body=body.replace(b'17656184060',b'17656184061')
            elif index==2:
                body = bytes.fromhex('3b2ddd4b40777741')+b'fixture'
                if not positive:body=b'X'+body[1:]
            else:body=b'fixture'
            response = (f'HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n'
                        'Content-Type: application/octet-stream\r\n\r\n').encode()+body
            connection.send(False,[response]);connection.close()
    raw = capture.bytes()
    return raw,{'schema':1,'scope':'synthetic_offline_file_no_network_transmission',
                'pcap_sha256':sha(raw),'packets':len(capture.packets),'cases':cases,
                'keep_remove_pairs':PAIRS,'HOME_NET':'198.18.0.0/24'}


def check(eve,phase):
    if phase not in ('before','candidate'):
        raise ValueError('unknown_phase')
    _,manifest = build()
    lookup = {ip:case for case in manifest['cases'] for ip in (case['home'],case['external'])}
    seen = {c['id']:[] for c in manifest['cases']}
    complete = Counter()
    for line in Path(eve).read_text().splitlines():
        event = json.loads(line)
        if event.get('event_type')!='alert':continue
        source,dest=event.get('src_ip'),event.get('dest_ip')
        if source not in lookup or dest not in lookup or lookup[source]!=lookup[dest]:
            raise ValueError('unexpected_offline_flow')
        case=lookup[source];sid=event['alert']['signature_id']
        if sid in ALL_IDS:seen[case['id']].append(sid)
        # Require all nonremoved alert observations to remain identical. Flow
        # IDs/engine counters are per-process values and are not compared.
        if sid not in REMOVE:
            complete[(case['id'],sid,source,dest,event.get('src_port'),event.get('dest_port'),
                      event['alert'].get('severity'),event['alert'].get('category'))]+=1
    rows=[]
    for case in manifest['cases']:
        wanted=case['expected'] if phase=='before' else [x for x in case['expected'] if x not in REMOVE]
        got=seen[case['id']]
        rows.append({'case':case['id'],'expected':sorted(wanted),'observed':sorted(got),
                     'pass':sorted(got)==sorted(wanted)})
    normalized=sorted([[list(k),v] for k,v in complete.items()])
    return {'phase':phase,'pass':all(r['pass'] for r in rows),'cases':rows,
            'all_retained_alerts_sha256':sha(json.dumps(normalized,separators=(',',':')).encode()),
            'all_retained_alert_count':sum(complete.values()),'fixture':manifest}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('generate','check'))
    p.add_argument('--output',type=Path);p.add_argument('--et',type=Path)
    p.add_argument('--eve',type=Path);p.add_argument('--phase',choices=('before','candidate'))
    a=p.parse_args()
    if a.action=='generate':
        if a.output is None or a.et is None:raise ValueError('output_and_ET_required')
        changed=candidate(a.et.read_bytes());raw,manifest=build()
        a.output.mkdir(parents=True,exist_ok=False)
        (a.output/'traffic.pcap').write_bytes(raw)
        (a.output/'candidate-et.rules').write_bytes(changed)
        (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        print(json.dumps(manifest))
    else:
        if a.eve is None or a.phase is None:raise ValueError('eve_and_phase_required')
        result=check(a.eve,a.phase)
        print(json.dumps(result))
        if not result['pass']:raise SystemExit(1)


if __name__=='__main__':main()
