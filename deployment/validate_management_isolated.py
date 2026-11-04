#!/usr/bin/env python3
"""Native management ACL packet checks in a new, disconnected network namespace.

Requires existing Linux ip/unshare/nft and root. No package downloads and no
packets on production interfaces. The namespace dies when this process exits.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time


def run(args, text=None):
    p=subprocess.run(args,input=text,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=40)
    if p.returncode:raise RuntimeError('isolated_command_failed:'+repr(args)+':'+p.stdout[-2500:])
    return p.stdout


def checksum(data):
    if len(data) % 2: data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    while total >> 16: total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(source, destination, port):
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    tcp = struct.pack('!HHLLBBHHH', 40000, port, 1, 0, 80, 2, 2048, 0, 0)
    if src.version == 4:
        pseudo = src.packed + dst.packed + struct.pack('!BBH', 0, 6, len(tcp))
        header = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, 1, 0, 64, 6, 0, src.packed, dst.packed)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    else:
        pseudo = src.packed + dst.packed + struct.pack('!L3xB', len(tcp), 6)
        header = struct.pack('!LHBB16s16s', 6<<28, len(tcp), 6, 64, src.packed, dst.packed)
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    return header + tcp


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inside',action='store_true');args=parser.parse_args()
    if os.geteuid()!=0: raise ValueError('root_required')
    if not args.inside:
        print(run(['unshare','--net','--','/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--inside']),end='');return
    spec=importlib.util.spec_from_file_location('management_policy',Path(__file__).with_name('management_access.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    run(['ip','link','set','lo','up'])
    macs={}
    for nic,peer,v4,v6 in [('ens192','peer192','192.168.16.230/25','fd42:1::1/64'),('ens160','peer160','10.200.10.1/24','fd42:2::1/64')]:
        run(['ip','link','add',nic,'type','veth','peer','name',peer]);run(['ip','addr','add',v4,'dev',nic]);run(['ip','-6','addr','add',v6,'dev',nic,'nodad'])
        for name in (nic,peer):run(['ip','link','set',name,'up'])
        macs[nic]=bytes.fromhex(json.loads(run(['ip','-j','link','show',nic]))[0]['address'].replace(':',''))
        macs[peer]=bytes.fromhex(json.loads(run(['ip','-j','link','show',peer]))[0]['address'].replace(':',''))
    rules='table inet capstone_fw {\n set mgmt_src {type ipv4_addr; flags interval; elements={192.168.16.231,211.170.162.0/24};}\n set never_block {type ipv4_addr; flags interval; elements={211.170.162.0/24};}\n set agent_block {type ipv4_addr; flags timeout; elements={198.51.100.77 timeout 120s};}\n chain prerouting_block {type filter hook prerouting priority raw; policy accept;\n ip saddr @never_block accept\n tcp dport {22,10443,80,443} counter accept comment "test-pass"\n}\n}\ntable ip capstone_fwd {chain prerouting {type nat hook prerouting priority dstnat; policy accept; iifname "ens192" ip saddr 192.168.16.0/25 tcp dport 10443 dnat to 10.200.10.10:443;\n}\n}\n'
    run(['nft','-f','-'],rules)
    transaction=m.kernel_change(m.nft_json(),m.ADMIN+'/32',[m.ADMIN])
    run(['nft','-c','-f','-'],transaction);run(['nft','-f','-'],transaction)
    def counters():
        rows=json.loads(run(['nft','-j','list','table','inet','capstone_fw']))['nftables'];result={}
        for row in rows:
            r=row.get('rule',{})
            if r.get('comment'):result[r['comment']]=sum(x['counter']['packets'] for x in r['expr'] if 'counter' in x)
        return result
    cases=[('admin-ssh','ens192','192.168.16.231','192.168.16.230',22,'test-pass'),
           ('campus-ssh','ens192','211.170.162.85','192.168.16.230',22,m.COMMENTS[1]),
           ('old-vpn-ssh','ens192','192.168.15.80','192.168.16.230',22,m.COMMENTS[1]),
           ('kali-ssh','ens192','192.168.16.232','192.168.16.230',22,m.COMMENTS[1]),
           ('admin-dnat','ens192','192.168.16.231','192.168.16.230',10443,'test-pass'),
           ('kali-dnat','ens192','192.168.16.232','192.168.16.230',10443,m.COMMENTS[1]),
           ('mcp-ssh','ens160','10.200.10.10','10.200.10.1',22,'test-pass'),
           ('service-ssh','ens160','10.200.10.20','10.200.10.1',22,m.COMMENTS[3]),
           ('service-external-address','ens160','10.200.10.20','192.168.16.230',22,m.COMMENTS[3]),
           ('v6-external-ssh','ens192','fd42:1::2','fd42:1::1',22,m.COMMENTS[0]),
           ('v6-external-dnat','ens192','fd42:1::2','fd42:1::1',10443,m.COMMENTS[0]),
           ('v6-internal-ssh','ens160','fd42:2::2','fd42:2::1',22,m.COMMENTS[2]),
           ('public-http','ens192','192.168.16.232','192.168.16.230',80,'test-pass'),
           ('public-https','ens192','192.168.16.232','192.168.16.230',443,'test-pass'),
           ('v6-public-https','ens192','fd42:1::2','fd42:1::1',443,'test-pass'),
           ('transit-ssh-not-local','ens160','10.200.10.20','10.200.10.30',22,'test-pass')]
    results=[]
    for name,nic,source,dest,port,expected in cases:
        before=counters();peer='peer192' if nic=='ens192' else 'peer160'
        ether=macs[nic]+macs[peer]+struct.pack('!H',0x800 if ':' not in source else 0x86dd)
        with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as s:s.bind((peer,0));s.send(ether+packet(source,dest,port))
        time.sleep(.025);after=counters();delta={k:after[k]-before[k] for k in before if after[k]!=before[k]}
        if delta!={expected:1}:raise AssertionError((name,expected,delta))
        results.append({'case':name,'counter':expected,'pass':True})
    # Exercise the inverse incremental transaction without recreating the set.
    inverse=m.kernel_change(m.nft_json(),m.OLD_SOURCE,[m.ADMIN,'211.170.162.0/24'],remove=True)
    run(['nft','-c','-f','-'],inverse);run(['nft','-f','-'],inverse)
    if m.guards(m.nft_json()):raise AssertionError('rollback_guard_remained')
    block=json.loads(run(['nft','-j','list','set','inet','capstone_fw','agent_block']))
    ttl=next(x['set']['elem'][0]['elem']['expires'] for x in block['nftables'] if 'set' in x)
    if not 100<ttl<=120:raise AssertionError(('test_block_ttl_changed',ttl,block))
    spec=importlib.util.spec_from_file_location('host_policy',Path(__file__).with_name('host_security.py'))
    h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
    fresh=h.rules({'schema':1,'role':'security','security_host':'10.200.10.1','siem_host':'10.200.10.10',
                   'service_host':'10.200.10.20','interface':'ens160','ssh_port':22,'web_port':80,
                   'legacy_bridge':'docker0','allow_legacy_management_http':False,'management_cidrs':['192.168.16.231/32']})
    run(['nft','-c','-f','-'],fresh)
    print(json.dumps({'status':'passed','namespace':'disconnected-unshare-net','cases':results,'count':len(results),'incremental_apply_and_rollback':True,'block_ttl_seconds':ttl,'fresh_security_native_syntax':True,'production_packets':0}))


if __name__=='__main__':main()
