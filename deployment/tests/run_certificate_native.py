#!/usr/bin/env python3
"""Linux-root synthetic certificate/probe verification in a private directory.

This test never installs/starts a unit, reads private operating keys, sends TLS
traffic, or publishes a journal event. OpenSSL verification uses synthetic keys;
the s_client transport and logger are the reviewed fixture's private mocks.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'deployment'))
import certificate_monitor as cm

ENV={'SECURITY_HOST':'192.0.2.10','SIEM_HOST':'192.0.2.20','SERVICE_HOST':'192.0.2.30',
     'LAB_PUBLIC_ORIGIN':'https://lab.example.org','LAB_HTTPS_PORT':'443','LAB_PROXY_SUBNET':'172.30.247.0/29'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir',type=Path,required=True)
    args=parser.parse_args()
    assert platform.system()=='Linux' and os.geteuid()==0
    meta=args.workdir.lstat()
    assert stat.S_ISDIR(meta.st_mode) and not args.workdir.is_symlink() and meta.st_uid==0 and stat.S_IMODE(meta.st_mode)==0o700
    template=cm.templates(ROOT,lambda p:p.read_bytes())
    raw=(ROOT/cm.BASE/'test-monitor.sh').read_text()
    assert cm.sha(raw.encode())=='c742e7a5aa8174b84487e23a8a8d538801171682275f6db7a36be20d73ee270a'
    results={}
    for role,spec in cm.site_specs(ENV).items():
        # Fixture-only changes match the renderer's domain, endpoint and 0444
        # public-certificate mode. Probe/source guards are otherwise retained.
        fixture=raw.replace(cm.OLD_DOMAIN,spec['domain']).replace('172.18.0.3:8443',spec['connect']).replace('644','444')
        with tempfile.TemporaryDirectory(prefix=role+'-',dir=args.workdir) as directory:
            root=Path(directory)
            monitor=root/'monitor.sh';monitor.write_bytes(cm.monitor(template['monitor.sh'],spec,'b'*32))
            monitor.chmod(0o500)
            test=root/'test-monitor.sh';test.write_text(fixture)
            process=subprocess.run(['/bin/bash',str(test),str(monitor),str(root)],capture_output=True,text=True,
                                   timeout=40,env=cm.ENV)
            (args.workdir/(role+'-probe.log')).write_text(process.stdout+process.stderr)
            assert process.returncode==0,(role,process.returncode)
            lines=[line for line in process.stdout.splitlines() if line.startswith('{')]
            result=json.loads(lines[-1]);assert result['passed']==26 and result['network_connections']==0
            assert not result['operating_access'] and result['tls_transport_simulated']
            # verify also checks that ExecStart exists and is executable. Use
            # the private rendered file so no installed operating monitor is
            # required. Keep every sandbox/network/calendar option unchanged.
            unit=root/cm.UNIT.name
            unit.write_bytes(cm.service(spec).replace(str(cm.EXECUTABLE).encode(),str(monitor).encode()))
            timer=root/cm.TIMER.name;timer.write_bytes(cm.timer())
            syntax=subprocess.run(['/usr/bin/systemd-analyze','verify',str(unit),str(timer)],capture_output=True,text=True,timeout=15,env=cm.ENV)
            (args.workdir/(role+'-unit.log')).write_text(syntax.stdout+syntax.stderr)
            assert syntax.returncode==0,(role,'unit syntax')
            result['systemd_unit_syntax']='passed'
            result['systemd_unit_syntax_adapter']='ExecStart path only -> private rendered monitor; no operating executable dependency'
            result['role']=role
            result['monitor_sha256']=cm.sha(monitor.read_bytes())
            result['fixture_source_sha256']=cm.sha(raw.encode())
            result['fixture_adapter']='domain/endpoint/0444 metadata only'
            results[role]=result
    result={'status':'passed','suites':results,'probe_conditions':52,'real_network_connections':0,
            'operating_files_modified':0,'private_operating_keys_read':0,'systemd_units_started':0,
            'fresh_OS_installation':False,'native_Wazuh_rule_evaluation':False}
    (args.workdir/'native-result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
