#!/usr/bin/env python3
"""Evaluate portable certificate rules in a private, existing Wazuh image.

Linux root only. No image pull, operating manager input, network connection,
rule installation, operating restart, or certificate/private-key access.
The caller supplies an empty root0700 workdir and a full operating manager CID
whose identity and public configuration fingerprints are checked before/after.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'sha256:f845c782483d6b439d3cde5dc05c0c9cff500b2f713b4a6e39337b8f8c48ce30'
LABEL = 'io.capstone.cert-native'
IDS = {str(n) for n in range(100300, 100312)}
ENV = {'SECURITY_HOST':'192.0.2.10', 'SIEM_HOST':'192.0.2.20',
       'SERVICE_HOST':'192.0.2.30', 'LAB_PUBLIC_ORIGIN':'https://lab.example.org',
       'LAB_HTTPS_PORT':'443', 'LAB_PROXY_SUBNET':'172.30.247.0/29'}
LISTS = ('audit-keys', 'amazon/aws-eventnames', 'security-eventchannel',
         'malicious-ioc/malware-hashes', 'malicious-ioc/malicious-ip',
         'malicious-ioc/malicious-domains')
MOUNTS = (('ossec.conf','/var/ossec/etc/ossec.conf'),
          ('decoder.xml','/var/ossec/etc/decoders/capstone_certificate_native.xml'),
          ('rules.xml','/var/ossec/etc/rules/capstone_certificate_native.xml'),
          ('local_internal_options.conf','/var/ossec/etc/local_internal_options.conf'),
          ('start.sh','/cert-start.sh'))
START = '''#!/bin/bash
set -euo pipefail
cp /var/ossec/data_tmp/exclusion/var/ossec/etc/internal_options.conf /var/ossec/etc/internal_options.conf
chmod 0444 /var/ossec/etc/internal_options.conf
chown -R root:wazuh /var/ossec/etc/lists
cp -r /var/ossec/data_tmp/exclusion/var/ossec/etc/lists/. /var/ossec/etc/lists/
find /var/ossec/etc/lists -type d -exec chmod 0770 {} +
find /var/ossec/etc/lists -type f -exec chmod 0644 {} +
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-db -f &
exec /var/ossec/bin/wazuh-analysisd -f
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixtures(source=ROOT):
    cm = module('portable_certificate_adapter', source/'deployment/certificate_monitor.py')
    original = module('original_certificate_cases', source/cm.BASE/'test-certificate-rules.py')
    templates = cm.templates(source, lambda p:p.read_bytes())
    specs = cm.site_specs(ENV)
    rows = []
    for offset, (role, spec) in enumerate(specs.items()):
        location = '('+spec['sensor']+') any->journald'
        for item in original.fixtures():
            row = dict(item)
            row['payload'] = row['payload'].replace(cm.OLD_DOMAIN, spec['domain'])
            row['location'] = row['location'].replace('groot-sec', spec['sensor'])
            if row['expected']:
                sid, level = row['expected']
                row['expected'] = (str(int(sid)+offset*6), level)
            row.update(role=role, hostname=spec['sensor'])
            rows.append(row)
        other = specs['siem' if role=='security' else 'security']
        expired = original.canonical(original.event('expired','unavailable')).replace(cm.OLD_DOMAIN,spec['domain'])
        base = dict(payload=expired, expected=None, program='capstone-cert-monitor',
                    location=location, role=role, hostname=spec['sensor'])
        for name, changes in (
            ('known_other_sensor', {'location':'('+other['sensor']+') any->journald'}),
            ('known_other_domain', {'payload':expired.replace(spec['domain'],other['domain'])}),
            ('location_suffix', {'location':location+'_extra'}),
            ('program_prefix', {'program':'xcapstone-cert-monitor'}),
            # Syslog hostname is message data; the trusted sensor location is
            # the routing boundary. Do not silently rely on hostname instead.
            ('message_hostname_differs', {'hostname':'untrusted-host',
                                        'expected':(str(100304+offset*6),10)})):
            rows.append(dict(base, name=name, **changes))
    lists = ''.join('<list>etc/lists/'+name+'</list>' for name in LISTS)
    config = ('<ossec_config><global><jsonout_output>yes</jsonout_output>'
              '<alerts_log>no</alerts_log><logall>no</logall><logall_json>no</logall_json>'
              '<email_notification>no</email_notification></global><ruleset>'
              '<decoder_dir>ruleset/decoders</decoder_dir><rule_dir>ruleset/rules</rule_dir>'
              '<rule_exclude>0215-policy_rules.xml</rule_exclude>'+lists+
              '<decoder_include>etc/decoders/capstone_certificate_native.xml</decoder_include>'
              '<rule_include>etc/rules/capstone_certificate_native.xml</rule_include>'
              '</ruleset><rule_test><enabled>yes</enabled><threads>1</threads>'
              '<max_sessions>64</max_sessions><session_timeout>1m</session_timeout>'
              '</rule_test></ossec_config>')
    files = {'ossec.conf':config.encode(), 'decoder.xml':templates['capstone_certificate_decoders.xml'],
             'rules.xml':cm.rules(templates['capstone_certificate_rules.xml'],specs),
             'start.sh':START.encode(), 'local_internal_options.conf':
             b'analysisd.event_threads=1\nanalysisd.rule_matching_threads=1\nanalysisd.decoder_order_size=1024\n'}
    return files, rows


def verdict(raw, rc, expected):
    text = raw.decode('utf-8',errors='replace')
    ids = re.findall(r"^\s*id: '([0-9]+)'",text,re.M)
    levels = re.findall(r"^\s*level: '([0-9]+)'",text,re.M)
    # Unexpected diagnostics invalidate even a negative case. Phase1 confirms
    # the engine consumed the supplied message rather than merely starting.
    good = (rc==0 and len(raw)<=65536 and 'Completed pre-decoding.' in text
            and re.search(r'(?:ERROR|CRITICAL|WARNING):',text) is None)
    if expected is None:
        good = good and not (set(ids)&IDS)
    else:
        sid, level = expected
        good = (good and ids==[sid] and levels==[str(level)]
                and "name: 'capstone_certificate_json'" in text)
    return {'passed':bool(good), 'ids':ids, 'levels':levels,
            'exit_code':rc, 'diagnostic_sha256':sha(raw)}


def create_command(docker, fixture, nonce):
    command = [docker,'create','--pull','never','--name','capstone-cert-engine-'+nonce,
               '--label',LABEL+'='+nonce,'--network','none','--ipc','private',
               '--cap-drop','ALL','--group-add','wazuh','--cap-add','CHOWN',
               '--cap-add','SETUID','--cap-add','SETGID','--cap-add','SYS_CHROOT',
               '--security-opt','no-new-privileges:true','--pids-limit','256',
               '--cpus','0.5','--memory','512m','--memory-swap','512m',
               '--entrypoint','/bin/bash']
    for name, destination in MOUNTS:
        command += ['--mount','type=bind,src='+str(fixture/name)+',dst='+destination+',readonly']
    return command+[IMAGE,'--noprofile','--norc','/cert-start.sh']


def owned_container(record, cid, nonce, fixture):
    if not re.fullmatch('[a-f0-9]{64}',cid):
        return False
    expected = {str(fixture/name):destination for name,destination in MOUNTS}
    mounts = record.get('Mounts',[])
    return (record.get('Id')==cid and record.get('Image')==IMAGE
            and record.get('Config',{}).get('Labels',{}).get(LABEL)==nonce
            and record.get('HostConfig',{}).get('NetworkMode')=='none'
            and len(mounts)==len(expected)
            and all(m.get('Type')=='bind' and m.get('RW') is False
                    and expected.get(m.get('Source'))==m.get('Destination') for m in mounts))


def run_native(workdir, manager, docker):
    record = {'schema':1, 'status':'failed', 'image':IMAGE, 'network':'none',
              'operating_rule_installation':False, 'fresh_OS_installation':False,
              'new_attacks':0, 'new_model_calls':0, 'cases':[]}
    deadline = time.monotonic()+360
    cleanup_phase = False
    cid = None
    nonce = secrets.token_hex(12)
    fixture = workdir/'fixture'
    logs = workdir/'logs'
    logs.mkdir(mode=0o700)

    def command(argv, data=None, cleanup=False):
        timeout = 15 if cleanup or cleanup_phase else min(12,deadline-time.monotonic())
        if timeout<=0:
            raise RuntimeError('native_suite_deadline')
        return subprocess.run(argv,input=data,capture_output=True,timeout=timeout)

    def checked(argv):
        proc = command(argv)
        if proc.returncode:
            raise RuntimeError('native_command_failed:'+Path(argv[0]).name+':'+str(proc.returncode))
        return proc.stdout

    def inspect(target):
        return json.loads(checked([docker,'inspect',target]))[0]

    def snapshot():
        data = inspect(manager)
        if data['Id']!=manager or not data['State']['Running'] or data['Image']!=IMAGE:
            raise RuntimeError('operating_manager_identity_changed')
        config = checked([docker,'exec',manager,'sha256sum','/var/ossec/etc/ossec.conf'])
        config += checked([docker,'exec',manager,'find','/var/ossec/etc/rules',
            '/var/ossec/etc/decoders','-maxdepth','2','-type','f','-name','*.xml',
            '-exec','sha256sum','{}','+'])
        if not config.splitlines() or any(not re.fullmatch(rb'[0-9a-f]{64}  /var/ossec/etc/[^\n]+',line) for line in config.splitlines()):
            raise RuntimeError('operating_config_fingerprint_invalid')
        # Store fingerprints and safe identity only; never inspect Env output.
        return {'CID':data['Id'], 'image':data['Image'], 'started_at':data['State']['StartedAt'],
                'restart_count':data['RestartCount'], 'running':True,
                'configuration_files':len(config.splitlines()),
                'configuration_sha256':sha(b'\n'.join(sorted(config.splitlines())))}

    try:
        record['operating_before'] = snapshot()
        image = json.loads(checked([docker,'image','inspect',IMAGE]))[0]
        if image.get('Id')!=IMAGE or image.get('Config',{}).get('Volumes'):
            raise RuntimeError('unexpected_image_or_anonymous_volumes')
        record['image_digest'] = image.get('RepoDigests',[])
        record['image_architecture'] = image.get('Architecture')
        files, rows = fixtures()
        fixture.mkdir(mode=0o755)
        for name, raw in files.items():
            path = fixture/name
            path.write_bytes(raw)
            path.chmod(0o444)
        record['fixtures'] = {name:{'bytes':len(raw),'sha256':sha(raw)} for name,raw in files.items()}
        record['case_inputs_sha256'] = sha(json.dumps(rows,sort_keys=True,separators=(',',':')).encode())
        record['cases_planned'] = len(rows)
        cid = checked(create_command(docker,fixture,nonce)).decode().strip()
        if not owned_container(inspect(cid),cid,nonce,fixture):
            raise RuntimeError('private_container_identity')
        checked([docker,'start',cid])
        ready = False
        for _ in range(90):
            if command([docker,'exec',cid,'/usr/bin/test','-S','/var/ossec/queue/sockets/logtest']).returncode==0:
                ready = True
                break
            if not inspect(cid)['State']['Running']:
                break
            time.sleep(.15)
        if not ready:
            raise RuntimeError('private_engine_not_ready')
        version = command([docker,'exec',cid,'/var/ossec/bin/wazuh-analysisd','-V'])
        if version.returncode:
            raise RuntimeError('native_version_failed')
        record['version'] = (version.stdout+version.stderr).decode()
        record['binaries_sha256'] = checked([docker,'exec',cid,'sha256sum',
            '/var/ossec/bin/wazuh-analysisd','/var/ossec/bin/wazuh-logtest']).decode().splitlines()
        for row in rows:
            line = ('Oct 15 09:00:00 '+row['hostname']+' '+row['program']+'[12345]: '+row['payload']+'\n').encode()
            proc = command([docker,'exec','-i',cid,'/var/ossec/bin/wazuh-logtest','-l',row['location']],line)
            raw = proc.stdout+proc.stderr
            result = dict(verdict(raw,proc.returncode,row['expected']),role=row['role'],
                          name=row['name'],expected=row['expected'])
            record['cases'].append(result)
            (logs/(row['role']+'-'+row['name']+'.log')).write_bytes(raw[:65536])
            progress = workdir/'progress.json'
            pending = workdir/'progress.pending'
            pending.write_text(json.dumps({'planned':len(rows),'finished':len(record['cases']),
                'last_role':row['role'],'last_case':row['name'],'private_CID':cid})+'\n')
            pending.replace(progress)
            if not result['passed']:
                raise RuntimeError('native_case_failed:'+row['role']+':'+row['name'])
        record['status'] = 'passed'
    except Exception as exc:
        record['failure'] = type(exc).__name__+':'+str(exc)
    finally:
        cleanup_phase = True
        # Cleanup uses exact full CID, reviewed image, nonce, five read-only
        # inputs and isolated network together; never rm an unverified name.
        try:
            if cid:
                data = inspect(cid)
                if not owned_container(data,cid,nonce,fixture):
                    raise RuntimeError('cleanup_identity_mismatch')
                proc = command([docker,'logs',cid],cleanup=True)
                raw = proc.stdout+proc.stderr
                (logs/'engine.log').write_bytes(raw[:131072])
                if re.search(rb'(?:ERROR|CRITICAL|WARNING):',raw):
                    record['status'] = 'failed'
                    record['engine_diagnostics'] = 'unexpected startup diagnostics; see engine.log'
                if command([docker,'rm','-f','-v',cid],cleanup=True).returncode:
                    raise RuntimeError('private_container_removal_failed')
                # A successful daemon listing proves absence; inspect failure
                # alone could mean the Docker daemon became unreachable.
                proc = command([docker,'ps','-a','--no-trunc','--format','{{.ID}}'],cleanup=True)
                if proc.returncode or cid in proc.stdout.decode().splitlines():
                    raise RuntimeError('private_container_absence_unconfirmed')
                record['private_container_removed'] = True
            record['operating_after'] = snapshot()
            record['operating_unchanged'] = record.get('operating_before')==record['operating_after']
            if not record['operating_unchanged']:
                record['status'] = 'failed'
            if fixture.exists() and (not cid or record.get('private_container_removed')):
                record['fixture_cleanup'] = {'files':len(list(fixture.iterdir())),
                    'bytes':sum(path.stat().st_size for path in fixture.iterdir())}
                shutil.rmtree(fixture)
                record['fixture_cleanup']['absence_verified'] = not fixture.exists()
        except Exception as exc:
            record['status'] = 'failed'
            record['cleanup_failure'] = type(exc).__name__+':'+str(exc)
    record['cases_passed'] = sum(row['passed'] for row in record['cases'])
    record['seconds'] = round(360-(deadline-time.monotonic()),3)
    (workdir/'native-result.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir',type=Path,required=True)
    parser.add_argument('--manager',required=True)
    parser.add_argument('--docker',default='/usr/local/bin/docker')
    args = parser.parse_args()
    if platform.system()!='Linux' or os.geteuid()!=0 or not re.fullmatch('[a-f0-9]{64}',args.manager):
        parser.error('Linux root and exact full operating manager CID required')
    path = args.workdir
    meta = path.lstat()
    if not (path.is_absolute() and path.resolve()==path and stat.S_ISDIR(meta.st_mode)
            and meta.st_uid==0 and stat.S_IMODE(meta.st_mode)==0o700 and not any(path.iterdir())):
        parser.error('empty absolute root0700 non-symlink workdir required')
    result = run_native(path,args.manager,args.docker)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':
    raise SystemExit(main())
