#!/usr/bin/env python3
"""Compare existing WAF policy with a candidate in disposable network-none images.

Uses the already installed WAF image and actual ModSecurity configuration. The
application backend is a loopback-only stub. No production reload, firewall
change, package download, or connection to the real application is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid


def command(args, timeout=25):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(json.dumps({'command': args[:4], 'rc': p.returncode, 'stderr': p.stderr[-1800:]}))
    return p.stdout


def inspect(name):
    return json.loads(command(['docker', 'inspect', name]))[0]


def logs(name):
    p=subprocess.run(['docker','logs',name],capture_output=True,text=True,timeout=10)
    return p.stdout + p.stderr


CLIENT = r'''import socket,http.client,json,time,sys
cases=json.loads(sys.argv[1]);out=[]
for row in cases:
 c=http.client.HTTPConnection('172.18.0.2',8080,timeout=3,source_address=(row.get('peer','172.18.0.3'),0))
 headers={'Host':'log4shell.grootlab.duckdns.org','X-Capstone-Lab-Mode':row['mode'],'X-Capstone-Lab-Client':'192.0.2.232:43210','X-Capstone-Lab-Request':row['id']}
 if row['canary']:headers['X-Groot-Lab-Check']='mode-check-v1'
 if row.get('attack'):headers['X-Test-Input']=row['attack']
 headers.update(row.get('headers',{}))
 try:
  c.request(row.get('method','GET'),row['path'],body=row.get('body'),headers=headers);r=c.getresponse();body=r.read();out.append({'name':row['name'],'status':r.status,'reached_stub':b'capstone-native-backend' in body,'request_id':row['id']})
 finally:c.close()
print(json.dumps(out))
'''


def native(root, before_policy, before_vhost, after_policy, after_vhost):
    if os.geteuid() != 0:
        raise ValueError('root_required_for_disconnected_native_test')
    if root.exists():
        raise ValueError('new_validation_directory_required')
    if not re.fullmatch(r'native-[0-9a-f]{16}', root.name):
        raise ValueError('dedicated_validation_directory_required')
    if int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                if line.startswith('MemAvailable:'))) < 786432:
        raise ValueError('insufficient_available_memory_for_bounded_fixture')
    original = inspect('waf'); image = original['Image']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('existing_image_identity_required')
    binary = command(['docker', 'exec', 'waf', 'sh', '-c', 'command -v nginx']).strip()
    if binary not in ('/usr/sbin/nginx', '/usr/local/nginx/sbin/nginx'):
        raise ValueError('unexpected_nginx_binary')
    root.mkdir(mode=0o700, parents=True)
    command(['docker', 'cp', 'waf:/etc/modsecurity.d', str(root / 'modsecurity.d')])
    # The image's CRS directory is a symlink. Resolve it inside the trusted
    # source container, never by following that absolute link on the host.
    crs = root / 'modsecurity.d/owasp-crs'
    if crs.is_symlink():
        crs.unlink()
        crs.mkdir(mode=0o755)
        command(['docker', 'cp', '-L', 'waf:/etc/modsecurity.d/owasp-crs/.', str(crs)])
    loaded = command(['docker', 'exec', 'waf', 'nginx', '-T'])
    modules = '\n'.join(line for line in loaded.splitlines() if line.strip().startswith('load_module '))
    policy_path = root / 'modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-LABS.conf'
    if policy_path.read_bytes() != before_policy:
        raise ValueError('source_changed_during_native_preparation')
    pointer = root / 'audit-path.conf'; pointer.write_text('SecAuditLog /tmp/native-audit.log\n'); pointer.chmod(0o644)
    config = root / 'nginx.conf'
    config.write_text(modules + '''
pid /tmp/native-nginx.pid;
worker_processes 1;
error_log /dev/stderr notice;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path /tmp/body;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  log_format main '$request_id $remote_addr $status';
  log_format capstone_waf_evidence '$request_id $remote_addr $status';
  modsecurity on;
  modsecurity_transaction_id $http_x_capstone_lab_request;
  modsecurity_rules_file /etc/modsecurity.d/setup.conf;
  modsecurity_rules 'SecAuditLog /tmp/native-audit.log
SecAuditEngine On
';
  include /tmp/native-vhost.conf;
  server {
    listen 80;
    modsecurity off;
    access_log /tmp/native-backend.log;
    location / { return 200 'capstone-native-backend'; }
  }
}
'''); config.chmod(0o644)
    phases = []
    for phase, policy, vhost in [('before', before_policy, before_vhost), ('candidate', after_policy, after_vhost)]:
        policy_path.write_bytes(policy)
        for f in (root / 'modsecurity.d').rglob('*'):
            if f.is_symlink(): continue
            if f.is_dir(): f.chmod(0o755)
            elif f.is_file(): f.chmod(0o644)
        fixture_vhost = root / 'vhost.conf'
        text = vhost.decode().replace('/var/log/nginx/access.log', '/tmp/native-main.log').replace('/var/log/modsecurity/', '/tmp/')
        fixture_vhost.write_text(text); fixture_vhost.chmod(0o644)
        name = 'capstone-web-native-' + uuid.uuid4().hex[:16]
        created_id = None
        try:
            created_id = command(['docker', 'run', '--detach', '--pull=never', '--network=none', '--read-only',
                '--user=101:101', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64',
                '--memory=384m', '--cpus=1', '--sysctl=net.ipv4.ip_unprivileged_port_start=0',
                '--tmpfs=/tmp:rw,nosuid,nodev,mode=1777,size=33554432', '--name', name,
                '--label=io.capstone.validation=web-policy-native-v1',
                '-v', str(root / 'modsecurity.d') + ':/etc/modsecurity.d:ro',
                '-v', str(pointer) + ':/var/log/modsecurity/capstone-managed/audit-path.conf:ro',
                '-v', str(config) + ':/tmp/native.conf:ro', '-v', str(fixture_vhost) + ':/tmp/native-vhost.conf:ro',
                '--entrypoint=' + binary, image, '-c', '/tmp/native.conf', '-g', 'daemon off;']).strip()
            row = inspect(name)
            if row['Id'] != created_id or row['HostConfig']['NetworkMode'] != 'none':
                raise ValueError('owned_disconnected_container_required')
            pid = row['State']['Pid']
            if not pid:
                raise RuntimeError('native_nginx_not_running:' + logs(name)[-2200:])
            for address in ('172.18.0.2/32', '172.18.0.3/32', '10.200.10.20/32'):
                command(['nsenter', '-t', str(pid), '-n', 'ip', 'addr', 'add', address, 'dev', 'lo'])
            cases = []
            for path in ['/log4shell/labs/CVE-2021-44228/api/status', '/log4shell/labs/CVE-2021-41773/',
                         '/log4shell/labs/CVE-2021-42013/', '/log4shell/', '/log4shell/api/status']:
                for canary in (False, True):
                    for mode in ('enforce', 'exempt'):
                        key = phase + path + mode + str(canary)
                        cases.append({'name': key, 'path': path, 'canary': canary, 'mode': mode,
                                      'id': hashlib.sha256(key.encode()).hexdigest()[:32]})
            if phase=='candidate':
                examples=[('normal-search','/log4shell/api/status?q=hello&order=desc',200),
                          ('normal-unicode','/log4shell/api/list?q=%EC%A0%95%EC%83%81',200),
                          ('normal-static','/log4shell/static/app.js?v=20261104',200),
                          ('SQLi','/log4shell/api/status?q=%27%20OR%201%3D1--',403),
                          ('XSS','/log4shell/api/status?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E',403),
                          ('JNDI','/log4shell/api/status?q=%24%7Bjndi%3Aldap%3A%2F%2F127.0.0.1%3A9%2Fcanary%7D',403)]
                for case_name,path,expected in examples:
                    cases.append({'name':case_name,'path':path,'canary':False,'mode':'enforce','expected':expected,
                                  'id':hashlib.sha256((phase+case_name).encode()).hexdigest()[:32]})
                cases.append({'name':'authentication-audit-privacy','path':'/log4shell/api/session','mode':'enforce','canary':False,
                              'method':'POST','body':json.dumps({'challenge_id':'a'*32,'proof':'b'*64}),
                              'headers':{'Cookie':'groot_lab_admin=fake-admin-cookie-native-only','Content-Type':'application/json'},
                              'expected':200,'id':hashlib.sha256(b'auth-audit-privacy').hexdigest()[:32]})
            time.sleep(.15)
            received = json.loads(command(['nsenter', '-t', str(pid), '-n', '/usr/bin/python3', '-B', '-c', CLIENT,
                                          json.dumps(cases)], timeout=45))
            if phase == 'candidate':
                for request, response in zip(cases, received):
                    expected = request.get('expected',403 if request['canary'] or request['mode'] == 'exempt' else 200)
                    if response['status'] != expected or response['reached_stub'] != (expected == 200):
                        raise AssertionError((request, response, expected))
            else:
                observed = [r for q,r in zip(cases,received) if '/labs/' in q['path'] and q['canary'] and q['mode']=='exempt']
                if len(observed) != 3 or not all(r['status']==200 and r['reached_stub'] for r in observed):
                    raise AssertionError(('existing_exemption_not_reproduced', observed))
            audit = command(['docker', 'exec', name, 'cat', '/tmp/native-audit.log'])
            if phase=='candidate' and any(secret in audit for secret in ('fake-admin-cookie-native-only','b'*64)):
                raise AssertionError('normal_administration_credentials_copied_to_audit')
            (root / (phase + '-audit.jsonl')).write_text(audit)
            evidence={}
            for line in audit.splitlines():
                transaction=json.loads(line).get('transaction',{})
                headers={str(k).lower():v for k,v in transaction.get('request',{}).get('headers',{}).items()}
                key=headers.get('x-capstone-lab-request') or transaction.get('unique_id')
                if key:
                    evidence[key]={'rule_ids':[str(x.get('details',{}).get('ruleId')) for x in transaction.get('messages',[])],
                                   'engine_mode':transaction.get('producer',{}).get('secrules_engine')}
            if phase=='candidate':
                for request,response in zip(cases,received):
                    if request.get('expected')==403:
                        facts=evidence.get(request['id'],{})
                        if '949110' not in facts.get('rule_ids',[]) or facts.get('engine_mode')!='Enabled':
                            raise AssertionError(('attack_verdict_without_actual_CRS_enforcement',request['name'],facts))
                    response['audit']=evidence.get(request['id'])
            phases.append({'name':phase,'cases':received,'count':len(received),
                           'policy_sha256':hashlib.sha256(policy).hexdigest(),'vhost_sha256':hashlib.sha256(vhost).hexdigest(),
                           'image_id':image,'network_mode':'none','backend':'isolated_stub_not_real_application'})
        except BaseException:
            if created_id:
                (root / (phase + '-nginx.log')).write_text(logs(name))
            raise
        finally:
            if created_id:
                row = inspect(name)
                if row['Id'] != created_id or row['Config']['Labels'].get('io.capstone.validation') != 'web-policy-native-v1':
                    raise ValueError('native_cleanup_identity_conflict')
                command(['docker', 'rm', '--force', name])
    current = inspect('waf')
    if (current['Id'], current['State']['StartedAt']) != (original['Id'], original['State']['StartedAt']):
        raise ValueError('production_waf_changed_during_native_test')
    return {'status':'passed','phases':phases,'operating_waf_unchanged':True,
            'containers_removed':True,'new_images':0,'external_packets':0}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('directory','before-policy','before-vhost','after-policy','after-vhost'):
        p.add_argument('--'+name, type=Path, required=True)
    args=p.parse_args()
    print(json.dumps(native(args.directory,args.before_policy.read_bytes(),args.before_vhost.read_bytes(),
                            args.after_policy.read_bytes(),args.after_vhost.read_bytes()),ensure_ascii=False))


if __name__=='__main__':main()
