#!/usr/bin/env python3
"""Pure schema9 regressions: no Docker, HTTP, package or server mutations."""
import copy
import hashlib
import io
import pathlib
import runpy
import zipfile
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent
SCRIPT=ROOT/'deployment/roles/service.sh'
spec=importlib.util.spec_from_file_location('offline_service',ROOT/'deployment/offline_service.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ENV={'CAPSTONE_SOURCE':str(ROOT),'SECURITY_HOST':'192.0.2.10','SERVICE_HOST':'192.0.2.30',
 'LAB_MANIFEST':'/opt/capstone-prereqs/cve_list.json','LAB_PUBLIC_ORIGIN':'https://labs.example.org',
 'LAB_GATEWAY_PORT':'18091','GATEWAY_ID':'sha256:'+'3'*64}
DATA=m.settings(ENV);ROLE='/opt/capstone/service'
def shell(code,data=None):
 env={**os.environ,**ENV,'APP_ID':'sha256:'+'1'*64,'DB_ID':'sha256:'+'2'*64,'ROLE':ROLE,'WEB_BACKEND_PORT':'8088'}
 return subprocess.run(['bash','-c','source "$1"; '+code,'service-test',str(SCRIPT)],input=data,text=True,capture_output=True,env=env)
def gateway():
 return {'State':{'Running':True,'Restarting':False},'Image':ENV['GATEWAY_ID'],
 'Config':{'Labels':{'com.docker.compose.project':'capstone-service','com.docker.compose.service':'gateway'},
 'User':'65532:65532','Entrypoint':['nginx'],'WorkingDir':'/tmp','Cmd':['-c','/etc/capstone-gateway.conf','-g','daemon off;'],
 'Healthcheck':{'Test':['NONE']},'Env':['PATH=/usr/bin:/bin']},
 'HostConfig':{'ReadonlyRootfs':True,'Privileged':False,'NetworkMode':'host','CapDrop':['ALL'],'CapAdd':[],
 'Memory':134217728,'NanoCpus':500000000,'PidsLimit':64,'Tmpfs':m.TMPFS.copy(),'PortBindings':{},
 'RestartPolicy':{'Name':'unless-stopped'},'SecurityOpt':['no-new-privileges:true'],'Devices':[],'Binds':[],
 'PidMode':'','IpcMode':'private','LogConfig':{'Type':'json-file','Config':{'max-size':'10m','max-file':'3'}}},
 'Mounts':[{'Type':'bind','Source':ROLE+'/config/gateway.conf','Destination':'/etc/capstone-gateway.conf','RW':False}],
 'NetworkSettings':{'Networks':{'host':{}}}}
class ConfigTests(unittest.TestCase):
 def test_routes_and_acl(self):
  text=m.render(DATA)
  for expected in ('listen 192.0.2.30:18091;','listen 127.0.0.1:18091;','allow 192.0.2.10;','deny all;',
   'location / { return 404; }','proxy_pass http://127.0.0.1:18081/log4shell/;','proxy_pass http://127.0.0.1:18090/;'):
   self.assertIn(expected,text)
  self.assertEqual(text.count('proxy_pass'),4);self.assertNotIn('dvwa',text.lower());self.assertNotIn('include ',text)
  self.assertIn('location ^~ /_offline-labs/ { proxy_read_timeout 275s;',text)
  self.assertEqual(text.count('proxy_read_timeout 275s;'),1)
 def test_host_authority_preserves_port(self):
  data=m.settings({**ENV,'LAB_PUBLIC_ORIGIN':'https://labs.example.org:8443'})
  self.assertIn('proxy_set_header Host labs.example.org:8443;',m.render(data))
 def test_origin_injection_and_http_rejected(self):
  for value in ('http://labs.example.org','https://user@labs.example.org','https://labs.example.org/',
   'https://labs.example.org;return 200','https://labs.example.org?x=y','https://labs.example.org:99999'):
   with self.subTest(value=value),self.assertRaises((m.Refused,ValueError)):m.settings({**ENV,'LAB_PUBLIC_ORIGIN':value})
 def test_reserved_port_rejected(self):
  for port in ('80','1514','18081','18082','18083','18090','65536','018091'):
   with self.subTest(port=port),self.assertRaises(m.Refused):m.settings({**ENV,'LAB_GATEWAY_PORT':port})
 def test_exact_catalog_and_ports(self):
  import sys
  sys.path.insert(0,str(ROOT/'infra/groot-c/offline-labs'));import manifest
  labs=manifest.validate_manifest(json.loads((ROOT/'infra/groot-c/offline-labs/cve_list.json').read_text()))
  with patch.object(manifest,'load_manifest',return_value=labs):self.assertEqual(len(m.catalog(ROOT,'unused')),6)
  variants=[labs[:-1],labs+[{'cve_id':'LAB-DVWA'}]]
  for key,value in [('host_port',18888),('path','/other/'),('vulnerable_version','2.17.1')]:
   bad=copy.deepcopy(labs);bad[0][key]=value;variants.append(bad)
  for cve in m.TERMINAL:
   for field,value in [('type','local-cli'),('vulnerable_version','latest')]:
    bad=copy.deepcopy(labs);next(item for item in bad if item['cve_id']==cve)[field]=value;variants.append(bad)
  for bad in variants:
   with patch.object(manifest,'load_manifest',return_value=bad),self.assertRaises(m.Refused):m.catalog(ROOT,'unused')
 def test_image_id_arch_volumes(self):
  image={'Id':ENV['GATEWAY_ID'],'Os':'linux','Architecture':'amd64','Config':{}}
  with patch.object(m,'run',return_value=json.dumps([image]).encode()):self.assertEqual(m.image_check(['docker'],'tag',ENV['GATEWAY_ID']),image)
  for key,value in [('Id','sha256:'+'4'*64),('Architecture','arm64'),('Config',{'Volumes':{'/data':{}}})]:
   with patch.object(m,'run',return_value=json.dumps([{**image,key:value}]).encode()),self.assertRaises(m.Refused):m.image_check(['docker'],'tag',ENV['GATEWAY_ID'])
class RuntimeTests(unittest.TestCase):
 def verify(self,value):m.gateway_contract(value,DATA,ROLE,{'Config':{'Env':['PATH=/usr/bin:/bin']}})
 def test_expected_gateway(self):
  value=gateway();self.verify(value)
  value['HostConfig']['Binds']=[ROLE+'/config/gateway.conf:/etc/capstone-gateway.conf:ro'];self.verify(value)
 def test_privileges_limits_namespaces_logs(self):
  for key,value in [('ReadonlyRootfs',False),('Privileged',True),('CapAdd',['NET_ADMIN']),('CapDrop',[]),('Memory',0),
   ('PidsLimit',0),('NanoCpus',0),('NetworkMode','bridge'),('PidMode','host'),('IpcMode','host'),('SecurityOpt',[]),('Tmpfs',{}),('LogConfig',{})]:
   data=gateway();data['HostConfig'][key]=value
   with self.subTest(key=key),self.assertRaises(m.Refused):self.verify(data)
 def test_command_env_user_mount(self):
  for key,value in [('User','0'),('Entrypoint',['/docker-entrypoint.sh']),('Cmd',['sh']),('Env',['LD_PRELOAD=/tmp/x']),('WorkingDir','/')]:
   data=gateway();data['Config'][key]=value
   with self.subTest(key=key),self.assertRaises(m.Refused):self.verify(data)
  for key,value in [('Source','/etc/shadow'),('RW',True)]:
   data=gateway();data['Mounts'][0][key]=value
   with self.subTest(key=key),self.assertRaises(m.Refused):self.verify(data)
 def test_foreign_image_owner(self):
  data=gateway();data['Image']='sha256:'+'4'*64
  with self.assertRaises(m.Refused):self.verify(data)
  data=gateway();data['Config']['Labels']['com.docker.compose.project']='foreign'
  with self.assertRaises(m.Refused):self.verify(data)
class SourceBindingTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='capstone-source-contract-');self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)
  files={'infra/groot-c/offline-labs/'+name for name in m.RUNTIME_REQUIRED}
  files|={'infra/groot-c/nonweb-labs/'+name for name in m.NONWEB_REQUIRED}
  files|={'infra/groot-c/offline-labs/nonweb/sudo/'+name for name in ('lab.py','publish.py','runtime/bootstrap.py')}
  files|={'infra/groot-c/offline-labs/wheel-inventory.json','infra/groot-c/offline-labs/requirements.lock',
          'infra/groot-c/offline-labs/scripts/bootstrap.py','deployment/offline_service.py'}
  for name in files:
   path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture')
 def test_nested_vendor_and_nonweb_sources_change_profile(self):
  baseline=m.source_hash(self.root)
  for name in ('infra/groot-c/offline-labs/static/terminal-vendor/xterm.js',
               'infra/groot-c/nonweb-labs/runtime.py','infra/groot-c/nonweb-labs/terminal.service',
               'infra/groot-c/nonweb-labs/sudo_terminal.py',
               'infra/groot-c/offline-labs/terminal_api.py'):
   path=self.root/name;path.write_text('changed')
   self.assertNotEqual(m.source_hash(self.root),baseline)
   path.write_text('fixture')
   self.assertEqual(m.source_hash(self.root),baseline)
 def test_missing_terminal_vendor_and_managed_runtime_source_refused(self):
  for name in ('infra/groot-c/offline-labs/static/terminal-vendor/xterm.js','infra/groot-c/nonweb-labs/bootstrap.py',
               'infra/groot-c/nonweb-labs/sudo_terminal.py'):
   path=self.root/name;path.unlink()
   with self.assertRaises(m.Refused):m.source_hash(self.root)
   path.write_text('fixture')
 def test_nested_file_and_directory_symlinks_refused(self):
  base=self.root/'infra/groot-c/offline-labs/static'
  link=base/'extra.js';link.symlink_to(base/'terminal.js')
  with self.assertRaises(m.Refused):m.source_hash(self.root)
  link.unlink();link=base/'linked';link.symlink_to(self.root/'deployment',target_is_directory=True)
  with self.assertRaises(m.Refused):m.source_hash(self.root)
class ManagedTerminalVerificationTests(unittest.TestCase):
 def verify(self,changed=None):
  raw=json.loads((ROOT/'infra/groot-c/offline-labs/cve_list.json').read_text())
  for item in raw:
   if item['cve_id'] in m.TERMINAL:item['type']='managed-terminal'
  rows=[{'cve_id':item['cve_id'],'type':item.get('type','managed-http'),
         'image_present':True,'status':'stopped','deployment_allowed':True,
         'verification':'environment_only','attack_tested':False} for item in raw]
  if changed:next(item for item in rows if item['cve_id']=='CVE-2021-3156').update(changed)
  requests=[]
  def http(path,data):
   requests.append(path)
   if path=='/_offline-labs/api/list':return json.dumps(raw).encode()
   if path=='/_offline-labs/api/status':return json.dumps({'deployment_allowed':True,'labs':rows}).encode()
   return (ROOT/'infra/groot-c/offline-labs/static'/path.removeprefix('/_offline-labs/static/')).read_bytes()
  with tempfile.TemporaryDirectory(prefix='capstone-terminal-status-') as directory:
   manifest=Path(directory)/'catalog.json';manifest.write_text(json.dumps(raw))
   data={**DATA,'LAB_MANIFEST':str(manifest)}
   with patch.object(m,'verify_installation'),patch.object(m,'run',return_value=b''),\
        patch.object(m,'catalog',return_value=raw),patch.object(m,'http',side_effect=http):
    result=m.verify(data,raw,['unused'])
  self.assertTrue(all('/api/deploy' not in path and '/api/stop' not in path for path in requests))
  return result
 def test_three_stopped_terminals_are_valid_without_starting_labs(self):
  result=self.verify()
  self.assertEqual((result['schema'],result['catalog_items'],result['managed_terminal_labs'],result['labs_started']),(9,6,3,0))
 def test_missing_sudo_image_is_not_a_ready_installation(self):
  with self.assertRaises(m.Refused):self.verify({'image_present':False})
 def test_sudo_errors_or_unverified_isolation_are_rejected(self):
  for changed in ({'status':'error'},{'deployment_allowed':False},{'verification':'inventory_only'},{'attack_tested':True}):
   with self.subTest(changed=changed),self.assertRaises(m.Refused):self.verify(changed)
class ShellTests(unittest.TestCase):
 def test_compose(self):
  result=shell('compose_document');self.assertEqual(result.returncode,0,result.stderr);doc=json.loads(result.stdout)
  self.assertEqual(set(doc['services']),{'dvwa','db','gateway'});self.assertEqual(set(doc['networks']),{'front','private'})
  self.assertTrue(doc['networks']['private']['internal']);self.assertEqual(doc['services']['db']['networks'],['private'])
  self.assertEqual(doc['services']['dvwa']['depends_on'],{'db':{'condition':'service_healthy'}})
  for svc in doc['services'].values():self.assertEqual(svc['pull_policy'],'never');self.assertNotIn('build',svc)
  g=doc['services']['gateway'];self.assertEqual(g['network_mode'],'host');self.assertEqual(g['user'],'65532:65532')
  self.assertTrue(g['read_only']);self.assertNotIn('ports',g);self.assertEqual(g['entrypoint'],['nginx']);self.assertEqual(len(g['volumes']),1)
 def test_independent_dvwa(self):
  result=shell('apache_document');self.assertEqual(result.returncode,0,result.stderr)
  self.assertIn('Alias /dvwa /var/www/html',result.stdout);self.assertNotIn('ProxyPass',result.stdout)
  self.assertNotIn('log4shell',result.stdout.lower());self.assertEqual(result.stdout.count('<VirtualHost'),1)
 def test_older_schema_and_missing_gateway_rejected(self):
  query=re.search(r"jq -e '(keys==.*?)' \"\$ROLE/manifest.json\"",SCRIPT.read_text(),re.S)[1]
  names=['compose.json','config/apache.conf','config/bootstrap.php','config/gateway.conf','config/ossec.conf.candidate',
   'credentials/admin-password','credentials/app.env','credentials/db-password','credentials/db-root-password','credentials/db.env','input.json']
  valid={'schema':9,'role':'service','state':'complete','container_ids':{x:'c'*64 for x in ('db','dvwa','gateway')},'files':{x:'a'*64 for x in names},
   **{x:'b'*64 for x in ('agent_config_sha256','enrollment_ca_sha256','enrollment_pass_sha256','script_sha256')}}
  def accepted(data):return subprocess.run(['jq','-e',query],input=json.dumps(data),text=True,capture_output=True).returncode==0
  self.assertTrue(accepted(valid))
  for old in range(1,9):self.assertFalse(accepted({**valid,'schema':old}))
  bad=copy.deepcopy(valid);del bad['files']['config/gateway.conf'];self.assertFalse(accepted(bad))
 def lifecycle(self,mode,existing=False,fail=False):
  with tempfile.TemporaryDirectory(prefix='capstone-service-test-') as directory:
   if existing:(Path(directory)/'service').mkdir()
   code=r'''
source "$1"
CAPSTONE_ROOT="$2"; ROLE="$2/service"
settings(){ MODE="$1"; }
safe_path(){ :; }; regular(){ :; }; stat(){ printf '0:0:600\n'; }; flock(){ :; }
fresh_namespace(){ printf 'preflight\n'; TEST_PREFLIGHT; }
assert_managed(){ printf 'managed-check\n'; }
verify(){ printf 'verify-only\n'; }
write_files(){ printf 'unexpected-write\n'; exit 92; }
main "$3"
'''.replace('TEST_PREFLIGHT','return 1' if fail else ':')
   return subprocess.run(['bash','-c',code,'lifecycle',str(SCRIPT),directory,mode],text=True,capture_output=True)
 def test_fresh_check_readonly(self):
  result=self.lifecycle('check');self.assertEqual(result.returncode,0,result.stderr);self.assertIn('preflight',result.stdout);self.assertNotIn('unexpected',result.stdout)
 def test_failed_preflight_stops(self):self.assertNotEqual(self.lifecycle('check',fail=True).returncode,0)
 def test_reapply_verify_no_reinstall(self):
  for mode in ('apply','verify'):
   result=self.lifecycle(mode,True);self.assertEqual(result.returncode,0,result.stderr);self.assertIn('verify-only',result.stdout);self.assertNotIn('unexpected',result.stdout)
 def test_installer_failure_prevents_compose(self):
  with tempfile.TemporaryDirectory(prefix='capstone-service-fail-') as directory:
   root=Path(directory)
   for name in ('ca','pass','key'):(root/name).write_text('synthetic-only')
   code=r'''
source "$1"
CAPSTONE_ROOT="$2"; ROLE="$2/service"; CAPSTONE_SOURCE="$2/source"
WAZUH_CA_FILE="$2/ca"; WAZUH_ENROLLMENT_PASS_FILE="$2/pass"; LAB_ADMIN_KEY_FILE="$2/key"
LAB_MANIFEST="$2/manifest"; LAB_PUBLIC_ORIGIN=https://labs.example.org; LAB_WHEEL_DIR="$2/wheels"; SIEM_HOST=192.0.2.20
settings(){ MODE=apply; }
ssh_macs(){ :; }
safe_path(){ :; }; regular(){ :; }; stat(){ printf '0:0:600\n'; }; flock(){ :; }
fresh_namespace(){ :; }; enrollment_inputs(){ :; }; timeout(){ :; }; apache_image_probe(){ :; }; gateway_image_probe(){ :; }
offline_command(){ :; }
write_files(){ mkdir -p "$ROLE/evidence"; }
mark(){ printf 'phase:%s\n' "$1"; }
logrun(){ printf 'run:%s\n' "$1"; [[ $1 != offline-install ]]; }
main apply
'''
   result=subprocess.run(['bash','-c',code,'failure',str(SCRIPT),directory],text=True,capture_output=True)
   self.assertNotEqual(result.returncode,0);self.assertIn('run:offline-install',result.stdout)
   self.assertNotIn('compose',result.stdout);self.assertNotIn('database-initialization',result.stdout)
   self.assertTrue((root/'service').exists())
 def test_nonweb_cli_arguments_are_fixed(self):
  for action,budget in (('check','600s'),('apply','1200s'),('verify','600s')):
   with self.subTest(action=action):
    result=shell('LAB_NONWEB_BUNDLE=/opt/custom/nonweb; timeout(){ printf "%s\\n" "$@"; }; nonweb_runtime '+action)
    self.assertEqual(result.returncode,0,result.stderr)
    self.assertEqual(result.stdout.splitlines(),['--kill-after=10s',budget,'python3','-B',
     str(ROOT/'infra/groot-c/nonweb-labs/bootstrap.py'),'--'+action,'--bundle','/opt/custom/nonweb',
     '--source-root',str(ROOT/'infra/groot-c/nonweb-labs')])
 def test_sudo_terminal_check_uses_fixed_readonly_adapter(self):
  result=shell('function /usr/bin/python3(){ printf "%s\\n" "$@"; }; sudo_terminal_check')
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(result.stdout.splitlines(),['-IB','/opt/capstone-nonweb-labs/sudo_terminal.py','check'])
 def test_role_verification_accepts_stopped_sudo_and_rejects_adapter_failure(self):
  for fail in (False,True):
   code=r'''
assert_managed(){ :; }
ssh_macs(){ :; }
docker_cmd(){ [[ $1 != ps ]] || printf '%064d\n' 0; }
jq(){ if [[ $1 == -r ]]; then printf '%064d\n' 0; fi; }
runtime_contract(){ :; }
verify_offline_apps(){ printf 'http-readonly\n'; }
sudo_runtime(){ printf 'legacy-running-verifier\n' >&2; return 1; }
sudo_terminal_check(){ printf 'adapter-check\n' >&2; return ADAPTER_RC; }
nonweb_runtime(){ printf 'nonweb-%s\n' "$1" >&2; }
systemctl(){ :; }; grep(){ :; }
verify
'''.replace('ADAPTER_RC','1' if fail else '0')
   with self.subTest(adapter_failure=fail):
    result=shell(code)
    self.assertNotIn('legacy-running-verifier',result.stderr)
    if fail:
     self.assertNotEqual(result.returncode,0)
     self.assertIn('sudo_terminal_verification_failed',result.stderr)
     self.assertNotIn('nonweb-verify',result.stderr)
    else:
     self.assertEqual(result.returncode,0,result.stderr)
     self.assertEqual(result.stdout.splitlines()[0],'http-readonly')
     self.assertEqual(result.stderr.splitlines(),['adapter-check','nonweb-verify'])
 def test_nonweb_preflight_failure_stops_before_agent(self):
  with tempfile.TemporaryDirectory(prefix='capstone-nonweb-preflight-') as directory:
   code=r'''
ROLE="$2/absent"; WEB_BACKEND_PORT=8088; LAB_GATEWAY_PORT=18091
docker_cmd(){ :; }; ss(){ :; }
offline_installer(){ printf 'offline-check\n'; }
sudo_runtime(){ printf 'sudo-check\n'; }
nonweb_runtime(){ printf 'nonweb:%s\n' "$1"; return 1; }
fresh_agent(){ printf 'unexpected-agent\n'; }
fresh_namespace
'''
   result=subprocess.run(['bash','-c','source "$1"; '+code,'preflight',str(SCRIPT),directory],text=True,capture_output=True)
   self.assertNotEqual(result.returncode,0);self.assertIn('nonweb_runtime_preflight_failed',result.stderr)
   self.assertEqual(result.stdout.splitlines(),['offline-check','sudo-check','nonweb:check'])
 def test_nonweb_apply_order_and_failure_preserve_partial_role(self):
  for fail in (False,True):
   with self.subTest(fail=fail),tempfile.TemporaryDirectory(prefix='capstone-nonweb-order-') as directory:
    root=Path(directory)
    for name in ('ca','pass','key'):(root/name).write_text('synthetic-only')
    code=r'''
source "$1"
CAPSTONE_ROOT="$2"; ROLE="$2/service"; CAPSTONE_SOURCE="$2/source"; EVENTS="$2/events"
WAZUH_CA_FILE="$2/ca"; WAZUH_ENROLLMENT_PASS_FILE="$2/pass"; LAB_ADMIN_KEY_FILE="$2/key"
LAB_MANIFEST="$2/manifest"; LAB_PUBLIC_ORIGIN=https://labs.example.org; LAB_WHEEL_DIR="$2/wheels"; SIEM_HOST=192.0.2.20
LAB_SUDO_BUNDLE="$2/sudo"; LAB_NONWEB_BUNDLE="$2/nonweb"; COMPOSE=(fixture)
settings(){ MODE=apply; }
ssh_macs(){ :; }
safe_path(){ :; }; regular(){ :; }; stat(){ printf '0:0:600\n'; }; flock(){ :; }
fresh_namespace(){ :; }; enrollment_inputs(){ :; }; apache_image_probe(){ :; }; gateway_image_probe(){ :; }
offline_command(){ :; }; write_files(){ mkdir -p "$ROLE/evidence"; }; mark(){ :; }
timeout(){ if [[ "$*" == *sudo/runtime/bootstrap.py* ]]; then printf 'sudo-apply\n' >>"$EVENTS"; fi; }
nonweb_runtime(){ printf 'nonweb-%s\n' "$1" >>"$EVENTS"; return FAIL_NONWEB; }
logrun(){ printf '%s\n' "$1" >>"$EVENTS"; if [[ $1 == compose-config ]]; then exit 0; fi; }
main apply
'''.replace('FAIL_NONWEB','1' if fail else '0')
    result=subprocess.run(['bash','-c',code,'order',str(SCRIPT),directory],text=True,capture_output=True)
    events=(root/'events').read_text().splitlines()
    self.assertEqual(events[:3],['offline-install','sudo-apply','nonweb-apply'])
    self.assertTrue((root/'service').exists())
    if fail:
     self.assertNotEqual(result.returncode,0);self.assertNotIn('compose-config',events)
     self.assertIn('nonweb_runtime_install_failed',result.stderr)
    else:
     self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(events[-1],'compose-config')
class ProbeTests(unittest.TestCase):
 def invoke(self,kind='gateway',start_code=0,changed=None,after_start=False):
  with tempfile.TemporaryDirectory(prefix='capstone-service-probe-') as directory:
   root=Path(directory);(root/'evidence').mkdir();(root/'config').mkdir()
   (root/'config/gateway.conf').write_text('synthetic configuration')
   cid='a'*64;image=ENV['GATEWAY_ID'] if kind=='gateway' else 'sha256:'+'1'*64
   owned={'Id':cid,'Image':image,'Config':{'Labels':{'io.capstone.portable.'+kind+'-probe':'service'}}}
   foreign=copy.deepcopy(owned)
   if changed=='id':foreign['Id']='b'*64
   if changed=='image':foreign['Image']='sha256:'+'4'*64
   if changed=='label':foreign['Config']['Labels']['io.capstone.portable.'+kind+'-probe']='foreign'
   (root/'before.json').write_text(json.dumps(owned if after_start else foreign))
   (root/'after.json').write_text(json.dumps(foreign))
   code=r'''
ROLE="$2"; START_CODE="$3"; PROBE_KIND="$4"
regular(){ :; }
docker_cmd(){
  printf '%s\n' "$1" >>"$ROLE/events"
  case "$1" in
    create) printf '%s\n' "$@" >"$ROLE/create.args"; printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;
    inspect) if [[ -f $ROLE/started ]]; then cat "$ROLE/after.json"; else cat "$ROLE/before.json"; fi;;
    start) : >"$ROLE/started"; return "$START_CODE";;
    rm) printf '%s\n' "$@" >"$ROLE/remove.args";;
    *) return 90;;
  esac
}
"${PROBE_KIND}_image_probe"
'''
   env={**os.environ,**ENV,'APP_ID':'sha256:'+'1'*64}
   result=subprocess.run(['bash','-c','source "$1"; '+code,'probe',str(SCRIPT),directory,str(start_code),kind],
     text=True,capture_output=True,env=env)
   files={x.name:x.read_text().splitlines() for x in root.iterdir() if x.is_file()}
   return result,files
 def test_gateway_isolated_syntax_test_and_owned_cleanup(self):
  result,files=self.invoke();self.assertEqual(result.returncode,0,result.stderr)
  args=files['create.args']
  for name,value in [('--pull','never'),('--network','none'),('--user','65532:65532'),('--cap-drop','ALL'),
    ('--security-opt','no-new-privileges:true'),('--ipc','private'),('--pids-limit','64'),('--memory','128m'),
    ('--cpus','0.5'),('--workdir','/tmp'),('--entrypoint','nginx'),
    ('--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777')]:
   self.assertEqual(args[args.index(name)+1],value)
  self.assertIn('--read-only',args);self.assertIn('--no-healthcheck',args)
  self.assertNotIn('--publish',args);self.assertNotIn('-p',args)
  self.assertEqual(args[-4:],[ENV['GATEWAY_ID'],'-t','-c','/etc/capstone-gateway.conf'])
  self.assertTrue(args[args.index('--mount')+1].endswith('/config/gateway.conf,dst=/etc/capstone-gateway.conf,readonly'))
  self.assertEqual(files['events'],['create','inspect','start','inspect','rm'])
  self.assertEqual(files['remove.args'],['rm','--force','a'*64])
 def test_apache_checks_owner_before_start_and_cleanup(self):
  result,files=self.invoke('apache');self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(files['events'],['create','inspect','start','inspect','rm'])
  self.assertEqual(files['remove.args'],['rm','--force','a'*64])
 def test_foreign_probe_never_started_or_removed(self):
  for kind in ('apache','gateway'):
   for changed in ('id','image','label'):
    with self.subTest(kind=kind,changed=changed):
     result,files=self.invoke(kind,changed=changed)
     self.assertNotEqual(result.returncode,0);self.assertIn('ownership_changed',result.stderr)
     self.assertEqual(files['events'],['create','inspect']);self.assertNotIn('remove.args',files)
 def test_changed_probe_not_removed_after_failure(self):
  for kind in ('apache','gateway'):
   result,files=self.invoke(kind,start_code=124,changed='label',after_start=True)
   self.assertNotEqual(result.returncode,0);self.assertIn('ownership_changed',result.stderr)
   self.assertEqual(files['events'],['create','inspect','start','inspect']);self.assertNotIn('remove.args',files)
 def test_failure_or_timeout_still_cleans_owned_probe(self):
  for kind in ('apache','gateway'):
   for code in (1,124):
    with self.subTest(kind=kind,code=code):
     result,files=self.invoke(kind,start_code=code)
     self.assertNotEqual(result.returncode,0);self.assertEqual(files['events'][-2:],['inspect','rm'])
 def test_syntax_failure_prevents_install_and_public_start(self):
  with tempfile.TemporaryDirectory(prefix='capstone-gateway-gate-') as directory:
   root=Path(directory)
   for name in ('ca','pass'):(root/name).write_text('synthetic-only')
   code=r'''
source "$1"
CAPSTONE_ROOT="$2"; ROLE="$2/service"; WAZUH_CA_FILE="$2/ca"; WAZUH_ENROLLMENT_PASS_FILE="$2/pass"; SIEM_HOST=192.0.2.20
settings(){ MODE=apply; }
ssh_macs(){ :; }
safe_path(){ :; }; regular(){ :; }; stat(){ printf '0:0:600\n'; }; flock(){ :; }
fresh_namespace(){ :; }; enrollment_inputs(){ :; }; timeout(){ :; }; apache_image_probe(){ :; }
offline_command(){ :; }; write_files(){ mkdir -p "$ROLE/evidence"; }
mark(){ printf 'phase:%s\n' "$1"; }
gateway_image_probe(){ printf 'syntax-failed\n'; return 1; }
logrun(){ printf 'unexpected:%s\n' "$1"; return 0; }
main apply
'''
   result=subprocess.run(['bash','-c',code,'gate',str(SCRIPT),directory],text=True,capture_output=True)
   self.assertNotEqual(result.returncode,0);self.assertIn('syntax-failed',result.stdout)
   self.assertNotIn('offline-install-armed',result.stdout);self.assertNotIn('compose',result.stdout)
   self.assertNotIn('unexpected:',result.stdout)

class InstallationReceiptTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='capstone-install-receipt-');self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);base=self.root/'infra/groot-c/offline-labs';(base/'static').mkdir(parents=True)
  self.content={};self.meta={}
  for name in m.RUNTIME_REQUIRED:
   (base/name).parent.mkdir(parents=True,exist_ok=True)
   (base/name).write_bytes(b'synthetic source')
   self.content['/opt/capstone-offline-labs/'+name]=b'synthetic source'
  self.content.update({x:b'synthetic settings' for x in ('/etc/capstone-offline-labs/cve_list.json','/etc/capstone-offline-labs/settings.env')})
  for unit in ('capstone-offline-labs','capstone-offline-labs-broker','capstone-offline-labs-guard'):
   self.content['/etc/systemd/system/'+unit+'.service']=b'synthetic unit'
  files={name:{'sha256':hashlib.sha256(data).hexdigest(),'mode':'0644','uid':0,'gid':0} for name,data in self.content.items()}
  self.state={'schema':1,'status':'installed','stage':'complete','automatic_cleanup':False,'files':files,
   'key_file':{'path':'/etc/capstone-offline-labs/admin-token','mode':'0640','uid':0,'gid':444}}
  self.state_path='/var/lib/capstone-offline-labs/install-state.json'
  self.content[self.state_path]=json.dumps(self.state).encode()
  self.content['/etc/capstone-offline-labs/admin-token']=b'synthetic-common-key\n'
  self.content['/opt/capstone-prereqs/lab-admin.key']=b'synthetic-common-key'
  self.meta={name:(0,0,0o100644) for name in self.content}
  self.meta[self.state_path]=(0,0,0o100600)
  self.meta['/etc/capstone-offline-labs/admin-token']=(0,444,0o100640)
  self.meta['/opt/capstone-prereqs/lab-admin.key']=(0,0,0o100600)
  fixture=self
  class FakeFile:
   def __init__(self,name):self.name=str(name)
   def stat(self):
    uid,gid,mode=fixture.meta[self.name]
    return types.SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=mode,st_size=len(fixture.content[self.name]))
   def read_bytes(self):return fixture.content[self.name]
  self.fake_file=FakeFile
 def verify(self,override=False):
  def run(args):
   if 'DropInPaths' in args:return b'override.conf' if override else b'\n'
   return ('/etc/systemd/system/'+args[-1]+'.service\n').encode()
  with patch.object(m,'trusted',side_effect=self.fake_file),patch.object(m,'run',side_effect=run),patch.dict(os.environ,{'LAB_ADMIN_KEY_FILE':'/opt/capstone-prereqs/lab-admin.key'}):
   m.verify_installation({**DATA,'CAPSTONE_SOURCE':str(self.root)})
 def test_complete_receipt_and_same_key(self):self.verify()
 def test_changed_artifact_and_unit_override_rejected(self):
  self.content['/opt/capstone-offline-labs/broker.py']=b'changed'
  with self.assertRaises(m.Refused):self.verify()
  self.content['/opt/capstone-offline-labs/broker.py']=b'synthetic source'
  with self.assertRaises(m.Refused):self.verify(override=True)
 def test_changed_key_or_permissions_rejected(self):
  self.content['/etc/capstone-offline-labs/admin-token']=b'different-key'
  with self.assertRaises(m.Refused):self.verify()
  self.content['/etc/capstone-offline-labs/admin-token']=b'synthetic-common-key'
  self.meta['/opt/capstone-prereqs/lab-admin.key']=(0,0,0o100644)
  with self.assertRaises(m.Refused):self.verify()
 def test_partial_receipt_cannot_be_adopted(self):
  self.state['status']='failed_partial';self.content[self.state_path]=json.dumps(self.state).encode()
  with self.assertRaises(m.Refused):self.verify()

JAR_CHECK=runpy.run_path(str(ROOT/'deployment/validate_log4shell_jar.py'))

def zip_bytes(entries):
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',zipfile.ZIP_STORED) as archive:
        for name,body in entries.items():archive.writestr(name,body)
    return output.getvalue()

def jar_fixture(version='2.14.1'):
    entries={
      'META-INF/MANIFEST.MF':'Main-Class: org.springframework.boot.loader.JarLauncher\nStart-Class: fr.christophetd.log4shell.vulnerableapp.VulnerableAppApplication\n',
      'org/springframework/boot/loader/JarLauncher.class':b'CAFEBABE',
      'BOOT-INF/classes/fr/christophetd/log4shell/vulnerableapp/MainController.class':b'CAFEBABE',
      'BOOT-INF/classes/fr/christophetd/log4shell/vulnerableapp/VulnerableAppApplication.class':b'CAFEBABE',
      'BOOT-INF/classes/fr/christophetd/log4shell/vulnerableapp/LabCsrf.class':b'CAFEBABE',
      'BOOT-INF/classes/application.properties':'server.servlet.context-path=/log4shell',
      'BOOT-INF/classes/log4j2-spring.xml':'<Configuration/>',
      'BOOT-INF/classes/static/index.html':'Log4Shell',
      'BOOT-INF/classes/static/app.js':'/* app */','BOOT-INF/classes/static/app.css':'/* style */'}
    for artifact,clazz in [('log4j-api','org/apache/logging/log4j/LogManager.class'),('log4j-core','org/apache/logging/log4j/core/lookup/JndiLookup.class')]:
        entries['BOOT-INF/lib/'+artifact+'-2.14.1.jar']=zip_bytes({
          'META-INF/maven/org.apache.logging.log4j/'+artifact+'/pom.properties':
            'groupId=org.apache.logging.log4j\nartifactId='+artifact+'\nversion='+version+'\n',clazz:b'CAFEBABE'})
    return entries

class JARContractTests(unittest.TestCase):
    def validate(self,entries):return JAR_CHECK['validate_bytes'](zip_bytes(entries))
    def test_complete_artifact_returns_exact_hash(self):
        data=zip_bytes(jar_fixture());self.assertEqual(JAR_CHECK['validate_bytes'](data),hashlib.sha256(data).hexdigest())
    def test_old_controller_without_spring_ui_rejected(self):
        entries=jar_fixture();del entries['BOOT-INF/classes/static/index.html']
        with self.assertRaises(ValueError):self.validate(entries)
    def test_nested_library_version_is_checked_not_just_filename(self):
        with self.assertRaises(ValueError):self.validate(jar_fixture('2.17.1'))
    def test_parallel_log4j_core_library_rejected(self):
        entries=jar_fixture();entries['BOOT-INF/lib/log4j-core-2.17.1.jar']=b'wrong'
        with self.assertRaises(ValueError):self.validate(entries)
    def test_wrong_entrypoint_rejected(self):
        entries=jar_fixture();entries['META-INF/MANIFEST.MF']='Main-Class: other.Main\n'
        with self.assertRaises(ValueError):self.validate(entries)
    def test_archive_traversal_rejected(self):
        entries=jar_fixture();entries['../escape']=b'bad'
        with self.assertRaises(ValueError):self.validate(entries)
    def test_symlink_source_rejected(self):
        with tempfile.TemporaryDirectory(prefix='capstone-jar-contract-') as directory:
            jar=pathlib.Path(directory)/'app.jar';jar.write_bytes(zip_bytes(jar_fixture()))
            link=jar.with_name('link.jar');link.symlink_to(jar)
            with self.assertRaises(ValueError):JAR_CHECK['validate_path'](link)


class SpringVerifierTests(unittest.TestCase):
    def verify_with(self,responses,hostname=''):
        namespace=runpy.run_path(str(ROOT/'deployment/verify_log4shell_app.py'))
        requests=[]
        class Response:
            def __init__(self,code,body,headers=None):
                self.code=code;self.body=body if isinstance(body,bytes) else json.dumps(body).encode();self.headers=headers or {}
            def read(self,limit):return self.body[:limit]
            def __enter__(self):return self
            def __exit__(self,*args):return False
        class Opener:
            def open(self,request,timeout):
                requests.append(request)
                return Response(*responses.pop(0))
        with patch('urllib.request.build_opener',return_value=Opener()):
            namespace['verify']('http://127.0.0.1/log4shell/',hostname,'8080')
        return requests
    def responses(self):
        return [(200,b'Log4Shell Java UI'),(200,b'js'),(200,b'css'),
          (200,{'ok':True,'log4jApiVersion':'2.14.1','log4jCoreVersion':'2.14.1','javaVersion':'1.8','csrfToken':'test-token'}),
          (200,{'ok':True,'source':'parameter','level':'INFO','message':'capstone-spring-verification','requestId':'test','time':'test'})]
    def test_only_inert_message_and_correct_csrf_header(self):
        requests=self.verify_with(self.responses());self.assertEqual(len(requests),5)
        self.assertEqual(requests[-1].full_url,'http://127.0.0.1/log4shell/api/log')
        self.assertEqual(requests[-1].data,b'source=parameter&message=capstone-spring-verification')
        self.assertEqual(requests[-1].get_header('X-lab-csrf-token'),'test-token')
    def test_welcome_page_and_assets_do_not_request_json(self):
        requests=self.verify_with(self.responses())
        self.assertIn('text/html',requests[0].get_header('Accept'))
        self.assertEqual([request.get_header('Accept') for request in requests[1:3]],['*/*','*/*'])
        self.assertEqual([request.get_header('Accept') for request in requests[3:]],['application/json','application/json'])
    def test_wrong_runtime_version_fails_before_log_request(self):
        responses=self.responses();responses[3][1]['log4jCoreVersion']='2.17.1'
        with self.assertRaises(ValueError):self.verify_with(responses)
    def test_wrong_log_receipt_is_not_success(self):
        responses=self.responses();responses[4][1]['message']='different'
        with self.assertRaises(ValueError):self.verify_with(responses)
    def test_hostname_redirects_preserve_public_port(self):
        responses=self.responses()+[(302,b'',{'Location':'http://log4shell.example.org:8080/log4shell/'})]*3
        requests=self.verify_with(responses,'log4shell.example.org')
        self.assertTrue(all(request.get_header('Host')=='log4shell.example.org' for request in requests))


if __name__=='__main__':unittest.main(verbosity=2)
