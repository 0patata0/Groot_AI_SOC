#!/usr/bin/env bash
# Local contract regression. No Docker, SSH, package, account, service or HTTP calls.
set -euo pipefail
exec python3 -B - "$(dirname "$0")/service.sh" <<'PY'
import ast,copy,hashlib,json,pathlib,re,shutil,subprocess,sys,tempfile,unittest

SCRIPT=pathlib.Path(sys.argv[1]).resolve()
SOURCE=SCRIPT.read_text()
ROOT=SCRIPT.parents[2]
IDS={name:'sha256:'+digit*64 for name,digit in [('dvwa','1'),('db','2'),('log4shell','3')]}
ROLE='/opt/capstone/service'
HOST='192.0.2.30'
PORT='8088'

def shell(function,stdin=None,*extra):
    command='source "$1"; APP_ID="$2"; DB_ID="$3"; LAB_ID="$4"; ROLE="$5"; SERVICE_HOST="$6"; WEB_BACKEND_PORT="$7"; shift 7; '+function
    return subprocess.run(['bash','-c',command,'service-contract',str(SCRIPT),IDS['dvwa'],IDS['db'],IDS['log4shell'],ROLE,HOST,PORT,*extra],
                          input=stdin,text=True,capture_output=True)

def snapshot(name):
    result={'State':{'Running':True,'Restarting':False},'Image':IDS[name],
      'Config':{'Labels':{'com.docker.compose.project':'capstone-service','com.docker.compose.service':name}},
      'HostConfig':{'Privileged':False,'RestartPolicy':{'Name':'unless-stopped'},'SecurityOpt':['no-new-privileges:true'],'PortBindings':{}},
      'NetworkSettings':{'Networks':{}},'Mounts':[]}
    if name=='log4shell':
        result['Config'].update(User='65532:65532',Cmd=['java','-jar','/app/spring-boot-application.jar'],
          Entrypoint=None,Healthcheck={'Test':['NONE']},Env=['TZ=Asia/Seoul','JAVA_TOOL_OPTIONS=-Xms64m -Xmx256m -Duser.timezone=Asia/Seoul'])
        result['HostConfig'].update(ReadonlyRootfs=True,CapDrop=['ALL'],CapAdd=None,PidsLimit=128,
          Memory=536870912,NanoCpus=1000000000,Dns=['127.0.0.1'],Tmpfs={'/tmp':'rw,nosuid,nodev,noexec,size=64m,mode=1777'})
        result['NetworkSettings']['Networks']={'capstone-service_lab':{}}
    elif name=='db':
        result['State']['Health']={'Status':'healthy'}
        result['Mounts']=[{'Type':'volume','Name':'capstone-service_database','Destination':'/var/lib/mysql','RW':True}]
        result['NetworkSettings']['Networks']={'capstone-service_private':{}}
    else:
        result['State']['Health']={'Status':'healthy'}
        result['HostConfig']['PortBindings']={'80/tcp':[{'HostIp':HOST,'HostPort':PORT}]}
        result['NetworkSettings']['Networks']={n:{} for n in ('capstone-service_front','capstone-service_private','capstone-service_lab')}
        for src,dst,write in [('config/apache.conf','/etc/apache2/sites-enabled/000-default.conf',False),
          ('config/bootstrap.php','/opt/capstone-bootstrap.php',False),('config/verify-log4shell.php','/opt/capstone-log4shell-verify.php',False),
          ('config/log4shell-ui','/var/www/html/log4shell',False),('state/log4shell-ui','/var/lib/capstone-log4shell-ui',True),
          ('logs','/var/log/capstone-service',True)]:
            result['Mounts'].append({'Type':'bind','Source':ROLE+'/'+src,'Destination':dst,'RW':write})
    return result

class ComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result=shell('compose_document')
        if result.returncode: raise AssertionError(result.stderr)
        cls.c=json.loads(result.stdout)
    def test_three_services_use_inspected_ids_and_never_pull(self):
        self.assertEqual(set(self.c['services']),{'dvwa','db','log4shell'})
        for name,s in self.c['services'].items():
            self.assertEqual(s['image'],IDS[name]);self.assertEqual(s['pull_policy'],'never')
            self.assertNotIn('build',s);self.assertNotIn('privileged',s)
    def test_only_dvwa_publishes_one_bound_port(self):
        ports={n:s.get('ports',[]) for n,s in self.c['services'].items()}
        self.assertEqual(ports,{'dvwa':[HOST+':'+PORT+':80'],'db':[],'log4shell':[]})
    def test_database_and_lab_are_separate_internal_networks(self):
        self.assertTrue(self.c['networks']['lab']['internal']);self.assertTrue(self.c['networks']['private']['internal'])
        self.assertEqual(self.c['services']['db']['networks'],['private'])
        self.assertEqual(self.c['services']['log4shell']['networks'],['lab'])
        self.assertEqual(set(self.c['services']['dvwa']['networks']),{'front','private','lab'})
    def test_lab_nonroot_readonly_and_bounded_runtime(self):
        s=self.c['services']['log4shell']
        self.assertEqual(s['user'],'65532:65532');self.assertTrue(s['read_only'])
        self.assertEqual(s['cap_drop'],['ALL']);self.assertIn('no-new-privileges:true',s['security_opt'])
        self.assertEqual(s['mem_limit'],'512m');self.assertEqual(s['pids_limit'],128);self.assertEqual(s['cpus'],1)
        self.assertEqual(s['dns'],['127.0.0.1'])
        self.assertEqual(s['tmpfs'],['/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777'])
    def test_lab_keeps_image_command_without_host_mounts_or_credentials(self):
        s=self.c['services']['log4shell']
        for field in ('command','entrypoint','volumes','devices','env_file','network_mode'):self.assertNotIn(field,s)
        self.assertEqual(set(s['environment']),{'TZ','JAVA_TOOL_OPTIONS'})
        self.assertEqual(s['healthcheck'],{'disable':True})
    def test_ui_is_readonly_and_only_state_is_writable(self):
        volumes=self.c['services']['dvwa']['volumes']
        self.assertIn('./config/log4shell-ui:/var/www/html/log4shell:ro',volumes)
        self.assertIn('./config/verify-log4shell.php:/opt/capstone-log4shell-verify.php:ro',volumes)
        self.assertIn('./state/log4shell-ui:/var/lib/capstone-log4shell-ui',volumes)
        self.assertFalse(any('docker.sock' in v for v in volumes))
    def test_mutable_lab_reference_rejected(self):
        for reference in ('ghcr.io/example/app:latest','sha256:'+'a'*63,'http://example.invalid/app','sha256:'+'A'*64,' a'):
            with self.subTest(reference=reference):self.assertNotEqual(shell('lab_reference "$1"',None,reference).returncode,0)
        for reference in ('sha256:'+'a'*64,'ghcr.io/example/app@sha256:'+'b'*64):
            self.assertEqual(shell('lab_reference "$1"',None,reference).returncode,0)

class RuntimeTests(unittest.TestCase):
    def accepted(self,name,data):
        return shell('runtime_contract "$1" "$2"',json.dumps(data),name,IDS[name]).returncode==0
    def test_expected_containers_accepted(self):
        for name in IDS:
            with self.subTest(name=name):self.assertTrue(self.accepted(name,snapshot(name)))
    def test_lab_published_port_rejected(self):
        s=snapshot('log4shell');s['HostConfig']['PortBindings']={'8080/tcp':[{'HostIp':'0.0.0.0','HostPort':'8080'}]}
        self.assertFalse(self.accepted('log4shell',s))
    def test_lab_extra_network_rejected(self):
        s=snapshot('log4shell');s['NetworkSettings']['Networks']['capstone-service_front']={}
        self.assertFalse(self.accepted('log4shell',s))
    def test_lab_privilege_or_limit_relaxation_rejected(self):
        for field,value in [('Privileged',True),('ReadonlyRootfs',False),('CapAdd',['NET_ADMIN']),('Memory',0),
          ('PidsLimit',0),('Dns',['8.8.8.8']),('SecurityOpt',[]),('Tmpfs',{'/tmp':'rw'})]:
            with self.subTest(field=field):
                s=snapshot('log4shell');s['HostConfig'][field]=value;self.assertFalse(self.accepted('log4shell',s))
    def test_lab_host_mount_rejected(self):
        s=snapshot('log4shell');s['Mounts']=[{'Type':'bind','Source':'/','Destination':'/host','RW':False}]
        self.assertFalse(self.accepted('log4shell',s))
    def test_lab_command_or_user_override_rejected(self):
        for field,value in [('Cmd',['sh']),('User','0:0'),('Entrypoint',['sh'])]:
            with self.subTest(field=field):
                s=snapshot('log4shell');s['Config'][field]=value;self.assertFalse(self.accepted('log4shell',s))
    def test_database_cannot_join_lab(self):
        s=snapshot('db');s['NetworkSettings']['Networks']['capstone-service_lab']={}
        self.assertFalse(self.accepted('db',s))
    def test_ui_mount_write_or_missing_rejected(self):
        for action in ('write','remove','source'):
            s=snapshot('dvwa');mount=next(m for m in s['Mounts'] if m['Destination']=='/var/www/html/log4shell')
            if action=='write':mount['RW']=True
            elif action=='remove':s['Mounts'].remove(mount)
            else:mount['Source']='/unreviewed/ui'
            with self.subTest(action=action):self.assertFalse(self.accepted('dvwa',s))
    def test_rate_state_must_be_writable(self):
        s=snapshot('dvwa');next(m for m in s['Mounts'] if m['Destination']=='/var/lib/capstone-log4shell-ui')['RW']=False
        self.assertFalse(self.accepted('dvwa',s))

class UISourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='capstone-service-pure-');self.root=pathlib.Path(self.temp.name)
        self.public=self.root/'infra/groot-c/log4shell-ui/public';self.public.parent.mkdir(parents=True)
        shutil.copytree(ROOT/'infra/groot-c/log4shell-ui/public',self.public)
        code=SOURCE.split('ui_sources(){',1)[1].split("<<'PY'\n",1)[1].split('\nPY',1)[0]
        tree=ast.parse(code);nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        self.ns={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'service-ui-functions','exec'),self.ns)
    def tearDown(self):self.temp.cleanup()
    def assets(self):return self.ns['ui_assets'](self.root)
    def test_only_exact_constant_is_remapped(self):
        before,after=self.assets();self.assertEqual(set(before),{'api.php','index.html','app.js','app.css'})
        self.assertEqual(after['api.php'],before['api.php'].replace(b"const LAB_URL = 'http://10.200.10.20:8080/';",b"const LAB_URL = 'http://log4shell:8080/';",1))
        for name in ('index.html','app.js','app.css'):self.assertEqual(before[name],after[name])
    def test_real_manifest_hashes_original_sources(self):
        r=shell('CAPSTONE_SOURCE="$1"; ui_sources manifest',None,str(self.root));self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads(r.stdout),{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in self.public.iterdir()})
    def test_duplicate_or_changed_constant_rejected(self):
        p=self.public/'api.php';original=p.read_bytes()
        for changed in (original+ b"\nconst LAB_URL = 'http://10.200.10.20:8080/';\n",original.replace(b'10.200.10.20',b'192.0.2.20')):
            p.write_bytes(changed)
            with self.assertRaises(AssertionError):self.assets()
    def test_extra_file_or_symlink_rejected(self):
        p=self.public/'unexpected.php';p.write_text('<?php ?>')
        with self.assertRaises(AssertionError):self.assets()
        p.unlink();p=self.public/'app.css';p.unlink();p.symlink_to(self.public/'app.js')
        with self.assertRaises(AssertionError):self.assets()
    def test_symlinked_ui_parent_rejected(self):
        parent=self.public.parent;actual=parent.with_name('real-ui')
        parent.rename(actual);parent.symlink_to(actual,target_is_directory=True)
        with self.assertRaises(AssertionError):self.assets()

class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.query=SOURCE.split("jq -e 'keys==",1)[1].split("' \"$ROLE/manifest.json\"",1)[0]
        self.query='keys=='+self.query
        names=['compose.json','config/apache.conf','config/bootstrap.php','config/log4shell-ui/api.php',
          'config/log4shell-ui/app.css','config/log4shell-ui/app.js','config/log4shell-ui/index.html',
          'config/ossec.conf.candidate','config/verify-log4shell.php','credentials/admin-password',
          'credentials/app.env','credentials/db-password','credentials/db-root-password','credentials/db.env','input.json']
        self.manifest={'schema':2,'role':'service','state':'complete','files':{n:'a'*64 for n in names},
          'agent_config_sha256':'b'*64,'enrollment_ca_sha256':'c'*64,'enrollment_pass_sha256':'d'*64,'script_sha256':'e'*64}
    def accepted(self):
        return subprocess.run(['jq','-e',self.query],input=json.dumps(self.manifest),text=True,capture_output=True).returncode==0
    def test_complete_new_layout_accepted(self):self.assertTrue(self.accepted())
    def test_missing_ui_or_old_schema_rejected(self):
        self.manifest['files'].pop('config/log4shell-ui/api.php');self.assertFalse(self.accepted())
    def test_dynamic_rate_content_not_a_static_manifest_file(self):
        self.manifest['files']['state/log4shell-ui/request.lock']='f'*64;self.assertFalse(self.accepted())
    def test_old_schema_cannot_be_adopted(self):
        self.manifest['schema']=1;self.assertFalse(self.accepted())

unittest.main(argv=['service-test'],verbosity=2)
PY
