#!/usr/bin/env bash
# Local contract regression. No Docker, SSH, package, account, service or HTTP calls.
set -euo pipefail
exec python3 -B - "$(dirname "$0")/service.sh" <<'PY'
import copy,hashlib,io,json,pathlib,re,runpy,subprocess,sys,tempfile,unittest,zipfile
from unittest.mock import patch

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
        result['Config'].update(User='65532:65532',Cmd=['-jar','/app/spring-boot-application.jar'],
          Entrypoint=['java'],WorkingDir='/app',Healthcheck={'Test':['NONE']},
          Env=['TZ=Asia/Seoul','JAVA_TOOL_OPTIONS=-Xms64m -Xmx256m -Duser.timezone=Asia/Seoul',
            'SERVER_ADDRESS=0.0.0.0','SERVER_PORT=8080','SERVER_SERVLET_CONTEXT_PATH=/log4shell','LOGGING_CONFIG=classpath:log4j2-spring.xml'])
        result['HostConfig'].update(ReadonlyRootfs=True,CapDrop=['ALL'],CapAdd=None,PidsLimit=128,
          Memory=536870912,NanoCpus=1000000000,Dns=['127.0.0.1'],Tmpfs={'/tmp':'rw,nosuid,nodev,noexec,size=64m,mode=1777'})
        result['NetworkSettings']['Networks']={'capstone-service_lab':{}}
        result['Mounts']=[{'Type':'bind','Source':ROLE+'/config/log4shell-app.jar','Destination':'/app/spring-boot-application.jar','RW':False}]
    elif name=='db':
        result['State']['Health']={'Status':'healthy'}
        result['Mounts']=[{'Type':'volume','Name':'capstone-service_database','Destination':'/var/lib/mysql','RW':True}]
        result['NetworkSettings']['Networks']={'capstone-service_private':{}}
    else:
        result['State']['Health']={'Status':'healthy'}
        result['HostConfig']['PortBindings']={'80/tcp':[{'HostIp':HOST,'HostPort':PORT}]}
        result['NetworkSettings']['Networks']={n:{} for n in ('capstone-service_front','capstone-service_private','capstone-service_lab')}
        for src,dst,write in [('config/apache.conf','/etc/apache2/sites-enabled/000-default.conf',False),
          ('config/bootstrap.php','/opt/capstone-bootstrap.php',False),
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
    def test_lab_explicitly_launches_java_and_only_mounts_reviewed_jar(self):
        s=self.c['services']['log4shell']
        for field in ('devices','env_file','network_mode'):self.assertNotIn(field,s)
        self.assertEqual(s['entrypoint'],['java'])
        self.assertEqual(s['command'],['-jar','/app/spring-boot-application.jar'])
        self.assertEqual(s['working_dir'],'/app')
        self.assertEqual(set(s['environment']),{'TZ','JAVA_TOOL_OPTIONS','SERVER_ADDRESS','SERVER_PORT','SERVER_SERVLET_CONTEXT_PATH','LOGGING_CONFIG'})
        self.assertEqual(s['volumes'],[{'type':'bind','source':'./config/log4shell-app.jar',
          'target':'/app/spring-boot-application.jar','read_only':True,'bind':{'create_host_path':False}}])
        self.assertEqual(s['environment']['SERVER_SERVLET_CONTEXT_PATH'],'/log4shell')
        self.assertEqual(s['environment']['SERVER_ADDRESS'],'0.0.0.0')
        self.assertEqual(s['environment']['SERVER_PORT'],'8080')
        self.assertEqual(s['environment']['LOGGING_CONFIG'],'classpath:log4j2-spring.xml')
        self.assertEqual(s['healthcheck'],{'disable':True})
    def test_dvwa_has_no_php_relay_or_lab_session_mounts(self):
        volumes=self.c['services']['dvwa']['volumes']
        self.assertEqual(len(volumes),3)
        self.assertFalse(any('log4shell' in v or 'docker.sock' in v for v in volumes))
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
        for field,value in [('Cmd',['sh']),('User','0:0'),('Entrypoint',['sh']),('WorkingDir','/tmp')]:
            with self.subTest(field=field):
                s=snapshot('log4shell');s['Config'][field]=value;self.assertFalse(self.accepted('log4shell',s))
    def test_database_cannot_join_lab(self):
        s=snapshot('db');s['NetworkSettings']['Networks']['capstone-service_lab']={}
        self.assertFalse(self.accepted('db',s))
    def test_jar_mount_write_missing_or_unreviewed_source_rejected(self):
        for action in ('write','remove','source'):
            s=snapshot('log4shell');mount=s['Mounts'][0]
            if action=='write':mount['RW']=True
            elif action=='remove':s['Mounts'].remove(mount)
            else:mount['Source']='/unreviewed/app.jar'
            with self.subTest(action=action):self.assertFalse(self.accepted('log4shell',s))
    def test_context_and_listener_overrides_required(self):
        for variable in ('TZ=Asia/Seoul','JAVA_TOOL_OPTIONS=-Xms64m -Xmx256m -Duser.timezone=Asia/Seoul',
                         'SERVER_ADDRESS=0.0.0.0','SERVER_PORT=8080','SERVER_SERVLET_CONTEXT_PATH=/log4shell',
                         'LOGGING_CONFIG=classpath:log4j2-spring.xml'):
            s=snapshot('log4shell');s['Config']['Env'].remove(variable)
            self.assertFalse(self.accepted('log4shell',s))
    def test_duplicate_or_conflicting_runtime_environment_rejected(self):
        for variable in ('SERVER_PORT=8080','SERVER_PORT=9090','SERVER_ADDRESS=127.0.0.1',
                         'LOGGING_CONFIG=/unreviewed.xml','JAVA_TOOL_OPTIONS=-Xmx2g'):
            s=snapshot('log4shell');s['Config']['Env'].append(variable)
            with self.subTest(variable=variable):self.assertFalse(self.accepted('log4shell',s))
    def test_old_image_inherited_launch_contract_rejected(self):
        s=snapshot('log4shell');s['Config']['Entrypoint']=None
        s['Config']['Cmd']=['java','-jar','/app/spring-boot-application.jar']
        self.assertFalse(self.accepted('log4shell',s))
    def test_retired_php_mount_is_rejected(self):
        s=snapshot('dvwa');s['Mounts'].append({'Type':'bind','Source':ROLE+'/config/log4shell-ui','Destination':'/var/www/html/log4shell','RW':False})
        self.assertFalse(self.accepted('dvwa',s))

class HTTPHostnameTests(unittest.TestCase):
    def config(self,name='',port='8080'):
        result=shell('SECURITY_HOST=192.0.2.10; LOG4SHELL_HOSTNAME="$1"; WAF_PORT="$2"; apache_document',None,name,port)
        self.assertEqual(result.returncode,0,result.stderr)
        return result.stdout
    def test_default_remains_one_dvwa_vhost_without_redirect(self):
        result=self.config()
        self.assertEqual(result.count('<VirtualHost *:80>'),1)
        self.assertIn('Alias /dvwa /var/www/html',result)
        self.assertNotIn('RedirectMatch',result)
        self.assertNotIn('grootlab.duckdns.org',result)
        self.assertIn('ProxyRequests Off',result)
        self.assertIn('ProxyPass /log4shell/ http://log4shell:8080/log4shell/',result)
        self.assertIn('ProxyPassReverse /log4shell/ http://log4shell:8080/log4shell/',result)
    def test_named_host_is_second_vhost_and_preserves_default_exactly(self):
        original=self.config();result=self.config('log4shell.example.org')
        self.assertTrue(result.startswith(original))
        second=result[len(original):]
        self.assertEqual(second.count('<VirtualHost *:80>'),1)
        self.assertIn('ServerName log4shell.example.org\n',second)
        self.assertNotIn('ServerAlias',second)
        self.assertIn('RedirectMatch 302 "^/(?!log4shell/).*" "http://log4shell.example.org:8080/log4shell/"',second)
        self.assertIn("%{CONN_REMOTE_ADDR} == '192.0.2.10'",second)
        self.assertIn('LogFormat ',second)
        self.assertIn('CustomLog /var/log/capstone-service/access.log capstone_combined',second)
        self.assertIn('ErrorLog /var/log/capstone-service/error.log',second)
        self.assertNotIn('https:',second)
        # Apache chooses the first vhost for unmatched names, exact ServerName for this host.
        vhosts=re.findall(r'<VirtualHost \*:80>(.*?)</VirtualHost>',result,re.S)
        for host,index in [('log4shell.example.org',1),('dvwa.example.org',0),('192.0.2.10',0),('other.example.org',0)]:
            selected=next((i for i,block in enumerate(vhosts) if 'ServerName '+host+'\n' in block),0)
            self.assertEqual(selected,index)
    def test_log4shell_host_redirects_wrong_dvwa_path_without_redirecting_its_assets(self):
        second=self.config('log4shell.example.org').split('<VirtualHost *:80>')[2]
        pattern,target=re.search(r'RedirectMatch 302 "([^"]+)" "([^"]+)"',second).groups()
        self.assertEqual(target,'http://log4shell.example.org:8080/log4shell/')
        for path in ('/','/log4shell','/dvwa/login.php','/index.php','/other'):
            with self.subTest(path=path):self.assertIsNotNone(re.search(pattern,path))
        for path in ('/log4shell/','/log4shell/app.css','/log4shell/app.js','/log4shell/api/status'):
            with self.subTest(path=path):self.assertIsNone(re.search(pattern,path))
    def test_http_default_port_omitted_but_custom_port_preserved(self):
        self.assertIn('"http://log4shell.example.org/log4shell/"',self.config('log4shell.example.org','80'))
        self.assertIn('"http://log4shell.example.org:9080/log4shell/"',self.config('log4shell.example.org','9080'))
    def test_host_injection_ip_wildcard_scheme_and_bad_labels_refused(self):
        for name in ('http://log4shell.example.org','log4shell.example.org:80','log4shell.example.org/x','*.example.org',
                     '192.0.2.10','example..org','-bad.example.org','a'*64+'.org','example.org\nListen 443', 'UPPER.example.org'):
            with self.subTest(name=name):self.assertNotEqual(shell('hostname_valid "$1"',None,name).returncode,0)

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

class JARPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='capstone-jar-preparation-')
        self.addCleanup(self.temp.cleanup)
        self.directory=pathlib.Path(self.temp.name)
        self.jar=self.directory/'prepared.jar'
        self.jar.write_bytes(zip_bytes(jar_fixture()))
        self.jar_sha=hashlib.sha256(self.jar.read_bytes()).hexdigest()
        self.source_sha='a'*64
        self.report={'schema':1,'mode':'offline-image-jdk','source_sha256':self.source_sha,
          'image_id':IDS['log4shell'],'package':{'output_sha256':self.jar_sha,
          'dependencies_unchanged':True,'loader_and_metadata_unchanged':True},'temporary_containers_removed':True}
    def prepare(self,mode='auto',fail=False,report=None,write_all=False,expected_sha=None):
        (self.directory/'report.json').write_text(json.dumps(self.report if report is None else report))
        command=r'''
source "$1"
ROLE="$2/role"; CAPSTONE_SOURCE="$3"; LAB_ID="$4"; LAB_SOURCE_SHA="$5"
LAB_JAR_MODE="$6"; LAB_JAR_SHA="$7"; LOG4SHELL_APP_JAR="$2/prepared.jar"
TRACE="$2/compiler-arguments"; REPORT="$2/report.json"; DOCKER=/usr/bin/docker
BUILD_FAIL="$8"; WRITE_ALL="$9"
python3(){
  if [[ $3 == build ]]; then
    printf '%s\n' "$@" >"$TRACE"
    if [[ $BUILD_FAIL == yes ]]; then printf 'private compiler details\n' >&2; return 51; fi
    cp "$LOG4SHELL_APP_JAR" "$6"
    cat "$REPORT"
  else command python3 "$@"; fi
}
install(){ cp "$7" "$8"; chmod "$6" "$8"; }
sha(){ command python3 -B -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
if [[ $WRITE_ALL == yes ]]; then write_files; else
  mkdir -p "$ROLE/config" "$ROLE/evidence"
  prepare_lab_jar
fi
'''
        return subprocess.run(['bash','-c',command,'jar-prepare-test',str(SCRIPT),str(self.directory),str(ROOT),
          IDS['log4shell'],self.source_sha,mode,self.jar_sha if expected_sha is None else expected_sha,
          'yes' if fail else 'no','yes' if write_all else 'no'],capture_output=True,text=True)
    def test_auto_build_uses_checked_image_source_and_private_artifact(self):
        result=self.prepare();self.assertEqual(result.returncode,0,result.stderr)
        args=(self.directory/'compiler-arguments').read_text().splitlines()
        self.assertEqual(args,['-B',str(ROOT/'infra/groot-c/log4shell-app/tools/prepare_from_image.py'),
          'build',str(ROOT),IDS['log4shell'],str(self.directory/'role/config/log4shell-app.jar'),
          '--expected-source-sha256',self.source_sha,'--docker','/usr/bin/docker'])
        self.assertEqual((self.directory/'role/config/log4shell-app.jar').read_bytes(),self.jar.read_bytes())
    def test_compiler_failure_stops_before_compose_credentials_or_agent_copy(self):
        result=self.prepare(fail=True,write_all=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('offline_log4shell_build_failed_private_evidence_preserved',result.stderr)
        self.assertNotIn('private compiler details',result.stderr)
        self.assertIn('private compiler details',(self.directory/'role/evidence/log4shell-build.log').read_text())
        for name in ('compose.json','input.json','config/log4shell-app.jar','config/verify-log4shell.py','evidence/ossec.conf.before'):
            self.assertFalse((self.directory/'role'/name).exists())
        self.assertEqual(list((self.directory/'role/credentials').iterdir()),[])
    def test_build_evidence_must_match_source_image_jar_and_cleanup(self):
        mutations=[('mode','provided'),('source_sha256','b'*64),('image_id','sha256:'+'f'*64),('temporary_containers_removed',False),
          ('package.output_sha256','c'*64),('package.dependencies_unchanged',False),('package.loader_and_metadata_unchanged',False)]
        for key,value in mutations:
            with self.subTest(key=key):
                report=copy.deepcopy(self.report)
                if '.' in key:parent,child=key.split('.');report[parent][child]=value
                else:report[key]=value
                result=self.prepare(report=report)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('offline_build_evidence_mismatch',result.stderr)
    def test_built_jar_still_passes_the_independent_validator(self):
        self.jar.write_bytes(b'not a Spring Boot JAR')
        result=self.prepare();self.assertNotEqual(result.returncode,0)
        self.assertIn('invalid_built_log4shell_jar',result.stderr)
    def test_provided_jar_does_not_invoke_compiler(self):
        result=self.prepare(mode='provided');self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.directory/'compiler-arguments').exists())
        report=json.loads((self.directory/'role/evidence/log4shell-build.json').read_text())
        self.assertEqual(report,{'schema':1,'mode':'provided','output_sha256':self.jar_sha})
    def test_changed_provided_jar_rejected_before_copy(self):
        result=self.prepare(mode='provided',expected_sha='f'*64)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('lab_jar_changed_before_copy',result.stderr)
        self.assertFalse((self.directory/'role/config/log4shell-app.jar').exists())

class BuildLifecycleTests(unittest.TestCase):
    def exercise(self,mode,existing=False):
        with tempfile.TemporaryDirectory(prefix='capstone-build-lifecycle-') as directory:
            if existing:(pathlib.Path(directory)/'service').mkdir()
            command=r'''
source "$1"
CAPSTONE_ROOT="$2"; ROLE="$2/service"; LAB_JAR_MODE=auto
settings(){ MODE="$1"; }
safe_path(){ :; }; regular(){ :; }; stat(){ printf '0:0:600\n'; }; flock(){ :; }
fresh_namespace(){ printf 'fresh-checked\n'; }
assert_managed(){ printf 'managed-checked\n'; }
verify(){ printf 'managed-verified\n'; }
prepare_lab_jar(){ printf 'unexpected-compile\n' >&2; exit 91; }
write_files(){ printf 'unexpected-write\n' >&2; exit 92; }
main "$3"
'''
            return subprocess.run(['bash','-c',command,'build-lifecycle-test',str(SCRIPT),directory,mode],capture_output=True,text=True)
    def test_fresh_check_is_static_without_compile_or_write(self):
        result=self.exercise('check');self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('fresh-checked',result.stdout);self.assertIn('automatic compilation only at apply',result.stdout)
    def test_completed_check_uses_managed_contract_without_rebuild(self):
        result=self.exercise('check',True);self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('managed-checked',result.stdout)
    def test_verify_does_not_build_or_write(self):
        result=self.exercise('verify',True);self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('managed-verified',result.stdout)
    def test_repeated_completed_apply_verifies_without_rebuild(self):
        result=self.exercise('apply',True);self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('managed-verified',result.stdout)

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

class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.query=SOURCE.split("jq -e 'keys==",1)[1].split("' \"$ROLE/manifest.json\"",1)[0]
        self.query='keys=='+self.query
        names=['compose.json','config/apache.conf','config/bootstrap.php','config/log4shell-app.jar',
          'config/ossec.conf.candidate','config/verify-log4shell.py','credentials/admin-password',
          'credentials/app.env','credentials/db-password','credentials/db-root-password','credentials/db.env','evidence/log4shell-build.json','input.json']
        self.manifest={'schema':6,'role':'service','state':'complete','files':{n:'a'*64 for n in names},
          'agent_config_sha256':'b'*64,'enrollment_ca_sha256':'c'*64,'enrollment_pass_sha256':'d'*64,'script_sha256':'e'*64}
    def accepted(self):
        return subprocess.run(['jq','-e',self.query],input=json.dumps(self.manifest),text=True,capture_output=True).returncode==0
    def test_complete_new_layout_accepted(self):self.assertTrue(self.accepted())
    def test_missing_jar_rejected(self):
        self.manifest['files'].pop('config/log4shell-app.jar');self.assertFalse(self.accepted())
    def test_missing_build_evidence_rejected(self):
        self.manifest['files'].pop('evidence/log4shell-build.json');self.assertFalse(self.accepted())
    def test_retired_php_rate_state_not_a_static_manifest_file(self):
        self.manifest['files']['state/log4shell-ui/request.lock']='f'*64;self.assertFalse(self.accepted())
    def test_old_schema_cannot_be_adopted(self):
        for schema in (1,2,3,4,5):
            self.manifest['schema']=schema;self.assertFalse(self.accepted())

unittest.main(argv=['service-test'],verbosity=2)
PY
