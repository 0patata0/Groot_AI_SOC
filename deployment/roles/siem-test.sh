#!/usr/bin/env bash
# Pure/local fixture: no Docker, account, service, HTTP, model or package calls.
set -euo pipefail
exec python3 -B - "$(dirname "$0")/siem.sh" <<'PY'
import ast,copy,hashlib,json,os,pathlib,stat,sys,tempfile,types,unittest
source=pathlib.Path(sys.argv[1]).read_text().split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
tree=ast.parse(source)
nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.ClassDef))]
def namespace():
    ns={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'siem-functions','exec'),ns)
    return ns
def fixture(root):
    ns=namespace();dest=root/'siem';dest.mkdir(); tls=dest/'tls';tls.mkdir()
    for name in ('root-ca.pem','root-ca-manager.pem','wazuh.manager.pem','wazuh.manager-key.pem',
                 'wazuh.indexer.pem','wazuh.indexer-key.pem','wazuh.dashboard.pem','wazuh.dashboard-key.pem',
                 'admin.pem','admin-key.pem','api-server.pem','api-server-key.pem'):
        (tls/name).write_bytes(b'public-synthetic-fixture')
    pre=root/'prereqs'; wt=pre/'wazuh-docker/single-node'
    images={n:'image:'+n for n in ('wazuh.manager','wazuh.indexer','wazuh.dashboard','mattermost','postgres','hermes')}
    names={n:'container-'+n for n in images}
    cfg={'schema_version':1,'wazuh_api_username':'wazuh-wui','wazuh_api_password':'Fixture-password-123!',
         'indexer_username':'admin','indexer_password':'Fixture-password-456!',
         'postgres_password':'Fixture-password-789!','mattermost_admin_username':'admin',
         'mattermost_admin_email':'admin@example.invalid','mattermost_admin_password':'Fixture-password-ABC!',
         'hermes_image':'sha256:'+'1'*64}
    ns.update(ROOT=root,DEST=dest,PRE=pre,TREE=wt,SOURCE=root/'source',IP='192.0.2.20',PROJECT='capstone-siem',
              HOSTS={'SECURITY_HOST':'192.0.2.10','SIEM_HOST':'192.0.2.20','SERVICE_HOST':'192.0.2.30'},
              LLM='http://192.0.2.40:11434/v1',MODEL='fixture-model',SSH_PORT='22',cfg=cfg,
              IMAGES={n:'wazuh/'+n+':4.14.8' for n in ('wazuh.manager','wazuh.indexer','wazuh.dashboard')},
              NAMES=names,dashboard_password='synthetic-dashboard-password')
    services={n:{'image':ns['IMAGES'][n],'volumes':[],'ports':[]} for n in ns['IMAGES']}
    services['wazuh.manager']['volumes']=[{'type':'bind','source':str(wt/'config/wazuh_cluster/wazuh_manager.conf'),
                                          'target':'/wazuh-config-mount/etc/ossec.conf'}]
    services['wazuh.indexer']['volumes']=[{'type':'bind','source':str(wt/'config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem'),
                                         'target':'/usr/share/wazuh-indexer/config/certs/wazuh.indexer.key'}]
    compose={'services':services,'volumes':{'old':{}},'networks':{'default':{}}}
    return ns,compose,images
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='capstone-siem-pure-');self.root=pathlib.Path(self.tmp.name)
        self.n,self.c,self.images=fixture(self.root)
    def tearDown(self): self.tmp.cleanup()
    def reject(self,fn):
        with self.assertRaises(self.n['Refused']):fn()
    def test_duplicate_secret_key_refused(self):
        self.reject(lambda:self.n['parse'](b'{"password":"one","password":"two"}'))
    def test_identity_allows_atime_only(self):
        s=types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o100600,st_uid=0,st_gid=0,st_nlink=1,
                                st_size=4,st_mtime_ns=5,st_ctime_ns=6,st_atime_ns=7)
        b=copy.copy(s);b.st_atime_ns=8
        self.assertEqual(self.n['identity'](s),self.n['identity'](b))
        b.st_ino=3;self.assertNotEqual(self.n['identity'](s),self.n['identity'](b))
    def test_three_official_services(self): self.n['validate_wazuh'](self.c)
    def test_custom_ssh_port_is_in_host_key_and_profile(self):
        self.assertEqual(self.n['ssh_host_token'](),'192.0.2.20')
        self.n['read']=lambda *a,**k:b'synthetic';old=self.n['profile']({},self.images)
        self.n['SSH_PORT']='2222'
        self.assertEqual(self.n['ssh_host_token'](),'[192.0.2.20]:2222')
        new=self.n['profile']({},self.images)
        self.assertEqual(new['ssh_port'],2222);self.assertNotEqual(old,new)
    def test_official_two_ossec_roots_preserve_unrelated_bytes(self):
        raw=b'<!-- fixture -->\n<ossec_config>\n <global><jsonout_output>yes</jsonout_output></global>\n <auth><disabled>no</disabled><use_password>no</use_password></auth>\n</ossec_config>\n<ossec_config>\n <localfile><log_format>syslog</log_format><location>/var/log/auth.log</location></localfile>\n</ossec_config>\n'
        new=self.n['manager_auth_configuration'](raw)
        oldauth=b'<auth><disabled>no</disabled><use_password>no</use_password></auth>'
        start=new.index(b'<auth>');end=new.index(b'</auth>')+len(b'</auth>')
        self.assertEqual(new[:start]+oldauth+new[end:],raw)
        self.assertIn(b'<use_password>yes</use_password>',new)
        self.assertIn(b'<use_source_ip>yes</use_source_ip>',new)
    def test_missing_auth_inserted_once(self):
        raw=b'<ossec_config><global/></ossec_config>\n<ossec_config><localfile/></ossec_config>'
        new=self.n['manager_auth_configuration'](raw)
        self.assertEqual(new.count(b'<auth>'),1)
        self.assertTrue(new.endswith(b'\n<ossec_config><localfile/></ossec_config>'))
    def test_duplicate_auth_refused(self):
        self.reject(lambda:self.n['manager_auth_configuration'](b'<ossec_config><auth/><auth/></ossec_config>'))
    def test_duplicate_auth_option_refused(self):
        self.reject(lambda:self.n['manager_auth_configuration'](b'<ossec_config><auth><port>1</port><port>2</port></auth></ossec_config>'))
    def test_extra_service_refused(self):
        self.c['services']['unknown']={};self.reject(lambda:self.n['validate_wazuh'](self.c))
    def test_privileged_refused(self):
        self.c['services']['wazuh.manager']['privileged']=True;self.reject(lambda:self.n['validate_wazuh'](self.c))
    def test_host_network_refused(self):
        self.c['services']['wazuh.manager']['network_mode']='host';self.reject(lambda:self.n['validate_wazuh'](self.c))
    def test_external_volume_refused(self):
        self.c['volumes']['old']['external']=True;self.reject(lambda:self.n['validate_wazuh'](self.c))
    def test_outside_source_refused(self):
        self.c['services']['wazuh.manager']['volumes'][0]['source']='/etc/shadow';self.reject(lambda:self.n['validate_wazuh'](self.c))
    def compose(self):
        self.n['os']=types.SimpleNamespace(chown=lambda *a:None,chmod=lambda *a:None)
        self.n['publish']=lambda p,d,*a,**k:p.write_bytes(d)
        return self.n['write_compose'](self.c,self.images)
    def test_first_volume_initialization_not_short_circuited(self):
        c=self.compose();vols=c['services']['wazuh.manager']['volumes'];targets={x['target'] for x in vols}
        self.assertIn('/wazuh-config-mount/etc/authd.pass',targets)
        self.assertIn('/wazuh-config-mount/api/configuration/ssl/server.key',targets)
        self.assertIn('/wazuh-config-mount/etc/local_internal_options.conf',targets)
        self.assertFalse(any(x.startswith('/var/ossec/') for x in targets))
        self.assertTrue(all(x['read_only'] for x in vols if x['target']!='/wazuh-config-mount/etc/ossec.conf'))
    def test_compose_images_credentials_and_no_pull(self):
        c=self.compose()
        for name,svc in c['services'].items():
            self.assertEqual(svc['image'],self.images[name]);self.assertEqual(svc['pull_policy'],'never')
        env=c['services']['wazuh.dashboard']['environment']
        self.assertEqual(env['API_PASSWORD'],self.n['cfg']['wazuh_api_password'])
        self.assertEqual(env['DASHBOARD_PASSWORD'],'synthetic-dashboard-password')
        self.assertEqual(c['services']['mattermost']['ports'][0]['host_ip'],self.n['IP'])
        self.assertFalse('hermes' in c['services'])
    def test_certificate_source_remapped_only_to_generated_private_tls(self):
        c=self.compose();v=c['services']['wazuh.indexer']['volumes'][0]
        self.assertEqual(v['source'],str(self.n['DEST']/'tls/wazuh.indexer-key.pem'))
        self.assertTrue(v['read_only'])
    def test_ca_and_leaf_subject_SAN_contract(self):
        # Native OpenSSL argv contract; no cryptographic binary is executed here.
        target=self.n['DEST']/'tls'
        for p in target.iterdir():p.unlink()
        target.rmdir();commands=[];checks=[]
        self.n['mkdir']=lambda p,*a,**k:p.mkdir()
        self.n['publish']=lambda p,d,*a,**k:p.write_bytes(d)
        self.n['read']=lambda p,*a,**k:pathlib.Path(p).read_bytes()
        self.n['cert_check']=lambda *args:checks.append(args)
        def run(argv,*a,**k):
            commands.append(argv)
            for opt in ('-keyout','-out'):
                if opt in argv:pathlib.Path(argv[argv.index(opt)+1]).write_bytes(b'fixture-certificate')
            return b''
        self.n['run']=run;self.n['create_certificates']()
        self.assertEqual(len(checks),5)
        subjects=[a[a.index('-subj')+1] for a in commands if '-subj' in a]
        self.assertIn('/C=US/L=California/O=Wazuh/OU=Wazuh/CN=admin',subjects)
        self.assertIn('/C=US/L=California/O=Wazuh/OU=Wazuh/CN=wazuh.indexer',subjects)
        self.assertIn('DNS:wazuh.manager,IP:192.0.2.20',(target/'api-server.ext').read_text())
        self.assertEqual(stat.S_IMODE((target/'root-ca-key.pem').stat().st_mode),0o600)
    def test_source_profile_changes_rejected_by_equality(self):
        values={'value':b'first'};self.n['read']=lambda *a,**k:values['value']
        a=self.n['profile']({'file':'0'*64},self.images);values['value']=b'second'
        self.assertNotEqual(a,self.n['profile']({'file':'0'*64},self.images))
    def test_api_bootstrap_does_not_post_chat_or_reuse_admin_for_MCP(self):
        calls=[];intents=[];published={}
        self.n['pending']=intents.append;self.n['publish']=lambda p,d,*a,**k:published.update({p.name:json.loads(d)})
        self.n['tls']=lambda:None;self.n['auth_api']=lambda:{'Authorization':'fixture'}
        self.n['readonly_credentials']=lambda c:None
        def api(url,method='GET',body=None,headers=None,context=None,raw=False,statuses=(200,)):
            calls.append((url,method,body))
            if '/api/v4/users/login' in url:return {},{'Token':'synthetic-admin-token'}
            if url.endswith('/api/v4/users'):return {'id':'admin-id','roles':'system_admin system_user'},{}
            if url.endswith('/teams'):return {'id':'team-id'},{}
            if url.endswith('/channels'):return {'id':'channel-id'},{}
            if url.endswith('/bots'):return {'user_id':'bot-id'},{}
            if url.endswith('/tokens'):return {'token':'a'*26},{}
            if url.endswith('/security/roles'):return {'data':{'affected_items':[{'name':'readonly','id':5}]}},{}
            if url.endswith('/security/users'):return {'data':{'affected_items':[{'id':101}]}},{}
            if 'user_ids=101' in url:return {'data':{'affected_items':[{'id':101,'roles':[5]}]}},{}
            if method=='GET' and url.endswith('/roles/capstone_mcp_readonly'):
                return {'capstone_mcp_readonly':{'index_permissions':[{'allowed_actions':['read']}],'tenant_permissions':[]}},{}
            return {},{}
        self.n['api']=api;creds=self.n['app_bootstrap']()
        self.assertEqual(creds['readonly_username'],'capstone-ro')
        self.assertNotEqual(creds['readonly_password'],self.n['cfg']['indexer_password'])
        self.assertEqual(len(intents),len(set(intents)))
        self.assertFalse(any('/posts' in u or '/notify' in u for u,_,_ in calls))
        self.assertEqual(len([u for u,m,_ in calls if '/api/v4/users' in u and m=='POST' and u.endswith('/tokens')]),1)
    def test_embedded_programs_compile(self):
        found=0
        for n in ast.walk(tree):
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('code','launcher') for t in n.targets) and isinstance(n.value,ast.Constant):
                ast.parse(n.value.value);found+=1
        self.assertEqual(found,3)
if __name__=='__main__':unittest.main(argv=['siem-pure-fixture'],verbosity=2)
PY
