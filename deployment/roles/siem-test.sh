#!/usr/bin/env bash
# Pure/local fixture: no Docker, account, service, HTTP, model or package calls.
set -euo pipefail
exec python3 -B - "$(dirname "$0")/siem.sh" <<'PY'
import ast,copy,hashlib,json,os,pathlib,stat,sys,tempfile,types,unittest
from unittest import mock
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
    def test_diagnostic_dispatch_precedes_all_wazuh_credential_reads(self):
        setup=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='setup_mcp_and_hermes')
        assignment=next(n for n in ast.walk(setup) if isinstance(n,ast.Assign) and
                        any(isinstance(t,ast.Name) and t.id=='launcher' for t in n.targets))
        launcher=ast.literal_eval(assignment.value)
        self.assertLess(launcher.index("if command=='system-diagnostics':"),launcher.index("credentials.json"))
        with mock.patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':'system-diagnostics'},clear=True), \
             mock.patch.object(pathlib.Path,'read_bytes',side_effect=AssertionError('credential read')), \
             mock.patch.object(os,'execve',side_effect=RuntimeError('fixed dispatch')) as execute:
            with self.assertRaisesRegex(RuntimeError,'fixed dispatch'):
                exec(compile(launcher,'diagnostic-dispatch','exec'),{'__file__':'/opt/capstone/siem/capstone-mcp/run-mcp'})
        self.assertEqual(execute.call_args.args[0],'/opt/mcp/run-system-diagnostics.sh')
        self.assertEqual(set(execute.call_args.args[2]),{'PATH','LANG','PYTHONDONTWRITEBYTECODE'})
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='capstone-siem-pure-');self.root=pathlib.Path(self.tmp.name)
        self.n,self.c,self.images=fixture(self.root)
    def tearDown(self): self.tmp.cleanup()
    def reject(self,fn):
        with self.assertRaises(self.n['Refused']):fn()
    def test_duplicate_secret_key_refused(self):
        self.reject(lambda:self.n['parse'](b'{"password":"one","password":"two"}'))
    def test_dashboard_disables_multitenancy_without_changing_other_lines(self):
        original=b'server.host: 0.0.0.0\nopensearch_security.multitenancy.enabled: true # old\nserver.port: 5601\n'
        expected=b'server.host: 0.0.0.0\nopensearch_security.multitenancy.enabled: false\nserver.port: 5601\n'
        self.assertEqual(self.n['dashboard_single_tenant'](original),expected)
        self.assertEqual(self.n['dashboard_single_tenant'](expected),expected)
        self.assertEqual(self.n['dashboard_single_tenant'](b'server.port: 5601\n'),
                         b'server.port: 5601\nopensearch_security.multitenancy.enabled: false\n')
    def test_dashboard_ambiguous_multitenancy_refused(self):
        key=b'opensearch_security.multitenancy.enabled'
        for value in (key+b': true\n'+key+b': false\n',key+b': "false"\n',b'  '+key+b': true\n',b'"'+key+b'": true\n'):
            with self.subTest(value=value):self.reject(lambda:self.n['dashboard_single_tenant'](value))
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
    def test_log_activation_budget_covers_all_native_groups(self):
        calls=[]
        self.n['run']=lambda argv,timeout: calls.append((argv,timeout))
        self.n['log_pipeline']('activate')
        self.assertGreater(calls[-1][1],4*180+120)
        self.assertEqual(calls[-1][0][-2:],['activate','siem'])
        for action in ('check','prepare'):
            self.n['log_pipeline'](action)
            self.assertEqual(calls[-1][1],120)
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
        self.n['run']=run
        # A pure fixture verifies the requested ownership without requiring root
        # or changing ownership of the developer's temporary files.
        with mock.patch.object(os,'chown') as chown:
            self.n['create_certificates']()
        self.assertEqual(chown.call_args_list,[mock.call(target/(n+'-key.pem'),0,1000)
            for n in ('wazuh.manager','wazuh.indexer','wazuh.dashboard','api-server','admin')])
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
    def test_mattermost_extensions_install_with_scoped_identity_and_native_paths(self):
        written={};created=[];reads=[]
        self.n['mkdir']=lambda p,mode,uid,gid:created.append((p,mode,uid,gid))
        self.n['publish']=lambda p,data,mode,uid,gid:written.update({str(p):(data,mode,uid,gid)})
        def read(path,*args):
            reads.append(str(path));return ('source:'+str(path)).encode()
        self.n['read']=read
        creds={name:'a'*26 for name in ('mattermost_admin_id','mattermost_team_id','mattermost_channel_id','mattermost_bot_id')}
        creds['mattermost_bot_token']='synthetic-bot-token'
        user=types.SimpleNamespace(pw_uid=995,pw_gid=986)
        config={'mcp_servers':{'only-readonly':{}},'toolsets':['mcp-wazuh-ro']}
        baseline=copy.deepcopy(config)
        env=self.n['install_hermes_extensions'](self.n['DEST']/'bot',user,creds,config)
        self.assertEqual(len(written),7)
        self.assertEqual(len(reads),7)
        self.assertEqual({pathlib.Path(p).name for p in written},{'__init__.py','plugin.yaml','channel_sync.py','HOOK.yaml','handler.py'})
        self.assertTrue(any('/plugins/groot-mattermost-context/' in p for p in written))
        self.assertTrue(any('/hooks/groot-mattermost-channel-sync/' in p for p in written))
        self.assertEqual({pathlib.Path(p).name for p in written if '/plugins/groot-query-completion/' in p},
                         {'__init__.py','plugin.yaml'})
        self.assertTrue(all(value[1:]==(0o600,995,986) for value in written.values()))
        self.assertTrue(all(value[1:]==(0o700,995,986) for value in created))
        self.assertEqual(config['plugins'],{'enabled':['groot-mattermost-context','groot-query-completion']})
        self.assertEqual({k:v for k,v in config.items() if k!='plugins'},baseline)
        self.assertEqual(env['MATTERMOST_ALLOWED_USERS'],creds['mattermost_admin_id'])
        self.assertEqual(env['MATTERMOST_ALLOWED_CHANNELS'],'')
        self.assertEqual(env['MATTERMOST_REQUIRE_MENTION'],'true')
        self.assertEqual(env['MATTERMOST_REPLY_MODE'],'thread')
        self.assertEqual(env['MATTERMOST_FREE_RESPONSE_CHANNELS'],'')
        self.assertEqual(env['MATTERMOST_HOME_CHANNEL'],creds['mattermost_channel_id'])
        self.assertEqual(env['CAPSTONE_MM_TEAM_ID'],creds['mattermost_team_id'])
        self.assertEqual(env['CAPSTONE_MM_BOT_ID'],creds['mattermost_bot_id'])
    def test_extension_identity_validation_precedes_filesystem_mutation(self):
        calls=[];self.n['mkdir']=lambda *a,**k:calls.append(a)
        user=types.SimpleNamespace(pw_uid=995,pw_gid=986)
        for key in ('mattermost_admin_id','mattermost_team_id','mattermost_channel_id','mattermost_bot_id'):
            creds={name:'a'*26 for name in ('mattermost_admin_id','mattermost_team_id','mattermost_channel_id','mattermost_bot_id')}
            creds[key]='../../invalid'
            self.reject(lambda:self.n['install_hermes_extensions'](self.n['DEST'],user,creds,{}))
        self.assertEqual(calls,[])
    def test_extension_sources_participate_in_immutable_profile(self):
        for source in self.n['hermes_extension_files']():
            with self.subTest(source=source):
                values={'extension':b'first'}
                def read(path,*args,**kwargs):
                    return values['extension'] if path==self.n['SOURCE']/source else b'unchanged'
                self.n['read']=read
                first=self.n['profile']({},self.images)
                values['extension']=b'second'
                second=self.n['profile']({},self.images)
                changed={key for key,value in first['source_sha256'].items() if value!=second['source_sha256'][key]}
                self.assertEqual(changed,{source})
    def query_plugin(self):
        return (pathlib.Path(sys.argv[1]).resolve().parents[2]/'infra/hermes/query-completion/__init__.py').read_bytes()
    def test_query_source_pins_use_bounded_plugin_source_without_import(self):
        calls=[];raw=self.query_plugin()
        def read(path,cap):calls.append((path,cap));return raw
        self.n['read']=read
        pins=self.n['query_completion_source_pins']()
        self.assertEqual(calls,[(self.n['SOURCE']/'infra/hermes/query-completion/__init__.py',512*1024)])
        self.assertEqual(set(pins),{'agent/turn_final_response.py','agent/conversation_loop.py',
                                   'agent/turn_context.py','agent/message_metadata.py',
                                   'agent/turn_api_request.py','agent/chat_completion_helpers.py'})
        self.assertTrue(all(len(value)==64 for value in pins.values()))
        # Parsing pins must not execute other top-level plugin code.
        self.assertEqual(self.n['query_completion_source_pins'](raw+b'\nraise RuntimeError("must_not_execute")\n'),pins)
    def test_query_source_pins_reject_missing_duplicate_executable_or_invalid_hash(self):
        pins=self.n['query_completion_source_pins'](self.query_plugin())
        valid='SOURCE_SHA256 = '+repr(pins)+'\n'
        variants=[b'\xff',b'SOURCE_SHA256 = {',b'SOURCE_SHA256 = dict()',b'OTHER = {}',
                  (valid+valid).encode(),b'SOURCE_SHA256 = __import__("os").environ']
        for path in pins:
            missing=dict(pins);missing.pop(path);variants.append(('SOURCE_SHA256 = '+repr(missing)).encode())
            wrong=dict(pins);wrong[path]='not-a-source-hash';variants.append(('SOURCE_SHA256 = '+repr(wrong)).encode())
        escaped=dict(pins);escaped['../../outside.py']=escaped.pop(next(iter(pins)))
        variants.append(('SOURCE_SHA256 = '+repr(escaped)).encode())
        duplicate='SOURCE_SHA256 = {'+','.join(repr(k)+':'+repr(v) for k,v in pins.items())+','+repr(next(iter(pins)))+':'+repr(next(iter(pins.values())))+'}'
        variants.append(duplicate.encode())
        for raw in variants:
            with self.subTest(raw=raw[:40]):self.reject(lambda:self.n['query_completion_source_pins'](raw))
    def image_probe_code(self):
        return next(n.value.value for n in ast.walk(tree) if isinstance(n,ast.Assign)
                    and any(isinstance(t,ast.Name) and t.id=='code' for t in n.targets)
                    and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)
                    and 'VALID_HOOKS' in n.value.value)
    def test_image_probe_rejects_drift_or_missing_native_source_for_each_pin(self):
        whole=self.image_probe_code()
        code=whole[whole.index('source_pins=json.loads'):whole.index('from hermes_cli.plugins import')]
        paths=self.n['query_completion_source_pins'](self.query_plugin())
        files={path:('synthetic-native:'+path).encode() for path in paths}
        pins={path:hashlib.sha256(data).hexdigest() for path,data in files.items()}
        def path(root,relative):
            self.assertEqual(root,'/opt/hermes')
            return types.SimpleNamespace(read_bytes=lambda:files[relative])
        scope={'sys':types.SimpleNamespace(argv=['probe','guard-sha',json.dumps(pins)]),
               'hashlib':hashlib,'json':json,'pathlib':types.SimpleNamespace(Path=path)}
        exec(code,scope)
        for relative in paths:
            with self.subTest(relative=relative):
                original=files[relative];files[relative]=b'changed-native-source'
                with self.assertRaises(AssertionError):exec(code,scope)
                del files[relative]
                with self.assertRaises(KeyError):exec(code,scope)
                files[relative]=original
    def test_image_probe_passes_plugin_pins_without_network_mounts_or_installs(self):
        commands=[];raw=self.query_plugin()
        self.n['read']=lambda path,*args,**kwargs:raw if 'query-completion' in str(path) else b'guard-fixture'
        self.n['run']=lambda argv,*args,**kwargs:commands.append(argv) or b''
        self.n['image_probe']('sha256:'+'a'*64)
        run=commands[0]
        self.assertEqual(json.loads(run[-1]),self.n['query_completion_source_pins'](raw))
        self.assertEqual(run[run.index('--network')+1],'none')
        self.assertEqual(run[run.index('--pull')+1],'never')
        self.assertIn('--read-only',run)
        self.assertNotIn('--volume',run);self.assertNotIn('--mount',run)
        self.assertEqual(commands[1][:3],['docker','ps','-a'])
    def test_query_source_and_image_compatibility_fail_before_fresh_installation(self):
        preflight=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='preflight')
        calls=[n for n in ast.walk(preflight) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        pin_calls=[n for n in calls if n.func.id=='query_completion_source_pins']
        self.assertEqual(len(pin_calls),1)
        self.assertLess(pin_calls[0].lineno,min(n.lineno for n in calls if n.func.id=='image_id'))
        main=next(n for n in tree.body if isinstance(n,ast.Try))
        direct=[node.value for node in main.body if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)]
        image=next(n for n in direct if isinstance(n.func,ast.Name) and n.func.id=='image_probe')
        prepare=next(n for n in ast.walk(main) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='prepare_files')
        self.assertLess(image.lineno,prepare.lineno)
    def response_policy(self):
        return (pathlib.Path(sys.argv[1]).resolve().parents[2]/'infra/hermes/SOUL.groot.md').read_bytes()
    def test_response_format_extracts_only_exact_shared_four_bullets(self):
        raw=self.response_policy();block=self.n['hermes_response_format'](raw)
        expected='### SOC 응답 서식\n'+raw.decode().split('### SOC 응답 서식\n',1)[1].split('\n## 보안 룰 변경 요청\n',1)[0].strip()+'\n'
        self.assertEqual(block,expected)
        self.assertEqual(sum(line.startswith('- ') for line in block.splitlines()),4)
        for text in ('`**요약**`','`**확인 내역**`','`**조치 및 다음 단계**`'):
            self.assertIn(text,block)
        self.assertNotIn('get_rule_change_target',block)
        self.assertNotIn('propose_rule_edit',block)
        self.assertNotIn('LLM이 SOC 운영의 관리 주체다',block)
    def test_response_format_uses_chat_lists_and_limits_table_exception(self):
        block=self.n['hermes_response_format'](self.response_policy())
        bullets=[line for line in block.splitlines() if line.startswith('- ')]
        self.assertIn('`- **대상명**: 상태 — 근거`',bullets[0])
        self.assertNotIn('`대상 | 상태 | 근거`',block)
        self.assertNotIn('`항목 | 내용`',block)
        for form in ('파이프(`|`)로 열을 나눈 표','공백으로 정렬한 표','HTML 표','표를 감싼 코드 블록'):
            self.assertIn(form,bullets[2])
        self.assertIn('기본 서식으로 쓰지 않는다',bullets[2])
        self.assertIn('Markdown 문서·파일 생성 요청의 문서 본문이나 사용자가 명시적으로 표를 요청한 경우에만 표를 사용한다',bullets[2])
        self.assertIn('파일을 제공하는 채팅 안내 자체는 목록으로 쓴다',bullets[2])
        self.assertIn('전체 답변을 코드 블록으로 감싸지 않는다',bullets[2])
    def test_response_format_approval_lists_keep_six_fields_and_card_authority(self):
        block=self.n['hermes_response_format'](self.response_policy())
        approval=[line for line in block.splitlines() if line.startswith('- ')][1]
        self.assertIn('`- **항목명**: 내용`',approval)
        fields=('대상','변경 전','변경 후','예상 영향','검증','승인 상태')
        positions=[approval.index('`'+field+'`') for field in fields]
        self.assertEqual(positions,sorted(positions))
        self.assertIn('여섯 항목을 각각 별도 줄에 쓴다',approval)
        self.assertIn('실제 도구가 제공한 승인 링크',approval)
        self.assertIn('아직 제출하지 않은 후보를 승인 요청 완료로 표시하지 않는다',approval)
        self.assertIn('일반 채팅의 동의는 카드 승인이 아니다',approval)
    def test_response_format_fails_closed_for_missing_duplicate_or_changed_structure(self):
        raw=self.response_policy()
        start='<!-- rule-change-policy:start -->\n### SOC 응답 서식\n'.encode()
        end='\n## 보안 룰 변경 요청\n'.encode()
        variants=(raw.replace(start,b'',1),raw+start,raw.replace(end,b'',1),raw+end,
                  raw.replace(end,b'\n- extra policy\n'+end,1),
                  raw.replace(end,b'\n## unexpected capability\n'+end,1),b'\xff',
                  end+raw.replace(end,b'',1))
        for invalid in variants:
            with self.subTest(case=variants.index(invalid)):
                self.reject(lambda:self.n['hermes_response_format'](invalid))
    def test_response_format_read_is_bounded_and_readonly_soul_retains_capabilities(self):
        calls=[]
        def read(path,cap):
            calls.append((path,cap));return self.response_policy()
        self.n['read']=read;soul=self.n['readonly_soul']()
        self.assertEqual(calls,[(self.n['SOURCE']/'infra/hermes/SOUL.groot.md',512*1024)])
        self.assertTrue(soul.startswith('# SOC 읽기 보조자\n'))
        self.assertIn('현재 제공된 Wazuh 읽기 MCP와 security-events MCP에서 확인한 사실만 보고한다.',soul)
        self.assertIn('이 환경에는 쓰기 승인·차단·규칙 수정 도구가 배포되지 않았다. 수행했다고 주장하지 않는다.',soul)
        self.assertTrue(soul.endswith(self.n['hermes_response_format'](self.response_policy())))
        self.assertNotIn('propose_rule_edit',soul)
    def test_response_format_source_hash_changes_deployment_profile(self):
        values={'policy':b'first'}
        self.n['read']=lambda path,*a,**k:values['policy'] if path.name=='SOUL.groot.md' else b'unchanged'
        first=self.n['profile']({},self.images);values['policy']=b'second'
        second=self.n['profile']({},self.images)
        changed={key for key,value in first['source_sha256'].items() if value!=second['source_sha256'][key]}
        self.assertEqual(changed,{'infra/hermes/SOUL.groot.md'})
    def test_response_format_preflight_runs_before_container_image_operations(self):
        preflight=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='preflight')
        calls=[n for n in ast.walk(preflight) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        format_calls=[n for n in calls if n.func.id=='hermes_response_format']
        self.assertEqual(len(format_calls),1)
        self.assertLess(format_calls[0].lineno,min(n.lineno for n in calls if n.func.id=='image_id'))
        self.assertIn('infra/hermes/SOUL.groot.md',ast.unparse(preflight))
    def test_prepared_image_native_contract_accepts_supported_and_rejects_unsafe_image(self):
        codes=[n.value.value for n in ast.walk(tree) if isinstance(n,ast.Assign)
               and any(isinstance(t,ast.Name) and t.id=='code' for t in n.targets)
               and isinstance(n.value,ast.Constant) and isinstance(n.value.value,str)]
        whole=next(value for value in codes if 'VALID_HOOKS' in value)
        code=whole[whole.index('from hermes_cli.plugins import'):whole.index('from hermes_cli.tools_config import')]
        plugins=types.ModuleType('hermes_cli.plugins')
        plugins.PluginContext=types.SimpleNamespace(register_hook=lambda:None,on_unload=lambda:None)
        plugins.VALID_HOOKS={'pre_gateway_dispatch'}
        hooks=types.ModuleType('gateway.hooks')
        hooks.HookRegistry=types.SimpleNamespace(discover_and_load=lambda:None,emit=lambda:None,emit_collect=lambda:None)
        events=types.ModuleType('gateway.platforms.event')
        events.MessageEvent=types.SimpleNamespace(__dataclass_fields__={key:None for key in
            ('internal','reply_to_text','reply_to_message_id','channel_context')},is_command=lambda:False)
        inbound=types.ModuleType('gateway.run_inbound')
        authz=types.ModuleType('gateway.authz_mixin')
        authz.GatewayAuthorizationMixin=types.SimpleNamespace(_intake_adapter_for=lambda source:None)
        prepare=lambda:None;quote=lambda:None
        inbound.GatewayInboundMixin=types.SimpleNamespace(_prepare_inbound_message_text=prepare,
                                                          _prepend_inbound_reply_context=quote)
        sources={prepare:'_expand_inbound_context_references before _prepend_inbound_reply_context',
                 quote:'reply_to_text and reply_to_message_id'}
        scope={'inspect':types.SimpleNamespace(getsource=lambda fn:sources[fn])}
        modules={'hermes_cli':types.ModuleType('hermes_cli'),'gateway':types.ModuleType('gateway'),
                 'gateway.platforms':types.ModuleType('gateway.platforms'),
                 'hermes_cli.plugins':plugins,'gateway.hooks':hooks,'gateway.platforms.event':events,
                 'gateway.run_inbound':inbound,'gateway.authz_mixin':authz}
        with mock.patch.dict(sys.modules,modules):
            exec(code,scope)
            plugins.VALID_HOOKS=set()
            with self.assertRaises(AssertionError):exec(code,scope)
            plugins.VALID_HOOKS={'pre_gateway_dispatch'}
            plugins.PluginContext.on_unload=None
            with self.assertRaises(AssertionError):exec(code,scope)
            plugins.PluginContext.on_unload=lambda:None
            sources[prepare]='_prepend_inbound_reply_context before _expand_inbound_context_references'
            with self.assertRaises(AssertionError):exec(code,scope)
    def test_embedded_programs_compile(self):
        found=0
        for n in ast.walk(tree):
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('code','launcher') for t in n.targets) and isinstance(n.value,ast.Constant):
                ast.parse(n.value.value);found+=1
        self.assertEqual(found,3)
if __name__=='__main__':unittest.main(argv=['siem-pure-fixture'],verbosity=2)
PY
