import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

h=load('runtime_health');d=load('system_diagnostics');d._runtime=h
m=load('soc_monitor');p=load('pipeline_probe')
NOW=1900000000


class RuntimeTests(unittest.TestCase):
    def test_catalog_has_no_arbitrary_paths_and_matches_validator(self):
        self.assertEqual(d.RUNTIME_TARGETS,h.ROLE_TARGETS)
        self.assertEqual(len(d.TARGETS),38)
        self.assertIn('soc:coverage',d.TARGETS)

    def test_missing_configuration_is_not_healthy(self):
        with patch.object(h,'load_config',side_effect=OSError): rows=h.collect('siem',None,NOW)
        self.assertTrue(all(r['status']=='unavailable' for r in rows.values()))
        h.validate(rows,'siem',NOW)

    def test_partial_collector_failure_does_not_hide_other_targets(self):
        def collect(target,*args):
            if target=='b:hermes': raise ValueError('secret must never leave collector')
            return h.observation('runtime',NOW)
        with patch.object(h,'load_config',return_value={}),patch.object(h,'collect_one',side_effect=collect): rows=h.collect('siem',None,NOW)
        self.assertEqual(rows['b:hermes']['status'],'unavailable')
        self.assertEqual(rows['b:ollama']['status'],'ok')
        self.assertNotIn('secret',json.dumps(rows))

    def test_runtime_schema_refuses_unknown_fields_and_free_text(self):
        good={t:h.observation('runtime',NOW) for t in h.ROLE_TARGETS['service']}
        for field,value in [('metrics',{'raw':'token=secret\nraw log'}),('codes',['arbitrary text']),('codes',[{}]),
                            ('observed_at',NOW+6),('status',{}),('metrics',{'n':float('nan')})]:
            with self.subTest(field=field,value=value),self.assertRaises((ValueError,TypeError)):
                rows=copy.deepcopy(good);rows['c:collection'][field]=value;h.validate(rows,'service',NOW)
        with self.assertRaises(ValueError): h.validate({},'service',NOW)

    def test_no_arbitrary_endpoint_credentials_paths_redirects(self):
        for endpoint in ('http://127.0.0.1/admin','http://u:p@10.0.0.1','file:///etc/passwd','http://0.0.0.0','http://224.0.0.1','http://-invalid.example','http://10.0.0.1?q=x'):
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError): h.endpoint(endpoint)
        self.assertEqual(h.endpoint('http://10.0.0.1:11434').port,11434)
        self.assertEqual(h.endpoint('https://dgx.example.org').hostname,'dgx.example.org')

    def test_heartbeat_rejects_previous_process_identity_and_stale(self):
        row={'schema':1,'engine':'ollama','pid':12,'process_start_ticks':300,'checked_at':NOW,'websocket_connected':True,'worker_alive':True}
        with patch.object(h,'read_file',return_value=(json.dumps(row).encode(),NOW)):
            self.assertEqual(h.heartbeat('/fixed',NOW,99,'ollama',12,300)[1],[])
            self.assertIn('chat_heartbeat_stale',h.heartbeat('/fixed',NOW+100,99,'ollama',12,300)[1])
            for pid,start in ((13,300),(12,301)):
                with self.assertRaises(ValueError): h.heartbeat('/fixed',NOW,99,'ollama',pid,start)

    def test_optional_wazuh_process_stopped_does_not_fail_core(self):
        cfg={'layout':'groot'}
        def runner(argv,maximum,seconds):
            if 'inspect' in argv: return 0,json.dumps({'Running':True,'Restarting':False,'OOMKilled':False,'ExitCode':0}).encode()
            if 'status' in argv: return 1,('\n'.join(x+' is running...' for x in h.CORE_WAZUH)+'\nwazuh-maild not running...').encode()
            if 'stat' in argv:return 0,str(NOW).encode()
            if 'analysisd.state' in argv[-1]: return 0,b'events_received=10\nevents_processed=10\nevents_dropped=0\nevent_queue_usage=0.00\n'
            return 0,b'queue_size=0\ntotal_queue_size=131072\ndiscarded_count=0\n'
        self.assertEqual(h.wazuh(cfg,runner,NOW)['status'],'ok')
        def dropping(argv,maximum,seconds):
            code,raw=runner(argv,maximum,seconds);return code,raw.replace(b'events_dropped=0',b'events_dropped=1')
        self.assertIn('loss_counter_nonzero',h.wazuh(cfg,dropping,NOW)['codes'])

    def test_probe_receipt_requires_matching_chain_not_success_boolean_alone(self):
        receipt={'schema':1,'checked_at':NOW,'success':True,'input_at':NOW,'canary_allowed':True}
        with patch.object(h,'read_file',return_value=(json.dumps(receipt).encode(),NOW)),self.assertRaises(ValueError): h.probe_receipt('ingestion',NOW)

    def test_fresh_names_match_installer(self):
        source=(Path(__file__).parents[2]/'deployment/roles/security.sh').read_text()
        for target in ('a:waf','a:suricata'): self.assertIn(h.CONTAINERS['fresh'][target],source)

    def test_agent_observation_needs_no_writable_wazuh_status_command(self):
        commands=[]
        def runner(argv,maximum,seconds):
            commands.append(argv)
            return 0,b'11\n' if argv[-1]=='wazuh-agentd' else b'12\n'
        def executable(path):
            return Path('/var/ossec/bin/wazuh-agentd' if '/11/' in str(path) else '/var/ossec/bin/wazuh-logcollector')
        with patch.object(h,'read_file',return_value=(b"status='connected'\nmsg_buffer='0'\n",NOW)), \
             patch.object(h.pwd,'getpwnam') as user,patch.object(Path,'readlink',autospec=True,side_effect=executable):
            user.return_value.pw_uid=110
            self.assertEqual(h.agent_collection('service',runner,NOW)['status'],'ok')
        self.assertEqual(len(commands),2)
        self.assertTrue(all(c[:2]==['/usr/bin/pgrep','-x'] for c in commands))


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.db=m.database(Path(self.tmp.name)/'state.sqlite3')
    def tearDown(self): self.db.close();self.tmp.cleanup()
    def test_outage_debounce_durable_retry_then_recovery(self):
        m.record(self.db,{'b:snapshot':'unavailable'},NOW)
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],0)
        m.record(self.db,{'b:snapshot':'unavailable'},NOW+60)
        def failing(*args):raise OSError('offline')
        with self.assertRaises(OSError):m.deliver(self.db,'ignored',NOW+60,sender=failing)
        self.assertEqual(self.db.execute('select delivered,attempts from outbox').fetchone(),(None,1))
        m.record(self.db,{'b:snapshot':'ok'},NOW+120)
        sent=[];self.assertEqual(m.deliver(self.db,'ignored',NOW+120,sender=lambda url,body:sent.append(body)),2)
        self.assertIn('복구',sent[0]);self.assertIn('+09:00',sent[0]);self.assertIn('#1',sent[0])
        self.assertEqual(m.deliver(self.db,'ignored',NOW+180,sender=lambda *x:self.fail('duplicate')),0)
        self.assertEqual(self.db.execute('select started from outbox order by id').fetchall(),[(NOW,),(NOW,)])
    def test_steady_failure_does_not_spam_and_pending_does_not_expire(self):
        for offset in range(0,600,60):m.record(self.db,{'b:llm':'degraded'},NOW+offset)
        m.record(self.db,{'b:llm':'degraded'},NOW+100*86400)
        self.assertEqual(self.db.execute('select count(*) from outbox where delivered is null').fetchone()[0],1)
    def test_reopen_keeps_pending_records(self):
        m.record(self.db,{'b:snapshot':'unavailable'},NOW);m.record(self.db,{'b:snapshot':'unavailable'},NOW+60)
        self.db.close();self.db=m.database(Path(self.tmp.name)/'state.sqlite3')
        self.assertEqual(self.db.execute('select count(*) from outbox where delivered is null').fetchone()[0],1)
    def test_optional_ollama_absence_is_not_failure(self):
        m.record(self.db,{'b:ollama':'not_installed'},NOW);m.record(self.db,{'b:ollama':'not_installed'},NOW+60)
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],0)
    def test_bad_webhook_is_rejected_without_network(self):
        for url in ('file:///etc/passwd','http://u:p@host/hooks/'+'x'*26,'https://host/arbitrary','https://host/hooks/'+'a'*26+'?redirect=x'):
            with self.assertRaises(ValueError):m.webhook_send(url,'body')


class PipelineTests(unittest.TestCase):
    def test_rotation_preserves_original_history_and_refuses_unacknowledged(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);state=base/'state';state.mkdir();path=base/'normalized.jsonl'
            path.write_bytes(b'prior-manual-evidence\n');path.chmod(0o600)
            rid='a'*32;receipt={'schema':1,'checked_at':NOW,'success':True,'run_id':rid,'append_end':path.stat().st_size}
            # Root-only file validation is tested on the Linux stage; use
            # bounded fixture reads for this portable rotation behavior test.
            with patch.object(p,'STATE',state),patch.object(d,'root_file',side_effect=lambda path,*a:Path(path).read_bytes()),patch.object(p.os,'fstat',wraps=p.os.fstat),patch.object(p.os,'geteuid',return_value=0):
                real_lstat=Path.lstat
                def metadata(obj):
                    value=real_lstat(obj)
                    if obj.name=='archive':
                        from types import SimpleNamespace
                        return SimpleNamespace(st_mode=value.st_mode,st_uid=0)
                    return value
                with patch.object(Path,'lstat',autospec=True,side_effect=metadata):
                    with self.assertRaises(ValueError):p.rotate(d,m.atomic,NOW,receipt,'b'*32,path)
                    self.assertEqual(path.read_bytes(),b'prior-manual-evidence\n')
                    p.rotate(d,m.atomic,NOW,receipt,rid,path)
                    self.assertEqual(path.read_bytes(),b'')
                    archived=list((base/'archive').iterdir());self.assertEqual(len(archived),1)
                    self.assertEqual(archived[0].read_bytes(),b'prior-manual-evidence\n')
                    self.assertTrue(archived[0].name.startswith('initial-'))
                    self.assertEqual(json.loads((state/'canary-input.json').read_text())['append_end'],0)

    def test_unexpected_append_refuses_new_canary(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);path=base/'normalized.jsonl';path.write_bytes(b'external append');path.chmod(0o600)
            (base/'canary-input.json').write_text(json.dumps({'checked_at':NOW-901,'success':True,'append_end':0}))
            with patch.object(p,'STATE',base),patch.object(d,'root_file',side_effect=lambda path,*a:Path(path).read_bytes()),patch.object(h,'read_file',return_value=(b'',NOW)):
                with self.assertRaisesRegex(ValueError,'canary_unowned_append'):p._write_canary(d,m.atomic,NOW,None,path)
            self.assertEqual(path.read_bytes(),b'external append')

    def test_rule_source_pin_matches_repo(self):
        import hashlib
        path=Path(__file__).parents[1]/'normalization/wazuh-vector/capstone_vector_rules.xml'
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),p.RULE_SHA256)
    def test_response_that_can_match_canary_is_refused(self):
        import hashlib
        raw=(Path(__file__).parents[1]/'normalization/wazuh-vector/capstone_vector_rules.xml').read_text()
        for response,allowed in [('<rules_id>100110</rules_id>',True),('<level>5</level>',True),
                                 ('<rules_id>100293</rules_id>',False),('<level>3</level>',False),('',False),
                                 ('<rules_id>100110</rules_id><level>3</level>',False)]:
            with self.subTest(response=response),patch.object(h,'command',side_effect=[raw,'<ossec_config><active-response>'+response+'</active-response></ossec_config>']):
                if allowed:self.assertTrue(p.safe_manager(d,{'layout':'groot'}))
                else:
                    with self.assertRaises(ValueError):p.safe_manager(d,{'layout':'groot'})


if __name__=='__main__':unittest.main()
