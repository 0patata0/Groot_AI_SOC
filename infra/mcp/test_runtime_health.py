import copy
import importlib.util
import json
import os
import io
import contextlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace


def load(name):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

h=load('runtime_health');d=load('system_diagnostics');d._runtime=h
m=load('soc_monitor');p=load('pipeline_probe')
NOW=1900000000


class RuntimeTests(unittest.TestCase):
    def test_live_target_clock_accepts_new_heartbeat_after_slow_prior_checks(self):
        value={'pid':44,'process_start_ticks':55,'at':NOW+12,'last_poll':NOW+11,
               'pending':1,'oldest_pending_at':NOW+10}
        def one(target,cfg,runner,at):
            if target=='b:management-pipeline':
                metrics,codes=h.review_chat(at,runner)
                return h.observation('management_pipeline',at,metrics,codes)
            return h.observation('runtime',at)
        with patch.object(h,'read_file',return_value=(json.dumps(value).encode(),NOW+12)), \
             patch.object(h,'command',return_value='44'),patch.object(h,'process_start',return_value=55), \
             patch.object(h,'load_config',return_value={}),patch.object(h,'collect_one',side_effect=one):
            # Reproduce the old batch-start comparison without sleeping.
            with self.assertRaises(ValueError):h.review_chat(NOW,None)
            rows=h.collect('siem',None,NOW,clock=lambda:NOW+12)
            row=rows['b:management-pipeline']
            self.assertEqual(row['codes'],[])
            self.assertEqual(row['observed_at'],NOW+12)
            self.assertEqual(row['metrics']['review_chat_poll_age_seconds'],1)
            self.assertEqual(row['metrics']['review_chat_pending_jobs'],1)

    def test_review_channel_health_binds_running_process_and_pending_age(self):
        value={'pid':44,'process_start_ticks':55,'at':NOW,'last_poll':NOW,'pending':1,'oldest_pending_at':NOW-10}
        with patch.object(h,'read_file',return_value=(json.dumps(value).encode(),NOW)), \
             patch.object(h,'command',return_value='44'),patch.object(h,'process_start',return_value=55):
            metrics,codes=h.review_chat(NOW,None)
            self.assertEqual(codes,[]);self.assertEqual(metrics['review_chat_pending_jobs'],1)
            self.assertIn('chat_heartbeat_stale',h.review_chat(NOW+31,None)[1])
            self.assertIn('job_stalled',h.review_chat(NOW+1800,None)[1])
        with patch.object(h,'read_file',return_value=(json.dumps(value).encode(),NOW)), \
             patch.object(h,'command',return_value='45'),patch.object(h,'process_start',return_value=55),self.assertRaises(ValueError):
            h.review_chat(NOW,None)

    def test_catalog_has_no_arbitrary_paths_and_matches_validator(self):
        self.assertEqual(d.RUNTIME_TARGETS,h.ROLE_TARGETS)
        self.assertEqual(len(d.TARGETS),42)
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
        with patch.object(h,'read_file',return_value=(b"status='connected'\nmsg_buffer='0'\n",NOW)), \
             patch.object(h.pwd,'getpwnam') as user,patch.object(h,'host_executable',return_value=True):
            user.return_value.pw_uid=110
            self.assertEqual(h.agent_collection('service',runner,NOW)['status'],'ok')
        self.assertEqual(len(commands),2)
        self.assertTrue(all(c[:2]==['/usr/bin/pgrep','-x'] for c in commands))

    def test_b_host_and_container_process_names_do_not_collide(self):
        def runner(*args): return 0,b'11\n12\n'
        with patch.object(h,'read_file',return_value=(b"status='connected'\n",NOW)), \
             patch.object(h.pwd,'getpwnam') as user, \
             patch.object(h,'host_executable',side_effect=lambda pid,name:pid==12):
            user.return_value.pw_uid=110
            self.assertEqual(h.collect_one('b:collection',{'role':'siem'},runner,NOW)['status'],'ok')
        with patch.object(h,'read_file',return_value=(b"status='disconnected'\n",NOW-181)), \
             patch.object(h.pwd,'getpwnam') as user,patch.object(h,'host_executable',return_value=False):
            user.return_value.pw_uid=110
            result=h.agent_collection('siem',runner,NOW)
            for code in ('process_missing','agent_disconnected','stats_stale'):self.assertIn(code,result['codes'])

    def test_same_path_in_container_is_not_host_executable(self):
        from types import SimpleNamespace
        with patch.object(Path,'stat',side_effect=[SimpleNamespace(st_dev=1,st_ino=2),SimpleNamespace(st_dev=3,st_ino=2)]):
            self.assertFalse(h.host_executable(11,'wazuh-logcollector'))


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

    def test_cached_failure_is_not_two_trials_and_recovery_needs_two_new_successes(self):
        def put(status,rid,offset):
            m.record(self.db,{'b:llm':status},NOW+offset,{'b:llm':rid*32},
                     {'b:llm':'request_timeout' if status=='degraded' else 'response_ok'})
        for t in (0,60,120):put('degraded','a',t)
        self.assertEqual(self.db.execute('select streak from health').fetchone()[0],1)
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],0)
        put('degraded','b',180)
        self.assertEqual(self.db.execute('select reason,started from outbox').fetchone(),('request_timeout',NOW))
        put('ok','c',360);put('ok','c',420)
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],1)
        # Reopen retains identity, episode start and pending notifications.
        self.db.close();self.db=m.database(Path(self.tmp.name)/'state.sqlite3')
        put('ok','c',480);put('ok','d',540)
        self.assertEqual(self.db.execute('select status,started,reason from outbox order by id').fetchall(),
            [('degraded',NOW,'request_timeout'),('ok',NOW,'independent_probe_recovery')])
        sent=[];m.deliver(self.db,'ignored',NOW+540,sender=lambda u,b:sent.append(b))
        self.assertIn('35초',sent[0]);self.assertIn('서버 중단 여부 미확정',sent[0]);self.assertIn('2회 성공',sent[0])

    def test_one_failed_trial_followed_by_success_is_preserved_as_observation_not_false_outage(self):
        m.record(self.db,{'b:llm':'degraded'},NOW,{'b:llm':'a'*32})
        m.record(self.db,{'b:llm':'degraded'},NOW+60,{'b:llm':'a'*32})
        m.record(self.db,{'b:llm':'ok'},NOW+180,{'b:llm':'b'*32})
        self.assertEqual(self.db.execute('select status,streak,announced from health').fetchone(),('ok',1,'ok'))
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],0)

    def test_legacy_streak_does_not_count_as_a_new_independent_probe(self):
        m.record(self.db,{'b:llm':'degraded'},NOW)
        m.record(self.db,{'b:llm':'degraded'},NOW+60,{'b:llm':'a'*32})
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],0)
        m.record(self.db,{'b:llm':'degraded'},NOW+180,{'b:llm':'b'*32})
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],1)

    def test_rollback_closed_episode_is_not_reused(self):
        self.db.execute("insert into health values('b:llm','ok',?,4,'ok')",(NOW,))
        self.db.execute("insert into episodes values('b:llm',?)",(NOW-1000,));self.db.commit()
        for t,rid in [(0,'a'),(180,'b')]:m.record(self.db,{'b:llm':'degraded'},NOW+t,{'b:llm':rid*32})
        for t,rid in [(360,'c'),(540,'d')]:m.record(self.db,{'b:llm':'ok'},NOW+t,{'b:llm':rid*32})
        self.assertEqual(self.db.execute('select started from outbox order by id').fetchall(),[(NOW,),(NOW,)])

    def test_stopped_probe_and_transport_failure_keep_live_observer_detection(self):
        snap={'b':{'runtime':{'b:llm':{'status':'degraded','codes':['pipeline_probe_stale'],
             'metrics':{'probe_run_id':'a'*32,'probe_result_reason':'response_ok'}}}}}
        self.assertEqual(m.probe_samples(snap),({},{}))
        for t in (0,60):m.record(self.db,{'b:llm':'degraded'},NOW+t,*m.probe_samples(snap))
        self.assertEqual(self.db.execute('select count(*) from outbox').fetchone()[0],1)
        snap['b']['runtime']['b:llm'].update(status='unavailable',codes=['runtime_collection_failed'])
        self.assertEqual(m.probe_samples(snap),({},{}))

    def test_probe_metadata_is_used_only_for_actual_model_results(self):
        row={'status':'degraded','codes':['model_request_failed'],
             'metrics':{'probe_run_id':'a'*32,'probe_result_reason':'request_timeout'}}
        self.assertEqual(m.probe_samples({'b':{'runtime':{'b:llm':row}}}),
                         ({'b:llm':'a'*32},{'b:llm':'request_timeout'}))
        row['metrics']['probe_run_id']='not-an-id'
        self.assertEqual(m.probe_samples({'b':{'runtime':{'b:llm':row}}}),({},{}))

    def test_additive_database_migration_preserves_old_pending_event(self):
        import sqlite3
        path=Path(self.tmp.name)/'legacy.sqlite3';db=sqlite3.connect(path)
        db.execute('create table outbox (id integer primary key autoincrement,target text,status text,started integer,observed integer,delivered integer,attempts integer not null default 0)')
        db.execute("insert into outbox values(9,'b:snapshot','unavailable',?,?,null,3)",(NOW,NOW));db.commit();db.close();path.chmod(0o600)
        db=m.database(path)
        self.assertEqual(db.execute('select id,attempts,reason from outbox').fetchone(),(9,3,None))
        sent=[];self.assertEqual(m.deliver(db,'ignored',NOW+60,sender=lambda u,b:sent.append(b)),1)
        self.assertIn('#9',sent[0]);db.close()


class ProbeDiagnosticsTests(unittest.TestCase):
    def test_distinct_trials_preserve_sanitized_failure_after_success_and_log_each_trial(self):
        with tempfile.TemporaryDirectory() as root:
            cfg={'llm_url':'http://127.0.0.1:11435','model':'test:35b'}
            health=SimpleNamespace(load_config=lambda role:cfg,request_json=Mock(side_effect=TimeoutError('private url token')))
            core=SimpleNamespace(runtime_library=lambda:health,root_file=lambda p,*a:p.read_bytes(),parsed=json.loads)
            path=Path(root)/'model-probe.json';log=io.StringIO()
            with patch.object(m,'STATE',Path(root)),patch.object(m.time,'time',return_value=NOW),contextlib.redirect_stdout(log):m.model_probe(core)
            failure=json.loads(path.read_text());self.assertFalse(failure['success']);self.assertEqual(failure['reason'],'request_timeout')
            health.request_json.side_effect=None;health.request_json.return_value={'done':True,'model':cfg['model'],'response':'OK'}
            with patch.object(m,'STATE',Path(root)),patch.object(m.time,'time',return_value=NOW+181),contextlib.redirect_stdout(log):m.model_probe(core)
            success=json.loads(path.read_text());self.assertTrue(success['success']);self.assertNotEqual(failure['run_id'],success['run_id'])
            self.assertEqual(success['last_failure'],failure['last_failure']);self.assertNotIn('private',path.read_text()+log.getvalue())
            self.assertEqual(len(log.getvalue().splitlines()),2)
            with patch.object(h,'read_file',return_value=(path.read_bytes(),NOW+181)):
                row=h.probe_receipt('model',NOW+181)
            self.assertEqual(row['status'],'ok');self.assertEqual(row['metrics']['last_probe_failure_reason'],'request_timeout')

    def test_network_http_protocol_and_invalid_result_are_distinct_and_redacted(self):
        import http.client
        for effect,reason in [(ConnectionRefusedError('private'),'connection_failure'),
                (OSError('private'),'network_failure'),(h.RuntimeHTTPError(503),'http_failure'),
                (http.client.BadStatusLine('private'),'protocol_failure'),(ValueError('private'),'invalid_response')]:
            with self.subTest(reason=reason),tempfile.TemporaryDirectory() as root:
                health=SimpleNamespace(load_config=lambda _: {'llm_url':'http://127.0.0.1:11435','model':'test'},request_json=Mock(side_effect=effect))
                core=SimpleNamespace(runtime_library=lambda:health)
                with patch.object(m,'STATE',Path(root)),contextlib.redirect_stdout(io.StringIO()):m.model_probe(core)
                text=(Path(root)/'model-probe.json').read_text();v=json.loads(text)
                self.assertEqual(v['reason'],reason);self.assertNotIn('private',text)
                if reason=='http_failure':self.assertEqual(v['http_status'],503)

    def test_legacy_receipt_identity_is_stable_and_stale_receipt_is_not_recovery(self):
        receipt={'schema':1,'checked_at':NOW,'success':True,'backend_sha256':'b'*64,'elapsed_ms':20}
        with patch.object(h,'read_file',return_value=(json.dumps(receipt).encode(),NOW)):
            first=h.probe_receipt('model',NOW);second=h.probe_receipt('model',NOW+60)
            self.assertEqual(first['metrics']['probe_run_id'],second['metrics']['probe_run_id'])
            self.assertIn('pipeline_probe_stale',h.probe_receipt('model',NOW+601)['codes'])


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
