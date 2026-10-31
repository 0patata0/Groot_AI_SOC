import copy
import io
import json
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_service_action_executor as fixtures

s=fixtures.service


class SystemdApproval(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.now=time.time();self.broker=fixtures.BrokerAdapter()
        self.engine=fixtures.helper.Engine('a',self.broker,Path(self.tmp.name).resolve(),clock=lambda:self.now)
        self.backend=fixtures.FakeBackend(self.now)
        self.backend.observation={'runtime_kind':'systemd','unit':'capstone-vector.service','boot_id':'b'*36,
            'active_state':'failed','sub_state':'failed','result':'exit-code','running':False,
            'invocation_id':'a'*32,'main_pid':0,'start_monotonic_us':100,
            'config_sha256':'c'*64,'files_sha256':'d'*64}
        self.svc=s.ServiceActionService(self.engine,backend=self.backend)
        self.backend.service=self.svc

    def propose(self):
        obs=self.svc.get_target('a:vector')
        self.assertFalse(obs['observation']['running'])
        self.assertEqual(obs['allowed_actions'],['restart'])
        return self.svc.propose('a:vector','restart',obs['base_state_sha256'],'Diagnosed unit failure')

    def test_no_approval_no_execution_and_approved_exactly_once(self):
        row=self.propose();self.svc.worker_once();self.assertEqual(self.backend.actions,[])
        self.assertIn('systemd unit',str(self.broker.cards))
        self.broker.decide(row['request_id']);self.svc.worker_once();self.svc.worker_once()
        self.assertEqual(self.backend.actions,[('a:vector','restart')]);self.assertEqual(self.broker.consumes,1)

    def test_denied_and_expired_never_dispatch(self):
        row=self.propose();self.broker.decide(row['request_id'],'deny');self.svc.worker_once()
        self.assertEqual(self.backend.actions,[])
        other=self.propose();self.now+=601;self.svc.worker_once()
        self.assertEqual(self.backend.actions,[])

    def test_state_change_aborts_before_consumption(self):
        row=self.propose();self.broker.decide(row['request_id'])
        self.backend.observation['files_sha256']='f'*64;self.svc.worker_once()
        self.assertEqual(self.backend.actions,[]);self.assertEqual(self.broker.consumes,0)

    def test_wrong_host_unknown_unit_and_unsupported_action(self):
        for target in ('b:wazuh-agent','c:wazuh-agent','a:ssh','a:docker','../../etc/passwd'):
            with self.assertRaises(fixtures.helper.RuleChangeError):self.svc.get_target(target)
        with self.assertRaises(fixtures.helper.RuleChangeError):
            self.svc.propose('a:vector','reload','a'*64,'not allowed')
        self.assertEqual(self.backend.actions,[])

    def test_preflight_failure_does_not_post_or_consume(self):
        self.backend.fail_preflight=True
        with self.assertRaises(fixtures.helper.RuleChangeError):self.propose()
        self.assertEqual(self.broker.cards,[]);self.assertEqual(self.broker.consumes,0)


class SystemdBackend(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.props={'Id':'capstone-vector.service','LoadState':'loaded','ActiveState':'failed',
            'SubState':'failed','Result':'exit-code','Type':'simple','InvocationID':'a'*32,
            'MainPID':'0','ExecMainStartTimestampMonotonic':'10',
            'FragmentPath':'/etc/systemd/system/capstone-vector.service','DropInPaths':'',
            'NeedDaemonReload':'no','Transient':'no',
            'TimeoutStartUSec':'3min','TimeoutStopUSec':'1min','KillMode':'control-group','Restart':'on-failure'}
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.engine=fixtures.helper.Engine('a',fixtures.BrokerAdapter(),Path(self.tmp.name).resolve(),
            runner=SimpleNamespace(call=self.call))
        self.backend=s.ServiceBackend(self.engine)
        self.meta=SimpleNamespace(st_uid=0,st_mode=0o100640)

    def call(self,argv,timeout=30):
        self.calls.append(argv)
        return ('\n'.join(k+'='+v for k,v in self.props.items())+'\n').encode()

    def observation(self):
        with patch.object(fixtures.helper,'_read_regular',return_value=(b'fixed',self.meta)), \
             patch.object(s.Path,'read_text',return_value='0'*8+'-'+'1'*4+'-'+'2'*4+'-'+'3'*4+'-'+'4'*12):
            return self.backend.observe('a:vector')

    def test_failed_unit_observable_and_sensitive_config_only_hashed(self):
        value=self.observation()
        self.assertEqual(value['active_state'],'failed');self.assertFalse(value['running'])
        self.assertNotIn('SENSITIVE',str(value))
        self.assertEqual(self.calls[0][-1],'capstone-vector.service')
        self.assertNotIn('restart',str(self.calls))

    def test_unit_definition_and_runtime_changes_invalidate_snapshot(self):
        first=self.observation();self.props['TimeoutStartUSec']='4min'
        self.assertNotEqual(first['config_sha256'],self.observation()['config_sha256'])
        self.props['InvocationID']='f'*32
        self.assertNotEqual(first['invocation_id'],self.observation()['invocation_id'])

    def test_reload_transient_missing_and_path_injection_refused(self):
        for key,value in (('NeedDaemonReload','yes'),('Transient','yes'),('LoadState','not-found'),
                          ('ActiveState','activating'),('FragmentPath','/tmp/host.service'),
                          ('DropInPaths','/etc/systemd/system/x.conf /tmp/evil'),('Id','ssh.service')):
            old=self.props[key];self.props[key]=value
            with self.subTest(key=key),self.assertRaises(fixtures.helper.RuleChangeError):self.observation()
            self.props[key]=old

    def test_untrusted_unit_mode_refused(self):
        self.meta.st_mode=0o100664
        with self.assertRaises(fixtures.helper.RuleChangeError):self.observation()

    def test_restart_argv_fixed_and_no_reload_fallback(self):
        self.backend.dispatch('a:vector','restart',{})
        self.assertEqual(self.calls,[['/usr/bin/systemctl','--no-block','restart','capstone-vector.service']])
        with self.assertRaises(fixtures.helper.RuleChangeError):self.backend.dispatch('a:vector','reload',{})
        self.assertEqual(len(self.calls),1)

    def test_preflight_only_fixed_path_variables_no_shell_source(self):
        env=b'SURICATA_EVE_PATH=/logs/eve.json\nWAF_AUDIT_PATH=/logs/audit.json\nWAF_ACCESS_PATH=/logs/access.log\nTOKEN=hidden\n'
        with patch.object(fixtures.helper,'_read_regular',return_value=(env,self.meta)):
            self.backend.preflight_systemd('a:vector')
        self.assertNotIn('hidden',str(self.calls));self.assertNotIn('sh',self.calls[0])
        self.assertIn('--no-environment',self.calls[0])
        with patch.object(fixtures.helper,'_read_regular',return_value=(env.replace(b'/logs/eve.json',b'$(touch /tmp/x)'),self.meta)),self.assertRaises(fixtures.helper.RuleChangeError):
            self.backend.preflight_systemd('a:vector')

    def test_agent_preflight_is_fixed_configuration_checks(self):
        self.backend.preflight_systemd('b:wazuh-agent')
        self.assertEqual(len(self.calls),4)
        self.assertTrue(all(c[0].startswith('/var/ossec/bin/') and c[1:]==['-t'] for c in self.calls))

    def test_old_invocation_or_changed_config_cannot_verify_restart(self):
        before=self.observation()
        for after in (before,dict(before,running=True),dict(before,running=True,invocation_id='f'*32,files_sha256='a'*64)):
            with patch.object(self.backend,'observe_systemd',return_value=after),self.assertRaises(fixtures.helper.RuleChangeError):
                self.backend.verify_systemd('a:vector',before)

    def test_vector_verification_requires_fresh_matching_invocation_telemetry(self):
        before=self.observation()
        after=dict(before,running=True,result='success',invocation_id='f'*32,main_pid=123)
        now=self.engine.clock()
        def resolved(path):
            return Path('/usr/local/bin/vector')
        for age,invocation,ok in ((1,'f'*32,True),(90,'f'*32,False),(1,'e'*32,False)):
            payload=json.dumps({'capstone_collection_health':{'metric':'uptime_seconds',
                'vector_pid':123,'invocation_id':invocation,'observed_unix':now-age}}).encode()+b'\n'
            stream=io.BytesIO(payload);stream.fileno=lambda:123
            meta=SimpleNamespace(st_uid=0,st_mode=0o100640,st_nlink=1,st_size=len(payload))
            with patch.object(self.backend,'observe_systemd',return_value=after), \
                 patch.object(s.Path,'resolve',resolved),patch.object(s.os,'open',return_value=123) as opened, \
                 patch.object(s.os,'fdopen',return_value=stream),patch.object(s.os,'fstat',return_value=meta):
                if ok:self.assertEqual(self.backend.verify_systemd('a:vector',before),after)
                else:
                    with self.assertRaises(fixtures.helper.RuleChangeError):self.backend.verify_systemd('a:vector',before)
                self.assertTrue(opened.call_args.args[1] & s.os.O_NOFOLLOW)


if __name__=='__main__':unittest.main()
