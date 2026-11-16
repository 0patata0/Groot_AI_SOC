"""Native action scope and state checks with no operating commands executed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('release_services_tested',Path(__file__).with_name('release_services.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)


class Backend:
    def __init__(self,host='b'):
        self.calls=[];self.rows={};self.skip_collection=False;self.refuse_stop=False;self.fail=False
        for names in m.catalog(host).values():
            for name in names:
                active=name.endswith('.timer')or name in ('capstone-journal-reader.service','capstone-ollama-chat.service','capstone-review-chat.service')
                self.rows[name]={'Id':name,'LoadState':'loaded','UnitFileState':'enabled'if active else 'static',
                  'ActiveState':'active'if active else 'inactive','SubState':'running'if active else 'dead',
                  'MainPID':'42'if active and name.endswith('.service')else '0','FragmentPath':'/etc/systemd/system/'+name,
                  'Result':'success','Type':'oneshot'if not active else 'simple','KillMode':'control-group',
                  'ConditionResult':'yes','ExecMainStartTimestampMonotonic':'100','ExecMainStatus':'0'}
                self.rows[name].update(MemoryHigh=str(192*1024*1024),MemoryMax=str(256*1024*1024),MemorySwapMax='0',
                    MemoryAccounting='yes',TasksAccounting='yes',TasksMax='64',LimitNOFILE='1024',TimeoutStopUSec='5s',
                    TimeoutStartUSec='2min 30s'if name==m.OPTIONAL else '1min 25s',NeedDaemonReload='no',DropInPaths='',User='root')
                if name=='capstone-journal-reader.service':self.rows[name].update(MemoryMax=str(128*1024*1024),TasksMax='8',TimeoutStopUSec='10s')
                if name in m.COLLECTION_SERVICES:self.rows[name]['DropInPaths']=' '.join(sorted(m.existing_dropins(name)|{m.release_dropin(name)}))
        self.container={'id':'a'*64,'image':'sha256:'+'b'*64,'running':True,'paused':False,'dead':False,'restarting':False,'pid':100,
                        'restart':{'Name':'unless-stopped','MaximumRetryCount':0}}

    def __call__(self,args,*,timeout):
        self.calls.append((list(args),timeout));out=b''
        if self.fail:return subprocess.CompletedProcess(args,1,b'',b'not returned to caller')
        if args[0]=='/usr/bin/systemctl':
            if args[1]=='show':out='\n'.join(k+'='+v for k,v in self.rows[args[2]].items()).encode()
            elif args[1]=='stop'and not self.refuse_stop:self.rows[args[-1]].update(ActiveState='inactive',MainPID='0',SubState='dead')
            elif args[1]=='start':
                row=self.rows[args[-1]]
                if args[-1]in ('capstone-system-diagnostics.service',m.OPTIONAL):
                    if not self.skip_collection:row.update(ExecMainStartTimestampMonotonic=str(int(row['ExecMainStartTimestampMonotonic'])+1),ConditionResult='yes')
                    else:row['ConditionResult']='no'
                else:row.update(ActiveState='active',MainPID='123'if args[-1].endswith('.service')else '0',
                    ExecMainStartTimestampMonotonic=str(int(row['ExecMainStartTimestampMonotonic'])+1))
        elif args[1]=='inspect':out=json.dumps(self.container).encode()
        elif args[1]=='update':self.container['restart']['Name']=args[2].split('=',1)[1]
        elif args[1]=='stop':self.container.update(running=False,pid=0)
        elif args[1]=='start':self.container.update(running=True,pid=101)
        return subprocess.CompletedProcess(args,0,out,b'')


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='release-native-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.backend=Backend();self.plan={k:copy.deepcopy(self.backend.container[k])for k in ('id','image','running')};self.plan['restart']='unless-stopped'
        self.native=m.Native('b',self.plan,filesystem_root=self.root,runner=self.backend)

    def test_fixture_cannot_fall_through_to_native_commands(self):
        with self.assertRaisesRegex(m.Refused,'native_execution_boundary'):m.Native('b',self.plan,filesystem_root=self.root)
        with patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaisesRegex(m.Refused,'native_execution_boundary'):m.Native('b',self.plan,runner=self.backend)

    def test_native_environment_cannot_redirect_docker_or_system_manager(self):
        with patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0),patch.dict(m.os.environ,{'DOCKER_HOST':'tcp://unapproved:1234','SYSTEMD_BUS_ADDRESS':'unapproved'}):
            native=m.Native('b',self.plan)
            with patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b''))as run:
                native.run(['/usr/bin/systemctl','daemon-reload'])
                self.assertEqual(run.call_args.kwargs['env'],m.ENV)
                self.assertNotIn('SYSTEMD_BUS_ADDRESS',run.call_args.kwargs['env'])

    def test_catalog_includes_direct_import_monitors_and_excludes_security_engines(self):
        self.assertIn('capstone-soc-observe.service',m.catalog('a')['consumer_services'])
        self.assertIn('capstone-soc-model.timer',m.catalog('b')['consumer_timers'])
        self.assertIn('capstone-soc-ingestion.service',m.catalog('b')['consumer_services'])
        for key in ('docker.service','sshd.service','capstone-vector.service','capstone-block-reaper.timer','capstone-storage-monitor.service'):
            self.assertNotIn(key,self.native.units)

    def test_stop_timers_before_services_and_verify_quiescence(self):
        self.native.stop('consumer');self.assertTrue(self.native.stopped('consumer'))
        names=[args[-1]for args,_ in self.backend.calls if args[1]=='stop'];first_service=next((i for i,n in enumerate(names)if n.endswith('.service')),len(names))
        self.assertTrue(all(n.endswith('.timer')for n in names[:first_service]));self.assertTrue(all(n.endswith('.service')for n in names[first_service:]))

    def test_optional_absent_backfill_is_skipped(self):
        self.backend.rows[m.OPTIONAL].update(LoadState='not-found',ActiveState='inactive',MainPID='0');self.native.stop('collection')
        self.assertFalse(any(args[1]=='stop'and args[-1]==m.OPTIONAL for args,_ in self.backend.calls))

    def test_unexpected_missing_required_unit_is_refused(self):
        self.backend.rows['capstone-management.service']['LoadState']='not-found'
        with self.assertRaisesRegex(m.Refused,'required_unit_missing'):self.native.probe('capstone-management.service')

    def test_live_pid_is_not_treated_as_quiesced(self):
        self.native.stop('consumer');self.backend.rows['capstone-review-chat.service']['MainPID']='123'
        self.assertFalse(self.native.stopped('consumer'))

    def test_stop_timeout_does_not_claim_success(self):
        with patch.object(self.native,'stopped',return_value=False),patch.object(m.time,'monotonic',side_effect=[0,2]):
            with self.assertRaisesRegex(m.Refused,'services_not_quiesced'):self.native.wait_stopped('collection',timeout=1)

    def test_snapshot_restores_only_original_active_units(self):
        before=self.native.snapshot();self.native.stop('consumer');self.backend.calls=[];self.native.resume_original('consumer',before)
        started=[args[-1]for args,_ in self.backend.calls if args[1]=='start']
        expected=[n for n in (*m.B_SERVICES,*m.B_TIMERS)if before[n]['ActiveState']=='active'];self.assertEqual(started,expected)

    def test_forged_baseline_unit_set_cannot_expand_actions(self):
        before=self.native.snapshot();before['sshd.service']={'ActiveState':'active'}
        with self.assertRaisesRegex(m.Refused,'baseline_unit_set'):self.native.resume_original('consumer',before)

    def test_entire_resume_baseline_is_checked_before_any_start(self):
        before=self.native.snapshot();self.native.stop('consumer');before[m.B_TIMERS[-1]]['Id']='sshd.service';self.backend.calls=[]
        with self.assertRaisesRegex(m.Refused,'baseline_unit_identity'):self.native.resume_original('consumer',before)
        self.assertFalse(any(args[1]=='start'for args,_ in self.backend.calls))

    def test_collection_must_execute_instead_of_condition_skip(self):
        self.native.stop('collection')
        self.native.bootstrap_collection(backfill=True)
        actions=[args[-1]for args,_ in self.backend.calls if args[1]=='start'];self.assertEqual(actions,['capstone-journal-reader.service','capstone-system-diagnostics.service',m.OPTIONAL])
        self.backend.skip_collection=True
        self.native.stop('collection')
        with self.assertRaisesRegex(m.Refused,'collection_did_not_execute'):self.native.bootstrap_collection()

    def test_resource_mismatch_blocks_publishers_before_the_first_start(self):
        self.native.stop('collection');self.backend.calls=[];self.backend.rows[m.OPTIONAL]['MemoryMax']='infinity'
        with self.assertRaisesRegex(m.Refused,'collection_resource_mismatch'):self.native.bootstrap_collection()
        self.assertFalse(any(args[1]=='start'for args,_ in self.backend.calls))

    def test_already_running_reader_cannot_be_adopted_as_restarted(self):
        with self.assertRaisesRegex(m.Refused,'reader_must_be_stopped'):self.native.bootstrap_collection()

    def test_container_boot_fence_stop_and_original_resume(self):
        self.native.stop_container();self.assertEqual(self.backend.container['restart']['Name'],'no');self.assertFalse(self.backend.container['running'])
        self.native.resume_container();self.assertTrue(self.backend.container['running']);self.assertEqual(self.backend.container['restart']['Name'],'unless-stopped')
        self.assertTrue(all(args[-1]==self.plan['id']for args,_ in self.backend.calls if args[0]=='/usr/local/bin/docker'))

    def test_idempotent_stop_resume_does_not_duplicate_mutation(self):
        self.native.stop_container();self.backend.calls=[];self.native.stop_container();self.assertFalse(any(a[1]in ('update','stop')for a,_ in self.backend.calls))
        self.native.resume_container();self.backend.calls=[];self.native.resume_container();self.assertFalse(any(a[1]in ('update','start')for a,_ in self.backend.calls))

    def test_foreign_container_or_policy_prevents_changes(self):
        for key,value in (('id','c'*64),('image','sha256:'+'c'*64),('restart',{'Name':'always','MaximumRetryCount':0})):
            with self.subTest(key=key):
                original=copy.deepcopy(self.backend.container);self.backend.container[key]=value
                with self.assertRaises(m.Refused):self.native.stop_container()
                self.backend.container=original

    def test_stopped_original_container_cannot_be_adopted_as_running_baseline(self):
        self.backend.container.update(running=False,pid=0)
        with self.assertRaisesRegex(m.Refused,'container_baseline_changed'):self.native.require_original_container()

    def test_restarting_paused_dead_or_bad_pid_is_not_stable(self):
        for key,value in (('restarting',True),('paused',True),('dead',True),('pid',True)):
            original=copy.deepcopy(self.backend.container);self.backend.container[key]=value
            with self.assertRaises(m.Refused):self.native.docker()
            self.backend.container=original

    def test_arbitrary_program_unit_container_or_inspection_is_rejected(self):
        commands=[['/bin/sh','-c','anything'],['/usr/bin/systemctl','start','sshd.service'],
          ['/usr/local/bin/docker','rm','-f',self.plan['id']],['/usr/local/bin/docker','start','c'*64],
          ['/usr/local/bin/docker','inspect','--format','{{json .Config.Env}}',self.plan['id']]]
        for args in commands:
            with self.subTest(args=args):
                with self.assertRaisesRegex(m.Refused,'native_command_scope'):self.native.run(args)

    def test_nonzero_command_does_not_echo_raw_error(self):
        self.backend.fail=True
        with self.assertRaisesRegex(m.Refused,'^native_command_failed$'):self.native.snapshot()

    def test_other_hosts_cannot_control_container(self):
        backend=Backend('a');native=m.Native('a',None,filesystem_root=self.root,runner=backend)
        with self.assertRaisesRegex(m.Refused,'container_host_scope'):native.stop_container()
        with self.assertRaisesRegex(m.Refused,'service_target'):native.probe('capstone-review-chat.service')


if __name__=='__main__':unittest.main()
