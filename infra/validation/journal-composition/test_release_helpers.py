"""Fixed helper start, actual-load evidence and cleanup refusal boundaries."""
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('release_helpers_tested','release_helpers.py')
source=load('release_helpers_fixture','test_release_files.py')


class Backend:
    def __init__(self):
        self.rows={};self.calls=[];self.skip_enable=False
        names={m.controls.STATUS,m.controls.WATCH,m.controls.TIMER}|{m.Manager.instance(n)for n in m.OPERATIONS}
        for name in names:
            fragment=m.controls.RUNNER if '@'in name else name
            self.rows[name]={'Id':name,'LoadState':'loaded','UnitFileState':'disabled','ActiveState':'inactive','MainPID':'0',
                'FragmentPath':str(m.controls.UNIT_DIR/fragment),'DropInPaths':'','NeedDaemonReload':'no',
                'Type':'simple'if name==m.controls.STATUS else 'oneshot','NextElapseUSecMonotonic':'0',
                'MemoryHigh':str(192*1024*1024),'MemoryMax':str(256*1024*1024),'MemorySwapMax':'0',
                'TasksMax':'64','LimitNOFILE':'1024','TimeoutStartUSec':'5min 30s'}

    def __call__(self,args,*,timeout):
        self.calls.append((list(args),timeout));out=b''
        if args[1]=='show':out='\n'.join(k+'='+v for k,v in self.rows[args[2]].items()).encode()
        elif args[1]=='enable'and not self.skip_enable:
            self.rows[args[-1]].update(UnitFileState='enabled',ActiveState='active',MainPID='321'if args[-1].endswith('.service')else '0',NextElapseUSecMonotonic='1000')
        elif args[1]in ('stop','disable'):
            self.rows[args[-1]].update(ActiveState='inactive',MainPID='0',NextElapseUSecMonotonic='0')
            if args[1]=='disable':self.rows[args[-1]]['UnitFileState']='disabled'
        elif args[1]=='start':self.rows[args[-1]].update(ActiveState='activating',MainPID='322')
        return subprocess.CompletedProcess(args,0,out,b'')


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.helper=source.SourceTransaction(methodName='runTest');self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.fs=self.helper.prepare();self.backend=Backend();self.manager=m.Manager(self.fs,'b'*64,runner=self.backend)
        self.controls=m.controls.Files(self.fs,'b'*64)
        for path in self.controls.docs:(self.fs.root/path.relative_to('/')).parent.mkdir(parents=True,exist_ok=True)
        self.controls.install()

    def test_installation_alone_is_not_armed(self):
        with self.assertRaisesRegex(m.Refused,'status_not_running'):self.manager.armed()

    def test_arm_enables_status_and_independent_timer_after_reload(self):
        result=self.manager.arm();self.assertEqual(set(result),self.manager.static)
        actions=[args for args,_ in self.backend.calls if args[1]!='show']
        self.assertEqual(actions,[['/usr/bin/systemctl','daemon-reload'],['/usr/bin/systemctl','enable','--now',m.controls.STATUS],['/usr/bin/systemctl','enable','--now',m.controls.TIMER]])

    def test_active_watchdog_is_valid_when_timer_has_no_next_tick_yet(self):
        self.manager.arm();self.backend.rows[m.controls.TIMER]['NextElapseUSecMonotonic']='0'
        self.backend.rows[m.controls.WATCH].update(ActiveState='activating',MainPID='444');self.manager.armed()
        self.backend.rows[m.controls.WATCH].update(ActiveState='inactive',MainPID='0')
        with self.assertRaisesRegex(m.Refused,'watchdog_not_armed'):self.manager.armed()

    def test_enable_failure_does_not_claim_armed(self):
        self.backend.skip_enable=True
        with self.assertRaisesRegex(m.Refused,'status_not_running'):self.manager.arm()

    def test_resource_drift_is_refused(self):
        self.manager.arm()
        for key in ('MemoryHigh','MemoryMax','MemorySwapMax','TasksMax','LimitNOFILE','TimeoutStartUSec'):
            with self.subTest(key=key):
                old=self.backend.rows[m.controls.WATCH][key];self.backend.rows[m.controls.WATCH][key]='infinity'
                with self.assertRaisesRegex(m.Refused,'watchdog_resource_contract'):self.manager.armed()
                self.backend.rows[m.controls.WATCH][key]=old

    def test_manager_override_and_unloaded_documents_are_refused(self):
        for key,value in (('DropInPaths','/etc/foreign.conf'),('NeedDaemonReload','yes'),('FragmentPath','/etc/foreign.service'),('LoadState','not-found')):
            with self.subTest(key=key):
                before=copy.deepcopy(self.backend.rows[m.controls.STATUS]);self.backend.rows[m.controls.STATUS][key]=value
                with self.assertRaises(m.Refused):self.manager.probe(m.controls.STATUS)
                self.backend.rows[m.controls.STATUS]=before

    def test_file_change_is_refused_before_any_native_action(self):
        path=self.fs.root/(m.controls.UNIT_DIR/m.controls.WATCH).relative_to('/');path.write_bytes(b'foreign document')
        with self.assertRaisesRegex(m.Refused,'helper_document_changed'):self.manager.arm()
        self.assertEqual(self.backend.calls,[])

    def test_job_is_detached_and_only_fixed_operation_can_start(self):
        self.manager.arm();name=self.manager.start_operation('verify');self.assertEqual(name,m.Manager.instance('verify'))
        self.assertIn((['/usr/bin/systemctl','start','--no-block',name],15),self.backend.calls)
        self.assertTrue(self.manager.operation_running('verify'))
        with self.assertRaisesRegex(m.Refused,'operation_already_running'):self.manager.start_operation('verify')

    def test_cleanup_refuses_any_running_action(self):
        self.manager.arm();self.manager.start_operation('verify');self.backend.calls=[]
        with self.assertRaisesRegex(m.Refused,'helper_action_still_running'):self.manager.disarm()
        self.assertFalse(any(args[1]in ('stop','disable')for args,_ in self.backend.calls))

    def test_disarm_preserves_documents_and_stops_only_helpers(self):
        self.manager.arm();self.backend.calls=[];self.manager.disarm()
        changes=[args for args,_ in self.backend.calls if args[1]!='show'];self.assertEqual(changes,[
            ['/usr/bin/systemctl','disable','--now',m.controls.TIMER],['/usr/bin/systemctl','stop',m.controls.WATCH],
            ['/usr/bin/systemctl','disable','--now',m.controls.STATUS]])
        self.manager.documents_match()

    def test_unit_program_environment_and_extra_arguments_cannot_expand_scope(self):
        for args in (['/bin/sh','-c','anything'],['/usr/bin/systemctl','start','sshd.service'],
                     ['/usr/bin/systemctl','enable','--now','docker.service'],['/usr/bin/systemctl','start','--no-block','unapproved.service']):
            with self.assertRaisesRegex(m.Refused,'helper_command_scope'):self.manager.run(args)
        with self.assertRaisesRegex(m.Refused,'helper_operation'):self.manager.start_operation('verify;anything')

    def test_fixture_cannot_execute_native_commands(self):
        with self.assertRaisesRegex(m.Refused,'helper_execution_boundary'):m.Manager(self.fs,'b'*64)

    def test_actual_manager_duration_format_is_not_assumed_to_be_an_integer(self):
        self.manager.arm();self.backend.rows[m.controls.TIMER]['NextElapseUSecMonotonic']='4d 15h 4min 27.390724s';self.manager.armed()
        for value in ('0','0us','0s','infinity','n/a'):
            self.backend.rows[m.controls.TIMER]['NextElapseUSecMonotonic']=value
            with self.assertRaisesRegex(m.Refused,'watchdog_not_armed'):self.manager.armed()
        for value in ('4d 4d','1s 1min','1.2.3s','anything','-1s'):
            with self.assertRaisesRegex(m.Refused,'timer_clock_shape'):m.scheduled(value)

    def test_cleanup_job_can_finish_itself_but_cannot_exempt_other_pids(self):
        self.manager.arm();name=self.manager.instance('cleanup')
        self.backend.rows[name].update(ActiveState='activating',MainPID=str(os.getpid()+10000))
        with self.assertRaisesRegex(m.Refused,'helper_action_still_running'):self.manager.disarm(finishing=True)
        self.backend.rows[name]['MainPID']=str(os.getpid());self.backend.calls=[];self.manager.disarm(finishing=True)
        self.assertFalse(any(args[1]in ('stop','disable')and args[-1]==name for args,_ in self.backend.calls))

    def test_cleanup_self_exception_does_not_allow_another_running_action(self):
        self.manager.arm();self.backend.rows[self.manager.instance('cleanup')].update(ActiveState='activating',MainPID=str(os.getpid()))
        self.backend.rows[self.manager.instance('verify')].update(ActiveState='active',MainPID='33333');self.backend.calls=[]
        with self.assertRaisesRegex(m.Refused,'helper_action_still_running'):self.manager.disarm(finishing=True)
        self.assertFalse(any(args[1]in ('stop','disable')for args,_ in self.backend.calls))


if __name__=='__main__':unittest.main()
