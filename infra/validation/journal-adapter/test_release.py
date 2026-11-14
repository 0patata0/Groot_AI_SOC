"""Exact file, recovery and confirmation tests; no services/SSH/host writes."""
import copy
from datetime import datetime,timedelta,timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


f = load('journal_files_test','file_transaction.py')
r = load('journal_release_test','release_runtime.py')


class Files(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='journal-transaction-test-',
            dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.storage=self.root/'storage';self.storage.mkdir()
        for name in ('candidates','backups'):(self.storage/name).mkdir()
        self.rows=[]
        for target in sorted(f.TARGETS):
            path=self.root/target.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True)
            before=None if target==f.NEW else ('original '+target).encode()
            after=('candidate '+target).encode()
            if before is not None:path.write_bytes(before);path.chmod(0o644)
            digest=f.sha(after);p=self.storage/'candidates'/(digest+'.data');p.write_bytes(after);p.chmod(0o600)
            self.rows.append({'target':target,'before_sha256':f.sha(before) if before else None,
                'after_sha256':digest,'uid':os.getuid(),'gid':path.parent.stat().st_gid,'mode':0o644})

    def files(self,rows=None):return f.FileSet(rows or self.rows,self.storage,filesystem_root=self.root)

    def test_all_three_apply_and_restore_new_helper_to_absence(self):
        files=self.files();files.apply()
        self.assertEqual(files.check(('after_sha256',)),[x['after_sha256'] for x in self.rows])
        self.assertEqual(files.restore(),3);self.assertFalse((self.root/f.NEW.lstrip('/')).exists())
        self.assertEqual(files.restore(),0)

    def test_fresh_load_works_after_every_file_write_and_during_restore(self):
        # A small dependency fixture models the actually reproduced legacy
        # core/new journal missing-root_file failure, without pinning an order.
        helper=self.root/f.NEW.lstrip('/')
        old_core=b'from types import SimpleNamespace\ndef export(): return SimpleNamespace()\n'
        new_core=('from types import SimpleNamespace\nfrom pathlib import Path\n'
            'def export(): return SimpleNamespace(root_file=lambda: Path('+repr(str(helper))+').is_file())\n').encode()
        old_journal=b'def read(core): return "legacy"\n'
        new_journal=b'def read(core):\n assert core.root_file() is True\n return "native"\n'
        fixtures={f.CODE+'system_diagnostics.py':(old_core,new_core),
            f.CODE+'diagnostic_journal.py':(old_journal,new_journal),f.NEW:(None,b'# private helper fixture\n')}
        for row in self.rows:
            before,after=fixtures[row['target']]
            if before is not None:(self.root/row['target'].lstrip('/')).write_bytes(before)
            row['before_sha256']=f.sha(before) if before is not None else None;row['after_sha256']=f.sha(after)
            p=self.storage/'candidates'/(row['after_sha256']+'.data');p.write_bytes(after);p.chmod(0o600)
        files=self.files();real=files.replace;loads=[]
        def cold_load():
            c={};j={}
            exec((self.root/(f.CODE+'system_diagnostics.py').lstrip('/')).read_bytes(),c)
            exec((self.root/(f.CODE+'diagnostic_journal.py').lstrip('/')).read_bytes(),j)
            loads.append(j['read'](c['export']()))
        def replace(row,data,expected):real(row,data,expected);cold_load()
        with patch.object(files,'replace',side_effect=replace):files.apply();files.restore()
        cold_load();self.assertIn('native',loads);self.assertEqual(loads[-1],'legacy')
        self.assertFalse(helper.exists())

    def test_partial_failure_restores_only_owned_candidates_and_preserves_new_evidence(self):
        files=self.files();real=files.replace;calls=[]
        def replace(row,data,expected):
            calls.append(row['target'])
            if len(calls)==3:raise OSError('fixture write failure')
            return real(row,data,expected)
        db=self.root/'new-incident.sqlite';db.write_bytes(b'evidence AFTER apply started')
        with patch.object(files,'replace',side_effect=replace),self.assertRaises(OSError):files.apply()
        self.assertEqual(calls[0],f.NEW)
        self.assertEqual(files.restore(),2);self.assertEqual(db.read_bytes(),b'evidence AFTER apply started')
        files.check(('before_sha256',))

    def test_closed_scope_rejects_old_status_gate_or_arbitrary_target(self):
        for target in ('/etc/nftables.conf','/opt/capstone-management/soc_management_run.py','/etc/shadow'):
            rows=copy.deepcopy(self.rows);rows[0]['target']=target
            with self.assertRaisesRegex(ValueError,'target_scope'):self.files(rows)
        with self.assertRaisesRegex(ValueError,'file_count'):self.files(self.rows[:2])

    def test_only_native_may_be_expected_absent(self):
        rows=copy.deepcopy(self.rows)
        row=next(x for x in rows if x['target']!=f.NEW);row['before_sha256']=None
        with self.assertRaisesRegex(ValueError,'digest_shape'):self.files(rows)

    def test_existing_foreign_helper_prevents_apply_without_overwrite(self):
        p=self.root/f.NEW.lstrip('/');p.write_bytes(b'foreign');p.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'target_bytes_changed'):self.files().apply()
        self.assertEqual(p.read_bytes(),b'foreign');self.assertEqual(list((self.storage/'backups').iterdir()),[])

    def test_foreign_drift_before_rollback_refuses_all_writes(self):
        files=self.files();files.apply();p=self.root/f.NEW.lstrip('/');p.write_bytes(b'foreign edit')
        with self.assertRaisesRegex(ValueError,'target_bytes_changed'):files.restore()
        self.assertEqual(p.read_bytes(),b'foreign edit')
        for row in self.rows:
            if row['target']!=f.NEW:
                self.assertEqual(f.sha(files.target(row).read_bytes()),row['after_sha256'])

    def test_metadata_and_symlink_or_hardlink_substitution_refused(self):
        for kind in ('mode','symlink','hardlink'):
            with self.subTest(kind=kind):
                row=next(x for x in self.rows if x['target']!=f.NEW);p=self.root/row['target'].lstrip('/')
                original=p.read_bytes()
                if kind=='mode':p.chmod(0o666)
                elif kind=='symlink':p.unlink();p.symlink_to(self.storage/'not-a-target')
                else:os.link(p,self.root/'extra-hardlink')
                with self.assertRaises((ValueError,OSError)):self.files().apply()
                if kind=='hardlink':(self.root/'extra-hardlink').unlink()
                if kind=='symlink':p.unlink();p.write_bytes(original)
                p.chmod(0o644)

    def test_changed_candidate_or_backup_refused(self):
        files=self.files();row=self.rows[0];p=self.storage/'candidates'/(row['after_sha256']+'.data')
        saved=p.read_bytes();p.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'stored_bytes_changed'):files.apply()
        p.write_bytes(saved);files.apply()
        row=next(x for x in self.rows if x['before_sha256'])
        p=self.storage/'backups'/(row['before_sha256']+'.data');p.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'stored_bytes_changed'):files.restore()
        files.check(('after_sha256',))

    def test_new_file_create_race_does_not_replace_foreign_file(self):
        files=self.files();row=next(x for x in self.rows if x['target']==f.NEW);real=os.link
        def link(*args,**kwargs):
            files.target(row).write_bytes(b'foreign concurrent creation')
            return real(*args,**kwargs)
        with patch.object(f.os,'link',side_effect=link),self.assertRaises(FileExistsError):
            files.replace(row,b'candidate',None)
        self.assertEqual(files.target(row).read_bytes(),b'foreign concurrent creation')
        self.assertEqual(list(files.target(row).parent.glob('.capstone-journal-native-*')),[])

    def test_new_file_metadata_defaults_cannot_expand_mode(self):
        for key,value in (('mode',0o755),('uid',-1),('gid',65534),('mode',True)):
            rows=copy.deepcopy(self.rows);rows[0][key]=value
            with self.assertRaisesRegex(ValueError,'file_metadata'):self.files(rows)


class FakeFiles:
    rows=[{'before_sha256':'before'}]
    def __init__(self,trace,fail=None):self.trace=trace;self.current='before';self.fail=fail
    def check(self,allowed):
        self.trace.append(('check',allowed))
        valid={'before_sha256':'before','after_sha256':'after'}
        if self.current not in {valid[a] for a in allowed}:raise ValueError('target_bytes_changed')
        return [self.current]
    def apply(self):
        self.trace.append('apply');self.current='after'
        if self.fail=='write':raise OSError('fixture partial failure')
    def restore(self):self.trace.append('restore');self.current='before';return 1


class FakeActor:
    def __init__(self,trace,fail=None):self.trace=trace;self.fail=fail;self.p='PREPARED';self.quiescences=0
    def phase(self):return self.p
    def preflight(self,rollback=False):
        self.trace.append(('preflight',rollback))
        if self.fail=='preflight':raise ValueError('preflight')
    def arm_rollback(self):
        self.trace.append('arm')
        if self.fail=='arm':raise ValueError('rollback_not_armed')
    def quiesce(self):
        self.trace.append('quiesce');self.quiescences+=1
        if self.fail=='busy' and self.quiescences==1:raise ValueError('collector_busy')
    def resume(self):self.trace.append('resume')
    def ready(self,candidate):
        self.trace.append(('ready',candidate))
        if self.fail=='new-read' and candidate:raise ValueError('reader_probe_failed')
    def mark(self,p,**extra):self.trace.append(('mark',p));self.p=p
    def disarm(self):self.trace.append('disarm')


class Recovery(unittest.TestCase):
    def test_timer_armed_before_quiesce_and_success_stays_unconfirmed(self):
        trace=[];actor=FakeActor(trace);files=FakeFiles(trace)
        self.assertTrue(r.execute_apply(actor,files));self.assertEqual(actor.p,'APPLIED')
        self.assertLess(trace.index('arm'),trace.index('quiesce'))
        self.assertLess(trace.index('quiesce'),trace.index('apply'));self.assertNotIn('disarm',trace)

    def test_failed_preflight_or_timer_never_stops_or_writes(self):
        for reason in ('preflight','arm'):
            trace=[]
            with self.assertRaises(ValueError):r.execute_apply(FakeActor(trace,reason),FakeFiles(trace))
            self.assertNotIn('quiesce',trace);self.assertNotIn('apply',trace)

    def test_partial_write_and_new_reader_failure_restore_old_service_then_disarm(self):
        for fail in ('write','new-read'):
            trace=[];actor=FakeActor(trace,fail);files=FakeFiles(trace,fail)
            self.assertFalse(r.execute_apply(actor,files));self.assertEqual(actor.p,'APPLY_FAILED_ROLLED_BACK')
            self.assertEqual(files.current,'before');self.assertIn(('ready',False),trace)
            self.assertLess(trace.index('restore'),trace.index(('ready',False)))
            self.assertEqual(trace[-1],'disarm')

    def test_collector_busy_without_writes_does_not_wait_or_stop_it_again(self):
        trace=[];actor=FakeActor(trace,'busy');files=FakeFiles(trace)
        self.assertFalse(r.execute_apply(actor,files));self.assertEqual(actor.quiescences,1)
        self.assertNotIn('apply',trace);self.assertNotIn('restore',trace)
        self.assertIn('resume',trace);self.assertEqual(trace[-1],'disarm')

    def test_committed_or_already_rolled_back_timer_is_complete_noop(self):
        for phase in r.TERMINAL:
            trace=[];actor=FakeActor(trace);actor.p=phase
            self.assertFalse(r.execute_rollback(actor,FakeFiles(trace)));self.assertEqual(trace,[])

    def test_expiry_restores_without_database_api(self):
        trace=[];actor=FakeActor(trace);actor.p='APPLIED';files=FakeFiles(trace);files.current='after'
        self.assertTrue(r.execute_rollback(actor,files));self.assertEqual(actor.p,'ROLLED_BACK')
        self.assertEqual(files.current,'before');self.assertEqual(trace[-1],'disarm')

    def test_foreign_file_stops_rollback_before_services(self):
        trace=[];files=FakeFiles(trace);files.current='foreign'
        with self.assertRaisesRegex(ValueError,'target_bytes_changed'):r.execute_rollback(FakeActor(trace),files)
        self.assertNotIn('quiesce',trace);self.assertNotIn('restore',trace)


class Proof(unittest.TestCase):
    def fixture(self):
        current=datetime(2026,11,15,8,tzinfo=timezone(timedelta(hours=9)))
        state={'at_kst':(current-timedelta(minutes=1)).isoformat()}
        reader={'pid':123,'start_ticks':456};sha='a'*64
        proof={'schema':1,'plan_sha256':sha,'host':'a','applied_at_kst':state['at_kst'],
            'observed_at_kst':current.isoformat(),'reader':reader,'mcp_evidence_sha256':['b'*64],
            'chat_evidence_sha256':['c'*64],'verdict':'passed'}
        return proof,state,sha,reader,current

    def test_only_current_matching_reader_and_mcp_plus_chat_evidence_can_confirm(self):
        proof,state,sha,reader,current=self.fixture()
        r.validate_proof(proof,state,sha,'a',reader,current)
        for field,value in (('host','b'),('plan_sha256','d'*64),('reader',{'pid':124,'start_ticks':456}),
            ('mcp_evidence_sha256',[]),('chat_evidence_sha256',[]),('verdict','not_verified'),
            ('observed_at_kst',(current+timedelta(seconds=1)).isoformat())):
            with self.subTest(field=field),self.assertRaises(ValueError):
                r.validate_proof({**proof,field:value},state,sha,'a',reader,current)

    def test_stale_or_other_application_proof_is_not_reusable(self):
        proof,state,sha,reader,current=self.fixture()
        for value in ((current-timedelta(minutes=6)).isoformat(),(current-timedelta(days=1)).isoformat()):
            with self.assertRaises(ValueError):r.validate_proof({**proof,'observed_at_kst':value},state,sha,'a',reader,current)
        with self.assertRaises(ValueError):
            r.validate_proof({**proof,'applied_at_kst':current.isoformat()},state,sha,'a',reader,current)

    def test_unrendered_cli_refuses_before_command_or_files(self):
        p=subprocess.run([sys.executable,'-I','-B',str(Path(r.__file__)),'observe','a'*64],capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertIn('refused_or_failed',p.stderr)
        self.assertNotIn('Traceback',p.stderr)


class RuntimeCommands(unittest.TestCase):
    def actor(self,host='a'):
        actor=object.__new__(r.Actor);actor.base=Path('/var/lib/capstone-journal-native/'+'a'*16+'-'+host)
        actor.plan_sha='b'*64;actor.plan={'bundle_id':'a'*64};actor.timer='capstone-journal-native-rollback-'+'a'*16+'-'+host
        actor.host={'reader_account':{'name':'mcp' if host=='b' else 'capstone-diagnostics','uid':110,'gid':111},
            'services':{r.JOURNAL:{'MainPID':'123','start_ticks':456},r.TIMER:{},r.COLLECTOR:{}},'protected':{}}
        return actor

    def test_protected_scope_accepts_existing_kst_receipt_and_rejects_other_paths(self):
        paths=['/opt/capstone-diagnostics/'+n for n in (
            'diagnostic_history.py','runtime_health.py','read-system-diagnostics.py','host_inventory.py')]
        paths += ['/etc/systemd/system/'+n for n in (r.JOURNAL,r.COLLECTOR,r.TIMER)]
        paths += ['/var/lib/capstone-diagnostics/installation/live-management-v5-20261024T021707+0900.json']
        row={'sha256':'a'*64,'uid':0,'gid':0,'mode':0o644}
        values={p:dict(row) for p in paths};r.validate_protected(values)
        for path in ('/etc/shadow','/var/lib/capstone-diagnostics/installation/../other.json',
            '/etc/systemd/system/ssh.service.d/override.conf'):
            with self.assertRaisesRegex(ValueError,'protected_scope'):r.validate_protected({**values,path:row})
        missing=dict(values);missing.pop(paths[0])
        with self.assertRaisesRegex(ValueError,'protected_scope'):r.validate_protected(missing)

    def test_protected_file_pins_may_not_allow_writable_or_nonroot_metadata(self):
        paths=['/opt/capstone-diagnostics/'+n for n in (
            'diagnostic_history.py','runtime_health.py','read-system-diagnostics.py','host_inventory.py')]
        paths += ['/etc/systemd/system/'+n for n in (r.JOURNAL,r.COLLECTOR,r.TIMER)]
        values={p:{'sha256':'a'*64,'uid':0,'gid':0,'mode':0o644} for p in paths}
        for key,value in (('mode',0o666),('uid',1000),('sha256','wrong'),('gid',-1)):
            altered=copy.deepcopy(values);altered[paths[0]][key]=value
            with self.assertRaisesRegex(ValueError,'protected_metadata'):r.validate_protected(altered)

    def test_fixed_subprocess_has_clean_env_and_failed_status_does_not_return(self):
        result=subprocess.CompletedProcess([],0,b'{}',b'')
        with patch.object(r.subprocess,'run',return_value=result) as run:
            self.assertEqual(r.run(['/usr/bin/fixed'],data=b'fixture'),b'{}')
        self.assertEqual(run.call_args.kwargs['env'],r.ENV)
        self.assertEqual(run.call_args.kwargs['input'],b'fixture');self.assertTrue(run.call_args.kwargs['close_fds'])
        for result in (subprocess.CompletedProcess([],1,b'',b''),
            subprocess.CompletedProcess([],0,b'x'*131073,b''),subprocess.CompletedProcess([],0,b'',b'x'*4097)):
            with patch.object(r.subprocess,'run',return_value=result),self.assertRaisesRegex(ValueError,'fixed_command_failed'):
                r.run(['/usr/bin/fixed'])

    def test_applied_state_is_atomically_saved_with_reader_and_probe_binding(self):
        actor=self.actor();reader={'pid':123,'start_ticks':456}
        actor.last_read={'request':{'target':'a:rule-worker'},'response_sha256':'c'*64}
        with tempfile.TemporaryDirectory(prefix='journal-state-test-') as work:
            actor.base=Path(work)
            with patch.object(r,'HOST','a'),patch.object(actor,'state',return_value={'phase':'PREPARED'}), \
                 patch.object(actor,'reader',return_value=reader):actor.mark('APPLIED')
            p=actor.base/'state.json';value=json.loads(p.read_text())
            self.assertEqual(value['phase'],'APPLIED');self.assertEqual(value['reader'],reader)
            self.assertEqual(value['read_probe'],actor.last_read);self.assertEqual(value['plan_sha256'],actor.plan_sha)
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            self.assertEqual(list(actor.base.glob('.state-*')),[])

    def test_rollback_timer_is_exactly_15_minutes_and_must_be_active(self):
        actor=self.actor();calls=[]
        def run(argv,**kw):
            calls.append(argv);return b'ActiveState=active\n' if argv[0].endswith('systemctl') else b''
        with patch.object(r,'run',side_effect=run):actor.arm_rollback()
        self.assertIn('--on-active=900s',calls[0]);self.assertIn('--property=RuntimeMaxSec=180',calls[0])
        self.assertEqual(calls[0][-2:],['rollback','b'*64])
        self.assertIn(str(actor.base/'release.py'),calls[0]);self.assertNotIn('sh',calls[0])
        with patch.object(r,'run',side_effect=[b'',b'ActiveState=inactive\n']),self.assertRaisesRegex(ValueError,'rollback_not_armed'):
            actor.arm_rollback()

    def test_quiesce_stops_timer_and_reader_but_never_kills_ongoing_collector(self):
        actor=self.actor();calls=[];states=iter(['activating','inactive'])
        def unit(name):return {'ActiveState':next(states)} if name==r.COLLECTOR else {'MainPID':'0'}
        with patch.object(actor,'unit',side_effect=unit),patch.object(r,'run',side_effect=lambda a,**kw:calls.append(a)),patch.object(r.time,'sleep'):
            actor.quiesce()
        self.assertEqual(calls,[['/usr/bin/systemctl','stop',r.TIMER],['/usr/bin/systemctl','stop',r.JOURNAL]])

    def test_busy_collector_refuses_before_stopping_reader(self):
        actor=self.actor();calls=[]
        with patch.object(actor,'unit',return_value={'ActiveState':'activating'}), \
             patch.object(r.time,'monotonic',side_effect=[0,91]),patch.object(r,'run',side_effect=lambda a,**kw:calls.append(a)), \
             self.assertRaisesRegex(ValueError,'collector_busy'):actor.quiesce()
        self.assertEqual(calls,[['/usr/bin/systemctl','stop',r.TIMER]])

    def test_preflight_requires_same_reader_process_and_active_timer(self):
        actor=self.actor()
        with patch.object(actor,'protected'),patch.object(actor,'phase',return_value='PREPARED'), \
             patch.object(actor,'unit',return_value={'ActiveState':'active'}), \
             patch.object(actor,'reader',return_value={'pid':123,'start_ticks':456}):
            actor.preflight()
            with patch.object(actor,'reader',return_value={'pid':123,'start_ticks':457}),self.assertRaises(ValueError):actor.preflight()
            with patch.object(actor,'phase',return_value='APPLIED'),self.assertRaisesRegex(ValueError,'not_prepared'):actor.preflight()
            with patch.object(actor,'unit',return_value={'ActiveState':'inactive'}),self.assertRaises(ValueError):actor.preflight()

    def test_existing_dropin_profile_is_preserved_and_change_is_refused(self):
        actor=self.actor();actor.host['services']={r.COLLECTOR:{'UnitFileState':'static','DropInPaths':'/etc/systemd/system/example.d/30-netlink.conf'}}
        user=types.SimpleNamespace(pw_uid=110,pw_gid=111)
        profile={'UnitFileState':'static','DropInPaths':'/etc/systemd/system/example.d/30-netlink.conf'}
        with patch.object(r,'HOST','a'),patch.object(r.pwd,'getpwnam',return_value=user),patch.object(actor,'unit',return_value=profile):
            actor.protected()
            with patch.object(actor,'unit',return_value={**profile,'DropInPaths':''}),self.assertRaisesRegex(ValueError,'service_profile_changed'):
                actor.protected()
            with patch.object(r.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=999,pw_gid=111)),self.assertRaisesRegex(ValueError,'reader_account_changed'):
                actor.protected()

    def test_readiness_uses_existing_nonprivileged_reader_on_every_host(self):
        for host in 'abc':
            actor=self.actor(host);actor.files=types.SimpleNamespace(check=lambda _:None);calls=[]
            target={'a':'a:rule-worker','b':'b:rule-worker','c':'c:apache'}[host]
            response={'status':'observed','target':target,'requested_window_total_count':None,'journal_retention_verified':False}
            def run(argv,**kw):calls.append((argv,kw));return json.dumps(response).encode()
            with patch.object(r,'HOST',host),patch.object(actor,'protected'),patch.object(actor,'reader'), \
                 patch.object(actor,'unit',return_value={'ActiveState':'active'}),patch.object(r,'run',side_effect=run):actor.ready(True)
            self.assertEqual(calls[0][0][:4],['/usr/sbin/runuser','-u',actor.host['reader_account']['name'],'--'])
            self.assertEqual(calls[0][0][-1],'/opt/capstone-diagnostics/read-system-diagnostics.py')
            self.assertEqual(json.loads(calls[0][1]['data'])['target'],target)
            self.assertEqual(actor.last_read['response_sha256'],r.sha(json.dumps(response).encode()))

    def test_readiness_unavailable_or_fabricated_total_is_not_success(self):
        actor=self.actor();actor.files=types.SimpleNamespace(check=lambda _:None)
        for response in ({'status':'unavailable'},{'status':'observed','target':'a:rule-worker','requested_window_total_count':0,'journal_retention_verified':False}):
            with patch.object(r,'HOST','a'),patch.object(actor,'protected'),patch.object(actor,'reader'), \
                 patch.object(actor,'unit',return_value={'ActiveState':'active'}),patch.object(r,'run',return_value=json.dumps(response).encode()), \
                 self.assertRaisesRegex(ValueError,'reader_probe_failed'):actor.ready(True)

    def test_confirmation_records_proof_before_disarming(self):
        actor=self.actor();current=datetime.now(r.KST);state={'phase':'APPLIED','at_kst':(current-timedelta(minutes=1)).isoformat()}
        reader={'pid':123,'start_ticks':456};actor.last_read={'response_sha256':'a'*64}
        proof={'schema':1,'host':'a','plan_sha256':actor.plan_sha,'applied_at_kst':state['at_kst'],
            'observed_at_kst':current.isoformat(),'reader':reader,'mcp_evidence_sha256':['c'*64],
            'chat_evidence_sha256':['d'*64],'verdict':'passed'}
        trace=[]
        with patch.object(r,'HOST','a'),patch.object(actor,'state',return_value=state),patch.object(actor,'reader',return_value=reader), \
             patch.object(actor,'ready',side_effect=lambda **kw:trace.append('ready')), \
             patch.object(r,'read_root',side_effect=lambda *a,**kw:json.dumps(proof).encode()), \
             patch.object(actor,'mark',side_effect=lambda *a,**kw:trace.append('mark')), \
             patch.object(actor,'disarm',side_effect=lambda:trace.append('disarm')):
            actor.commit()
            self.assertEqual(trace,['ready','mark','disarm'])
            trace.clear();proof['chat_evidence_sha256']=[]
            with self.assertRaises(ValueError):actor.commit()
            self.assertEqual(trace,['ready'])


if __name__ == '__main__':unittest.main()
