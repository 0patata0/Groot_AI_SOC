"""Wired source/cache/service lifecycle on three isolated filesystem fixtures.

Real SQLite, hashes, durable journals and atomic filesystem operations; fixed
service/Docker/process backends are simulated. Not a native systemd, installer,
independent watchdog, actual MCP or bot-chat acceptance test.
"""
import copy
from datetime import datetime,timedelta
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('release_lifecycle_tested','release_lifecycle.py')
files_fixture=load('lifecycle_file_fixture','test_release_files.py')
cache_fixture=load('lifecycle_cache_fixture','test_cache_transaction.py')
native_fixture=load('lifecycle_native_fixture','test_release_services.py')
helper_fixture=load('lifecycle_helper_fixture','test_release_helpers.py')
process_fixture=load('lifecycle_process_fixture','test_release_processes.py')
cache_module=load('lifecycle_cache','release_cache.py')
state_module=load('lifecycle_state','release_state.py')
store_module=load('lifecycle_store','release_storage.py')
control_module=load('lifecycle_control','release_controls.py')
native_module=load('lifecycle_native','release_services.py')
helper_module=load('lifecycle_helper','release_helpers.py')
process_module=load('lifecycle_process','release_processes.py')
plan_module=load('lifecycle_plan','release_plan.py')


class Backend(native_fixture.Backend):
    def __init__(self,host,legacy):
        super().__init__(host);self.legacy=legacy
    def __call__(self,args,*,timeout):
        if args[0]=='/usr/bin/systemctl'and args[1]=='show':
            name=args[2];directory=self.legacy.root/'etc/systemd/system'/(name+'.d')
            self.rows[name]['DropInPaths']=' '.join('/'+str(p.relative_to(self.legacy.root))for p in sorted(directory.glob('*.conf')))
        if args[0]=='/usr/bin/systemctl'and args[1]=='show'and args[2]==native_module.OPTIONAL:
            path=self.legacy.root/'etc/systemd/system'/native_module.OPTIONAL
            self.rows[native_module.OPTIONAL]['LoadState']='loaded'if path.exists()else 'not-found'
        result=super().__call__(args,timeout=timeout)
        if args[:3]==['/usr/bin/systemctl','start','capstone-system-diagnostics.service']and not self.skip_collection:
            db=sqlite3.connect(self.legacy.path)
            try:policy=db.execute("SELECT value FROM metadata WHERE key='source_filter_policy'").fetchone()
            finally:db.close()
            if policy is None:self.legacy.candidate_publish()
        return result


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.offset=timedelta();self.nodes={};self.source_helpers=[]
        for host in 'abc':
            f=files_fixture.SourceTransaction(methodName='runTest');f.setUp();self.addCleanup(f.doCleanups);fs=f.prepare(host)
            (fs.root/m.c.BASE.relative_to('/')).chmod(0o700);(fs.storage/'cache').mkdir(mode=0o700)
            legacy=cache_fixture.CacheTest(methodName='runTest');legacy.root=fs.root;legacy.path=fs.root/cache_fixture.mod.CACHE.relative_to('/')
            legacy.path.parent.mkdir(parents=True,exist_ok=True);legacy.make_database();legacy.mutate("UPDATE metadata SET value=? WHERE key='host'",(host,))
            backend=Backend(host,legacy);hb=helper_fixture.Backend();pb=process_fixture.Backend()
            container={k:copy.deepcopy(backend.container[k])for k in ('id','image','running')}if host=='b'else None
            if container:container['restart']='unless-stopped'
            native=native_module.Native(host,container,filesystem_root=fs.root,runner=backend)
            machine=(host*32+'\n').encode();(fs.root/'etc/machine-id').write_bytes(machine)
            protected={}
            for relative in plan_module.PROTECTED[host]:
                path=fs.root/relative.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True)
                if relative==(plan_module.ACTIVE_PROTECTED if host=='b'else plan_module.OPTIONAL_PROTECTED):
                    protected[relative]=None;continue
                raw=('unchanged fixture '+host+' '+relative+'\n').encode();path.write_bytes(raw);path.chmod(0o600)
                protected[relative]={'sha256':plan_module.sha(raw),'uid':0,'gid':0,'mode':0o600}
            for name in plan_module.HELPERS:
                path=fs.storage/name;path.write_bytes((HERE/name).read_bytes());path.chmod(0o600)
            self.nodes[host]={'fixture':f,'files':fs,'legacy':legacy,'native':native,'backend':backend,'helper_backend':hb,'process_backend':pb,
                'host_plan':{'rows':fs.rows,'machine_sha256':plan_module.sha(machine),'diagnostic_gid':os.getgid(),'reader_uid':77,
                    'mcp_uid':88 if host=='b'else None,'container':container,'protected':protected,'previous_current_sha256':None,'normal_reader_sha256':plan_module.sha(('# permanent normal reader '+host+'\n').encode())}}
            if host=='b':
                (fs.root/'etc/mcp/system-diagnostics').mkdir(parents=True,mode=0o750,exist_ok=True)
                for relative in ('var/lib/capstone-review-chat/queue.sqlite','var/lib/capstone-ollama-trial/chat/queue.sqlite'):
                    p=fs.root/relative;p.parent.mkdir(parents=True,exist_ok=True);db=sqlite3.connect(p);db.execute('CREATE TABLE jobs(status TEXT)');db.commit();db.close();p.chmod(0o640)
                path=fs.root/'opt/hermes-data/state.db';db=sqlite3.connect(path);db.execute('CREATE TABLE session_turn_leases(expires_at REAL)');db.commit();db.close();path.chmod(0o600)
                path=fs.root/'opt/hermes-data/gateway_state.json';path.write_text(json.dumps({'active_agents':0,'active_work':[],'updated_at':datetime.now(m.c.KST).isoformat()}));path.chmod(0o600)
        plan={'schema':1,'release_id':'a'*32,'source_commit':'c'*40,'hosts':{h:n['host_plan']for h,n in self.nodes.items()},
            'helpers':{name:plan_module.sha((HERE/name).read_bytes())for name in plan_module.HELPERS},
            'cohort':{'schema':1,'release_id':'a'*32,'hosts':{h:[r for r in n['files'].rows if r['target']not in m.source.BARRIERS[h]]for h,n in self.nodes.items()}}}
        self.plan_sha=m.digest(plan)
        for host,n in self.nodes.items():
            fs=n['files'];store=store_module.Store(fs,self.plan_sha);bundle=plan_module.Plan(plan).bundle()
            (fs.storage/'normal-reader.py').write_bytes(('# permanent normal reader '+host+'\n').encode());(fs.storage/'normal-reader.py').chmod(0o600)
            store.immutable('plan.json',plan);store.immutable('bundle.json',bundle)
            now=datetime.now(m.c.KST);approval={'schema':1,'release_id':fs.release_id,'plan_sha256':self.plan_sha,
                'bundle_sha256':m.digest(bundle),'decision':'approved','approved_at_kst':(now-timedelta(seconds=1)).isoformat(),
                'expires_at_kst':(now+timedelta(minutes=15)).isoformat(),'reference':'synthetic-root-fixture'}
            store.immutable('approval.json',approval);store.immutable('revert-approval.json',approval)
            journal=state_module.Journal(fs,self.plan_sha);controls=control_module.Files(fs,self.plan_sha)
            helpers=helper_module.Manager(fs,self.plan_sha,runner=n['helper_backend'])
            readers=process_module.Readers(fs,controls,journal,77,88 if host=='b'else None,backend=n['process_backend'])
            cache=cache_module.Cache(host,os.getgid(),fs.storage/'cache',filesystem_root=fs.root)
            lifecycle=m.Lifecycle(fs,cache,journal,store,controls,n['native'],helpers,readers,clock=lambda:datetime.now(m.c.KST)+self.offset)
            n.update(controller=lifecycle,store=store,journal=journal,controls=controls,cache=cache)
            lifecycle.initialize(now+timedelta(minutes=10))
        self.b=self.nodes['b']['controller']

    def step(self,operation):
        if operation=='arm'and not self.b.state()['facts'].get('helpers_prepared'):self.step('prepare')
        proofs=self.proofs()if operation in ('arm','apply')else None
        for host in ('bac'if operation=='arm'else 'abc'):self.nodes[host]['controller'].execute(operation,proofs=proofs)
    def applied(self):
        for operation in ('arm','quiesce','backup','apply'):self.step(operation)
    def verified(self):self.applied();self.step('verify')
    def proofs(self):return {h:n['controller'].local_proof()for h,n in self.nodes.items()}
    def confirmed(self):
        self.verified()
        for host in 'acb':self.nodes[host]['controller'].execute('confirm',proofs=self.proofs())
    def resume(self):
        for host in 'acb':self.nodes[host]['controller'].execute('resume',proofs=self.proofs())

    def test_complete_coherent_source_commit_then_resume(self):
        self.confirmed();self.resume()
        for host,n in self.nodes.items():
            ctl=n['controller'];self.assertEqual(ctl.state()['phase'],'confirmed');self.assertIsNone(ctl.state()['pending'])
            self.assertTrue(ctl.state()['facts']['services_resumed']);self.assertFalse(n['controls'].fenced('consumer'))
            n['files'].check('after_sha256');self.assertEqual(n['cache'].inspect(n['cache'].path,live=True)[2]['metadata']['source_filter_policy'],'application-severity-v1')
        self.assertTrue(self.nodes['b']['backend'].container['running'])

    def test_b_cannot_confirm_before_peers(self):
        self.verified();before=self.b.state()
        with self.assertRaisesRegex(ValueError,'coherent_peer_proof_required'):self.b.execute('confirm',proofs=self.proofs())
        self.assertEqual(self.b.state(),before)

    def test_missing_peer_does_not_change_state_or_start_consumers(self):
        self.verified();before=self.b.state()
        with self.assertRaisesRegex(ValueError,'peer_proof_set'):self.b.execute('confirm',proofs={'b':self.b.local_proof()})
        self.assertEqual(self.b.state(),before);self.assertTrue(self.b.controls.fenced('consumer'))

    def test_partial_apply_recovers_sources_and_cache_without_resuming_bots(self):
        for op in ('arm','quiesce','backup'):self.step(op)
        real=self.b.files.replace;seen=[]
        def broken(row,data,expected):
            if len(seen)==2:raise OSError('fixture crash')
            real(row,data,expected);seen.append(row['target'])
        with patch.object(self.b.files,'replace',side_effect=broken):
            with self.assertRaises(OSError):self.b.execute('apply',proofs=self.proofs())
        self.b.execute('recover');self.assertEqual(self.b.state()['phase'],'rolled_back');self.assertTrue(self.b.core_is('before_sha256'))
        self.assertTrue(self.b.controls.fenced('consumer'));self.assertFalse(self.nodes['b']['backend'].container['running'])

    def test_deadline_recovery_preserves_candidate_observations(self):
        self.verified();self.offset=timedelta(minutes=11);candidate=self.b.cache.path.read_bytes();self.b.execute('recover')
        self.assertEqual(self.b.state()['phase'],'rolled_back');self.assertEqual((self.b.cache.storage/'after.sqlite3').read_bytes(),candidate)
        self.assertNotEqual(self.b.cache.path.read_bytes(),candidate)

    def test_new_legacy_observations_are_not_erased_by_later_recovery(self):
        self.verified();self.offset=timedelta(minutes=11);self.b.execute('recover')
        self.nodes['b']['legacy'].mutate('INSERT INTO events VALUES(?,?,?,?)',('later',3500000,'example.service','{}'))
        latest=self.b.cache.path.read_bytes();self.b.execute('recover');self.assertEqual(self.b.cache.path.read_bytes(),latest)

    def test_lost_rollback_ack_finishes_original_receipt_without_overwrite(self):
        self.applied();real=self.b.journal.finish
        with patch.object(self.b.journal,'finish',side_effect=OSError('lost ack')):
            with self.assertRaises(OSError):self.b.execute('rollback')
        value=self.b.state();nonce=value['pending']['nonce'];old=self.b.store.read('operation-'+nonce+'.json')
        self.b.execute('recover');self.assertEqual(self.b.state()['phase'],'rolled_back')
        self.assertEqual(self.b.store.read('operation-'+nonce+'.json'),old)

    def test_unknown_source_is_not_overwritten_during_recovery(self):
        for op in ('arm','quiesce','backup'):self.step(op)
        row=next(r for r in self.b.files.rows if r['target']not in m.source.BARRIERS['b']and r['before_sha256'])
        path=self.b.files.target(row);path.write_bytes(b'foreign source')
        with self.assertRaises(ValueError):self.b.execute('apply',proofs=self.proofs())
        self.offset=timedelta(minutes=11)
        with self.assertRaises(ValueError):self.b.execute('recover')
        self.assertEqual(path.read_bytes(),b'foreign source');self.assertTrue(self.b.controls.fenced('consumer'))

    def test_candidate_resume_requires_unexpired_approval(self):
        self.confirmed();self.offset=timedelta(minutes=16)
        with self.assertRaisesRegex(ValueError,'approval_expired'):self.b.execute('resume',proofs=self.proofs())
        self.assertFalse(self.nodes['b']['backend'].container['running'])

    def test_confirmed_sources_do_not_auto_rollback_at_deadline(self):
        self.confirmed();self.offset=timedelta(hours=1);before=self.b.files.check('after_sha256');self.b.execute('recover')
        self.assertEqual(self.b.files.check('after_sha256'),before);self.assertEqual(self.b.state()['phase'],'confirmed')

    def test_lost_resume_ack_is_reconciled_without_duplicate_start(self):
        self.confirmed()
        with patch.object(self.b.journal,'finish',side_effect=OSError('lost ack')):
            with self.assertRaises(OSError):self.b.execute('resume',proofs=self.proofs())
        self.nodes['b']['backend'].calls=[];self.b.execute('resume',proofs=self.proofs())
        self.assertIsNone(self.b.state()['pending'])
        self.assertFalse(any(args[1]=='start'for args,_ in self.nodes['b']['backend'].calls))

    def assert_completed_resume_is_read_only(self):
        before=self.b.state();raw=self.b.journal.path.read_bytes();cache=self.b.cache.path.read_bytes()
        artifacts={p.name:p.read_bytes()for p in self.b.files.storage.glob('operation-*.json')}
        self.nodes['b']['backend'].calls=[];self.nodes['b']['helper_backend'].calls=[]
        result=self.b.execute('resume',proofs=self.proofs())
        self.assertEqual(result,before);self.assertEqual(self.b.journal.path.read_bytes(),raw)
        self.assertEqual(self.b.cache.path.read_bytes(),cache)
        self.assertEqual({p.name:p.read_bytes()for p in self.b.files.storage.glob('operation-*.json')},artifacts)
        for backend in (self.nodes['b']['backend'],self.nodes['b']['helper_backend']):
            self.assertFalse(any(args[1]in ('start','stop','update','enable','disable','daemon-reload')
                                 for args,_ in backend.calls))

    def test_completed_candidate_resume_does_not_create_another_intent_or_start(self):
        self.confirmed();self.resume();self.assert_completed_resume_is_read_only()

    def test_completed_baseline_resume_preserves_later_legacy_observations(self):
        self.applied();self.step('rollback');self.resume()
        self.nodes['b']['legacy'].mutate('INSERT INTO events VALUES(?,?,?,?)',
                                       ('later-after-resume',3500000,'example.service','{}'))
        self.assert_completed_resume_is_read_only()

    def test_completed_resume_cannot_repair_drift_or_create_a_pending_intent(self):
        self.confirmed();self.resume();before=self.b.journal.path.read_bytes()
        backend=self.nodes['b']['backend'];backend.rows['capstone-review-chat.service']['ActiveState']='inactive'
        backend.calls=[]
        with self.assertRaisesRegex(ValueError,'completed_resume_services_changed'):
            self.b.execute('resume',proofs=self.proofs())
        self.assertEqual(self.b.journal.path.read_bytes(),before)
        self.assertFalse(any(args[1]=='start'for args,_ in backend.calls))

    def test_completed_resume_requires_its_original_immutable_receipt(self):
        self.confirmed();self.resume();before=self.b.journal.path.read_bytes()
        alias=self.b.files.storage/'resume-candidate.json';saved=self.b.store.read(alias.name)
        saved['nonce']='0'*32;alias.write_bytes(m.c.canonical(saved))
        with self.assertRaisesRegex(ValueError,'completed_resume_receipt_changed'):
            self.b.execute('resume',proofs=self.proofs())
        self.assertEqual(self.b.journal.path.read_bytes(),before)

    def test_partial_confirmation_does_not_allow_local_revert(self):
        self.confirmed();self.b.execute('revert_fence')
        with self.assertRaisesRegex(ValueError,'coordinated_revert_proof_required'):self.b.execute('recover')
        self.assertTrue(self.b.core_is('after_sha256'))

    def test_global_revert_restores_before_sources_then_baseline_resume(self):
        self.confirmed();self.resume();self.step('revert_fence')
        decision={h:n['controller'].local_control_proof()for h,n in self.nodes.items()}
        for host in 'acb':self.nodes[host]['controller'].execute('revert',proofs=decision)
        self.resume()
        for n in self.nodes.values():
            ctl=n['controller'];self.assertEqual(ctl.state()['phase'],'rolled_back');self.assertTrue(ctl.state()['facts']['baseline_services_resumed'])
            self.assertTrue(ctl.core_is('before_sha256'));self.assertTrue(ctl.state()['facts']['services_resumed'])

    def test_busy_root_job_is_not_stopped(self):
        self.step('arm');backend=self.nodes['b']['backend'];backend.rows['capstone-management.service'].update(ActiveState='active',MainPID='9999')
        with patch.object(m.time,'monotonic',side_effect=[0,31]):
            with self.assertRaisesRegex(ValueError,'consumer_work_still_running'):self.b.execute('quiesce')
        self.assertFalse(any(args[1]=='stop'and args[-1]=='capstone-management.service'for args,_ in backend.calls))
        self.assertTrue(self.b.core_is('before_sha256'))

    def test_completed_oneshot_is_not_misclassified_as_busy(self):
        self.nodes['b']['backend'].rows['capstone-management.service'].update(ActiveState='active',SubState='exited',MainPID='0')
        self.assertTrue(self.b.idle())

    def test_preparation_deadline_does_not_stop_untouched_services(self):
        self.step('prepare');backend=self.nodes['b']['backend'];backend.calls=[];self.offset=timedelta(minutes=11)
        self.b.execute('recover');self.assertEqual(self.b.state()['phase'],'rolled_back')
        self.assertTrue(backend.container['running']);self.assertFalse(any(args[1]in ('stop','start','update')for args,_ in backend.calls))
        self.assertTrue(self.b.core_is('before_sha256'));self.assertFalse(self.b.controls.fenced('consumer'))

    def test_apply_cannot_begin_while_another_host_has_not_backed_up(self):
        self.step('arm');self.step('quiesce');self.b.execute('backup');before=self.b.state()
        with self.assertRaisesRegex(ValueError,'peer_preparation_phase'):self.b.execute('apply',proofs=self.proofs())
        self.assertEqual(self.b.state(),before)

    def test_staged_recovery_with_lost_ack_never_stops_or_restarts_services(self):
        self.step('prepare');backend=self.nodes['b']['backend'];backend.calls=[]
        before=self.b.cache.path.read_bytes();self.offset=timedelta(minutes=11)
        with patch.object(self.b.journal,'finish',side_effect=OSError('lost ack')):
            with self.assertRaises(OSError):self.b.execute('recover')
        pending=self.b.state()['pending'];self.assertEqual(pending['from_phase'],'staged')
        original=self.b.store.read('operation-'+pending['nonce']+'.json')
        self.b.execute('recover');self.b.execute('recover')
        self.assertEqual(self.b.state()['phase'],'rolled_back')
        self.assertTrue(self.b.state()['facts']['services_untouched'])
        self.assertEqual(self.b.store.read('operation-'+pending['nonce']+'.json'),original)
        self.assertEqual(self.b.cache.path.read_bytes(),before)
        self.assertTrue(backend.container['running']);self.assertFalse(self.b.controls.fenced('consumer'))
        self.assertFalse(any(args[1]in ('stop','start','update')for args,_ in backend.calls))

    def test_actual_gateway_without_active_work_field_uses_lease_and_agent_counts(self):
        path=self.b.files.root/'opt/hermes-data/gateway_state.json';value=json.loads(path.read_text());value.pop('active_work');path.write_text(json.dumps(value))
        self.assertTrue(self.b.idle());value['active_agents']=1;path.write_text(json.dumps(value));self.assertFalse(self.b.idle())


if __name__=='__main__':unittest.main()
