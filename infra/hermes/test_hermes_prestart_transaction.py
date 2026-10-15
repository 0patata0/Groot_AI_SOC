"""Synthetic fixed-container lifecycle contracts. No Docker or service calls."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import sqlite3
import hermes_guard_checks as guard_checks
import unittest
from unittest.mock import patch

import hermes_prestart_contract as contract
import hermes_prestart_transaction as tx
from test_hermes_prestart_contract import fixture, NEW_ID

TOKEN = '0123456789ab'
BOOT = 'a'*32
GUARD = 'c'*64
MCP={'uid':995,'gid':986,'servers':{n:{'tools':3,'names_sha256':'e'*64} for n in ('wazuh-ro','security-events','resp','rule-a','rule-b')},'initialize':5,'tools_list':5,'tools_call':0,'model_calls':0,'chat_posts':0,'parents_write_protected':True}

class Scenario:
    def __init__(self):
        self.old,self.new = fixture()
        self.members=[self.old]
        self.snapshot={name:{'exists':True,'sha256':'d'*64,'size':12,'uid':995,'gid':986,'mode':384}
                       for name in tx.PROTECTED}
        self.heartbeat=1760000000.0
        self.plan=tx.init_plan(TOKEN,self.old,self.snapshot,BOOT,MCP)
        self.ledger=tx.initial(self.plan)
    def evidence(self):
        return copy.deepcopy({'containers':self.members,'snapshot':self.snapshot,'boot_id':BOOT,
            'docker_host':{'oom_kill_disable':False,'cgroup_version':'2'},
            'database_ok':True,'guard_sha256':GUARD,'command_container_id':NEW_ID,
            'idle':{'idle':True,'active_leases':0,'heartbeat_age_seconds':1,'observed_at_epoch':time.time()},
            'mcp':MCP,'heartbeat_epoch':self.heartbeat,'runtime_uid':995,'runtime_gid':986,
            'runtime':{'passed':11,'real_chat_posts':0,'runtime_checks':tx.RUNTIME_CHECKS,
                       'unicode_engine':{'package':'regex','version':'2026.9.29'}}})
    def execute(self,action):
        self.ledger=tx.arm(self.plan,self.ledger,action,self.evidence())
        if action=='create': self.members.append(self.new)
        if action=='stop-old': self.old['State'].update(Running=False,Pid=0,Status='exited')
        if action=='retain-old':self.old['Name']='/'+self.plan['retained_name']
        if action=='name-new':self.new['Name']='/hermes'
        if action=='start-new':
            self.new['State'].update(Running=True,Pid=456,Status='running',StartedAt='2026-10-15T00:00:00Z')
            self.new['HostConfig']['OomKillDisable']=None
            self.heartbeat=tx.timestamp('2026-10-15T00:00:02Z')
        if action=='stop-new':self.new['State'].update(Running=False,Pid=0,Status='exited',FinishedAt='2026-10-15T00:00:10Z')
        if action=='park-new':self.new['Name']='/'+self.plan['candidate_name']
        if action=='restore-name':self.old['Name']='/hermes'
        if action=='start-old':
            self.old['State'].update(Running=True,Pid=789,Status='running',StartedAt='2026-10-15T00:01:00Z')
            self.heartbeat=tx.timestamp('2026-10-15T00:01:02Z')
        self.ledger=tx.finish(self.plan,self.ledger,action,self.evidence())
    def through(self,last):
        sequence=['create','install','stop-old','retain-old','name-new','start-new','stop-new','park-new','restore-name','start-old']
        for action in sequence:
            self.execute(action)
            if action==last:break
        return self

class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.p=patch.object(tx,'contract',return_value=contract);self.p.start();self.addCleanup(self.p.stop)
    def test_existing_original_profile_and_plan_digest_are_unchanged(self):
        s=Scenario()
        self.assertEqual(s.plan['profile_sha256'],'ce84f922a54092ce08e4bace3bf7cb99b6f9dc7d4ae681c76c756a97ab3f21fa')
        self.assertEqual(tx.sha(tx.canonical(s.plan)),'2792316eb1bc93788feec4d0fb384ca370cccad7d45dbc4befd2424689433d42')
        self.assertNotEqual(tx.profile(s.new),s.plan['profile_sha256'])
        self.assertEqual(tx.profile(s.new,candidate=True),s.plan['profile_sha256'])
    def test_existing_create_intent_can_finish_observed_candidate_without_create_reissue(self):
        s=Scenario();armed=tx.arm(s.plan,s.ledger,'create',s.evidence());original_plan=tx.canonical(s.plan)
        s.members.append(s.new)
        out=tx.finish(s.plan,armed,'create',s.evidence())
        self.assertEqual((out['phase'],out['candidate_id'],out['intent']),('created',NEW_ID,None))
        self.assertEqual(tx.canonical(s.plan),original_plan)
        with self.assertRaisesRegex(tx.Refused,'unarmed_action'):tx.finish(s.plan,out,'create',s.evidence())
    def test_explicit_candidate_profile_mapping_never_applies_to_original(self):
        s=Scenario().through('create');s.old['Config'].update(AttachStdout=True,AttachStderr=True)
        s.old['HostConfig']['OomKillDisable']=False
        with self.assertRaisesRegex(tx.Refused,'container_profile_changed'):
            tx.check_containers(s.plan,s.members,NEW_ID)
    def test_poststart_requires_daemon_null_and_keeps_evidence_bound(self):
        s=Scenario().through('name-new');armed=tx.arm(s.plan,s.ledger,'start-new',s.evidence())
        s.new['State'].update(Running=True,Pid=456,Status='running',StartedAt='2026-10-15T00:00:00Z')
        s.new['HostConfig']['OomKillDisable']=None;e=s.evidence()
        out=tx.finish(s.plan,armed,'start-new',e)
        self.assertEqual(out['proofs']['start-new'],tx.sha(tx.canonical(e)))
        self.assertEqual(tx.profile(s.new,candidate=True,candidate_started=True),s.plan['profile_sha256'])
        with self.assertRaisesRegex(contract.ContractError,'candidate_never_started_unproved'):
            tx.profile(s.new,candidate=True)
    def test_poststart_boolean_or_missing_oom_value_is_refused(self):
        for value in (False,True,0,'missing'):
            s=Scenario().through('start-new');e=s.evidence()
            new=next(x for x in e['containers'] if x['Id']==NEW_ID)
            if value=='missing':del new['HostConfig']['OomKillDisable']
            else:new['HostConfig']['OomKillDisable']=value
            with self.assertRaisesRegex(contract.ContractError,'candidate_started_oom_default_mismatch'):
                tx.ready(s.plan,s.ledger,e)
    def test_host_capability_is_required_before_and_after_start(self):
        for started in (False,True):
            for host in (None,{'oom_kill_disable':True,'cgroup_version':'2'},
                         {'oom_kill_disable':0,'cgroup_version':'2'},
                         {'oom_kill_disable':False,'cgroup_version':'1'}):
                s=Scenario().through('start-new') if started else Scenario()
                e=s.evidence();e['docker_host']=host
                with self.assertRaisesRegex(tx.Refused,'docker_host_capability_changed'):
                    if started:tx.ready(s.plan,s.ledger,e)
                    else:tx.arm(s.plan,s.ledger,'create',e)
    def test_normal_firststart_commit_and_original_retained(self):
        s=Scenario().through('start-new');out=tx.ready(s.plan,s.ledger,s.evidence(),commit=True)
        self.assertEqual(out['phase'],'committed'); self.assertFalse(out['database_restore'])
        self.assertEqual(s.old['Name'],'/'+s.plan['retained_name']);self.assertFalse(s.old['State']['Running'])
    def test_real_firststart_then_verified_fallback_uses_current_database(self):
        s=Scenario().through('start-new');s.ledger=tx.ready(s.plan,s.ledger,s.evidence())
        s.snapshot['state.db']['sha256']='e'*64
        for action in ['stop-new','park-new','restore-name','start-old']:s.execute(action)
        out=tx.ready(s.plan,s.ledger,s.evidence(),commit=True)
        self.assertEqual(out['phase'],'rolled-back');self.assertEqual(s.snapshot['state.db']['sha256'],'e'*64)
        self.assertFalse(out['original_container_deleted']);self.assertEqual(s.new['Name'],'/'+s.plan['candidate_name'])
    def test_confirmed_firststart_exit_can_restore_original_without_another_new_start(self):
        s=Scenario().through('name-new')
        s.ledger=tx.arm(s.plan,s.ledger,'start-new',s.evidence())
        s.new['State'].update(Running=False,Pid=0,Status='exited',StartedAt='2026-10-15T00:00:00Z',FinishedAt='2026-10-15T00:00:01Z',ExitCode=1)
        s.new['HostConfig']['OomKillDisable']=None
        s.ledger=tx.finish(s.plan,s.ledger,'start-new',s.evidence())
        with self.assertRaisesRegex(tx.Refused,'readiness_identity'):tx.ready(s.plan,s.ledger,s.evidence())
        for action in ['stop-new','park-new','restore-name','start-old']:s.execute(action)
        self.assertEqual(tx.ready(s.plan,s.ledger,s.evidence(),commit=True)['phase'],'rolled-back')
    def test_unproved_never_started_exit_is_not_automatic_fallback(self):
        s=Scenario().through('name-new');armed=tx.arm(s.plan,s.ledger,'start-new',s.evidence())
        with self.assertRaisesRegex(contract.ContractError,'candidate_started_metadata_unproved'):tx.finish(s.plan,armed,'start-new',s.evidence())
    def test_fallback_requires_a_new_original_heartbeat(self):
        s=Scenario().through('start-old');e=s.evidence();e['heartbeat_epoch']=tx.timestamp('2026-10-15T00:00:59Z')
        with self.assertRaisesRegex(tx.Refused,'new_heartbeat_unverified'):tx.ready(s.plan,s.ledger,e)
    def test_expired_idle_observation_is_not_reused(self):
        s=Scenario().through('install');e=s.evidence();e['idle']['observed_at_epoch']=time.time()-6
        with self.assertRaisesRegex(tx.Refused,'idle_observation_expired'):tx.arm(s.plan,s.ledger,'stop-old',e)
    def test_mcp_tools_calls_or_missing_server_or_changed_toolset_refused(self):
        for change in ('call','missing','toolset'):
            s=Scenario().through('start-new');e=s.evidence()
            if change=='call':e['mcp']['tools_call']=1
            if change=='missing':del e['mcp']['servers']['resp']
            if change=='toolset':e['mcp']['servers']['resp']['names_sha256']='f'*64
            with self.assertRaises(tx.Refused):tx.ready(s.plan,s.ledger,e)
    def test_arm_crash_never_reissues_create(self):
        s=Scenario();armed=tx.arm(s.plan,s.ledger,'create',s.evidence())
        with self.assertRaisesRegex(tx.Refused,'action_already_armed_no_retry'):tx.arm(s.plan,armed,'create',s.evidence())
    def test_every_mutation_rejects_an_existing_intent(self):
        s=Scenario()
        for action in tx.TRANSITIONS:
            armed=tx.arm(s.plan,s.ledger,action,s.evidence())
            with self.assertRaisesRegex(tx.Refused,'action_already_armed_no_retry'):tx.arm(s.plan,armed,action,s.evidence())
            s.execute(action)
    def test_created_candidate_id_requires_exact_command_receipt(self):
        s=Scenario();armed=tx.arm(s.plan,s.ledger,'create',s.evidence());s.members.append(s.new)
        e=s.evidence();e['command_container_id']='f'*64
        with self.assertRaisesRegex(tx.Refused,'create_receipt_mismatch'):tx.finish(s.plan,armed,'create',e)
    def test_finish_without_intent_is_refused(self):
        s=Scenario()
        with self.assertRaisesRegex(tx.Refused,'unarmed_action'):tx.finish(s.plan,s.ledger,'create',s.evidence())
    def test_unknown_additional_data_user_even_stopped_refused(self):
        s=Scenario();third=copy.deepcopy(s.new);third['Id']='f'*64;s.members.append(third)
        with self.assertRaisesRegex(tx.Refused,'unexpected_data_mount_user'):tx.arm(s.plan,s.ledger,'create',s.evidence())
    def test_both_gateways_running_is_refused(self):
        s=Scenario().through('install');s.new['State'].update(Running=True,Pid=99,Status='running')
        with self.assertRaisesRegex(contract.ContractError,'candidate_never_started_unproved'):tx.arm(s.plan,s.ledger,'stop-old',s.evidence())
    def test_same_id_profile_environment_drift_is_refused(self):
        for change in ['environment','host','mount']:
            s=Scenario().through('install')
            if change=='environment':s.new['Config']['Env'][-1]='SYNTHETIC_SECRET=changed'
            if change=='host':s.new['HostConfig']['Privileged']=True
            if change=='mount':s.new['Mounts'][0]['RW']=False
            with self.assertRaisesRegex(tx.Refused,'container_profile_changed'):tx.arm(s.plan,s.ledger,'stop-old',s.evidence())
    def test_guarded_candidate_must_never_have_started(self):
        s=Scenario().through('install');s.new['State']['StartedAt']='2026-10-15T00:00:00Z'
        with self.assertRaises(contract.ContractError):tx.arm(s.plan,s.ledger,'stop-old',s.evidence())
    def test_busy_or_old_heartbeat_refuses_before_stop(self):
        for idle in ({'idle':False,'active_leases':0,'heartbeat_age_seconds':1,'observed_at_epoch':time.time()},
                     {'idle':True,'active_leases':1,'heartbeat_age_seconds':1,'observed_at_epoch':time.time()},
                     {'idle':True,'active_leases':0,'heartbeat_age_seconds':15}):
            s=Scenario().through('install');e=s.evidence();e['idle']=idle
            with self.assertRaisesRegex(tx.Refused,'idle_not_fresh'):tx.arm(s.plan,s.ledger,'stop-old',e)
    def test_guard_readback_drift_rejected_before_firststart(self):
        s=Scenario().through('name-new');e=s.evidence();e['guard_sha256']='f'*64
        with self.assertRaisesRegex(tx.Refused,'guard_readback_changed'):tx.arm(s.plan,s.ledger,'start-new',e)
    def test_stopped_database_or_cron_drift_refused_before_firststart(self):
        for path in ('state.db','state.db-wal','cron/jobs.json'):
            s=Scenario().through('name-new');e=s.evidence();e['snapshot'][path]['sha256']='f'*64
            with self.assertRaisesRegex(tx.Refused,'stopped_data_changed'):tx.arm(s.plan,s.ledger,'start-new',e)
    def test_immutable_config_change_refused_at_all_phases(self):
        for path in tx.IMMUTABLE:
            s=Scenario().through('start-new');e=s.evidence();e['snapshot'][path]['sha256']='f'*64
            with self.assertRaisesRegex(tx.Refused,'protected_configuration_changed'):tx.ready(s.plan,s.ledger,e)
    def test_runtime_db_growth_is_allowed_after_firststart(self):
        s=Scenario().through('start-new');e=s.evidence();e['snapshot']['state.db']['size']+=100
        self.assertEqual(tx.ready(s.plan,s.ledger,e)['phase'],'new-started')
    def test_old_heartbeat_cannot_prove_candidate_ready(self):
        s=Scenario().through('start-new');e=s.evidence();e['heartbeat_epoch']=tx.timestamp('2026-10-14T23:59:59Z')
        with self.assertRaisesRegex(tx.Refused,'new_heartbeat_unverified'):tx.ready(s.plan,s.ledger,e)
    def test_new_pid_or_started_at_drift_refused_during_readiness(self):
        for key,value in [('Pid',999),('StartedAt','2026-10-15T00:00:01Z')]:
            s=Scenario().through('start-new');s.new['State'][key]=value
            with self.assertRaisesRegex(tx.Refused,'started_identity_changed'):tx.ready(s.plan,s.ledger,s.evidence())
    def test_real_uid_and_all_eleven_checks_required(self):
        for change in ['uid','missing_check','posts','engine']:
            s=Scenario().through('start-new');e=s.evidence()
            if change=='uid':e['runtime_uid']=0
            if change=='missing_check':e['runtime']['runtime_checks'].pop()
            if change=='posts':e['runtime']['real_chat_posts']=1
            if change=='engine':e['runtime']['unicode_engine']['version']='other'
            with self.assertRaises(tx.Refused):tx.ready(s.plan,s.ledger,e)
    def test_ambiguous_new_stop_prevents_old_start(self):
        s=Scenario().through('start-new');armed=tx.arm(s.plan,s.ledger,'stop-new',s.evidence())
        for fields in ({'Running':True},{'Running':False,'Pid':0,'Restarting':True},{'Running':False,'Pid':42}):
            s.new['State'].update(fields)
        with self.assertRaisesRegex(contract.ContractError,'candidate_started_metadata_unproved'):tx.finish(s.plan,armed,'stop-new',s.evidence())
    def test_partial_stop_or_rename_is_manual_not_automatic_restart(self):
        s=Scenario().through('stop-old')
        with self.assertRaisesRegex(tx.Refused,'wrong_phase'):tx.arm(s.plan,s.ledger,'start-old',s.evidence())
        with self.assertRaisesRegex(tx.Refused,'wrong_phase'):tx.arm(s.plan,s.ledger,'stop-new',s.evidence())
    def test_fallback_stopped_database_must_stay_current(self):
        s=Scenario().through('restore-name');e=s.evidence();e['snapshot']['state.db']['sha256']='f'*64
        with self.assertRaisesRegex(tx.Refused,'fallback_data_changed'):tx.arm(s.plan,s.ledger,'start-old',e)
    def test_reboot_during_transition_refused(self):
        s=Scenario();e=s.evidence();e['boot_id']='f'*32
        with self.assertRaisesRegex(tx.Refused,'boot_changed'):tx.arm(s.plan,s.ledger,'create',e)
    def test_wrong_plan_or_database_restore_ledger_rejected(self):
        for key,value in [('plan_sha256','e'*64),('database_restore',True),('original_container_deleted',True)]:
            s=Scenario();s.ledger[key]=value
            with self.assertRaisesRegex(tx.Refused,'ledger_invalid'):tx.arm(s.plan,s.ledger,'create',s.evidence())
    def test_duplicate_and_nonfinite_json_refused(self):
        for raw in ['{"a":1,"a":2}','{"a":NaN}','{}{}']:
            with self.assertRaises(tx.Refused):tx.parse(raw)
    def test_durable_exclusive_cas_and_file_fsync_failure(self):
        # Pure temp fixture: no production path, service, container or package access.
        with tempfile.TemporaryDirectory() as directory, patch.object(tx,'trusted_parent'):
            p=Path(directory)/'ledger.json'
            original_read=tx.read
            with patch.object(tx,'read',side_effect=lambda path,*a,**k:original_read(path,*a,**dict(k,trusted=False))):
                tx.durable(p,b'original\n')
                with self.assertRaisesRegex(tx.Refused,'receipt_exists'):tx.durable(p,b'rewrite\n')
                with self.assertRaisesRegex(tx.Refused,'receipt_cas_conflict'):tx.durable(p,b'new\n',expected='0'*64)
                with patch.object(tx.os,'fsync',side_effect=OSError('synthetic')):
                    with self.assertRaises(OSError):tx.durable(p,b'new\n',expected=tx.sha(b'original\n'))
                self.assertEqual(p.read_bytes(),b'original\n')
                tx.durable(p,b'new\n',expected=tx.sha(b'original\n'))
                self.assertEqual(p.read_bytes(),b'new\n')
    def test_symlink_receipt_refused(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(tx,'trusted_parent'):
            p=Path(directory)/'link';p.symlink_to(Path(directory)/'absent')
            with self.assertRaisesRegex(tx.Refused,'receipt_exists'):tx.durable(p,b'value')

class PackageReadbackTests(unittest.TestCase):
    def setUp(self):
        import base64
        import csv
        import hashlib
        import io
        import zipfile
        from contextlib import ExitStack
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.package=self.root/tx.REGEX_REL;self.package.mkdir(parents=True)
        self.record='regex-2026.9.29.dist-info/RECORD'
        payload={'regex/payload%d.py'%i:b'# synthetic package\n' for i in range(9)}
        payload[self.record]=b''
        wheel=self.root/'synthetic.whl'
        with zipfile.ZipFile(wheel,'w') as archive:
            for name,raw in payload.items():archive.writestr(name,raw)
        files=dict(payload)
        files.update({'regex-2026.9.29.dist-info/'+name:b'' for name in ('INSTALLER','REQUESTED','uv_cache.json')})
        rows=[]
        for name,raw in files.items():
            rows.append([name,'',''] if name==self.record else [name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='),str(len(raw))])
        output=io.StringIO();csv.writer(output).writerows(rows);files[self.record]=output.getvalue().encode()
        files['.lock']=b''
        for name,raw in files.items():
            path=self.package/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
        guard_bytes=b'# synthetic source\n'
        guards={name:tx.sha(guard_bytes) for name in tx.FILES}
        for name in guards:
            path=self.root/'hermes'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(guard_bytes);path.chmod(0o644)
        wheel.chmod(0o644);self.wheel=wheel;self.files=files;self.guards=guards
        self.stack.enter_context(patch.object(tx,'FILES',guards))
        self.stack.enter_context(patch.object(tx,'WHEEL_SHA',tx.sha(wheel.read_bytes())))
        self.stack.enter_context(patch.object(tx,'trusted_parent'))
        # Native root retains exact owner checks; Mac fixture skips only UID/GID.
        if os.geteuid()!=0:
            original=tx.read
            self.stack.enter_context(patch.object(tx,'read',side_effect=lambda p,*a,**k:original(p,*a,**dict(k,trusted=False))))
    def verify(self):return tx.verify_tree(self.root,self.wheel)
    def test_empty_uv_lock_is_seventeenth_hashed_file_outside_record(self):
        result=self.verify();expected={'hermes/'+k:v for k,v in self.guards.items()}
        expected.update({tx.REGEX_REL+'/'+k:tx.sha(v) for k,v in self.files.items()})
        self.assertEqual(result,{'guard_sha256':tx.sha(tx.canonical(expected)),'files':17,'native_code_executed':False})
    def test_nonempty_uv_lock_is_refused(self):
        (self.package/'.lock').write_bytes(b'x')
        with self.assertRaises(tx.Refused):self.verify()
    def test_uv_lock_directory_symlink_hardlink_and_wrong_mode_are_refused(self):
        lock=self.package/'.lock';lock.unlink();lock.mkdir()
        with self.assertRaises(tx.Refused):self.verify()
        lock.rmdir();target=self.root/'empty';target.write_bytes(b'');target.chmod(0o644);lock.symlink_to(target)
        with self.assertRaises((tx.Refused,OSError)):self.verify()
        lock.unlink();os.link(target,lock)
        with self.assertRaises(tx.Refused):self.verify()
        lock.unlink();lock.write_bytes(b'');lock.chmod(0o600)
        with self.assertRaisesRegex(tx.Refused,'wrong_file_mode'):self.verify()
    def test_uv_lock_cannot_replace_a_record_member(self):
        path=self.package/self.record
        path.write_text(path.read_text().replace('regex-2026.9.29.dist-info/REQUESTED,','.lock,'))
        with self.assertRaisesRegex(tx.Refused,'regex_record_paths'):self.verify()
    @unittest.skipUnless(os.geteuid()==0,'native root owner boundary')
    def test_uv_lock_nonroot_owner_or_group_is_refused(self):
        lock=self.package/'.lock'
        for uid,gid in ((995,0),(0,986)):
            os.chown(lock,uid,gid)
            with self.assertRaisesRegex(tx.Refused,'unsafe_owner_mode'):self.verify()
        os.chown(lock,0,0)

class PrivateSQLiteChecks(unittest.TestCase):
    def setup_data(self,directory,wal):
        data=Path(directory)/'data';data.mkdir();(data/'cron').mkdir()
        for name in (*tx.IMMUTABLE,'cron/jobs.json'):(data/name).write_text('synthetic')
        (data/'gateway_state.json').write_text(json.dumps({'gateway_state':'running','active_agents':0,'active_work':False,'updated_at':100}))
        db=sqlite3.connect(data/'state.db')
        if wal:db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA wal_autocheckpoint=0')
        db.execute('CREATE TABLE session_turn_leases(expires_at REAL)');db.commit()
        if wal:db.execute('INSERT INTO session_turn_leases VALUES(200)');db.commit()
        else:db.close();db=None
        return data,db
    def test_live_wal_is_included_without_touching_original_sidecars(self):
        with tempfile.TemporaryDirectory() as root:
            data,db=self.setup_data(root,True)
            try:
                before=guard_checks.snapshot(data);names=sorted(x.name for x in data.iterdir())
                real=sqlite3.connect;opened=[]
                def connect(database,*a,**kw):opened.append(database);self.assertNotIn(str(data),str(database));return real(database,*a,**kw)
                with patch.object(tx.sqlite3,'connect',side_effect=connect):
                    result=tx.capture_data(data,root,guard_checks,now=100)
                self.assertEqual(result['active_leases'],1)
                self.assertEqual(guard_checks.snapshot(data),before)
                self.assertEqual(sorted(x.name for x in data.iterdir()),names)
                self.assertEqual(len(opened),1);self.assertNotIn('immutable=1',opened[0])
                self.assertEqual([x.name for x in Path(root).iterdir()],['data'])
            finally:db.close()
    def test_stopped_database_gets_no_operating_wal_or_shm(self):
        with tempfile.TemporaryDirectory() as root:
            data,_=self.setup_data(root,False);before=guard_checks.snapshot(data)
            self.assertFalse(before['state.db-wal']['exists']);self.assertFalse(before['state.db-shm']['exists'])
            result=tx.capture_data(data,root,guard_checks,now=100)
            self.assertEqual(result['active_leases'],0);self.assertEqual(guard_checks.snapshot(data),before)
            self.assertFalse((data/'state.db-wal').exists());self.assertFalse((data/'state.db-shm').exists())
    def test_original_source_change_during_copy_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            data,_=self.setup_data(root,False);original=tx.read
            def change(path,*a,**kw):
                value=original(path,*a,**kw)
                if Path(path).name=='state.db':(data/'SOUL.md').write_text('changed')
                return value
            with patch.object(tx,'read',side_effect=change):
                with self.assertRaisesRegex(tx.Refused,'data_changed_during_validation'):tx.capture_data(data,root,guard_checks,now=100)

class NativeOrchestrationContractTests(unittest.TestCase):
    def setUp(self):self.base=Path(__file__).parents[1]/'automation/ansible';self.role=self.base/'roles/hermes_prestart/tasks'
    def tasks(self,name):return json.loads((self.role/name).read_text())
    def test_native_docker_operations_have_no_retry_or_shell(self):
        source=(self.base/'hermes-prestart-b.yml').read_text();play=json.loads(source)[0]
        self.assertEqual(set(play['vars']['hp_commands']),set(tx.TRANSITIONS)-{'install'})
        for name,argv in play['vars']['hp_commands'].items():
            self.assertEqual(argv[0],'/usr/local/bin/docker');self.assertNotIn('rm',argv)
        action=self.tasks('action.yml');mutation=action[8]
        self.assertIn('Persist fsynced one-shot intent',action[6]['name'])
        self.assertNotIn('until',mutation);self.assertNotIn('retries',mutation)
        self.assertFalse(any('ansible.builtin.shell' in t for path in self.role.glob('*.yml') for t in self.tasks(path.name)))
    def test_fallback_exercise_is_after_actual_runtime_readiness(self):
        block=self.tasks('cutover.yml')[-1]['block']
        self.assertEqual(block[0]['ansible.builtin.include_tasks'],'ready.yml')
        self.assertIn('after successful firststart',block[2]['name'])
        actions=self.tasks('fallback.yml')[2]['loop']
        self.assertEqual(actions,['stop-new','park-new','restore-name','start-old'])
    def test_prepare_never_starts_and_copies_before_readback(self):
        self.assertEqual(self.tasks('prepare.yml')[-1]['loop'],['create','install'])
        self.assertEqual(self.tasks('cutover.yml')[2]['loop'],['stop-old','retain-old','name-new','start-new'])
    def test_source_pins_match_and_runtime_uses_actual_uid_no_model(self):
        variables=json.loads((self.base/'hermes-prestart-b.yml').read_text())[0]['vars']
        pins=variables['capstone_prestart_sources']
        for name,digest in pins.items():self.assertEqual(tx.sha(Path(__file__).with_name(name).read_bytes()),digest)
        self.assertEqual(tx.sha((self.role.parent/'files/mcp-readonly.py').read_bytes()),variables['capstone_prestart_mcp_sha256'])
        argv=self.tasks('ready.yml')[1]['ansible.builtin.command']['argv']
        self.assertIn('995:986',argv);self.assertNotIn('--model',argv)
    def test_python_helper_has_no_subprocess_or_docker_mutation(self):
        import ast
        tree=ast.parse(Path(tx.__file__).read_text())
        imported={n.names[0].name for n in ast.walk(tree) if isinstance(n,ast.Import)}
        self.assertFalse(imported & {'subprocess','requests','docker'})
    def test_released_cli_remains_fixed_root_host_and_lock_only(self):
        source=(self.base/'hermes-prestart-local-b.sh').read_text()
        self.assertNotIn('prestart_lifecycle_candidate_not_released',source)
        self.assertIn('$(id -u) == 0',source)
        self.assertIn(tx.MID,source)
        self.assertIn('flock -n 9',source)
        self.assertIn('capstone_prestart_probe_fallback=true',source)

class MCPProbeCompatibilityTests(unittest.TestCase):
    def test_v2_model_fields_and_paginated_result_refusal_close_contexts(self):
        # SDK 2.0 uses snake_case attributes; camelCase is only a wire alias.
        # No SDK install, SSH process, or endpoint access in this regression.
        import asyncio
        from contextlib import asynccontextmanager
        from types import ModuleType, SimpleNamespace
        source=Path(__file__).parents[1]/'automation/ansible/roles/hermes_prestart/files/mcp-readonly.py'
        probe={'__name__':'mcp_probe_test'}
        exec(compile(source.read_text(),str(source),'exec'),probe)
        for cursor in (None,'another-page'):
            with self.subTest(next_cursor=cursor):
                calls=[]
                class Session:
                    def __init__(self,*args):pass
                    async def __aenter__(self):return self
                    async def __aexit__(self,*args):calls.append('session_closed')
                    async def initialize(self):
                        calls.append('initialize')
                        return SimpleNamespace(server_info=SimpleNamespace(name='synthetic'))
                    async def list_tools(self):
                        calls.append('tools/list')
                        return SimpleNamespace(next_cursor=cursor,tools=[SimpleNamespace(name='read-only')])
                @asynccontextmanager
                async def transport(server,errlog):
                    try:yield object(),object()
                    finally:calls.append('transport_closed')
                sdk=ModuleType('mcp');sdk.ClientSession=Session;sdk.StdioServerParameters=SimpleNamespace
                stdio=ModuleType('mcp.client.stdio');stdio.stdio_client=transport
                with patch.dict('sys.modules',{'mcp':sdk,'mcp.client':ModuleType('mcp.client'),'mcp.client.stdio':stdio}):
                    if cursor is None:
                        result=asyncio.run(probe['request'](['mcp-b']))
                        self.assertEqual(result['tools'],1)
                        self.assertEqual(len(result['names_sha256']),64)
                    else:
                        with self.assertRaisesRegex(ValueError,'read_only_probe_failed'):
                            asyncio.run(probe['request'](['mcp-b']))
                self.assertEqual(calls,['initialize','tools/list','session_closed','transport_closed'])

if __name__=='__main__':unittest.main(verbosity=2)
