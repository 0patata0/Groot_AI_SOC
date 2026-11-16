"""Exact-plan operator lifecycle combining sources, cache and native services.

No CLI, network listener, model tool or arbitrary command API. The separately
reviewed runtime must stage root-private approved artifacts and authenticated
peer observations. Source confirmation is not operating/chat acceptance.
"""
from datetime import datetime,timedelta
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
c=load('release_lifecycle_contract','release_status.py')
cohort=load('release_lifecycle_cohort','cohort_guard.py')
source=load('release_lifecycle_sources','release_files.py')
plans=load('release_lifecycle_plan','release_plan.py')
need=c.need
Refused=c.Refused
OPS=frozenset({'prepare','arm','quiesce','backup','apply','verify','confirm','resume','rollback','revert_fence','revert','recover'})


def digest(value):return hashlib.sha256(c.canonical(value)).hexdigest()


class Lifecycle:
    def __init__(self,files,cache,journal,store,controls,native,helpers,readers,*,clock=None):
        self.files,self.cache,self.journal,self.store=files,cache,journal,store
        self.controls,self.native,self.helpers,self.readers=controls,native,helpers,readers
        self.w=files.witness;self.host=files.host
        need(all(getattr(item,'files',None)is files for item in (journal,store,controls,helpers,readers))
             and journal.plan==store.plan and readers.controls is controls and readers.journal is journal,'lifecycle_binding')
        need(cache.root==files.root and cache.storage==files.storage/'cache'and cache.host==self.host
             and native.root==files.root and native.host==self.host and native.fixture==self.w.fixture
             and cache.production is not self.w.fixture,'lifecycle_filesystem_binding')
        need(clock is None or self.w.fixture and callable(clock),'lifecycle_clock_boundary')
        self.clock=clock or(lambda:datetime.now(c.KST))
        plan=store.read('plan.json');self.contract=plans.Plan(plan)
        need(isinstance(plan,dict)and type(plan.get('schema'))is int and plan['schema']==1 and plan.get('release_id')==files.release_id
             and digest(plan)==store.plan and isinstance(plan.get('hosts'),dict)and set(plan['hosts'])==set(c.TARGETS),'lifecycle_plan')
        need(plan['hosts'][self.host]['rows']==files.rows,'lifecycle_source_rows')
        self.plan=plan;self.cohort=cohort.Cohort(plan['cohort'])
        own=plan['hosts'][self.host]
        need(self.w.gid==own['diagnostic_gid']and readers.uids=={own['reader_uid']}|({own['mcp_uid']}if self.host=='b'else set())
             and native.container==own['container'],'lifecycle_account_container_binding')
        for host,rows in self.cohort.rows.items():
            full=plan['hosts'][host]['rows']
            need(isinstance(full,list)and len(full)==len(source.TARGETS[host])and {r['target']for r in full}==source.TARGETS[host]
                 and {r['target']:r for r in full if r['target']not in source.BARRIERS[host]}==rows,'lifecycle_cohort_binding')

    def authorize(self,*,recovery=False,revert=False,protected=True):
        self.contract.verify(self.files,protected=protected)
        name='revert-approval.json'if revert else 'approval.json';value=self.store.read(name)
        need(isinstance(value,dict)and set(value)=={'schema','release_id','plan_sha256','bundle_sha256','decision',
             'approved_at_kst','expires_at_kst','reference'}and type(value['schema'])is int and value['schema']==1
             and value['release_id']==self.files.release_id and value['plan_sha256']==self.store.plan
             and value['decision']=='approved'and isinstance(value['reference'],str)
             and re.fullmatch(r'[A-Za-z0-9_:/.-]{1,160}',value['reference']),'exact_approval_required')
        bundle=self.store.read('bundle.json')
        need(bundle==self.contract.bundle()
             and value['bundle_sha256']==digest(bundle),'approval_bundle_changed')
        before=datetime.fromisoformat(value['approved_at_kst']);until=datetime.fromisoformat(value['expires_at_kst']);now=self.clock()
        need(all(t.utcoffset()==timedelta(hours=9)for t in (before,until,now))
             and 0<(until-before).total_seconds()<=1800 and before<=now,'approval_clock')
        need(recovery or now<until,'approval_expired')
        return value

    def state(self):return self.journal.read()[0]

    def core_is(self,key):
        for row in self.files.rows:
            if row['target']in source.BARRIERS[self.host]:continue
            raw,_=self.files.read_target(row)
            if(hashlib.sha256(raw).hexdigest()if raw is not None else None)!=row[key]:return False
        return True

    def baseline(self):
        value=self.store.read('baseline.json');need(digest(value)==self.state()['facts'].get('baseline_sha256'),'baseline_receipt_changed')
        need(isinstance(value,dict)and set(value)=={'schema','host','release_id','units','container','previous_current'}
             and value['schema']==1 and value['host']==self.host and value['release_id']==self.files.release_id,'baseline_identity')
        return value

    def initialize(self,deadline):
        """Stage only; no units, source or live cache are changed here."""
        with self.store.locked(),self.journal.locked():
            approval=self.authorize();need(deadline<=datetime.fromisoformat(approval['expires_at_kst']),'deadline_exceeds_approval')
            previous,previous_sha=self.store.current()
            need(previous_sha==self.plan['hosts'][self.host]['previous_current_sha256'],'previous_current_changed')
            self.store.claim();self.files.check('before_sha256');self.files.payloads('candidates','after_sha256')
            self.files.backup();units=self.native.snapshot()
            need(all(v['ActiveState']not in ('activating','deactivating')for v in units.values()),'baseline_units_transitioning')
            need(all(v.get('KillMode')in ('control-group','mixed')for n,v in units.items()
                if n.endswith('.service')and v['LoadState']=='loaded'),'baseline_kill_mode')
            need(all(v['LoadState']=='not-found'or set(v.get('DropInPaths','').split())==self.native.baseline_dropins(n)
                for n,v in units.items()),'unreviewed_baseline_dropin')
            container=self.native.require_original_container()if self.host=='b'else None
            value={'schema':1,'host':self.host,'release_id':self.files.release_id,'units':units,'container':container,
                   'previous_current':previous}
            self.store.immutable('baseline.json',value)
            self.store.immutable('witness.json',{'schema':1,'host':self.host,'release_id':self.files.release_id,
                'reader_uid':self.plan['hosts'][self.host]['reader_uid'],'rows':[r for r in self.files.rows if r['target']not in source.BARRIERS[self.host]]})
            self.journal.initialize(deadline,now=self.clock())
            self.journal.mark(now=self.clock(),baseline_sha256=digest(value),rollback_ready=True)
            return self.state()

    def local_proof(self):
        return self.w.answer({'schema':1,'host':self.host,'release_id':self.files.release_id})

    def coherent(self,proofs,intent):
        need(isinstance(proofs,dict)and set(proofs)==set(c.TARGETS),'peer_proof_set')
        proofs={**proofs,self.host:self.local_proof()}
        # Only the explicit filesystem fixture may project its tagged local
        # proofs into the unchanged pure operating-contract validator. Stored
        # evidence retains its real fixture tag; the production path never
        # accepts that projection or a fixture proof.
        checked={}
        for host,value in proofs.items():
            need(isinstance(value,dict)and value.get('isolated_filesystem')is self.w.fixture,'peer_proof_environment')
            checked[host]={**value,'isolated_filesystem':False}if self.w.fixture else value
        gate=self.cohort.check(checked,intent,now=self.clock());need(gate['allow'],'coherent_peer_proof_required')
        return {'intent':intent,'proofs':proofs,'gate':gate,'isolated_filesystem':self.w.fixture}

    def require_fences(self):
        need(self.controls.fenced('collection')and self.controls.fenced('consumer'),'lifecycle_fences_required')
        if self.host=='b':need(self.controls.fenced('mcp'),'lifecycle_mcp_fence_required')

    def baseline_coherent(self,proofs,phases):
        need(isinstance(proofs,dict)and set(proofs)==set(c.TARGETS),'peer_proof_set')
        proofs={**proofs,self.host:self.local_proof()};checked={}
        for host,value in proofs.items():
            need(isinstance(value,dict)and value.get('isolated_filesystem')is self.w.fixture
                 and value.get('phase')in phases,'peer_preparation_phase')
            checked[host]={**value,'phase':'rolled_back','isolated_filesystem':False}
        gate=self.cohort.check(checked,'resume_baseline',now=self.clock());need(gate['allow'],'coherent_baseline_proof_required')
        return {'proofs':proofs,'gate':gate,'required_phases':sorted(phases),'isolated_filesystem':self.w.fixture}

    def fence(self):
        for name in self.controls.markers:self.controls.fence(name)
        self.native.run(['/usr/bin/systemctl','daemon-reload']);self.require_fences()

    def quiesced(self):
        self.require_fences();need(self.native.stopped('collection')and self.native.stopped('consumer'),'lifecycle_services_not_quiesced')
        if self.host=='b':
            value=self.native.docker();need(not value['running']and value['pid']==0 and value['restart']['Name']=='no','lifecycle_container_not_quiesced')
        need(not self.readers.snapshot(),'lifecycle_readers_not_quiesced')

    def _stop_consumers(self):
        self.native.stop_timers('consumer');deadline=time.monotonic()+30
        while not self.idle():
            need(time.monotonic()<deadline,'consumer_work_still_running');time.sleep(0.2)
        self.native.stop_services('consumer');self.native.wait_stopped('consumer')
        if self.host=='b':self.native.stop_container()

    def _stop(self):
        self._stop_consumers()
        self.native.stop('collection');self.native.wait_stopped('collection');proof=self.readers.drain();self.quiesced();return proof

    def _record(self,nonce,operation,value):
        name='operation-'+nonce+'.json';old=self.store.read(name,absent=True)
        if old is not None:
            need(isinstance(old,dict)and set(old)=={'schema','host','release_id','plan_sha256','nonce','operation','at_kst','evidence','isolated_filesystem'}
                 and old['schema']==1 and old['host']==self.host and old['release_id']==self.files.release_id
                 and old['plan_sha256']==self.store.plan and old['nonce']==nonce and old['operation']==operation
                 and old['isolated_filesystem']is self.w.fixture,'operation_receipt_changed')
            return digest(old)
        result={'schema':1,'host':self.host,'release_id':self.files.release_id,'plan_sha256':self.store.plan,'nonce':nonce,
            'operation':operation,'at_kst':self.clock().isoformat(),'evidence':value,'isolated_filesystem':self.w.fixture}
        self.store.immutable(name,result);return digest(result)

    def execute(self,operation,*,proofs=None):
        need(isinstance(operation,str)and operation in OPS,'lifecycle_operation')
        with self.store.locked(),self.journal.locked():
            self.store.require_active();phase=self.state()['phase']
            self.authorize(recovery=operation in ('recover','rollback')or operation=='resume'and phase=='rolled_back',
                revert=operation in ('revert_fence','revert'),protected=operation not in ('recover','rollback'))
            self.baseline()
            if operation=='recover':return self.recover()
            need(not self.state()['facts'].get('completion_prepared'),'completion_already_prepared')
            if operation=='rollback':return self.rollback()
            if operation=='revert':return self.revert(proofs)
            if operation=='resume':return self.resume(proofs)
            self.helpers.armed()if operation!='prepare'else None
            gate=None
            if operation=='confirm':gate=self.coherent(proofs,'confirm_b'if self.host=='b'else 'confirm_peers')
            elif operation=='arm':gate=self.baseline_coherent(proofs,{'staged','armed','quiesced','backed_up'})
            elif operation=='apply':gate=self.baseline_coherent(proofs,{'backed_up'})
            nonce=self.journal.begin(operation,now=self.clock())
            if operation=='prepare':
                self.controls.install();self.helpers.arm();self.files.install_barriers()
                self._record(nonce,operation,{'helpers_prepared':True,'normal_baseline_reads_retained':True})
                self.journal.finish(nonce,now=self.clock(),helpers_prepared=True,barriers_installed=True)
            elif operation=='arm':
                self.fence();self._record(nonce,operation,gate)
                self.journal.finish(nonce,now=self.clock(),fence_installed=True,barriers_installed=True)
            elif operation in ('quiesce','revert_fence'):
                self.fence();drained=self._stop();receipt=self._record(nonce,operation,{'drain':drained,'units':self.native.snapshot()})
                if operation=='quiesce':
                    cache=self.cache.inspect(self.cache.path,live=True)[2]
                    need(cache['metadata'].get('source_filter_policy')is None,'legacy_quiescence_required')
                    self.store.immutable('quiescence.json',{'cache':cache,'receipt_sha256':receipt})
                    self.journal.finish(nonce,now=self.clock(),services_quiesced=True)
                else:self.journal.finish(nonce,now=self.clock(),revert_fenced=True,revert_fence_sha256=receipt)
            elif operation=='backup':
                self.quiesced();need(self.core_is('before_sha256'),'baseline_core_required')
                self.files.payloads('backups','before_sha256');cache=self.cache.prepare()
                need(cache==self.store.read('quiescence.json')['cache'],'cache_changed_after_quiescence')
                self._record(nonce,operation,{'cache':cache});self.journal.finish(nonce,now=self.clock(),source_backup=True,cache_backup=True)
            elif operation=='apply':
                self.quiesced();before=self.cache.saved('before')[1]
                need(self.cache.inspect(self.cache.path,live=True)[2]==before,'cache_changed_after_backup')
                self.files.apply();self._record(nonce,operation,{'sources_after':True,'baseline_decision':gate});self.journal.finish(nonce,now=self.clock())
            elif operation=='verify':
                self.quiesced();self.files.check('after_sha256');self.controls.unfence('collection')
                self.native.bootstrap_collection(backfill=True);cache=self.cache.inspect(self.cache.path,live=True)[2]
                need(cache['metadata'].get('source_filter_policy')=='application-severity-v1','candidate_cache_policy_required')
                receipt=self._record(nonce,operation,{'cache':cache,'units':self.native.snapshot()})
                self.journal.finish(nonce,now=self.clock(),verification_sha256=receipt)
            elif operation=='confirm':
                self.files.check('after_sha256');need(self.controls.fenced('consumer'),'consumers_must_remain_fenced')
                receipt=self._record(nonce,operation,gate);self.journal.finish(nonce,now=self.clock(),confirmation_sha256=receipt)
            return self.state()

    def restore(self,nonce,operation):
        self.fence()
        barrier_values=[]
        for row in self.files.rows:
            if row['target']in source.BARRIERS[self.host]:
                raw,_=self.files.read_target(row);barrier_values.append(hashlib.sha256(raw).hexdigest()==row['after_sha256'])
        if not all(barrier_values):self.files.complete_barriers()
        self._stop();facts=self.state()['facts']
        if not facts.get('source_restored'):
            self.files.restore_core();self.journal.mark(now=self.clock(),source_restored=True)
        need(self.core_is('before_sha256'),'source_restore_checkpoint_invalid')
        if not self.state()['facts'].get('cache_restored'):
            if facts.get('cache_backup'):cache=self.cache.restore()
            else:
                # No candidate publisher may run before a verified cache
                # backup. A crash during its creation can leave a partial
                # private artifact; it must not force a restore from it.
                value=self.cache.inspect(self.cache.path,live=True)[2]
                need(value['metadata'].get('source_filter_policy')is None,'unbacked_candidate_cache')
                cache={'changed':False,'legacy_cache_preserved':True,'sha256':value['sha256']}
            self.journal.mark(now=self.clock(),cache_restored=True)
        else:
            # Never restore again after a durable checkpoint: that could erase
            # legitimate legacy observations written after collection resumed.
            value=self.cache.inspect(self.cache.path,live=True)[2]
            need(value['metadata'].get('source_filter_policy')is None,'cache_restore_checkpoint_invalid')
            cache={'changed':False,'checkpoint_verified':True,'sha256':value['sha256']}
        # Only after both durable restoration checkpoints may legacy writers
        # restart. Bots/monitors remain fenced until a fresh coherent cohort.
        self.controls.unfence('collection');self.native.run(['/usr/bin/systemctl','daemon-reload'])
        self.native.resume_original('collection',self.baseline()['units'])
        receipt=self._record(nonce,operation,{'cache':cache,'sources_before':True})
        self.journal.finish(nonce,now=self.clock(),rollback_receipt_sha256=receipt)
        return self.state()

    def rollback(self):
        value=self.state();pending=value['pending']
        # A lost final acknowledgement already moved the phase to rolling_back.
        # Keep the original no-op decision instead of stopping live services on
        # the next recovery pass. The pending intent is durable before any work.
        staged=value['phase']=='staged' or bool(pending and pending['name']=='rollback'and pending['from_phase']=='staged')
        if pending and pending['name']=='rollback':nonce=pending['nonce']
        else:nonce=self.journal.begin('rollback',now=self.clock())
        if staged:
            need(self.core_is('before_sha256'),'staged_core_changed')
            need(self.w.cache()=={'status':'observed','source_filter_policy':None},'staged_cache_policy_changed')
            self.files.check('before_sha256','after_sha256')
            receipt=self._record(nonce,'rollback',{'staged_core_and_legacy_cache_unchanged':True,'services_untouched':True})
            self.journal.finish(nonce,now=self.clock(),source_restored=True,cache_restored=True,
                services_untouched=True,rollback_receipt_sha256=receipt)
            return self.state()
        return self.restore(nonce,'rollback')

    def revert(self,proofs):
        """A fresh all-host fence decision must be durable before restoring.

        The runtime must obtain these control records over the authenticated
        administrator route, never from model output or a public MCP request.
        A partially confirmed partition remains fenced for reconciliation.
        """
        value=self.state();pending=value['pending']
        if pending and pending['name']=='revert':return self.restore(pending['nonce'],'revert')
        if value['facts'].get('revert_authorization_sha256'):
            self.authorize(recovery=True,revert=True,protected=False);saved=self.store.read('revert.json')
            need(digest(saved['proofs'])==saved['authorization_sha256']==value['facts']['revert_authorization_sha256'],'revert_decision_changed')
            nonce=self.journal.begin('revert',now=self.clock());return self.restore(nonce,'revert')
        need(value['phase']=='rolling_back'and value['facts'].get('revert_fenced'),'revert_fence_required')
        need(isinstance(proofs,dict)and set(proofs)==set(c.TARGETS),'revert_peer_proof_set');times=[]
        proofs={**proofs,self.host:self.local_control_proof()}
        for host,record in proofs.items():
            need(isinstance(record,dict)and set(record)=={'schema','host','release_id','plan_sha256','at_kst','fenced','source','isolated_filesystem'}
                 and type(record['schema'])is int and record['schema']==1 and record['host']==host
                 and record['release_id']==self.files.release_id and record['plan_sha256']==self.store.plan
                 and record['fenced']is True and record['isolated_filesystem']is self.w.fixture,'revert_peer_fence')
            stamp=datetime.fromisoformat(record['at_kst']);need(stamp.utcoffset()==timedelta(hours=9)
                and -2<=(self.clock()-stamp).total_seconds()<=15,'revert_peer_freshness');times.append(stamp)
            source_proof=record['source'];need(source_proof.get('phase')=='rolling_back','revert_peer_phase')
            # Reuse the frozen common source/cache/freshness validator, with
            # its verify phase projected only after the raw revert phase and
            # fenced native state have independently been checked above.
        need((max(times)-min(times)).total_seconds()<=5,'revert_peer_span')
        projected={host:{**record['source'],'phase':'verified','isolated_filesystem':False}for host,record in proofs.items()}
        need(all(record['source'].get('isolated_filesystem')is self.w.fixture for record in proofs.values()),'revert_source_environment')
        need(self.cohort.check(projected,'verify_candidate',now=self.clock())['allow'],'revert_source_proof_required')
        self.quiesced();self.files.check('after_sha256');authorization=digest(proofs)
        self.store.immutable('revert.json',{'proofs':proofs,'authorization_sha256':authorization})
        self.journal.mark(now=self.clock(),revert_authorization_sha256=authorization)
        nonce=self.journal.begin('revert',now=self.clock());return self.restore(nonce,'revert')

    def resume(self,proofs):
        value=self.state();pending=value['pending']
        need(pending is None or pending['name']=='resume','outcome_requires_inspection')
        candidate=value['phase']=='confirmed';need(candidate or value['phase']=='rolled_back','stable_cohort_required')
        self.helpers.armed();baseline=self.baseline()
        for group in ('collection','consumer'):self.native.loaded_matches(group,baseline['units'])
        gate=self.coherent(proofs,'resume_candidate'if candidate else 'resume_baseline')
        if candidate:self.files.check('after_sha256')
        else:need(self.core_is('before_sha256'),'baseline_core_required')
        nonce=pending['nonce']if pending else self.journal.begin('resume',now=self.clock())
        self.controls.unfence('collection');self.native.resume_original('collection',baseline['units'])
        self.controls.unfence('consumer')
        if self.host=='b':self.controls.unfence('mcp')
        self.native.resume_original('consumer',baseline['units'])
        if self.host=='b':self.native.resume_container()
        receipt=self._record(nonce,'resume',gate)
        if candidate:self.journal.finish(nonce,now=self.clock(),services_resumed=True,resume_sha256=receipt)
        else:self.journal.finish(nonce,now=self.clock(),baseline_services_resumed=True,baseline_resume_sha256=receipt)
        return self.state()

    def recover(self):
        value=self.state();pending=value['pending']
        # Finalization changes only owned relay/control artifacts after a
        # coherent accepted outcome. Never stop functioning bots because an
        # acknowledgement for that housekeeping operation was lost.
        if pending and pending['name']in ('completion_prepare','cleanup'):
            need(value['phase']in ('confirmed','rolled_back'),'completion_stable_phase')
            need(self.core_is('after_sha256'if value['phase']=='confirmed'else'before_sha256'),'completion_core_changed')
            return value
        if value['phase']=='staged'and pending is None and datetime.fromisoformat(value['deadline_kst'])>self.clock():return value
        if value['phase']=='confirmed':
            if pending:
                self.fence();self._stop_consumers()
                raise Refused('confirmed_resume_requires_reconciliation')
            return value
        if value['phase']=='rolled_back':
            if pending:
                self.fence();self._stop_consumers()
                raise Refused('baseline_resume_requires_reconciliation')
            return value
        if value['facts'].get('revert_fenced')or pending and pending['name']=='revert_fence':
            self.fence()
            if value['facts'].get('revert_authorization_sha256'):
                return self.revert(None)
            raise Refused('coordinated_revert_proof_required')
        need(datetime.fromisoformat(value['deadline_kst'])<=self.clock()or pending is not None,'recovery_not_due')
        return self.rollback()

    def local_control_proof(self):
        """Root operator read; the separate transport authenticates this record."""
        _,before=self.journal.read();proof=self.local_proof()
        try:self.quiesced();fenced=True
        except (OSError,ValueError,KeyError):fenced=False
        _,after=self.journal.read();need(before==after,'control_observation_changed')
        return {'schema':1,'host':self.host,'release_id':self.files.release_id,'plan_sha256':self.store.plan,
            'at_kst':self.clock().isoformat(),'fenced':fenced,'source':proof,'isolated_filesystem':self.w.fixture}

    def idle(self):
        """Read aggregates only; never migrate, finish or edit an existing job."""
        units=self.native.snapshot()
        for name,row in units.items():
            if name.endswith('.service')and name not in ('capstone-journal-reader.service','capstone-ollama-chat.service','capstone-review-chat.service'):
                # Root managers/oneshot monitors finish before their service
                # can be stopped. Queued work stays on disk for a later start.
                completed=row['ActiveState']=='active'and row.get('SubState')=='exited'and row.get('MainPID','0')=='0'
                if not completed and(row['ActiveState']in ('active','activating','deactivating')or row.get('MainPID','0')!='0'):return False
        if self.host!='b':return True
        queries=[('/var/lib/capstone-review-chat/queue.sqlite','capstone-review-chat.service',"SELECT count(*) FROM jobs WHERE status='running'"),
            ('/var/lib/capstone-ollama-trial/chat/queue.sqlite','capstone-ollama-chat.service',"SELECT count(*) FROM jobs WHERE status='running'"),
            ('/opt/hermes-data/state.db',None,'SELECT count(*) FROM session_turn_leases WHERE expires_at>?')]
        container_running=self.native.docker()['running']
        for name,unit,sql in queries:
            if unit is None and not container_running:continue
            if unit is not None and units[unit]['ActiveState']!='active':continue
            path=self.files.root/name.lstrip('/');meta=path.lstat()
            need(stat.S_ISREG(meta.st_mode)and meta.st_nlink==1 and 0<meta.st_size<=64*1024*1024,'idle_database_metadata')
            for parent in (path.parent,*path.parent.parents):
                if not parent.is_relative_to(self.files.root):continue
                item=parent.lstat();need(stat.S_ISDIR(item.st_mode)and item.st_uid in (self.w.owner,meta.st_uid)
                     and not stat.S_IMODE(item.st_mode)&0o022,'idle_database_directory')
            db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=1)
            try:
                db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF');db.set_progress_handler(lambda:1,100000)
                db.execute('BEGIN');values=db.execute(sql,(self.clock().timestamp(),)if unit is None else()).fetchall()
                need(len(values)==1 and len(values[0])==1 and type(values[0][0])is int and values[0][0]>=0,'idle_count_shape')
                if values[0][0]>0:return False
            finally:db.close()
            now=path.lstat();need((meta.st_dev,meta.st_ino,meta.st_uid,meta.st_gid,meta.st_mode)==
                (now.st_dev,now.st_ino,now.st_uid,now.st_gid,now.st_mode),'idle_database_changed')
        if container_running:
            raw,_=self.w.read(self.files.root/'opt/hermes-data/gateway_state.json',limit=262144);value=c.parsed(raw)
            work=value.get('active_work')
            need(isinstance(value,dict)and type(value.get('active_agents'))is int and value['active_agents']>=0
                 and(work is None or isinstance(work,list)and len(work)<=256),'gateway_idle_shape')
            stamp=value.get('updated_at')
            if type(stamp)in (int,float):age=self.clock().timestamp()-stamp
            else:
                parsed=datetime.fromisoformat(str(stamp).replace('Z','+00:00'));need(parsed.utcoffset()is not None,'gateway_clock_offset')
                age=(self.clock()-parsed).total_seconds()
            need(-2<=age<=30,'gateway_idle_stale')
            if value['active_agents']or work:return False
        return True
