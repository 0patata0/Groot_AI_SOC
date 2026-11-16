"""Accepted all-host outcome, owned cleanup and current installation witness.

Root operator artifacts only, never an MCP or model attestation API. Original
bootstrap receipts stay byte-for-byte intact. Preparation, common decision and
authorization are durable before detached cleanup can remove its own relay.
"""
from datetime import datetime,timedelta
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
c=load('release_completion_contract','release_status.py')
source=load('release_completion_sources','release_files.py')
need=c.need
CHECKS=frozenset({'collection','mcp','hermes_chat','ollama_chat'})


def digest(value):return hashlib.sha256(c.canonical(value)).hexdigest()


class Completion:
    def __init__(self,lifecycle):
        self.ctl=lifecycle;self.files=lifecycle.files;self.store=lifecycle.store;self.journal=lifecycle.journal
        self.host=lifecycle.host;self.w=lifecycle.w

    def outcome(self):
        state=self.ctl.state();need(state['phase']in ('confirmed','rolled_back'),'completion_stable_phase')
        candidate=state['phase']=='confirmed'
        need(state['facts'].get('services_resumed')if candidate else any(state['facts'].get(k)for k in ('baseline_services_resumed','services_untouched')),
             'completion_services_not_resumed')
        return 'candidate'if candidate else'baseline'

    def stable(self,*,cleaned=False):
        outcome=self.outcome();state=self.ctl.state()
        need(state['pending']is None or state['pending']['name']in ('completion_prepare','cleanup'),'completion_pending_operation')
        need(self.ctl.core_is('after_sha256'if outcome=='candidate'else'before_sha256'),'completion_core_changed')
        self.files.check('before_sha256','after_sha256')
        need(not any(self.ctl.controls.fenced(name)for name in self.ctl.controls.markers),'completion_still_fenced')
        need(self.w.cache()=={'status':'observed','source_filter_policy':'application-severity-v1'if outcome=='candidate'else None},'completion_cache_policy')
        before=self.ctl.baseline()['units'];now=self.ctl.native.snapshot()
        for group in ('collection','consumer'):self.ctl.native.loaded_matches(group,before)
        for name,old in before.items():
            need(now[name].get('UnitFileState')==old.get('UnitFileState')or old['LoadState']=='not-found','completion_unit_enable_changed')
            if old['ActiveState']=='active':need(now[name]['ActiveState']=='active','completion_original_service_not_running')
        if self.host=='b':self.ctl.native.require_original_container()
        if outcome=='candidate':self.ctl.native.collection_resources(release_dropins=None if cleaned is None else not cleaned)
        return outcome

    def acceptance(self,*,fresh):
        value=self.store.read('acceptance.json',absent=True)
        need(isinstance(value,dict)and set(value)=={'schema','host','release_id','plan_sha256','bundle_sha256','outcome','at_kst','reference','checks'}
             and type(value['schema'])is int and value['schema']==1 and value['host']==self.host
             and value['release_id']==self.files.release_id and value['plan_sha256']==self.store.plan
             and value['bundle_sha256']==digest(self.store.read('bundle.json'))and value['outcome']==self.outcome()
             and isinstance(value['reference'],str)and re.fullmatch(r'[A-Za-z0-9_:/.-]{1,160}',value['reference']),
             'operator_acceptance_required')
        stamp=datetime.fromisoformat(value['at_kst']);age=(self.ctl.clock()-stamp).total_seconds()
        need(stamp.utcoffset()==timedelta(hours=9)and age>=-2 and(not fresh or age<=300),'acceptance_freshness')
        checks=value['checks'];need(isinstance(checks,dict)and set(checks)==CHECKS,'acceptance_checks')
        for item in checks.values():
            need(isinstance(item,dict)and set(item)=={'status','evidence_sha256'}and item['status']=='passed'
                 and isinstance(item['evidence_sha256'],str)and c.HEX.fullmatch(item['evidence_sha256']),'acceptance_check_unverified')
        return value

    def prepare(self,proofs):
        with self.store.locked(),self.journal.locked():
            self.store.require_active();state=self.ctl.state();pending=state['pending']
            retry=pending is not None and pending['name']=='completion_prepare'
            self.ctl.authorize(recovery=retry or bool(state['facts'].get('completion_prepared')));outcome=self.stable()
            old=self.store.read('completion.json',absent=True);accept=self.acceptance(fresh=old is None)
            if state['facts'].get('completion_prepared'):
                need(old is not None and digest(old)==state['facts']['completion_sha256'],'completion_receipt_changed');return state
            gate=self.ctl.coherent(proofs,'resume_candidate'if outcome=='candidate'else'resume_baseline')
            nonce=pending['nonce']if retry else self.journal.begin('completion_prepare',now=self.ctl.clock())
            if old is None:
                old={'schema':1,'host':self.host,'release_id':self.files.release_id,'plan_sha256':self.store.plan,
                    'outcome':outcome,'acceptance_sha256':digest(accept),'baseline_sha256':state['facts']['baseline_sha256'],
                    'at_kst':self.ctl.clock().isoformat(),'cohort':gate,'isolated_filesystem':self.w.fixture}
                self.store.immutable('completion.json',old)
            need(old['outcome']==outcome and old['acceptance_sha256']==digest(accept)
                 and old['baseline_sha256']==state['facts']['baseline_sha256'],'completion_receipt_changed')
            self.journal.finish(nonce,now=self.ctl.clock(),completion_prepared=True,completion_sha256=digest(old));return self.ctl.state()

    def proof(self):
        with self.store.locked(),self.journal.locked():
            self.ctl.contract.verify(self.files);state=self.ctl.state()
            outcome=self.stable(cleaned=True if state['facts'].get('cleanup_complete')else None)
            need(state['facts'].get('completion_prepared'),'completion_not_prepared')
            need(digest(self.store.read('completion.json'))==state['facts']['completion_sha256'],'completion_receipt_changed')
            return {'schema':1,'host':self.host,'release_id':self.files.release_id,'plan_sha256':self.store.plan,
                'outcome':outcome,'at_kst':self.ctl.clock().isoformat(),'completion_sha256':state['facts']['completion_sha256'],
                'decision_sha256':state['facts'].get('cleanup_decision_sha256'),'source':self.ctl.local_proof(),
                'isolated_filesystem':self.w.fixture}

    def peer_gate(self,proofs,*,decided):
        need(isinstance(proofs,dict)and set(proofs)==set(c.TARGETS),'cleanup_peer_set');times=[];outcome=self.outcome()
        for host,row in proofs.items():
            need(isinstance(row,dict)and set(row)=={'schema','host','release_id','plan_sha256','outcome','at_kst','completion_sha256','decision_sha256','source','isolated_filesystem'}
                 and type(row['schema'])is int and row['schema']==1 and row['host']==host
                 and row['release_id']==self.files.release_id and row['plan_sha256']==self.store.plan and row['outcome']==outcome
                 and isinstance(row['completion_sha256'],str)and c.HEX.fullmatch(row['completion_sha256'])
                 and row['isolated_filesystem']is self.w.fixture,'cleanup_peer_identity')
            stamp=datetime.fromisoformat(row['at_kst']);times.append(stamp)
            need(stamp.utcoffset()==timedelta(hours=9)and -2<=(self.ctl.clock()-stamp).total_seconds()<=15,'cleanup_peer_freshness')
            if decided:need(row['decision_sha256']==self.ctl.state()['facts'].get('cleanup_decision_sha256'),'cleanup_peer_decision')
            else:need(row['decision_sha256']is None,'cleanup_peer_already_decided')
        need((max(times)-min(times)).total_seconds()<=5,'cleanup_peer_span')
        need(proofs[self.host]['completion_sha256']==self.ctl.state()['facts'].get('completion_sha256'),'cleanup_local_completion_changed')
        gate=self.ctl.coherent({h:r['source']for h,r in proofs.items()},'resume_candidate'if outcome=='candidate'else'resume_baseline')
        return gate

    def decide(self,proofs):
        with self.store.locked(),self.journal.locked():
            self.store.require_active();old=self.store.read('cleanup-decision.json',absent=True)
            self.ctl.authorize(recovery=old is not None);self.stable();state=self.ctl.state()
            need(state['pending']is None and state['facts'].get('completion_prepared'),'completion_not_prepared')
            value={'schema':1,'proofs':proofs,'plan_sha256':self.store.plan,'outcome':self.outcome()}
            if old is None:self.peer_gate(proofs,decided=False)
            else:need(old==value,'cleanup_decision_changed')
            self.store.immutable('cleanup-decision.json',value)
            self.journal.mark(now=self.ctl.clock(),cleanup_decision_sha256=digest(value));return self.ctl.state()

    def authorize(self,proofs):
        with self.store.locked(),self.journal.locked():
            self.store.require_active();old=self.store.read('cleanup-grant.json',absent=True)
            self.ctl.authorize(recovery=old is not None);self.stable();state=self.ctl.state()
            need(state['pending']is None and state['facts'].get('cleanup_decision_sha256'),'cleanup_decision_required')
            need(digest(self.store.read('cleanup-decision.json'))==state['facts']['cleanup_decision_sha256'],'cleanup_decision_changed')
            value={'schema':1,'proofs':proofs,'plan_sha256':self.store.plan,'decision_sha256':state['facts']['cleanup_decision_sha256']}
            if old is None:self.peer_gate(proofs,decided=True)
            else:need(old==value,'cleanup_grant_changed')
            self.store.immutable('cleanup-grant.json',value)
            self.journal.mark(now=self.ctl.clock(),cleanup_authorization_sha256=digest(value));return self.ctl.state()

    def documents_absent(self):
        for path in self.ctl.controls.docs:
            try:raw,_=self.ctl.controls.read(path,mode=0o644)
            except FileNotFoundError:raw=None
            need(raw is None,'cleanup_document_remaining')

    def installed(self):
        outcome=self.outcome();rows={}
        for row in self.files.rows:
            key='before_sha256'if row['target']in source.BARRIERS[self.host]or outcome=='baseline'else'after_sha256'
            raw,meta=self.files.read_target(row);actual=hashlib.sha256(raw).hexdigest()if raw is not None else None
            need(actual==row[key],'current_source_changed')
            rows[row['target']]=None if meta is None else {'sha256':actual,'uid':row['uid'],'gid':row['gid'],'mode':row['mode']}
        return rows

    def receipt(self):
        state=self.ctl.state();outcome=self.outcome();rows={}
        for row in self.files.rows:
            key='before_sha256'if row['target']in source.BARRIERS[self.host]or outcome=='baseline'else'after_sha256'
            rows[row['target']]=None if row[key]is None else {'sha256':row[key],'uid':row['uid'],'gid':row['gid'],'mode':row['mode']}
        return {'schema':1,'host':self.host,'release_id':self.files.release_id,'plan_sha256':self.store.plan,
            'bundle_sha256':digest(self.store.read('bundle.json')),'source_commit':self.ctl.plan['source_commit'],
            'outcome':outcome,'installed':rows,'protected':self.ctl.plan['hosts'][self.host]['protected'],
            'baseline_sha256':state['facts']['baseline_sha256'],'completion_sha256':state['facts']['completion_sha256'],
            'cleanup_authorization_sha256':state['facts']['cleanup_authorization_sha256'],'isolated_filesystem':self.w.fixture}

    def pointer(self,receipt):
        return {**self.store.token,'bundle_sha256':receipt['bundle_sha256'],'receipt_sha256':digest(receipt),
                'runtime_sha256':self.ctl.plan['helpers']['release_runtime.py']}

    def cleanup(self):
        with self.store.locked(),self.journal.locked():
            state=self.ctl.state();pending=state['pending']
            if self.store.active(absent=True)is None and state['facts'].get('cleanup_complete'):return self._current()
            self.store.require_active()
            retry=pending is not None and pending['name']=='cleanup'
            self.ctl.authorize(recovery=retry or bool(state['facts'].get('cleanup_complete')))
            need(state['facts'].get('completion_prepared'),'completion_not_prepared')
            if state['facts'].get('cleanup_complete'):
                result=self._current(allow_active=True,finishing=True)
                self.store.relinquish();return {**result,'status':'cleaned'}
            decision=self.store.read('cleanup-decision.json');grant=self.store.read('cleanup-grant.json')
            need(digest(decision)==state['facts'].get('cleanup_decision_sha256')and digest(grant)==state['facts'].get('cleanup_authorization_sha256')
                 and grant['decision_sha256']==digest(decision),'cleanup_authorization_required')
            self.stable(cleaned=None)
            receipt=self.receipt();pointer,previous=self.store.current()
            need(previous==self.ctl.plan['hosts'][self.host]['previous_current_sha256']or pointer==self.pointer(receipt),
                 'current_pointer_changed')
            # Check every remaining owned document before removing the relay.
            for path,expected in self.ctl.controls.docs.items():
                try:raw,_=self.ctl.controls.read(path,mode=0o644)
                except FileNotFoundError:raw=None
                need(raw is None or raw==expected,'foreign_control_file')
            nonce=pending['nonce']if retry else self.journal.begin('cleanup',now=self.ctl.clock())
            self.files.restore_barriers()
            if not self.ctl.state()['facts'].get('helpers_disarmed'):
                self.ctl.helpers.disarm(finishing=True);self.journal.mark(now=self.ctl.clock(),helpers_disarmed=True)
            self.ctl.helpers.stopped(finishing=True);self.ctl.controls.remove_documents()
            self.ctl.native.run(['/usr/bin/systemctl','daemon-reload']);self.documents_absent()
            self.stable(cleaned=True);need(self.installed()==receipt['installed'],'current_source_changed')
            old=self.store.read('current-release.json',absent=True)
            if old is not None:need(old==receipt,'current_receipt_changed')
            self.store.immutable('current-release.json',receipt)
            self.store.publish_current(self.pointer(receipt),self.ctl.plan['hosts'][self.host]['previous_current_sha256'])
            evidence={'current_receipt_sha256':digest(receipt),'initial_receipts_preserved':True,
                'owned_documents_removed':len(self.ctl.controls.docs),'shared_dropin_directories_preserved':True}
            self.store.immutable('cleanup.json',evidence)
            self.journal.finish(nonce,now=self.ctl.clock(),cleanup_complete=True,cleanup_receipt_sha256=digest(evidence))
            self.store.relinquish();return {'status':'cleaned','receipt_sha256':digest(receipt),'operating_acceptance_is_operator_attestation':True}

    def current(self):
        """Read the actual installation, not merely its saved receipt."""
        with self.store.locked(),self.journal.locked():
            return self._current()

    def _current(self,*,allow_active=False,finishing=False):
        need(self.store.held and self.journal.held,'completion_locks_required')
        self.ctl.contract.verify(self.files);state=self.ctl.state()
        need(state['pending']is None and state['facts'].get('cleanup_complete'),'current_cleanup_incomplete')
        active=self.store.active(absent=True)
        need(active is None or allow_active and active==self.store.token,'current_release_still_active')
        self.stable(cleaned=True);self.documents_absent();self.ctl.helpers.stopped(finishing=finishing)
        receipt=self.store.read('current-release.json');pointer,_=self.store.current()
        need(pointer==self.pointer(receipt),'current_pointer_changed')
        need(receipt==self.receipt()and receipt['installed']==self.installed(),'current_receipt_changed')
        cleanup=self.store.read('cleanup.json');need(digest(cleanup)==state['facts']['cleanup_receipt_sha256']
            and cleanup['current_receipt_sha256']==digest(receipt),'cleanup_receipt_changed')
        completion=self.store.read('completion.json');need(digest(completion)==state['facts']['completion_sha256'],
            'completion_receipt_changed')
        accept=self.acceptance(fresh=False);need(digest(accept)==completion['acceptance_sha256'],'acceptance_receipt_changed')
        need(receipt['outcome']==self.outcome()and receipt['source_commit']==self.ctl.plan['source_commit']
             and receipt['host']==self.host and receipt['release_id']==self.files.release_id and receipt['plan_sha256']==self.store.plan
             and receipt['bundle_sha256']==pointer['bundle_sha256']and receipt['isolated_filesystem']is self.w.fixture,'current_receipt_identity')
        return {'schema':1,'status':'verified','host':self.host,'release_id':self.files.release_id,'plan_sha256':self.store.plan,
            'outcome':self.outcome(),'installed':receipt['installed'],'initial_receipts_preserved':True,
            'initial_stage':'prepared_only'if self.ctl.plan['hosts'][self.host]['protected'].get('/var/lib/capstone-diagnostics/installation/active.json')is None else'active_record_present',
            'operator_acceptance_sha256':self.store.read('completion.json')['acceptance_sha256'],
            'at_kst':self.ctl.clock().isoformat(),'mutation_performed':False,'isolated_filesystem':self.w.fixture}
