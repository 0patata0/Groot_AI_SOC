"""Durable operator intent/receipt journal; never executes an OS operation.

Root lifecycle code must hold this lock, inspect actual resources, and resolve
ambiguous work. This module never retries a protected action after a lost ack.
Its fixed state file is also read by the release witness. No model/MCP API.
"""
from contextlib import contextmanager
from datetime import datetime,timedelta
import fcntl
import hashlib
import os
import stat
import uuid

import importlib.util
from pathlib import Path

SPEC=importlib.util.spec_from_file_location('release_state_contract',Path(__file__).with_name('release_status.py'))
c=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(c)
need=c.need
Refused=c.Refused
_atomic_spec=importlib.util.spec_from_file_location('release_state_atomic',Path(__file__).with_name('release_atomic.py'))
atomic=importlib.util.module_from_spec(_atomic_spec);_atomic_spec.loader.exec_module(atomic)
TRANSITIONS={'prepare':('staged','staged','staged'),'arm':('staged','armed','armed'),'quiesce':('armed','armed','quiesced'),
 'backup':('quiesced','quiesced','backed_up'),'apply':('backed_up','applying','applied'),
 'verify':('applied','applied','verified'),'confirm':('verified','confirming','confirmed')}
FLAGS=frozenset({'rollback_ready','fence_installed','barriers_installed','services_quiesced',
 'source_backup','cache_backup','source_restored','cache_restored','services_resumed','cleanup_complete',
 'revert_fenced','baseline_services_resumed','helpers_prepared','services_untouched'})
DIGESTS=frozenset({'baseline_sha256','verification_sha256','confirmation_sha256','resume_sha256',
 'rollback_receipt_sha256','cleanup_receipt_sha256','revert_fence_sha256',
 'revert_authorization_sha256','baseline_resume_sha256'})
REVERSE=frozenset({'revert_fence','revert'})
KEYS={'schema','host','release_id','plan_sha256','phase','sequence','deadline_kst','updated_at_kst','pending','facts','interrupted'}


def iso(value):
    need(isinstance(value,datetime)and value.utcoffset()==timedelta(hours=9),'clock_kst')
    return value.isoformat()


def instant(value):
    need(isinstance(value,str),'clock_kst');parsed=datetime.fromisoformat(value);iso(parsed);return parsed


class Journal:
    def __init__(self,files,plan_sha256):
        need(isinstance(plan_sha256,str)and c.HEX.fullmatch(plan_sha256),'plan_digest')
        self.files,self.w,self.plan=files,files.witness,plan_sha256
        self.path=self.w.storage/'state.json';self.held=False

    def validate(self,value):
        need(isinstance(value,dict)and set(value)==KEYS,'state_shape')
        need(type(value['schema'])is int and value['schema']==1 and value['host']==self.files.host
             and value['release_id']==self.files.release_id and value['plan_sha256']==self.plan,'state_identity')
        need(isinstance(value['phase'],str)and value['phase']in c.PHASES,'state_phase')
        need(type(value['sequence'])is int and 0<=value['sequence']<=1000,'state_sequence')
        instant(value['deadline_kst']);instant(value['updated_at_kst']);facts=value['facts']
        need(isinstance(facts,dict)and set(facts)<=FLAGS|DIGESTS,'state_facts')
        for key,val in facts.items():
            need(val is True if key in FLAGS else isinstance(val,str)and c.HEX.fullmatch(val),'state_fact_type')
        pending=value['pending']
        if pending is not None:self.validate_pending(pending)
        interrupted=value['interrupted'];need(isinstance(interrupted,list)and len(interrupted)<=16,'interruption_bound')
        for item in interrupted:self.validate_pending(item)
        return value

    @staticmethod
    def validate_pending(value):
        need(isinstance(value,dict)and set(value)=={'name','nonce','from_phase','to_phase','started_at_kst'},'pending_shape')
        need(isinstance(value['name'],str)and value['name']in {*TRANSITIONS,*REVERSE,'rollback','resume','cleanup'},'pending_name')
        need(isinstance(value['nonce'],str)and c.RELEASE.fullmatch(value['nonce']),'pending_nonce')
        need(all(isinstance(value[k],str)and value[k]in c.PHASES for k in ('from_phase','to_phase')),'pending_phase')
        instant(value['started_at_kst'])

    def read(self,*,absent=False):
        raw,st=self.w.read(self.path,limit=65536,absent=absent)
        if raw is None:return None,None
        gid=os.getgid()if self.w.fixture else 0
        need((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(self.w.owner,gid,0o600),'state_metadata')
        return self.validate(c.parsed(raw)),hashlib.sha256(raw).hexdigest()

    @contextmanager
    def locked(self):
        need(not self.held,'nested_operation_lock')
        parent=self.w.directory(self.w.storage)
        fd=None
        try:
            fd=os.open('.operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
            st=os.fstat(fd);gid=os.getgid()if self.w.fixture else 0
            need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==self.w.owner
                 and st.st_gid==gid and stat.S_IMODE(st.st_mode)==0o600,'operation_lock_metadata')
            named=os.stat('.operation.lock',dir_fd=parent,follow_symlinks=False)
            need((st.st_dev,st.st_ino)==(named.st_dev,named.st_ino),'operation_lock_changed')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Refused('operation_busy')from None
            self.held=True;yield self
        finally:
            self.held=False
            if fd is not None:os.close(fd)
            os.close(parent)

    def save(self,value,expected):
        need(self.held,'operation_lock_required');self.validate(value);raw=c.canonical(value)
        need(len(raw)<=65536,'state_bound');before,current=self.read(absent=expected is None)
        need(current==expected,'state_cas_conflict')
        if before is None:need(value['sequence']==0,'state_sequence')
        else:
            need(value['sequence']==before['sequence']+1 and value['deadline_kst']==before['deadline_kst'],'state_sequence_or_deadline')
            need(all(value['facts'].get(k)==v for k,v in before['facts'].items()),'immutable_fact_changed')
        parent=self.w.directory(self.path.parent);name='.state-'+uuid.uuid4().hex;created=False
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
            with os.fdopen(fd,'wb')as stream:
                os.fchown(stream.fileno(),self.w.owner,os.getgid()if self.w.fixture else 0)
                os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
            _,current=self.read(absent=expected is None);need(current==expected,'state_cas_conflict')
            if expected is None:
                atomic.create(parent,name,self.path.name);created=False
            else:os.replace(name,self.path.name,src_dir_fd=parent,dst_dir_fd=parent);created=False
            os.fsync(parent)
        finally:
            if created:
                try:os.unlink(name,dir_fd=parent)
                except FileNotFoundError:pass
            os.close(parent)
        saved,digest=self.read();need(saved==value,'state_not_verified');return digest

    def initialize(self,deadline,*,now):
        iso(deadline);iso(now);need(0<(deadline-now).total_seconds()<=1800,'release_deadline_bound')
        value={'schema':1,'host':self.files.host,'release_id':self.files.release_id,'plan_sha256':self.plan,
               'phase':'staged','sequence':0,'deadline_kst':iso(deadline),'updated_at_kst':iso(now),
               'pending':None,'facts':{},'interrupted':[]}
        self.save(value,None);return value

    @staticmethod
    def facts(value,changes):
        need(isinstance(changes,dict)and set(changes)<=FLAGS|DIGESTS,'state_facts')
        for key,val in changes.items():
            need(val is True if key in FLAGS else isinstance(val,str)and c.HEX.fullmatch(val),'state_fact_type')
            need(key not in value['facts']or value['facts'][key]==val,'immutable_fact_changed')
        value['facts'].update(changes)

    def mark(self,*,now,**facts):
        iso(now)
        value,digest=self.read();self.facts(value,facts);value['sequence']+=1;value['updated_at_kst']=iso(now)
        self.save(value,digest);return value

    def begin(self,name,*,now):
        iso(now)
        need(isinstance(name,str)and name in {*TRANSITIONS,*REVERSE,'rollback','resume','cleanup'},'operation_name')
        value,digest=self.read();phase=value['phase'];pending=value['pending']
        if name=='rollback':
            need(phase not in ('confirmed','rolled_back'),'stable_phase_requires_coordinated_decision')
            need(not value['facts'].get('revert_fenced')and
                 (pending is None or pending['name']not in REVERSE),'coordinated_revert_proof_required')
            if pending is not None:
                need(pending['name']!='rollback','ambiguous_rollback_requires_inspection')
                value['interrupted'].append(pending)
            to='rolled_back';during='rolling_back'
        else:
            need(pending is None,'outcome_requires_inspection')
            if name in TRANSITIONS:
                before,during,to=TRANSITIONS[name];need(phase==before,'operation_phase')
                need(instant(value['deadline_kst'])>now,'release_deadline_elapsed')
            elif name in REVERSE:
                need(phase==('confirmed'if name=='revert_fence'else 'rolling_back'),'operation_phase')
                during='rolling_back';to='rolling_back'if name=='revert_fence'else 'rolled_back'
            else:
                need(phase in ('confirmed','rolled_back'),'stable_cohort_required');during=to=phase
        required={'prepare':('rollback_ready','baseline_sha256'),
                  'arm':('rollback_ready','baseline_sha256','helpers_prepared','barriers_installed'),'quiesce':('fence_installed','barriers_installed'),
                  'backup':('services_quiesced',),'apply':('source_backup','cache_backup'),
                  'confirm':('verification_sha256',),
                  'revert':('revert_fenced','revert_fence_sha256','revert_authorization_sha256')}.get(name,())
        need(all(value['facts'].get(k)for k in required),'operation_prerequisites')
        nonce=uuid.uuid4().hex;value['pending']={'name':name,'nonce':nonce,'from_phase':phase,'to_phase':to,'started_at_kst':iso(now)}
        value.update(phase=during,sequence=value['sequence']+1,updated_at_kst=iso(now));self.save(value,digest);return nonce

    def finish(self,nonce,*,now,**facts):
        iso(now)
        value,digest=self.read();pending=value['pending'];need(pending is not None and pending['nonce']==nonce,'operation_nonce')
        self.facts(value,facts)
        required={'prepare':('helpers_prepared','barriers_installed'),
                  'arm':('fence_installed','barriers_installed'),'quiesce':('services_quiesced',),
                  'backup':('source_backup','cache_backup'),'verify':('verification_sha256',),
                  'confirm':('confirmation_sha256',),'resume':(('services_resumed','resume_sha256')if pending['to_phase']=='confirmed'else('baseline_services_resumed','baseline_resume_sha256')),
                  'rollback':('source_restored','cache_restored','rollback_receipt_sha256'),
                  'revert_fence':('revert_fenced','revert_fence_sha256'),
                  'revert':('source_restored','cache_restored','rollback_receipt_sha256'),
                  'cleanup':('cleanup_complete','cleanup_receipt_sha256')}.get(pending['name'],())
        need(all(value['facts'].get(k)for k in required),'operation_receipt_required')
        value.update(phase=pending['to_phase'],pending=None,sequence=value['sequence']+1,updated_at_kst=iso(now));self.save(value,digest);return value
