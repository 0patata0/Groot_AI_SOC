"""Root-private immutable release artifacts and one active release per host.

This library has no CLI, commands, approval decisions or source/cache writes.
The caller holds the host lock across actual inspection and the local journal
lock. A different release cannot adopt a lost acknowledgement or an old fence.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import uuid

SPEC=importlib.util.spec_from_file_location('release_storage_contract',Path(__file__).with_name('release_status.py'))
c=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(c)
need=c.need
Refused=c.Refused
_atomic_spec=importlib.util.spec_from_file_location('release_storage_atomic',Path(__file__).with_name('release_atomic.py'))
atomic=importlib.util.module_from_spec(_atomic_spec);_atomic_spec.loader.exec_module(atomic)
FIXED=frozenset({'plan.json','bundle.json','approval.json','revert-approval.json','baseline.json','witness.json',
    'quiescence.json','verification.json','confirmation.json','resume.json','rollback.json',
    'revert-fence.json','revert.json','cleanup.json','current-release.json'})
MAX_ARTIFACT=2*1024*1024


class Store:
    def __init__(self,files,plan_sha256):
        need(isinstance(plan_sha256,str)and c.HEX.fullmatch(plan_sha256),'store_plan_digest')
        self.files,self.w,self.plan=files,files.witness,plan_sha256
        self.base=self.w.root/c.BASE.relative_to('/');self.held=False
        fd=self.w.directory(self.base)
        try:need(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'global_storage_private')
        finally:os.close(fd)
        self.token={'schema':1,'host':files.host,'release_id':files.release_id,'plan_sha256':plan_sha256}

    @property
    def gid(self):return os.getgid()if self.w.fixture else 0

    def name(self,name):
        need(isinstance(name,str)and(name in FIXED or re.fullmatch(r'operation-[0-9a-f]{32}\.json',name)),'artifact_name')
        return self.files.storage/name

    def read_path(self,path,*,absent=False):
        raw,st=self.w.read(path,limit=MAX_ARTIFACT,absent=absent)
        if raw is None:return None
        need((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(self.w.owner,self.gid,0o600),'artifact_metadata')
        return raw

    def read(self,name,*,absent=False):
        raw=self.read_path(self.name(name),absent=absent)
        return c.parsed(raw)if raw is not None else None

    def immutable(self,name,value):
        raw=c.canonical(value);need(0<len(raw)<=MAX_ARTIFACT,'artifact_bound')
        return self.create(self.name(name),raw)

    def create(self,path,raw):
        need((path.parent==self.base and path.name=='active.json')or
             (path.parent==self.files.storage and
              (path.name in FIXED or re.fullmatch(r'operation-[0-9a-f]{32}\.json',path.name))),'artifact_scope')
        parent=self.w.directory(path.parent);temporary='.artifact-'+uuid.uuid4().hex;created=False
        try:
            old=self.read_path(path,absent=True)
            if old is not None:need(old==raw,'immutable_artifact_changed');return False
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
            with os.fdopen(fd,'wb')as stream:
                os.fchown(stream.fileno(),self.w.owner,self.gid);os.fchmod(stream.fileno(),0o600)
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            atomic.create(parent,temporary,path.name);created=False;os.fsync(parent)
        finally:
            if created:
                try:os.unlink(temporary,dir_fd=parent)
                except FileNotFoundError:pass
            os.close(parent)
        need(self.read_path(path)==raw,'artifact_not_verified');return True

    @contextmanager
    def locked(self):
        need(not self.held,'nested_host_lock');parent=self.w.directory(self.base);fd=None
        try:
            fd=os.open('.host.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
            st=os.fstat(fd);named=os.stat('.host.lock',dir_fd=parent,follow_symlinks=False)
            need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==self.w.owner
                 and st.st_gid==self.gid and stat.S_IMODE(st.st_mode)==0o600
                 and(st.st_dev,st.st_ino)==(named.st_dev,named.st_ino),'host_lock_metadata')
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise Refused('host_operation_busy')from None
            self.held=True;yield self
        finally:
            self.held=False
            if fd is not None:os.close(fd)
            os.close(parent)

    def active(self,*,absent=False):
        raw=self.read_path(self.base/'active.json',absent=absent)
        if raw is None:return None
        value=c.parsed(raw)
        need(isinstance(value,dict)and set(value)==set(self.token)and type(value['schema'])is int
             and value['schema']==1 and value['host']==self.files.host
             and isinstance(value['release_id'],str)and c.RELEASE.fullmatch(value['release_id'])
             and isinstance(value['plan_sha256'],str)and c.HEX.fullmatch(value['plan_sha256']),'active_release_shape')
        return value

    def claim(self):
        need(self.held,'host_lock_required');value=self.active(absent=True)
        need(value is None or value==self.token,'another_release_active')
        self.create(self.base/'active.json',c.canonical(self.token));need(self.active()==self.token,'active_release_changed')

    def require_active(self):
        need(self.held and self.active()==self.token,'active_release_required')

    def relinquish(self):
        """Caller must first verify global reconciliation and owned cleanup."""
        self.require_active();path=self.base/'active.json';parent=self.w.directory(path.parent)
        try:
            before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            need(self.active()==self.token,'active_release_changed')
            need(c.stamp(before)==c.stamp(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'active_release_changed')
            os.unlink(path.name,dir_fd=parent);os.fsync(parent)
        finally:os.close(parent)


def digest(value):return hashlib.sha256(c.canonical(value)).hexdigest()
