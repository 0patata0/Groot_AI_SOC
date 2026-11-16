"""Reuse the frozen cache transaction with bounded nonblocking file reads.

The coordinator still must stop all writers/readers. This adapter changes no
SQLite schema, snapshot/restore semantics, target path or approval boundary.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import uuid

HERE=Path(__file__).parent
SPEC=importlib.util.spec_from_file_location('release_cache_original',HERE/'cache_transaction.py')
original=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(original)
BASE_SHA='a4960a44c08b335c0f09b55f30c1c2e0a294c1c7f3c7e78e313f7d1788c59864'
need=original.need
Refused=original.Refused
_atomic_spec=importlib.util.spec_from_file_location('release_cache_atomic',HERE/'release_atomic.py')
atomic=importlib.util.module_from_spec(_atomic_spec);_atomic_spec.loader.exec_module(atomic)


class Cache(original.Cache):
    def __init__(self,*args,**kwargs):
        need(hashlib.sha256((HERE/'cache_transaction.py').read_bytes()).hexdigest()==BASE_SHA,'cache_base_changed')
        super().__init__(*args,**kwargs)

    def save(self,name,raw):
        need(name in ('before.sqlite3','before.json','after.sqlite3','after.json','restored.json'),'fixed_artifact_name')
        need(isinstance(raw,bytes)and 0<len(raw)<=original.MAX_BYTES,'cache_artifact_bound')
        parent=self.directory(self.storage);temporary='.cache-artifact-'+uuid.uuid4().hex;created=False
        try:
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:
                saved,_=self.read(self.storage/name);need(saved==raw,'immutable_backup_changed');return
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
            with os.fdopen(fd,'wb')as stream:
                os.fchown(stream.fileno(),self.owner,self.owner_gid());os.fchmod(stream.fileno(),0o600)
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            atomic.create(parent,temporary,name);created=False;os.fsync(parent)
        finally:
            if created:
                try:os.unlink(temporary,dir_fd=parent)
                except FileNotFoundError:pass
            os.close(parent)

    def read(self,path,*,database=False):
        path=Path(path);parent=self.directory(path.parent)
        try:
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            with os.fdopen(fd,'rb')as stream:
                before=os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==self.owner
                     and 0<before.st_size<=original.MAX_BYTES,'unsafe_cache_file')
                expected=(self.gid,0o640)if database else(self.owner_gid(),0o600)
                need((before.st_gid,stat.S_IMODE(before.st_mode))==expected,'cache_file_metadata')
                raw=stream.read(original.MAX_BYTES+1);after=os.fstat(stream.fileno())
                current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                need(original.identity(before)==original.identity(after)==original.identity(current)
                     and len(raw)==before.st_size,'cache_file_changed_during_read')
                again=self.directory(path.parent)
                try:
                    a,b=os.fstat(parent),os.fstat(again)
                    need((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'cache_directory_changed')
                finally:os.close(again)
                return raw,after
        finally:os.close(parent)
