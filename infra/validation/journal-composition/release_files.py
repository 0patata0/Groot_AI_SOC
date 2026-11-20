"""Operator-only source transaction for the fixed journal release footprint.

No CLI, service/command execution, approval, model or cache API. The separate
coordinator must quiesce consumers and pin this module and every payload first.
Original installation records and unrelated databases are outside this scope.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import uuid

SPEC=importlib.util.spec_from_file_location('release_file_contract',Path(__file__).with_name('release_status.py'))
contract=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(contract)
need=contract.need
Refused=contract.Refused
_atomic_spec=importlib.util.spec_from_file_location('release_file_atomic',Path(__file__).with_name('release_atomic.py'))
atomic=importlib.util.module_from_spec(_atomic_spec);_atomic_spec.loader.exec_module(atomic)
READER='/opt/capstone-diagnostics/read-system-diagnostics.py'
MCP_LAUNCHER='/opt/mcp/run-wazuh-ro.sh'
BARRIERS={host:{READER}|({MCP_LAUNCHER}if host=='b'else set())for host in contract.TARGETS}
TARGETS={host:paths|BARRIERS[host]for host,paths in contract.TARGETS.items()}
MAX_TOTAL=8*1024*1024


def sha(raw):return hashlib.sha256(raw).hexdigest()


class FileSet:
    def __init__(self,host,release_id,rows,gid,*,filesystem_root=Path('/')):
        need(isinstance(host,str)and host in TARGETS,'file_host')
        need(isinstance(rows,list)and len(rows)==len(TARGETS[host]),'file_count')
        for row in rows:
            need(isinstance(row,dict)and set(row)=={'target','before_sha256','after_sha256','uid','gid','mode'},'row_shape')
            p=row['target'];need(isinstance(p,str)and p in TARGETS[host],'file_target')
        need({r['target']for r in rows}==TARGETS[host],'file_target_set')
        base=[r for r in rows if r['target']not in BARRIERS[host]]
        self.witness=contract.Witness({'schema':1,'host':host,'release_id':release_id,'rows':base,'reader_uid':0},gid,filesystem_root=filesystem_root)
        row=next(r for r in rows if r['target']==READER)
        need(all(isinstance(row[k],str)and contract.HEX.fullmatch(row[k])for k in ('before_sha256','after_sha256')),'reader_digest')
        need(type(row['uid'])is int and row['uid']==0 and type(row['gid'])is int and 0<=row['gid']<65534
             and type(row['mode'])is int and row['mode']==0o550,'reader_metadata')
        if host=='b':
            row=next(r for r in rows if r['target']==MCP_LAUNCHER)
            need(all(isinstance(row[k],str)and contract.HEX.fullmatch(row[k])for k in ('before_sha256','after_sha256')),'mcp_launcher_digest')
            need(type(row['uid'])is int and row['uid']==0 and type(row['gid'])is int and 0<=row['gid']<65534
                 and type(row['mode'])is int and row['mode']==0o750,'mcp_launcher_metadata')
        self.host,self.release_id=host,release_id
        self.rows=sorted((dict(r)for r in rows),key=lambda r:r['target'])
        self.root,self.storage=self.witness.root,self.witness.storage
        for p in (self.storage,self.storage/'candidates',self.storage/'backups'):
            fd=self.witness.directory(p)
            try:need(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'private_storage')
            finally:os.close(fd)

    def target(self,row):
        need(isinstance(row,dict)and row in self.rows,'file_target')
        return self.root/row['target'].lstrip('/')

    def metadata(self,row):
        need(isinstance(row,dict)and row in self.rows,'file_target')
        return (os.getuid(),os.getgid(),row['mode'])if self.witness.fixture else (row['uid'],row['gid'],row['mode'])

    def read_target(self,row):
        raw,st=self.witness.read(self.target(row),absent=row['before_sha256']is None)
        need(st is None or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==self.metadata(row),'target_metadata_changed')
        return raw,st

    def check(self,*keys):
        need(keys and all(k in ('before_sha256','after_sha256')for k in keys),'file_state_key')
        values=[]
        for row in self.rows:
            raw,_=self.read_target(row);digest=sha(raw)if raw is not None else None
            need(digest in {row[k]for k in keys},'target_bytes_changed');values.append(digest)
        return values

    def read_stored(self,kind,digest):
        need(kind in ('candidates','backups')and isinstance(digest,str)and contract.HEX.fullmatch(digest),'stored_scope')
        need(digest in {r['after_sha256'if kind=='candidates'else 'before_sha256']for r in self.rows},'stored_digest_not_in_plan')
        raw,st=self.witness.read(self.storage/kind/(digest+'.data'))
        owner=self.witness.owner;gid=os.getgid()if self.witness.fixture else 0
        need((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(owner,gid,0o600)and sha(raw)==digest,'stored_bytes_changed')
        return raw

    def put(self,kind,raw):
        """Content-addressed immutable staging; never creates a target file."""
        need(kind in ('candidates','backups')and isinstance(raw,bytes)and 0<len(raw)<=contract.MAX_SOURCE,'stored_scope')
        digest=sha(raw);key='after_sha256'if kind=='candidates'else 'before_sha256'
        need(digest in {r[key]for r in self.rows},'stored_digest_not_in_plan')
        parent=self.witness.directory(self.storage/kind);name=digest+'.data';temporary='.stage-'+uuid.uuid4().hex
        created=False
        try:
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:
                need(self.read_stored(kind,digest)==raw,'immutable_backup_changed');return digest
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
            with os.fdopen(fd,'wb')as stream:
                os.fchown(stream.fileno(),self.witness.owner,os.getgid()if self.witness.fixture else 0)
                os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
            try:atomic.create(parent,temporary,name);created=False
            except FileExistsError:need(self.read_stored(kind,digest)==raw,'immutable_backup_changed')
            os.fsync(parent)
        finally:
            if created:
                try:os.unlink(temporary,dir_fd=parent)
                except FileNotFoundError:pass
            os.close(parent)
        need(self.read_stored(kind,digest)==raw,'stored_bytes_changed');return digest

    def payloads(self,kind,key):
        need((kind,key)in (('candidates','after_sha256'),('backups','before_sha256')),'stored_scope')
        data={}
        for row in self.rows:
            digest=row[key]
            if digest is not None and digest not in data:data[digest]=self.read_stored(kind,digest)
        need(sum(map(len,data.values()))<=MAX_TOTAL,'payload_total_bound')
        return data

    def backup(self):
        self.check('before_sha256')
        for row in self.rows:
            raw,_=self.read_target(row)
            if raw is not None:
                need(sha(raw)==row['before_sha256'],'target_changed_during_backup');self.put('backups',raw)
        self.check('before_sha256');return self.payloads('backups','before_sha256')

    def replace(self,row,data,expected,*,normal_reader_sha256=None):
        raw,original=self.read_target(row);need((sha(raw)if raw is not None else None)==expected,'target_changed_before_replace')
        need(isinstance(data,bytes)and 0<len(data)<=contract.MAX_SOURCE,'candidate_bound')
        if normal_reader_sha256 is not None:
            need(row['target']==READER and isinstance(normal_reader_sha256,str)
                 and contract.HEX.fullmatch(normal_reader_sha256),'normal_reader_replacement_scope')
        need(sha(data)in (row['before_sha256'],row['after_sha256'],normal_reader_sha256),'replacement_not_in_plan')
        path=self.target(row);parent=self.witness.directory(path.parent);name='.release-'+uuid.uuid4().hex;created=False
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
            with os.fdopen(fd,'wb')as stream:
                uid,gid,mode=self.metadata(row);os.fchown(stream.fileno(),uid,gid);os.fchmod(stream.fileno(),mode)
                stream.write(data);stream.flush();os.fsync(stream.fileno())
            if original is None:
                atomic.create(parent,name,path.name);created=False
            else:
                need(contract.stamp(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==contract.stamp(original),'target_changed_before_replace')
                os.replace(name,path.name,src_dir_fd=parent,dst_dir_fd=parent);created=False
            os.fsync(parent)
        finally:
            if created:os.unlink(name,dir_fd=parent)
            os.close(parent)
        fresh,_=self.read_target(row);need(fresh==data,'replacement_not_verified')

    @staticmethod
    def order(row):
        priority={'diagnostic_journal_native.py':0,'diagnostic_history.py':1,'system_diagnostics.py':2,'diagnostic_journal.py':3}
        return priority.get(Path(row['target']).name,4),row['target']

    def apply(self):
        data=self.payloads('candidates','after_sha256');values=self.check('before_sha256','after_sha256')
        if values==[r['after_sha256']for r in self.rows]:
            self.payloads('backups','before_sha256');return 0
        expected=[r['after_sha256']if r['target']in BARRIERS[self.host]else r['before_sha256']for r in self.rows]
        need(values==expected,'partial_apply_requires_restore')
        self.payloads('backups','before_sha256')
        count=0
        for row in sorted(self.rows,key=self.order):
            if row['target']in BARRIERS[self.host]or row['before_sha256']==row['after_sha256']:continue
            self.replace(row,data[row['after_sha256']],row['before_sha256']);count+=1
        self.check('after_sha256');return count

    def install_barriers(self):
        """Before core writes, so phase-gated normal reads can be drained."""
        data=self.payloads('candidates','after_sha256');values=self.check('before_sha256','after_sha256')
        expected=[r['after_sha256']if r['target']in BARRIERS[self.host]else r['before_sha256']for r in self.rows]
        if values==expected:
            self.payloads('backups','before_sha256');return 0
        need(values==[r['before_sha256']for r in self.rows],'reader_install_requires_baseline')
        self.backup();count=0
        for row in self.rows:
            if row['target']in BARRIERS[self.host]:
                self.replace(row,data[row['after_sha256']],row['before_sha256']);count+=1
        return count

    def complete_barriers(self):
        """Recovery of an interrupted barrier install, before any core write."""
        values=self.check('before_sha256','after_sha256')
        need(all(v==r['before_sha256']for r,v in zip(self.rows,values)
                 if r['target']not in BARRIERS[self.host]),'barrier_recovery_requires_baseline_core')
        data=self.payloads('candidates','after_sha256');self.payloads('backups','before_sha256');count=0
        for row,current in zip(self.rows,values):
            if row['target']not in BARRIERS[self.host]or current==row['after_sha256']:continue
            self.replace(row,data[row['after_sha256']],row['before_sha256']);count+=1
        return count

    def restore_core(self):
        """Retain the status relay until all hosts are reconciled by B."""
        values=self.check('before_sha256','after_sha256')
        if all(v==r['before_sha256']for r,v in zip(self.rows,values)if r['target']not in BARRIERS[self.host]):return 0
        data=self.payloads('backups','before_sha256');count=0
        pairs=sorted(zip(self.rows,values),key=lambda pair:(pair[0]['before_sha256']is None,pair[0]['target']))
        for row,current in pairs:
            if row['target']in BARRIERS[self.host]or current==row['before_sha256']:continue
            if row['before_sha256']is not None:self.replace(row,data[row['before_sha256']],current)
            else:
                path=self.target(row);raw,st=self.read_target(row);need(sha(raw)==current,'target_changed_before_remove')
                parent=self.witness.directory(path.parent)
                try:
                    need(contract.stamp(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==contract.stamp(st),'target_changed_before_remove')
                    os.unlink(path.name,dir_fd=parent);os.fsync(parent)
                finally:os.close(parent)
            count+=1
        for row in self.rows:
            if row['target']in BARRIERS[self.host]:continue
            raw,_=self.read_target(row);need((sha(raw)if raw is not None else None)==row['before_sha256'],'core_restore_not_verified')
        return count

    def restore_barriers(self):
        """Operator cleanup only, after the coordinator has reconciled peers."""
        values=self.check('before_sha256','after_sha256')
        if all(v==r['before_sha256']for r,v in zip(self.rows,values)if r['target']in BARRIERS[self.host]):return 0
        data=self.payloads('backups','before_sha256');count=0
        for row,current in zip(self.rows,values):
            if row['target']not in BARRIERS[self.host]or current==row['before_sha256']:continue
            self.replace(row,data[row['before_sha256']],row['after_sha256']);count+=1
        return count

    def finish_barriers(self,normal_reader,normal_reader_sha256):
        """Install the plan-pinned permanent reader after all-host acceptance."""
        need(isinstance(normal_reader,bytes)and 0<len(normal_reader)<=131072
             and sha(normal_reader)==normal_reader_sha256,'normal_reader_payload_changed')
        values=[]
        for row in self.rows:
            raw,_=self.read_target(row);current=sha(raw)if raw is not None else None
            allowed={row['before_sha256'],row['after_sha256']}
            if row['target']==READER:allowed.add(normal_reader_sha256)
            need(current in allowed,'target_bytes_changed');values.append(current)
        data=self.payloads('backups','before_sha256');count=0
        for row,current in zip(self.rows,values):
            if row['target']not in BARRIERS[self.host]:continue
            final=normal_reader_sha256 if row['target']==READER else row['before_sha256']
            if current==final:continue
            raw=normal_reader if row['target']==READER else data[final]
            self.replace(row,raw,current,normal_reader_sha256=normal_reader_sha256 if row['target']==READER else None)
            count+=1
        return count
