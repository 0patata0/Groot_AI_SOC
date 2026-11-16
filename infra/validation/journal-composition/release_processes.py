"""Drain only dedicated reader/MCP SSH descendants using Linux pidfds.

No arbitrary PID, user, command or signal input. Existing SSH administrators,
root sshd parents, security engines and other accounts are excluded. Fences
and the exact reader/launcher bytes must be present before the first signal.
"""
import importlib.util
import os
from pathlib import Path
import pwd
import signal
import sys
import time

SPEC=importlib.util.spec_from_file_location('release_process_contract',Path(__file__).with_name('release_status.py'))
c=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(c)
need=c.need
Refused=c.Refused


class Linux:
    def __init__(self,uids):
        need(sys.platform=='linux'and os.getuid()==os.geteuid()==0
             and hasattr(os,'pidfd_open')and hasattr(signal,'pidfd_send_signal'),'pidfd_support_required')
        self.uids=set(uids)

    @staticmethod
    def read(pid,name,limit):
        need(type(pid)is int and pid>1 and name in ('status','stat'),'proc_scope')
        fd=os.open('/proc/'+str(pid)+'/'+name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb')as stream:raw=stream.read(limit+1)
        need(0<len(raw)<=limit,'proc_bound');return raw

    def one(self,pid):
        try:
            status=self.read(pid,'status',65536);raw=self.read(pid,'stat',65536)
            fields=raw[raw.rfind(b')')+2:].split();need(len(fields)>=20,'proc_stat_shape')
            lines=[line.split()[1:]for line in status.splitlines()if line.startswith(b'Uid:')]
            need(len(lines)==1 and len(lines[0])==4,'proc_uid_shape');uids=[int(x)for x in lines[0]]
            need(not self.uids.intersection(uids)or len(set(uids))==1,'proc_mixed_identity')
            return {'pid':pid,'uid':uids[1],'ppid':int(fields[1]),'start_ticks':int(fields[19])}
        except (FileNotFoundError,ProcessLookupError):return None

    def pids(self):return sorted(int(name)for name in os.listdir('/proc')if name.isdigit()and int(name)>1)
    def sshd(self,pid):
        try:return os.readlink('/proc/'+str(pid)+'/exe')in ('/usr/sbin/sshd','/usr/bin/sshd')
        except (FileNotFoundError,ProcessLookupError):return False
    def open(self,pid):return os.pidfd_open(pid,0)
    def send(self,fd,number):signal.pidfd_send_signal(fd,number)
    def close(self,fd):os.close(fd)


class Readers:
    def __init__(self,files,controls,journal,reader_uid,mcp_uid,*,backend=None):
        self.files,self.controls,self.journal=files,controls,journal;self.w=files.witness
        need(type(reader_uid)is int and 1<=reader_uid<65534,'reader_account')
        if files.host=='b':need(type(mcp_uid)is int and 1<=mcp_uid<65534 and mcp_uid!=reader_uid,'mcp_account')
        else:need(mcp_uid is None,'mcp_host_scope')
        need(backend is not None if self.w.fixture else backend is None,'proc_execution_boundary')
        if not self.w.fixture:
            need(pwd.getpwnam('capstone-diagnostics').pw_uid==reader_uid,'reader_account_changed')
            if files.host=='b':need(pwd.getpwnam('mcp').pw_uid==mcp_uid,'mcp_account_changed')
        self.uids={reader_uid}|({mcp_uid}if mcp_uid is not None else set())
        self.backend=backend if self.w.fixture else Linux(self.uids)

    def permitted(self,row):
        need(isinstance(row,dict)and set(row)=={'pid','uid','ppid','start_ticks'}
             and all(type(v)is int for v in row.values())and row['pid']>1 and row['start_ticks']>0
             and row['uid']in self.uids,'reader_process_identity')
        seen={row['pid']};current=row
        for _ in range(16):
            parent=current['ppid'];need(parent not in seen,'reader_process_ancestry');seen.add(parent)
            if parent<=1:break
            current=self.backend.one(parent)
            if current is None:
                need(self.backend.one(row['pid'])is None,'reader_ancestry_unavailable');return False
            need(current['uid']in self.uids|{0},'reader_process_ancestry')
            if current['uid']==0 and self.backend.sshd(parent):return True
        raise Refused('reader_not_ssh_descendant')

    def snapshot(self):
        rows=[]
        for pid in self.backend.pids():
            row=self.backend.one(pid)
            if row is None or row['uid']not in self.uids:continue
            if self.permitted(row):rows.append(row)
        return rows

    def fenced(self):
        need(self.controls.fenced('collection')and self.controls.fenced('consumer'),'process_fences_required')
        if self.files.host=='b':need(self.controls.fenced('mcp'),'mcp_fence_required')
        value,_=self.journal.read()
        need(value['phase']in ('armed','quiesced','backed_up','applying','applied','verified','confirming','rolling_back'),'reader_phase_not_fenced')
        for row in self.files.rows:
            if row['target']not in {'/opt/capstone-diagnostics/read-system-diagnostics.py','/opt/mcp/run-wazuh-ro.sh'}:continue
            raw,_=self.files.read_target(row)
            import hashlib
            need(hashlib.sha256(raw).hexdigest()==row['after_sha256'],'reader_barrier_changed')

    def drain(self,*,timeout=15):
        need(type(timeout)is int and 1<=timeout<=15,'reader_drain_timeout');self.fenced()
        deadline=time.monotonic()+timeout;terminated=[];empty=0
        while empty<3:
            need(time.monotonic()<deadline,'reader_drain_incomplete');self.fenced();rows=self.snapshot()
            if not rows:empty+=1;time.sleep(0.1);continue
            empty=0
            # Validate the entire dedicated-account snapshot before a signal.
            handles=[]
            try:
                for row in rows:
                    try:fd=self.backend.open(row['pid'])
                    except ProcessLookupError:continue
                    handles.append((fd,row))
                    current=self.backend.one(row['pid'])
                    need(current is None or current==row,'reader_pid_reused')
                    if current is not None:need(self.permitted(current),'reader_process_ancestry')
                for fd,row in handles:
                    try:self.backend.send(fd,signal.SIGTERM)
                    except ProcessLookupError:continue
                    terminated.append(row)
                end=min(deadline,time.monotonic()+2)
                while time.monotonic()<end and any(self.backend.one(row['pid'])==row for _,row in handles):time.sleep(0.05)
                for fd,row in handles:
                    if self.backend.one(row['pid'])!=row:continue
                    try:self.backend.send(fd,signal.SIGKILL)
                    except ProcessLookupError:pass
            finally:
                for fd,_ in handles:self.backend.close(fd)
        return {'schema':1,'host':self.files.host,'release_id':self.files.release_id,
            'terminated':terminated,'empty_observations':empty,'quiesced':True,'isolated_filesystem':self.w.fixture}
