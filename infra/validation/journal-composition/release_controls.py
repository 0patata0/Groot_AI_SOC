"""Fixed maintenance fences and owned systemd documents, without execution.

Only the operator controller creates these artifacts after exact-plan checks.
Existing unrelated drop-ins, SSH configuration, credentials and security
engines are outside the allowlist. The controller separately starts/verifies
the watchdog before changing consumers or sources.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import uuid

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
c=load('release_control_contract','release_status.py')
services=load('release_control_services','release_services.py')
atomic=load('release_control_atomic','release_atomic.py')
need=c.need
Refused=c.Refused
BASE=c.BASE
COLLECTION=BASE/'collection-fenced'
CONSUMERS=BASE/'consumers-fenced'
MCP=Path('/etc/mcp/system-diagnostics/release-fenced')
DROPIN='95-capstone-journal-release.conf'
STATUS='capstone-journal-release-status.service'
WATCH='capstone-journal-release-watchdog.service'
TIMER='capstone-journal-release-watchdog.timer'
RUNNER='capstone-journal-release-run@.service'
UNIT_DIR=Path('/etc/systemd/system')


def documents(host,release_id,plan_sha256):
    c.request({'schema':1,'host':host,'release_id':release_id})
    need(isinstance(plan_sha256,str)and c.HEX.fullmatch(plan_sha256),'control_plan_digest')
    paths={};groups=services.catalog(host)
    for group,marker in (('collection',COLLECTION),('consumer',CONSUMERS)):
        for name in (*groups[group+'_timers'],*groups[group+'_services']):
            paths[UNIT_DIR/(name+'.d')/DROPIN]=('[Unit]\n# Journal release '+release_id+' plan '+plan_sha256+' host '+host+'\nConditionPathExists=!'+str(marker)+'\n').encode()
    code=BASE/release_id/host
    common=('User=root\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n'
            'PrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectControlGroups=yes\n'
            'ProtectClock=yes\nLockPersonality=yes\nMemoryAccounting=yes\nTasksAccounting=yes\nMemorySwapMax=0\n'
            'LimitNOFILE=1024\nKillMode=control-group\nTimeoutStopSec=5s\n')
    paths[UNIT_DIR/STATUS]=(
        '[Unit]\nDescription=Read-only fixed journal release witness\nAfter=local-fs.target\n'
        '[Service]\nType=simple\nGroup=capstone-diagnostics\n'+common+
        'ExecStart=/usr/bin/python3 -IB '+str(code/'release_status.py')+' --host '+host+' --release-id '+release_id+'\n'
        'RuntimeDirectory=capstone-journal-release-status\nRuntimeDirectoryMode=0750\n'
        'ReadWritePaths=/run/capstone-journal-release-status\nRestrictAddressFamilies=AF_UNIX\n'
        'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN\nMemoryHigh=64M\nMemoryMax=96M\nTasksMax=8\n'
        'Restart=on-failure\nRestartSec=2s\nStandardOutput=null\n[Install]\nWantedBy=multi-user.target\n').encode()
    writes=['/var/lib/capstone-journal-release','/var/lib/capstone-diagnostics','/opt/capstone-diagnostics','/etc/systemd/system']
    if host=='b':writes+=['/opt/capstone-management','/opt/capstone-ollama-trial','/opt/capstone-review-chat',
        '/opt/hermes-data/management-code','/opt/hermes-data/plugins/groot-query-completion','/opt/mcp',
        '/etc/capstone-ollama-trial','/etc/capstone-review-chat','/etc/mcp/system-diagnostics']
    native=(common+'ReadWritePaths='+' '.join(writes)+'\nRestrictAddressFamilies=AF_UNIX'+(' AF_INET'if host in ('a','b')else '')+'\n'
        'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID CAP_SYS_PTRACE\n'
        'MemoryHigh=192M\nMemoryMax=256M\nTasksMax=64\nTimeoutStartSec=330s\n')
    command='/usr/bin/python3 -IB '+str(code/'release_runtime.py')+' --host '+host+' --release-id '+release_id+' --plan-sha256 '+plan_sha256+' --operation '
    paths[UNIT_DIR/WATCH]=('[Unit]\nDescription=Independent fixed journal release recovery\nAfter=local-fs.target '+STATUS+
        (' docker.service network-online.target'if host=='b'else ' network-online.target'if host=='a'else '')+'\nWants='+STATUS+'\n[Service]\nType=oneshot\n'+native+
        'SuccessExitStatus=75\nExecStart='+command+'recover\n').encode()
    paths[UNIT_DIR/RUNNER]=('[Unit]\nDescription=Exact-plan journal release action %i\nAfter='+STATUS+
        '\n[Service]\nType=oneshot\n'+native+'ExecStart='+command+'%i\n').encode()
    paths[UNIT_DIR/TIMER]=('[Unit]\nDescription=Independent persistent journal release recovery check\n'
        '[Timer]\nOnBootSec=5s\nOnUnitInactiveSec=10s\nAccuracySec=1s\nUnit='+WATCH+
        '\n[Install]\nWantedBy=timers.target\n').encode()
    return paths


class Files:
    def __init__(self,source_files,plan_sha256):
        need(isinstance(plan_sha256,str)and c.HEX.fullmatch(plan_sha256),'control_plan_digest')
        self.files=source_files;self.w=source_files.witness;self.root=self.w.root
        self.docs=documents(source_files.host,source_files.release_id,plan_sha256)
        self.markers={'collection':COLLECTION,'consumer':CONSUMERS}
        if source_files.host=='b':self.markers['mcp']=MCP
        self.allowed=set(self.docs)|set(self.markers.values())
        self.token=c.canonical({'schema':1,'host':source_files.host,'release_id':source_files.release_id,'plan_sha256':plan_sha256})

    def path(self,relative):
        need(relative in self.allowed,'control_path_scope');return self.root/relative.relative_to('/')

    def parent(self,relative,*,create=False):
        path=self.path(relative);parent=path.parent
        if create and relative in self.docs and relative.name==DROPIN:
            # Only the one fixed unit drop-in directory can be created; its
            # parent /etc/systemd/system is already trusted and never replaced.
            fd=self.w.directory(parent.parent)
            try:
                try:os.mkdir(parent.name,0o755,dir_fd=fd)
                except FileExistsError:pass
                os.fsync(fd)
            finally:os.close(fd)
        return self.w.directory(parent)

    def read(self,relative,*,mode):
        raw,st=self.w.read(self.path(relative),limit=65536,absent=True)
        if st is None:return None,None
        need((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(self.w.owner,os.getgid()if self.w.fixture else 0,mode),'control_file_metadata')
        return raw,st

    def create(self,relative,raw,*,mode):
        need(isinstance(raw,bytes)and 0<len(raw)<=65536 and mode in (0o600,0o644),'control_payload')
        need((relative in self.docs and raw==self.docs[relative]and mode==0o644)
             or(relative in self.markers.values()and raw==self.token and mode==0o600),'control_payload_not_in_plan')
        parent=self.parent(relative,create=True);name='.control-'+uuid.uuid4().hex;created=False
        try:
            existing,_=self.read(relative,mode=mode)
            if existing is not None:need(existing==raw,'foreign_control_file');return False
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent);created=True
            with os.fdopen(fd,'wb')as stream:
                os.fchown(stream.fileno(),self.w.owner,os.getgid()if self.w.fixture else 0);os.fchmod(stream.fileno(),mode)
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            atomic.create(parent,name,relative.name);created=False;os.fsync(parent)
        finally:
            if created:
                try:os.unlink(name,dir_fd=parent)
                except FileNotFoundError:pass
            os.close(parent)
        value,_=self.read(relative,mode=mode);need(value==raw,'control_not_verified');return True

    def remove(self,relative,expected,*,mode):
        need((relative in self.docs and expected==self.docs[relative]and mode==0o644)
             or(relative in self.markers.values()and expected==self.token and mode==0o600),'control_payload_not_in_plan')
        raw,st=self.read(relative,mode=mode)
        if raw is None:return False
        need(raw==expected,'foreign_control_file');parent=self.parent(relative)
        try:
            need(c.stamp(os.stat(relative.name,dir_fd=parent,follow_symlinks=False))==c.stamp(st),'control_file_changed')
            os.unlink(relative.name,dir_fd=parent);os.fsync(parent)
        finally:os.close(parent)
        return True

    def fence(self,kind):
        need(isinstance(kind,str)and kind in self.markers,'fence_kind')
        return self.create(self.markers[kind],self.token,mode=0o600)

    def unfence(self,kind):
        need(isinstance(kind,str)and kind in self.markers,'fence_kind')
        return self.remove(self.markers[kind],self.token,mode=0o600)

    def fenced(self,kind):
        need(isinstance(kind,str)and kind in self.markers,'fence_kind')
        raw,_=self.read(self.markers[kind],mode=0o600)
        need(raw is None or raw==self.token,'foreign_control_file');return raw is not None

    def install(self):
        # Preflight all existing files before creating any new document.
        for path,raw in self.docs.items():
            try:existing,_=self.read(path,mode=0o644)
            except FileNotFoundError:existing=None
            need(existing is None or existing==raw,'foreign_control_file')
        return sum(self.create(path,raw,mode=0o644)for path,raw in self.docs.items())

    def remove_documents(self):
        # Do not stop/delete units here. The controller separately proves
        # helpers are stopped and global consumers can run without the relay.
        for path,raw in self.docs.items():
            try:existing,_=self.read(path,mode=0o644)
            except FileNotFoundError:existing=None
            need(existing is None or existing==raw,'foreign_control_file')
        count=0
        for path,raw in self.docs.items():
            try:count+=self.remove(path,raw,mode=0o644)
            except FileNotFoundError:pass
        return count
