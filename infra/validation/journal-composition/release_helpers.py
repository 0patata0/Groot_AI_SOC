"""Fixed service-manager actions for this release's four owned helper units.

No general unit, command, container or environment interface is exposed. This
does not authorize source changes or a resume; the coordinator checks those.
"""
import importlib.util
import os
from pathlib import Path
import re
import subprocess

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
c=load('release_helper_contract','release_status.py')
controls=load('release_helper_documents','release_controls.py')
services=load('release_helper_services','release_services.py')
need=c.need
Refused=c.Refused
OPERATIONS=frozenset({'arm','quiesce','backup','apply','verify','confirm','resume','rollback','revert_fence','revert','cleanup'})
PROPERTIES=(*services.PROPERTIES,'NextElapseUSecMonotonic','LastTriggerUSecMonotonic')


def scheduled(value):
    """systemctl prints monotonic USec as a duration on the actual hosts."""
    need(isinstance(value,str)and 0<len(value)<=256,'timer_clock_shape')
    if value in ('0','n/a','infinity'):return False
    if re.fullmatch(r'[0-9]{1,20}',value):return int(value)>0
    ranks={'y':9,'month':8,'w':7,'d':6,'h':5,'min':4,'s':3,'ms':2,'us':1};previous=10;positive=False
    for token in value.split(' '):
        match=re.fullmatch(r'([0-9]{1,20}(?:\.[0-9]{1,9})?)(y|month|w|d|h|min|ms|us|s)',token)
        need(match is not None and ranks[match[2]]<previous,'timer_clock_shape');previous=ranks[match[2]]
        positive|=any(ch in '123456789'for ch in match[1])
    return positive


class Manager:
    def __init__(self,files,plan_sha256,*,runner=None):
        self.files=files;self.w=files.witness
        need(callable(runner)if self.w.fixture else runner is None and os.getuid()==os.geteuid()==0,'helper_execution_boundary')
        self.runner=runner;self.docs=controls.documents(files.host,files.release_id,plan_sha256)
        self.static=frozenset({controls.STATUS,controls.WATCH,controls.TIMER})
        self.units=self.static|{self.instance(operation)for operation in OPERATIONS}

    @staticmethod
    def instance(operation):
        need(isinstance(operation,str)and operation in OPERATIONS,'helper_operation')
        return 'capstone-journal-release-run@'+operation+'.service'

    def run(self,args,*,timeout=15):
        need(type(timeout)is int and 1<=timeout<=30,'helper_timeout')
        need(isinstance(args,list)and args and args[0]=='/usr/bin/systemctl','helper_command_scope')
        allowed=(args==['/usr/bin/systemctl','daemon-reload']or
            len(args)==5 and args[1]=='show'and args[2]in self.units and args[3:]==['--no-pager','--property='+','.join(PROPERTIES)]or
            len(args)==3 and args[1]in ('start','stop')and args[2]in self.static or
            len(args)==4 and args[1:3]==['start','--no-block']and args[3]in self.units-self.static or
            len(args)==4 and args[1]in ('enable','disable')and args[2]=='--now'and args[3]in (controls.STATUS,controls.TIMER))
        need(allowed,'helper_command_scope')
        result=(self.runner(args,timeout=timeout)if self.w.fixture else subprocess.run(args,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=dict(services.ENV),timeout=timeout))
        need(type(result.returncode)is int and result.returncode==0 and isinstance(result.stdout,bytes)
             and len(result.stdout)<=65536,'helper_command_failed')
        return result.stdout

    def probe(self,name):
        value=self.inspect(name)
        fragment=controls.RUNNER if name not in self.static else name
        need(value.get('LoadState')=='loaded'
             and value.get('FragmentPath')==str(controls.UNIT_DIR/fragment),'helper_unit_identity')
        need(value.get('DropInPaths')==''and value.get('NeedDaemonReload')=='no','helper_unit_overridden')
        return value

    def inspect(self,name):
        need(isinstance(name,str)and name in self.units,'helper_unit')
        raw=self.run(['/usr/bin/systemctl','show',name,'--no-pager','--property='+','.join(PROPERTIES)]).decode()
        value={}
        for line in raw.splitlines():
            key,sep,item=line.partition('=');need(sep and key in PROPERTIES and key not in value,'helper_property_shape');value[key]=item
        need(value.get('Id')==name,'helper_unit_identity')
        return value

    def stopped(self,*,finishing=False):
        need(type(finishing)is bool,'helper_cleanup_scope')
        result={name:self.inspect(name)for name in sorted(self.units)}
        for name,value in result.items():
            fragment=str(controls.UNIT_DIR/(controls.RUNNER if name not in self.static else name))
            need(value.get('LoadState')in ('loaded','not-found')and value.get('FragmentPath')in ('',fragment)
                 and value.get('DropInPaths')=='','helper_cleanup_unit_changed')
            own=finishing and name==self.instance('cleanup')and value.get('MainPID')==str(os.getpid())
            need(own or value.get('ActiveState')in ('inactive','failed')and value.get('MainPID','0')=='0','helper_not_stopped')
        return result

    def documents_match(self):
        """Check files as well as manager state; a saved document is not a load."""
        for path,raw in self.docs.items():
            found,st=self.w.read(self.w.root/path.relative_to('/'),limit=65536)
            import stat
            need(found==raw and(st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==
                (self.w.owner,os.getgid()if self.w.fixture else 0,0o644),'helper_document_changed')

    def armed(self):
        self.documents_match();status=self.probe(controls.STATUS);timer=self.probe(controls.TIMER);watch=self.probe(controls.WATCH)
        need(status.get('ActiveState')=='active'and status.get('UnitFileState')=='enabled'
             and status.get('Type')=='simple'and int(status.get('MainPID','0'))>1,'status_not_running')
        next_tick=scheduled(timer.get('NextElapseUSecMonotonic','0'))
        executing=watch.get('ActiveState')in ('active','activating')and int(watch.get('MainPID','0'))>1
        need(timer.get('ActiveState')=='active'and timer.get('UnitFileState')=='enabled'
             and(next_tick or executing),'watchdog_not_armed')
        need(watch.get('Type')=='oneshot'and watch.get('TimeoutStartUSec')=='5min 30s'
             and watch.get('MemoryHigh')==str(192*1024*1024)and watch.get('MemoryMax')==str(256*1024*1024)
             and watch.get('MemorySwapMax')=='0'and watch.get('TasksMax')=='64'
             and watch.get('LimitNOFILE')=='1024','watchdog_resource_contract')
        return {name:self.probe(name)for name in (controls.STATUS,controls.WATCH,controls.TIMER)}

    def arm(self):
        self.documents_match();self.run(['/usr/bin/systemctl','daemon-reload'])
        self.run(['/usr/bin/systemctl','enable','--now',controls.STATUS])
        self.run(['/usr/bin/systemctl','enable','--now',controls.TIMER]);return self.armed()

    def start_operation(self,operation):
        name=self.instance(operation);self.armed();state=self.probe(name)
        need(state.get('ActiveState')in ('inactive','failed')and state.get('MainPID','0')=='0','operation_already_running')
        self.run(['/usr/bin/systemctl','start','--no-block',name]);return name

    def operation_running(self,operation):
        state=self.probe(self.instance(operation))
        return state.get('ActiveState')in ('active','activating','deactivating')or int(state.get('MainPID','0'))>0

    def disarm(self,*,finishing=False):
        """Only after global reconciliation; a local success is insufficient."""
        need(type(finishing)is bool,'helper_cleanup_scope');self.documents_match()
        for operation in OPERATIONS:
            running=self.operation_running(operation)
            own=(finishing is True and operation=='cleanup'and running
                 and self.probe(self.instance(operation)).get('MainPID')==str(os.getpid()))
            need(not running or own,'helper_action_still_running')
        self.run(['/usr/bin/systemctl','disable','--now',controls.TIMER])
        self.run(['/usr/bin/systemctl','stop',controls.WATCH])
        self.run(['/usr/bin/systemctl','disable','--now',controls.STATUS])
        for name in self.static:
            state=self.probe(name);need(state.get('ActiveState')in ('inactive','failed')and state.get('MainPID','0')=='0','helper_not_stopped')
        for name in (controls.STATUS,controls.TIMER):need(self.probe(name).get('UnitFileState')=='disabled','helper_not_disabled')
