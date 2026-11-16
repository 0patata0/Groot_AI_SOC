"""Fixed native lifecycle primitives for the operator's journal coordinator.

No CLI or approval interface. A controller must first bind exact approval,
fences, a durable baseline and fresh coherent proofs. This module neither
installs those fences nor authorizes resumption merely because a unit is idle.
Fixtures require an explicit Python runner; production cannot inject one.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

SPEC=importlib.util.spec_from_file_location('release_service_contract',Path(__file__).with_name('release_status.py'))
c=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(c)
need=c.need
Refused=c.Refused
COLLECTION_TIMERS=('capstone-system-diagnostics.timer',)
COLLECTION_SERVICES=('capstone-journal-reader.service','capstone-system-diagnostics.service','capstone-diagnostic-history-backfill.service')
A_TIMERS=('capstone-soc-observe.timer',)
A_SERVICES=('capstone-soc-observe.service',)
B_TIMERS=('capstone-management.timer','capstone-hermes-guard-reapply.timer','capstone-harness2-audit.timer',
          'capstone-soc-model.timer','capstone-soc-ingestion.timer')
B_SERVICES=('capstone-management.service','capstone-ollama-chat.service','capstone-review-chat.service',
            'capstone-hermes-guard-reapply.service','capstone-harness2-audit.service','capstone-harness2-context.service',
            'capstone-soc-model.service','capstone-soc-ingestion.service')
PROPERTIES=('Id','LoadState','UnitFileState','ActiveState','SubState','MainPID','FragmentPath','Result',
            'Type','KillMode','TimeoutStopUSec','MemoryHigh','MemoryMax','MemorySwapMax','TasksMax','LimitNOFILE',
            'TimeoutStartUSec','Conditions','ConditionResult','ExecMainStartTimestampMonotonic','ExecMainStatus',
            'User','DropInPaths','NeedDaemonReload','MemoryAccounting','TasksAccounting')
OPTIONAL='capstone-diagnostic-history-backfill.service'
INSPECT='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"restarting":{{json .State.Restarting}},"paused":{{json .State.Paused}},"dead":{{json .State.Dead}},"pid":{{json .State.Pid}},"restart":{{json .HostConfig.RestartPolicy}}}'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/nonexistent','DOCKER_CONFIG':'/nonexistent',
     'DOCKER_HOST':'unix:///var/run/docker.sock','LANG':'C','LC_ALL':'C','TZ':'Asia/Seoul',
     'SYSTEMD_PAGER':'','SYSTEMD_COLORS':'0','PYTHONDONTWRITEBYTECODE':'1'}
NETLINK='/etc/systemd/system/capstone-system-diagnostics.service.d/30-inventory-netlink.conf'
MANAGEMENT_TIMEOUT='/etc/systemd/system/capstone-management.service.d/10-timeout.conf'


def existing_dropins(name):
    return {NETLINK}if name=='capstone-system-diagnostics.service'else{MANAGEMENT_TIMEOUT}if name=='capstone-management.service'else set()


def release_dropin(name):return '/etc/systemd/system/'+name+'.d/95-capstone-journal-release.conf'


def catalog(host):
    need(isinstance(host,str)and host in ('a','b','c'),'service_host')
    timers=A_TIMERS if host=='a'else B_TIMERS if host=='b'else ()
    services=A_SERVICES if host=='a'else B_SERVICES if host=='b'else ()
    return {'collection_timers':COLLECTION_TIMERS,'collection_services':COLLECTION_SERVICES,
            'consumer_timers':timers,'consumer_services':services}


class Native:
    baseline_dropins=staticmethod(existing_dropins)
    def __init__(self,host,container,*,filesystem_root=Path('/'),runner=None):
        self.host=host;self.groups=catalog(host);self.units=frozenset(n for items in self.groups.values()for n in items)
        self.root=Path(filesystem_root);need(self.root.is_absolute()and '..'not in self.root.parts,'filesystem_root')
        self.fixture=self.root!=Path('/')
        need(callable(runner)if self.fixture else runner is None and os.getuid()==os.geteuid()==0,'native_execution_boundary')
        self.runner=runner
        if host=='b':
            need(isinstance(container,dict)and set(container)=={'id','image','restart','running'},'container_plan')
            need(isinstance(container['id'],str)and re.fullmatch('[0-9a-f]{64}',container['id'])
                 and isinstance(container['image'],str)and re.fullmatch('sha256:[0-9a-f]{64}',container['image']),'container_identity')
            need(container['restart']=='unless-stopped'and container['running']is True,'container_original_policy')
            self.container=dict(container)
        else:need(container is None,'container_host_scope');self.container=None

    def run(self,args,*,timeout=15,max_bytes=65536):
        need(isinstance(args,list)and args and args[0]in ('/usr/bin/systemctl','/usr/local/bin/docker')
             and all(isinstance(a,str)and '\0'not in a and len(a)<=4096 for a in args),'native_command_scope')
        need(type(timeout)is int and 1<=timeout<=180,'native_command_timeout')
        if args[0]=='/usr/bin/systemctl':
            allowed=(args==['/usr/bin/systemctl','daemon-reload']or
                len(args)==5 and args[1]=='show'and args[2]in self.units and args[3:] ==['--no-pager','--property='+','.join(PROPERTIES)]or
                len(args)==4 and args[1:3]==['stop','--no-block']and args[3]in self.units or
                len(args)==3 and args[1]=='start'and args[2]in self.units)
        else:
            need(self.host=='b','container_host_scope');cid=self.container['id']
            allowed=(args==['/usr/local/bin/docker','inspect','--format',INSPECT,cid]or
                args==['/usr/local/bin/docker','update','--restart=no',cid]or
                args==['/usr/local/bin/docker','update','--restart=unless-stopped',cid]or
                args==['/usr/local/bin/docker','stop','--time','20',cid]or args==['/usr/local/bin/docker','start',cid])
        need(allowed,'native_command_scope')
        if self.fixture:r=self.runner(args,timeout=timeout)
        else:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,env=dict(ENV))
        need(type(r.returncode)is int and r.returncode==0 and isinstance(r.stdout,bytes)and len(r.stdout)<=max_bytes,'native_command_failed')
        return r.stdout

    def probe(self,name):
        need(isinstance(name,str)and name in self.units,'service_target')
        raw=self.run(['/usr/bin/systemctl','show',name,'--no-pager','--property='+','.join(PROPERTIES)]).decode()
        values={}
        for line in raw.splitlines():
            key,sep,value=line.partition('=');need(sep and key in PROPERTIES and key not in values,'unit_property_shape');values[key]=value
        need(values.get('Id')==name and values.get('LoadState')in ('loaded','not-found'),'unit_identity')
        need(values['LoadState']=='loaded'or name==OPTIONAL,'required_unit_missing')
        need(values.get('ActiveState')in ('active','inactive','failed','activating','deactivating'),'unit_active_state')
        return values

    def snapshot(self):return {name:self.probe(name)for name in sorted(self.units)}

    def stop(self,group):
        need(group in ('collection','consumer'),'service_group')
        self.stop_timers(group);self.stop_services(group)

    def stop_timers(self,group):
        need(group in ('collection','consumer'),'service_group');self._stop(self.groups[group+'_timers'])

    def stop_services(self,group):
        need(group in ('collection','consumer'),'service_group');self._stop(self.groups[group+'_services'])

    def _stop(self,names):
        for name in names:
            value=self.probe(name)
            if value['LoadState']=='not-found':continue
            if value['ActiveState']=='inactive'and value.get('MainPID','0')=='0':continue
            self.run(['/usr/bin/systemctl','stop','--no-block',name])

    def stopped(self,group):
        need(group in ('collection','consumer'),'service_group')
        result={name:self.probe(name)for name in (*self.groups[group+'_timers'],*self.groups[group+'_services'])}
        return all(v['LoadState']=='not-found'or(v['ActiveState']in ('inactive','failed')and v.get('MainPID','0')=='0')for v in result.values())

    def wait_stopped(self,group,*,timeout=30):
        need(type(timeout)is int and 1<=timeout<=30,'stop_timeout')
        end=time.monotonic()+timeout
        while not self.stopped(group):
            need(time.monotonic()<end,'services_not_quiesced');time.sleep(0.1)

    def resume_original(self,group,before):
        need(group in ('collection','consumer')and isinstance(before,dict)and set(before)==self.units,'baseline_unit_set')
        need(all(isinstance(row,dict)and row.get('Id')==name and row.get('ActiveState')in ('active','inactive','failed','activating','deactivating')for name,row in before.items()),'baseline_unit_identity')
        self.loaded_matches(group,before)
        for name in (*self.groups[group+'_services'],*self.groups[group+'_timers']):
            row=before[name];need(isinstance(row,dict)and row.get('Id')==name,'baseline_unit_identity')
            if row['ActiveState']!='active':continue
            current=self.probe(name)
            need(current['LoadState']=='loaded','resume_unit_missing')
            if current['ActiveState']=='active':continue
            self.run(['/usr/bin/systemctl','start',name],timeout=100)
            need(self.probe(name)['ActiveState']=='active','unit_did_not_resume')

    def loaded_matches(self,group,before):
        need(group in ('collection','consumer')and isinstance(before,dict)and set(before)==self.units,'baseline_unit_set')
        for name in (*self.groups[group+'_services'],*self.groups[group+'_timers']):
            value=self.probe(name)
            if value['LoadState']=='not-found':
                need(name==OPTIONAL and before[name]['LoadState']=='not-found','resume_unit_missing');continue
            expected=set(before[name].get('DropInPaths','').split())
            if(self.root/release_dropin(name).lstrip('/')).exists():expected.add(release_dropin(name))
            fragment=before[name].get('FragmentPath')or '/etc/systemd/system/'+name
            need(value.get('FragmentPath')==fragment and value.get('NeedDaemonReload')=='no'
                 and set(value.get('DropInPaths','').split())==expected,'resume_unit_configuration_changed')

    def bootstrap_collection(self,*,backfill=False):
        """After applied sources and collection-fence removal, before bots."""
        self.run(['/usr/bin/systemctl','daemon-reload'])
        self.collection_resources()
        old_reader=self.probe('capstone-journal-reader.service')
        need(old_reader['ActiveState']in ('inactive','failed')and old_reader.get('MainPID','0')=='0','reader_must_be_stopped')
        self.run(['/usr/bin/systemctl','start','capstone-journal-reader.service'],timeout=15)
        reader=self.probe('capstone-journal-reader.service')
        need(reader['ActiveState']=='active'and int(reader.get('MainPID','0'))>1
             and int(reader.get('ExecMainStartTimestampMonotonic','0'))>int(old_reader.get('ExecMainStartTimestampMonotonic','0')),'reader_not_restarted')
        for name,timeout in [('capstone-system-diagnostics.service',100)]+([(OPTIONAL,165)]if backfill else []):
            before=self.probe(name);self.run(['/usr/bin/systemctl','start',name],timeout=timeout);after=self.probe(name)
            need(after.get('ConditionResult')=='yes'and after.get('Result')=='success'and after.get('ExecMainStatus')=='0'
                 and int(after.get('ExecMainStartTimestampMonotonic','0'))>int(before.get('ExecMainStartTimestampMonotonic','0')),
                 'collection_did_not_execute')

    def collection_resources(self):
        result={}
        for name,timeout in [('capstone-system-diagnostics.service','1min 25s'),(OPTIONAL,'2min 30s')]:
            value=self.probe(name);expected={'LoadState':'loaded','Type':'oneshot','MemoryAccounting':'yes','MemoryHigh':str(192*1024*1024),
                'MemoryMax':str(256*1024*1024),'MemorySwapMax':'0','TasksAccounting':'yes','TasksMax':'64','LimitNOFILE':'1024',
                'KillMode':'control-group','TimeoutStartUSec':timeout,'TimeoutStopUSec':'5s','NeedDaemonReload':'no'}
            need(all(value.get(k)==v for k,v in expected.items()),'collection_resource_mismatch');result[name]=value
        reader=self.probe('capstone-journal-reader.service')
        need(reader.get('MemoryMax')==str(128*1024*1024)and reader.get('TasksMax')=='8'and reader.get('LimitNOFILE')=='1024'
             and reader.get('KillMode')=='control-group'and reader.get('NeedDaemonReload')=='no','reader_resource_mismatch')
        result['capstone-journal-reader.service']=reader
        for name,value in result.items():
            need(value.get('FragmentPath')=='/etc/systemd/system/'+name and value.get('User')in ('','root')
                 and set(value.get('DropInPaths','').split())==existing_dropins(name)|{release_dropin(name)},'collection_loaded_source_mismatch')
        return result

    def docker(self):
        need(self.host=='b','container_host_scope')
        raw=self.run(['/usr/local/bin/docker','inspect','--format',INSPECT,self.container['id']]);value=c.parsed(raw)
        need(isinstance(value,dict)and set(value)=={'id','image','running','restarting','paused','dead','pid','restart'},'container_observation')
        need(value['id']==self.container['id']and value['image']==self.container['image'],'container_changed')
        need(all(type(value[k])is bool for k in ('running','restarting','paused','dead'))and type(value['pid'])is int and value['pid']>=0,'container_state')
        need(isinstance(value['restart'],dict)and set(value['restart'])=={'Name','MaximumRetryCount'}
             and value['restart']['Name']in ('no','unless-stopped')and type(value['restart']['MaximumRetryCount'])is int
             and value['restart']['MaximumRetryCount']==0,'container_restart_policy')
        need(not value['restarting']and not value['paused']and not value['dead'],'container_not_stable')
        return value

    def stop_container(self):
        value=self.docker()
        if value['restart']['Name']!='no':self.run(['/usr/local/bin/docker','update','--restart=no',self.container['id']])
        need(self.docker()['restart']['Name']=='no','container_boot_fence_failed')
        if self.docker()['running']:self.run(['/usr/local/bin/docker','stop','--time','20',self.container['id']],timeout=30)
        value=self.docker();need(not value['running']and value['pid']==0,'container_not_stopped')

    def require_original_container(self):
        value=self.docker();need(value['running']==self.container['running']and value['restart']['Name']==self.container['restart'],'container_baseline_changed')
        return value

    def resume_container(self):
        value=self.docker()
        if value['restart']['Name']!=self.container['restart']:
            self.run(['/usr/local/bin/docker','update','--restart='+self.container['restart'],self.container['id']])
        if not self.docker()['running']:self.run(['/usr/local/bin/docker','start',self.container['id']],timeout=30)
        value=self.docker();need(value['running']and value['pid']>1 and value['restart']['Name']==self.container['restart'],'container_did_not_resume')
