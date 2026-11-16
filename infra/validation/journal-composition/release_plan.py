"""One exact source/helper/control/protected-state contract for the release.

No filesystem writes, commands, network, approvals or model API. Fixed names
and metadata are checked before the operator lifecycle may change a source.
"""
import hashlib
import grp
import importlib.util
import os
from pathlib import Path
import re
import pwd
import stat

HERE=Path(__file__).parent
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
c=load('release_plan_contract','release_status.py')
source=load('release_plan_sources','release_files.py')
cohort=load('release_plan_cohort','cohort_guard.py')
control=load('release_plan_control','release_controls.py')
services=load('release_plan_services','release_services.py')
need=c.need
Refused=c.Refused
HELPERS=frozenset({'release_status.py','cohort_guard.py','cache_transaction.py','reader_bridge.py',
    'release_files.py','release_reader.py','release_mcp_launcher.py','release_state.py','release_services.py',
    'release_controls.py','release_storage.py','release_helpers.py','release_processes.py','release_cache.py',
    'release_lifecycle.py','release_atomic.py','release_plan.py','release_runtime.py'})
COMMON_PROTECTED=frozenset({'/etc/systemd/system/capstone-system-diagnostics.service.d/30-inventory-netlink.conf',
    '/var/lib/capstone-diagnostics/installation/active.json','/var/lib/capstone-diagnostics/installation/intent.json',
    '/var/lib/capstone-diagnostics/installation/prepared.json'})
PROTECTED={h:COMMON_PROTECTED|({'/etc/nftables.conf'}if h=='a'else{
    '/etc/capstone-ollama-trial/config.json','/etc/capstone-review-chat/config.json','/opt/hermes-data/.env',
    '/opt/hermes-data/SOUL.md','/opt/hermes-data/config.yaml','/opt/hermes-data/management/config.yaml',
    '/etc/mcp/system-diagnostics.json','/etc/mcp/system-diagnostics/known_hosts'}if h=='b'else set())for h in c.TARGETS}
for _host in PROTECTED:
    PROTECTED[_host]|={str(Path('/etc/systemd/system')/name)for values in services.catalog(_host).values()
                       for name in values if str(Path('/etc/systemd/system')/name)not in source.TARGETS[_host]}
PROTECTED['b']|={'/etc/systemd/system/capstone-management.service.d/10-timeout.conf'}
PROTECTED['a']|={'/etc/capstone-diagnostics/monitor.json','/etc/capstone-diagnostics/observer_known_hosts'}
OPTIONAL_PROTECTED='/var/lib/capstone-diagnostics/installation/prepared.json'


def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):return sha(c.canonical(value))


class Plan:
    def __init__(self,value):
        need(isinstance(value,dict)and set(value)=={'schema','release_id','source_commit','hosts','helpers','cohort'}
             and type(value['schema'])is int and value['schema']==1,'plan_shape')
        need(isinstance(value['release_id'],str)and c.RELEASE.fullmatch(value['release_id'])
             and isinstance(value['source_commit'],str)and re.fullmatch('[0-9a-f]{40}',value['source_commit']),'plan_identity')
        helpers=value['helpers'];need(isinstance(helpers,dict)and set(helpers)==HELPERS
             and all(isinstance(v,str)and c.HEX.fullmatch(v)for v in helpers.values()),'plan_helper_set')
        hosts=value['hosts'];need(isinstance(hosts,dict)and set(hosts)==set(c.TARGETS),'plan_hosts')
        self.cohort=cohort.Cohort(value['cohort']);need(self.cohort.release_id==value['release_id'],'plan_cohort_release')
        for host,item in hosts.items():
            need(isinstance(item,dict)and set(item)=={'rows','machine_sha256','diagnostic_gid','reader_uid','mcp_uid','container','protected'},'plan_host_shape')
            need(isinstance(item['machine_sha256'],str)and c.HEX.fullmatch(item['machine_sha256'])
                 and all(type(item[k])is int and 1<=item[k]<65534 for k in ('diagnostic_gid','reader_uid')),'plan_machine_account')
            if host=='b':
                need(type(item['mcp_uid'])is int and 1<=item['mcp_uid']<65534 and item['mcp_uid']!=item['reader_uid'],'plan_mcp_account')
                container=item['container'];need(isinstance(container,dict)and set(container)=={'id','image','restart','running'}
                    and isinstance(container['id'],str)and re.fullmatch('[0-9a-f]{64}',container['id'])
                    and isinstance(container['image'],str)and re.fullmatch('sha256:[0-9a-f]{64}',container['image'])
                    and container['restart']=='unless-stopped'and container['running']is True,'plan_container')
            else:need(item['mcp_uid']is None and item['container']is None,'plan_container_host')
            rows=item['rows'];need(isinstance(rows,list)and len(rows)==len(source.TARGETS[host])
                and all(isinstance(r,dict)and set(r)=={'target','before_sha256','after_sha256','uid','gid','mode'}for r in rows)
                and {r['target']for r in rows}==source.TARGETS[host],'plan_source_set')
            need({r['target']:r for r in rows if r['target']not in source.BARRIERS[host]}==self.cohort.rows[host],'plan_source_cohort')
            for row in rows:
                if row['target']not in source.BARRIERS[host]:continue
                need(all(isinstance(row[k],str)and c.HEX.fullmatch(row[k])for k in ('before_sha256','after_sha256'))
                     and type(row['uid'])is int and row['uid']==0 and type(row['gid'])is int and 0<=row['gid']<65534
                     and type(row['mode'])is int and row['mode']==(0o550 if row['target']==source.READER else 0o750),'plan_barrier_metadata')
            protected=item['protected'];need(isinstance(protected,dict)and set(protected)==PROTECTED[host],'plan_protected_set')
            for path,row in protected.items():
                if row is None:need(path==OPTIONAL_PROTECTED,'plan_required_protected_file');continue
                need(isinstance(row,dict)and set(row)=={'sha256','uid','gid','mode'}
                     and isinstance(row['sha256'],str)and c.HEX.fullmatch(row['sha256'])
                     and all(type(row[k])is int and 0<=row[k]<65534 for k in ('uid','gid'))
                     and type(row['mode'])is int and row['mode']in (0o550,0o600,0o640,0o644,0o750),'plan_protected_metadata')
        self.value=value;self.sha256=digest(value)

    def bundle(self):
        return {'schema':1,'release_id':self.value['release_id'],'plan_sha256':self.sha256,'helpers':self.value['helpers'],
            'payloads':{h:{r['target']:r['after_sha256']for r in item['rows']}for h,item in self.value['hosts'].items()},
            'controls':{h:{str(p):sha(raw)for p,raw in control.documents(h,self.value['release_id'],self.sha256).items()}for h in c.TARGETS}}

    def verify(self,files,*,protected=True):
        need(files.release_id==self.value['release_id']and files.rows==self.value['hosts'][files.host]['rows'],'plan_file_binding')
        w=files.witness;host=self.value['hosts'][files.host]
        need(w.fixture or HERE.resolve()==files.storage,'private_operator_code_required')
        if not w.fixture:
            need(grp.getgrnam('capstone-diagnostics').gr_gid==host['diagnostic_gid']
                 and pwd.getpwnam('capstone-diagnostics').pw_uid==host['reader_uid'],'diagnostic_account_changed')
            if files.host=='b':need(pwd.getpwnam('mcp').pw_uid==host['mcp_uid'],'mcp_account_changed')
        for name,expected in self.value['helpers'].items():
            raw,meta=w.read(files.storage/name)
            need(sha(raw)==expected and(meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode))==
                (w.owner,os.getgid()if w.fixture else 0,0o600),'operator_helper_changed')
        raw,meta=w.read(files.root/'etc/machine-id',limit=64)
        need(re.fullmatch(rb'[0-9a-f]{32}\n?',raw)and sha(raw)==host['machine_sha256']
             and meta.st_uid==w.owner and not stat.S_IMODE(meta.st_mode)&0o022,'operator_machine_changed')
        if protected:
            for path,expected in host['protected'].items():
                raw,meta=w.read(files.root/path.lstrip('/'),limit=262144,absent=expected is None)
                if expected is None:need(raw is None,'protected_file_appeared');continue
                need(raw is not None and sha(raw)==expected['sha256']and(meta.st_uid,meta.st_gid,stat.S_IMODE(meta.st_mode))==
                    (w.owner if w.fixture else expected['uid'],os.getgid()if w.fixture else expected['gid'],expected['mode']),'protected_state_changed')
        return {'schema':1,'host':files.host,'plan_sha256':self.sha256,'helpers_verified':len(HELPERS),
            'protected_verified':len(host['protected'])if protected else 0,'isolated_filesystem':w.fixture}
