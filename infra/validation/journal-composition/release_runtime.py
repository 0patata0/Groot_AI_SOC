#!/usr/bin/env python3
"""Fixed operator entry point and independent recovery dispatch, not an MCP.

Root-only fixed private path, pinned plan and every helper before importing
project code. Existing read-only peer identities are used without copying keys.
Cleanup/current-installation acceptance is a separate, not-yet-connected gate.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timedelta,timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

BASE=Path('/var/lib/capstone-journal-release')
KST=timezone(timedelta(hours=9))
OPERATIONS=('initialize','prepare','arm','quiesce','backup','apply','verify','confirm','resume','rollback',
            'revert_fence','revert','recover','status','peers','dispatch')


def need(value,code):
    if not value:raise ValueError(code)


def pairs(items):
    value={}
    for key,item in items:need(key not in value,'duplicate_key');value[key]=item
    return value


def parsed(raw):
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))


def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def directory(path):
    need(path.is_absolute()and '..'not in path.parts,'operator_path')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.relative_to('/').parts:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            item=os.fstat(fd);need(item.st_uid==0 and not stat.S_IMODE(item.st_mode)&0o022,'operator_directory')
        if path.is_relative_to(BASE):need(stat.S_IMODE(os.fstat(fd).st_mode)==0o700,'operator_private_directory')
        return fd
    except BaseException:os.close(fd);raise


def read(path,*,limit,mode):
    parent=directory(path.parent)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb')as stream:
            before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode)and before.st_nlink==1
                and before.st_uid==0 and stat.S_IMODE(before.st_mode)==mode and 0<before.st_size<=limit,'operator_file')
            raw=stream.read(limit+1);after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            fields=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            need(fields(before)==fields(after)==fields(named)and len(raw)==before.st_size,'operator_file_changed');return raw
    finally:os.close(parent)


def bootstrap(host,release_id,plan_sha256):
    need(sys.platform=='linux'and os.getuid()==os.geteuid()==0,'root_operator_required')
    need(host in ('a','b','c')and re.fullmatch('[0-9a-f]{32}',release_id)
         and re.fullmatch('[0-9a-f]{64}',plan_sha256),'operator_identity')
    root=BASE/release_id/host
    need(Path(__file__).absolute()==root/'release_runtime.py','fixed_operator_entry_required')
    raw=read(root/'plan.json',limit=2*1024*1024,mode=0o600);value=parsed(raw)
    need(sha(canonical(value))==plan_sha256 and isinstance(value,dict)and value.get('release_id')==release_id,'operator_plan_changed')
    helpers=value.get('helpers');need(isinstance(helpers,dict)and 1<=len(helpers)<=32 and 'release_runtime.py'in helpers,'operator_helper_manifest')
    for name,expected in helpers.items():
        need(isinstance(name,str)and re.fullmatch(r'[a-z_]+\.py',name)and isinstance(expected,str)
             and re.fullmatch('[0-9a-f]{64}',expected),'operator_helper_name')
        need(sha(read(root/name,limit=2*1024*1024,mode=0o600))==expected,'operator_helper_changed')
    return root,value


def bounded(argv,raw,env,*,identity=None):
    """One owned, bounded SSH child; no shell or inherited authentication env."""
    options={}
    if identity is not None:options.update(user=identity.pw_uid,group=identity.pw_gid,extra_groups=os.getgrouplist(identity.pw_name,identity.pw_gid))
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        cwd='/',env=dict(env),start_new_session=True,**options)
    output=bytearray();errors=0;deadline=time.monotonic()+12
    try:
        process.stdin.write(raw);process.stdin.close()
        with selectors.DefaultSelector()as poller:
            for stream in (process.stdout,process.stderr):os.set_blocking(stream.fileno(),False);poller.register(stream,selectors.EVENT_READ)
            while poller.get_map():
                need(time.monotonic()<deadline,'peer_observation_timeout')
                for key,_ in poller.select(min(0.2,max(0,deadline-time.monotonic()))):
                    chunk=os.read(key.fileobj.fileno(),4096)
                    if not chunk:poller.unregister(key.fileobj);continue
                    if key.fileobj is process.stdout:output.extend(chunk);need(len(output)<=65536,'peer_reply_bound')
                    else:errors+=len(chunk);need(errors<=4096,'peer_error_bound')
        need(process.wait(timeout=max(0.1,deadline-time.monotonic()))==0,'peer_observation_unavailable');return parsed(bytes(output))
    finally:
        if process.poll()is None:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=3)
        for stream in (process.stdout,process.stderr):stream.close()


class Context:
    def __init__(self,host,release_id,plan_sha256):
        self.root,self.plan=bootstrap(host,release_id,plan_sha256);self.host=host;self.release_id=release_id;self.plan_sha=plan_sha256
        def load(name):
            need(name in self.plan['helpers'],'unlisted_operator_module')
            spec=importlib.util.spec_from_file_location('operator_'+name.replace('.py',''),self.root/name)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
        self.modules={name:load(name)for name in ('release_files.py','release_state.py','release_storage.py','release_controls.py',
            'release_services.py','release_helpers.py','release_processes.py','release_cache.py','release_lifecycle.py')}
        item=self.plan['hosts'][host];self.files=self.modules['release_files.py'].FileSet(host,release_id,item['rows'],item['diagnostic_gid'])
        journal=self.modules['release_state.py'].Journal(self.files,plan_sha256);store=self.modules['release_storage.py'].Store(self.files,plan_sha256)
        controls=self.modules['release_controls.py'].Files(self.files,plan_sha256)
        native=self.modules['release_services.py'].Native(host,item['container']);helpers=self.modules['release_helpers.py'].Manager(self.files,plan_sha256)
        readers=self.modules['release_processes.py'].Readers(self.files,controls,journal,item['reader_uid'],item['mcp_uid'])
        cache=self.modules['release_cache.py'].Cache(host,item['diagnostic_gid'],self.files.storage/'cache')
        self.lifecycle=self.modules['release_lifecycle.py'].Lifecycle(self.files,cache,journal,store,controls,native,helpers,readers)
        self.lifecycle.contract.verify(self.files,protected=False)

    def peers(self):
        self.lifecycle.contract.verify(self.files)
        need(self.host in ('a','b'),'peer_transport_not_installed_on_c')
        if self.host=='a':
            cfg=parsed(read(Path('/etc/capstone-diagnostics/monitor.json'),limit=8192,mode=0o600));names={'b','c'}
            key=Path('/etc/capstone-diagnostics/observer_ed25519');known=Path('/etc/capstone-diagnostics/observer_known_hosts');mode=0o600;identity=None
        else:
            cfg=parsed(read(Path('/etc/mcp/system-diagnostics.json'),limit=4096,mode=0o640));names={'a','c'}
            key=Path('/etc/mcp/system-diagnostics/id_ed25519');known=Path('/etc/mcp/system-diagnostics/known_hosts');mode=0o640;identity=pwd.getpwnam('mcp')
            need(identity.pw_uid==self.plan['hosts']['b']['mcp_uid'],'peer_mcp_identity')
        need(isinstance(cfg,dict)and cfg.get('schema')==1 and isinstance(cfg.get('hosts'),dict)and set(cfg['hosts'])==names
             and type(cfg.get('ssh_port'))is int and 1<=cfg['ssh_port']<=65535,'peer_route_configuration')
        # Validate metadata without copying the existing private key anywhere.
        parent=directory(key.parent)
        try:
            meta=os.stat(key.name,dir_fd=parent,follow_symlinks=False)
            need(stat.S_ISREG(meta.st_mode)and meta.st_nlink==1 and meta.st_uid==0 and stat.S_IMODE(meta.st_mode)==mode,'peer_key_metadata')
        finally:os.close(parent)
        read(known,limit=32768,mode=mode)
        def one(host):
            address=cfg['hosts'][host];need(isinstance(address,str),'peer_address')
            parsed_address=ipaddress.IPv4Address(address)
            need(str(parsed_address)==address and not(parsed_address.is_unspecified or parsed_address.is_multicast or parsed_address.is_loopback),'peer_address')
            argv=['/usr/bin/ssh','-F','/dev/null','-T','-p',str(cfg['ssh_port']),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ControlMaster=no','-o','ControlPath=none',
                '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','ConnectTimeout=4',
                '-o','ConnectionAttempts=1','-o','UserKnownHostsFile='+str(known),'-i',str(key),'capstone-diagnostics@'+address]
            raw=canonical({'release_status':{'schema':1,'host':host,'release_id':self.release_id}})
            return host,bounded(argv,raw,self.modules['release_services.py'].ENV,identity=identity)
        with ThreadPoolExecutor(max_workers=2)as pool:result=dict(pool.map(one,sorted(names)))
        result[self.host]=self.lifecycle.local_proof();return result

    def dispatch(self,operation):
        need(operation in self.modules['release_helpers.py'].OPERATIONS and operation!='arm','dispatch_operation')
        with self.lifecycle.store.locked():
            self.lifecycle.store.require_active()
            self.lifecycle.authorize(recovery=operation=='rollback'or operation=='resume'and self.lifecycle.state()['phase']=='rolled_back',
                revert=operation in ('revert_fence','revert'),protected=operation!='rollback')
        unit=self.lifecycle.helpers.start_operation(operation)
        return {'status':'submitted','unit':unit,'operation':operation,'completion_verified':False}


def arguments(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',choices=('a','b','c'),required=True)
    parser.add_argument('--release-id',required=True);parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--operation',choices=OPERATIONS,required=True)
    parser.add_argument('--deadline-kst');parser.add_argument('--action')
    value=parser.parse_args(argv)
    need(bool(value.deadline_kst)==(value.operation=='initialize')and bool(value.action)==(value.operation=='dispatch'),'operator_argument_scope')
    return value


def input_proof():
    raw=sys.stdin.buffer.read(2*1024*1024+1);need(0<len(raw)<=2*1024*1024,'operator_proof_input_bound');return parsed(raw)


def main():
    args=arguments();context=Context(args.host,args.release_id,args.plan_sha256);ctl=context.lifecycle
    if args.operation=='initialize':result=ctl.initialize(datetime.fromisoformat(args.deadline_kst))
    elif args.operation=='status':result=ctl.local_control_proof()
    elif args.operation=='peers':result=context.peers()
    elif args.operation=='dispatch':result=context.dispatch(args.action)
    else:
        proof=None
        if args.operation in ('arm','confirm','resume'):proof=context.peers()if args.host in ('a','b')else input_proof()
        elif args.operation in ('apply','revert'):proof=input_proof()
        result=ctl.execute(args.operation,proofs=proof)
        if args.operation=='recover'and result['phase']=='rolled_back'and args.host in ('a','b')\
                and not any(result['facts'].get(k)for k in ('baseline_services_resumed','services_untouched')):
            try:result=ctl.execute('resume',proofs=context.peers())
            except (OSError,ValueError,KeyError):
                result={**ctl.state(),'resume_deferred':True,'reason':'fresh_coherent_baseline_required'}
    print(canonical({'schema':1,'host':args.host,'release_id':args.release_id,'plan_sha256':args.plan_sha256,
        'at_kst':datetime.now(KST).isoformat(),'operation':args.operation,'result':result}).decode())


if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)
        reason=reason if re.fullmatch('[a-z0-9_]{1,80}',reason)else'operator_operation_unavailable'
        deferred=reason in ('host_operation_busy','operation_busy')
        print(canonical({'schema':1,'status':'deferred'if deferred else'unavailable','reason':reason,
            'completion_verified':False,'at_kst':datetime.now(KST).isoformat()}).decode())
        raise SystemExit(75 if deferred else 1)from None
