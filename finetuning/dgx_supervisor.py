"""DGX-only unattended execution. Enter installation through root deploy.sh.

Root controls only this run's unit/container; training runs as the designated UID.
Inference services, host firewall and unrelated workloads are never changed.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
from zoneinfo import ZoneInfo

sys.path.insert(0,str(Path(__file__).resolve().parent))


def now():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def cutoff(value):
    date = datetime.fromisoformat(value)
    if date.utcoffset() is None or date.utcoffset().total_seconds() != 32400:
        raise ValueError('Deadline must explicitly use KST +09:00')
    return date.timestamp()


def read_config(path):
    c = json.loads(Path(path).read_text())
    required = {'run_id','root','uid','gid','image','deadline_kst','files'}
    if not required <= c.keys() or c.keys()-required-{'resume_parent','resource_root','retry_policy','environment_parent','purpose','smoke_data_subdir'}:
        raise ValueError('Unexpected DGX configuration fields')
    if not re.fullmatch(r'capstone-dgx-[0-9]{8}(?:-[a-z0-9]+)?', c['run_id']):
        raise ValueError('Unsafe run identifier')
    root = Path(c['root'])
    if not root.is_absolute() or (root.exists() and root.resolve() != root) or len(root.parts) != 5 or root.parts[1] != 'home' or root.parts[3] != 'Capstone_Groot_training':
        raise ValueError('Use /home/USER/Capstone_Groot_training/RUN without symlinks')
    for field in ('resume_parent','resource_root','environment_parent'):
        if field not in c: continue
        parent = Path(c[field])
        if (parent == root or parent.parent != root.parent or not parent.is_absolute()
                or (parent.exists() and parent.resolve() != parent)):
            raise ValueError('Resume only from a distinct sibling run without symlinks')
    if 'resource_root' in c and 'resume_parent' not in c:
        raise ValueError('Resource reuse requires an explicit checkpoint parent')
    if 'environment_parent' in c and 'resume_parent' in c:
        raise ValueError('Fresh training environment reuse is not checkpoint continuation')
    if c.get('purpose','main_training') not in ('main_training','preflight_only'):
        raise ValueError('Unknown run purpose')
    if c.get('purpose')=='preflight_only' and ('environment_parent' not in c or 'retry_policy' in c):
        raise ValueError('Preflight only reuses an existing environment without automatic retries')
    if 'smoke_data_subdir' in c and c['smoke_data_subdir']!='smoke':
        raise ValueError('Only the manifest-bound data/smoke directory is allowed')
    if 'retry_policy' in c:
        policy=c['retry_policy']
        if (not ('resume_parent' in c or ('environment_parent' in c and c.get('purpose')=='main_training')) or not isinstance(policy,dict)
                or set(policy)!={'max_attempts','idle_seconds'}
                or type(policy['max_attempts']) is not int or not 1<=policy['max_attempts']<=32
                or type(policy['idle_seconds']) is not int or not 30<=policy['idle_seconds']<=300):
            raise ValueError('Require a bounded resume retry policy')
    if any(type(c[k]) is not int or c[k] < 1000 for k in ('uid','gid')):
        raise ValueError('Training must use an unprivileged identity')
    if not re.fullmatch(r'nvcr.io/nvidia/pytorch@sha256:[a-f0-9]{64}', c['image']):
        raise ValueError('Pin an exact NVIDIA image digest')
    cutoff(c['deadline_kst'])
    if not c['files']:
        raise ValueError('Require an immutable input manifest')
    for rel, digest in c['files'].items():
        p = Path(rel)
        if p.is_absolute() or '..' in p.parts or p.parts[0] not in ('source','data','profiles','installer','guide-candidates') or not re.fullmatch('[a-f0-9]{64}', digest):
            raise ValueError('Unsafe manifest entry')
    return c


def resource_config(c):
    """Resolve the original validated environment, never an empty resume mountpoint."""
    origin=c
    seen=set()
    declared=[]
    for _ in range(64):
        if c['root'] in seen: raise ValueError('Cyclic resume provenance')
        seen.add(c['root'])
        verify_files(c)
        if 'resource_root' in c:declared.append(c['resource_root'])
        parent_root=c.get('resume_parent') or c.get('environment_parent')
        if parent_root is None:
            if any(root!=c['root'] for root in declared):
                raise ValueError('Declared resource root differs from original provenance')
            return c
        parent=read_config(Path(parent_root)/'control.json')
        if (parent['root']!=parent_root
                or any(parent[k]!=origin[k] for k in ('image','uid','gid'))):
            raise ValueError('Resume resource identity differs')
        c=parent
    raise ValueError('Resume provenance chain is too deep')


def verify_files(c):
    root = Path(c['root'])
    for rel, digest in c['files'].items():
        p = root/rel
        if p.is_symlink() or not p.resolve().is_relative_to(root) or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            raise ValueError('Input digest mismatch: '+rel)
        if p.stat().st_uid != 0 or p.stat().st_mode & 0o022:
            raise ValueError('Run inputs must be root owned and not group/world writable')


def save(c, value):
    path = Path(c['root'])/'supervisor-status.json'
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps({**value,'at_kst':now()}, indent=2)+'\n')
    tmp.replace(path)


def docker_args(c, stage):
    root = Path(c['root'])
    data=root/'data'
    if stage=='smoke' and c.get('smoke_data_subdir'):
        data=data/c['smoke_data_subdir']
    args = ['docker','run','--rm','--name',c['run_id']+'-job','--label','capstone.run='+c['run_id'],
        '--user',str(c['uid'])+':'+str(c['gid']), '--cap-drop=ALL','--security-opt=no-new-privileges',
        '--pids-limit=512','--memory=110g','--memory-swap=110g','--shm-size=2g',
        '--mount',f'type=bind,src={root}/workspace,dst=/workspace',
        '--mount',f'type=bind,src={root}/source,dst=/source,readonly',
        '--mount',f'type=bind,src={data},dst=/data,readonly',
        '--mount',f'type=bind,src={root}/profiles,dst=/workspace/profiles,readonly',
        '-w','/workspace']
    if 'resume_parent' in c or 'environment_parent' in c:
        resources = Path(c.get('resource_root') or c.get('environment_parent') or c['resume_parent'])/'workspace'
        for name in ('base','venv'):
            args += ['--mount',f'type=bind,src={resources}/{name},dst=/workspace/{name},readonly']
        if 'resume_parent' in c:
            parent = Path(c['resume_parent'])/'workspace'
            args += ['--mount',f'type=bind,src={parent}/main,dst=/resume,readonly']
    for item in ('TZ=Asia/Seoul','HOME=/workspace','PYTHONDONTWRITEBYTECODE=1','PYTHONUNBUFFERED=1',
        'PIP_NO_CACHE_DIR=1','PIP_DISABLE_PIP_VERSION_CHECK=1','HF_HOME=/workspace/.cache/huggingface',
        'HF_HUB_DISABLE_IMPLICIT_TOKEN=1','HF_HUB_DISABLE_TELEMETRY=1',
        'CUBLAS_WORKSPACE_CONFIG=:4096:8','TOKENIZERS_PARALLELISM=false'):
        args += ['-e',item]
    if stage in ('prepare','smoke','main'):
        args += ['--gpus','all']
    else:
        args += ['--runtime=runc','-e','CUDA_VISIBLE_DEVICES=','-e','NVIDIA_VISIBLE_DEVICES=void']
    if stage not in ('prepare','download') or (stage=='download' and 'environment_parent' in c):
        args += ['--network=none','-e','HF_HUB_OFFLINE=1','-e','TRANSFORMERS_OFFLINE=1']
    python = 'python3' if stage == 'prepare' else '/workspace/venv/bin/python'
    return args+[c['image'], python,'-IB','/source/dgx_task.py',stage]


def loading_inference_process(proc=Path('/proc')):
    # /api/ps need not show a model while its worker is still allocating memory.
    # Recognize only Ollama's known worker executables; never signal these PIDs.
    for directory in proc.iterdir():
        if not directory.name.isdigit():
            continue
        try:
            args = (directory/'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, ProcessLookupError):
            continue
        executable = args[0].decode(errors='replace')
        if (executable == '/usr/local/lib/ollama/llama-server'
                or (Path(executable).name == 'ollama' and len(args)>1 and args[1] == b'runner')):
            return True
    return False


def shared_model_active():
    # If a shared Ollama workload appears, yield our training resources.
    if loading_inference_process():
        return True
    with urllib.request.urlopen('http://127.0.0.1:11434/api/ps', timeout=0.5) as response:
        return bool(json.load(response)['models'])


class SharedInferenceBusy(RuntimeError):
    """Only this resource-contention condition permits a bounded retry."""


def check_shared_during_training():
    try:
        active=shared_model_active()
    except (OSError, ValueError) as exc:
        raise SharedInferenceBusy('Shared inference state unavailable; releasing only this training') from exc
    if active:
        raise SharedInferenceBusy('Shared inference became active; stopping only this training')


def stop_container(c):
    # Exact run-owned name AND label. Never stop services or other containers.
    name = c['run_id']+'-job'
    result = subprocess.run(['docker','inspect',name], capture_output=True, text=True)
    if result.returncode:
        return
    info = json.loads(result.stdout)[0]
    if info.get('Config',{}).get('Labels',{}).get('capstone.run') != c['run_id']:
        raise RuntimeError('Refuse to stop a container not owned by this run')
    subprocess.run(['docker','kill',name], check=True)


def verified_operator_release(c):
    """Skip the repeated smoke only for the exact reviewed data/runtime bundle."""
    if 'data/release.json'not in c['files']:return False
    release=json.loads((Path(c['root'])/'data/release.json').read_text())
    if (release.get('status')!='ready_for_bounded_training' or release.get('gpu_preflight_passed')is not True
            or release.get('train_sha256')!=c['files'].get('data/train.jsonl')):
        raise ValueError('Operator release does not bind the passed GPU test and training data')
    expected={name.removeprefix('source/'):digest for name,digest in c['files'].items()if name.startswith('source/')}
    if release.get('runtime_sources')!=expected:raise ValueError('Operator release runtime coverage or digest differs')
    return True


def run_once(c, *, smoke_only=False):
    if (c.get('purpose')=='preflight_only') != smoke_only:
        raise ValueError('Preflight cannot enter the main-training execution path')
    if 'environment_parent' in c and resource_config(c)['root']!=c['environment_parent']:
        raise ValueError('Environment reuse must name the original resource root')
    root = Path(c['root'])
    if (root/'supervisor-status.json').exists():
        raise RuntimeError('Run already attempted; restarting is not automatic')
    status = {'status':'running','started_at_kst':now(),'deadline_kst':c['deadline_kst'],
              'purpose':'preflight_only' if smoke_only else 'main_training'}
    save(c,status)
    try:
        if smoke_only:
            stages=('download','tokenize','smoke')
        elif 'resume_parent' in c:
            stages=('resume-check','download','tokenize','main')
        elif 'environment_parent' in c:
            stages=('download','tokenize','main')if verified_operator_release(c)else('download','tokenize','smoke','main')
        else:
            stages=('prepare','download','tokenize','smoke','main')
        for stage in stages:
            verify_files(c)
            if time.time() >= cutoff(c['deadline_kst'])-900:
                raise RuntimeError('No new stage inside checkpoint grace period')
            status['stage'] = stage
            save(c,status)
            previous=root/'workspace'/(stage+'-status.json')
            if stage=='resume-check' and previous.exists():
                if json.loads(previous.read_text())['status']!='completed':
                    raise RuntimeError('Previous checkpoint continuation check failed')
                continue
            if stage=='prepare' and previous.exists():
                if json.loads(previous.read_text())['status']!='completed':
                    raise RuntimeError('Previous preparation failed')
                hardware=json.loads((root/'workspace/hardware.json').read_text())
                if hardware['compute_capability']!=[12,1] or hardware['cuda_forward_backward']!='passed':
                    raise RuntimeError('Previous environment was not validated on Spark')
                continue
            while stage in ('smoke','main') and shared_model_active():
                if time.time() >= cutoff(c['deadline_kst'])-900:
                    raise RuntimeError('Shared inference stayed active until the training cutoff')
                status.update(stage='waiting_for_shared_inference',pending_stage=stage)
                save(c,status)
                time.sleep(10)
            status.update(stage=stage)
            status.pop('pending_stage',None)
            save(c,status)
            with (root/'workspace'/(stage+'.log')).open('a', buffering=1) as log:
                child = subprocess.Popen(docker_args(c,stage), stdout=log, stderr=subprocess.STDOUT)
                try:
                    while child.poll() is None:
                        if time.time() >= cutoff(c['deadline_kst']):
                            raise RuntimeError('Hard deadline reached')
                        if stage in ('smoke','main'):
                            check_shared_during_training()
                        time.sleep(0.25 if stage in ('smoke','main') else 5)
                    if child.returncode:
                        raise RuntimeError(stage+' container failed: '+str(child.returncode))
                finally:
                    if child.poll() is None:
                        stop_container(c)
                        child.wait(timeout=20)
            receipt=json.loads((root/'workspace'/(stage+'-status.json')).read_text())
            if stage=='main' and receipt['status'] in ('stopped_deadline','completed_training_validation_pending'):
                status['status']=receipt['status']
                return
            if receipt['status'] != 'completed':
                raise RuntimeError(stage+' did not produce a completion receipt')
        status['status'] = 'completed'
    except BaseException as exc:
        status.update(status='failed', error=type(exc).__name__+': '+str(exc))
        raise
    finally:
        save(c,status)


def available_memory():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):return int(line.split()[1])*1024
    raise RuntimeError('MemAvailable is unavailable')


def wait_idle(c, status):
    """Require a continuous healthy idle window; never unload shared models."""
    start=None
    while time.time()<cutoff(c['deadline_kst'])-900:
        try:
            idle=not shared_model_active() and available_memory()>=96*2**30
        except (OSError, ValueError):
            idle=False
        if not idle:start=None
        elif start is None:start=time.monotonic()
        elapsed=0 if start is None else time.monotonic()-start
        status.update(stage='waiting_for_idle_resources',idle_seconds=round(elapsed))
        save(c,status)
        if elapsed>=c['retry_policy']['idle_seconds']:return True
        time.sleep(2)
    return False


def newest_checkpoint(root, minimum):
    from resume_training import verified_completion
    output=Path(root)/'workspace/main'
    if not output.exists():return None
    candidates=[]
    for checkpoint in output.glob('checkpoint-*'):
        try:receipt=verified_completion(output,checkpoint)
        except (OSError,ValueError,KeyError):continue
        if receipt['step']>minimum:candidates.append(receipt['step'])
    return max(candidates) if candidates else None


def run(c):
    if 'retry_policy' not in c:return run_once(c)
    from prepare_dgx_resume import build, build_fresh
    root=Path(c['root'])
    if (root/'supervisor-status.json').exists():
        raise RuntimeError('Controller already attempted; refuse implicit restart')
    status={'status':'running','started_at_kst':now(),'deadline_kst':c['deadline_kst'],'attempts':[]}
    parent=Path(c['resume_parent'])if 'resume_parent'in c else None
    step=json.loads((root/'profiles/resume.json').read_text())['step']if parent else 0
    try:
        for number in range(1,c['retry_policy']['max_attempts']+1):
            verify_files(c)
            if not wait_idle(c,status):
                status.update(status='stopped_deadline',stage='idle_cutoff');return
            attempt=root.with_name(root.name+'-a'+str(number))
            if parent is None:
                build_fresh(c,attempt)
            else:
                build(parent,attempt,c['run_id'],c['deadline_kst'],root/'source',step)
            current=read_config(attempt/'control.json')
            status.update(stage='attempt_running',current_attempt_root=str(attempt),resumed_from_step=step)
            record={'attempt':number,'root':str(attempt),'resumed_from_step':step,'started_at_kst':now()}
            status['attempts'].append(record);save(c,status)
            try:
                run_once(current)
            except SharedInferenceBusy as exc:
                record.update(status='yielded_to_shared_inference',error=str(exc),ended_at_kst=now())
                saved=newest_checkpoint(attempt,step)
                if saved is not None:parent,step=attempt,saved
                status.update(latest_checkpoint_parent=str(parent)if parent else None,latest_checkpoint_step=step)
                save(c,status)
                continue
            result=json.loads((attempt/'supervisor-status.json').read_text())
            record.update(status=result['status'],ended_at_kst=now())
            status.update(status=result['status'],stage='finished');return
        status.update(status='stopped_retry_limit',stage='finished')
    except BaseException as exc:
        status.update(status='failed',error=type(exc).__name__+': '+str(exc));raise
    finally:save(c,status)


def reviewed_remaining_seconds(c, window_hours=12):
    """Keep the default window; an explicitly reviewed extension stays bounded."""
    if type(window_hours) is not int or window_hours not in (12, 24):
        raise ValueError('Reviewed installation window must be 12 or 24 hours')
    remaining = int(cutoff(c['deadline_kst'])-time.time())
    if not 1800 < remaining <= window_hours*3600:
        raise ValueError(f'Start only in a reviewed future window of 30 minutes to {window_hours} hours')
    return remaining


def apply(c, path, *, reviewed_window_hours=12):
    if c.get('purpose')=='preflight_only':
        raise ValueError('Preflight-only control cannot start main training')
    if 'environment_parent' in c and resource_config(c)['root']!=c['environment_parent']:
        raise ValueError('Environment reuse must name the original resource root')
    verify_files(c)
    remaining = reviewed_remaining_seconds(c, reviewed_window_hours)
    subprocess.run(['docker','image','inspect',c['image']], check=True, stdout=subprocess.DEVNULL)
    source = Path(c['root'])/'source/dgx_supervisor.py'
    if str(path) != str(Path(c['root'])/'control.json'):
        raise ValueError('Keep the immutable control at the run root')
    # systemd ExecStart paths must not need shell interpolation.
    if any(ch.isspace() for ch in str(path)) or not re.fullmatch(r'[/a-zA-Z0-9_.-]+',str(path)):
        raise ValueError('Unsafe unit path')
    prefix = c['run_id']
    command = f'/usr/bin/python3 -IB {source} --config {path}'
    units = {
        prefix+'.service': '[Unit]\nDescription=Bounded DGX SOC training\nAfter=docker.service network-online.target\n[Service]\nType=simple\nRestart=no\nKillMode=control-group\nTimeoutStopSec=20\nRuntimeMaxSec='+str(remaining)+'\nExecStart='+command+' --run\nExecStopPost='+command+' --stop-container\n',
        prefix+'-deadline.service': '[Unit]\nDescription=Independent DGX training cutoff\n[Service]\nType=oneshot\nExecStart='+command+' --stop\n',
        prefix+'-deadline.timer': '[Unit]\nDescription=KST training hard deadline\n[Timer]\nOnCalendar='+datetime.fromisoformat(c['deadline_kst']).strftime('%Y-%m-%d %H:%M:%S')+' Asia/Seoul\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=true\nUnit='+prefix+'-deadline.service\n[Install]\nWantedBy=timers.target\n'}
    directory = Path('/etc/systemd/system')
    for name in units:
        if (directory/name).exists():
            raise RuntimeError('Existing unit; refuse overwrite')
    for name, body in units.items():
        (directory/name).write_text(body)
    subprocess.run(['systemd-analyze','verify',*[str(directory/n) for n in units]], check=True)
    subprocess.run(['systemctl','daemon-reload'], check=True)
    subprocess.run(['systemctl','enable','--now',prefix+'-deadline.timer'], check=True)
    subprocess.run(['systemctl','is-active','--quiet',prefix+'-deadline.timer'], check=True)
    subprocess.run(['systemctl','start',prefix+'.service'], check=True)
    print(json.dumps({'started':prefix,'deadline_kst':c['deadline_kst'],'at_kst':now()}))


def start_preflight(c, path):
    """PID 1 owns a bounded smoke run; it cannot proceed to the main stage."""
    if c.get('purpose')!='preflight_only' or 'environment_parent' not in c:
        raise ValueError('Require an explicit environment-reusing preflight control')
    verify_files(c)
    resources=resource_config(c)
    if resources['root']!=c['environment_parent']:
        raise ValueError('Preflight environment must name the original resource root')
    workspace=Path(resources['root'])/'workspace'
    prepared=json.loads((workspace/'prepare-status.json').read_text())
    hardware=json.loads((workspace/'hardware.json').read_text())
    if prepared['status']!='completed' or hardware.get('compute_capability')!=[12,1] or hardware.get('cuda_forward_backward')!='passed':
        raise ValueError('Environment has not passed the Spark runtime checks')
    remaining=int(cutoff(c['deadline_kst'])-time.time())
    if not 1800<remaining<=3600:
        raise ValueError('Preflight control needs a bounded 30-to-60-minute window')
    if shared_model_active():raise SharedInferenceBusy('Shared inference is active; no smoke run started')
    if available_memory()<96*2**30:raise RuntimeError('Insufficient available memory for smoke')
    path=Path(path)
    if str(path)!=str(Path(c['root'])/'control.json') or not re.fullmatch(r'[/a-zA-Z0-9_.-]+',str(path)):
        raise ValueError('Unsafe control path')
    if (Path(c['root'])/'supervisor-status.json').exists():raise RuntimeError('Preflight already attempted')
    source=Path(c['root'])/'source/dgx_supervisor.py'
    command=['/usr/bin/python3','-IB',str(source),'--config',str(path)]
    subprocess.run(['systemd-run','--unit='+c['run_id']+'-preflight',
        '--property=RuntimeMaxSec=1800','--property=Restart=no','--property=KillMode=control-group',
        '--property=TimeoutStopSec=20',
        '--property=ExecStopPost='+' '.join(command+['--stop-container']),
        *command,'--run-smoke'],check=True)
    print(json.dumps({'started':c['run_id']+'-preflight','purpose':'preflight_only',
                      'runtime_max_seconds':1800,'main_training_started':False,'at_kst':now()}))


def save_queue(c, status, **fields):
    path=Path(c['root'])/'preflight-queue.json'
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'status':status,'at_kst':now(),'main_training_started':False,**fields},indent=2)+'\n')
    temporary.replace(path)


def wait_for_preflight_idle(c):
    """Reserve 30 minutes for the smoke itself; unknown shared state is busy."""
    idle_since=None
    while time.time()<cutoff(c['deadline_kst'])-1800:
        available=None;reason='shared_inference_active'
        try:
            busy=shared_model_active();available=available_memory()
            if not busy and available<96*2**30:reason='insufficient_available_memory'
            ready=not busy and available>=96*2**30
        except (OSError,ValueError,RuntimeError):
            ready=False;reason='shared_state_unavailable'
        instant=time.time()
        if ready:
            if idle_since is None:idle_since=instant
            if instant-idle_since>=60:return
            reason='confirming_60_seconds_idle'
        else:idle_since=None
        save_queue(c,'waiting',reason=reason,available_bytes=available,deadline_kst=c['deadline_kst'])
        time.sleep(10)
    raise RuntimeError('No idle training window before preflight cutoff')


def run_queued_smoke(c, path):
    if c.get('purpose')!='preflight_only':raise ValueError('Queue accepts only preflight')
    if (Path(c['root'])/'supervisor-status.json').exists():raise RuntimeError('Preflight already attempted')
    try:
        wait_for_preflight_idle(c)
        save_queue(c,'running_smoke',runtime_max_seconds=1800)
        subprocess.run(['/usr/bin/python3','-IB',str(Path(c['root'])/'source/dgx_supervisor.py'),
                        '--config',str(path),'--run-smoke'],check=True,timeout=1800)
        result=json.loads((Path(c['root'])/'supervisor-status.json').read_text())
        if result['status']!='completed':raise RuntimeError('Smoke has no successful completion receipt')
        save_queue(c,'completed',gpu_smoke_passed=True)
    except BaseException as exc:
        save_queue(c,'failed',error=type(exc).__name__+': '+str(exc),gpu_smoke_passed=False)
        raise
    finally:stop_container(c)


def start_preflight_queue(c, path):
    if c.get('purpose')!='preflight_only' or 'environment_parent'not in c:
        raise ValueError('Only fresh-base preflight may wait for shared inference')
    verify_files(c);resources=resource_config(c)
    if resources['root']!=c['environment_parent']:raise ValueError('Require original resource root')
    workspace=Path(resources['root'])/'workspace'
    prepared=json.loads((workspace/'prepare-status.json').read_text())
    hardware=json.loads((workspace/'hardware.json').read_text())
    if prepared['status']!='completed' or hardware.get('compute_capability')!=[12,1] or hardware.get('cuda_forward_backward')!='passed':
        raise ValueError('Environment has not passed the Spark runtime checks')
    remaining=int(cutoff(c['deadline_kst'])-time.time())
    if not 2100<remaining<=12*3600:raise ValueError('Queue needs a bounded window, including a 30-minute smoke reserve')
    path=Path(path);root=Path(c['root'])
    if str(path)!=str(root/'control.json') or not re.fullmatch(r'[/a-zA-Z0-9_.-]+',str(path)):
        raise ValueError('Unsafe control path')
    if any((root/name).exists()for name in ('preflight-queue.json','supervisor-status.json')):
        raise RuntimeError('Preflight queue already attempted')
    command=['/usr/bin/python3','-IB',str(root/'source/dgx_supervisor.py'),'--config',str(path)]
    subprocess.run(['systemd-run','--unit='+c['run_id']+'-preflight',
        '--property=RuntimeMaxSec='+str(remaining),'--property=Restart=no','--property=KillMode=control-group',
        '--property=TimeoutStopSec=20','--property=ExecStopPost='+' '.join(command+['--stop-container']),
        *command,'--run-queued-smoke'],check=True)
    print(json.dumps({'queued':c['run_id']+'-preflight','deadline_kst':c['deadline_kst'],
                      'smoke_runtime_max_seconds':1800,'main_training_started':False,'at_kst':now()}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--reviewed-window-hours',type=int,choices=(12,24),default=12,
                        help='Explicitly reviewed installation window; only --apply may use 24')
    group=parser.add_mutually_exclusive_group(required=True)
    for action in ('check','apply','verify','run','stop','stop-container','prepare-environment','admit-guide','check-resume','smoke-only','run-smoke','queue-smoke','run-queued-smoke'):
        group.add_argument('--'+action,action='store_true')
    args=parser.parse_args()
    if args.reviewed_window_hours != 12 and not args.apply:
        parser.error('--reviewed-window-hours 24 requires --apply')
    c=read_config(args.config)
    if args.check:
        verify_files(c)
        print(json.dumps({'inputs_verified':len(c['files']),'deadline_kst':c['deadline_kst']}))
    elif args.verify:
        verify_files(c)
        units=[c['run_id']+'-preflight.service']if c.get('purpose')=='preflight_only'else[c['run_id']+'.service',c['run_id']+'-deadline.timer']
        subprocess.run(['systemctl','show',*units,
            '-p','ActiveState','-p','SubState','-p','MainPID','-p','Result','-p','NextElapseUSecRealtime'],check=True)
        queue=Path(c['root'])/'preflight-queue.json'
        if queue.exists():print(queue.read_text())
        status=Path(c['root'])/'supervisor-status.json'
        if status.exists(): print(status.read_text())
    else:
        if os.geteuid()!=0: raise PermissionError('Host supervisor requires root; training remains unprivileged')
        if args.check_resume:
            verify_files(c)
            if 'resume_parent' not in c:raise ValueError('Not a checkpoint continuation run')
            command=docker_args(c,'resume-check')
            command[command.index('--memory=110g')]='--memory=4g'
            command[command.index('--memory-swap=110g')]='--memory-swap=4g'
            subprocess.run(command,check=True)
        elif args.admit_guide:
            verify_files(c)
            root=Path(c['root'])
            remaining=int(cutoff(c['deadline_kst'])-time.time())
            if remaining<1200: raise ValueError('Insufficient admission window')
            command=docker_args(c,'tokenize')
            # Separate CPU-only admission. The GPU training job has not started.
            if '--gpus' in command:
                i=command.index('--gpus');del command[i:i+2]
            i=command.index('--name');command[i+1]=c['run_id']+'-admit'
            command[command.index('--memory=110g')]='--memory=4g'
            command[command.index('--memory-swap=110g')]='--memory-swap=4g'
            command=command[:-4]+['--cpus=2','-e','CUDA_VISIBLE_DEVICES=',
                '--mount',f'type=bind,src={root}/guide-candidates,dst=/candidates,readonly',
                c['image'],'/workspace/venv/bin/python','-IB','/source/admit_guide_sft.py',
                '--candidates','/candidates','--evidence','/data','--base','/workspace/base',
                '--output','/workspace/guide-mixed','--train-count','256']
            # Remove the original image which precedes the replaced command.
            del command[command.index(c['image'])]
            subprocess.run(['systemd-run','--unit='+c['run_id']+'-admit','--property=RuntimeMaxSec=1200',
                '--property=Restart=no','--property=ExecStopPost=-/usr/bin/docker kill '+c['run_id']+'-admit',*command],check=True)
        elif args.prepare_environment:
            verify_files(c)
            if cutoff(c['deadline_kst'])-time.time()<1800: raise ValueError('Insufficient preparation window')
            if shared_model_active(): raise RuntimeError('Shared model active')
            subprocess.run(['systemd-run','--unit='+c['run_id']+'-environment',
                '--property=RuntimeMaxSec=1800','--property=Restart=no',
                '--property=ExecStopPost=/usr/bin/python3 -IB '+str(Path(c['root'])/'source/dgx_supervisor.py')+' --config '+str(args.config.resolve())+' --stop-container',
                *docker_args(c,'prepare')],check=True)
        elif args.queue_smoke:start_preflight_queue(c,args.config.resolve())
        elif args.run_queued_smoke:run_queued_smoke(c,args.config.resolve())
        elif args.smoke_only:start_preflight(c,args.config.resolve())
        elif args.run_smoke:run_once(c,smoke_only=True)
        elif args.apply: apply(c,args.config.resolve(),reviewed_window_hours=args.reviewed_window_hours)
        elif args.run: run(c)
        else:
            stop_container(c)
            if args.stop:
                preflight=c.get('purpose')=='preflight_only'
                unit=c['run_id']+('-preflight.service'if preflight else'.service')
                subprocess.run(['systemctl','stop',unit],check=True)
                if preflight:
                    save_queue(c,'stopped_by_operator',gpu_smoke_passed=False)
                    return
                status_path=Path(c['root'])/'supervisor-status.json'
                status=json.loads(status_path.read_text()) if status_path.exists() else {'status':'not_started'}
                if status['status']=='running': status['status']='stopped_deadline'
                save(c,{**status,'hard_cutoff_checked_at_kst':now()})


if __name__=='__main__': main()
