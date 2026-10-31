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
import time
import urllib.request
from zoneinfo import ZoneInfo


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
    if not required <= c.keys() or c.keys()-required-{'resume_parent'}:
        raise ValueError('Unexpected DGX configuration fields')
    if not re.fullmatch(r'capstone-dgx-[0-9]{8}(?:-[a-z0-9]+)?', c['run_id']):
        raise ValueError('Unsafe run identifier')
    root = Path(c['root'])
    if not root.is_absolute() or (root.exists() and root.resolve() != root) or len(root.parts) != 5 or root.parts[1] != 'home' or root.parts[3] != 'Capstone_Groot_training':
        raise ValueError('Use /home/USER/Capstone_Groot_training/RUN without symlinks')
    if 'resume_parent' in c:
        parent = Path(c['resume_parent'])
        if (parent == root or parent.parent != root.parent or not parent.is_absolute()
                or (parent.exists() and parent.resolve() != parent)):
            raise ValueError('Resume only from a distinct sibling run without symlinks')
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
    args = ['docker','run','--rm','--name',c['run_id']+'-job','--label','capstone.run='+c['run_id'],
        '--user',str(c['uid'])+':'+str(c['gid']), '--cap-drop=ALL','--security-opt=no-new-privileges',
        '--pids-limit=512','--memory=110g','--memory-swap=110g','--shm-size=2g',
        '--mount',f'type=bind,src={root}/workspace,dst=/workspace',
        '--mount',f'type=bind,src={root}/source,dst=/source,readonly',
        '--mount',f'type=bind,src={root}/data,dst=/data,readonly',
        '--mount',f'type=bind,src={root}/profiles,dst=/workspace/profiles,readonly',
        '-w','/workspace']
    if 'resume_parent' in c:
        parent = Path(c['resume_parent'])/'workspace'
        for name in ('base','venv'):
            args += ['--mount',f'type=bind,src={parent}/{name},dst=/workspace/{name},readonly']
        args += ['--mount',f'type=bind,src={parent}/main,dst=/resume,readonly']
    for item in ('TZ=Asia/Seoul','HOME=/workspace','PYTHONDONTWRITEBYTECODE=1','PYTHONUNBUFFERED=1',
        'PIP_NO_CACHE_DIR=1','PIP_DISABLE_PIP_VERSION_CHECK=1','HF_HOME=/workspace/.cache/huggingface',
        'HF_HUB_DISABLE_IMPLICIT_TOKEN=1','HF_HUB_DISABLE_TELEMETRY=1',
        'CUBLAS_WORKSPACE_CONFIG=:4096:8','TOKENIZERS_PARALLELISM=false'):
        args += ['-e',item]
    if stage in ('prepare','smoke','main'):
        args += ['--gpus','all']
    if stage not in ('prepare','download'):
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
    with urllib.request.urlopen('http://127.0.0.1:11434/api/ps', timeout=3) as response:
        return bool(json.load(response)['models'])


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


def run(c):
    root = Path(c['root'])
    if (root/'supervisor-status.json').exists():
        raise RuntimeError('Run already attempted; restarting is not automatic')
    status = {'status':'running','started_at_kst':now(),'deadline_kst':c['deadline_kst']}
    save(c,status)
    try:
        stages = ('resume-check','download','tokenize','main') if 'resume_parent' in c else ('prepare','download','tokenize','smoke','main')
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
                        if stage in ('smoke','main') and shared_model_active():
                            raise RuntimeError('Shared inference became active; stopping only this training')
                        time.sleep(1 if stage in ('smoke','main') else 5)
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


def apply(c, path):
    verify_files(c)
    remaining = int(cutoff(c['deadline_kst'])-time.time())
    if not 1800 < remaining <= 12*3600:
        raise ValueError('Start only in a reviewed future window of 30 minutes to 12 hours')
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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    group=parser.add_mutually_exclusive_group(required=True)
    for action in ('check','apply','verify','run','stop','stop-container','prepare-environment','admit-guide','check-resume'):
        group.add_argument('--'+action,action='store_true')
    args=parser.parse_args()
    c=read_config(args.config)
    if args.check:
        verify_files(c)
        print(json.dumps({'inputs_verified':len(c['files']),'deadline_kst':c['deadline_kst']}))
    elif args.verify:
        verify_files(c)
        subprocess.run(['systemctl','show',c['run_id']+'.service',c['run_id']+'-deadline.timer',
            '-p','ActiveState','-p','SubState','-p','MainPID','-p','Result','-p','NextElapseUSecRealtime'],check=True)
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
        elif args.apply: apply(c,args.config.resolve())
        elif args.run: run(c)
        else:
            stop_container(c)
            if args.stop:
                subprocess.run(['systemctl','stop',c['run_id']+'.service'],check=True)
                status_path=Path(c['root'])/'supervisor-status.json'
                status=json.loads(status_path.read_text()) if status_path.exists() else {'status':'not_started'}
                if status['status']=='running': status['status']='stopped_deadline'
                save(c,{**status,'hard_cutoff_checked_at_kst':now()})


if __name__=='__main__': main()
