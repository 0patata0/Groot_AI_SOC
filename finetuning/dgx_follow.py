"""Follow one authorized training plan across estimated, bounded time windows.

Install through deploy.sh --training-dgx-follow. Never edit an active run,
restart an unknown failure, change training mathematics, or stop shared inference.
"""
import argparse
from datetime import datetime
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

KST = ZoneInfo('Asia/Seoul')
POLICY_FIELDS = {'schema', 'root', 'unit', 'parent_control', 'parent_sha256',
                 'authorized_at_kst', 'max_steps', 'initial_step', 'initial_started_at_kst',
                 'fallback_seconds_per_step', 'validation_seconds', 'startup_seconds',
                 'save_grace_seconds', 'poll_seconds', 'files'}


def stamp():
    return datetime.now(KST).isoformat()


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def read(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Symlink is not an accepted state file')
    return json.loads(path.read_text())


def trusted(path):
    path = Path(path)
    if path.resolve() != path or path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise ValueError('Require root-owned, non-writable, non-symlink control/source')


def load_policy(path):
    path = Path(path)
    trusted(path)
    p = read(path)
    if set(p) != POLICY_FIELDS or p['schema'] != 1:
        raise ValueError('Unexpected follow policy')
    root = Path(p['root'])
    if path != root/'follow.json' or len(root.parts) != 5 or root.parts[1] != 'home' or root.parts[3] != 'Capstone_Groot_training':
        raise ValueError('Require a separate training sibling directory')
    trusted(root)
    if not re.fullmatch(r'capstone-dgx-[0-9]{8}-follow[a-z0-9]*', p['unit']):
        raise ValueError('Unsafe follow unit')
    if not re.fullmatch(r'[/a-zA-Z0-9_.-]+', str(root)):
        raise ValueError('Unsafe unit path')
    parent = Path(p['parent_control'])
    if parent.name != 'control.json' or parent.parent.parent != root.parent or parent.parent == root:
        raise ValueError('Parent must be a distinct sibling run')
    trusted(parent)
    if sha(parent) != p['parent_sha256']:
        raise ValueError('Authorized parent control changed')
    for key in ('authorized_at_kst', 'initial_started_at_kst'):
        if datetime.fromisoformat(p[key]).utcoffset().total_seconds() != 32400:
            raise ValueError('Use explicit KST timestamps')
    limits = {'max_steps': (1, 10000000), 'initial_step': (1, p['max_steps']-1),
              'fallback_seconds_per_step': (1, 3600), 'validation_seconds': (600, 14400),
              'startup_seconds': (60, 3600), 'save_grace_seconds': (900, 900),
              'poll_seconds': (15, 300)}
    for key, (low, high) in limits.items():
        if type(p[key]) not in (int, float) or not math.isfinite(p[key]) or not low <= p[key] <= high:
            raise ValueError('Invalid policy timing/step bound: '+key)
    if type(p['max_steps']) is not int or type(p['initial_step']) is not int:
        raise ValueError('Steps must be integers')
    if set(p['files']) != {'deploy.sh', 'finetuning/dgx_follow.py'}:
        raise ValueError('Unexpected follow bundle')
    for name, digest in p['files'].items():
        trusted(root/name)
        if sha(root/name) != digest:
            raise ValueError('Follow source digest mismatch')
    return p


def runtime(p):
    # Imports are exclusively from the original manifest-verified source bundle.
    parent = read(p['parent_control'])
    root = Path(parent['root'])
    for rel, digest in parent['files'].items():
        path = root/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or not path.resolve().is_relative_to(root):
            raise ValueError('Unsafe parent manifest path')
        trusted(path)
        if sha(path) != digest:
            raise ValueError('Original run input changed')
    sys.path.insert(0, str(root/'source'))
    dgx = importlib.import_module('dgx_supervisor')
    builder = importlib.import_module('prepare_dgx_resume')
    resume = importlib.import_module('resume_training')
    parent = dgx.read_config(p['parent_control'])
    if parent.get('purpose', 'main_training') != 'main_training':
        raise ValueError('Only an authorized main training plan can be followed')
    if read(root/'profiles/resume.json')['step'] != p['initial_step']:
        raise ValueError('Initial step differs from authorized continuation')
    return dgx, builder, resume, parent


def command(args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def bound_control(path, origin, dgx, resume):
    path = Path(path)
    trusted(path)
    c = dgx.read_config(path)
    if Path(c['root']) != path.parent or path.parent.parent != Path(origin['root']).parent:
        raise ValueError('Followed run is outside the authorized training directory')
    dgx.verify_files(c)
    for key in ('uid', 'gid', 'image'):
        if c[key] != origin[key]:
            raise ValueError('Training identity changed')
    for rel, digest in origin['files'].items():
        if rel.startswith(('source/', 'data/')) and c['files'].get(rel) != digest:
            raise ValueError('Training source/data changed: '+rel)
    current = read(path.parent/'profiles/main.json')
    old = read(Path(origin['root'])/'profiles/main.json')
    if ({k:v for k,v in current.items() if k not in resume.RUNTIME_FIELDS}
            != {k:v for k,v in old.items() if k not in resume.RUNTIME_FIELDS}):
        raise ValueError('Training mathematics changed')
    return c


def snapshot(c):
    root = Path(c['root'])
    status = read(root/'supervisor-status.json')
    attempt = Path(status.get('current_attempt_root', root))
    if attempt != root and (attempt.parent != root.parent or not re.fullmatch(re.escape(root.name)+r'-a[1-9][0-9]*', attempt.name)):
        raise ValueError('Unexpected attempt location')
    props = dict(line.split('=',1) for line in command(['systemctl','show',c['run_id']+'.service',
        '-p','LoadState','-p','ActiveState','-p','SubState','-p','MainPID','-p','Result']).splitlines())
    if props.get('LoadState') != 'loaded':
        raise RuntimeError('Training service handle is missing')
    names = command(['docker','ps','--filter','label=capstone.run='+c['run_id'],'--format','{{.Names}}']).splitlines()
    if any(name != c['run_id']+'-job' for name in names):
        raise RuntimeError('Unexpected labeled container')
    progress_path = attempt/'workspace/main/progress.json'
    progress_scope = 'current_attempt'
    if not progress_path.exists():
        fallback = Path(status.get('latest_checkpoint_parent') or c['resume_parent'])
        if fallback.parent != root.parent or fallback.resolve() != fallback:
            raise ValueError('Unexpected resume progress location')
        progress_path = fallback/'workspace/main/progress.json'
        progress_scope = 'previous_checkpoint_parent'
    return {'status':status, 'attempt':str(attempt), 'service':props, 'containers':names,
            'progress':read(progress_path) if progress_path.exists() else None,
            'progress_scope':progress_scope}


def decision(s, c, current_time):
    service = s['service']
    if service['ActiveState'] in ('active','activating','deactivating') or int(service['MainPID']) or s['containers']:
        return 'wait'
    result = s['status']['status']
    if result == 'completed':
        if service['ActiveState'] != 'inactive' or service['Result'] != 'success':
            raise RuntimeError('Completion disagrees with actual service result')
        return 'complete'
    if result == 'completed_training_validation_pending':
        return 'validation_pending'
    if result != 'stopped_deadline' or service['Result'] != 'success':
        raise RuntimeError('Only a successful saved deadline exit permits automatic continuation: '+result)
    if current_time < datetime.fromisoformat(c['deadline_kst']).timestamp()-900:
        raise RuntimeError('Early/manual stop must not be automatically reversed')
    return 'continue'


def estimate(p, progress, current_time):
    if not progress or type(progress.get('step')) is not int or progress.get('max_steps') != p['max_steps']:
        raise ValueError('A matching progress observation is required for an estimate')
    step = progress['step']
    if not p['initial_step'] <= step <= p['max_steps']:
        raise ValueError('Progress is outside the authorized plan')
    rates = [p['fallback_seconds_per_step']]
    new = step-progress.get('resumed_from_step', step)
    elapsed = progress.get('elapsed_seconds', 0)
    if new >= 8 and math.isfinite(elapsed) and elapsed > 0:
        rates.append(elapsed/new)
    total_new = step-p['initial_step']
    if total_new >= 8:
        rates.append((current_time-datetime.fromisoformat(p['initial_started_at_kst']).timestamp())/total_new)
    rate = max(rates)
    if not math.isfinite(rate) or rate <= 0:
        raise ValueError('Invalid measured throughput')
    remaining = (p['max_steps']-step)*rate
    duration = remaining+p['validation_seconds']+p['startup_seconds']+p['save_grace_seconds']
    # Each new window retains the existing explicit 24-hour installation bound.
    seconds = min(24*3600, max(2*3600, math.ceil(duration/900)*900))
    return {'basis_step':step, 'seconds_per_step_with_observed_waits':rate,
            'remaining_training_seconds':remaining, 'validation_reserve_seconds':p['validation_seconds'],
            'window_seconds':seconds, 'window_capped':duration>24*3600,
            'proposed_deadline_kst':datetime.fromtimestamp(current_time+seconds,KST).isoformat(),
            'scope':'estimate, includes observed waits; not a completion guarantee'}


def checkpoint(s, c, origin, dgx, resume):
    candidates = {s['attempt'], c['resume_parent']}
    if s['status'].get('latest_checkpoint_parent'):
        candidates.add(s['status']['latest_checkpoint_parent'])
    found = []
    for directory in candidates:
        parent = Path(directory)
        bound_control(parent/'control.json', origin, dgx, resume)
        output = parent/'workspace/main'
        for path in output.glob('checkpoint-*'):
            if not (path/resume.COMPLETION_MARKER).is_file():
                continue
            receipt = resume.verified_completion(output,path)
            found.append((receipt['step'],parent,receipt))
    if not found:
        raise RuntimeError('No complete verified checkpoint')
    return max(found, key=lambda row:row[0])


def completion(s, c, p, origin):
    output = Path(s['attempt'])/'workspace/main'
    progress = read(output/'progress.json')
    if progress['status'] != 'completed' or progress['step'] != p['max_steps'] or progress['max_steps'] != p['max_steps']:
        raise RuntimeError('The full optimizer plan has not completed')
    if read(Path(s['attempt'])/'workspace/main-status.json')['status'] != 'completed':
        raise RuntimeError('Main-stage completion receipt is absent')
    metrics = read(output/'eval_results.json')
    if not math.isfinite(metrics['eval_loss']):
        raise RuntimeError('Final validation did not produce a finite loss')
    manifest = read(output/'run_manifest.json')
    for split in ('train','validation','test'):
        if manifest['data']['sha256'][split] != origin['files']['data/'+split+'.jsonl']:
            raise RuntimeError('Final data lineage differs')
    files = {}
    for path in (output/'adapter').iterdir():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('Unexpected adapter artifact')
        files[path.name] = {'sha256':sha(path), 'bytes':path.stat().st_size}
    if not {'adapter_model.safetensors','adapter_config.json'} <= files.keys():
        raise RuntimeError('Final adapter is incomplete')
    return {'step':progress['step'], 'validation_loss':metrics['eval_loss'], 'adapter':files,
            'run_manifest_sha256':sha(output/'run_manifest.json'), 'operational_quality_passed':False}


def write_state(p, state):
    root = Path(p['root'])
    state['at_kst'] = stamp()
    temp = root/'follow-status.tmp'
    temp.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n')
    temp.replace(root/'follow-status.json')


def run(p):
    dgx, builder, resume, origin = runtime(p)
    root = Path(p['root'])
    if (root/'follow-status.json').exists():
        raise RuntimeError('Follower already attempted; refuse an implicit restart')
    state = {'status':'running', 'current_control':p['parent_control'], 'windows':[], 'started_at_kst':stamp()}
    last_step = p['initial_step']
    try:
        while True:
            c = bound_control(state['current_control'],origin,dgx,resume)
            try:
                s = snapshot(c)
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
                # A failed observation is not a terminal training state.
                state.update(stage='observation_unavailable', observation_error=type(exc).__name__)
                write_state(p,state)
                time.sleep(p['poll_seconds'])
                continue
            state.pop('observation_error',None)
            action = decision(s,c,time.time())
            state.update(stage=action, observation=s)
            if s['progress']:
                state['estimate'] = estimate(p,s['progress'],time.time())
            write_state(p,state)
            if action == 'wait':
                time.sleep(p['poll_seconds'])
                continue
            if action == 'validation_pending':
                state.update(status='validation_pending',stage='needs_validation_only')
                return
            if action == 'complete':
                state['completion'] = completion(s,c,p,origin)
                subprocess.run(['systemctl','disable','--now',c['run_id']+'-deadline.timer'],check=True)
                state.update(status='completed',stage='finished_early_without_waiting_for_deadline')
                return
            step, parent, receipt = checkpoint(s,c,origin,dgx,resume)
            if step <= last_step or receipt['max_steps'] != p['max_steps']:
                raise RuntimeError('Do not renew a window without verified forward progress')
            proposal = estimate(p,{**s['progress'],'step':step},time.time())
            number = len(state['windows'])+1
            day = p['unit'].split('-')[2]
            run_id = f'capstone-dgx-{day}-f{number}'
            target = root.with_name(f'operator-auto-{day}-f{number}')
            if target.exists():
                raise RuntimeError('Continuation output exists; refuse overwrite')
            builder.build(parent,target,run_id,proposal['proposed_deadline_kst'],
                          Path(origin['root'])/'source',step,{'max_attempts':32,'idle_seconds':60})
            new = bound_control(target/'control.json',origin,dgx,resume)
            dgx.apply(new,target/'control.json',reviewed_window_hours=24)
            subprocess.run(['systemctl','disable','--now',c['run_id']+'-deadline.timer'],check=True)
            state['windows'].append({'run_id':run_id,'root':str(target),'resume_step':step,
                'control_sha256':sha(target/'control.json'),**proposal})
            state['current_control'] = str(target/'control.json')
            last_step = step
            write_state(p,state)
            time.sleep(p['poll_seconds'])
    except BaseException as exc:
        state.update(status='failed',error=type(exc).__name__+': '+str(exc))
        raise
    finally:
        write_state(p,state)


def apply(p, path):
    dgx, _, resume, origin = runtime(p)
    bound_control(p['parent_control'],origin,dgx,resume)
    s = snapshot(origin)
    if decision(s,origin,time.time()) != 'wait':
        raise RuntimeError('Install only while the authorized parent is actually active')
    unit = Path('/etc/systemd/system')/(p['unit']+'.service')
    if unit.exists() or (Path(p['root'])/'follow-status.json').exists():
        raise RuntimeError('Follower already exists')
    body = ('[Unit]\nDescription=Follow authorized DGX training to estimated completion\nAfter=docker.service\n'
            '[Service]\nType=simple\nRestart=no\nUMask=0077\nKillMode=control-group\nTimeoutStopSec=30\n'
            f'ExecStart=/usr/bin/python3 -IB {p["root"]}/finetuning/dgx_follow.py --config {path} --run\n')
    unit.write_text(body)
    subprocess.run(['systemd-analyze','verify',str(unit)],check=True)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','start',unit.name],check=True)
    print(json.dumps({'started':unit.name,'current_training_unchanged':True,'at_kst':stamp()}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    for name in ('check','apply','run','verify','stop'):
        action.add_argument('--'+name,action='store_true')
    args = parser.parse_args()
    p = load_policy(args.config)
    if args.check:
        dgx, _, resume, origin = runtime(p)
        bound_control(p['parent_control'],origin,dgx,resume)
        print(json.dumps({'policy_valid':True,'original_inputs_verified':True}))
    elif args.verify:
        print(command(['systemctl','show',p['unit']+'.service','-p','MainPID','-p','ActiveState','-p','SubState','-p','Result']))
        print((Path(p['root'])/'follow-status.json').read_text())
    else:
        if os.geteuid() != 0:
            raise PermissionError('Root installs the follower; training remains unprivileged')
        if args.apply:
            apply(p,args.config)
        elif args.run:
            run(p)
        else:
            subprocess.run(['systemctl','stop',p['unit']+'.service'],check=True)
            print('Follower stopped; current training was not stopped.')


if __name__ == '__main__':
    main()
