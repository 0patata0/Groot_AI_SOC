"""Create a distinct DGX resume bundle; install it through root deploy.sh."""
import argparse
import json
import os
from pathlib import Path
import shutil

from dgx_supervisor import read_config, verify_files, cutoff, resource_config
from prepare_dgx_run import FILES
from resume_training import make_receipt, digest


def build_fresh(control, root):
    """A retry before the first complete checkpoint restarts the exact fresh base."""
    if control.get('purpose')!='main_training' or 'environment_parent'not in control or 'resume_parent'in control:
        raise ValueError('Fresh attempt requires a reviewed fresh-base training controller')
    verify_files(control)
    original=Path(control['root']);root=Path(root)
    if root.parent!=original.parent or root==original:raise ValueError('Fresh attempt must be a distinct sibling')
    resources=Path(resource_config(control)['root'])/'workspace'
    root.mkdir(exist_ok=False)
    os.chmod(root,0o755);os.chown(root,0,0)
    for rel in control['files']:
        destination=root/rel;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(original/rel,destination)
    workspace=root/'workspace';workspace.mkdir()
    for name in ('base','venv'):(workspace/name).mkdir()
    for name in ('base-manifest.json','base-transfer.json','hardware.json'):
        shutil.copyfile(resources/name,workspace/name)
    for path in root.rglob('*'):
        os.chmod(path,0o755 if path.is_dir()else 0o644);os.chown(path,0,0)
    os.chown(workspace,control['uid'],control['gid'])
    current={**control,'root':str(root)};current.pop('retry_policy',None)
    (root/'control.json').write_text(json.dumps(current,indent=2)+'\n')
    read_config(root/'control.json');verify_files(current)
    return current


def build(parent, root, run_id, deadline, sources, step, retry_policy=None):
    parent, root, sources = Path(parent), Path(root), Path(sources)
    old = read_config(parent/'control.json')
    if old.get('purpose')=='preflight_only':
        raise ValueError('A preflight smoke adapter is not a main-training checkpoint')
    verify_files(old)
    if str(parent) != old['root'] or root.parent != parent.parent or root == parent:
        raise ValueError('Use a separate sibling run')
    workspace = parent/'workspace'
    resources=Path(resource_config(old)['root'])/'workspace'
    for name in ('prepare-status.json', 'smoke-status.json'):
        if json.loads((resources/name).read_text())['status'] != 'completed':
            raise ValueError('Original environment and full-model smoke must have passed')
    hardware = json.loads((resources/'hardware.json').read_text())
    if hardware['compute_capability'] != [12, 1] or hardware['cuda_forward_backward'] != 'passed':
        raise ValueError('Original environment was not validated on Spark')
    receipt = make_receipt(workspace/'main', workspace/'main'/('checkpoint-'+str(step)))
    root.mkdir(exist_ok=False)
    os.chmod(root,0o755);os.chown(root,0,0)
    for name in ('source','profiles','data','installer/finetuning','workspace'):
        (root/name).mkdir(parents=True,exist_ok=True)
    for name in (*FILES, 'check_resume_runtime.py','prepare_dgx_resume.py','prepare_dgx_run.py'):
        shutil.copyfile(sources/name, root/'source'/name)
    for rel in old['files']:
        if rel.startswith('data/'):
            (root/rel).parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(parent/rel, root/rel)
    profile = json.loads((parent/'profiles/main.json').read_text())
    profile.update(training_deadline_epoch=cutoff(deadline)-900,
                   resume_from_checkpoint='/resume/'+receipt['checkpoint'],
                   resume_manifest='/workspace/profiles/resume.json')
    (root/'profiles/main.json').write_text(json.dumps(profile,indent=2)+'\n')
    (root/'profiles/resume.json').write_text(json.dumps(receipt,indent=2)+'\n')
    shutil.copyfile(parent/'installer/deploy.sh',root/'installer/deploy.sh')
    shutil.copyfile(sources/'dgx_supervisor.py',root/'installer/finetuning/dgx_supervisor.py')
    for name in ('base-manifest.json','base-transfer.json','hardware.json'):
        shutil.copyfile(resources/name,root/'workspace'/name)
    # Read-only mounts reuse the existing environment/base/checkpoint. No copy of weights.
    for name in ('base','venv'):
        (root/'workspace'/name).mkdir()
    for p in root.rglob('*'):
        os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chown(p,0,0)
    os.chown(root/'workspace',old['uid'],old['gid'])
    hashes={str(p.relative_to(root)):digest(p) for folder in ('source','data','profiles','installer')
            for p in sorted((root/folder).rglob('*')) if p.is_file()}
    c={**old,'root':str(root),'run_id':run_id,'deadline_kst':deadline,
       'resume_parent':str(parent),'resource_root':str(resources.parent),'files':hashes}
    c.pop('retry_policy',None)
    c.pop('environment_parent',None)
    if retry_policy is not None:c['retry_policy']=retry_policy
    (root/'control.json').write_text(json.dumps(c,indent=2)+'\n')
    read_config(root/'control.json');verify_files(c)
    return {'run_id':run_id,'step':receipt['step'],'max_steps':receipt['max_steps'],
            'inputs_verified':len(hashes),'deadline_kst':deadline}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('parent','root','sources'):p.add_argument('--'+arg,type=Path,required=True)
    for arg in ('run-id','deadline'):p.add_argument('--'+arg,required=True)
    p.add_argument('--step',type=int,required=True)
    p.add_argument('--retry-attempts',type=int,choices=range(1,33))
    p.add_argument('--idle-seconds',type=int,default=60)
    a=p.parse_args()
    policy={'max_attempts':a.retry_attempts,'idle_seconds':a.idle_seconds} if a.retry_attempts else None
    print(json.dumps(build(a.parent,a.root,a.run_id,a.deadline,a.sources,a.step,policy)))
