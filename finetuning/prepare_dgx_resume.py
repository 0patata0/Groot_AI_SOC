"""Create a distinct DGX resume bundle; install it through root deploy.sh."""
import argparse
import json
import os
from pathlib import Path
import shutil

from dgx_supervisor import read_config, verify_files, cutoff
from prepare_dgx_run import FILES
from resume_training import make_receipt, digest


def build(parent, root, run_id, deadline, sources, step):
    parent, root, sources = Path(parent), Path(root), Path(sources)
    old = read_config(parent/'control.json')
    verify_files(old)
    if str(parent) != old['root'] or root.parent != parent.parent or root == parent:
        raise ValueError('Use a separate sibling run')
    workspace = parent/'workspace'
    for name in ('prepare-status.json', 'smoke-status.json'):
        if json.loads((workspace/name).read_text())['status'] != 'completed':
            raise ValueError('Original environment and full-model smoke must have passed')
    hardware = json.loads((workspace/'hardware.json').read_text())
    if hardware['compute_capability'] != [12, 1] or hardware['cuda_forward_backward'] != 'passed':
        raise ValueError('Original environment was not validated on Spark')
    receipt = make_receipt(workspace/'main', workspace/'main'/('checkpoint-'+str(step)))
    root.mkdir(exist_ok=False)
    for name in ('source','profiles','data','installer/finetuning','workspace'):
        (root/name).mkdir(parents=True,exist_ok=True)
    for name in (*FILES, 'check_resume_runtime.py'):
        shutil.copyfile(sources/name, root/'source'/name)
    for rel in old['files']:
        if rel.startswith('data/'):
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
        shutil.copyfile(workspace/name,root/'workspace'/name)
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
       'resume_parent':str(parent),'files':hashes}
    (root/'control.json').write_text(json.dumps(c,indent=2)+'\n')
    read_config(root/'control.json');verify_files(c)
    return {'run_id':run_id,'step':receipt['step'],'max_steps':receipt['max_steps'],
            'inputs_verified':len(hashes),'deadline_kst':deadline}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('parent','root','sources'):p.add_argument('--'+arg,type=Path,required=True)
    for arg in ('run-id','deadline'):p.add_argument('--'+arg,required=True)
    p.add_argument('--step',type=int,required=True)
    a=p.parse_args();print(json.dumps(build(a.parent,a.root,a.run_id,a.deadline,a.sources,a.step)))
