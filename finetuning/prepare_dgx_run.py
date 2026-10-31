"""Freeze the already reviewed 191-row evidence arm for a new Spark run."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
from dgx_supervisor import read_config, cutoff

SOURCE=Path(__file__).resolve().parent
FILES=('train.py','model_profile.py','memory_budget.py','memory_telemetry.py',
       'bounded_loading.py','completion_loss.py','dialogue_encoding.py','training_lineage.py',
       'guarded_process.py','download_model.py','dgx_task.py','dgx_supervisor.py',
       'requirements.qwen36-thor.txt','requirements.qwen36-dgx.txt','admit_guide_sft.py',
       'check_dgx_architecture.py','resume_training.py')


def build(output, root, uid, gid, image, deadline, guide_mix=None, run_id='capstone-dgx-20261031'):
    evidence=SOURCE/'data-evidence-run-20261031-r1-final'
    release=json.loads((evidence/'release.json').read_text())
    if release['training_rows']!=191 or release['source_arm_sha256']!='acee5ff65c57b50991620504713d0b22703516715ffa9ae7107aa9444dddaf84':
        raise ValueError('Unexpected reviewed data release')
    for rel, sha in release['files'].items():
        p=evidence/rel
        if p.is_symlink() or not p.resolve().is_relative_to(evidence.resolve()) or hashlib.sha256(p.read_bytes()).hexdigest()!=sha:
            raise ValueError('Frozen evidence release differs: '+rel)
    output.mkdir(parents=True,exist_ok=False)
    for name in ('source','data','profiles','installer/finetuning'):
        (output/name).mkdir(parents=True,exist_ok=True)
    for name in FILES: shutil.copyfile(SOURCE/name,output/'source'/name)
    for name in release['files']:
        if name.startswith('data/'):
            shutil.copyfile(evidence/name,output/name)
    training_rows=191
    if guide_mix is not None:
        guide_mix=Path(guide_mix)
        admission=json.loads((guide_mix/'manifest.json').read_text())
        count=admission['guide_training_admitted']
        if (admission['status']!='source_and_token_verified_bounded_pilot' or count not in (128,192,256)
                or admission['base_revision']!=release['base_revision']
                or admission['cross_split_organization_overlap']!=0 or admission['truncation']
                or admission['prior_manifest_sha256']!=release['files']['data/manifest.json']):
            raise ValueError('GUIDE mixture did not pass bounded source/token admission')
        for split,expected in admission['outputs'].items():
            if split not in ('train','validation','test') or hashlib.sha256((guide_mix/(split+'.jsonl')).read_bytes()).hexdigest()!=expected['sha256']:
                raise ValueError('GUIDE mixture bytes changed')
        for p in guide_mix.iterdir():
            if not p.is_file() or p.is_symlink():raise ValueError('Only regular mixture files are allowed')
            shutil.copyfile(p,output/'data'/p.name)
        training_rows=191+count
    for stage in ('main','smoke'):
        c=json.loads((evidence/'profiles'/(stage+'.json')).read_text())
        c.update(hardware_profile='dgx-spark-sm121',data_dir='/data',output_dir='/workspace/'+stage,
                 training_deadline_epoch=cutoff(deadline)-900,save_steps=8 if stage=='main' else 2,
                 final_eval_only=True)
        if stage=='main': c['eval_steps']=(training_rows+1)//2
        (output/'profiles'/(stage+'.json')).write_text(json.dumps(c,indent=2)+'\n')
    shutil.copyfile(SOURCE.parent/'deploy.sh',output/'installer/deploy.sh')
    shutil.copyfile(SOURCE/'dgx_supervisor.py',output/'installer/finetuning/dgx_supervisor.py')
    hashes={str(p.relative_to(output)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob('*')) if p.is_file()}
    control={'run_id':run_id,'root':root,'uid':uid,'gid':gid,
             'image':image,'deadline_kst':deadline,'files':hashes}
    path=output/'control.json'
    path.write_text(json.dumps(control,indent=2)+'\n')
    read_config(path)
    return control


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--root',required=True)
    p.add_argument('--uid',type=int,required=True)
    p.add_argument('--gid',type=int,required=True)
    p.add_argument('--image',required=True)
    p.add_argument('--deadline',required=True)
    p.add_argument('--guide-mix',type=Path)
    p.add_argument('--run-id',default='capstone-dgx-20261031')
    a=p.parse_args()
    print(json.dumps(build(a.output,a.root,a.uid,a.gid,a.image,a.deadline,a.guide_mix,a.run_id),indent=2))
