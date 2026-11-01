"""Freeze a reviewed SOC mixture for fresh-base DGX preparation or main training.

Local preparation only. Enter remote execution through deploy.sh --training-dgx.
An environment parent supplies read-only base/venv, never its adapter/optimizer.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil

from dgx_supervisor import cutoff, read_config
from prepare_dgx_run import FILES, SOURCE
from prepare_operator_sources import sha, rows, dump
from train import check_data, read_config as training_config


def data_manifest(directory):
    outputs={split:{'records':len(rows(directory/(split+'.jsonl'))),
                    'sha256':sha((directory/(split+'.jsonl')).read_bytes())}for split in ('train','validation','test')}
    (directory/'manifest.json').write_text(json.dumps({'outputs':outputs,'truncation':False},indent=2)+'\n')
    return outputs


def build(data, output, root, environment_parent, run_id, image, deadline, purpose='preflight_only', retry_policy=None, release_review=None):
    data, output = Path(data), Path(output)
    if purpose not in ('preflight_only','main_training'):raise ValueError('Unknown purpose')
    if retry_policy is not None and purpose!='main_training':raise ValueError('Retry policy is for main training only')
    if output.exists():raise ValueError('Preserve previous run bundles')
    admission=json.loads((data/'admission.json').read_text())
    if admission['status']!='source_and_token_verified_waiting_final_review_and_gpu_smoke' or admission['truncation']:
        raise ValueError('Require verified whole-dialogue admission')
    for name,digest in admission['files'].items():
        if sha((data/name).read_bytes())!=digest:raise ValueError('Admitted data changed')
    receipt=json.loads((data/'token-review.json').read_text())
    if sha((data/'token-review.json').read_bytes())!=admission['token_receipt_sha256']:
        raise ValueError('Token receipt changed')
    if purpose=='main_training':
        release_path=Path(release_review)if release_review else data/'release.json'
        review=json.loads(release_path.read_text())
        if (review['status']!='ready_for_bounded_training' or not review['gpu_preflight_passed']
                or review['train_sha256']!=admission['files']['train.jsonl']):
            raise ValueError('Final source/quality-boundary/GPU preparation review is incomplete')
        for name,digest in review['runtime_sources'].items():
            if sha((SOURCE/name).read_bytes())!=digest:raise ValueError('Runtime differs from tested preparation')
        expected_names=set((*FILES,'check_resume_runtime.py','prepare_dgx_resume.py','prepare_dgx_run.py'))
        if set(review['runtime_sources'])!=expected_names:raise ValueError('Release must cover every runtime source')
    full=rows(data/'train.jsonl')
    token_counts={r['id']:r['tokens']for r in receipt['records']if r['reason']is None}
    longest=max(full,key=lambda r:(token_counts[r['id']],r['id']))
    multi=[r for r in full if sum(m['role']=='assistant'for m in r['messages'])>=3
           and sum(m['role']=='tool'for m in r['messages'])>=2]
    if not multi:raise ValueError('Require an actual multi-turn tool trajectory in GPU preparation')
    longest_multi=max(multi,key=lambda r:(token_counts[r['id']],r['id']))
    selected={r['id']:r for r in (longest,longest_multi)}
    if len(selected)!=2:raise ValueError('Require distinct longest-input and longest-multi-turn examples')
    output.mkdir(parents=True)
    for name in ('source','data','data/smoke','profiles','installer/finetuning'):
        (output/name).mkdir(parents=True,exist_ok=True)
    for name in (*FILES,'check_resume_runtime.py','prepare_dgx_resume.py','prepare_dgx_run.py'):
        shutil.copyfile(SOURCE/name,output/'source'/name)
    for split in ('train','validation','test'):
        shutil.copyfile(data/(split+'.jsonl'),output/'data'/(split+'.jsonl'))
        if split!='train':shutil.copyfile(data/(split+'.jsonl'),output/'data/smoke'/(split+'.jsonl'))
    dump(output/'data/smoke/train.jsonl',list(selected.values()))
    full_manifest=data_manifest(output/'data');smoke_manifest=data_manifest(output/'data/smoke')
    shutil.copytree(data/'licenses',output/'data/licenses')
    for name in ('admission.json','composition.json','token-review.json','mcp-contract.json'):
        shutil.copyfile(data/name,output/'data'/name)
    if purpose=='main_training':shutil.copyfile(release_path,output/'data/release.json')
    selection={'selection':'longest admitted conversation plus longest complete trajectory with at least two tool calls and three assistant turns',
               'records':[{'id':r['id'],'tokens':token_counts[r['id']],
                           'assistant_turns':sum(m['role']=='assistant'for m in r['messages'])}for r in selected.values()],
               'train_sha256':full_manifest['train']['sha256'],'smoke_sha256':smoke_manifest['train']['sha256'],
               'main_training_rows':len(full),'planned_main_optimizer_steps':(len(full)+1)//2,
               'smoke_optimizer_steps':2,'smoke_gradient_accumulation':2,'main_training_started':False}
    (output/'profiles/selection.json').write_text(json.dumps(selection,ensure_ascii=False,indent=2)+'\n')
    for stage in ('main','smoke'):
        config=json.loads((SOURCE/'data-evidence-run-20261031-r1-final/profiles'/(stage+'.json')).read_text())
        config.update(hardware_profile='dgx-spark-sm121',data_dir='/data',output_dir='/workspace/'+stage,
                      training_deadline_epoch=cutoff(deadline)-900,final_eval_only=True,
                      save_steps=4 if stage=='main'else 2)
        if stage=='main':config['eval_steps']=(len(full)+1)//2
        else:
            config.update(smoke_longest_prefixes=False,max_train_samples=0,
                          gradient_accumulation_steps=2,max_steps=2,max_eval_samples=8)
        path=output/'profiles'/(stage+'.json');path.write_text(json.dumps(config,indent=2)+'\n')
        local=training_config(path);local['data_dir']=str(output/('data/smoke'if stage=='smoke'else'data'))
        check_data(local)
    shutil.copyfile(SOURCE.parent/'deploy.sh',output/'installer/deploy.sh')
    shutil.copyfile(SOURCE/'dgx_supervisor.py',output/'installer/finetuning/dgx_supervisor.py')
    hashes={str(p.relative_to(output)):sha(p.read_bytes())for p in sorted(output.rglob('*'))if p.is_file()}
    control={'run_id':run_id,'root':root,'uid':1000,'gid':1000,'image':image,'deadline_kst':deadline,
             'files':hashes,'environment_parent':environment_parent,'purpose':purpose,'smoke_data_subdir':'smoke'}
    if retry_policy is not None:control['retry_policy']=retry_policy
    path=output/'control.json';path.write_text(json.dumps(control,indent=2)+'\n');read_config(path)
    return {'purpose':purpose,'root':root,'files':len(hashes),'selection':selection,
            'control_sha256':sha(path.read_bytes()),'main_training_started':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('data','output'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('root','environment-parent','run-id','image','deadline'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--purpose',choices=('preflight_only','main_training'),default='preflight_only')
    parser.add_argument('--retry-attempts',type=int,choices=range(1,33))
    parser.add_argument('--idle-seconds',type=int,default=60)
    parser.add_argument('--release-review',type=Path)
    args=parser.parse_args()
    retry={'max_attempts':args.retry_attempts,'idle_seconds':args.idle_seconds}if args.retry_attempts else None
    print(json.dumps(build(args.data,args.output,args.root,args.environment_parent,args.run_id,args.image,args.deadline,args.purpose,retry,args.release_review),ensure_ascii=False,indent=2))
