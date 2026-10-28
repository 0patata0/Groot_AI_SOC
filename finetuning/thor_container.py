"""Launch an isolated durable training stage on Thor using an existing pinned image."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
from download_model import verify_artifact

IMAGE = 'nvcr.io/nvidia/pytorch@sha256:ace9a848c0ae543317e3c4763b6b4248961c47902625abfe3c77a0fb931c50fb'
STAGES = ('prepare','download','tokenize','smoke','train','soc-tokenize','soc-smoke','soc-pilot','soc-train',
          'soc-v2-tokenize','soc-v2-smoke','soc-v2-pilot')


def command(root, stage, uid, gid):
    if stage not in STAGES: raise ValueError('Unknown stage')
    root = Path(root).resolve()
    training = stage in ('smoke','train','soc-smoke','soc-pilot','soc-train','soc-v2-smoke','soc-v2-pilot')
    env = {'PYTHONDONTWRITEBYTECODE':'1','PIP_NO_CACHE_DIR':'1','PIP_DISABLE_PIP_VERSION_CHECK':'1',
           'HF_HUB_DISABLE_TELEMETRY':'1','HF_HUB_DISABLE_PROGRESS_BARS':'1','HF_HOME':'/workspace/hf-cache',
           'HF_HUB_DISABLE_IMPLICIT_TOKEN':'1',
           'XDG_CACHE_HOME':'/workspace/runtime-cache','TRITON_CACHE_DIR':'/workspace/runtime-cache/triton',
           'TOKENIZERS_PARALLELISM':'false','CUDA_VISIBLE_DEVICES':'0','TZ':'Asia/Seoul',
           'PIP_CONSTRAINT':'/workspace/vendor-constraints.txt'}
    if stage not in ('prepare','download'): env.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
    if training: env['HF_DEACTIVATE_ASYNC_LOAD']='1'
    args = ['docker','run','-d','--pull=never','--name','capstone-qwen36-'+stage,
            '--user',f'{uid}:{gid}','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--pids-limit','512','--cpus','10' if training else '4','--memory','112g' if training else '12g',
            '--memory-swap','112g' if training else '12g','--shm-size','1g','--log-driver','local',
            '--log-opt','max-size=10m','--log-opt','max-file=2',
            '--network','bridge' if stage in ('prepare','download') else 'none',
            '--mount',f'type=bind,source={root},target=/workspace','--workdir','/workspace/finetuning']
    if training or stage == 'prepare': args += ['--gpus','device=0']
    for name,value in env.items(): args += ['--env',name+'='+value]
    return args + ['--entrypoint','python',IMAGE,'-B','/workspace/finetuning/container_task.py',stage]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=STAGES)
    parser.add_argument('--root',type=Path,required=True)
    args=parser.parse_args()
    if platform.system()!='Linux' or platform.machine()!='aarch64':raise SystemExit('Run on the Thor host')
    root=args.root.resolve()
    if not (root/'finetuning/config.qwen36-thor.json').is_file():raise SystemExit('Verified training source/data required')
    for stage in STAGES:
        p=subprocess.run(['docker','inspect','--format','{{.State.Running}}','capstone-qwen36-'+stage],capture_output=True,text=True)
        if p.returncode==0 and p.stdout.strip()=='true':
            if not (args.stage=='tokenize' and stage=='download'):
                raise SystemExit('Another training stage is running')
    if (root/f'{args.stage}-status.json').exists():raise SystemExit('Prior stage evidence exists; inspect it before an explicit retry')
    if args.stage != 'prepare':
        for stage in ['prepare'] + ([] if args.stage in ('download','tokenize') else ['download','tokenize']):
            if json.loads((root/f'{stage}-status.json').read_text())['status']!='completed':raise SystemExit('Prerequisite stage incomplete')
    if args.stage not in ('prepare','download'):
        manifest=json.loads((root/'base-manifest.json').read_text())
        config=json.loads((root/'finetuning/config.qwen36-thor.json').read_text())
        if manifest.get('revision')!=config['revision'] or manifest.get('model')!=config['model_name_or_path']:
            raise SystemExit('Base manifest does not match model and revision')
        if args.stage=='tokenize':
            for item in manifest['files']:
                if not item['path'].endswith('.safetensors'): verify_artifact(root/'base',item)
        elif manifest.get('verified') is not True:
            raise SystemExit('Pinned base artifacts are not verified')
    if args.stage == 'train' and json.loads((root/'smoke-status.json').read_text())['status']!='completed':
        raise SystemExit('Successful smoke stage required')
    if args.stage == 'soc-pilot' and json.loads((root/'soc-smoke-status.json').read_text())['status']!='completed':
        raise SystemExit('Successful SOC smoke stage required')
    if args.stage == 'soc-train' and json.loads((root/'soc-pilot-status.json').read_text())['status']!='completed':
        raise SystemExit('Successful SOC pilot stage required')
    if args.stage in ('soc-smoke','soc-pilot','soc-train') and json.loads((root/'soc-tokenize-status.json').read_text())['status']!='completed':
        raise SystemExit('Successful SOC tokenization required')
    if args.stage in ('soc-v2-smoke','soc-v2-pilot') and json.loads((root/'soc-v2-tokenize-status.json').read_text())['status']!='completed':
        raise SystemExit('Successful v2 tokenization required')
    if args.stage in ('soc-v2-smoke','soc-v2-pilot'):
        report=json.loads((root/'soc-v2-tokenization/tokenization_report.json').read_text())
        profile=json.loads((root/'finetuning/config.qwen36-soc-v2.json').read_text())
        if report.get('max_length')!=profile['max_length'] or report.get('require_all_prefixes') is not True:
            raise SystemExit('v2 tokenization settings do not match the strict profile')
        if any(report[s].get('kept')!=report[s].get('candidate_turns') for s in ('train','validation','test')):
            raise SystemExit('v2 required assistant prefixes were excluded')
    if args.stage=='soc-v2-pilot' and json.loads((root/'soc-v2-smoke-status.json').read_text())['status']!='completed':
        raise SystemExit('Successful v2 smoke required')
    print(subprocess.check_output(command(root,args.stage,os.getuid(),os.getgid()),text=True).strip())


if __name__=='__main__':main()
