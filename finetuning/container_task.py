"""Fixed stages inside the pinned Thor training container; never controls Ollama."""
import argparse
import importlib.metadata as md
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
from datetime import datetime
from zoneinfo import ZoneInfo
import guarded_process

ROOT = Path('/workspace')
SOURCE = ROOT / 'finetuning'
PYTHON = ROOT / 'venv/bin/python'


def run(args, log, env=None):
    subprocess.run([str(x) for x in args], cwd=SOURCE, env=env or os.environ.copy(),
                   stdout=log, stderr=subprocess.STDOUT, check=True)


def main():
    def interrupted(signum, frame):
        raise InterruptedError(f'Training stage interrupted by signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=['prepare','download','tokenize','smoke','train','soc-tokenize','soc-smoke','soc-pilot','soc-train'])
    stage = parser.parse_args().stage
    status = {'stage':stage, 'started_at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(), 'status':'running'}
    record = ROOT / f'{stage}-status.json'
    def save():
        temp = record.with_suffix('.tmp');temp.write_text(json.dumps(status, indent=2)+'\n');temp.replace(record)
    save()
    try:
        with (ROOT / f'{stage}.log').open('a', buffering=1) as log:
            if stage == 'prepare':
                if not PYTHON.exists(): run([sys.executable,'-m','venv','--system-site-packages',ROOT/'venv'],log)
                pins = []
                for name in ('torch','torchvision','torchaudio','triton'):
                    try: pins.append(name+'=='+md.version(name))
                    except md.PackageNotFoundError: pass
                constraints=ROOT/'vendor-constraints.txt';constraints.write_text('\n'.join(pins)+'\n')
                env=os.environ.copy();env['PIP_CONSTRAINT']=str(constraints)
                run([PYTHON,'-m','pip','install','--no-cache-dir','--disable-pip-version-check',
                     '--report',ROOT/'install-report.json','-r',SOURCE/'requirements.qwen36-thor.txt'],log,env)
                run([PYTHON,'-m','pip','check'],log,env)
                run([PYTHON,'-B',SOURCE/'train.py','--config',SOURCE/'config.qwen36-thor.json','--preflight'],log,env)
            elif stage == 'download':
                run([PYTHON,'-B',SOURCE/'download_model.py'],log)
            else:
                soc=stage.startswith('soc-')
                profile='config.qwen36-soc-main.json' if stage=='soc-train' else ('config.qwen36-soc.json' if soc else 'config.qwen36-thor.json')
                config=json.loads((SOURCE/profile).read_text())
                if stage in ('tokenize','soc-tokenize'):
                    config.update(max_train_samples=0,max_eval_samples=0)
                if stage in ('smoke','train','soc-smoke','soc-pilot','soc-train'):
                    raw=(ROOT/'base-manifest.json').read_bytes();manifest=json.loads(raw)
                    if not manifest.get('verified') or manifest['revision']!=config['revision'] or manifest['model']!=config['model_name_or_path']:
                        raise ValueError('Verified base manifest does not match the training profile')
                    config['base_artifact_manifest']={'model':manifest['model'],'revision':manifest['revision'],
                        'manifest_sha256':hashlib.sha256(raw).hexdigest()}
                config.update(model_name_or_path='/workspace/base',offline=True)
                if stage in ('smoke','soc-smoke'): config['gradient_accumulation_steps']=1
                local_config=SOURCE/'config.run.local.json'
                local_config.write_text(json.dumps(config,indent=2)+'\n')
                args=[PYTHON,'-B',SOURCE/'train.py','--config',local_config]
                if stage in ('tokenize','soc-tokenize'): args += ['--tokenize-only','--output-dir','/workspace/soc-tokenization' if soc else '/workspace/tokenization']
                elif stage in ('smoke','soc-smoke'): args += ['--train','--max-steps','2','--max-train-samples','32',
                    '--max-eval-samples','8','--output-dir','/workspace/outputs/'+('soc-smoke' if soc else 'smoke')]
                elif stage == 'soc-pilot': args += ['--train','--output-dir','/workspace/outputs/soc-pilot']
                elif stage == 'soc-train': args += ['--train','--output-dir','/workspace/outputs/soc-main']
                else: args += ['--train','--output-dir','/workspace/outputs/train']
                if stage in ('smoke','train','soc-smoke','soc-pilot','soc-train'):
                    guarded_process.run([str(x) for x in args],log=log,cwd=SOURCE,env=os.environ.copy(),
                                        report=ROOT/f'{stage}-memory-guard.json')
                else: run(args,log)
        status['status']='completed'
    except Exception as exc:
        status.update(status='failed',error_type=type(exc).__name__,error=str(exc))
        raise
    finally:
        status['updated_at_kst']=datetime.now(ZoneInfo('Asia/Seoul')).isoformat();save()


if __name__=='__main__': main()
