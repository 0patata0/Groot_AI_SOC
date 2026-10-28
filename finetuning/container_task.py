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
    parser.add_argument('stage', choices=['prepare','download','tokenize','smoke','train','soc-tokenize','soc-smoke','soc-pilot','soc-train',
                                        'soc-v4-full-tokenize','soc-v4-full-smoke','soc-v4-full-train','soc-v4-tokenize','soc-v4-smoke','soc-v4-pilot','soc-v3-tokenize','soc-v3-smoke','soc-v3-pilot','soc-v2-tokenize','soc-v2-smoke','soc-v2-pilot','soc-memory-smoke','soc-memory-vmm','soc-memory-trace','soc-memory-loss'])
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
                memory_repro=stage in ('soc-memory-smoke','soc-memory-vmm','soc-memory-trace','soc-memory-loss')
                full4=stage.startswith('soc-v4-full-')
                v4=stage.startswith('soc-v4-')
                v3=stage.startswith('soc-v3-')
                v2=stage.startswith('soc-v2-') or memory_repro
                profile='config.qwen36-soc-v4-full.json' if full4 else 'config.qwen36-soc-v4.json' if v4 else 'config.qwen36-soc-v3.json' if v3 else 'config.qwen36-soc-v2.json' if v2 else ('config.qwen36-soc-main.json' if stage=='soc-train' else ('config.qwen36-soc.json' if soc else 'config.qwen36-thor.json'))
                config=json.loads((SOURCE/profile).read_text())
                if stage in ('tokenize','soc-tokenize','soc-v2-tokenize','soc-v3-tokenize','soc-v4-tokenize','soc-v4-full-tokenize'):
                    config.update(max_train_samples=0,max_eval_samples=0)
                if stage in ('smoke','train','soc-smoke','soc-pilot','soc-train','soc-v4-full-smoke','soc-v4-full-train','soc-v4-smoke','soc-v4-pilot','soc-v3-smoke','soc-v3-pilot','soc-v2-smoke','soc-v2-pilot','soc-memory-smoke','soc-memory-vmm','soc-memory-trace','soc-memory-loss'):
                    raw=(ROOT/'base-manifest.json').read_bytes();manifest=json.loads(raw)
                    if not manifest.get('verified') or manifest['revision']!=config['revision'] or manifest['model']!=config['model_name_or_path']:
                        raise ValueError('Verified base manifest does not match the training profile')
                    config['base_artifact_manifest']={'model':manifest['model'],'revision':manifest['revision'],
                        'manifest_sha256':hashlib.sha256(raw).hexdigest()}
                config.update(model_name_or_path='/workspace/base',offline=True)
                if stage in ('smoke','soc-smoke','soc-v4-full-smoke','soc-v4-smoke','soc-v3-smoke','soc-v2-smoke','soc-memory-smoke','soc-memory-vmm','soc-memory-trace','soc-memory-loss'): config['gradient_accumulation_steps']=1
                if stage in ('soc-v4-full-smoke','soc-v4-smoke','soc-v3-smoke','soc-v2-smoke','soc-memory-smoke','soc-memory-vmm','soc-memory-trace','soc-memory-loss'):config['smoke_longest_prefixes']=True
                if stage=='soc-memory-trace':config['trace_first_step']=True
                if config.get('model_kind')=='qwen3_5_moe':config.setdefault('assistant_only_logits',True)
                if stage in ('soc-memory-smoke','soc-memory-vmm','soc-memory-trace'):config['assistant_only_logits']=False
                if stage=='soc-memory-loss':config['assistant_only_logits']=True
                local_config=SOURCE/(f'config.{stage}.run.local.json' if stage in ('soc-memory-vmm','soc-memory-trace','soc-memory-loss') else 'config.soc-memory.run.local.json' if memory_repro else 'config.soc-v4-full.run.local.json' if full4 else 'config.soc-v4.run.local.json' if v4 else 'config.soc-v3.run.local.json' if v3 else 'config.soc-v2.run.local.json' if v2 else 'config.run.local.json')
                local_config.write_text(json.dumps(config,indent=2)+'\n')
                args=[PYTHON,'-B',SOURCE/'train.py','--config',local_config]
                if stage in ('tokenize','soc-tokenize','soc-v2-tokenize','soc-v3-tokenize','soc-v4-tokenize','soc-v4-full-tokenize'): args += ['--tokenize-only','--output-dir','/workspace/soc-v4-full-tokenization' if full4 else '/workspace/soc-v4-tokenization' if v4 else '/workspace/soc-v3-tokenization' if v3 else '/workspace/soc-v2-tokenization' if v2 else '/workspace/soc-tokenization' if soc else '/workspace/tokenization']
                elif stage in ('smoke','soc-smoke','soc-v4-full-smoke','soc-v4-smoke','soc-v3-smoke','soc-v2-smoke','soc-memory-smoke','soc-memory-vmm','soc-memory-trace','soc-memory-loss'): args += ['--train','--max-steps','2','--max-train-samples','2' if (v2 or v3 or v4) else '32',
                    '--max-eval-samples','8','--output-dir','/workspace/outputs/'+(stage if (memory_repro or v3 or v4) else 'soc-v2-smoke' if v2 else 'soc-smoke' if soc else 'smoke')]
                elif stage == 'soc-v4-full-train': args += ['--train','--output-dir','/workspace/outputs/soc-v4-full-train']
                elif stage == 'soc-v4-pilot': args += ['--train','--output-dir','/workspace/outputs/soc-v4-pilot']
                elif stage == 'soc-v3-pilot': args += ['--train','--output-dir','/workspace/outputs/soc-v3-pilot']
                elif stage == 'soc-v2-pilot': args += ['--train','--output-dir','/workspace/outputs/soc-v2-pilot']
                elif stage == 'soc-pilot': args += ['--train','--output-dir','/workspace/outputs/soc-pilot']
                elif stage == 'soc-train': args += ['--train','--output-dir','/workspace/outputs/soc-main']
                else: args += ['--train','--output-dir','/workspace/outputs/train']
                if stage in ('smoke','train','soc-smoke','soc-pilot','soc-train','soc-v4-full-smoke','soc-v4-full-train','soc-v4-smoke','soc-v4-pilot','soc-v3-smoke','soc-v3-pilot','soc-v2-smoke','soc-v2-pilot','soc-memory-smoke','soc-memory-vmm','soc-memory-trace','soc-memory-loss'):
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
