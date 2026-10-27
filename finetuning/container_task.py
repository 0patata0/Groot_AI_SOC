"""Fixed stages inside the pinned Thor training container; never controls Ollama."""
import argparse
import importlib.metadata as md
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

ROOT = Path('/workspace')
SOURCE = ROOT / 'finetuning'
PYTHON = ROOT / 'venv/bin/python'


def run(args, log, env=None):
    subprocess.run([str(x) for x in args], cwd=SOURCE, env=env or os.environ.copy(),
                   stdout=log, stderr=subprocess.STDOUT, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=['prepare','download','tokenize','smoke','train'])
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
                config=json.loads((SOURCE/'config.qwen36-thor.json').read_text())
                config.update(model_name_or_path='/workspace/base',offline=True)
                if stage == 'smoke': config['gradient_accumulation_steps']=1
                local_config=SOURCE/'config.run.local.json'
                local_config.write_text(json.dumps(config,indent=2)+'\n')
                args=[PYTHON,'-B',SOURCE/'train.py','--config',local_config]
                if stage == 'tokenize': args += ['--tokenize-only','--output-dir','/workspace/tokenization']
                elif stage == 'smoke': args += ['--train','--max-steps','2','--max-train-samples','32',
                    '--max-eval-samples','8','--output-dir','/workspace/outputs/smoke']
                else: args += ['--train','--output-dir','/workspace/outputs/train']
                run(args,log)
        status['status']='completed'
    except Exception as exc:
        status.update(status='failed',error_type=type(exc).__name__,error=str(exc))
        raise
    finally:
        status['updated_at_kst']=datetime.now(ZoneInfo('Asia/Seoul')).isoformat();save()


if __name__=='__main__': main()
