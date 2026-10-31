"""Unprivileged stages in the pinned Spark container. Never manages inference."""
import hashlib
import importlib.metadata as md
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

ROOT = Path('/workspace')
SOURCE = Path('/source')
PYTHON = ROOT / 'venv/bin/python'
sys.path.insert(0, str(SOURCE))


def save(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')
    temp.replace(path)


def main(stage):
    status = {'stage': stage, 'status': 'running',
              'at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat()}
    record = ROOT / (stage+'-status.json')
    if record.exists():
        raise RuntimeError('Stage already attempted; use a new run directory')
    save(record, status)
    try:
        if stage == 'prepare':
            subprocess.run([sys.executable, '-m', 'venv', '--system-site-packages', str(ROOT/'venv')], check=True)
            pins = []
            for name in ('torch', 'torchvision', 'torchaudio', 'triton'):
                try: pins.append(name+'=='+md.version(name))
                except md.PackageNotFoundError: pass
            constraints = ROOT/'vendor-constraints.txt'
            constraints.write_text('\n'.join(pins)+'\n')
            env = dict(os.environ, PIP_CONSTRAINT=str(constraints))
            subprocess.run([str(PYTHON), '-m', 'pip', 'install', '--no-cache-dir',
                '--disable-pip-version-check', '--report', str(ROOT/'install-report.json'),
                '-r', str(SOURCE/'requirements.qwen36-dgx.txt')], env=env, check=True)
            subprocess.run([str(PYTHON), '-m', 'pip', 'check'], env=env, check=True)
            subprocess.run([str(PYTHON), '-IB', str(__file__), 'preflight'], check=True)
        elif stage == 'preflight':
            from train import preflight
            import model_profile
            config = json.loads((ROOT/'profiles/main.json').read_text())
            hardware = preflight(config)
            save(ROOT/'hardware.json', hardware)
            model_profile.check_training_capacity(config, hardware)
        elif stage == 'download':
            from download_model import download, verify_artifact
            config = json.loads((ROOT/'profiles/main.json').read_text())
            config['model_name_or_path'] = 'Qwen/Qwen3.6-35B-A3B'
            transfer=ROOT/'base-transfer.json'
            if transfer.exists():
                import time
                from train import deadline_reached
                while json.loads(transfer.read_text())['status'] not in ('completed','failed'):
                    if deadline_reached(config): raise RuntimeError('Base transfer exceeded training window')
                    time.sleep(5)
                if json.loads(transfer.read_text())['status']!='completed': raise RuntimeError('Base transfer failed')
                manifest=json.loads((ROOT/'base-manifest.json').read_text())
                if not manifest.get('verified') or manifest['revision']!=config['revision'] or manifest['model']!=config['model_name_or_path']:
                    raise ValueError('Transferred base differs from pinned model')
                for artifact in manifest['files']: verify_artifact(ROOT/'base',artifact)
            else:
                download(config, ROOT/'base')
            # Release only this run's verified file-read cache before GPU loading.
            # This is an advisory optimization, not a global drop_caches operation.
            manifest=json.loads((ROOT/'base-manifest.json').read_text())
            released=[]
            for artifact in manifest['files']:
                if not artifact['path'].endswith('.safetensors'):continue
                path=ROOT/'base'/artifact['path']
                if path.is_symlink() or not path.resolve().is_relative_to((ROOT/'base').resolve()):
                    raise ValueError('Unsafe base path for file cache advice')
                with path.open('rb') as stream:
                    os.posix_fadvise(stream.fileno(),0,0,os.POSIX_FADV_DONTNEED)
                released.append(artifact['path'])
            save(ROOT/'base-read-cache.json',{'scope':'verified run-owned weight files only',
                'files':released,'global_cache_flush':False})
        elif stage in ('tokenize', 'smoke', 'main', 'resume-check'):
            config = json.loads((ROOT/'profiles'/('main.json' if stage in ('tokenize','resume-check') else stage+'.json')).read_text())
            raw = (ROOT/'base-manifest.json').read_bytes()
            manifest = json.loads(raw)
            if not manifest.get('verified') or manifest['revision'] != config['revision'] or manifest['model'] != 'Qwen/Qwen3.6-35B-A3B':
                raise ValueError('Unverified base or incompatible revision')
            config['base_artifact_manifest'] = {'model': manifest['model'], 'revision':manifest['revision'],
                'manifest_sha256':hashlib.sha256(raw).hexdigest()}
            config.update(data_dir='/data', output_dir=str(ROOT/stage), model_name_or_path=str(ROOT/'base'), offline=True)
            if stage=='resume-check':
                from check_resume_runtime import check
                save(ROOT/'resume-runtime-check.json',check(config,ROOT/'resume-cpu-test'))
                status['status']='completed'
                return
            profile = ROOT/(stage+'-resolved.json')
            save(profile, config)
            args = [str(PYTHON), '-B', str(SOURCE/'train.py'), '--config', str(profile),
                    '--tokenize-only' if stage == 'tokenize' else '--train']
            if stage == 'tokenize':
                subprocess.run(args, check=True)
            else:
                import guarded_process
                guarded_process.run(args, log=sys.stdout, cwd=SOURCE, env=os.environ.copy(),
                    report=ROOT/(stage+'-memory-guard.json'), reserve_bytes=16*2**30)
                progress = json.loads((ROOT/stage/'progress.json').read_text())
                if stage=='main' and progress['status'] in ('stopped_deadline','completed_training_validation_pending'):
                    status['status']=progress['status']
                    status['step']=progress['step']
                    return
                if progress['status'] != 'completed':
                    raise RuntimeError('Training stopped before the full plan completed: '+progress['status'])
                metrics = json.loads((ROOT/stage/'eval_results.json').read_text())
                import math
                if not math.isfinite(metrics['eval_loss']):
                    raise RuntimeError('Nonfinite final validation loss')
        else:
            raise ValueError('Unknown stage')
        status['status'] = 'completed'
    except BaseException as exc:
        status.update(status='failed', error=type(exc).__name__+': '+str(exc))
        raise
    finally:
        status['updated_at_kst'] = datetime.now(ZoneInfo('Asia/Seoul')).isoformat()
        save(record, status)


if __name__ == '__main__':
    main(sys.argv[1])
