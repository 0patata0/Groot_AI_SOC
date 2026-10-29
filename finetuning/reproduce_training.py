"""Repeat the same two-step smoke in fresh processes under one deterministic profile.

Requires a separately reviewed bounded root window. Does not change production
profiles, full-training inputs, model tags or the historical reference threshold.
"""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from zoneinfo import ZoneInfo


def now():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def trial_config(original, output):
    required = {'max_steps': 2, 'max_train_samples': 2, 'max_eval_samples': 8,
                'gradient_accumulation_steps': 1, 'smoke_longest_prefixes': True}
    for key, value in required.items():
        if original.get(key) != value:
            raise ValueError('Original smoke scope differs: ' + key)
    config = dict(original)
    config.update(output_dir=str(output), deterministic_training=True)
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/workspace'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    if output.exists():
        raise ValueError('Prior reproduction exists; choose a new reviewed output')
    output.mkdir(parents=True)
    record = {'started_at_kst': now(), 'status': 'preparing', 'training_updates': 0,
              'runs': [], 'prepare_only': args.prepare_only}
    def save():
        p = output / '.report.json.tmp'
        p.write_text(json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False)+'\n')
        p.replace(output / 'report.json')
    save()
    try:
        original = json.loads((root/'outputs/soc-v5-smoke/run_manifest.json').read_text())['config']
        for index in (1, 2):
            config = trial_config(original, output/f'run-{index}')
            path = output/f'config-{index}.json'
            path.write_text(json.dumps(config, indent=2)+'\n')
        if args.prepare_only:
            import torch
            from train import read_config, check_data, prepare_tokens, collate_lists
            from reproduce_evaluation import token_fingerprint
            config = read_config(output/'config-1.json')
            checks = check_data(config)
            tokenizer, data = prepare_tokens(config, output)
            record.update(status='prepared', data_sha256=checks['sha256'],
                          validation_fingerprint=token_fingerprint(data['validation']),
                          model_input_fingerprint=token_fingerprint([
                              collate_lists([item],tokenizer.pad_token_id) for item in data['validation']]),
                          train_prefixes=[item['prefix_identity'] for item in data['train']],
                          cuda_initialized=torch.cuda.is_initialized())
        else:
            record['status'] = 'training';save()
            for index in (1, 2):
                config_path = output/f'config-{index}.json'
                log = output/f'run-{index}.log'
                with log.open('w') as handle:
                    subprocess.run([sys.executable,'-B',str(root/'finetuning/train.py'),
                                    '--config',str(config_path),'--train','--offline'],
                                   stdout=handle,stderr=subprocess.STDOUT,check=True,timeout=210,
                                   env={**os.environ,'CUBLAS_WORKSPACE_CONFIG':':4096:8'})
                run = output/f'run-{index}'
                state = json.loads((run/'trainer_state.json').read_text())
                if state['global_step'] != 2:
                    raise ValueError('Expected exactly two completed optimizer steps')
                metrics = {**json.loads((run/'train_results.json').read_text()),
                           **json.loads((run/'eval_results.json').read_text())}
                manifest = json.loads((run/'run_manifest.json').read_text())
                record['runs'].append({'index':index,'metrics':metrics,
                                       'determinism':manifest['hardware']['determinism']})
                record['training_updates'] += 2;save()
            import torch
            from safetensors.torch import load_file
            paths = [output/f'run-{i}/adapter/adapter_model.safetensors' for i in (1,2)]
            tensors = [load_file(str(path),device='cpu') for path in paths]
            if tensors[0].keys() != tensors[1].keys():
                raise ValueError('Adapter tensor coverage differs')
            if not tensors[0] or any(not torch.isfinite(value).all() for item in tensors for value in item.values()):
                raise ValueError('Empty or nonfinite adapter')
            differences = [key for key in tensors[0] if not torch.equal(tensors[0][key],tensors[1][key])]
            record.update(tensor_count=len(tensors[0]),different_tensor_count=len(differences),
                          maximum_tensor_difference=max(float((tensors[0][k]-tensors[1][k]).abs().max()) for k in tensors[0]),
                          adapter_sha256=[hashlib.sha256(path.read_bytes()).hexdigest() for path in paths])
            if differences:
                raise ValueError('Deterministic training still produces different adapter tensors')
            first,second=(row['metrics'] for row in record['runs'])
            for key in ('train_loss','eval_loss'):
                if first[key] != second[key]:raise ValueError('Repeated metric differs: '+key)
            record['status']='completed'
        record['finished_at_kst']=now();save()
    except BaseException as exc:
        record.update(status='failed',error_type=type(exc).__name__,error=str(exc)[-1000:],finished_at_kst=now())
        save();raise


if __name__=='__main__':
    main()
