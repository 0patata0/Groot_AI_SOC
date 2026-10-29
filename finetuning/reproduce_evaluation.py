"""Operator diagnostic: repeated evaluation of saved adapters, no training/update.

Runs in the existing pinned Thor container. No model download, merge,
registration or promotion. A separate root-owned window restores inference.
"""
import argparse
from array import array
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import time
from zoneinfo import ZoneInfo


def now():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def compare_repeats(passes):
    groups = defaultdict(list)
    for row in passes:
        values = row['per_example_loss']
        if not values or any(not math.isfinite(v) for v in values):
            raise ValueError('Nonfinite or empty evaluation')
        groups[(row['adapter'], row['mode'])].append(values)
    result = []
    for (adapter, mode), rows in groups.items():
        if any(len(r) != len(rows[0]) for r in rows):
            raise ValueError('Different evaluation observation counts')
        maximum = max((max(abs(a-b) for a,b in zip(rows[0],r)) for r in rows[1:]), default=0.0)
        result.append({'adapter':adapter, 'mode':mode, 'runs':len(rows),
                       'examples':len(rows[0]), 'maximum_repeat_loss_difference':maximum})
    return result


def token_fingerprint(validation):
    """Canonical token integers; array storage and list storage mean the same input."""
    def plain(value):
        if isinstance(value, array):
            if value.typecode not in 'bBhHiIlLqQ':
                raise ValueError('Token arrays must contain integers')
            return value.tolist()
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError('Token metadata keys must be strings')
            return {key: plain(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [plain(item) for item in value]
        if value is None or type(value) in (str, int, bool):
            return value
        raise ValueError('Unsupported token metadata type: ' + type(value).__name__)
    encoded = json.dumps(plain(validation), sort_keys=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def evaluate(root, output, prepare_only=False):
    if output.exists():
        raise ValueError('Prior diagnostic exists; select a new reviewed output')
    output.mkdir(parents=True)
    record = {'schema': 1, 'started_at_kst': now(), 'status': 'preparing',
              'training_updates': 0, 'passes': [], 'prepare_only': prepare_only}
    def save():
        temporary = output / '.report.json.tmp'
        temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
        temporary.replace(output / 'report.json')
    save()
    try:
        return run_evaluation(root, output, record, save, prepare_only)
    except BaseException as exc:
        record.update(status='failed', failed_phase=record['status'],
                      error_type=type(exc).__name__, error=str(exc)[-2000:], finished_at_kst=now())
        save()
        raise


def run_evaluation(root, output, record, save, prepare_only):
    import torch
    from transformers import set_seed
    from peft import PeftModel
    import model_profile
    from train import prepare_tokens, checkpoint_loading, collate_lists
    from completion_loss import completion_loss
    old = root/'attempts/v5-checkpointed-20261029/outputs/soc-v5-smoke'
    new = root/'outputs/soc-v5-smoke'
    config = json.loads((new/'run_manifest.json').read_text())['config']
    record.update(config=config, packages={n:__import__('importlib.metadata',fromlist=['version']).version(n)
                    for n in ['torch','transformers','peft']}, cublas_workspace=os.environ.get('CUBLAS_WORKSPACE_CONFIG'))
    set_seed(config['seed'])
    tokenizer, data = prepare_tokens(config, output)
    validation = data['validation']
    if len(validation) != 8:
        raise ValueError('Exactly the original eight evaluation examples required')
    record['validation_fingerprint'] = token_fingerprint(validation)
    batches = [collate_lists([item], tokenizer.pad_token_id) for item in validation]
    # Use the training collator: raw rows store prompt boundaries, not attention masks/labels.
    for batch in batches:
        shapes = {tuple(torch.tensor(batch[k], dtype=torch.long).shape)
                  for k in ('input_ids', 'attention_mask', 'labels')}
        if len(shapes) != 1 or next(iter(shapes))[0] != 1:
            raise ValueError('Invalid singleton evaluation batch')
        if not any(label != -100 for label in batch['labels'][0][1:]):
            raise ValueError('No shifted supervised labels')
    record['model_input_fingerprint'] = token_fingerprint(batches)
    if prepare_only:
        record.update(status='prepared', validation_examples=len(validation), finished_at_kst=now(),
                      cuda_initialized=torch.cuda.is_initialized())
        save()
        return record
    record['status']='loading';save()
    with checkpoint_loading(config):
        base = model_profile.model_class(config).from_pretrained(config['model_name_or_path'],
            revision=config['revision'],trust_remote_code=False,local_files_only=True,dtype=torch.bfloat16,
            **model_profile.loading_kwargs(config),device_map={'':0},attn_implementation='sdpa')
    base.config.use_cache=False
    if hasattr(base.config,'text_config'):base.config.text_config.use_cache=False
    model=PeftModel.from_pretrained(base,str(old/'adapter'),adapter_name='reference',is_trainable=False)
    model.load_adapter(str(new/'adapter'),adapter_name='r7',is_trainable=False)
    model.eval();record['status']='evaluating';save()
    for mode in ['current','deterministic']:
        if mode=='deterministic':
            torch.use_deterministic_algorithms(True)
            torch.backends.cudnn.benchmark=False
            torch.backends.cudnn.deterministic=True
            torch.backends.cuda.matmul.allow_tf32=False
            torch.backends.cudnn.allow_tf32=False
        for adapter in ['reference','r7','reference','r7']:
            model.set_adapter(adapter);model.eval();losses=[];started=time.monotonic()
            try:
                with torch.no_grad(),torch.autocast('cuda',dtype=torch.bfloat16):
                    for item in batches:
                        inputs={k:torch.tensor(item[k],dtype=torch.long,device='cuda')
                                for k in ['input_ids','attention_mask','labels']}
                        loss,_,_=completion_loss(model,inputs);losses.append(float(loss.detach().float().cpu()))
                row={'adapter':adapter,'mode':mode,'at_kst':now(),'seconds':time.monotonic()-started,
                     'per_example_loss':losses,'mean_loss':sum(losses)/len(losses)}
                record['passes'].append(row);save()
            except Exception as exc:
                record.update(failed_mode=mode, failed_adapter=adapter)
                save();raise
    record.update(status='completed',finished_at_kst=now(),repeat_comparison=compare_repeats(record['passes']),
                  peak_cuda_allocated_gib=torch.cuda.max_memory_allocated()/2**30)
    save()
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('/workspace'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--prepare-only',action='store_true',help='Token preparation/fingerprint only; no model/CUDA')
    args=parser.parse_args()
    # Must be supplied before the process initializes CUDA/cuBLAS.
    if os.environ.get('CUBLAS_WORKSPACE_CONFIG')!=':4096:8':
        raise ValueError('Reviewed cuBLAS workspace setting required')
    evaluate(args.root.resolve(),args.output.resolve(),args.prepare_only)


if __name__=='__main__':
    main()
