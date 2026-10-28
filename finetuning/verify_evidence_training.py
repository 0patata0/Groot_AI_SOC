"""Require the full selected epoch and exact microbatch lineage before export."""
from collections import Counter
import json
import math
from pathlib import Path

from prepare_evidence_v5 import sha
from training_lineage import prefix_identity


def verify(root):
    root = Path(root); folder = root/'outputs/soc-v5-train'
    frozen = json.loads((root/'finetuning/V5_TRAINING_INPUTS.json').read_text())
    profile_raw = (root/'finetuning/config.qwen36-soc-v5.json').read_bytes()
    if sha(profile_raw) != frozen['profile_sha256']:
        raise ValueError('Frozen training profile changed')
    config = json.loads(profile_raw)
    progress = json.loads((folder/'progress.json').read_text())
    trainer = json.loads((folder/'trainer_state.json').read_text())
    run = json.loads((folder/'run_manifest.json').read_text())
    if progress.get('status') != 'completed' or trainer.get('global_step') != config['max_steps'] or not math.isclose(trainer.get('epoch', -1), 1.0):
        raise ValueError('Complete V5 epoch required before export')
    if run['data']['sha256'] != frozen['data_sha256'] or run['config']['max_steps'] != config['max_steps']:
        raise ValueError('Run used different corpus or steps')
    if run.get('base_revision_resolved') != '995ad96eacd98c81ed38be0c5b274b04031597b0':
        raise ValueError('Pinned original base required')
    if (run['config'].get('loss_mode'), run['config'].get('record_prefix_usage'), run['config'].get('max_train_samples')) != ('all_assistant_turns', True, 0):
        raise ValueError('Full source-observation coverage was not requested')
    path = root/'finetuning'/frozen['data_folder']/'train.jsonl'; raw = path.read_bytes()
    if sha(raw) != frozen['data_sha256']['train']:
        raise ValueError('Training corpus changed')
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != frozen['records']['train'] or config['max_steps']*config['gradient_accumulation_steps'] != len(rows):
        raise ValueError('Full epoch observation/step count differs')
    expected = {row['id']: prefix_identity(row, len(row['messages'])-1) for row in rows}
    trace = [json.loads(line) for line in (folder/'successful_microbatch_lineage.jsonl').read_text().splitlines()]
    seen, steps = Counter(), Counter()
    for event in trace:
        if event.get('successful_forward_backward') is not True or len(event.get('prefixes', [])) != 1:
            raise ValueError('Invalid actual microbatch record')
        item = event['prefixes'][0]; identifier = item['record_id']
        if identifier not in expected or any(item.get(k) != v for k,v in expected[identifier].items()):
            raise ValueError('Actual training identity differs from original row')
        if item.get('encoding_mode') != 'all_assistant_turns' or item.get('supervised_assistant_indices') != [2]:
            raise ValueError('Actual target coverage differs')
        seen[identifier] += 1; steps[event['optimizer_step_before']] += 1
    if seen != Counter({k:1 for k in expected}) or steps != Counter({s:config['gradient_accumulation_steps'] for s in range(config['max_steps'])}):
        raise ValueError('Selected observations were omitted, repeated or not fully optimized')
    for name in ('train_results.json','eval_results.json'):
        metrics = json.loads((folder/name).read_text())
        if any(not math.isfinite(v) for v in metrics.values() if isinstance(v,(float,int))):
            raise ValueError('Nonfinite final metric')
    return {'status':'passed','epoch':1,'steps':config['max_steps'],'distinct_observations':len(seen),
            'successful_microbatches':len(trace),'adapter_sha256':sha((folder/'adapter/adapter_model.safetensors').read_bytes())}
