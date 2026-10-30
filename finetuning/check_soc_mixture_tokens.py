"""Exact CPU-only candidate length/mask audit, with no silent row filtering."""
import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path

from check_soc_observation_tokens import metadata_check, MODEL, REVISION
from dialogue_encoding import encode_dialogue, label_values
from prepare_soc_observation_inputs import require, verified
from train import encode_completion


def measure(rows, tokenizer):
    results = []
    for row in rows:
        encoded, error = encode_dialogue(row, tokenizer, 2_000_000, encode_completion)
        if error:
            results.append({'id': row['id'], 'error': error})
            continue
        ids = list(encoded['input_ids'])
        spans = encoded['supervised_ranges']
        require(len(spans) == sum(m['role'] == 'assistant' for m in row['messages']),
                'Assistant turn lost')
        labels = label_values(encoded, tokenizer.pad_token_id, len(ids) + 3)
        expected = [-100] * (len(ids) + 3)
        for start, end in spans:
            expected[start:end] = ids[start:end]
        require(labels == expected, 'Input/tool/padding loss mask differs')
        results.append({'id': row['id'], 'tokens': len(ids), 'assistant_turns': len(spans),
                        'supervised_tokens': sum(b-a for a, b in spans), 'truncated': False,
                        'over_4096': len(ids) > 4096})
    return {'records': results, 'rows': len(rows),
            'alignment_errors': dict(Counter(r['error'] for r in results if 'error' in r)),
            'over_4096': sum(r.get('over_4096', False) for r in results),
            'max_tokens': max((r.get('tokens', 0) for r in results), default=0)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--base-dir', type=Path, required=True)
    p.add_argument('--base-manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    require(not args.output.exists(), 'Output already exists')
    manifest_raw = (args.bundle / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_raw)
    require(manifest['status'] == 'separate_candidate_inventory_not_training_release'
            and manifest['training_admitted'] == 0, 'Unexpected release status')
    require(set(manifest['pool_files']) == {'cti-replay-candidates.jsonl',
            'observation-candidates.jsonl', 'optional-harness-candidates.jsonl'}, 'Unknown pool')
    pools = {}
    for name, spec in manifest['pool_files'].items():
        raw = verified(args.bundle / name, spec['sha256'])
        rows = [json.loads(line) for line in raw.splitlines()]
        require(len(rows) == spec['rows'], 'Pool row count differs')
        pools[name] = rows
    metadata = metadata_check(args.base_dir, json.loads(args.base_manifest.read_text()))
    os.environ.update(CUDA_VISIBLE_DEVICES='', TOKENIZERS_PARALLELISM='false',
                      HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1')
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(args.base_dir), local_files_only=True, trust_remote_code=False)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    results = {name: measure(rows, tokenizer) for name, rows in pools.items()}
    result = {'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
              'model': MODEL, 'revision': REVISION, 'metadata_sha256': metadata,
              'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
              'pool_files': manifest['pool_files'], 'measurements': results,
              'training_admitted': 0, 'rows_dropped': 0, 'truncated': False,
              'tool_calls_executed': 0, 'model_weights_loaded': False,
              'all_fit_4096_and_aligned': all(not r['alignment_errors'] and not r['over_4096'] for r in results.values())}
    with args.output.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({name: {k: v for k, v in data.items() if k != 'records'} for name, data in results.items()}))
    raise SystemExit(0 if result['all_fit_4096_and_aligned'] else 2)


if __name__ == '__main__':
    main()
