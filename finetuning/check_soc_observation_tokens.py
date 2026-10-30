"""CPU-only exact-tokenizer gate. Does not load weights or admit/train examples."""
import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path

from download_model import verify_artifact
from dialogue_encoding import encode_dialogue, label_values
from train import encode_completion
from prepare_soc_observation_inputs import require, verified
from prepare_data import canonical

MODEL = 'Qwen/Qwen3.6-35B-A3B'
REVISION = '995ad96eacd98c81ed38be0c5b274b04031597b0'


def metadata_check(base, manifest):
    require(manifest.get('model') == MODEL and manifest.get('revision') == REVISION
            and manifest.get('verified') is True, 'Unverified/different base model')
    items = [x for x in manifest['files'] if Path(x['path']).suffix in ('.json', '.jinja', '.txt', '.model')]
    paths = {x['path'] for x in items}
    require({'config.json', 'tokenizer.json', 'tokenizer_config.json'} <= paths,
            'Required tokenizer metadata missing')
    require(len(paths) == len(items), 'Repeated base metadata')
    actual = {str(p.relative_to(base)) for p in base.rglob('*')
              if p.is_file() and '.cache' not in p.relative_to(base).parts
              and p.suffix in ('.json', '.jinja', '.txt', '.model')}
    require(actual == paths, 'Unlisted/missing model metadata')
    hashes = {}
    for item in items:
        verify_artifact(base, item)
        hashes[item['path']] = hashlib.sha256((base / item['path']).read_bytes()).hexdigest()
    return hashes


def measure(rows, tokenizer, max_length):
    require(bool(rows), 'No candidate dialogues to measure')
    require(type(max_length) is int and 1 <= max_length <= 4096, 'Unsupported reviewed token budget')
    results, failures = [], Counter()
    for row in rows:
        require([m['role'] for m in row['messages']] == ['system', 'user', 'assistant']
                and not row.get('tools'), 'Unexpected candidate dialogue shape')
        # Measure without truncation, then apply the reviewed 4096-token ceiling.
        encoded, reason = encode_dialogue(row, tokenizer, 2_000_000, encode_completion)
        if reason:
            failures[reason] += 1
            results.append({'id': row['id'], 'failure': reason})
            continue
        ids = list(encoded['input_ids'])
        spans = encoded['supervised_ranges']
        labels = label_values(encoded, tokenizer.pad_token_id, len(ids) + 3)
        require(len(spans) == 1 and spans[0][0] == encoded['prompt_length']
                and spans[0][1] == len(ids), 'Complete assistant target not preserved')
        start, end = spans[0]
        require(labels[:start] == [-100] * start and labels[start:end] == ids[start:end]
                and labels[end:] == [-100] * 3, 'Prompt/assistant/padding loss-mask mismatch')
        failure = 'over_max_length' if len(ids) > max_length else None
        if failure:
            failures[failure] += 1
        results.append({'id': row['id'], 'tokens': len(ids), 'prompt_tokens': start,
                        'supervised_tokens': end - start, 'truncated': False, 'failure': failure})
    return {'records': results, 'failures': dict(failures), 'all_fit_and_aligned': not failures,
            'measured_records': sum('tokens' in x for x in results),
            'max_tokens': max((x.get('tokens', 0) for x in results), default=0),
            'training_admitted': 0}


def load_candidates(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    require(manifest['status'] in ('formatted_candidate_not_admitted_training',
                                   'semantically_refined_candidate_not_admitted')
            and type(manifest['training_admitted']) is int and manifest['training_admitted'] == 0,
            'Unexpected candidate status')
    raw = verified(directory / 'candidate-dialogues.jsonl', manifest['dialogues_sha256'])
    traces = verified(directory / 'lineage.jsonl', manifest['lineage_sha256'])
    require(len(raw) <= 2_000_000 and len(traces) <= 2_000_000, 'Candidate byte budget exceeded')
    rows = [json.loads(x) for x in raw.splitlines()]
    lineage = [json.loads(x) for x in traces.splitlines()]
    require(len(rows) == len(lineage) == manifest['records'] == 17 and
            len({r['id'] for r in rows}) == 17, 'Candidate records missing/repeated')
    for row, trace in zip(rows, lineage):
        require(trace['record_id'] == row['id'] and trace['training_admitted'] is False
                and trace['partition'] == 'historical_training_candidate_only'
                and trace['record_sha256'] == hashlib.sha256(canonical(row).encode()).hexdigest(),
                'Candidate lineage/partition differs')
    return manifest, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--base-dir', type=Path, required=True)
    parser.add_argument('--base-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-length', type=int, default=4096)
    args = parser.parse_args()
    require(not args.output.exists(), 'Output already exists')
    manifest, rows = load_candidates(args.candidate_dir)
    base_manifest = json.loads(args.base_manifest.read_text())
    hashes = metadata_check(args.base_dir, base_manifest)
    os.environ.update(CUDA_VISIBLE_DEVICES='', TOKENIZERS_PARALLELISM='false',
                      HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1')
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(args.base_dir), local_files_only=True, trust_remote_code=False)
    require(bool(tokenizer.chat_template), 'Model chat template missing')
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    require(tokenizer.pad_token_id is not None, 'Padding token missing')
    result = measure(rows, tokenizer, args.max_length)
    result.update(checked_at_kst=datetime.now(timezone(timedelta(hours=9))).isoformat(),
                  model=MODEL, revision=REVISION, tokenizer_metadata_sha256=hashes,
                  candidate_dialogues_sha256=manifest['dialogues_sha256'],
                  candidate_lineage_sha256=manifest['lineage_sha256'],
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  actual_tokenizer=True, max_length=args.max_length, GPU_training=False)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'records'}))
    raise SystemExit(0 if result['all_fit_and_aligned'] else 2)


if __name__ == '__main__':
    main()
