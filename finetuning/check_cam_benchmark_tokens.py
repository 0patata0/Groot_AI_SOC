"""CPU-only prompt sizing for CAM; no truncation, generation, or training."""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path

from check_soc_observation_tokens import metadata_check, MODEL, REVISION
from score_cam_benchmark import load_bundle
from audit_cam_inputs import require


def measure(inputs, tokenizer, reserve):
    require(type(reserve) is int and 1 <= reserve <= 4096, 'Invalid completion reserve')
    rows = []
    for row in inputs:
        require(len(row['messages']) == 1 and row['messages'][0]['role'] == 'user', 'Unexpected prompt shape')
        text = tokenizer.apply_chat_template(row['messages'], tokenize=False,
                                             add_generation_prompt=True, enable_thinking=False)
        original = row['messages'][0]['content']
        require(isinstance(text, str) and bool(original.strip()) and original.strip() in text,
                'Template lost prompt content beyond outer whitespace')
        ids = tokenizer.encode(text, add_special_tokens=False)
        require(isinstance(ids, (list, tuple)) and ids and all(type(x) is int for x in ids),
                'Expected flat token IDs, not mapping fields or a batched encoding')
        direct = tokenizer.apply_chat_template(row['messages'], tokenize=True, return_dict=False,
                                               add_generation_prompt=True, enable_thinking=False)
        require(isinstance(direct, (list, tuple)) and list(direct) == list(ids),
                'Rendered encoding differs from direct flat template tokenization')
        rows.append({'id': row['id'], 'prompt_tokens': len(ids),
                     'required_context_with_reserve': len(ids) + reserve, 'truncated': False,
                     'template_outer_whitespace_trimmed': original not in text})
    require(rows and len({r['id'] for r in rows}) == len(rows), 'Empty/repeated input')
    return {'records': rows, 'inputs': len(rows), 'completion_reserve_tokens': reserve,
            'max_prompt_tokens': max(r['prompt_tokens'] for r in rows),
            'max_required_context': max(r['required_context_with_reserve'] for r in rows),
            'rendered_and_direct_token_ids_equal': True,
            'inputs_with_template_outer_whitespace_trimmed': sum(r['template_outer_whitespace_trimmed'] for r in rows),
            'context_budget_analysis': {str(size): {'fit': sum(r['required_context_with_reserve'] <= size for r in rows),
                                                   'over': sum(r['required_context_with_reserve'] > size for r in rows)}
                                        for size in (4096, 8192, 16384, 32768)},
            'scope': 'Hypothetical context budgets; not a claim about live server settings or actual completion length.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--base-dir', type=Path, required=True)
    p.add_argument('--base-manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--completion-reserve', type=int, default=512)
    args = p.parse_args()
    require(not args.output.exists(), 'Output already exists')
    manifest, blobs = load_bundle(args.bundle)
    hashes = metadata_check(args.base_dir, json.loads(args.base_manifest.read_text()))
    os.environ.update(CUDA_VISIBLE_DEVICES='', HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', TOKENIZERS_PARALLELISM='false')
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(args.base_dir), local_files_only=True, trust_remote_code=False)
    require(bool(tokenizer.chat_template), 'No model chat template')
    result = measure(blobs['inputs.jsonl'], tokenizer, args.completion_reserve)
    result.update(checked_at_kst=datetime.now(timezone(timedelta(hours=9))).isoformat(),
                  actual_tokenizer=True, model=MODEL, revision=REVISION,
                  tokenizer_metadata_sha256=hashes, input_sha256=manifest['outputs']['inputs.jsonl']['sha256'],
                  bundle_manifest_sha256=hashlib.sha256((args.bundle / 'manifest.json').read_bytes()).hexdigest(),
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  model_generation=False, GPU_training=False)
    with args.output.open('x') as f:
        f.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('inputs', 'max_prompt_tokens', 'max_required_context', 'context_budget_analysis')}))


if __name__ == '__main__':
    main()
