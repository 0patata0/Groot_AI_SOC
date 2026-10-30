"""Reserve original CAM queries for a source-labelled benchmark, never for SFT.

Collapse byte-identical repetitions; preserve original prompts, labels and all
source coordinates. Identifier-bearing inputs remain intact and stratified.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path

from audit_cam_inputs import audit, parse, require, visible_annotations

ROOT = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def build(queries, labels):
    source_audit = audit(queries, labels)
    require(source_audit['identical_prompt_conflicting_label_groups'] == 0,
            'Identical prompt has conflicting provider labels')
    require(source_audit['cross_step_identical_prompt_groups'] == 0,
            'Cross-step shared input needs grouping review')
    grouped = defaultdict(list)
    for n, row in enumerate(queries, 1):
        grouped[sha(row['prompt'].encode())].append((n, row))
    inputs, gold, lineage = [], [], []
    for digest, occurrences in sorted(grouped.items()):
        row = occurrences[0][1]
        identifier = 'CAM-' + digest[:24]
        literal, structured, paths = visible_annotations(row['prompt'])
        stratum = ('structured_technique_identifier' if structured else
                   'other_literal_technique_identifier' if literal else 'no_literal_technique_identifier')
        # Only messages are model input. Gold, scenario and strata stay outside.
        inputs.append({'id': identifier, 'messages': [{'role': 'user', 'content': row['prompt']}]})
        gold.append({'id': identifier, 'techniques': sorted(row['ground_truth']),
                     'meaning': 'Provider attack-step labels, not full SOC response gold'})
        lineage.append({'id': identifier, 'prompt_sha256': digest,
                        'scenario_group': 'cam-scenario:' + row['scenario'],
                        'scenario_step': row['scenario'] + '-' + row['step'],
                        'stratum': stratum, 'literal_ids': sorted(literal),
                        'structured_annotation_ids': sorted(structured), 'annotation_paths': paths,
                        'exact_gold_id_visible': bool(literal & set(row['ground_truth'])),
                        'occurrences': [{'source_line': n,
                                         'label_key': r['scenario'] + ('_' + r['variant'] if r['variant'] else '') + '-' + r['step'],
                                         'variant': r['variant']} for n, r in occurrences],
                        'partition': 'reserved_external_benchmark_candidate',
                        'eligible_for_training': False})
    require(len({x['id'] for x in inputs}) == len(inputs), 'Opaque ID collision')
    return inputs, gold, lineage, {
        'source_queries': len(queries), 'unique_inputs': len(inputs),
        'source_repetitions_collapsed': len(queries) - len(inputs),
        'scenario_steps': len({x['scenario_step'] for x in lineage}),
        'scenario_groups': len({x['scenario_group'] for x in lineage}),
        'inputs_by_scenario': dict(Counter(x['scenario_group'] for x in lineage)),
        'inputs_by_stratum': dict(Counter(x['stratum'] for x in lineage)),
        'exact_gold_identifier_visible_inputs': sum(x['exact_gold_id_visible'] for x in lineage),
        'max_labels_per_input': max(len(g['techniques']) for g in gold),
        'inputs_with_more_than_10_provider_labels': sum(len(g['techniques']) > 10 for g in gold),
        'label_count_distribution': dict(Counter(len(g['techniques']) for g in gold)),
        'provider_top_k_request': 10,
        'training_admitted': 0, 'independent_final_evaluation_records': 0,
        'original_user_prompt_bytes_unchanged': True,
        'normal_vs_attack_confidence_accuracy_supported': False}


def prepare(directory, output):
    require(not output.exists(), 'Output already exists')
    reviewed = json.loads((ROOT / 'CAM_INPUT_REVIEW.json').read_text())
    specs = {x['file']: x for x in reviewed['sources']['files']}
    blobs = {}
    for name in ('labels.json', 'llm_queries.json', 'LICENSE'):
        path = directory / name
        require(not path.is_symlink() and path.stat().st_size <= 10_000_000, 'Unsafe/oversized source')
        raw = path.read_bytes()
        require(len(raw) == specs[name]['bytes'] and sha(raw) == specs[name]['sha256'], 'Pinned source mismatch')
        blobs[name] = raw
    inputs, gold, lineage, counts = build([parse(x) for x in blobs['llm_queries.json'].splitlines()], parse(blobs['labels.json']))
    notices = (
        'CAM-LDS, Austrian Institute of Technology; virtual AttackBed attack experiments, not production victim incidents.\n'
        'Original log release v1: https://doi.org/10.5281/zenodo.18390561 (CC BY 4.0).\n'
        'Paper: https://doi.org/10.1007/s10207-026-01318-x\n'
        'Queries/labels: https://github.com/ait-aecid/attack-manifestations-interpretation/tree/42bbd2cf8409f64a1e6c8fc936c91725e8c558b2\n'
        'Repository LICENSE is GPL-3.0; preserved in UPSTREAM_LICENSE.txt. Do not relabel repository artifacts as CC BY.\n'
        'Provider prompts/labels remain unchanged. Project authorship: deduplication, IDs, provenance, stratification and scoring.\n'
        'No benign-user simulation; confidence fields cannot establish real-world false-positive rate.\n'
        'No provider model responses used as ground truth. Not SFT, not certified operator decisions, not a sealed independent final test.\n'
    ).encode()
    artifacts = {'inputs.jsonl': inputs, 'gold.jsonl': gold, 'lineage.jsonl': lineage}
    raw_files = {name: ''.join(canonical(x) + '\n' for x in values).encode() for name, values in artifacts.items()}
    raw_files.update({'SOURCE_NOTICE.txt': notices, 'UPSTREAM_LICENSE.txt': blobs['LICENSE']})
    manifest = {'schema': 1, 'prepared_at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
                'status': 'reserved_benchmark_candidate_not_final_test', 'counts': counts,
                'source_commit': '42bbd2cf8409f64a1e6c8fc936c91725e8c558b2',
                'source_sha256': {n: sha(raw) for n, raw in blobs.items()},
                'outputs': {n: {'sha256': sha(raw), 'bytes': len(raw)} for n, raw in raw_files.items()},
                'builder_sha256': sha(Path(__file__).read_bytes()),
                'scoring_contract': {
                    'request': 'Preserved provider JSON: exactly10 unique ranked techniques, confidence enum and nonempty explanation.',
                    'main_aggregation': 'Each unique prompt once; equal mean within each step, then equal step means within each scenario, then equal scenario means.',
                    'strata': 'Report structured IDs, other literal IDs, and no literal IDs separately; none proves pure raw-log reasoning.',
                    'metrics': ['top1_hit', 'exact_recall_at_1_3_5_10', 'parent_recall_at_1_3_5_10', 'label_mean_reciprocal_rank', 'omitted_provider_labels_at10', 'response_coverage', 'schema_failures'],
                    'missing_or_invalid': 'Zero credit and all provider labels counted omitted; never silently skip.',
                    'extra_ranked_choices': 'The prompt explicitly requests10 choices; non-gold choices are not automatically hallucinations.',
                    'over_10_reference_labels': 'Report the attainable recall ceiling and unavoidable omissions separately; do not penalize impossible exhaustive coverage as a model omission.',
                    'prohibited_claims': ['benign detection accuracy', 'SOC approval/write/rollback ability', 'new independent final-test score', 'institution-certified Korean operator decisions']},
                'remaining': ['Actual tokenizer/context coverage without truncation',
                              'Historical whole-source overlap and held-out episode review',
                              'Freeze model/harness/runtime before final use; curator audit is not blindness',
                              'Separate operational MCP/approval/write/rollback evaluation']}
    output.mkdir()
    for name, raw in raw_files.items():
        with (output / name).open('xb') as f:
            f.write(raw)
    with (output / 'manifest.json').open('x') as f:
        f.write(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(prepare(args.directory, args.output)['counts']))


if __name__ == '__main__':
    main()
