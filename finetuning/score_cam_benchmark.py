"""Score reserved CAM ranking responses; never execute a model or promote it.

Source-label agreement is not a complete SOC quality or hallucination measure.
No skipped missing outputs; no weighting by duplicate provider repetitions.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from statistics import mean

from audit_cam_inputs import TECHNIQUE, parse, require, parent

CONFIDENCE = {'Certain: Attack', 'Almost Certain: Attack', 'Somewhat Certain: Attack',
              'Neutral', 'Somewhat Certain: Normal', 'Almost Certain: Normal', 'Certain: Normal'}


def score_response(raw, gold):
    require(isinstance(gold, list) and gold and len(set(gold)) == len(gold)
            and all(isinstance(x, str) and TECHNIQUE.fullmatch(x) for x in gold), 'Invalid provider labels')
    predicted, failure = [], None
    if raw is None:
        failure = 'missing_response'
    else:
        try:
            require(isinstance(raw, str) and len(raw.encode()) <= 1_000_000, 'Invalid response type/size')
            obj = parse(raw)
            require(isinstance(obj, dict) and set(obj) == {'techniques', 'confidence', 'explanation'}, 'Wrong response fields')
            values = obj['techniques']
            require(isinstance(values, list) and len(values) == 10
                    and all(isinstance(x, str) and TECHNIQUE.fullmatch(x) for x in values)
                    and len(set(values)) == len(values), 'Exactly10 distinct ranked technique IDs required')
            require(isinstance(obj['confidence'], str) and obj['confidence'] in CONFIDENCE, 'Invalid confidence enum')
            require(isinstance(obj['explanation'], str) and bool(obj['explanation'].strip()), 'Missing explanation')
            predicted = values
        except (ValueError, TypeError):
            failure = 'invalid_response_schema'
    expected = set(gold)
    expected_parents = {parent(x) for x in gold}
    # Preserve source ranking positions when collapsing parent matches; do not
    # move the 11th original prediction into top10 through de-duplication.
    exact = {str(k): len(expected & set(predicted[:k])) / len(expected) for k in (1, 3, 5, 10)}
    parents = {str(k): len(expected_parents & {parent(x) for x in predicted[:k]}) / len(expected_parents)
               for k in (1, 3, 5, 10)}
    missing = sorted(expected - set(predicted))
    unavoidable = max(len(expected) - 10, 0)
    return {'valid_response': failure is None, 'failure': failure,
            'top1_hit': float(bool(predicted) and predicted[0] in expected),
            'exact_recall': exact, 'parent_recall': parents,
            'label_mean_reciprocal_rank': sum(1 / (predicted.index(x) + 1) if x in predicted else 0 for x in gold) / len(gold),
            'omitted_provider_labels_at10': missing,
            'unavoidable_omissions_at10': unavoidable,
            'avoidable_omissions_at10': max(len(missing) - unavoidable, 0),
            'exact_recall_at10_ceiling': min(10, len(gold)) / len(gold),
            'all_provider_labels_present': not missing,
            'confidence_accuracy_scored': False, 'explanation_factuality_scored': False}


def flat_metrics(row):
    return {'top1_hit': row['top1_hit'], 'label_mean_reciprocal_rank': row['label_mean_reciprocal_rank'],
            'response_coverage': float(row['valid_response']),
            'exact_recall_at10_ceiling': row['exact_recall_at10_ceiling'],
            **{'exact_recall_at' + k: v for k, v in row['exact_recall'].items()},
            **{'parent_recall_at' + k: v for k, v in row['parent_recall'].items()}}


def average(items):
    require(bool(items), 'Empty aggregate')
    return {key: mean(x[key] for x in items) for key in items[0]}


def aggregate(rows):
    steps = defaultdict(list)
    for row in rows:
        steps[(row['scenario_group'], row['scenario_step'])].append(flat_metrics(row))
    scenarios = defaultdict(list)
    for (scenario, _), values in steps.items():
        scenarios[scenario].append(average(values))
    scenario_means = {k: average(v) for k, v in sorted(scenarios.items())}
    return {'inputs': len(rows), 'steps': len(steps), 'scenarios': len(scenarios),
            'scenario_macro': average(list(scenario_means.values())),
            'step_macro': average([average(v) for v in steps.values()]),
            'unique_input_micro': average([flat_metrics(x) for x in rows]),
            'per_scenario': scenario_means,
            'failure_counts': dict(Counter(r['failure'] for r in rows if r['failure'])),
            'inputs_with_avoidable_omissions': sum(r['avoidable_omissions_at10'] > 0 for r in rows),
            'inputs_with_over_10_reference_labels': sum(r['unavoidable_omissions_at10'] > 0 for r in rows),
            'omitted_reference_labels': sum(len(r['omitted_provider_labels_at10']) for r in rows),
            'unavoidable_omissions_due_to_requested_top10': sum(r['unavoidable_omissions_at10'] for r in rows),
            'avoidable_omissions': sum(r['avoidable_omissions_at10'] for r in rows)}


def score(gold, lineage, predictions):
    ids = [x['id'] for x in gold]
    require(ids and len(set(ids)) == len(ids), 'Repeated/empty gold IDs')
    require([x['id'] for x in lineage] == ids, 'Gold/lineage identity mismatch')
    by_id = {}
    for item in predictions:
        require(isinstance(item, dict) and set(item) == {'id', 'response'} and isinstance(item['id'], str), 'Invalid prediction record')
        require(item['id'] in ids and item['id'] not in by_id, 'Unexpected/duplicate prediction ID')
        by_id[item['id']] = item['response']
    rows = []
    for g, trace in zip(gold, lineage):
        require(trace['partition'] == 'reserved_external_benchmark_candidate'
                and trace['eligible_for_training'] is False, 'Benchmark training isolation changed')
        rows.append({'id': g['id'], 'scenario_group': trace['scenario_group'],
                     'scenario_step': trace['scenario_step'], 'stratum': trace['stratum'],
                     **score_response(by_id.get(g['id']), g['techniques'])})
    return {'aggregate': aggregate(rows),
            'strata': {s: aggregate([r for r in rows if r['stratum'] == s]) for s in sorted({r['stratum'] for r in rows})},
            'records': rows, 'model_promotion_allowed': False,
            'interpretation': 'Agreement with provider attack-step labels under ranked top10. Not SOC competence, calibrated attack confidence, or an independent final test.'}


def load_bundle(directory):
    manifest = parse((directory / 'manifest.json').read_text())
    require(manifest['status'] == 'reserved_benchmark_candidate_not_final_test', 'Wrong bundle status')
    blobs = {}
    for name in ('inputs.jsonl', 'gold.jsonl', 'lineage.jsonl'):
        path = directory / name
        require(not path.is_symlink() and path.stat().st_size <= 20_000_000, 'Unsafe/oversized benchmark file')
        raw = path.read_bytes()
        require(manifest['outputs'][name] == {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}, 'Bundle hash mismatch')
        blobs[name] = [parse(x) for x in raw.splitlines()]
    require([x['id'] for x in blobs['inputs.jsonl']] == [x['id'] for x in blobs['gold.jsonl']]
            == [x['id'] for x in blobs['lineage.jsonl']], 'Input/gold/lineage IDs differ')
    require(len(blobs['gold.jsonl']) == manifest['counts']['unique_inputs'], 'Bundle count mismatch')
    return manifest, blobs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--predictions', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    require(not args.output.exists(), 'Output already exists')
    manifest, blobs = load_bundle(args.bundle)
    prediction_bytes = args.predictions.read_bytes()
    result = score(blobs['gold.jsonl'], blobs['lineage.jsonl'], [parse(x) for x in prediction_bytes.splitlines()])
    result.update(source_commit=manifest['source_commit'],
                  bundle_manifest_sha256=hashlib.sha256((args.bundle / 'manifest.json').read_bytes()).hexdigest(),
                  predictions_sha256=hashlib.sha256(prediction_bytes).hexdigest(),
                  scorer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with args.output.open('x') as f:
        f.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result['aggregate']))


if __name__ == '__main__':
    main()
