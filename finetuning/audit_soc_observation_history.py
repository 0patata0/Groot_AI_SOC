"""Verify frozen historical inputs and compare candidate prompts/source groups.

No old answers are emitted or copied into candidates. Exact prompt differences
do not establish new incidents, source independence, or unseen model pretraining.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path

from check_soc_observation_tokens import load_candidates
from prepare_soc_observation_inputs import audit_existing, require, verified


def safe_path(root, relative):
    p = Path(relative)
    require(not p.is_absolute() and '..' not in p.parts, 'Unsafe historical path')
    target = root / p
    require(not target.is_symlink() and target.resolve().is_relative_to(root.resolve()),
            'Historical path escapes root')
    return target


def read_frozen(root, spec):
    """Check six splits via two calls, including case/split identity alignment."""
    cases_raw = verified(safe_path(root, spec['source_cases']), spec['source_cases_sha256'])
    cases = [json.loads(line) for line in cases_raw.splitlines()]
    require(cases and len({x['id'] for x in cases}) == len(cases), 'Duplicate/empty historical cases')
    by_id = {c['id']: c for c in cases}
    require(set(spec['data_sha256']) == set(spec['records']) == {'train', 'validation', 'test'},
            'All historical splits required')
    require(all(c['split'] in spec['records'] for c in cases), 'Unknown case split')
    inputs = []
    seen = set()
    for split, digest in spec['data_sha256'].items():
        name = spec['data_folder'] + '/' + split + '.jsonl'
        raw = verified(safe_path(root, name), digest)
        rows = [json.loads(line) for line in raw.splitlines()]
        ids = [r['id'] for r in rows]
        require(len(rows) == spec['records'][split] and len(set(ids)) == len(ids),
                'Historical split count/identity differs')
        require(not seen.intersection(ids), 'Historical ID crosses splits')
        require(all(i in by_id and by_id[i]['split'] == split for i in ids),
                'Historical case/split mismatch')
        seen.update(ids)
        inputs.append({'file': name, 'rows': len(rows), 'sha256': digest})
    require(seen == set(by_id), 'Unmatched historical source cases')
    return cases, {'splits': inputs, 'source_cases': spec['source_cases'],
                   'source_cases_sha256': spec['source_cases_sha256'], 'cases': len(cases)}


def compare_groups(traces, v4_cases, v5_cases):
    historical = defaultdict(list)
    raw_rows = defaultdict(list)
    comparable = 0
    for case in v4_cases:
        review = case.get('review', {})
        environments = set()
        if review.get('ait_environment'):
            environments.add(review['ait_environment'])
        for source in review.get('source_rows', []):
            if source.get('environment'):
                environments.add(source['environment'])
            # Processed ADS row hashes are a different representation and are
            # intentionally not compared with original archive-line hashes.
            if source.get('environment') and source.get('source_file', '').startswith('gather/'):
                key = (source['environment'], source['source_file'], source['source_line'])
                raw_rows[key].append({'id': case['id'], 'split': case['split'],
                                      'sha256': source['source_line_sha256']})
                comparable += 1
        for env in environments:
            historical['ait-lds-ads:' + env].append({'id': case['id'], 'split': case['split']})
    rows, conflicts, exact, changed = [], [], [], []
    shared_cases = set()
    for trace in traces:
        require(trace['partition'] == 'historical_training_candidate_only'
                and trace['training_admitted'] is False, 'Candidate partition changed')
        matches = historical.get(trace['leakage_group'], [])
        shared_cases.update(m['id'] for m in matches)
        counts = dict(Counter(m['split'] for m in matches))
        rows.append({'candidate': trace['record_id'], 'group': trace['leakage_group'],
                     'matched_v4_cases_by_split': counts})
        if any(m['split'] != 'train' for m in matches):
            conflicts.append({'candidate': trace['record_id'], 'group': trace['leakage_group'],
                              'held_out_splits': sorted({m['split'] for m in matches if m['split'] != 'train'})})
        if trace['leakage_group'].startswith('ait-lds-ads:'):
            env = trace['leakage_group'].split(':', 1)[1]
            for ref, binding in trace['bindings'].items():
                if ref == 'separate_execution_diary':
                    continue
                for old in raw_rows.get((env, binding['member'], binding['line']), []):
                    record = {'candidate': trace['record_id'], 'ref': ref,
                              'historical_case': old['id'], 'split': old['split']}
                    (exact if old['sha256'] == binding['sha256'] else changed).append(record)
    return {'candidate_groups': rows, 'known_held_out_group_conflicts': conflicts,
            'candidates_reusing_v4_training_environments': sum(bool(r['matched_v4_cases_by_split'].get('train')) for r in rows),
            'shared_v4_cases': len(shared_cases), 'v4_raw_rows_comparable': comparable,
            'exact_original_row_matches': exact, 'same_coordinate_different_hash': changed,
            'v4_source_uris': dict(Counter(c['source_uri'] for c in v4_cases)),
            'v5_providers': dict(Counter(c['provider'] for c in v5_cases)),
            'limitations': [
                'Group linkage covers frozen V4/V5 metadata; other corpora receive exact-prompt checks only.',
                'Original-row comparison covers V4 gather/ archive rows, not processed ADS hashes.',
                'Linux-APT is absent from the declared V4/V5 source inventory; this is not a proof of absence from every older corpus or pretraining.',
                'AIT environments already used in historical training cannot become new independent final evaluation.',
                'All 17 reviewed candidates remain training-only candidates, not unseen evaluation or admitted SFT.'
            ]}


def audit(root, candidate_dir):
    manifest, candidates = load_candidates(candidate_dir)
    traces = [json.loads(line) for line in (candidate_dir / 'lineage.jsonl').read_text().splitlines()]
    historical, checked = {}, {}
    for version in ('V4', 'V5'):
        spec_raw = (root / (version + '_TRAINING_INPUTS.json')).read_bytes()
        historical[version], checked[version] = read_frozen(root, json.loads(spec_raw))
        checked[version]['spec_sha256'] = hashlib.sha256(spec_raw).hexdigest()
    prompts = audit_existing(root, candidates)
    require(not prompts['required_historical_files_missing'], 'Historical split absent')
    groups = compare_groups(traces, historical['V4'], historical['V5'])
    passed = not (prompts['matches'] or groups['known_held_out_group_conflicts']
                  or groups['same_coordinate_different_hash'])
    return {'schema': 1, 'checked_at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
            'status': 'scoped_history_checks_passed_not_admitted' if passed else 'blocked_by_history_conflict',
            'candidate_dialogues_sha256': manifest['dialogues_sha256'],
            'candidate_lineage_sha256': manifest['lineage_sha256'],
            'historical_integrity': checked, 'prompt_audit': prompts, 'source_group_audit': groups,
            'historical_row_visits': sum(f['rows'] for f in prompts['scanned']),
            'counts_are_unique_incidents': False, 'training_admitted': 0,
            'independent_final_evaluation_created': 0, 'model_quality_tested': False,
            'auditor_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--candidate-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    require(not args.output.exists(), 'Output already exists')
    result = audit(args.root, args.candidate_dir)
    with args.output.open('x') as handle:
        handle.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('status', 'historical_row_visits', 'training_admitted')}))
    raise SystemExit(0 if result['status'] == 'scoped_history_checks_passed_not_admitted' else 2)


if __name__ == '__main__':
    main()
