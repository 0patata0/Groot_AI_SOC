"""Freeze small comparison arms from reviewed candidates, without admitting SFT.

The complete1197 inventory is retained. Row counts, target-token counts and actual
gradient contribution are different quantities. No evaluation/model outputs are
used to select the replay subset; no optimizer or production service is invoked.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path

from audit_soc_observation_history import read_frozen
from prepare_data import canonical
from prepare_soc_observation_inputs import require, verified
from score_cam_benchmark import load_bundle as load_cam_bundle

SEED = 'soc-source-grouped-pilot-20261030-v1'


def sha(raw):
    return hashlib.sha256(raw if isinstance(raw, bytes) else canonical(raw).encode()).hexdigest()


def technique_ids(case):
    values = [x['id'] for x in case['mappings']]
    require(values and len(set(values)) == len(values), 'Missing/repeated CTI mappings')
    return set(values)


def choose_replay(cases, count=48):
    require(type(count) is int and count > 0 and cases, 'Positive replay size required')
    require(all(c['split'] == 'train' for c in cases), 'Never select held-out cases')
    require(len({c['id'] for c in cases}) == len(cases), 'Repeated replay identity')
    require(len({c['group'] for c in cases}) >= count, 'Too few source groups')
    providers = sorted({c['provider'] for c in cases})
    require(count >= len(providers), 'Cannot preserve provider coverage')
    chosen, groups, covered = [], set(), set()

    def take(eligible):
        require(bool(eligible), 'Provider/source groups cannot be separated')
        # Greedy technique coverage, then a reproducible hash tie-break. These
        # are training metadata only, never quality scores or held-out labels.
        best = min(eligible, key=lambda c: (-len(technique_ids(c) - covered),
                                            sha((SEED+':'+c['id']).encode())))
        chosen.append(best);groups.add(best['group']);covered.update(technique_ids(best))

    for provider in providers:
        take([c for c in cases if c['provider'] == provider and c['group'] not in groups])
    while len(chosen) < count:
        take([c for c in cases if c['group'] not in groups])
    return sorted(chosen, key=lambda c: sha((SEED+':order:'+c['id']).encode()))


def group_partitions(cases):
    groups = defaultdict(set)
    for case in cases: groups[case['group']].add(case['split'])
    require(not any(len(v) > 1 for v in groups.values()), 'Related source group crosses historical splits')
    return {s: sum(v == {s} for v in groups.values()) for s in ('train', 'validation', 'test')}


def load_inventory(directory, token_proof):
    raw_manifest = (directory/'manifest.json').read_bytes();manifest = json.loads(raw_manifest)
    require(manifest['status'] == 'separate_candidate_inventory_not_training_release'
            and manifest['training_admitted'] == 0, 'Unexpected inventory release')
    require(manifest.get('V4_observation_revision', {}).get('records') == 126, 'Source-rechecked V4 observations required')
    proof = json.loads(token_proof.read_text())
    require(proof['state']['Running'] is False and proof['state']['ExitCode'] == 0
            and proof['state']['OOMKilled'] is False, 'Token gate did not finish successfully')
    token = proof['token_check']
    require(token['manifest_sha256'] == sha(raw_manifest) and token['pool_files'] == manifest['pool_files']
            and token['all_fit_4096_and_aligned'] is True and token['rows_dropped'] == 0
            and token['truncated'] is False, 'Token proof does not cover this complete inventory')
    require(set(manifest['pool_files']) == {'cti-replay-candidates.jsonl', 'observation-candidates.jsonl',
                                          'optional-harness-candidates.jsonl'}, 'Unexpected candidate pool')
    pools, measures = {}, {}
    for name, spec in manifest['pool_files'].items():
        raw = verified(directory/name, spec['sha256'])
        lines = raw.splitlines(keepends=True);rows = [json.loads(line) for line in lines]
        checked = token['measurements'][name]
        require(len(rows) == spec['rows'] == checked['rows'] and not checked['alignment_errors']
                and checked['over_4096'] == 0, 'Pool token count/errors differ')
        require(len({r['id'] for r in rows}) == len(rows), 'Repeated pool ID')
        by_id = {r['id']: line for r,line in zip(rows, lines)}
        require(len(checked['records']) == len(rows) and
                {x['id'] for x in checked['records']} == set(by_id), 'Per-record token proof incomplete')
        for rec in checked['records']:
            require('error' not in rec and rec['truncated'] is False and rec['over_4096'] is False
                    and type(rec['supervised_tokens']) is int and 0 < rec['supervised_tokens'] <= rec['tokens'] <= 4096,
                    'Invalid token measurement')
            require(rec['id'] not in measures, 'ID reused across pools')
            measures[rec['id']] = rec
        pools[name] = by_id
    require(len(measures) == 1197, 'Unexpected full inventory size')
    return manifest, pools, measures


def statistics(pools, measurements):
    stats = {}
    for name, ids in pools.items():
        rows = [measurements[i] for i in ids]
        stats[name] = {'rows': len(rows), 'input_and_target_tokens': sum(x['tokens'] for x in rows),
                       'target_tokens': sum(x['supervised_tokens'] for x in rows),
                       'assistant_turns': sum(x['assistant_turns'] for x in rows)}
    total_rows = sum(s['rows'] for s in stats.values());total_targets = sum(s['target_tokens'] for s in stats.values())
    require(total_rows > 0 and total_targets > 0, 'Empty exposure inventory')
    for s in stats.values():
        s['row_share_percent'] = round(100*s['rows']/total_rows, 4)
        s['target_token_share_percent'] = round(100*s['target_tokens']/total_targets, 4)
    return {'categories': stats, 'total_rows': total_rows, 'total_target_tokens': total_targets,
            'gradient_contribution_measured': False,
            'interpretation': 'Row frequency and supervised-token mass only. Gradients depend on data/model, batch reduction, accumulation and order.'}


def build(root, inventory, token_proof, output, loss_proof):
    require(not output.exists(), 'Output already exists')
    manifest, pools, measures = load_inventory(inventory, token_proof)
    config = json.loads((root/'config.qwen36-soc-v5.json').read_text())
    require(config['assistant_only_logits'] is True and config['per_device_train_batch_size'] == 1
            and config['loss_mode'] == 'all_assistant_turns', 'Recheck changed loss/batching contract')
    cam_manifest, _ = load_cam_bundle(root/'data-cam-benchmark-20261030-r2')
    require(cam_manifest['status'] == 'reserved_benchmark_candidate_not_final_test'
            and cam_manifest['counts']['training_admitted'] == 0, 'CAM partition changed')
    v5 = json.loads((root/'V5_TRAINING_INPUTS.json').read_text())
    loss_observation = json.loads(loss_proof.read_text());loss_check = loss_observation['loss_check']
    require(loss_observation['state']['Running'] is False and loss_observation['state']['ExitCode'] == 0
            and loss_observation['state']['OOMKilled'] is False
            and loss_check['completion_loss_sha256'] == v5['source_sha256']['completion_loss.py']
            and loss_check['profile_sha256'] == v5['profile_sha256']
            and loss_check['external_token_denominator_refused'] is True
            and loss_check['cuda_initialized'] is False and loss_check['model_weights_loaded'] is False
            and loss_check['training_started'] is False, 'Runtime loss proof differs or incomplete')
    cases, frozen = read_frozen(root, v5)
    partitions = group_partitions(cases)
    training = [c for c in cases if c['split'] == 'train']
    require({c['id'] for c in training} == set(pools['cti-replay-candidates.jsonl']), 'Replay pool differs from frozen training')
    selected = choose_replay(training)
    replay = {c['id']: pools['cti-replay-candidates.jsonl'][c['id']] for c in selected}
    observations = pools['observation-candidates.jsonl'];harness = pools['optional-harness-candidates.jsonl']
    arms = {'evidence-only.jsonl': {**replay, **observations},
            'evidence-plus-harness.jsonl': {**replay, **observations, **harness}}
    require(len(arms['evidence-only.jsonl']) == 191 and len(arms['evidence-plus-harness.jsonl']) == 221,
            'Pilot count or ID collision')
    pool_stats = statistics(pools, measures)
    arm_stats = {name: statistics({'CTI_replay': replay, 'institutional_observations': observations,
                                  **({'optional_harness': harness} if 'plus-harness' in name else {})}, measures)
                 for name in arms}
    all_techniques = set().union(*(technique_ids(c) for c in training))
    selected_techniques = set().union(*(technique_ids(c) for c in selected))
    selection = [{'id': c['id'], 'group': c['group'], 'provider': c['provider'],
                  'mapping_ids': sorted(technique_ids(c)), 'source_case_sha256': sha(c),
                  'original_record_line_sha256': sha(replay[c['id']])} for c in selected]
    evaluation = {
        'status': 'development_and_reserved_banks_only_final_operational_bank_missing',
        'training_admission_allowed': False,
        'banks': [
            {'name': 'V5_regression', 'role': 'development_regression_already_used', 'eligible_as_new_final': False,
             'path': v5['data_folder']+'/test.jsonl', 'sha256': v5['data_sha256']['test'], 'rows': 128,
             'scope': 'CTI technique mapping; not SOC operation proficiency'},
            {'name': 'CAM_external_candidate', 'role': 'reserved_public_benchmark_candidate', 'eligible_as_new_final': False,
             'rows': cam_manifest['counts']['unique_inputs'], 'manifest_sha256': sha((root/'data-cam-benchmark-20261030-r2/manifest.json').read_bytes()),
             'scope': 'Provider technique ranking, source-ID strata/ceiling limits; not all-role operational evidence',
             'remaining': 'Whole-source/episode separation and final model/harness freeze'},
            {'name': 'final_operational', 'role': 'not_created', 'rows': 0, 'eligible_as_new_final': False,
             'required': ['fresh source/incident-grouped evidence', 'full tool catalog including FW',
                          'read/target/pagination completeness', 'approval/edit/apply/verify/rollback',
                          'unavailable tools/storage/model and conflicting evidence',
                          'time/provenance correctness and no fabricated completion']}],
        'nonwaivable_failures': ['security-critical requested evidence/step omitted', 'fabricated evidence/state/action',
                                'wrong host/address/rule/target', 'unapproved protected action or approval bypass'],
        'scoring': {'clear': 100, 'minor': 80, 'major': 0, 'fatal': 0,
                    'missing_response': 'retain in denominator; incomplete case, no silent exclusion',
                    'manual_review_pending': 'not finalized and not eligible for promotion',
                    'required_facts': 'semantic completeness, not exact-wording match',
                    'promotion': 'Any nonwaivable failure blocks promotion; average score cannot offset it'},
        'comparison_controls': ['same base revision/quantization/context/decoding',
            'same tool schemas/permissions/approval limits', 'fresh conversations',
            'shared-server load and warm/cold cache reported', 'raw calls/arguments/results and all failures retained',
            'untrained+existing vs trained+cleaned, plus trained+existing and untrained+cleaned controls'],
        'training_compute_confound': 'One pass through191 versus221 rows is not equal-update or equal-token training. At batch1/accumulation2 with no dropped rows it is nominally96 versus111 updates. Report this and add a matched-compute control before attributing differences solely to harness examples; do not silently repeat data or count repeated rows as new cases.',
        'harness_cleanup': 'Retain rollback and all execution/approval/address/hash guards; learned behavior does not replace enforcement',
    }
    result = {'schema': 1, 'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
        'status': 'small_comparison_candidates_not_training_release', 'training_admitted': 0,
        'full_inventory_rows_preserved': 1197, 'unique_pilot_rows': 221, 'arm_rows_are_not_added_together': True,
        'seed': SEED, 'selection_method': '48 training source groups, one row per related group, provider coverage then greedy technique coverage/hash ties',
        'selection_uses_evaluation_labels_or_model_scores': False, 'recommended_as_optimal_mix': False,
        'why_48': 'Exploratory CTI replay cap near one quarter of the no-harness arm; keeps all143 reviewed observations and avoids CTI row-frequency dominance. Not an empirically optimized ratio.',
        'full_inventory_manifest_sha256': sha((inventory/'manifest.json').read_bytes()),
        'token_observation_sha256': sha(token_proof.read_bytes()), 'frozen_V5': frozen,
        'runtime_loss_observation_sha256': sha(loss_proof.read_bytes()),
        'runtime_loss_contract': loss_check,
        'historical_source_groups_by_split': partitions,
        'full_inventory_exposure': pool_stats, 'pilot_arm_exposure': arm_stats,
        'CTI_selection': {'rows': len(selected), 'groups': len({c['group'] for c in selected}),
                         'providers': dict(Counter(c['provider'] for c in selected)),
                         'full_train_distinct_mapping_ids': len(all_techniques),
                         'pilot_distinct_mapping_ids': len(selected_techniques),
                         'mapping_ids_not_in_pilot': sorted(all_techniques-selected_techniques)},
        'coverage_warning': f'Pilot replay includes{len(selected_techniques)} of{len(all_techniques)} distinct training mapping IDs;{len(all_techniques-selected_techniques)} remain in the intact full inventory. This is not a replacement for full CTI learning or proof of retention. Regression/coverage evaluation is mandatory before choosing a final mix.',
        'loss_contract': {'existing_profile': 'config.qwen36-soc-v5.json',
            'assistant_only_logits': True, 'per_device_train_batch_size': 1,
            'loss_reduction': 'ForCausalLMLoss default mean with num_items_in_batch=None',
            'not_claimed': 'Target token share equals gradient share, or more target text automatically increases sample weight',
            'implementation_sha256': sha((root/'completion_loss.py').read_bytes())},
        'remaining': ['Actual training profile, matched-compute comparison and memory preflight; no GPU/outage authorized by this file',
            'Final operational evaluation and further distinct authoritative operator evidence',
            'Small measured quality comparison; these arms are a proposal, not a selected winner'],
        'source_notice': 'All source hashes, licenses and authorship distinctions from the complete inventory remain applicable.',
    }
    files = {}
    for name, records in arms.items():
        # Same deterministic ordering for common rows; do not rewrite any row.
        ids = sorted(records, key=lambda i: sha((SEED+':arm:'+i).encode()))
        files[name] = b''.join(records[i] for i in ids)
    files['selection.json'] = (json.dumps(selection, ensure_ascii=False, indent=2)+'\n').encode()
    files['evaluation-boundaries.json'] = (json.dumps(evaluation, ensure_ascii=False, indent=2)+'\n').encode()
    files['full-inventory-manifest.json'] = (inventory/'manifest.json').read_bytes()
    for name, digest in manifest['support_files'].items():
        if name.endswith(('.txt', '.json')) and ('NOTICE' in name or 'LICENSE' in name or 'ATTRIBUTION' in name):
            files[name] = verified(inventory/name, digest)
    result['files'] = {n: {'sha256': sha(v), 'bytes': len(v)} for n,v in files.items()}
    result['arm_files'] = {n: {'rows': len(arms[n]), 'sha256': sha(files[n])} for n in arms}
    output.mkdir(parents=True, exist_ok=False)
    for n,v in files.items(): (output/n).write_bytes(v)
    (output/'manifest.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--token-proof', type=Path, required=True)
    p.add_argument('--loss-proof', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args();result = build(a.root,a.inventory,a.token_proof,a.output,a.loss_proof)
    print(json.dumps({'status': result['status'], 'arms': result['arm_files'],
                      'CTI': {k:v for k,v in result['CTI_selection'].items() if k != 'mapping_ids_not_in_pilot'}}))


if __name__ == '__main__': main()
