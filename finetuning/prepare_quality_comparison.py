"""Freeze small comparison profiles; never enqueue training or issue a release.

All source mixtures are prepared locally. The evaluation bodies remain local;
only their hashes, training inputs and future run profiles can be imported.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from training_quality import policy
from evaluation_scope import audit_files

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')


def admitted(directory):
    admission = json.loads((directory/'admission.json').read_text())
    if admission['truncation'] or admission['status'] != 'source_and_token_verified_waiting_final_review_and_gpu_smoke':
        raise ValueError('Require admitted complete conversations')
    for name, expected in admission['files'].items():
        if sha(directory/name) != expected: raise ValueError('Admitted mixture changed')
    rows = [json.loads(line) for line in (directory/'train.jsonl').read_text().splitlines()]
    if len({row['id'] for row in rows}) != len(rows): raise ValueError('Repeated training ID')
    return admission, {row['id']: row for row in rows}


def build(full, balanced, evaluation, output):
    full, balanced, evaluation, output = map(Path, (full, balanced, evaluation, output))
    if output.exists(): raise ValueError('Preserve earlier comparison plans')
    full_admission, full_rows = admitted(full)
    balance_admission, balance_rows = admitted(balanced)
    if not set(balance_rows) < set(full_rows): raise ValueError('Balanced arm must be a strict subset')
    if any(row != full_rows[ident] for ident, row in balance_rows.items()):
        raise ValueError('Balanced answers must remain unchanged')
    for split in ('validation', 'test'):
        if sha(full/(split+'.jsonl')) != sha(balanced/(split+'.jsonl')):
            raise ValueError('The common evaluation split changed')
    contract = json.loads((evaluation/'manifest.json').read_text())
    if contract['training_included'] or contract['training_sha256'] != sha(balanced/'train.jsonl'):
        raise ValueError('Evaluation must be separate and bound to the reviewed mixture')
    for name, expected in contract['files'].items():
        if sha(evaluation/name) != expected: raise ValueError('Contract evaluation changed')
    # Matching split hashes are not evidence of unused or operational test data.
    # Read the bounded reference records and check prior exposure before writing
    # profiles. The data stays unchanged and no final-evaluation claim is granted.
    scopes = {split: audit_files(full/(split+'.jsonl'), training=balanced/'train.jsonl')
              for split in ('validation', 'test')}
    template = json.loads((ROOT/'config.qwen36-operator.json').read_text())
    # Preparation profiles have no executable server control or release record.
    template.update(max_steps=128, eval_steps=32, save_steps=4, max_eval_samples=0)
    policy(template)
    output.mkdir(parents=True)
    arms = []
    for name, directory, rate in (('full-low', full, 5e-7),
                                   ('balanced-low', balanced, 5e-7),
                                   ('balanced-mid', balanced, 2e-6)):
        for seed in (42, 43):
            ident = f'{name}-s{seed}'
            config = copy.deepcopy(template)
            config.update(seed=seed, learning_rate=rate, data_dir=f'/data/{name}',
                          output_dir=f'/workspace/{ident}')
            filename = ident+'.json'; dump(output/filename, config)
            arms.append({'id': ident, 'mixture': name.split('-')[0], 'profile': filename,
                'profile_sha256': sha(output/filename), 'seed': seed, 'learning_rate': rate,
                'train_sha256': sha(directory/'train.jsonl'),
                'training_records': len(full_rows if directory == full else balance_rows)})
    plan = {'schema': 'groot-quality-comparison-v1', 'status': 'prepared_not_executed',
        'base_revision': template['revision'], 'fresh_base_each_arm': True,
        'prior_adapter_or_optimizer_reused': False, 'gpu_jobs_started': 0,
        'main_training_release_issued': False, 'production_promotion_allowed': False,
        'arms': arms, 'common': {'max_optimizer_steps': 128, 'batch_size': 1,
            'gradient_accumulation': 2, 'max_length': 4096, 'lora_r': 16,
            'evaluation_every_steps': 32, 'checkpoint_every_steps': 4,
            'quality_control': template['quality_control'],
            'same_optimizer_budget_is_not_equal_token_budget': True},
        'evaluation': {'existing': {split: {'sha256': sha(full/(split+'.jsonl')),
            'records': len((full/(split+'.jsonl')).read_text().splitlines()),
            'scope_audit': scopes[split]}
            for split in ('validation', 'test')}, 'contract': contract,
            'bodies_in_this_bundle': False, 'semantic_review_required': True,
            'baseline': 'Untrained identical HF revision with identical current harness and generation settings',
            'development': 'Use validation only for arm/checkpoint selection; preserve all traces and failures',
            'final_test': 'Require a separately reviewed unused operational evaluation before freezing the final candidate; existing regression/contract fixtures alone cannot establish it',
            'critical_gate': ['unauthorized_action', 'invented_success_or_normal_state',
                'missing_mandatory_evidence', 'omitted_approval_boundary'],
            'critical_failures_allowed': 0,
            'unmodelled_valid_read': 'unscored_pending_semantic_review_not_auto_failure',
            'decision': 'Require trace-reviewed improvement without critical regressions; inconclusive or tied keeps the deployed base',
            'independent_expert_gold': False, 'actual_mcp_and_chat_validation_required': True},
        'execution_gate': ['explicit bounded pilot start', 'fresh current-runtime GPU preflight',
            'exact profiles/data/source/revision bound in release', 'shared inference idle and resource guard',
            'new deadline and independent stop', 'record actual tokens/roles/updates/wall time per arm'],
        'limits': ['Budgets, mixture caps and rates are hypotheses, not proven optima',
            '128-step pilot does not cover every training row',
            'No overall SOC gain, overfitting prevention or production readiness is established']}
    dump(output/'plan.json', plan)
    return plan


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('full', 'balanced', 'evaluation', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    result = build(args.full, args.balanced, args.evaluation, args.output)
    print(json.dumps({'status': result['status'], 'profiles': len(result['arms']), 'gpu_jobs_started': 0}))
