"""Select an auditable operator-focused pilot mixture locally, without new answers.

Caps are experimental budgets, not a proven optimal distribution. All admitted
MCP trajectories and less abundant sources are retained byte-for-byte. Excluded
rows remain in the parent archive. No model, tool or remote service is invoked.
"""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
from zoneinfo import ZoneInfo

from audit_tools import audit_rows
from prepare_operator_release import input_identity, private_observations

POLICY = {'version': 'operator-balance-20261107-r1', 'crs_per_family': 8,
          'wazuh_per_family': 4, 'guide_per_label': 96, 'guide_per_organization': 1,
          'rule_supervised_token_share_max': 0.5,
          'selection_order': 'sha256(record ID), round-robin provider oracle within family',
          'answers_rewritten': False, 'oversampling': False}
DOMINANT = {'crs', 'wazuh', 'microsoft-guide-v2-retrospective-triage'}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def sha(value):
    return hashlib.sha256(value).hexdigest()


def read_rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line]


def write_rows(path, rows):
    Path(path).write_text(''.join(canonical(row)+'\n' for row in rows))


def family(row):
    p = row.get('provenance', {})
    return p.get('split_group') or p.get('scenario_group') or p.get('group') or p.get('base_incident')


def selection(rows, policy=POLICY):
    selected = {r['id'] for r in rows if r['source'] not in DOMINANT}
    for source in ('crs', 'wazuh'):
        groups = defaultdict(lambda: defaultdict(list))
        for row in rows:
            if row['source'] != source:
                continue
            if not family(row) or not row['provenance'].get('provider_target'):
                raise ValueError('Provider family and exact oracle are required')
            groups[family(row)][canonical(row['provenance']['provider_target'])].append(row)
        for oracles in groups.values():
            queues = [deque(sorted(items, key=lambda r: sha(r['id'].encode())))
                      for _, items in sorted(oracles.items(), key=lambda pair: sha(pair[0].encode()))]
            count = 0
            while any(queues) and count < policy[source+'_per_family']:
                for queue in queues:
                    if queue and count < policy[source+'_per_family']:
                        selected.add(queue.popleft()['id']); count += 1
    labels = defaultdict(list)
    for row in rows:
        if row['source'] != 'microsoft-guide-v2-retrospective-triage':
            continue
        label = json.loads(row['messages'][-1]['content'])['classification']
        if label not in ('TruePositive', 'FalsePositive', 'BenignPositive') or not family(row):
            raise ValueError('Unregistered GUIDE label/organization')
        labels[label].append(row)
    queues = {k: deque(sorted(v, key=lambda r: sha(r['id'].encode()))) for k, v in labels.items()}
    used = Counter(); label_counts = Counter()
    while any(queues.values()):
        progressed = False
        for label in sorted(queues):
            q = queues[label]
            while q and label_counts[label] < policy['guide_per_label']:
                row = q.popleft()
                if used[family(row)] >= policy['guide_per_organization']:
                    continue
                selected.add(row['id']); used[family(row)] += 1; label_counts[label] += 1
                progressed = True
                break
            if label_counts[label] >= policy['guide_per_label']:
                q.clear()
        if not progressed and not any(queues.values()):
            break
    return [r for r in rows if r['id'] in selected]


def metrics(rows, tokens):
    counts = Counter(); inputs = Counter(); targets = Counter(); calls = full = 0
    groups = defaultdict(set)
    for row in rows:
        record = tokens[('train', row['id'])]
        source = row['source']; counts[source] += 1
        inputs[source] += record['tokens']; targets[source] += record['supervised_tokens']
        if family(row): groups[source].add(family(row))
        calls += any(m.get('tool_calls') for m in row['messages'])
        full += any(m['role'] == 'tool' for m in row['messages'])
    return {'rows': len(rows), 'source_rows': dict(counts), 'input_tokens': dict(inputs),
            'supervised_tokens': dict(targets), 'total_supervised_tokens': sum(targets.values()),
            'rule_supervised_token_share': (targets['crs']+targets['wazuh'])/sum(targets.values()),
            'tool_call_dialogues': calls, 'complete_tool_dialogues': full,
            'source_family_counts': {k: len(v) for k, v in groups.items()}}


def build(parent, output):
    parent, output = Path(parent), Path(output)
    if output.exists() or not output.name.startswith('data-'):
        raise ValueError('Require a fresh data-* directory')
    admission = json.loads((parent/'admission.json').read_text())
    if admission['status'] != 'source_and_token_verified_waiting_final_review_and_gpu_smoke':
        raise ValueError('Parent is not source/token admitted')
    for rel, digest in admission['files'].items():
        if sha((parent/rel).read_bytes()) != digest: raise ValueError('Parent input changed')
    token_bytes = (parent/'token-review.json').read_bytes()
    if sha(token_bytes) != admission['token_receipt_sha256']:
        raise ValueError('Parent token receipt changed')
    receipt = json.loads(token_bytes)
    tokens = {(r['split'], r['id']): r for r in receipt['records']}
    full = read_rows(parent/'train.jsonl'); chosen = selection(full)
    evaluations = {s: read_rows(parent/(s+'.jsonl')) for s in ('validation', 'test')}
    eval_rows = [r for rs in evaluations.values() for r in rs]
    eval_inputs = {input_identity(r) for r in eval_rows}; eval_ids = {r['id'] for r in eval_rows}
    eval_families = {(r['source'], family(r)) for r in eval_rows if family(r)}
    ids = set(); identities = set()
    for row in full:
        identity = input_identity(row)
        if row['id'] in ids or identity in identities or row['id'] in eval_ids or identity in eval_inputs:
            raise ValueError('Duplicate/evaluation-overlapping input')
        if family(row) and (row['source'], family(row)) in eval_families:
            raise ValueError('Source-family overlap with held-out evaluation')
        if private_observations(row): raise ValueError('Credential marker')
        ids.add(row['id']); identities.add(identity)
    for row in chosen:
        record = tokens['train', row['id']]
        if record['reason'] is not None or record['mask_verified'] is not True:
            raise ValueError('Selected row lacks a verified token/loss mask')
    before, after = metrics(full, tokens), metrics(chosen, tokens)
    if after['rule_supervised_token_share'] > POLICY['rule_supervised_token_share_max']:
        raise ValueError('Rule answer tokens still dominate this candidate')
    for key in ('tool_call_dialogues', 'complete_tool_dialogues'):
        if after[key] != before[key]: raise ValueError('Tool workflow was lost')
    registry = json.loads((parent/'mcp-contract.json').read_text())
    audit = audit_rows(chosen, registry)
    if audit['counts'].get('calls') != audit['counts'].get('schema_valid_calls'):
        raise ValueError('Invalid tool contract')
    output.mkdir(parents=True)
    write_rows(output/'train.jsonl', chosen)
    shutil.copytree(parent/'licenses', output/'licenses')
    for name in ('validation.jsonl', 'test.jsonl', 'mcp-contract.json'):
        shutil.copyfile(parent/name, output/name)
    (output/'held-token.jsonl').write_text('')
    selected_ids = {r['id'] for r in chosen}
    write_rows(output/'selection.jsonl', [{'id': r['id'], 'source': r['source'], 'family': family(r),
        'row_sha256': sha(canonical(r).encode()), 'selected': r['id'] in selected_ids,
        'reason': 'retained_exact_parent_row' if r['id'] in selected_ids else 'source_family_or_label_budget_only'} for r in full])
    token_inputs = [{'split': s, 'row': row} for s, rs in [('train', chosen), *evaluations.items()] for row in rs]
    write_rows(output/'token-input.jsonl', token_inputs)
    selected_token_records = [tokens[r['split'], r['row']['id']] for r in token_inputs]
    derived = {**receipt, 'input_sha256': sha((output/'token-input.jsonl').read_bytes()),
        'records': selected_token_records, 'derivation': 'exact unchanged record subset of parent DGX CPU token/mask receipt',
        'parent_receipt_sha256': sha(token_bytes), 'fresh_dgx_recheck_completed': False}
    (output/'token-review.json').write_text(json.dumps(derived, ensure_ascii=False, indent=2)+'\n')
    report = {'schema': 'groot-operator-balance-v1', 'at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
        'policy': POLICY, 'parent_train_sha256': admission['files']['train.jsonl'],
        'parent_token_receipt_sha256': sha(token_bytes), 'before': before, 'after': after,
        'schema_audit': audit, 'unchanged_evaluation': {s: sha((output/(s+'.jsonl')).read_bytes()) for s in evaluations},
        'ready_for_gpu_training': False, 'quality_improvement_proven': False,
        'independent_expert_review': False, 'new_answers_created': 0,
            'remaining_gaps': ['Complete tool dialogues remain 35: 11 historical live reads and 24 isolated executor fixtures; selection does not manufacture experience.',
            'Existing validation/test contain no tool workflows; separate contract/semantic evaluation is required.',
            'Source caps are experimental, not an empirically optimal mix.',
            'Unmodelled reasonable read branches must be unscored rather than marked wrong.',
            'Source-family checks do not prove absence of all semantic overlap.']}
    (output/'balance-review.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    composition = {'status': 'exact_parent_subset_waiting_runtime_recheck', 'candidate_rows': len(chosen),
        'source_counts': after['source_rows'], 'schema_audit': audit,
        'validation_rows': len(evaluations['validation']), 'test_rows': len(evaluations['test']),
        'token_input_sha256': sha((output/'token-input.jsonl').read_bytes()),
        'files': {str(p.relative_to(output)): sha(p.read_bytes()) for p in output.rglob('*') if p.is_file()}}
    (output/'composition.json').write_text(json.dumps(composition, ensure_ascii=False, indent=2)+'\n')
    final = {**admission, 'at_kst': report['at_kst'], 'parent_admission_sha256': sha((parent/'admission.json').read_bytes()),
        'train_rows': len(chosen), 'source_counts': after['source_rows'],
        'max_tokens': max(tokens['train', r['id']]['tokens'] for r in chosen),
        'total_tokens': sum(after['input_tokens'].values()),
        'token_receipt_sha256': sha((output/'token-review.json').read_bytes()),
        'token_evidence_kind': 'verified unchanged parent subset; fresh DGX recheck pending',
        'files': {name: sha((output/name).read_bytes()) for name in ('train.jsonl', 'validation.jsonl', 'test.jsonl', 'held-token.jsonl')}}
    (output/'admission.json').write_text(json.dumps(final, ensure_ascii=False, indent=2)+'\n')
    manifest = {'outputs': {s: {'records': len(chosen) if s == 'train' else len(evaluations[s]),
        'sha256': sha((output/(s+'.jsonl')).read_bytes())} for s in ('train', 'validation', 'test')}, 'truncation': False}
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.parent, args.output), ensure_ascii=False, indent=2))
