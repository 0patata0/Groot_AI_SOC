"""Freeze and compare matched V5 CTI models without executing MCP tools.

The historical single-model development scorer remains unchanged. This runner
names the actual split, pins both digests and inputs, and records restoration
separately from evaluation success. Test outputs must not guide retraining.
"""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import time
from zoneinfo import ZoneInfo

from evaluate_evidence_v5 import api, assess
from register_soc import parameters

ORIGINAL = 'qwen3.6:35b'
ORIGINAL_DIGEST = 'a7eb95c53bcf96b4bdd008d0fab4a5dac88047d9c1a7a9ab88ed453423fbd87c'
OPTIONS = {'temperature': 0, 'seed': 42, 'num_ctx': 8192, 'num_predict': 512}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def source_hashes():
    folder = Path(__file__).resolve().parent
    return {n: sha((folder/n).read_bytes()) for n in
            ('evaluate_evidence_pair.py', 'evaluate_evidence_v5.py', 'register_soc.py')}


def read_rows(dataset, split, expected_hash):
    if split not in ('validation', 'test'):
        raise ValueError('Only development validation or untouched test is allowed')
    raw = (Path(dataset)/(split+'.jsonl')).read_bytes()
    if sha(raw) != expected_hash:
        raise ValueError('Frozen evaluation dataset changed')
    rows = [json.loads(line) for line in raw.splitlines()]
    if not rows or len({r['id'] for r in rows}) != len(rows):
        raise ValueError('Empty or duplicate evaluation records')
    for row in rows:
        if row['messages'][-1]['role'] != 'assistant':
            raise ValueError('Expected withheld final reference answer')
        gold = json.loads(row['messages'][-1]['content'])
        if not gold.get('mappings'):
            raise ValueError('Missing original-provider reference mappings')
    return {r['id']: r for r in rows}


def runtime_fingerprint(show):
    return {'template_sha256': sha(show.get('template', '').encode()),
            'system_sha256': sha(show.get('system', '').encode()),
            'parameters': parameters(show.get('parameters', '')),
            'renderer': show.get('renderer'), 'parser': show.get('parser'),
            'requires': show.get('requires'), 'messages': show.get('messages'),
            'quantization': show['details']['quantization_level'],
            'runner': show['details'].get('runner'),
            'capabilities': sorted(show.get('capabilities', []))}


def pin_plan(dataset, frozen, development, registration, split, control, candidate, request=api):
    if control == candidate or ORIGINAL in (control, candidate):
        raise ValueError('Use distinct same-HF control and candidate, not the registry original')
    rows = read_rows(dataset, split, frozen['data_sha256'][split])
    if development['validation_sha256'] != frozen['data_sha256']['validation']:
        raise ValueError('Development selection belongs to another dataset')
    ids = list(development['case_ids']) if split == 'validation' else list(rows)
    if not ids or len(ids) != len(set(ids)) or not set(ids) <= rows.keys():
        raise ValueError('Invalid frozen case selection')
    if split == 'test' and len(ids) != frozen['records']['test']:
        raise ValueError('Full untouched test split required')
    tags = {m['name']: m['digest'] for m in request('tags')['models']}
    if tags.get(ORIGINAL) != ORIGINAL_DIGEST:
        raise ValueError('Original operational model changed')
    if tags.get(control) != frozen['HF_control_digest'] or candidate not in tags:
        raise ValueError('Expected HF control and registered candidate required')
    coverage = registration.get('training_coverage', {})
    if (registration.get('status') != 'completed' or registration.get('variant') != 'v5'
            or registration.get('model') != candidate or registration.get('digest') != tags[candidate]
            or coverage.get('status') != 'passed' or coverage.get('steps') != 512
            or coverage.get('distinct_observations') != 1024):
        raise ValueError('Verified full-epoch V5 registration receipt required')
    runtimes = {name: runtime_fingerprint(request('show', {'model': name}))
                for name in (control, candidate)}
    if runtimes[control] != runtimes[candidate] or runtimes[control]['quantization'] != 'Q4_K_M':
        raise ValueError('Control/candidate runtime mismatch')
    return {'schema': 1, 'created_at_kst': now(), 'split': split,
            'dataset_sha256': frozen['data_sha256'][split], 'case_ids': ids,
            'models': {'control': {'name': control, 'digest': tags[control]},
                       'candidate': {'name': candidate, 'digest': tags[candidate]}},
            'runtime': runtimes[control], 'options': OPTIONS,
            'candidate_registration': registration,
            'source_sha256': source_hashes(), 'arm_order': ['control', 'candidate'],
            'scope': 'source-reported CTI mapping; not full SOC competence or live MCP',
            'holdout_policy': 'Do not use final test responses for tuning or checkpoint selection',
            'wall_limit_seconds': 3600}


def persist(path, value):
    temporary = Path(path).with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')
    temporary.replace(path)


def summarize(rows):
    return {'requests': len(rows),
            'strict_complete': sum(r['assessment']['strict_complete'] for r in rows),
            'format_valid': sum(r['assessment']['format_valid'] for r in rows),
            'macro_f1': sum(r['assessment']['f1'] for r in rows)/len(rows),
            'missing_IDs': sum(len(r['assessment']['missing_IDs']) for r in rows),
            'unsupported_IDs': sum(len(r['assessment']['unsupported_IDs']) for r in rows)}


def run_pair(dataset, plan_path, output, request=api, clock=time.monotonic):
    output = Path(output)
    if output.exists():
        raise ValueError('Use a fresh report; previous evidence must not be overwritten')
    plan_raw = Path(plan_path).read_bytes(); plan = json.loads(plan_raw)
    if set(plan['models']) != {'control', 'candidate'}:
        raise ValueError('Exactly two comparison arms required')
    names = [m['name'] for m in plan['models'].values()]
    if len(set(names)) != 2 or ORIGINAL in names:
        raise ValueError('Distinct non-operational comparison models required')
    if plan['source_sha256'] != source_hashes() or plan['options'] != OPTIONS:
        raise ValueError('Frozen scorer or decoding options changed')
    if plan['arm_order'] != ['control', 'candidate'] or not 1 <= plan['wall_limit_seconds'] <= 3600:
        raise ValueError('Unexpected comparison execution bounds')
    rows = read_rows(dataset, plan['split'], plan['dataset_sha256'])
    ids = plan['case_ids']
    if not ids or len(ids) != len(set(ids)) or not set(ids) <= rows.keys():
        raise ValueError('Invalid frozen evaluation cases')
    if plan['split'] == 'test' and set(ids) != rows.keys():
        raise ValueError('Test comparison must cover every held-out case')
    tags = {m['name']: m['digest'] for m in request('tags')['models']}
    if tags.get(ORIGINAL) != ORIGINAL_DIGEST:
        raise ValueError('Original model digest differs')
    for model in plan['models'].values():
        if tags.get(model['name']) != model['digest']:
            raise ValueError('Pinned evaluation model digest differs')
        if runtime_fingerprint(request('show', {'model': model['name']})) != plan['runtime']:
            raise ValueError('Pinned runtime changed')
    before = {m['name']: m for m in request('ps')['models']}
    original_context = before.get(ORIGINAL, {}).get('context_length', 8192)
    result = {'status': 'running', 'started_at_kst': now(), 'split': plan['split'],
              'plan_sha256': sha(plan_raw), 'dataset_sha256': plan['dataset_sha256'],
              'models': plan['models'], 'arms': {},
              'original_ps_before': ({k: before[ORIGINAL].get(k) for k in
                                     ('name', 'digest', 'context_length', 'size')}
                                    if ORIGINAL in before else None),
              'actual_MCP_tools_executed': False, 'operational_model_changed': False,
              'latency_scope': 'sequential arm blocks on shared inference; no isolated-load claim'}
    with output.open('x') as handle:
        handle.write(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    started = clock(); attempted = set()
    try:
        for arm in plan['arm_order']:
            model = plan['models'][arm]['name']; attempted.add(model)
            entry = result['arms'][arm] = {'model': model, 'results': []}
            warm = request('generate', {'model': model, 'prompt': 'OK', 'raw': True,
                           'think': False, 'stream': False, 'keep_alive': '10m',
                           'options': {**OPTIONS, 'num_predict': 1}})
            if not warm.get('done') or warm.get('model') != model or warm.get('eval_count', 0) < 1:
                raise RuntimeError('Evaluation warm-up failed')
            entry['warmup_completed'] = True
            for identifier in ids:
                if clock()-started >= plan['wall_limit_seconds']:
                    raise TimeoutError('Comparison wall limit reached')
                row = rows[identifier]; tick = clock()
                response = request('chat', {'model': model, 'messages': row['messages'][:-1],
                    'stream': False, 'think': False, 'format': 'json', 'keep_alive': '10m',
                    'options': dict(OPTIONS)})
                if response.get('done') is not True or response.get('model') != model:
                    raise RuntimeError('Incomplete or wrong-model inference result')
                assessment = assess(response.get('message', {}), json.loads(row['messages'][-1]['content']))
                if response.get('done_reason') == 'length':
                    assessment['strict_complete'] = False
                entry['results'].append({'case_id': identifier, 'seconds': clock()-tick,
                    'message': response.get('message', {}), 'done_reason': response.get('done_reason'),
                    'timing': {k: response.get(k) for k in ('total_duration', 'load_duration',
                        'prompt_eval_count', 'prompt_eval_duration', 'eval_count', 'eval_duration')},
                    'assessment': assessment})
                persist(output, result)
            entry['summary'] = summarize(entry['results']); persist(output, result)
        result['status'] = 'completed'
    except BaseException as exc:
        result.update(status='failed', error_type=type(exc).__name__)
        raise
    finally:
        restore = {'status': 'checking', 'errors': []}
        # Only unload evaluation models introduced by this invocation.
        for model in sorted(attempted - before.keys()):
            try:
                request('generate', {'model': model, 'keep_alive': 0})
            except Exception as exc:
                restore['errors'].append({'phase': 'unload', 'error_type': type(exc).__name__})
        try:
            current = {m['name']: m for m in request('ps')['models']}
            ctx = current.get(ORIGINAL, {}).get('context_length', original_context)
            if type(ctx) is not int or not 512 <= ctx <= 1048576:
                raise ValueError('Invalid original runtime context')
            answer = request('generate', {'model': ORIGINAL, 'prompt': 'OK', 'raw': True,
                'think': False, 'stream': False, 'keep_alive': '10m',
                'options': {'num_ctx': ctx, 'num_predict': 1, 'temperature': 0}})
            after = {m['name']: m['digest'] for m in request('tags')['models']}
            if after != tags or not answer.get('done') or answer.get('model') != ORIGINAL or answer.get('eval_count', 0) < 1:
                raise RuntimeError('Original generation or registry restoration not verified')
            restore.update(status='verified', context_length=ctx, registry_unchanged=True,
                           original_generation_verified=True)
        except Exception as exc:
            restore.update(status='failed', error_type=type(exc).__name__)
        result.update(restoration=restore, finished_at_kst=now()); persist(output, result)
    if result['restoration']['status'] != 'verified' or result['restoration']['errors']:
        raise RuntimeError('Comparison finished but restoration needs review')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('plan', 'run')); p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--plan', type=Path, required=True); p.add_argument('--output', type=Path)
    p.add_argument('--frozen', type=Path); p.add_argument('--development', type=Path)
    p.add_argument('--registration', type=Path)
    p.add_argument('--split', choices=('validation', 'test')); p.add_argument('--control'); p.add_argument('--candidate')
    a = p.parse_args()
    if a.action == 'plan':
        if a.plan.exists() or not all((a.frozen, a.development, a.registration, a.split, a.control, a.candidate)):
            p.error('Fresh plan and all pinning inputs required')
        frozen = json.loads(a.frozen.read_text())
        if sha(a.development.read_bytes()) != frozen['development_plan_sha256']:
            p.error('Original development selection hash changed')
        result = pin_plan(a.dataset, frozen, json.loads(a.development.read_text()),
                          json.loads(a.registration.read_text()), a.split, a.control, a.candidate)
        with a.plan.open('x') as handle:
            handle.write(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    else:
        if a.output is None:
            p.error('--output is required')
        result = run_pair(a.dataset, a.plan, a.output)
    print(json.dumps({'status': result.get('status', 'plan_prepared'), 'split': result['split']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
