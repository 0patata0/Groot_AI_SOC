"""Score held-out provider mappings through local Ollama; never execute tools."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import time
from urllib import request
from zoneinfo import ZoneInfo
from prepare_evidence_v5 import sha, normalized_name


def api(path, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request('http://127.0.0.1:11434/api/' + path, data=data, headers={'Content-Type': 'application/json'})
    with request.urlopen(req, timeout=120) as response: return json.load(response)


def assess(message, expected):
    text = message.get('content', '')
    try:
        answer = json.loads(text)
        if not isinstance(answer, dict) or not isinstance(answer.get('mappings'), list): raise ValueError()
        mappings = answer['mappings']
        if any(not isinstance(m, dict) or not isinstance(m.get('id'), str) or not isinstance(m.get('name'), str) for m in mappings): raise ValueError()
        predicted = {m['id'] for m in mappings}; valid = len(predicted) == len(mappings)
    except (ValueError, TypeError):
        answer = {}; mappings = []; predicted = set(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text)); valid = False
    gold = {m['id']: m['name'] for m in expected['mappings']}
    matched = predicted & gold.keys(); extra = predicted - gold.keys(); missing = gold.keys() - predicted
    precision = len(matched) / len(predicted) if predicted else 0
    recall = len(matched) / len(gold) if gold else 0
    names = {m['id']: m['name'] for m in mappings}
    names_match = all(normalized_name(names.get(i, '')) == normalized_name(n) for i, n in gold.items())
    scope = answer.get('scope') == 'reported_mapping_only' and answer.get('local_status') == 'not_assessed'
    attribution = answer.get('evidence_ref') == expected['evidence_ref']
    attempted_tool = bool(message.get('tool_calls')) or '<tool_call>' in text
    return {'format_valid': valid, 'precision': precision, 'recall': recall,
            'f1': 2 * precision * recall / (precision + recall) if precision + recall else 0,
            'missing_IDs': sorted(missing), 'unsupported_IDs': sorted(extra),
            'names_match': names_match,
            'scope_preserved': scope, 'evidence_attributed': attribution,
            'attempted_unavailable_tool': attempted_tool,
            'strict_complete': valid and not missing and not extra and names_match and scope and attribution and not attempted_tool}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', type=Path, required=True); p.add_argument('--model', required=True)
    p.add_argument('--plan', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists(): raise ValueError('Use a fresh evaluation report')
    plan = json.loads(a.plan.read_text()); raw = (a.dataset / 'validation.jsonl').read_bytes()
    if sha(raw) != plan['validation_sha256']: raise ValueError('Frozen development input changed')
    rows = {r['id']: r for r in map(json.loads, raw.splitlines())}
    if len(plan['case_ids']) != len(set(plan['case_ids'])): raise ValueError('Duplicate development request')
    tags = {m['name']: m['digest'] for m in api('tags')['models']}
    if a.model not in tags: raise ValueError('Evaluation model missing')
    result = {'status': 'running', 'started_at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
              'model': a.model, 'model_digest': tags[a.model], 'validation_sha256': sha(raw),
              'plan_sha256': sha(a.plan.read_bytes()), 'results': [], 'actual_MCP_tools_executed': False}
    def save():
        temporary = a.output.with_suffix('.tmp'); temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n'); temporary.replace(a.output)
    save()
    loaded = {m['name'] for m in api('ps')['models']}
    try:
        for identifier in plan['case_ids']:
            row = rows[identifier]; tick = time.perf_counter()
            response = api('chat', {'model': a.model, 'messages': row['messages'][:-1], 'stream': False,
                'think': False, 'format': 'json', 'keep_alive': '10m',
                'options': {'temperature': 0, 'seed': 42, 'num_ctx': 8192, 'num_predict': 512}})
            result['results'].append({'case_id': identifier, 'seconds': time.perf_counter() - tick,
                'message': response.get('message', {}), 'done_reason': response.get('done_reason'),
                'timing': {k: response.get(k) for k in ('total_duration', 'load_duration', 'prompt_eval_count', 'prompt_eval_duration', 'eval_count', 'eval_duration')},
                'assessment': assess(response.get('message', {}), json.loads(row['messages'][-1]['content']))})
            save()
        count = len(result['results'])
        result.update(status='completed', summary={'requests': count,
            'strict_complete': sum(r['assessment']['strict_complete'] for r in result['results']),
            'format_valid': sum(r['assessment']['format_valid'] for r in result['results']),
            'macro_f1': sum(r['assessment']['f1'] for r in result['results']) / count,
            'missing_IDs': sum(len(r['assessment']['missing_IDs']) for r in result['results']),
            'unsupported_IDs': sum(len(r['assessment']['unsupported_IDs']) for r in result['results'])})
    except BaseException as e:
        result.update(status='failed', error_type=type(e).__name__); raise
    finally:
        if a.model not in loaded and a.model != 'qwen3.6:35b':
            api('generate', {'model': a.model, 'keep_alive': 0})
        restored = api('generate', {'model': 'qwen3.6:35b', 'keep_alive': '10m'})
        result['original_warm_done'] = restored.get('done') is True
        result['finished_at_kst'] = datetime.now(ZoneInfo('Asia/Seoul')).isoformat(); save()


if __name__ == '__main__': main()
