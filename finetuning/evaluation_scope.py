"""Audit evaluation reuse and workflow coverage without running a model.

An unused byte sequence is not proof of independent incidents, expert gold,
pretraining separation or operational quality. This module never grants any of
those claims, admits training data, executes tools or changes a served model.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from prepare_operator_release import input_identity

ROOT = Path(__file__).resolve().parent
REGISTRY = ROOT / 'EVALUATION_USAGE.json'
HEX = re.compile(r'[0-9a-f]{64}\Z')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_jsonl(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('Evaluation input must be a bounded regular file')
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def fingerprints(row):
    messages = row.get('messages') if isinstance(row, dict) else None
    if (not isinstance(messages, list) or len(messages) < 2
            or any(not isinstance(m, dict) or m.get('role') not in
                   ('system', 'developer', 'user', 'assistant', 'tool') for m in messages)
            or messages[-1]['role'] != 'assistant'
            or not any(m['role'] == 'user' for m in messages)):
        raise ValueError('Evaluation requires a complete referenced conversation')
    for message in messages:
        if message['role'] == 'user':
            content = message.get('content')
            if not isinstance(content, (str, list)) or not content:
                raise ValueError('Evaluation requires a nonempty user input')
    reference = messages[-1]
    if not reference.get('content') and not reference.get('tool_calls'):
        raise ValueError('Evaluation requires a nonempty assistant reference')
    tools = row.get('tools', [])
    if not isinstance(tools, list):
        raise ValueError('Evaluation tool definitions must be a list')
    return {
        'record_sha256': digest(canonical(row)),
        'visible_input_sha256': digest(canonical({'messages': messages[:-1], 'tools': tools})),
        # Reuse the training preparation identity. This ignores system/assistant
        # messages and is a potential-overlap signal, not exact prompt equality.
        'nonassistant_input_sha256': input_identity(row),
    }


def usage_sets(registry):
    if not isinstance(registry, dict) or registry.get('schema') != 'groot-evaluation-usage-v1':
        raise ValueError('Unknown evaluation usage registry')
    keys = ('record_sha256', 'visible_input_sha256', 'nonassistant_input_sha256')
    result = {k: set() for k in keys}
    entries = registry.get('consumed')
    if not isinstance(entries, list):
        raise ValueError('Missing evaluation usage entries')
    for entry in entries:
        rows = entry.get('fingerprints') if isinstance(entry, dict) else None
        if (not isinstance(rows, list) or type(entry.get('records')) is not int
                or entry['records'] != len(rows) or not isinstance(entry.get('data_sha256'), str)
                or not HEX.fullmatch(entry['data_sha256'])
                or not entry.get('evidence') or entry.get('status') != 'consumed'):
            raise ValueError('Invalid evaluation usage entry')
        for key in keys:
            values = [row.get(key) if isinstance(row, dict) else None for row in rows]
            if (any(not isinstance(v, str) or not HEX.fullmatch(v) for v in values)
                    or (key == 'record_sha256' and len(set(values)) != len(values))):
                raise ValueError('Invalid or duplicate evaluation fingerprints')
            result[key].update(values)
    return result


def audit_rows(rows, registry, training_rows=()):
    if not rows:
        raise ValueError('Empty evaluation cannot establish coverage')
    used = usage_sets(registry)
    ids = [fingerprints(r) for r in rows]
    train = [fingerprints(r) for r in training_rows]
    train_used = {key: {r[key] for r in train} for key in used}
    counts = {}
    for key in used:
        counts['known_consumed_' + key.removesuffix('_sha256')] = sum(r[key] in used[key] for r in ids)
        counts['training_overlap_' + key.removesuffix('_sha256')] = sum(r[key] in train_used[key] for r in ids)
    definitions = sum(bool(r.get('tools') or r.get('tool_names')) for r in rows)
    observations = sum(any(m['role'] == 'tool' for m in r['messages']) for r in rows)
    calls = sum(any(m['role'] == 'assistant' and m.get('tool_calls') for m in r['messages']) for r in rows)
    reasons = []
    if counts['known_consumed_visible_input'] or counts['known_consumed_record']:
        reasons.append('Previously consumed evaluation records or visible inputs')
    if counts['known_consumed_nonassistant_input']:
        reasons.append('Previously consumed nonassistant inputs; inspect context and source-family reuse')
    if counts['training_overlap_nonassistant_input']:
        reasons.append('Training input overlap; inspect source and context')
    if not calls or not observations:
        reasons.append('No observed tool workflow coverage')
    reasons.append('Source/incident independence, expert correctness and actual MCP/chat execution are not established by fingerprints')
    return {
        'records': len(rows), 'tool_definition_rows': definitions,
        'tool_observation_rows': observations, 'assistant_tool_call_rows': calls,
        'sources': dict(Counter(str((r.get('provenance') if isinstance(r.get('provenance'), dict) else {}).get('source')
                                  or r.get('source') or r.get('dataset_version')) for r in rows)),
        **counts,
        'allowed_use': 'development_regression_only' if any(counts.values()) or not calls or not observations
                       else 'unverified_evaluation_candidate_only',
        'independent_operational_quality_proven': False,
        'promotion_evidence_allowed_by_this_audit': False,
        'limits': reasons,
    }


def audit_files(cases, registry=REGISTRY, training=None):
    path = Path(registry)
    result = audit_rows(read_jsonl(cases), json.loads(path.read_text()),
                        read_jsonl(training) if training else ())
    return {'data_sha256': digest(Path(cases).read_bytes()),
            'usage_registry_sha256': digest(path.read_bytes()), **result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--training', type=Path)
    parser.add_argument('--registry', type=Path, default=REGISTRY)
    args = parser.parse_args()
    print(json.dumps(audit_files(args.cases, args.registry, args.training), ensure_ascii=False, indent=2))
