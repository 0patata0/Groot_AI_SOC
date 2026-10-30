"""Audit pinned CAM-LDS query coverage, repeats and visible technique identifiers.

No upstream code/model execution, prompt modification, dataset split or admission.
The supplied technique labels describe the testbed execution, not SOC action gold.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
TECHNIQUE = re.compile(r'T\d{4}(?:\.\d{3})?')
VISIBLE = re.compile(r'(?<![A-Za-z0-9])T\d{4}(?:\.\d{3})?(?![A-Za-z0-9.])')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, 'Duplicate JSON field')
        obj[key] = value
    return obj


def parse(text):
    return json.loads(text, object_pairs_hook=unique_object)


def parent(identifier):
    return identifier.split('.')[0]


def label_ids(label):
    ids = set(label['metadata'])
    require(ids and all(TECHNIQUE.fullmatch(x) for x in ids), 'Invalid label technique')
    return ids


def visible_annotations(prompt):
    """Distinguish literal-ID flags from parsed detector/audit annotation fields."""
    literal = set(VISIBLE.findall(prompt))
    paths = Counter()
    structured = set()
    allowed = {('rule', 'mitre', 'id'), ('data', 'alert', 'metadata', 'mitre_technique_id'),
               ('data', 'audit', 'key')}
    for line in prompt.splitlines():
        try:
            event = parse(line.strip())
        except (ValueError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        for path in sorted(allowed):
            value = event
            for key in path:
                value = value.get(key) if isinstance(value, dict) else None
            values = value if isinstance(value, list) else [value]
            ids = {s for s in values if isinstance(s, str) and TECHNIQUE.fullmatch(s)}
            if ids:
                paths['.'.join(path)] += 1
                structured.update(ids)
    return literal, structured, dict(paths)


def audit(queries, labels):
    require(isinstance(labels, dict) and labels and queries, 'Empty source')
    all_ids = set()
    for key, value in labels.items():
        require(key == value['scenario_variant'] + '-' + str(value['event_id']), 'Label identity mismatch')
        all_ids.update(label_ids(value))
    queried_ids = set()
    groups = defaultdict(list)
    repeated = defaultdict(list)
    visible = []
    for number, row in enumerate(queries, 1):
        require(set(row) == {'scenario', 'variant', 'step', 'prompt', 'ground_truth'}, 'Unreviewed query shape')
        require(all(isinstance(row[k], str) for k in ('scenario', 'variant', 'step', 'prompt')),
                'Unexpected query field type')
        require(re.fullmatch(r'[1-9]\d*', row['scenario']) and re.fullmatch(r'[1-9]\d*', row['step'])
                and re.fullmatch(r'[a-z0-9_]*', row['variant']) and row['prompt'], 'Invalid query identity')
        key = row['scenario'] + ('_' + row['variant'] if row['variant'] else '') + '-' + row['step']
        gold = row['ground_truth']
        require(isinstance(gold, list) and all(isinstance(x, str) for x in gold)
                and len(set(gold)) == len(gold), 'Repeated or invalid query labels')
        require(key in labels and set(gold) == label_ids(labels[key]), 'Query/label mismatch')
        queried_ids.update(gold)
        step = row['scenario'] + '-' + row['step']
        digest = hashlib.sha256(row['prompt'].encode()).hexdigest()
        record = {'line': number, 'scenario_step': step, 'variant': row['variant'],
                  'prompt_sha256': digest, 'label_key': key}
        groups[step].append(record)
        repeated[digest].append({**record, 'labels': sorted(gold)})
        literals, structured, paths = visible_annotations(row['prompt'])
        if literals:
            visible.append({**record, 'literal_ids': sorted(literals),
                            'literal_exact_gold_overlap': sorted(literals & set(gold)),
                            'literal_parent_gold_overlap': sorted({parent(x) for x in literals} & {parent(x) for x in gold}),
                            'parsed_annotation_ids': sorted(structured), 'parsed_annotation_line_counts': paths,
                            'parsed_exact_gold_overlap': sorted(structured & set(gold)),
                            'parsed_parent_gold_overlap': sorted({parent(x) for x in structured} & {parent(x) for x in gold})})
    omitted = all_ids - queried_ids
    return {'label_records': len(labels), 'query_records': len(queries),
            'all_label_ids': sorted(all_ids), 'all_label_parent_ids': sorted({parent(x) for x in all_ids}),
            'query_ids': sorted(queried_ids), 'query_parent_ids': sorted({parent(x) for x in queried_ids}),
            'unqueried_ids': sorted(omitted),
            'unqueried_id_label_keys': {x: sorted(k for k, v in labels.items() if x in v['metadata']) for x in sorted(omitted)},
            'scenario_steps': len(groups), 'unique_prompts': len(repeated),
            'step_repetition_counts': dict(Counter(len(v) for v in groups.values())),
            'steps_with_identical_all_repetitions': sum(len({r['prompt_sha256'] for r in v}) == 1 for v in groups.values()),
            'cross_step_identical_prompt_groups': sum(len({r['scenario_step'] for r in v}) > 1 for v in repeated.values()),
            'identical_prompt_conflicting_label_groups': sum(len({tuple(r['labels']) for r in v}) > 1 for v in repeated.values()),
            'visible_literal_id_queries': len(visible),
            'visible_literal_exact_gold_queries': sum(bool(r['literal_exact_gold_overlap']) for r in visible),
            'visible_literal_parent_gold_queries': sum(bool(r['literal_parent_gold_overlap']) for r in visible),
            'parsed_annotation_id_queries': sum(bool(r['parsed_annotation_ids']) for r in visible),
            'parsed_annotation_exact_gold_queries': sum(bool(r['parsed_exact_gold_overlap']) for r in visible),
            'parsed_annotation_parent_gold_queries': sum(bool(r['parsed_parent_gold_overlap']) for r in visible),
            'unique_prompt_identifier_counts': {
                key: len({r['prompt_sha256'] for r in visible if r[key]})
                for key in ('literal_ids', 'literal_exact_gold_overlap', 'literal_parent_gold_overlap',
                            'parsed_annotation_ids', 'parsed_exact_gold_overlap', 'parsed_parent_gold_overlap')},
            'visible_identifier_coordinates': visible,
            'scenario_step_groups': dict(sorted(groups.items())),
            'training_admitted': 0, 'new_final_evaluation_records': 0,
            'limits': ['Literal technique IDs are review flags, not proof that every occurrence is an answer label.',
                       'Parsed detector/audit annotations are pre-existing sensor judgments, not label-free log inference.',
                       'Source labels are attack-step metadata, not a verdict that every selected log is malicious.',
                       'Same step/repetition/variant must not be randomly split across train and evaluation.',
                       'Zero identical prompts across steps does not prove episode/source independence.',
                       'No original log removal, new operator answer, tokenizer or model execution.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'Output already exists')
    source = json.loads((ROOT / 'SOC_EXTRA_CORPORA_REVIEW.json').read_text())['candidates'][0]
    require(source['id'] == 'cam_lds', 'Source registry changed')
    specs = {s['file']: s for s in source['repository']['selected_files']}
    blobs = {}
    for name in ('labels.json', 'llm_queries.json'):
        path = args.directory / name
        require(path.stat().st_size <= 10_000_000, 'Source byte budget exceeded')
        raw = path.read_bytes()
        require(len(raw) == specs[name]['bytes'] and hashlib.sha256(raw).hexdigest() == specs[name]['sha256'],
                'Pinned source mismatch')
        blobs[name] = raw
    result = audit([parse(x) for x in blobs['llm_queries.json'].splitlines()], parse(blobs['labels.json']))
    result.update(checked_at_kst=datetime.now(timezone(timedelta(hours=9))).isoformat(),
                  source_commit=source['repository']['commit'],
                  source_sha256={name: hashlib.sha256(raw).hexdigest() for name, raw in blobs.items()},
                  checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if not isinstance(v, (dict, list))}))


if __name__ == '__main__':
    main()
