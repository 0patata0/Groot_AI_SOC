"""Audit incident families, answer leakage, evidence links and recorded tool outcomes.

All outputs remain source candidates. A textual answer hit is not a validated
causal investigation; a completed tool part is not proof of successful response.
"""
import argparse
from collections import Counter, defaultdict
import csv
from itertools import combinations
import json
from pathlib import Path
import re
import yaml
from collect_defensive_sources import now, sha, verify_blob, write
from review_defensive_sources import canonical, history_review
from collect_excytin_evidence import csv_records

LABEL_FIELDS = {'AttackTechnique', 'AttackTechniques', 'Techniques', 'SubTechniques'}
RESERVED = {'134', '166'}


def norm(value): return ' '.join(str(value).split()).casefold()


def target_present(target, text, *, normalized_text=False):
    target = norm(target)
    if not normalized_text: text = norm(text)
    if len(target) < 4: return False
    if re.fullmatch(r'[0-9.]+', target) or '@' in target and ' ' not in target:
        return re.search(r'(?<![a-z0-9_.@-])'+re.escape(target)+r'(?![a-z0-9_.@-])', text) is not None
    return target in text


def capture_label(value):
    value = norm(value)
    match = re.fullmatch(r'(attack (?:[1-9]|10|11))(?: detected)?', value)
    return match.group(1) if match else value


def incident_id(path):
    match = re.search(r'(?:^|/)incident_(\d+)(?:/|_)', path)
    if not match:
        match = re.search(r'/saber_sim_incident_(\d+)_v\d+/', path)
    if not match: raise ValueError('Unresolved incident family')
    return match.group(1)


def partition(incident, provider_split):
    if incident in RESERVED: return 'reserved_evaluation_family'
    return 'training_source_candidate' if provider_split == 'train' else 'provider_test_excluded_from_training'


def incident_components(alert_ids):
    parent = {key:key for key in alert_ids}
    def find(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]; key = parent[key]
        return key
    for a,b in combinations(sorted(alert_ids),2):
        if alert_ids[a] & alert_ids[b]: parent[find(b)] = find(a)
    groups = defaultdict(list)
    for key in sorted(parent): groups[find(key)].append(key)
    return sorted(groups.values())


def separate_labels(value):
    """Keep provider-derived ATT&CK labels out of the observable input."""
    removed = []
    def clean(x, prefix=''):
        if isinstance(x, dict):
            result = {}
            for k, v in x.items():
                if k in LABEL_FIELDS: removed.append({'field': prefix+k, 'value': v})
                else: result[k] = clean(v, prefix+k+'.')
            return result
        if isinstance(x, list): return [clean(v, prefix+str(i)+'.') for i, v in enumerate(x)]
        return x
    return clean(value), removed


def trace_stats(value):
    tools, ids, reasons = [], [], []
    for message in value.get('messages', []):
        for part in message.get('parts', []):
            if part.get('type') != 'tool': continue
            state = part.get('state', {})
            ids.append(part.get('callID'))
            metadata = state.get('metadata', {})
            exit_code = metadata.get('exit', metadata.get('exitCode', metadata.get('exit_code')))
            tools.append({'tool': part.get('tool'), 'status': state.get('status'),
                          'has_input': isinstance(state.get('input'), dict),
                          'has_output': 'output' in state, 'exit_code': exit_code,
                          'explicit_error': bool(state.get('error'))})
    if any(not x for x in ids) or len(ids) != len(set(ids)): reasons.append('missing_or_duplicate_call_id')
    return {'tool_calls': len(tools), 'tools': dict(Counter(x['tool'] for x in tools)),
            'states': dict(Counter(x['status'] for x in tools)),
            'input_output_pairs': sum(x['has_input'] and x['has_output'] for x in tools),
            'explicit_errors': sum(x['explicit_error'] or x['status']=='error' for x in tools),
            'nonzero_exit': sum(x['exit_code'] not in (None, 0, '0') for x in tools),
            'unknown_exit': sum(x['exit_code'] is None for x in tools), 'issues': reasons}


def write_jsonl(path, rows):
    path.write_text(''.join(json.dumps(x, ensure_ascii=False)+'\n' for x in rows))


def quarantine_observable_duplicates(rows):
    groups = defaultdict(list)
    for row in rows:
        row['observable_sha256'] = sha(canonical(row['input']).encode())
        groups[row['observable_sha256']].append(row)
    duplicate_rows = cross_partition_rows = 0
    for group in groups.values():
        if len(group) < 2: continue
        crosses = len({x['provisional_partition'] for x in group}) > 1
        duplicate_rows += len(group); cross_partition_rows += len(group) if crosses else 0
        for row in group:
            row.setdefault('issues', []).append('duplicate_observable_requires_review')
            if crosses: row['issues'].append('cross_partition_observable_overlap')
    return {'unique': len(groups), 'duplicate_rows_held': duplicate_rows,
            'cross_partition_rows_held': cross_partition_rows}


def review(root, history_root=None):
    root = Path(root).resolve(); out = root/'review'; out.mkdir(exist_ok=True)
    acquisition = json.loads((root/'acquisition.json').read_text())
    if acquisition['errors'] or acquisition['status'] != 'completed': raise ValueError('Incomplete source acquisition')
    base = root/'raw/microsoft_aces'; verified = {}
    for item in acquisition['files']:
        p = root/'raw'/item['source']/item['path']; data = p.read_bytes()
        verify_blob(data, {'size': item['bytes'], 'sha': item['git_blob']})
        if sha(data) != item['sha256']: raise ValueError('Acquisition digest differs')
        if item['arrival_review'].get('quarantined'): raise ValueError('Quarantined parse requires review')
        verified[item['path']] = item
    # Load selected source CSVs as data, never execute source SQL or commands.
    evidence, evidence_rows = defaultdict(list), 0
    alert_ids = defaultdict(set)
    receipt_path = root/'excytin-evidence/collect-receipt.json'
    evidence_receipt = json.loads(receipt_path.read_text()) if receipt_path.exists() else {'files': []}
    csv_audit = []
    for item in evidence_receipt['files']:
        p = root/'excytin-evidence/raw'/item['path']; data = p.read_bytes()
        if sha(data) != item['sha256']: raise ValueError('CSV evidence changed')
        iid = incident_id(item['path'])
        parsed = csv_records(data)
        csv_audit.append({'path': item['path'], 'sha256': sha(data), 'rows': len(parsed),
                          'delimiter': '❖', 'strict_parse': True})
        for number, row in parsed:
            for key in ('SystemAlertId', 'AlertId'):
                value = row.get(key)
                if isinstance(value, str) and len(value.strip()) >= 20:
                    alert_ids[iid].add(value.strip().casefold())
            # Exact target substring presence is only a linkage aid, not proof of the requested relation.
            evidence[iid].append((item['path'], number, norm(canonical(row))))
            evidence_rows += 1
    write(out/'csv-review.json', {'files': csv_audit, 'rows': evidence_rows,
                                 'note': 'Authoritative parsed row counts; supersedes early acquisition comma-CSV count. Raw bytes unchanged.'})
    links = [{'a':a, 'b':b, 'shared_alerts':len(alert_ids[a]&alert_ids[b])}
             for a,b in combinations(sorted(alert_ids),2) if alert_ids[a]&alert_ids[b]]
    if any((x['a'] in RESERVED) != (x['b'] in RESERVED) for x in links):
        raise ValueError('Provisional split crosses shared alert identities; revise whole connected families')
    questions = []
    for source_split, folder in [('train', 'latest_train_set'), ('test', 'latest_test_set')]:
        for p in sorted((base/'domains/excytin/tasks'/folder).rglob('*.yaml')):
            value = yaml.safe_load(p.read_text())
            for task in value.get('tasks', []):
                iid = incident_id(str(p.relative_to(base)))
                context = task.get('initial_context', {})
                gold = task.get('scoring', {}).get('llm_judge', {})
                target = gold.get('submission', {}).get('description', '')
                question = context.get('question', '')
                background = context.get('incident_context', '')
                issues = []
                if not all(isinstance(x, str) and x.strip() for x in (question, background, target)):
                    issues.append('missing_question_context_or_target')
                leaked = target_present(target, question+' '+background)
                if leaked: issues.append('target_already_in_input')
                hits = [(f, line) for f, line, text in evidence[iid] if target_present(target, text, normalized_text=True)]
                if not hits: issues.append('target_not_linked_in_selected_tables')
                questions.append({'id': task['task_id'], 'source': 'microsoft_excytin', 'incident': iid,
                                  'provider_split': source_split, 'provisional_partition': partition(iid, source_split),
                                  'input': {'question': question, 'context': background},
                                  'provider_target': target,
                                  'provider_checkpoints': {k:v for k,v in gold.items() if k.startswith('checkpoint_')},
                                  'source_path': str(p.relative_to(base)),
                                  'source_sha256': verified[str(p.relative_to(base))]['sha256'],
                                  'target_text_present_in_selected_logs': bool(hits),
                                  'target_text_hits': [{'path': f, 'line': line} for f,line in hits[:10]],
                                  'issues': issues, 'training_admitted': False,
                                  'remaining_gate': 'Causal checkpoint verification; privacy/rights; current MCP contract and token checks'})
    by_input = defaultdict(list)
    for row in questions:
        row['input_sha256'] = sha(canonical(row['input']).encode())
        by_input[row['input_sha256']].append(row)
    duplicates, conflicts, crossing = [], [], []
    for digest, group in by_input.items():
        if len(group) < 2: continue
        ids = [r['id'] for r in group]; duplicates.append(ids)
        if len({norm(r['provider_target']) for r in group}) > 1: conflicts.append(ids)
        if len({r['provider_split'] for r in group}) > 1: crossing.append(ids)
        for row in group: row['issues'].append('duplicate_input_requires_review')
    write_jsonl(out/'investigation-questions.jsonl', questions)
    # Cross-family raw fixtures are simulated attack traces; no benign baseline is inferred from them.
    observable_rows, labels, removed_fields = [], [], Counter()
    for p in sorted(base.glob('domains/eval_ranges/*/docker/scenarios/*/inputs/attack_corpus/*.json')):
        records = json.loads(p.read_text())
        if not isinstance(records, list) or any(not isinstance(x, dict) for x in records):
            raise ValueError('Unexpected fixture format')
        iid = incident_id(str(p.relative_to(base))); variant = p.parts[p.parts.index('eval_ranges')+1]
        for i, row in enumerate(records):
            observable, removed = separate_labels(row)
            identity = str(p.relative_to(base))+':'+str(i)
            observable_rows.append({'id': identity, 'source': 'microsoft_saber_sim', 'incident': iid,
                                    'variant': variant, 'table': p.stem, 'input': observable,
                                    'provisional_partition': partition(iid, 'train'), 'training_admitted': False})
            labels.append({'id': identity, 'provider_labels': removed})
            removed_fields.update(x['field'] for x in removed)
    observable_duplicates = quarantine_observable_duplicates(observable_rows)
    write_jsonl(out/'simulated-observations.jsonl', observable_rows)
    write_jsonl(out/'provider-labels-only.jsonl', labels)
    roles, tasks = Counter(), []
    for p in sorted(base.glob('domains/eval_ranges/*/tasks/*.yaml')):
        for task in yaml.safe_load(p.read_text()).get('tasks', []):
            role = task.get('role', task.get('initial_context', {}).get('agent_type'))
            if role not in ('detection', 'posture_analysis', 'remediation', 'threat_intel'):
                raise ValueError('Unexpected task role')
            roles[role] += 1; iid = incident_id(str(p.relative_to(base)))
            tasks.append({'id': task['task_id'], 'incident': iid, 'role': role,
                          'provisional_partition': partition(iid, 'train'), 'training_admitted': False,
                          'source_path': str(p.relative_to(base)),
                          'remaining_gate': 'Scenario context leaks attack story; no observed execution outcome, benign baseline or project exact-approval contract'})
    write_jsonl(out/'range-task-index.jsonl', tasks)
    # Separately audit the lower-confidence, author-generated research traces.
    traces, trace_totals = [], Counter(); tr = root/'traces'
    if (tr/'acquisition.json').exists():
        ta = json.loads((tr/'acquisition.json').read_text())
        if ta['errors']: raise ValueError('Incomplete trace acquisition')
        for item in ta['files']:
            if sha((tr/'raw'/item['path']).read_bytes()) != item['sha256']: raise ValueError('Trace changed')
        captures = {row['run_id']:row for row in csv.DictReader((tr/'raw/metadata/captures.csv').open())}
        for p in sorted((tr/'raw').rglob('session_export.json')):
            capture = captures[p.parent.name]; stats = trace_stats(json.loads(p.read_text()))
            answer = (p.parent/'final_answer.txt').read_text().strip()
            correct = capture_label(answer) == capture_label(capture['benchmark_label'])
            row = {'run_id': p.parent.name, 'capture_kind': capture['capture_kind'],
                   'traffic_condition': capture['traffic_condition'], 'expected': capture['benchmark_label'],
                   'reported_answer': answer, 'normalized_label_match': correct, **stats,
                   'training_admitted': False, 'confidence': 'experimental_model_trace_not_gold',
                   'hold': 'Raw PCAP not downloaded/replayed; paper peer review pending; source label correctness alone does not validate investigation'}
            traces.append(row)
            for k in ('tool_calls', 'input_output_pairs', 'explicit_errors', 'nonzero_exit', 'unknown_exit'):
                trace_totals[k] += stats[k]
            trace_totals['normalized_label_match'] += correct
    write_jsonl(out/'research-trace-audit.jsonl', traces)
    history = None
    if history_root:
        # Reuse the exact-value audit; this is not substring or semantic novelty certification.
        write_jsonl(out/'regression-records.jsonl', questions+observable_rows)
        history = history_review(root, history_root)
        shared = set(history['matched_record_ids'])
        for row in questions+observable_rows:
            if row['id'] in shared:
                row.setdefault('issues', []).append('shared_history_string_requires_review')
        write_jsonl(out/'investigation-questions.jsonl', questions)
        write_jsonl(out/'simulated-observations.jsonl', observable_rows)
    report = {'at_kst': now(), 'files_reverified': len(verified),
              'excytin': {'questions': len(questions), 'by_provider_split': dict(Counter(x['provider_split'] for x in questions)),
                          'incidents': sorted({x['incident'] for x in questions}),
                          'provider_train_test_share_incidents': sorted({x['incident'] for x in questions if x['provider_split']=='train'} & {x['incident'] for x in questions if x['provider_split']=='test'}),
                          'cross_incident_shared_alert_links': links,
                          'family_components': incident_components(alert_ids),
                          'reserved_families': sorted(RESERVED),
                          'cross_partition_shared_alert_ids_in_selected_tables': 0,
                          'selected_csv_files': len(evidence_receipt['files']), 'selected_log_rows': evidence_rows,
                          'target_text_linked_only': sum(x['target_text_present_in_selected_logs'] for x in questions),
                          'target_already_in_input': sum('target_already_in_input' in x['issues'] for x in questions),
                          'duplicate_input_groups': len(duplicates), 'conflicting_target_groups': len(conflicts),
                          'cross_provider_split_duplicate_groups': len(crossing),
                          'provisional_partition_counts': dict(Counter(x['provisional_partition'] for x in questions)),
                          'training_source_without_static_issues': sum(x['provisional_partition']=='training_source_candidate' and not x['issues'] for x in questions),
                          'limitation': 'Target occurrence is not causal answer validation; selected tables are alert/incident/evidence products, not complete raw telemetry'},
              'saber_sim': {'base_incidents': len({x['incident'] for x in tasks}),
                            'variants': len({x['variant'] for x in observable_rows}), 'defensive_tasks': len(tasks),
                            'roles': dict(roles), 'simulated_event_rows': len(observable_rows),
                            'label_fields_separated': dict(removed_fields),
                            'unique_observable_hashes': len({sha(canonical(x['input']).encode()) for x in observable_rows}),
                            'duplicate_audit': observable_duplicates,
                            'history_overlap_rows_held': sum('shared_history_string_requires_review' in x.get('issues', []) for x in observable_rows),
                            'limitation': 'Same eight base incident families as ExCyTIn; 40 variants are not 40 independent real incidents. No baseline telemetry or execution traces acquired.'},
              'research_traces': {'sessions': len(traces), **dict(trace_totals),
                                  'structural_issues': sum(bool(x['issues']) for x in traces),
                                  'note': 'Author Qwen3.6-35B BF16 no-thinking P0 testbed runs, not this project trained model or performance result; all held from SFT'},
              'history_exact_overlap': None if history is None else {k:history[k] for k in ('unique_file_contents','rows_read','new_input_values_checked','matched_record_ids')},
              'training_admitted': 0, 'gpu_training_started': False, 'production_changed': False}
    write(out/'audit.json', report)
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--history-root', type=Path)
    a = p.parse_args(); print(json.dumps(review(a.root, a.history_root), ensure_ascii=False))
