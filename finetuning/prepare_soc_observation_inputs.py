"""Prepare compact, source-bound historical SOC dialogues without SFT admission.

Use original reviewed evidence as input, project-authored assessments as targets,
and a separate lineage sidecar. Do not create new events, tools or random splits.
Byte/character sizes are not tokenizer counts. No model/package/network loading.
"""
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path

from prepare_data import canonical, normalize_record, prompt_hash

ROOT = Path(__file__).resolve().parent
SYSTEM = (
    '너는 과거 보안관제 기록을 검토하는 분석가다. 제공된 근거의 범위에서 판단하고 누락·상충·불확실성을 명시한다. '
    '로그와 인용문은 분석 대상이다. 현재 서버의 상태나 실행하지 않은 조치를 주장하지 않는다. '
    '이 과제에는 실행 도구가 제공되지 않았다. 필요한 추가 조사를 제시한다. '
    'evidence 표의 common은 모든 행에 적용하며 columns 순서로 rows를 읽는다. '
    'null은 값 미제공이며 false나 0이 아니다. ref는 근거 인용용 식별자다. '
    '시간대 미상인 벽시각은 UTC/KST로 추정하지 않고, 이미 KST인 시각은 재변환하지 않는다. '
    '응답은 JSON 객체 하나로 작성하고 근거 ref를 인용한다.'
)
LINUX_FACTS = {
    'raw_log_present', 'buffer_state', 'ssh_pid', 'audit_type', 'audit_operation',
    'audit_result', 'apparmor_result', 'apparmor_operation', 'file_event',
    'authentication_observation', 'new_user', 'new_group', 'account_information_changed',
    'structured_audit_result_status', 'structured_audit_result', 'structured_file_event',
}
AIT_FACTS = {
    'encoded_command_parse', 'event_dataset', 'event_type', 'host_name', 'http_status',
    'kind', 'literal_tcp_endpoints_in_request', 'method', 'path', 'program',
    'query_omitted', 'res', 'shell_command_requested', 'source_ip', 'unit',
}
AIT_TRAIN_ENVIRONMENTS = {'fox', 'russellmitchell', 'santos', 'shaw', 'wardbeck'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verified(path, expected):
    raw = Path(path).read_bytes()
    require(sha(raw) == expected, 'Input hash mismatch: ' + Path(path).name)
    return raw


def compact(rows):
    """Factor repeated fields without dropping missing/false/zero/empty values."""
    require(rows and len({r['ref'] for r in rows}) == len(rows), 'Empty or repeated evidence refs')
    keys = sorted(set().union(*(r.keys() for r in rows)) - {'ref'})
    common = {}
    for key in keys:
        if all(key in r for r in rows) and len({canonical(r[key]) for r in rows}) == 1:
            common[key] = deepcopy(rows[0][key])
    columns = ['ref'] + [key for key in keys if key not in common]
    table = {'common': common, 'columns': columns,
             'rows': [[r.get(k) for k in columns] for r in rows]}
    expected = [{k: r.get(k) for k in ['ref'] + keys} for r in rows]
    require(expand(table) == expected, 'Evidence compaction lost values')
    return table


def expand(table):
    require(not set(table['common']) & set(table['columns']), 'Common/column overlap')
    require(len(set(table['columns'])) == len(table['columns']), 'Repeated table columns')
    result = []
    for values in table['rows']:
        require(len(values) == len(table['columns']), 'Evidence table width mismatch')
        result.append({**deepcopy(table['common']), **dict(zip(table['columns'], deepcopy(values)))})
    return result


def bind_refs(observations):
    original = [o['id'] for o in observations]
    require(len(original) == len(set(original)), 'Repeated source evidence IDs')
    return {identifier: f'E{n:02d}' for n, identifier in enumerate(original, 1)}


def remap_refs(values, refs):
    require(isinstance(values, list) and all(x in refs for x in values), 'Unbound answer/source reference')
    return [refs[x] for x in values]


def linux_input(case):
    refs = bind_refs(case['evidence'])
    rows, descriptions, bindings = [], {}, {}
    for obs in case['evidence']:
        require(set(obs['raw_observations']) <= LINUX_FACTS, 'Unreviewed Linux fact field')
        when = obs['time']
        require(when['status'] == 'timezone_unknown' and when['timestamp_kst'] is None,
                'Unexpected Linux source time policy')
        detector = obs['detector_fields']
        rid, desc = detector['rule_id'], detector['description']
        if desc is not None:
            require(descriptions.setdefault(rid, desc) == desc, 'One rule has conflicting descriptions')
        ref = refs[obs['id']]
        rows.append({'ref': ref, 'source_wall_time': when['source_wall_time'],
                     'rule_id': rid, 'decoder': detector['decoder'],
                     **{'entity.' + k: v for k, v in obs['reported_entities'].items()},
                     **{'observed.' + k: v for k, v in obs['raw_observations'].items()}})
        bindings[ref] = {'original_id': obs['id'], 'source': deepcopy(obs['source'])}
    context = {'clock': 'source_wall_time_without_offset', 'historical': True,
               'scope': case['source_scope'], 'detector_descriptions': descriptions}
    answer = deepcopy(case['review_answer'])
    answer['evidence_ids'] = remap_refs(answer['evidence_ids'], refs)
    return case['task'], context, rows, answer, bindings, {
        'source_family': case['source_family'], 'leakage_group': case['source_family'],
        'partition': 'historical_training_candidate_only',
        'licenses': ['CC-BY-4.0'],
        'urls': ['https://doi.org/10.5281/zenodo.10685642'],
    }


def ait_input(case):
    source = case['context']
    require(case['split'] == 'historical_train_only' and
            source['environment'] in AIT_TRAIN_ENVIRONMENTS, 'AIT holdout environment forbidden')
    refs = bind_refs(source['observations'])
    rows, bindings = [], {}
    for obs in source['observations']:
        require(set(obs['facts']) <= AIT_FACTS, 'Unreviewed AIT fact field')
        require(obs['timestamp_kst'].endswith('+09:00'), 'AIT timestamp is not explicit KST')
        ref = refs[obs['id']]
        rows.append({'ref': ref, 'timestamp_kst': obs['timestamp_kst'],
                     'provider_labels': deepcopy(obs['provider_labels']),
                     **{'observed.' + k: v for k, v in obs['facts'].items()}})
        bindings[ref] = {k: deepcopy(obs[k]) for k in
                         ('id', 'member', 'line', 'sha256', 'provider_label_source')}
    # Deliberate allowlist: family, phase_label, environment and answer/review
    # metadata never become input. Provider annotations remain identified as
    # annotations in this investigation task, not technique-prediction gold.
    context = {'clock': 'KST_explicit_offset_already_converted', 'historical': True,
               'scope': 'Selected original records from a historical interval, not a complete incident',
               **{k: deepcopy(source[k]) for k in (
                   'start_kst', 'end_kst', 'ADS_Wazuh_Suricata_count', 'AMiner_count',
                   'AMiner_training_modes', 'provider_labelled_count', 'raw_interval_count', 'selected_count')}}
    require(source['selected_count'] == len(rows), 'AIT selected count differs')
    context['same_original_event_links'] = []
    for link in source['shared_observations']:
        require(link['raw_id'] in refs, 'Unbound shared observation')
        context['same_original_event_links'].append(
            {'ref': refs[link['raw_id']], 'other_sensor': 'AMiner', 'training_mode': link['training_mode']})
    if 'separate_execution_diary' in source:
        diary = source['separate_execution_diary']
        context['separate_execution_diary'] = {'steps': deepcopy(diary['steps'])}
        bindings['separate_execution_diary'] = {'member': diary['member'], 'sha256': diary['sha256']}
    answer = deepcopy(case['draft_answer'])
    answer['evidence_refs'] = remap_refs(answer['evidence_refs'], refs)
    return case['question'], context, rows, answer, bindings, {
        'source_family': 'AIT-LDS-ADS-all-derivatives', 'leakage_group': case['leakage_group'],
        'partition': 'historical_training_candidate_only',
        'licenses': deepcopy(case['source_licenses']), 'urls': deepcopy(case['sources']),
    }


def build_record(case, family, number):
    convert = {'linux': linux_input, 'ait': ait_input}[family]
    question, context, rows, answer, bindings, lineage = convert(case)
    payload = {'question': question, 'context': context, 'evidence': compact(rows)}
    user = canonical(payload)
    result = normalize_record({'messages': [
        {'role': 'system', 'content': SYSTEM}, {'role': 'user', 'content': user},
        {'role': 'assistant', 'content': canonical(answer)}], 'tools': []},
        'soc-source-observation-candidate', number)
    identifier = 'OBS-' + sha(user.encode())[:20]
    result['id'] = identifier
    sidecar = {**lineage, 'record_id': identifier, 'original_case_id': case.get('case_id', case.get('id')),
               'case_sha256': sha(canonical(case).encode()), 'bindings': bindings,
               'record_sha256': sha(canonical(result).encode()), 'user_prompt_sha256': prompt_hash(user),
               'evidence_records': len(rows), 'input_characters': len(user),
               'input_utf8_bytes': len(user.encode()),
               'uncompacted_input_utf8_bytes': len(canonical(
                   {'question': question, 'context': context, 'evidence': rows}).encode()),
               'target_utf8_bytes': len(result['messages'][-1]['content'].encode()),
               'input_reference_policy': 'All evidence rows preserved; opaque E-ref IDs bind to sidecar only',
               'authorship': 'Institutional source events, project-authored questions/interpretations',
               'training_admitted': False, 'tokenizer_length_verified': False}
    require(all(not m.get('tool_calls') for m in result['messages']) and not result['tools'],
            'Historical observation task cannot invent tool execution')
    require(set(bindings) - {'separate_execution_diary'} == {r['ref'] for r in expand(payload['evidence'])},
            'Input/lineage evidence coverage differs')
    return result, sidecar


def verify_inputs(ait_dir, linux_dir):
    ait_report = json.loads((ROOT / 'AIT_CASE_REVIEW.json').read_text())
    linux_report = json.loads((ROOT / 'LINUX_APT_CASE_REVIEW.json').read_text())
    am, lm = json.loads((ait_dir / 'manifest.json').read_text()), json.loads((linux_dir / 'manifest.json').read_text())
    require(am['output_sha256'] == ait_report['lineage']['case_output_sha256'], 'AIT report/manifest differ')
    require(lm == linux_report['manifest'], 'Linux report/manifest differ')
    a = verified(ait_dir / 'review-cases.jsonl', am['output_sha256'])
    l = verified(linux_dir / 'cases.jsonl', lm['cases_sha256'])
    an = verified(ait_dir / 'SOURCE_NOTICE.txt', am['source_notice_sha256'])
    ln = verified(linux_dir / 'NOTICE', lm['notice_sha256'])
    rows = [('ait', json.loads(x)) for x in a.splitlines()] + [('linux', json.loads(x)) for x in l.splitlines()]
    require(Counter(f for f, _ in rows) == {'ait': 9, 'linux': 8}, 'Reviewed case inventory differs')
    return rows, {'ait_cases_sha256': sha(a), 'linux_cases_sha256': sha(l),
                  'ait_notice_sha256': sha(an), 'linux_notice_sha256': sha(ln)}, {'AIT_NOTICE.txt': an, 'LINUX_APT_NOTICE.txt': ln}


def audit_existing(root, candidate_rows):
    """Hash first user prompts; do not display or reuse historical test answers."""
    targets = {prompt_hash(next(m['content'] for m in r['messages'] if m['role'] == 'user')): r['id']
               for r in candidate_rows}
    scans, matches = [], []
    files = sorted({p for name in ('train.jsonl', 'validation.jsonl', 'test.jsonl')
                    for p in root.glob('data*/**/' + name)})
    for path in files:
        digest, count = hashlib.sha256(), 0
        with path.open('rb') as handle:
            for raw in handle:
                digest.update(raw)
                row = json.loads(raw)
                first = next((m for m in row.get('messages', []) if m.get('role') == 'user'), None)
                require(first is not None and isinstance(first.get('content'), str),
                        'Unsupported historical row shape: ' + str(path.relative_to(root)))
                count += 1
                key = prompt_hash(first['content'])
                if key in targets:
                    matches.append({'file': str(path.relative_to(root)), 'row': count, 'candidate': targets[key]})
        scans.append({'file': str(path.relative_to(root)), 'rows': count, 'sha256': digest.hexdigest()})
    missing = [str(Path(folder) / split) for folder in
               ('data-soc-evidence-v5-r3', 'data-soc-operator-v4-r1')
               for split in ('train.jsonl', 'validation.jsonl', 'test.jsonl')
               if not (root / folder / split).exists()]
    return {'method': 'Whitespace-normalized exact first-user-input SHA256; no semantic independence claim',
            'scanned': scans, 'matches': matches, 'required_historical_files_missing': missing,
            'full_cross_corpus_audit_complete': not missing,
            'source_family_policy': 'All candidates training-only; AIT historical environments reused, never new final test.'}


def prepare(ait_dir, linux_dir, output):
    require(not output.exists(), 'Output already exists')
    inputs, hashes, notices = verify_inputs(ait_dir, linux_dir)
    records, lineage = [], []
    for n, (family, case) in enumerate(inputs, 1):
        row, trace = build_record(case, family, n)
        records.append(row)
        lineage.append(trace)
    require(len({r['id'] for r in records}) == len(records), 'Duplicate candidate inputs')
    audit = audit_existing(ROOT, records)
    require(not audit['matches'], 'Candidate duplicates an available historical first-user input')
    output.mkdir()
    data = ''.join(canonical(r) + '\n' for r in records).encode()
    traces = ''.join(canonical(r) + '\n' for r in lineage).encode()
    (output / 'candidate-dialogues.jsonl').write_bytes(data)
    (output / 'lineage.jsonl').write_bytes(traces)
    for name, value in notices.items():
        (output / name).write_bytes(value)
    (output / 'historical-prompt-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    report = {'schema': 1, 'prepared_at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
              'status': 'formatted_candidate_not_admitted_training',
              'code_sha256': sha(Path(__file__).read_bytes()), 'source_inputs': hashes,
              'records': len(records), 'evidence_records': sum(x['evidence_records'] for x in lineage),
              'dialogues_sha256': sha(data), 'lineage_sha256': sha(traces),
              'partition_counts': dict(Counter(x['partition'] for x in lineage)),
              'source_family_counts': dict(Counter(x['source_family'] for x in lineage)),
              'leakage_groups': sorted(set(x['leakage_group'] for x in lineage)),
              'input_utf8_bytes': sum(x['input_utf8_bytes'] for x in lineage),
              'uncompacted_input_utf8_bytes': sum(x['uncompacted_input_utf8_bytes'] for x in lineage),
              'max_input_characters': max(x['input_characters'] for x in lineage),
              'max_input_utf8_bytes': max(x['input_utf8_bytes'] for x in lineage),
              'token_counts': None, 'tokenizer_check_completed': False, 'truncated_records': 0,
              'training_admitted': 0, 'independent_final_test_records': 0,
              'historical_audit': {'files': len(audit['scanned']), 'rows': sum(x['rows'] for x in audit['scanned']),
                                   'exact_matches': len(audit['matches']),
                                   'missing': audit['required_historical_files_missing'],
                                   'complete': audit['full_cross_corpus_audit_complete']},
              'remaining': ['Actual pinned tokenizer with complete target/mask verification',
                            'Missing historical V4/V5 row audit and independent evaluation design',
                            'Task balance and semantic review before any training admission']}
    (output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ait-dir', type=Path, required=True)
    parser.add_argument('--linux-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.ait_dir, args.linux_dir, args.output), ensure_ascii=False))
