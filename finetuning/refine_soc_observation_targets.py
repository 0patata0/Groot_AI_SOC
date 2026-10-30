"""Refine historical investigation targets from evidence already in each prompt.

This is offline data preparation, not a live agent decision rule or SFT admission.
Inputs, evidence, source licences, source groups and prior candidates are retained.
No model calls, raw-log downloads, new scenarios or tokenizer-length claims.
"""
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from prepare_data import canonical
from prepare_soc_observation_inputs import expand

ROOT = Path(__file__).resolve().parent
KST = timezone(timedelta(hours=9))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def moment(value):
    when = datetime.fromisoformat(value)
    require(when.utcoffset() == timedelta(hours=9), 'Expected explicit KST, no inferred timezone')
    return when


def integer(value):
    return type(value) is int and value >= 0


def refine_ait(payload, original):
    context, rows = payload['context'], expand(payload['evidence'])
    require(context['historical'] is True and
            context['clock'] == 'KST_explicit_offset_already_converted', 'Unreviewed AIT scope')
    refs = {r['ref'] for r in rows}
    require(len(refs) == len(rows), 'Repeated evidence ref')
    for key in ('ADS_Wazuh_Suricata_count', 'AMiner_count', 'provider_labelled_count',
                'raw_interval_count', 'selected_count'):
        require(integer(context[key]), 'Invalid sensor count')
    require(context['ADS_Wazuh_Suricata_count'] == 0, 'Review scope is zero-ADS historical windows')
    require(context['selected_count'] == len(rows) <= context['raw_interval_count'], 'Selection count mismatch')
    modes = context['AMiner_training_modes']
    require(set(modes) <= {'true', 'false'} and all(integer(v) for v in modes.values())
            and sum(modes.values()) == context['AMiner_count'], 'AMiner mode/count mismatch')
    links = context['same_original_event_links']
    require(all(link['ref'] in refs and type(link['training_mode']) is bool
                and link['other_sensor'] == 'AMiner' for link in links), 'Unbound sensor link')
    require(len(links) <= context['AMiner_count'], 'Sensor bindings exceed observations')
    start, end = moment(context['start_kst']), moment(context['end_kst'])
    require(start <= end and all(start <= moment(r['timestamp_kst']) <= end for r in rows),
            'Evidence outside stated interval')
    service = [r for r in rows if r.get('observed.event_type') in ('SERVICE_START', 'SERVICE_STOP')]
    shell = [r for r in rows if r.get('observed.shell_command_requested') is True
             and r.get('observed.literal_tcp_endpoints_in_request')]
    web = [r for r in rows if 'webshell_cmd' in r.get('provider_labels', [])]
    require(sum(bool(x) for x in (service, shell, web)) == 1, 'Unreviewed or ambiguous evidence family')
    answer = deepcopy(original)
    findings = []
    if service:
        require(len(service) == 2 and {r['observed.event_type'] for r in service} ==
                {'SERVICE_START', 'SERVICE_STOP'}, 'Incomplete service pair')
        units = {r.get('observed.unit') for r in service}
        require(len(units) == 1 and None not in units and '' not in units, 'Service units differ/missing')
        events = {r['observed.event_type']: r for r in service}
        a, b = events['SERVICE_START'], events['SERVICE_STOP']
        ta, tb = moment(a['timestamp_kst']), moment(b['timestamp_kst'])
        relation = 'same_recorded_timestamp' if ta == tb else ('start_before_stop' if ta < tb else 'stop_before_start')
        relation_text = {
            'same_recorded_timestamp': '두 기록의 표시 시각이 같아 표시 시각만으로 선후나 실행 시간을 정할 수 없습니다.',
            'start_before_stop': '표시 시각상 시작 기록이 종료 기록보다 앞섭니다. 이것만으로 실제 서비스 가동 시간을 확정하지 않습니다.',
            'stop_before_start': '표시 시각상 종료 기록이 시작 기록보다 앞섭니다. 기록 순서를 임의로 뒤집지 않습니다.',
        }[relation]
        require(all(isinstance(r.get('observed.res'), str) and r['observed.res'] for r in service),
                'Missing service event result')
        findings = [{'ref': r['ref'], 'event_type': r['observed.event_type'],
                     'unit': r['observed.unit'], 'recorded_result': r['observed.res'],
                     'timestamp_kst': r['timestamp_kst'], 'provider_labels': r['provider_labels']}
                    for r in service]
        diary = context.get('separate_execution_diary', {}).get('steps', [])
        require(len(diary) == 1 and diary[0]['step'] == 'dnsteal_stop', 'Missing/ambiguous separate diary')
        when = moment(diary[0]['timestamp_kst'])
        require(diary[0]['inside_phase_interval'] is False and not start <= when <= end,
                'Diary no longer separate from interval')
        diary_relation = 'before_interval' if when < start else 'after_interval'
        diary_text = '앞선' if when < start else '뒤인'
        answer['conclusion'] = (
            f"{a['ref']}의 SERVICE_START와 {b['ref']}의 SERVICE_STOP은 같은 unit={a['observed.unit']}의 기록입니다. "
            + relation_text + ' 각 res는 해당 감사 이벤트의 기록된 결과이며 유출 성공·전체 서비스 장애·침해 제거를 증명하지 않습니다. '
            + f'별도 dnsteal_stop 일지는 이 구간보다 {diary_text} 시각이므로 동일 종료 사건으로 합치지 않습니다.')
        answer['recorded_time_relation'] = relation
        answer['separate_diary'] = {'timestamp_kst': diary[0]['timestamp_kst'],
                                    'step': 'dnsteal_stop', 'relation_to_interval': diary_relation,
                                    'same_event_established': False}
        family = 'service_start_stop'
    else:
        relevant = shell if shell else web
        require(all(r.get('observed.encoded_command_parse') == 'json_string_array'
                    and isinstance(r.get('observed.program'), str) for r in relevant),
                'Provider label alone is not parsed command evidence')
        findings = [{'ref': r['ref'], 'timestamp_kst': r['timestamp_kst'],
                     'requested_program': r['observed.program'],
                     'http_status': r.get('observed.http_status'),
                     'shell_command_requested': r.get('observed.shell_command_requested'),
                     'literal_tcp_endpoints_in_request': r.get('observed.literal_tcp_endpoints_in_request'),
                     'provider_labels': r['provider_labels']}
                    for r in relevant]
        programs = ', '.join(f"{r['ref']}={r['observed.program']}" for r in relevant)
        if shell:
            answer['conclusion'] = (f'{programs}의 HTTP 요청에는 셸 명령과 리터럴 TCP 목적지가 함께 있습니다. '
                '제공자 라벨 유무와 별도로 조사할 위험 정황입니다. 목적지는 요청 문자열에서 추출한 값이며 '
                '실제 연결이나 원격 명령 실행 성공은 확인되지 않았습니다.')
            family = 'request_with_shell_tcp_literal'
        else:
            answer['conclusion'] = (f'{programs}는 HTTP 요청에서 해석한 명령 배열입니다. '
                'webshell_cmd는 제공자 주석이며 실제 실행 결과와 구분합니다. '
                'HTTP 상태만으로 명령 실행·다운로드 성공·권한 상승을 확정할 수 없습니다.')
            family = 'provider_annotated_command_request'
    answer['evidence_findings'] = findings
    answer['evidence_refs'] = [f['ref'] for f in findings]
    answer['sensor_scope'] = (
        f"이 구간의 Wazuh/Suricata 공개 기록은 0건이고 명시 시각 원문 {context['raw_interval_count']}행 중 "
        f"{len(rows)}행이 입력에 있습니다. 제공자 라벨은 원문 {context['provider_labelled_count']}행에 있으며 "
        f"AMiner 객체 {context['AMiner_count']}개 중 TrainingMode=false는 {modes.get('false', 0)}개, "
        f"true는 {modes.get('true', 0)}개입니다.")
    limits = ['이 구간의 경보·라벨 부재만으로 정상 종료나 공격 실패를 확정하지 않습니다.']
    if links:
        counts = Counter(link['ref'] for link in links)
        linked = ', '.join(f'{ref} {count}연결' for ref, count in sorted(counts.items()))
        limits.append(f'동일 원문을 공유하는 AMiner 연결은 {linked}입니다. 독립된 공격 성공 증거로 중복 집계하지 않습니다.')
    if modes.get('true', 0):
        limits.append(f"TrainingMode=true인 {modes['true']}객체는 운영 탐지 성공으로 집계하지 않습니다.")
    if len(rows) < context['raw_interval_count']:
        limits.append('입력은 구간 원문의 일부 표본입니다. 나머지 원문까지 조회했다고 주장하지 않습니다.')
    limits.append('과거 시험망의 선택 구간이며 현재 서버 상태·현재 차단 대상·사건 전체를 뜻하지 않습니다.')
    answer['limits'] = limits
    require(answer['live_action_taken'] is False and answer['tools_called'] == [], 'Invented live action')
    return answer, family


def refine_record(row, trace):
    require(row.get('tools') == [] and [m['role'] for m in row['messages']] ==
            ['system', 'user', 'assistant'], 'Unsupported dialogue or tool trajectory')
    require(all(not m.get('tool_calls') for m in row['messages']), 'Unexpected tool call')
    require(trace['training_admitted'] is False and trace['partition'] == 'historical_training_candidate_only',
            'Unreviewed partition or admitted source')
    require(sha(canonical(row).encode()) == trace['record_sha256'] and row['id'] == trace['record_id'],
            'Record/lineage mismatch')
    payload = json.loads(row['messages'][1]['content'])
    observations = expand(payload['evidence'])
    require({r['ref'] for r in observations} == set(trace['bindings']) - {'separate_execution_diary'},
            'Input/source binding coverage differs')
    original = json.loads(row['messages'][-1]['content'])
    if trace['source_family'] == 'AIT-LDS-ADS-all-derivatives':
        answer, family = refine_ait(payload, original)
        changes = ['bind_claims_to_observed_fields', 'record_sensor_modes_and_sample_scope',
                   'conditional_limits_only']
    else:
        require(trace['source_family'] == 'linux-apt-2024-all-releases-and-derivatives', 'Unknown source family')
        require(payload['context']['clock'] == 'source_wall_time_without_offset', 'Unknown clock policy changed')
        answer = deepcopy(original)
        family = trace['original_case_id'].removeprefix('linux-apt-')
        changes = []
        if family == 'audit_config':
            require(len(observations) == 1 and observations[0].get('observed.audit_type') == 'CONFIG_CHANGE'
                    and observations[0].get('observed.audit_operation') == 'add_rule'
                    and observations[0].get('observed.audit_result') == '1'
                    and observations[0].get('observed.structured_audit_result_status') == 'noncanonical',
                    'Audit-config evidence changed')
            answer['assessment'] = ('E01의 추출된 감사 필드는 CONFIG_CHANGE, op=add_rule, res=1입니다. '
                '구조화 res는 noncanonical로 표시되어 단순 결과 코드로 신뢰할 수 없습니다. '
                '그 필드의 구체적인 문자열은 이 입력에 없으므로 어떤 내용이 섞였는지 단정하지 않습니다. '
                '원문 필드와 파서 경계를 확인하고 변경의 승인 여부·주체를 별도로 조사해야 합니다.')
            changes = ['remove_claim_about_unprovided_structured_result_contents']
    result = deepcopy(row)
    result['messages'][-1]['content'] = canonical(answer)
    require(result['messages'][:-1] == row['messages'][:-1], 'Prompt changed')
    revised = deepcopy(trace)
    revised.update(record_sha256=sha(canonical(result).encode()),
                   supersedes_record_sha256=trace['record_sha256'],
                   target_utf8_bytes=len(result['messages'][-1]['content'].encode()),
                   target_revision='evidence-specific-r2', tokenizer_length_verified=False,
                   training_admitted=False)
    review = {'record_id': row['id'], 'original_case_id': trace['original_case_id'],
              'task_family': family, 'changes': changes,
              'target_changed': result != row, 'prompt_unchanged': True,
              'source_bindings_unchanged': revised['bindings'] == trace['bindings'],
              'review_author': 'project_agent', 'independent_expert_review': False}
    return result, revised, review


def prepare(source, output):
    require(not output.exists(), 'Output already exists')
    report = json.loads((ROOT / 'SOC_OBSERVATION_INPUT_REVIEW.json').read_text())
    expected = report['manifest']
    raw = (source / 'candidate-dialogues.jsonl').read_bytes()
    trace_raw = (source / 'lineage.jsonl').read_bytes()
    require(sha(raw) == expected['dialogues_sha256'] and sha(trace_raw) == expected['lineage_sha256'],
            'Pinned R1 source hash mismatch')
    rows, traces = ([json.loads(line) for line in data.splitlines()] for data in (raw, trace_raw))
    require(len(rows) == len(traces) == expected['records'] == 17, 'Candidate count differs')
    require(len({r['id'] for r in rows}) == 17, 'Repeated candidate ID')
    revised, lineage, reviews = [], [], []
    for row, trace in zip(rows, traces):
        item, binding, review = refine_record(row, trace)
        revised.append(item); lineage.append(binding); reviews.append(review)
    notices = {}
    for name, key in [('AIT_NOTICE.txt', 'ait_notice_sha256'), ('LINUX_APT_NOTICE.txt', 'linux_notice_sha256')]:
        notice = (source / name).read_bytes()
        require(sha(notice) == expected['source_inputs'][key], 'Source notice differs')
        notices[name] = notice
    data = ''.join(canonical(row) + '\n' for row in revised).encode()
    lines = ''.join(canonical(row) + '\n' for row in lineage).encode()
    summary = {'schema': 1, 'prepared_at_kst': datetime.now(KST).isoformat(),
        'status': 'semantically_refined_candidate_not_admitted', 'records': len(rows),
        'input_dialogues_sha256': sha(raw), 'input_lineage_sha256': sha(trace_raw),
        'dialogues_sha256': sha(data), 'lineage_sha256': sha(lines),
        'code_sha256': sha(Path(__file__).read_bytes()),
        'changed_targets': sum(r['target_changed'] for r in reviews),
        'unchanged_targets': sum(not r['target_changed'] for r in reviews),
        'evidence_bindings': sum(t['evidence_records'] for t in traces),
        'all_input_bytes_unchanged': True, 'all_source_bindings_unchanged': True,
        'original_unique_complete_targets': len({r['messages'][-1]['content'] for r in rows}),
        'revised_unique_complete_targets': len({r['messages'][-1]['content'] for r in revised}),
        'task_family_counts': dict(Counter(r['task_family'] for r in reviews)),
        'source_family_counts': dict(Counter(t['source_family'] for t in traces)),
        'leakage_groups': sorted({t['leakage_group'] for t in traces}),
        'input_utf8_bytes': sum(len(r['messages'][1]['content'].encode()) for r in revised),
        'target_utf8_bytes_before': sum(len(r['messages'][-1]['content'].encode()) for r in rows),
        'target_utf8_bytes_after': sum(len(r['messages'][-1]['content'].encode()) for r in revised),
        'training_admitted': 0, 'tokenizer_verified': False, 'independent_expert_review': False,
        'new_independent_incidents_claimed': 0, 'new_final_test_records': 0,
        'reviews': reviews,
        'limits': ['Unique targets include different observed times/units; uniqueness is not quality or task diversity.',
                   'Nine AIT windows were selected for zero ADS records; selection bias remains.',
                   'Historical no-tools investigation tasks do not teach actual tool selection/approval/write/rollback.',
                   'Provider annotations are input evidence; not label-free detection evaluation.',
                   'No new raw acquisition, actual tokenizer, missing V4/V5 overlap audit, GPU run or live verification.']}
    output.mkdir()
    (output / 'candidate-dialogues.jsonl').write_bytes(data)
    (output / 'lineage.jsonl').write_bytes(lines)
    for name, notice in notices.items():
        (output / name).write_bytes(notice)
    (output / 'manifest.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), ensure_ascii=False))


if __name__ == '__main__':
    main()
