"""Prepare source-bound investigation drafts from verified historical AIT evidence.

No invented incidents, tool calls, incident-success gold, model calls or training.
Draft wording is project-authored, not an official AIT answer or expert review.
"""
import argparse
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit

from link_ait_labels import explicit_time

KST = timezone(timedelta(hours=9))
TRAIN = {'fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck'}
ACCESS = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "([A-Z]+) ([^" ]+) HTTP/\d(?:\.\d)?" (\d{3}) ')
NOTICE = '''AIT source-bound investigation drafts
LDS: https://doi.org/10.5281/zenodo.5789064 (CC BY-NC-SA 4.0)
Creators: Max Landauer, Florian Skopik, Maximilian Frank, Wolfgang Hotwagner,
Markus Wurzenberger, Andreas Rauber. Paper: DOI 10.1109/TDSC.2022.3201582.
ADS: https://doi.org/10.5281/zenodo.8263181 (CC BY 4.0)
Creators: Max Landauer, Florian Skopik, Markus Wurzenberger.
Paper: DOI 10.1145/3675741.3675748.
License texts: https://creativecommons.org/licenses/by-nc-sa/4.0/
and https://creativecommons.org/licenses/by/4.0/
Modifications: bounded selection, KST projection, minimal request/audit fields,
query argument/full command omission, shared-source bindings, project-agent
question/answer wording. Derived LDS material retains CC BY-NC-SA 4.0.
Not official/provider or independent-expert answers; no endorsement or warranty.
Historical training environments only. Not independent evaluation or admitted
training data. Exact source coordinates, hashes and limits accompany each case.
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def project_raw(sample):
    """Extract evidence only; never execute or reproduce query credentials/commands."""
    text = sample['raw_text']
    require(sha(text.encode()) == sample['raw_line_sha256'], 'Raw sample hash differs')
    when, basis = explicit_time(text)
    require(when is not None and when.astimezone(KST).isoformat() == sample['timestamp_kst'],
            'Sample timestamp differs or unresolved')
    out = {'kind': basis}
    if basis == 'audit_epoch':
        out['event_type'] = re.search(r'(?:^|\s)type=([A-Z_]+) ', text)[1]
        for key in ('unit', 'res'):
            match = re.search(r"(?:^|[ '\t])" + key + r"=([^ '\t\r\n]+)", text)
            out[key] = match[1] if match else None
    elif basis == 'apache_offset':
        match = ACCESS.match(text)
        require(match is not None, 'Unsupported Apache request syntax')
        source, method, target, status = match.groups()
        uri = urlsplit(target)
        out.update(source_ip=source, method=method, path=uri.path, http_status=int(status))
        # Query arguments can contain passwords. Only derive a minimal program
        # name and literal TCP endpoint indicator, never retain the command.
        params = parse_qs(uri.query, max_num_fields=128).get('wp_meta', [])
        out['query_omitted'] = bool(uri.query)
        if params:
            out['encoded_command_parse'] = 'unresolved'
            if len(params) == 1 and len(params[0]) <= 8192:
                try:
                    argv = json.loads(base64.b64decode(params[0], validate=True))
                    require(isinstance(argv, list) and bool(argv) and
                            all(isinstance(x, str) for x in argv), 'Not a command array')
                    require(bool(re.fullmatch(r'[A-Za-z0-9_./-]{1,128}', argv[0])), 'Invalid program')
                    out.update(encoded_command_parse='json_string_array', program=argv[0])
                    out['shell_command_requested'] = (argv[0].rsplit('/', 1)[-1] in ('bash', 'sh', 'dash', 'zsh')
                                                      and len(argv) > 2 and argv[1] == '-c')
                    # This is request content, not proof of process execution or a socket.
                    endpoints = re.findall(r'/dev/tcp/([0-9.]+)/([0-9]{1,5})', '\n'.join(argv[1:]))
                    out['literal_tcp_endpoints_in_request'] = sorted(set(h + ':' + p for h, p in endpoints))
                except (ValueError, UnicodeDecodeError):
                    pass
    else:
        record = json.loads(text)
        out['event_dataset'] = (record.get('event') or {}).get('dataset')
        out['host_name'] = (record.get('host') or {}).get('name')
    return out


def verified_results(envelope, report):
    pinned = report['integrity']['remote_result_file_SHA256']
    results = []
    for name, entry in envelope['files'].items():
        digest = sha(entry['content'].encode())
        require(digest == entry['sha256'] == pinned[name], 'Result envelope hash differs: ' + name)
        if name.endswith('-linkage.json'):
            value = json.loads(entry['content'])
            require(value['environment'] in TRAIN, 'Holdout environment is forbidden')
            require(value['status'] == 'linked' and bool(value.get('completed_at_kst')), 'Incomplete source review')
            require(all(p['all_label_references_bound'] and p['selected_member_CRCs_verified']
                        for p in value['pairs']), 'Incomplete member verification')
            results.append(value)
    require(json.loads(envelope['files']['linkage-state.json']['content'])['stage'] == 'completed',
            'Source job is not terminal')
    require(len({v['environment'] for v in results}) == len(results) == 5, 'Missing/duplicate environments')
    return results


def build_cases(results, report, aminer):
    windows = {(w['environment'], w['phase']): w for w in report['windows']}
    require(len(windows) == len(report['windows']) == 9, 'Missing/duplicate windows')
    aminer_by_env = {v['environment']: v for v in aminer['results']}
    cases = []
    for result in results:
        env = result['environment']
        require(env in TRAIN, 'Holdout environment is forbidden')
        for window in result['windows']:
            phase = window['phase']
            official = windows[(env, phase)]
            observations = []
            raw_count = labelled_count = 0
            for pair in result['pairs']:
                raw_count += pair['gap_interval_raw_rows'].get(phase, 0)
                labelled_count += pair['gap_interval_provider_labelled_rows'].get(phase, 0)
                for sample in pair['selected']:
                    if phase not in sample['matching_gap_intervals']:
                        continue
                    when, _ = explicit_time(sample['raw_text'])
                    require(when is not None and window['start_epoch'] <= when.timestamp() <= window['end_epoch'],
                            'Selected record outside interval')
                    binding = sample['provider_binding']
                    require(binding is None or binding['record']['line'] == sample['raw_line'], 'Label coordinate differs')
                    observations.append({
                        'id': f'{env}:{sample["raw_member"]}:{sample["raw_line"]}',
                        'member': sample['raw_member'], 'line': sample['raw_line'],
                        'sha256': sample['raw_line_sha256'], 'timestamp_kst': sample['timestamp_kst'],
                        'facts': project_raw(sample),
                        'provider_labels': binding['record']['labels'] if binding else [],
                        'provider_label_source': {'member': sample['label_member'],
                            'line': binding['label_source_line'], 'sha256': binding['label_source_line_sha256']}
                            if binding else None,
                    })
            require(raw_count == official['raw_rows_in_interval_with_explicit_time'] and
                    labelled_count == official['provider_labelled_raw_rows_in_interval'], 'Interval counts differ')
            require(len({o['id'] for o in observations}) == len(observations), 'Duplicate source coordinates')
            expected_refs = {(s['member'], s['line'], s['line_sha256']) for s in official['sample_source_references']}
            require(expected_refs == {(o['member'], o['line'], o['sha256']) for o in observations}, 'Samples differ')
            av = aminer_by_env[env]['intervals'][phase]
            require(av['count'] == official['AMiner_objects'] and av['training_modes'] == official['AMiner_training_modes'],
                    'AMiner counts or training modes differ')
            # Exact shared raw text corroborates the same observation, not an
            # independent second execution/success event.
            bindings = []
            selected = {o['id']: o for o in observations}
            raw_lookup = {f'{env}:{s["raw_member"]}:{s["raw_line"]}': s['raw_text']
                          for p in result['pairs'] for s in p['selected']}
            examples = {x['source_line']: x for x in av['examples']}
            for b in official['exact_AMiner_to_LDS_sample_bindings']:
                ref = f'{env}:{b["raw_member"]}:{b["raw_line"]}'
                require(ref in selected, 'Cross-sensor source missing')
                example = examples[b['aminer_line']]
                require(raw_lookup[ref].rstrip('\r\n') in
                        [s.rstrip('\r\n') for s in example['raw_alert']['LogData']['RawLogData']],
                        'AMiner/raw text binding differs')
                bindings.append({'raw_id': ref, 'aminer_member': aminer_by_env[env]['member'],
                                 'aminer_line': b['aminer_line'], 'aminer_sha256': example['line_sha256'],
                                 'training_mode': example['component']['TrainingMode']})
            diary = []
            for line in result['attack_diary']['lines']:
                if line.endswith('dnsteal_stop'):
                    when = datetime.fromisoformat(line.rsplit(' ', 1)[0])
                    require(when.utcoffset() is not None, 'Diary timezone missing')
                    diary.append({'timestamp_kst': when.astimezone(KST).isoformat(), 'step': 'dnsteal_stop',
                                  'inside_phase_interval': window['start_epoch'] <= when.timestamp() <= window['end_epoch']})
            context = {'environment': env, 'phase_label': phase, 'start_kst': window['start_kst'],
                       'end_kst': window['end_kst'], 'ADS_Wazuh_Suricata_count': official['ADS_Wazuh_Suricata_records'],
                       'raw_interval_count': raw_count, 'provider_labelled_count': labelled_count,
                       'selected_count': len(observations), 'observations': observations,
                       'AMiner_count': av['count'], 'AMiner_training_modes': av['training_modes'],
                       'shared_observations': bindings}
            if phase == 'service_stop':
                require(len(diary) == 1 and not diary[0]['inside_phase_interval'],
                        'Service/diary relationship requires a fresh review')
                context['separate_execution_diary'] = {'member': result['attack_diary']['member'],
                    'sha256': result['attack_diary']['sha256'], 'steps': diary}
            assessment = make_assessment(context)
            cases.append({'id': f'ait-source-review:{env}:{phase}', 'family': phase,
                'split': 'historical_train_only', 'leakage_group': 'ait-lds-ads:' + env,
                'sources': ['https://doi.org/10.5281/zenodo.8263181', 'https://doi.org/10.5281/zenodo.5789064'],
                'source_licenses': ['CC-BY-4.0', 'CC-BY-NC-SA-4.0'],
                'review': {'facts': 'verified_against_source_coordinates', 'answer_author': 'project_agent',
                           'independent_expert_review': False, 'training_admitted': False,
                           'purpose': 'investigation_draft_not_official_incident_verdict'},
                'question': '경보가 안 보이는데 정상으로 종료해도 돼? 이 과거 시험자료의 근거와 다음 조사 항목을 정리해줘.',
                'context': context, 'draft_answer': assessment})
    require(len(cases) == 9 and len({c['id'] for c in cases}) == 9, 'Incomplete case coverage')
    return sorted(cases, key=lambda c: c['id'])


def make_assessment(context):
    phase = context['phase_label']
    facts = context['observations']
    if phase == 'reverse_shell':
        relevant = [o for o in facts if o['facts'].get('literal_tcp_endpoints_in_request')
                    and o['facts'].get('shell_command_requested')]
        require(bool(relevant), 'No request-level TCP shell evidence')
        conclusion = '역방향 접속을 지시하는 셸 문자열이 HTTP 요청에 포함되어 있어 우선 조사할 위험 정황입니다. 연결 성립이나 명령 실행 성공은 이 요청 기록만으로 확정할 수 없습니다.'
        next_evidence = ['해당 시각 웹 서버의 프로세스 실행·부모 자식 관계', '요청에 포함된 목적지로의 실제 통신과 연결 결과', '애플리케이션 실행 결과 및 후속 인증·감사 로그']
    elif phase == 'webshell':
        relevant = [o for o in facts if 'webshell_cmd' in o['provider_labels']]
        require(bool(relevant), 'No provider webshell request evidence')
        conclusion = '제공자가 webshell_cmd로 표시한 웹 요청과 인코딩된 명령 배열이 관측됩니다. 공격 관련 요청을 조사해야 하며 HTTP 응답만으로 호스트에서의 실행·침해 범위를 확정할 수 없습니다.'
        next_evidence = ['웹 업로드 파일과 애플리케이션 실행 결과', '웹 서버 프로세스·감사 로그', '후속 인증·권한 변경과 접근 범위']
    elif phase == 'service_stop':
        relevant = [o for o in facts if o['facts'].get('event_type') in ('SERVICE_START', 'SERVICE_STOP')]
        require({o['facts']['event_type'] for o in relevant} == {'SERVICE_START', 'SERVICE_STOP'}, 'Missing service event')
        conclusion = '같은 구간에 서비스 시작과 종료 기록이 있고 각 이벤트 결과는 별도로 확인해야 합니다. 단계 이름이나 dnsteal 라벨을 유출 성공·일반 서비스 장애·침해 제거 완료로 확대할 수 없습니다. 실행 일지의 dnsteal_stop은 시각이 다른 별도 관측으로 보존합니다.'
        next_evidence = ['해당 서비스의 정의·실행 대상과 종료 원인', 'DNS 질의·응답 및 수신 측 유출 결과', '실행 일지와 서비스 이벤트의 시간·역할 관계']
    else:
        raise ValueError('Unsupported review family')
    return {'conclusion': conclusion, 'evidence_refs': [o['id'] for o in relevant],
            'sensor_scope': f"선택된 공개 구간에서 Wazuh/Suricata {context['ADS_Wazuh_Suricata_count']}건, 명시 시각 원문 {context['raw_interval_count']}행, 제공자 라벨 {context['provider_labelled_count']}행, AMiner {context['AMiner_count']}객체입니다. 표본 수·전체 행 수·독립 사건 수는 다릅니다.",
            'limits': ['경보·라벨 부재를 정상이나 공격 실패로 판정하지 않습니다.',
                       'AMiner와 원문이 같은 행이면 독립 공격 성공 증거 두 건으로 세지 않습니다.',
                       'AMiner TrainingMode=true 관측은 운영 탐지 성공으로 세지 않습니다.',
                       '이 자료는 과거 시험망입니다. 현재 서버 상태나 현재 차단 대상으로 사용하지 않습니다.'],
            'next_evidence': next_evidence, 'management_status': 'needs_review',
            'live_action_taken': False, 'tools_called': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('results', 'report', 'aminer', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), 'Use a new output directory')
    report = json.loads(args.report.read_text())
    raw_aminer = args.aminer.read_bytes()
    require(sha(raw_aminer) == report['integrity']['AMiner_analysis_sha256'], 'AMiner input hash differs')
    cases = build_cases(verified_results(json.loads(args.results.read_text()), report), report, json.loads(raw_aminer))
    body = ''.join(json.dumps(c, ensure_ascii=False, sort_keys=True) + '\n' for c in cases)
    manifest = {'schema': 1, 'created_at_kst': datetime.now(KST).isoformat(), 'cases': len(cases),
                'environments': len({c['context']['environment'] for c in cases}),
                'status': 'source_bound_drafts_not_training_admitted', 'expert_reviews': 0,
                'new_training_examples_admitted': 0, 'GPU_training_started': False,
                'output_sha256': sha(body.encode()),
                'inputs_sha256': {k: sha(getattr(args, k).read_bytes()) for k in ('results', 'report', 'aminer')},
                'code_sha256': sha(Path(__file__).read_bytes()),
                'source_notice_sha256': sha(NOTICE.encode()),
                'rights': 'Derived LDS portions retain CC-BY-NC-SA-4.0; ADS CC-BY-4.0. Cite both datasets and papers.',
                'scope': 'Nine correlated historical phase windows in five training environments; not nine independent incidents or an unused evaluation set.'}
    args.output.mkdir(parents=True)
    (args.output / 'review-cases.jsonl').write_text(body)
    (args.output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    (args.output / 'SOURCE_NOTICE.txt').write_text(NOTICE)
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == '__main__':
    main()
