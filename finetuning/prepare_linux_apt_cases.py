"""Build source-bound SOC investigation drafts, not invented attack outcomes.

Reads only the two pinned source CSVs. No raw commands, paths, users, hosts or
network addresses are copied. Equality-preserving case-local aliases retain
correlation evidence. Questions/interpretation are project-authored and are
not institutional answers, independent incident gold, or admitted SFT.
"""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re

from prepare_linux_apt import RecordingLines, canonical, sha, source_time, safe_code

FILES = ('01-05-October.csv', '06-20-October.csv')
KST = timezone(timedelta(hours=9))
DESCRIPTIONS = {
    '202': 'Agent event queue is 90% full.',
    '203': 'Agent event queue is full. Events may be lost.',
    '204': 'Agent event queue is flooded. Check the agent configuration.',
    '205': 'Agent event queue is back to normal load.',
    '5710': 'sshd: Attempt to login using a non-existent user',
    '5503': 'PAM: User login failed.',
    '5715': 'sshd: authentication success.',
    '550': 'Integrity checksum changed.',
    '554': 'File added to the system.',
    '80730': 'Auditd: SELinux permission check.',
    '80705': 'Auditd: Configuration changed.',
    '80703': 'Auditd: Daemon End.',
    '5902': 'New user added to the system.',
    '5901': 'New group added to the system.',
    '5904': 'Information from the user was changed.',
}
CASES = [
    ('queue', FILES[1], None, '수집 큐는 정상 복귀했나? 그 전 누락 로그까지 복구됐다고 볼 수 있나?',
     '수집기 통계와 원본 로그를 대조해 유실 범위·재수집 가능성을 확인하고 재발 원인을 조사한다.'),
    ('auth', FILES[1], [2785, 2786, 1132, 1180], '이 네 기록만으로 같은 SSH 세션의 공격 성공을 확정할 수 있나?',
     '접속 승인·계정 소유자·세션 및 프로세스 기록을 추가 조회해 정상 접속과 침해를 구분한다.'),
    ('fim', FILES[1], [3669, 259], 'decoder가 syscheck_deleted이므로 두 파일 모두 삭제됐다는 판단이 맞나?',
     '원본 FIM 이벤트·파일 이력·승인된 변경을 대조하고 decoder 분류 차이를 확인한다.'),
    ('apparmor', FILES[1], [87], '이 경보의 실제 보안 모듈과 관측된 동작 결과를 원문 근거로 설명해줘.',
     '해당 정책·프로세스·주변 감사 기록을 확인하고 거부 원인 및 업무 영향을 조사한다.'),
    ('audit_config', FILES[1], [1701], '감사 설정 변경의 동작과 결과가 무엇인가? 파싱된 res 필드도 믿을 수 있나?',
     '원문 및 파서 경계를 확인하고 변경 주체·승인 이력·현재 감사 룰을 대조한다.'),
    ('audit_stop', FILES[1], [3539], '감사 데몬 종료 기록이 보이는데 공격자가 감사를 껐다고 단정할 수 있나?',
     '서비스 재시작·점검 승인·감사 로그 연속성을 확인하고 종료 구간의 수집 공백을 조사한다.'),
    ('account', FILES[0], [519, 520, 760], '계정 관련 세 기록의 순서와 확인 가능한 사실, 추가 확인 사항을 정리해줘.',
     '계정 생성 주체·설치 작업·변경 승인을 확인한다. 미승인 여부와 계정 용도를 조사한 뒤 대응안을 작성한다.'),
    ('missing_raw', FILES[0], [2], '이 SCA 경보에 원문 로그가 있는가? 경보만으로 실제 공격을 확인할 수 있나?',
     '구조화된 SCA 검사 결과와 실제 설정을 조회하고 공격 흔적은 별도의 사건 로그에서 확인한다.'),
]
NOTICE = """Linux-APT source-bound SOC investigation drafts
Source: Sohaib Karim, Linux-APT-Dataset-2024, DOI 10.5281/zenodo.10685642.
Dataset license: CC BY 4.0 https://creativecommons.org/licenses/by/4.0/
Paper: Karim et al., DOI 10.1016/j.dib.2024.110290 (paper license separate).
Changes: bounded record selection, source-byte coordinates/hashes, strict field
extraction, case-local entity aliases, raw payload omission, project-authored
Korean questions and interpretations. No institutional endorsement or expert
gold claim. Source times have unknown offset and are not converted to KST.
Same source family as every Linux-APT/Mendeley/SecCoRA derivative; not fresh
independent evaluation. Drafts are not automatically admitted to training.
"""


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_source(data, entry, checked):
    file_sha = sha(data)
    require(len(data) == entry['bytes'] and hashlib.md5(data).hexdigest() == entry['md5']
            and file_sha == checked['sha256'], 'Source integrity differs')
    lines = RecordingLines(data.decode('utf-8-sig'))
    reader = csv.reader(lines, strict=True)
    header = next(reader)
    require(len(header) == len(set(header)), 'Duplicate source columns')
    lines.take()
    previous, records = reader.line_num, {}
    for number, values in enumerate(reader, 1):
        raw = lines.take()
        start, end = previous + 1, reader.line_num
        previous = end
        require(len(values) == len(header), 'Source width differs')
        row = dict(zip(header, values))
        records[number] = (row, {
            'file': entry['name'], 'url': entry['url'], 'file_sha256': file_sha,
            'csv_record_number': number, 'physical_start_line': start,
            'physical_end_line': end, 'csv_record_bytes_sha256': sha(raw),
            'normalized_record_sha256': sha(canonical({k: v for k, v in row.items() if v.strip()}).encode()),
            'full_log_sha256': sha(row['_source.full_log'].encode()),
        })
    require(len(records) == checked['rows'], 'Source row count differs')
    return records


def raw_facts(row):
    text = row.get('_source.full_log', '')
    facts = {'raw_log_present': bool(text.strip())}
    buffer = re.fullmatch(r"wazuh: Agent buffer: '(90%|full|flooded|normal)'\.", text.strip())
    if buffer:
        facts['buffer_state'] = buffer[1]
    for name, pattern in (
        ('ssh_pid', r'\bsshd\[(\d+)\]'),
        ('audit_type', r'(?:^|\s)type=(AVC|CONFIG_CHANGE|DAEMON_END|ANOM_ABEND)\b'),
        ('audit_operation', r'(?:^|\s)op=(add_rule|delete_rule|terminate)\b'),
        ('audit_result', r'(?:^|[\s\x1d])res=(success|failed|0|1)(?=[\s\x1d]|$)'),
        ('apparmor_result', r'\bapparmor="(DENIED|ALLOWED)"'),
        ('apparmor_operation', r'\boperation="(capable|open|exec|file_mmap)"'),
        ('file_event', r"^File '[^']+' (added|modified|deleted)\b"),
    ):
        match = re.search(pattern, text)
        if match:
            facts[name] = match[1]
    if re.search(r'\bAccepted (?:password|publickey) for ', text):
        facts['authentication_observation'] = 'accepted'
    elif 'invalid user' in text.lower():
        facts['authentication_observation'] = 'invalid_user_mentioned'
    elif 'authentication failure' in text.lower():
        facts['authentication_observation'] = 'authentication_failure'
    for label, pattern in (('new_user', r'new user:'), ('new_group', r'new group:'),
                           ('account_information_changed', r'changed.*(?:information|info)')):
        if re.search(pattern, text, re.I):
            facts[label] = True
    value = row.get('_source.data.audit.res', '').strip()
    if value:
        facts['structured_audit_result_status'] = (
            'canonical' if re.fullmatch(r'(?:0|1|success|failed)', value) else 'noncanonical')
        if facts['structured_audit_result_status'] == 'canonical':
            facts['structured_audit_result'] = value
    event = row.get('_source.syscheck.event', '').strip()
    if event:
        facts['structured_file_event'] = event if event in ('added', 'modified', 'deleted') else 'unrecognized'
    return facts


def project_records(records, numbers):
    require(len(numbers) == len(set(numbers)) and all(n in records for n in numbers), 'Missing/repeated coordinates')
    aliases, output = {}, []

    def alias(kind, value):
        if not value:
            return None
        mapping = aliases.setdefault(kind, {})
        if value not in mapping:
            mapping[value] = f'{kind}-{len(mapping) + 1}'
        return mapping[value]

    for n in numbers:
        row, binding = records[n]
        when = source_time(row)
        require(when['status'] == 'timezone_unknown', 'Reviewed source clock assumption differs')
        agent = [row.get(k, '').strip() for k in ('_source.manager.name', '_source.agent.id', '_source.agent.name')]
        host = alias('agent', canonical(agent)) if all(agent) else None
        rid = row['_source.rule.id']
        description = row.get('_source.rule.description', '')
        output.append({
            'id': f'{binding["file"]}:{n}', 'source': binding, 'time': when,
            'reported_entities': {
                'agent': host, 'source': alias('source', row.get('_source.data.srcip', '').strip()),
                'destination_user': alias('user', row.get('_source.data.dstuser', '').strip()),
                'source_port': alias('port', row.get('_source.data.srcport', '').strip()),
                'file': alias('file', row.get('_source.syscheck.path', '').strip()),
            },
            'raw_observations': raw_facts(row),
            'detector_fields': {'rule_id': safe_code(rid),
                'decoder': safe_code(row.get('_source.decoder.name', '')),
                'description': description if description == DESCRIPTIONS.get(rid) else None,
                'description_sha256': sha(description.encode())},
            'payload_copied': False,
        })
    return sorted(output, key=lambda x: (x['time']['source_wall_time'], x['source']['csv_record_number']))


def interpret(kind, observations):
    facts = [x['raw_observations'] for x in observations]
    agents = {x['reported_entities']['agent'] for x in observations}
    require(None not in agents and len(agents) == 1, 'Reviewed case must share a reported agent')
    if kind == 'queue':
        states = [x.get('buffer_state') for x in facts]
        require(None not in states, 'Unrecognized buffer message')
        cycles, pending = 0, False
        for state in states:
            if state in ('90%', 'full', 'flooded'):
                pending = True
            elif state == 'normal' and pending:
                cycles += 1
                pending = False
        require(not pending and cycles > 0, 'Incomplete observed recovery sequence')
        counts = dict(Counter(states))
        return {'state_counts': counts, 'observed_returns_to_normal': cycles,
                'last_observed_state': states[-1], 'lost_events': None,
                'backfill_verified': False}, (
            f'제공된 기록에서 큐 상태 {counts}와 정상 복귀 {cycles}회를 관측했다. '
            '마지막 큐 상태는 normal이다. full 구간은 수집 유실 위험을 뜻하지만 유실 건수는 제시되지 않았다. '
            'normal은 큐 부하 복귀 기록이며 과거 누락 로그가 재수집됐다는 증거가 아니다.')
    if kind == 'auth':
        statuses = [x.get('authentication_observation') for x in facts]
        require(statuses.count('accepted') == 2 and 'invalid_user_mentioned' in statuses
                and 'authentication_failure' in statuses, 'Authentication evidence differs')
        sources = {x['reported_entities']['source'] for x in observations}
        pids = {x.get('ssh_pid') for x in facts}
        require(None not in sources and len(sources) == 1 and None not in pids and len(pids) == 4,
                'Source/session relation differs')
        require(any(x['reported_entities']['destination_user'] is None for x in observations),
                'Expected incomplete user linkage differs')
        return {'same_reported_agent_and_source': True, 'distinct_ssh_pids': 4,
                'same_session_proven': False, 'compromise_proven': False}, (
            '같은 보고 에이전트·출발지에서 존재하지 않는 사용자 언급과 PAM 인증 실패, 이후 SSH 인증 성공 2건이 보인다. '
            '네 기록의 sshd PID는 서로 다르고 실패 기록의 대상 사용자 정보도 빠져 있다. '
            '같은 세션이나 동일 계정 공격의 성공으로 연결할 근거는 부족하며, 승인된 접속인지도 확인되지 않았다.')
    if kind == 'fim':
        require({x.get('file_event') for x in facts} == {'added', 'modified'} and
                all(x.get('file_event') == x.get('structured_file_event') for x in facts) and
                all(x['detector_fields']['decoder'] == 'syscheck_deleted' for x in observations),
                'FIM discrepancy differs')
        return {'raw_structured_event_agree': True, 'decoder_name_is_deletion_evidence': False}, (
            '원문과 구조화 syscheck.event는 각각 modified와 added로 일치한다. '
            'decoder 이름은 두 기록 모두 syscheck_deleted이지만 이 이름만으로 삭제 사건으로 분류하면 안 된다. '
            '변경의 승인 여부나 악성 여부는 이 두 기록만으로 확인할 수 없다.')
    if kind == 'apparmor':
        require(len(facts) == 1 and facts[0].get('audit_type') == 'AVC' and
                facts[0].get('apparmor_result') == 'DENIED' and facts[0].get('apparmor_operation') == 'capable'
                and observations[0]['detector_fields']['description'] == DESCRIPTIONS['80730'],
                'AppArmor evidence differs')
        return {'observed_module': 'AppArmor', 'observed_result': 'DENIED'}, (
            '원문에는 type=AVC, apparmor=DENIED, operation=capable이 있어 AppArmor의 거부 기록으로 해석한다. '
            '룰 설명의 SELinux 명칭과 원문 모듈이 다르다. 이 기록은 특정 동작의 거부를 보여 주며 '
            '프로세스 전체 종료·공격 성공·해당 시스템의 모든 위협 차단을 증명하지 않는다.')
    if kind == 'audit_config':
        require(len(facts) == 1 and facts[0].get('audit_type') == 'CONFIG_CHANGE' and
                facts[0].get('audit_operation') == 'add_rule' and facts[0].get('audit_result') == '1'
                and facts[0].get('structured_audit_result_status') == 'noncanonical',
                'Audit result parsing evidence differs')
        return {'raw_operation': 'add_rule', 'raw_result': '1', 'structured_result_needs_parser_review': True}, (
            '원문 감사 기록은 CONFIG_CHANGE, op=add_rule, res=1이다. 구조화된 res에는 결과 외의 내용이 섞여 있어 '
            '그 전체 값을 단순 결과 코드로 해석하면 안 된다. 원문의 결과 코드와 파싱 이상을 구분하고 '
            '이 변경이 승인됐는지 또는 악성인지는 별도로 확인해야 한다.')
    if kind == 'audit_stop':
        require(len(facts) == 1 and facts[0].get('audit_type') == 'DAEMON_END' and
                facts[0].get('audit_operation') == 'terminate' and facts[0].get('audit_result') == 'success',
                'Audit daemon termination evidence differs')
        return {'termination_reported': True, 'subsequent_restart_verified': False}, (
            'DAEMON_END, op=terminate, res=success가 기록됐다. success는 이 감사 이벤트의 결과이며 공격 성공 판정이 아니다. '
            '제공된 한 기록에는 재시작·점검 승인·악성 중지 여부가 없어 수집 공백과 종료 원인을 추가 조사해야 한다.')
    if kind == 'account':
        require(len(facts) == 3 and facts[0].get('new_group') and facts[1].get('new_user')
                and facts[2].get('account_information_changed'), 'Account event sequence differs')
        return {'observed_order': ['new_group', 'new_user', 'account_information_changed'],
                'approval_evidence_present': False}, (
            '같은 보고 에이전트에서 원본 벽시각 기준 그룹 생성→사용자 생성→계정 정보 변경 순서가 보인다. '
            '각 원문에 해당 동작 표현이 있으나 승인된 설치 작업인지 공격자의 계정 생성인지는 확인되지 않았다. '
            '시간대가 없으므로 이 시각을 KST 또는 UTC로 단정하지 않는다.')
    require(kind == 'missing_raw' and len(facts) == 1 and not facts[0]['raw_log_present']
            and observations[0]['detector_fields']['decoder'] == 'sca', 'Missing raw-log case differs')
    return {'raw_log_missing': True, 'raw_attack_evidence_available': False}, (
        '이 SCA 기록의 full_log는 공백이다. 구조화된 검사 경보는 존재하지만 검토 입력에 원문 사건 로그는 없다. '
        '원문을 조회한 것처럼 답하거나 SCA 경보만으로 공격 발생을 확정할 수 없다.')


def build_cases(sources):
    cases = []
    for kind, filename, numbers, question, next_step in CASES:
        records = sources[filename]
        if numbers is None:
            numbers = [n for n, (row, _) in records.items() if row['_source.rule.id'] in ('202', '203', '204', '205')]
        observations = project_records(records, numbers)
        findings, assessment = interpret(kind, observations)
        cases.append({'case_id': 'linux-apt-' + kind,
            'source_family': 'linux-apt-2024-all-releases-and-derivatives',
            'task': question, 'evidence': observations,
            'source_scope': 'All 202/203/204/205 rows in the selected CSV' if kind == 'queue' else
                            'Explicitly selected original records; not a complete incident/window',
            'review_answer': {'findings': findings, 'assessment': assessment,
                              'next_investigation': next_step,
                              'evidence_ids': [x['id'] for x in observations]},
            'authorship': 'Real source observations; project-authored question, interpretation and follow-up',
            'status': 'source_bound_draft_not_independent_expert_gold',
            'training_admitted': False, 'tool_execution_performed': False,
            'production_state_inferred': False})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'Output already exists')
    root = Path(__file__).resolve().parent
    spec_bytes = (root / 'LINUX_APT_SOURCE_SPEC.json').read_bytes()
    report = json.loads((root / 'LINUX_APT_EVIDENCE_REVIEW.json').read_text())
    require(sha(spec_bytes) == report['source_manifest']['sha256'], 'Source manifest differs')
    entries = {x['name']: x for x in json.loads(spec_bytes)['files']}
    checked = {x['name']: x for x in report['complete_scan']['files']}
    sources = {name: read_source((args.source_dir / name).read_bytes(), entries[name], checked[name])
               for name in FILES}
    cases = build_cases(sources)
    args.output.mkdir()
    content = ''.join(canonical(x) + '\n' for x in cases).encode()
    (args.output / 'cases.jsonl').write_bytes(content)
    (args.output / 'NOTICE').write_text(NOTICE)
    manifest = {'schema': 1, 'created_at_kst': datetime.now(KST).isoformat(),
                'code_sha256': sha(Path(__file__).read_bytes()),
                'parser_sha256': sha((root / 'prepare_linux_apt.py').read_bytes()),
                'source_spec_sha256': sha(spec_bytes), 'source_files': [checked[n] for n in FILES],
                'case_count': len(cases), 'selected_record_count': sum(len(x['evidence']) for x in cases),
                'cases_sha256': sha(content), 'notice_sha256': sha(NOTICE.encode()),
                'training_admitted': 0, 'independent_incident_count_claimed': 0}
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
