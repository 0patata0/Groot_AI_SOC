"""Recheck 126 withheld V4 training observations against original source bytes.

Preserve frozen V4. Produce separate project-authored targets and evidence bindings,
not provider-certified answers, a new held-out test, or a training release.
"""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re
import zipfile

from audit_soc_observation_history import read_frozen
from prepare_data import canonical
from prepare_soc_observation_inputs import require, verified

KST = timezone(timedelta(hours=9))
KEV_HASH = '2d9931c086e42d05425c2da924299c8d9b7ff836de373f981668b7ef5f6f0fd7'
KEV_COMMIT = '30a09b6f3f7e2f03618cc8c95d212966d3c14e6e'
KEV_FIELDS = ('cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
              'shortDescription', 'requiredAction', 'dueDate', 'knownRansomwareCampaignUse', 'cwes')


def sha(raw):
    return hashlib.sha256(raw if isinstance(raw, bytes) else canonical(raw).encode()).hexdigest()


def evidence(case):
    return json.loads(case['messages'][1]['content'].rsplit('\n', 1)[1])


def explicit_kst(value):
    when = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(when.utcoffset() is not None, 'No timezone inference')
    return when.astimezone(KST).isoformat()


def verify_ads(root, cases):
    """Full processed-file hashes, exact rows, and original ZIP objects/CRC."""
    by_file = defaultdict(dict)
    for c in cases:
        for ref in c['review']['source_rows']:
            name = ref['source_file']
            require(re.fullmatch(r'datasets/processed/ait/[a-z]+\.labeled\.jsonl', name), 'Unexpected ADS path')
            by_file[name][ref['source_line']] = ref
    sources, proofs = {}, []
    original_needed = defaultdict(dict)
    for name, requested in sorted(by_file.items()):
        path = root / name
        require(not path.is_symlink(), 'Symlink ADS source')
        file_hash = hashlib.sha256()
        found = {}
        with path.open('rb') as stream:
            for number, raw in enumerate(stream, 1):
                file_hash.update(raw)
                if number in requested:
                    ref = requested[number]
                    require(sha(raw) == ref['source_line_sha256'], 'ADS selected row changed')
                    found[number] = json.loads(raw)
        require(set(found) == set(requested) and all(
            file_hash.hexdigest() == x['source_file_sha256'] for x in requested.values()), 'ADS file/coordinate mismatch')
        sources[name] = found
        for number, row in found.items():
            original = deepcopy(row);env = original.pop('ait_env');original.pop('phase_window')
            digest = sha(original)
            if original['id'] in original_needed[env]:
                require(original_needed[env][original['id']] == digest, 'Conflicting ADS identity')
            original_needed[env][original['id']] = digest
        proofs.append({'file': name, 'sha256': file_hash.hexdigest(), 'selected_rows': len(found)})
    total = sum(len(x) for x in original_needed.values())
    with zipfile.ZipFile(root / 'datasets/raw/ait-ads/ait_ads.zip') as archive:
        for env, expected in original_needed.items():
            matches = Counter()
            # Read to EOF so ZipFile validates member CRC, even after matches.
            with archive.open(env + '_wazuh.json') as stream:
                for raw in stream:
                    row = json.loads(raw)
                    if row.get('id') in expected:
                        require(sha(row) == expected[row['id']], 'Original ADS object differs')
                        matches[row['id']] += 1
            require(set(matches) == set(expected) and all(v == 1 for v in matches.values()),
                    'ADS original identity missing/repeated')
    for c in cases:
        payload = evidence(c)
        require(len(payload['evidence']) == len(c['review']['source_rows']) == 2, 'Expected two ADS observations')
        for obs, ref in zip(payload['evidence'], c['review']['source_rows']):
            row = sources[ref['source_file']][ref['source_line']]
            rule = row['rule']
            expected = {'source_id': row['id'], 'timestamp_kst': explicit_kst(row['@timestamp']),
                        'agent_id': row['agent']['id'], 'rule_id': str(rule['id']), 'level': rule['level'],
                        'description': rule['description'], 'groups': rule.get('groups', []),
                        'mitre_ids': rule.get('mitre', {}).get('id', []), 'phase_window': row['phase_window']}
            require(obs == expected, 'ADS prompt projection not bound to source')
    return {'processed_files': proofs, 'original_objects_verified': total,
            'original_ZIP_members_CRC_verified': len(original_needed),
            'phase_window_scope': 'Existing processed contextual annotation retained; not a malicious label or a newly verified raw-log fact'}


def audit_field(line, name):
    matches = re.findall(r'(?<![\w])' + re.escape(name) + r'=(?:"([^"]*)"|([^\s\'\"]+))', line)
    require(len(matches) <= 1, 'Ambiguous audit field: ' + name)
    return (matches[0][0] or matches[0][1]) if matches else None


def audit_time(line):
    matches = re.findall(r'audit\((\d+)\.(\d{1,6}):(\d+)\)', line)
    require(len(matches) == 1, 'Missing/ambiguous audit timestamp')
    seconds, fraction, serial = matches[0]
    when = datetime.fromtimestamp(int(seconds), KST).replace(microsecond=int(fraction.ljust(6, '0')))
    return when.isoformat(), serial


def verify_lds(raw, labels_raw, cases):
    lines = raw.splitlines(keepends=True)
    labels = {}
    for i, line in enumerate(labels_raw.splitlines(keepends=True), 1):
        item = json.loads(line)
        require(type(item['line']) is int and 1 <= item['line'] <= len(lines)
                and item['line'] not in labels and item['labels'], 'Bad/duplicate provider line label')
        labels[item['line']] = (i, line, item)
    for c in cases:
        ref, = c['review']['source_rows'];obs = evidence(c)
        require(sha(raw) == ref['source_file_sha256'] and sha(labels_raw) == ref['label_file_sha256'],
                'LDS selected member changed')
        data = lines[ref['source_line'] - 1]
        require(sha(data) == ref['source_line_sha256'] == obs['raw_line_sha256']
                and data.decode().rstrip('\n') == obs['raw_line'], 'LDS raw line mismatch')
        when, _ = audit_time(obs['raw_line'])
        require(when == obs['observed_at_kst'], 'LDS KST conversion differs')
        label = labels.get(ref['source_line'])
        if label:
            require(label[0] == ref['label_line'] and sha(label[1]) == ref['label_line_sha256']
                    and label[2]['labels'] == obs['provider_line_labels']
                    and label[2]['rules'] == obs['provider_rules'], 'LDS label binding differs')
        else:
            require(ref['label_line'] is None and ref['label_line_sha256'] is None
                    and obs['provider_line_labels'] == [] and obs['provider_rules'] == {}, 'Unlabelled row invented a label')
    return {'raw_sha256': sha(raw), 'label_sha256': sha(labels_raw), 'source_rows': len(lines),
            'provider_labelled_rows': len(labels), 'candidate_rows': len(cases),
            'whole_archive_checksum_verified': False}


def verify_kev(raw, cases):
    require(sha(raw) == KEV_HASH, 'Pinned KEV document differs')
    doc = json.loads(raw)
    selected = {}
    for c in cases:
        review = c['review'];obs = evidence(c)
        require(review['source_document_sha256'] == KEV_HASH and review['source_commit'] == KEV_COMMIT,
                'KEV version mismatch')
        pointer = review['source_json_pointer']
        require(re.fullmatch(r'/vulnerabilities/\d+', pointer), 'Unknown KEV pointer')
        row = doc['vulnerabilities'][int(pointer.rsplit('/', 1)[1])]
        require(sha(row) == review['source_record_sha256'], 'KEV record differs')
        expected = {k: row.get(k) for k in KEV_FIELDS}
        expected.update(catalog_version=doc['catalogVersion'], source_commit=KEV_COMMIT,
                        released_at_kst=explicit_kst(doc['dateReleased']))
        require(obs == expected, 'KEV prompt differs from original fields')
        require(row.get('forensicTriage') in ('Yes', 'No') and isinstance(row.get('notes'), str),
                'Unknown forensicTriage/notes representation; manual review required')
        selected[c['id']] = row
    return selected, {'document_sha256': KEV_HASH, 'catalog_version': doc['catalogVersion'],
                      'source_commit': KEV_COMMIT, 'selected_records': len(selected),
                      'forensicTriage_counts': dict(Counter(x['forensicTriage'] for x in selected.values()))}


def ads_answer(payload):
    rows = payload['evidence']
    require(len(rows) == 2, 'Missing ADS observation')
    times = [datetime.fromisoformat(x['timestamp_kst']) for x in rows]
    require(all(t.utcoffset() == timedelta(hours=9) for t in times) and times[0] <= times[1], 'ADS order/zone differs')
    equal = times[0] == times[1]
    relation = ('두 기록의 표시 시각이 같아 이 시각만으로 선후관계를 정할 수 없습니다. 아래 순서는 입력의 나열 순서입니다.' if equal
                else '표시된 KST 시각상 첫 번째 기록이 두 번째 기록보다 앞섭니다. 발생 원인이나 같은 행위자의 연속 행동까지 증명하지는 않습니다.')
    lines = [payload['archive_case_id'] + ': 역사 시험장 표본2건입니다.', relation]
    for row in rows:
        lines.append(f"{row['timestamp_kst']} | 증거 {row['source_id']} | agent {row['agent_id']} | rule {row['rule_id']} | level {row['level']} | {row['description']}")
        lines.append('해당 센서의 groups=' + canonical(row['groups']) + ', mitre_ids=' + canonical(row['mitre_ids'])
                     + ', 시간 구간 컨텍스트 phase_window=' + str(row['phase_window']))
    lines.extend([
        '센서의 rule/level/groups/mitre_ids는 경보 주석입니다. attack 그룹이나 기법 ID가 있어도 원행에서 그 공격이 성공했거나 침해가 확정됐다는 뜻은 아닙니다. 빈 기법 목록도 공격 부재의 증명이 아닙니다.',
        'phase_window는 시나리오 시간 구간이며 개별 악성 정답이 아닙니다. normal 구간도 전체 정상 판정을 뜻하지 않습니다.',
        ('높은 센서 레벨 경보의 원문·관련 호스트/인증 증거를 우선 대조하되 실제 자산 위험과 동일시하지 않습니다.'
         if max(x['level'] for x in rows) >= 10 else '센서 레벨만으로 종결하지 않고 관련 인증·프로세스·네트워크 증거를 대조합니다.'),
        '표본 밖 전체 사건 수·영향 범위·현재 운영 상태는 미확인입니다. 이 과거 자료로 현재 MCP 조회나 차단을 실행하지 않았습니다. 추가 증거와 시험장 시나리오를 대조해 인계합니다.',
        'MANAGEMENT_STATUS: needs_review'])
    return '\n'.join(lines), {'equal_displayed_time': equal, 'sensor_MITRE_annotation_present': any(x['mitre_ids'] for x in rows)}


def lds_answer(obs):
    when, serial = audit_time(obs['raw_line'])
    fields = {k: audit_field(obs['raw_line'], k) for k in
              ('type', 'pid', 'uid', 'auid', 'ses', 'op', 'acct', 'exe', 'hostname', 'addr', 'terminal', 'res')}
    labels = obs['provider_line_labels']
    lines = [f"증거 {obs['evidence_id']} | {when} KST | audit serial={serial}",
             '직접 관측 필드(null은 원문 미기록): ' + canonical(fields),
             '제공자 행 라벨=' + canonical(labels) + ', 라벨 규칙=' + canonical(obs['provider_rules']),
             ('원문과 연결된 제공자 공격 연관 라벨입니다. 해당 규칙의 판정이며 모든 단계의 성공 증명은 아닙니다.' if labels else
              '짝지은 제공자 라벨 파일에서 이 행의 공격 연관 주석이 없습니다. 제공 데이터셋의 비공격 분류 범위이며 이 행·호스트가 무해하다고 독립적으로 입증한 것은 아닙니다.'),
             'res는 해당 로그 이벤트 결과입니다. success가 있어도 전체 공격 성공·침해 범위·정보 탈취를 확정하지 않습니다. 계정/실행 파일/인증 결과와 관련 프로세스·네트워크 기록을 추가 대조합니다.',
             '원문 행 SHA256=' + obs['raw_line_sha256'] + '. 현재 자산 상태·실행한 대응은 이 역사자료에서 확인하지 못했습니다.',
             'MANAGEMENT_STATUS: needs_review']
    return '\n'.join(lines), {'provider_attack_annotation': bool(labels), 'audit_fields': fields}


def kev_answer(obs):
    require(obs['forensicTriage'] in ('Yes', 'No'), 'No unknown-to-No coercion')
    lines = [f"{obs['cveID']}: CISA KEV 수집본 {obs['catalog_version']}, 공급자={obs['vendorProject']}, 제품={obs['product']}.",
             '취약점 이름(제공자 원문): ' + obs['vulnerabilityName'],
             '취약 행위 설명(제공자 원문; 현재 자산의 발생 증거 아님): ' + obs['shortDescription'],
             f"dateAdded={obs['dateAdded']}, dueDate={obs['dueDate']}. 날짜만 있는 필드에는 시각·시간대를 만들거나 변환하지 않습니다.",
             'cwes=' + canonical(obs['cwes']) + ', knownRansomwareCampaignUse=' + str(obs['knownRansomwareCampaignUse']) + '.',
             'Unknown은 알려진 사용 여부가 이 필드에서 미확정이라는 뜻이며 사용되지 않았다는 증거가 아닙니다.'
             if obs['knownRansomwareCampaignUse'] == 'Unknown' else
             '랜섬웨어 관련 사용 표시는 제공 카탈로그의 기록이며 우리 자산의 감염을 입증하지 않습니다.',
             'forensicTriage=' + obs['forensicTriage'] + '. ' + (
                 '수집본에 포렌식 검토 대상으로 표시되어 있어 이 항목을 인계 우선 확인사항에 포함합니다.'
                 if obs['forensicTriage'] == 'Yes' else
                 '수집본의 표시값이며 모든 사건에서 포렌식 검토가 불필요하다는 결론은 아닙니다.'),
             '제공 requiredAction 원문: ' + obs['requiredAction'],
             '제공 notes/참조: ' + obs['notes'],
             '이는 제공자가 알려진 악용 취약점으로 수록한 수집본의 근거입니다. 우리 서버의 설치·버전·노출·침해는 미확인입니다. 자산과 취약 범위를 대조한 뒤 제공 조치·포렌식 표시/참조와 최신 공식 지침을 검토하고 우리 승인·기한 정책에 따라 변경안을 준비합니다. dueDate를 우리 조직의 확정 기한으로 자동 적용하지 않습니다.',
             '현재 판단에는 최신 카탈로그·자산 증거를 재조회해야 합니다. 패치·차단·이미징을 실행하지 않았으며 사후 확인도 미완료입니다.',
             'MANAGEMENT_STATUS: needs_review']
    return '\n'.join(lines), {'forensicTriage': obs['forensicTriage'], 'knownRansomwareCampaignUse': obs['knownRansomwareCampaignUse']}


def build(root, kev_path, lds_raw_path, lds_labels_path, output):
    require(not output.exists(), 'Output already exists')
    fine = root / 'finetuning'
    require(json.loads((fine / 'V4_DATA_REVIEW.json').read_text())['decision'] == 'withheld', 'Reassess changed V4 decision')
    spec = json.loads((fine / 'V4_TRAINING_INPUTS.json').read_text())
    cases, frozen = read_frozen(fine, spec)
    chosen = [c for c in cases if c['split'] == 'train' and c['review']['evidence_kind'] in
              ('public_testbed_log', 'public_institutional_record')]
    require(Counter(c['review']['workflow'] for c in chosen) ==
            {'archive_investigation': 72, 'labelled_host_investigation': 18, 'kev_triage': 36}, 'Unexpected review pool')
    flows = {name: [c for c in chosen if c['review']['workflow'] == name] for name in
             ('archive_investigation', 'labelled_host_investigation', 'kev_triage')}
    proofs = {'ADS': verify_ads(root, flows['archive_investigation']),
              'LDS': verify_lds(lds_raw_path.read_bytes(), lds_labels_path.read_bytes(), flows['labelled_host_investigation'])}
    kev_rows, proofs['KEV'] = verify_kev(kev_path.read_bytes(), flows['kev_triage'])
    original_rows = {r['id']: r for r in map(json.loads, (fine/spec['data_folder']/'train.jsonl').read_text().splitlines())}
    revised, lineage, source_records = [], [], []
    for c in chosen:
        row = deepcopy(original_rows[c['id']]);old = deepcopy(row)
        require(not row['tools'] and [m['role'] for m in row['messages']] == ['system', 'user', 'assistant'],
                'Unexpected tool/role in observational example')
        payload = evidence(c);flow = c['review']['workflow']
        if flow == 'archive_investigation':
            answer, details = ads_answer(payload)
        elif flow == 'labelled_host_investigation':
            answer, details = lds_answer(payload)
        else:
            original = kev_rows[c['id']]
            payload.update(forensicTriage=original['forensicTriage'], notes=original['notes'])
            row['messages'][1]['content'] = row['messages'][1]['content'].rsplit('\n', 1)[0] + '\n' + canonical(payload)
            answer, details = kev_answer(payload)
            source_records.append({'id': c['id'], 'pointer': c['review']['source_json_pointer'],
                                   'source_record': original, 'source_record_sha256': sha(original)})
        row['messages'][-1]['content'] = answer
        row['provenance']['target_refinement'] = {'version': 'v4-observation-review-20261030',
            'original_record_sha256': sha(old), 'original_source_case_sha256': sha(c),
            'authorship': 'project-authored, source-bound; not independent expert gold',
            'original_withheld_decision_preserved': True}
        revised.append(row)
        lineage.append({'id': row['id'], 'original_record_sha256': sha(old), 'record_sha256': sha(row),
                        'source_case_sha256': sha(c), 'workflow': flow, 'source_uri': c['source_uri'],
                        'source_review': c['review'], 'license': c['license'], 'findings': details,
                        'input_changed': flow == 'kev_triage', 'target_changed': answer != old['messages'][-1]['content'],
                        'partition': 'historical_training_candidate_only', 'training_admitted': False})
    raw = ''.join(canonical(r)+'\n' for r in revised).encode()
    trace = ''.join(canonical(r)+'\n' for r in lineage).encode()
    manifest = {'schema': 1, 'at_kst': datetime.now(KST).isoformat(),
        'status': 'source_rechecked_refined_candidates_not_training_release', 'training_admitted': 0,
        'records': len(revised), 'dialogues_sha256': sha(raw), 'lineage_sha256': sha(trace),
        'frozen_V4': frozen, 'source_verification': proofs,
        'findings': {'equal_time_pairs': sum(x['findings'].get('equal_displayed_time', False) for x in lineage),
                     'sensor_MITRE_annotated_pairs': sum(x['findings'].get('sensor_MITRE_annotation_present', False) for x in lineage),
                     'forensicTriage_previously_omitted': 36, 'forensicTriage_Yes_previously_omitted': proofs['KEV']['forensicTriage_counts'].get('Yes', 0),
                     'KEV_input_fields_added': ['forensicTriage', 'notes'], 'inputs_changed': 36,
                     'targets_changed': sum(x['target_changed'] for x in lineage)},
        'original_rows_and_held_out_splits_unchanged': True,
        'source_labels_are_not_local_compromise_or_independent_expert_answers': True,
        'actual_tokenizer_checked': False, 'independent_final_evaluation': False,
        'limitations': ['All targets remain project-authored; source verification is not independent expert validation.',
                       'AIT is a research testbed; sensor ATT&CK tags and phase windows are not success/compromise proof.',
                       'Historical CISA fields are not current asset exposure or automatic organizational deadlines.',
                       'No tools, current services, model responses or training were executed by this preparation.']}
    files = {'candidate-dialogues.jsonl': raw, 'lineage.jsonl': trace,
             'KEV_SOURCE_RECORDS.jsonl': ''.join(canonical(r)+'\n' for r in source_records).encode(),
             'AIT_NOTICE.txt': (fine/'data-soc-observation-candidate-20261030-r2/AIT_NOTICE.txt').read_bytes()}
    files['SOURCE_NOTICE.txt'] = (
        'Historical V4 training observations, reviewed from pinned source records. No new incidents.\n'
        'CISA KEV: https://github.com/cisagov/kev-data/tree/'+KEV_COMMIT+' (CC0-1.0).\n'
        'AIT LDS/ADS: see AIT_NOTICE.txt; LDS derived content retains CC BY-NC-SA 4.0.\n'
        'Changes: explicit tied-time uncertainty, sensor annotation scope, literal audit fields,\n'
        'source-bound KEV forensicTriage/notes added, specific provider description/action preserved.\n'
        'Questions and Korean interpretations are project-authored, not institutional endorsement.\n'
        'Original source-case hashes, exact row coordinates, labels and licences are in lineage.\n'
        'No raw source collection is certified complete; selected LDS members only, no whole ZIP MD5.\n'
        'Candidate review only; not admitted SFT, not an independent unseen final evaluation.\n').encode()
    manifest['support_files'] = {n: sha(v) for n,v in files.items() if n not in ('candidate-dialogues.jsonl', 'lineage.jsonl')}
    output.mkdir(parents=True, exist_ok=False)
    for n,v in files.items(): (output/n).write_bytes(v)
    (output/'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n')
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--kev', type=Path, required=True)
    p.add_argument('--lds-audit', type=Path, required=True)
    p.add_argument('--lds-labels', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    report = build(args.root, args.kev, args.lds_audit, args.lds_labels, args.output)
    print(json.dumps({'status': report['status'], 'records': report['records'], 'findings': report['findings']}))


if __name__ == '__main__': main()
