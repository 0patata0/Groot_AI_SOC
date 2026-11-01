"""Prepare reviewed source candidates before transfer; never fabricate tool traces.

No raw archives/research-model answers go into this bundle. Source candidates
are deliberately not SFT messages and cannot be called training-ready.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
from collect_defensive_sources import now, sha, write
from collect_excytin_evidence import csv_records
from review_investigation_sources import canonical, separate_labels, target_present, write_jsonl


def read_rows(path): return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def scrub_secrets(value):
    """Redact explicit credential fields without interpreting embedded commands."""
    removed = []
    def scrub(x, path=''):
        if isinstance(x, dict):
            out = {}
            for key, val in x.items():
                compact = re.sub(r'[^a-z]', '', key.casefold())
                if compact in {'password','passwd','clientsecret','accesstoken','refreshtoken','authorization','privatekey','apikey'} and val:
                    removed.append(path+key); out[key] = '[REDACTED_CREDENTIAL_FIELD]'
                else: out[key] = scrub(val, path+key+'.')
            return out
        if isinstance(x, list): return [scrub(y, path+str(i)+'.') for i,y in enumerate(x)]
        return x
    return scrub(value), removed


def normalize_row(row):
    result = {}
    for key, value in row.items():
        # Only decode actual valid JSON containers; malformed cells stay out of this bundle.
        stripped = value.strip()
        if stripped.startswith(('{','[')):
            try: result[key] = json.loads(stripped)
            except json.JSONDecodeError: raise ValueError('Malformed embedded JSON field: '+key)
        else: result[key] = None if value == '' else value
    result, labels = separate_labels(result)
    result, redactions = scrub_secrets(result)
    return result, labels, redactions


def eligible_question(row):
    return (row['provisional_partition'] in ('training_source_candidate','reserved_evaluation_family')
            and not row['issues'] and row['target_text_present_in_selected_logs']
            and row['training_admitted'] is False)


def prepare(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    if not root.name.startswith('data-') or not output.name.startswith('data-') or root == output:
        raise ValueError('Use distinct ignored data-* directories')
    if output.exists(): raise ValueError('Output exists; preserve prior clean bundle')
    audit = json.loads((root/'review/audit.json').read_text())
    if audit['training_admitted'] != 0 or audit['production_changed']: raise ValueError('Unexpected source review state')
    if audit['excytin']['cross_partition_shared_alert_ids_in_selected_tables'] != 0:
        raise ValueError('Shared alerts cross source partitions')
    questions = read_rows(root/'review/investigation-questions.jsonl')
    observations = read_rows(root/'review/simulated-observations.jsonl')
    csv_receipt = json.loads((root/'excytin-evidence/collect-receipt.json').read_text())
    expected_csv = {x['path']:x for x in csv_receipt['files']}
    wanted = defaultdict(set)
    for row in questions:
        if eligible_question(row):
            for hit in row['target_text_hits']: wanted[hit['path']].add(hit['line'])
    evidence, bad_evidence = {}, {}
    for name, lines in wanted.items():
        data = (root/'excytin-evidence/raw'/name).read_bytes()
        if sha(data) != expected_csv[name]['sha256']: raise ValueError('CSV changed since review')
        for line, raw in csv_records(data):
            if line not in lines: continue
            key = (name, line)
            try: observed, labels, redactions = normalize_row(raw)
            except ValueError as error: bad_evidence[key] = str(error); continue
            eid = sha((expected_csv[name]['sha256']+':'+str(line)).encode())
            evidence[key] = {'id':eid, 'source_archive_revision':'8bc9ce1f97f8a6880c815dfba76d88651ddb761a',
                             'source_member':name, 'source_sha256':expected_csv[name]['sha256'],
                             'source_start_line':line, 'observed':observed,
                             'provider_annotation_fields_separated':len(labels), 'redacted_fields':redactions,
                             'scope':'Retrospective detector/incident evidence; not complete raw telemetry or live MCP response',
                             'timestamp_policy':'Preserve source timestamps; project presentation must use KST'}
    bundles = {'investigation-train-candidates':[], 'investigation-eval-reserved':[],
               'observations-train-candidates':[], 'observations-eval-reserved':[]}
    exclusions, by_partition = [], {'train':{}, 'eval':{}}
    for row in questions:
        reasons = list(row['issues'])
        if row['provisional_partition']=='provider_test_excluded_from_training': reasons.append('provider_test_never_train')
        if not eligible_question(row):
            exclusions.append({'id':row['id'], 'kind':'question', 'reasons':reasons or ['not_eligible']});continue
        hits = [evidence[(h['path'],h['line'])] for h in row['target_text_hits'] if (h['path'],h['line']) in evidence]
        hits = [hit for hit in hits if target_present(row['provider_target'], canonical(hit['observed']))]
        if not hits:
            exclusions.append({'id':row['id'],'kind':'question','reasons':['no_target_support_after_structural_cleaning']});continue
        p = 'train' if row['provisional_partition']=='training_source_candidate' else 'eval'
        for hit in hits: by_partition[p][hit['id']] = hit
        cleaned = {'id':row['id'], 'source':'microsoft_excytin', 'base_incident':row['incident'],
                   'provider_split':row['provider_split'], 'input':row['input'],
                   'provider_answer_candidate':row['provider_target'], 'evidence_ids':[x['id'] for x in hits],
                   'source_path':row['source_path'], 'source_sha256':row['source_sha256'],
                   'quality':'Source-linked candidate; target presence does not prove causal checkpoint correctness',
                   'training_admitted':False}
        bundles['investigation-train-candidates' if p=='train' else 'investigation-eval-reserved'].append(cleaned)
    for row in observations:
        if row.get('issues'):
            exclusions.append({'id':row['id'],'kind':'simulated_observation','reasons':row['issues']});continue
        observed, labels = separate_labels(row['input'])
        if labels: raise ValueError('Provider labels survived observation review')
        observed, redactions = scrub_secrets(observed)
        if redactions:
            exclusions.append({'id':row['id'],'kind':'simulated_observation','reasons':['explicit_credential_field']});continue
        p = 'train' if row['provisional_partition']=='training_source_candidate' else 'eval'
        bundles['observations-train-candidates' if p=='train' else 'observations-eval-reserved'].append(
            {'id':row['id'], 'base_incident':row['incident'], 'variant':row['variant'], 'table':row['table'],
             'observed':observed, 'origin':'Provider mock fixture, not production log', 'training_admitted':False})
    train_cases = {x['base_incident'] for k,v in bundles.items() if 'train-' in k for x in v}
    eval_cases = {x['base_incident'] for k,v in bundles.items() if 'eval-' in k for x in v}
    if train_cases & eval_cases: raise ValueError('Incident leakage across bundle partitions')
    if set(by_partition['train']) & set(by_partition['eval']): raise ValueError('Evidence leakage across partitions')
    output.mkdir()
    for name, rows in bundles.items(): write_jsonl(output/(name+'.jsonl'), rows)
    for name, rows in by_partition.items(): write_jsonl(output/('evidence-'+name+'.jsonl'), list(rows.values()))
    write_jsonl(output/'exclusions.jsonl', exclusions)
    licenses = output/'licenses'; licenses.mkdir()
    for name,p in [('MICROSOFT-MIT.txt',root/'raw/microsoft_aces/LICENSE'),
                   ('MICROSOFT-NOTICE.md',root/'raw/microsoft_aces/NOTICE.md'),
                   ('EXCYTIN-DATA-CARD.md',root/'metadata/excytin-card-pinned.md'),
                   ('EXCYTIN-TRANSPARENCY.md',root/'metadata/excytin_transparency'),
                   ('CDLA-Permissive-2.0.txt',root/'metadata/CDLA-Permissive-2.0.txt')]:
        (licenses/name).write_bytes(p.read_bytes())
    for name, src in [('SOURCE-SPEC.json',Path(__file__).with_name('INVESTIGATION_SOURCE_SPEC.json')),
                      ('SOURCE-REVIEW.json',root/'review/audit.json')]: (output/name).write_bytes(src.read_bytes())
    manifest = {'prepared_at_kst':now(), 'status':'cleaned_source_candidates_NOT_SFT_admitted',
                'counts':{k:len(v) for k,v in bundles.items()},
                'evidence_counts':{k:len(v) for k,v in by_partition.items()},
                'excluded':len(exclusions), 'exclusion_reasons':dict(Counter(r for x in exclusions for r in x['reasons'])),
                'malformed_embedded_json_evidence_rows_held':len(bad_evidence),
                'train_incidents':sorted(train_cases), 'reserved_eval_incidents':sorted(eval_cases),
                'source_incident_components':audit['excytin']['family_components'],
                'raw_archives_included':False, 'research_model_traces_included':False,
                'provider_checkpoint_prose_or_synthetic_tool_trajectories_included':False,
                'remaining_gates':['Causal checkpoint/answer review, not simple target presence',
                                   'Current MCP schemas and exact-approval/post-check/rollback conversion',
                                   'Privacy and license attribution of final derivatives',
                                   'Real tokenizer limits and independent critical-error evaluation'],
                'ready_for_gpu_training':False, 'training_admitted':0, 'production_changed':False}
    (output/'README.md').write_text('# 정제한 조사 자료 후보\n\n원문 전체와 모델 생성 조사 답변은 반입하지 않습니다. 정답 노출·근거 미연결·중복·과거 공통 문자열·분할 충돌 항목을 제외했습니다.\n\n이 묶음은 출처가 연결된 **학습 전 검수 후보**이며 SFT messages가 아닙니다. 정답 문자열이 로그에 존재하는 것과 인과적 조사 정답은 다릅니다. MCP 실행·정확 후보 승인·사후확인 기록을 만들어냈다고 표시하지 않습니다. `ready_for_gpu_training=false`이며 운영/학습 설정에 자동 연결하지 않습니다.\n\n`evidence-*.jsonl`의 식별자로 선택한 원로그 행·원파일 SHA·실제 CSV 시작행을 추적합니다. 관측 원시각은 보존하며 프로젝트 출력은 KST입니다. 명령·URL은 조사 대상 데이터로만 취급합니다. 공급자 합성 Azure 환경/그래프 생성 질문이라는 성격과 기관 문서·각 파일의 이용조건을 보존합니다. 공유 경보가 없는 사건134/166과 모든 변형은 평가 보존, 나머지6사건은같은경보로연결되므로한분할로묶고해당공급자test질문도학습제외합니다.\n')
    manifest['files'] = [{'path':str(p.relative_to(output)), 'bytes':p.stat().st_size, 'sha256':sha(p.read_bytes())}
                         for p in sorted(output.rglob('*')) if p.is_file()]
    write(output/'MANIFEST.json', manifest)
    return manifest


def validate_bundle(root):
    root = Path(root).resolve(); manifest = json.loads((root/'MANIFEST.json').read_text())
    if manifest['ready_for_gpu_training'] or manifest['training_admitted'] != 0:
        raise ValueError('Source-candidate safety gate missing')
    expected = {x['path']:x for x in manifest['files']}
    if set(expected) != {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and p.name not in ('MANIFEST.json','transfer-receipt.json','validation.json')}:
        raise ValueError('Unexpected or missing clean-bundle file')
    for name, item in expected.items():
        p=root/name
        if p.is_symlink() or not p.resolve().is_relative_to(root): raise ValueError('Unsafe bundle path')
        data=p.read_bytes()
        if sha(data)!=item['sha256'] or len(data)!=item['bytes']: raise ValueError('Clean bundle changed')
    alert_ids = {'train':set(), 'eval':set()}; cases = {'train':set(), 'eval':set()}
    for part, qname, oname in [('train','investigation-train-candidates','observations-train-candidates'),
                               ('eval','investigation-eval-reserved','observations-eval-reserved')]:
        evidence = {x['id']:x for x in read_rows(root/('evidence-'+part+'.jsonl'))}
        questions = read_rows(root/(qname+'.jsonl')); observations = read_rows(root/(oname+'.jsonl'))
        if len(questions)!=manifest['counts'][qname] or len(observations)!=manifest['counts'][oname]:
            raise ValueError('Bundle count mismatch')
        for q in questions:
            if q['training_admitted'] or part=='train' and q['provider_split']!='train':
                raise ValueError('Provider evaluation row admitted to training')
            if not q['evidence_ids'] or any(e not in evidence for e in q['evidence_ids']):
                raise ValueError('Unresolved evidence pointer')
            if not any(target_present(q['provider_answer_candidate'],canonical(evidence[e]['observed'])) for e in q['evidence_ids']):
                raise ValueError('Source answer unlinked after cleaning')
            cases[part].add(q['base_incident'])
        for o in observations:
            if o['training_admitted'] or separate_labels(o['observed'])[1]: raise ValueError('Leaked observation label')
            cases[part].add(o['base_incident'])
        for e in evidence.values():
            if separate_labels(e['observed'])[1]: raise ValueError('Leaked evidence label')
            for key in ('SystemAlertId','AlertId'):
                value=e['observed'].get(key)
                if isinstance(value,str) and len(value.strip())>=20:alert_ids[part].add(value.strip().casefold())
    if cases['train']&cases['eval'] or alert_ids['train']&alert_ids['eval']:
        raise ValueError('Incident or alert leakage across partitions')
    return {'at_kst':now(),'files_sha256_verified':len(expected),'counts':manifest['counts'],
            'cross_partition_incidents':0,'cross_partition_alert_ids':0,'source_answers_linked_after_cleaning':True,
            'training_admitted':0,'ready_for_gpu_training':False,
            'scope':'Structure/provenance/linkage/partition checks; not semantic correctness or token validation'}


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path);p.add_argument('--validate',action='store_true')
    a=p.parse_args()
    if a.validate:result=validate_bundle(a.root)
    else:
        if a.output is None:p.error('--output is required for preparation')
        result=prepare(a.root,a.output)
    print(json.dumps({k:v for k,v in result.items() if k!='files'},ensure_ascii=False))
