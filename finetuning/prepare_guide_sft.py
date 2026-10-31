"""Source-labelled retrospective GUIDE triage; never invent investigation/actions.

The complete selected source is audited first. Keep all rows of admitted incidents
under an explicit feature projection. Oversize/ambiguous cases are quarantined,
not truncated. Final token admission is a separate pinned-tokenizer stage.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
from zoneinfo import ZoneInfo
import audit_guide_evidence as audit

GRADES=('TruePositive','FalsePositive','BenignPositive')
SOURCE_SHA='f333a2750d165ff92df6dbdc26e113d5aafa8403e1110d4583013d9376e120b9'
SOURCE_URL='https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction'
KEEP=('Timestamp','Category','MitreTechniques','EntityType')
FORBIDDEN=('IncidentGrade','ActionGrouped','ActionGranular','LastVerdict','SuspicionLevel','EvidenceRole','ThreatFamily')
SYSTEM=('익명화된 과거 보안 사건의 사후 경보 분류 작업이다. 제공된 경보 특징으로 '
        'TruePositive, FalsePositive, BenignPositive 중 하나를 분류한다. '
        '출력은 classification 필드 하나의 JSON이다. 익명화 번호를 실제 IP·계정·파일로 '
        '해석하지 않는다. 이 분류는 실시간 공격 확정, 변경 승인 또는 조치 성공을 뜻하지 않는다.')


def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def org_split(org):
    # Split by organization before token filtering or class quota selection.
    bucket=int(hashlib.sha256(('groot-guide-org-v1:'+org).encode()).hexdigest()[:8],16)%100
    return 'train' if bucket<80 else 'validation' if bucket<90 else 'test'


def observation(record):
    date=datetime.fromisoformat(record['Timestamp'].replace('Z','+00:00'))
    if date.tzinfo is None: raise ValueError('Missing source timezone')
    return {'time_kst':date.astimezone(ZoneInfo('Asia/Seoul')).isoformat(),
            'category':record['Category'],'mitre_techniques':record['MitreTechniques'],
            'entity_type':record['EntityType']}


def make_case(key, items, grade):
    if grade not in GRADES: raise ValueError('Missing/unknown grade cannot become benign')
    counts=Counter(canonical(observation(item['record'])) for item in items)
    # Counts preserve repeated projected observations; full source references remain in the sidecar.
    features={'observed_rows':len(items),'observations':[
        {**json.loads(value),'count':count} for value,count in sorted(counts.items())]}
    prompt='다음 과거 사건의 경보 특징을 사후 분류해줘.\n'+canonical(features)
    record={'id':'guide-v2-'+key[0]+'-'+key[1], 'source':'microsoft-guide-v2-retrospective-triage',
        'provenance':{'source_uri':SOURCE_URL,'license':'CDLA-Permissive-2.0',
          'scenario_group':'guide-org-'+key[0], 'original_split':'GUIDE_Train.csv',
          'source_selected_sha256':SOURCE_SHA,'target_field':'IncidentGrade',
          'target_authorship':'provider label; project-authored prompt and feature projection',
          'scope':'retrospective triage; not decision-time or MCP execution supervision'},
        'messages':[{'role':'system','content':SYSTEM},{'role':'user','content':prompt},
                    {'role':'assistant','content':canonical({'classification':grade})}]}
    lineage={'id':record['id'],'organization':key[0],'incident':key[1],
        'split':org_split(key[0]),'source_selected_sha256':SOURCE_SHA,
        'source_records':[{'ordinal':i['record_ordinal'],'sha256':i['parsed_record_sha256']}for i in items],
        'source_rows':len(items),'represented_rows':sum(counts.values()),
        'retained_fields':list(KEEP),'excluded_fields':[x for x in audit.G.COLUMNS if x not in KEEP],
        'target_field':'IncidentGrade','target_value':grade,'input_sha256':digest(features)}
    return record,lineage


def build(source, output):
    manifest,groups=audit.audit_selected(source/'evidence-r1')
    if manifest['selected_sha256']!=SOURCE_SHA: raise ValueError('Not the reviewed GUIDE release')
    raw=(source/'audit-r2/manifest.json').read_bytes()
    review=json.loads(raw)
    ledger=json.loads((Path(__file__).resolve().parent/'SOC_GUIDE_EVIDENCE_REVIEW.json').read_text())
    previous=ledger['original_test_audit']
    if (hashlib.sha256(raw).hexdigest()!=ledger['preserved_files']['audit-r2/manifest.json']['sha256']
            or review['prior_test_audit_sha256']!=ledger['preserved_files']['audit-r1/manifest.json']['sha256']
            or not previous['test_eof_verified'] or previous['overlap_incidents']!=0
            or previous['selected_source_sha256']!=SOURCE_SHA or review['selected_source_sha256']!=SOURCE_SHA):
        raise ValueError('Original-test overlap audit missing or inconsistent')
    indexed,_=audit.task_indexes(groups,set())
    eligible={(g['org_id'],g['incident_id']):next(iter(g['grades']))for g in indexed['triage_cases']}
    rows=defaultdict(list)
    for line in (source/'evidence-r1/selected.jsonl').open():
        item=json.loads(line);r=item['record'];rows[(r['OrgId'],r['IncidentId'])].append(item)
    output.mkdir(parents=True,exist_ok=False)
    candidates=[];excluded=[];by_input=defaultdict(list)
    for key,items in sorted(rows.items()):
        identity='guide-v2-'+key[0]+'-'+key[1]
        if key not in eligible:
            excluded.append({'id':identity,'reason':'missing_conflicting_or_unknown_provider_triage','rows':len(items)})
            continue
        record,lineage=make_case(key,items,eligible[key])
        if len(canonical(record).encode())>16000:
            excluded.append({'id':identity,'reason':'whole_incident_projection_over_candidate_byte_budget','rows':len(items)})
            continue
        index=len(candidates);candidates.append((record,lineage));by_input[lineage['input_sha256']].append(index)
    duplicate=set()
    for indices in by_input.values():
        if len(indices)>1: duplicate.update(indices) # quarantine all, including cross-label collisions
    opened={s:(output/(s+'.candidates.jsonl')).open('w') for s in ('train','validation','test')}
    counts={s:Counter()for s in opened};lineages=[]
    try:
        for i,(record,lineage) in enumerate(candidates):
            if i in duplicate:
                excluded.append({'id':record['id'],'reason':'identical_projected_input','rows':lineage['source_rows']})
                continue
            opened[lineage['split']].write(canonical(record)+'\n')
            counts[lineage['split']][lineage['target_value']]+=1;lineages.append(lineage)
    finally:
        for f in opened.values(): f.close()
    (output/'source-lineage.jsonl').write_text(''.join(canonical(x)+'\n'for x in lineages))
    (output/'excluded.jsonl').write_text(''.join(canonical(x)+'\n'for x in excluded))
    (output/'CDLA-Permissive-2.0.txt').write_bytes((source/'CDLA-Permissive-2.0.txt').read_bytes())
    orgs={s:{x['organization']for x in lineages if x['split']==s}for s in opened}
    if any(orgs[a]&orgs[b]for a,b in (('train','validation'),('train','test'),('validation','test'))):
        raise ValueError('Organization leakage')
    summary={'status':'candidates_waiting_actual_tokenizer','at_kst':audit.G.now(),
        'source_selected_sha256':SOURCE_SHA,'source_incidents':len(groups),'source_rows':manifest['selected_records'],
        'candidate_counts':{k:dict(v)for k,v in counts.items()},'candidate_incidents':len(lineages),
        'excluded_incidents':len(excluded),'excluded_reasons':dict(Counter(x['reason']for x in excluded)),
        'organization_counts':{k:len(v)for k,v in orgs.items()},'cross_split_organization_overlap':0,
        'retained_fields':list(KEEP),'post_verdict_fields_in_input':0,'labels_in_input':0,
        'source_rows_preserved_per_admitted_incident':True,'projection_is_full_raw_evidence':False,
        'training_admitted':0,'action_supervision_admitted':0,'original_test_used_for_training':False,
        'limitations':['Retrospective classification only; publication does not establish decision-time availability.',
          'Opaque alert/entity identifiers and evidence role excluded; no reconstructed narratives or executable action targets.',
          'Source labels are provider annotations, not independently audited clinical-style gold or correct SOC decisions in this deployment.',
          'All source rows contribute retained fields/counts; excluded source fields remain in preserved source and are listed in lineage.'],
        'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(output.iterdir()) if p.is_file()}}
    (output/'review.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(build(a.source,a.output),ensure_ascii=False,indent=2))
