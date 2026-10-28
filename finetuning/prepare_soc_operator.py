"""Prepare SOC workflow plus attributed archived AIT evidence; never train or act.

AIT phase windows are scenario-time context, never per-alert malicious labels.
Public tool-calling corpora are not included in this SOC-core recipe.
"""
import argparse
from collections import Counter,defaultdict
from datetime import datetime,timezone,timedelta
import hashlib,json
from pathlib import Path
import zipfile
from prepare_data import canonical,normalize_record
from soc_dataset import prepare,validate_case
from soc_operator_curriculum import ROOT,SYSTEM,build,audit,digest
KST=timezone(timedelta(hours=9))
def sha(data):return hashlib.sha256(data).hexdigest()
def select_ait(root=ROOT,each=12):
    splits=json.loads((root/'datasets/processed/ait/split.json').read_text());old=set()
    source=root/'finetuning/data-soc-v1'
    for split in ('train','validation','test'):
        for line in (source/(split+'.jsonl')).read_text().splitlines():
            review=json.loads(line)['provenance']['review']
            if review.get('evidence_kind')=='public_testbed_log':old.add((review['source_file'],review['source_line']))
    output=[]
    for role,envs in splits.items():
        split={'train':'train','val':'validation','holdout':'test'}[role]
        for env in envs:
            path=root/'datasets/processed/ait'/(env+'.labeled.jsonl');relative=path.relative_to(root).as_posix();file_sha=sha(path.read_bytes());buckets=defaultdict(list)
            for number,line in enumerate(path.open('rb'),1):
                if (relative,number) in old:continue
                value=json.loads(line);rule=value.get('rule',{});at=value.get('@timestamp');agent=value.get('agent',{}).get('id')
                if not at or not agent or not isinstance(rule.get('level'),int) or not rule.get('id') or not rule.get('description'):continue
                try:when=datetime.fromisoformat(at.replace('Z','+00:00')).astimezone(KST).isoformat()
                except ValueError:continue
                # Bounded diversity reservoir: two different records per rule/phase/agent.
                key=(value['phase_window'],agent,str(rule['id']))
                item={'key':sha(line),'raw':value,'projection':{'source_id':value['id'],'timestamp_kst':when,'agent_id':agent,'rule_id':str(rule['id']),'level':rule['level'],'description':rule['description'],'groups':rule.get('groups',[]),'mitre_ids':rule.get('mitre',{}).get('id',[]),'phase_window':value['phase_window']},'lineage':{'source_file':relative,'source_file_sha256':file_sha,'source_line':number,'source_line_sha256':sha(line)}}
                bucket=buckets[key];bucket.append(item);bucket.sort(key=lambda x:x['key']);del bucket[2:]
            groups=defaultdict(list)
            for (phase,agent,rid),items in buckets.items():groups[(phase,agent)].extend(items)
            pairs=[]
            for group,items in groups.items():
                items.sort(key=lambda x:x['projection']['timestamp_kst'])
                for a,b in zip(items[::2],items[1::2]):pairs.append((digest([env,a['key'],b['key']]),a,b))
            pairs.sort(key=lambda x:x[0]);used=set();chosen=[]
            # Prefer distinct contextual phases before taking further pairs.
            for novel_only in (True,False):
                for key,a,b in pairs:
                    if len(chosen)>=each:break
                    phase=a['projection']['phase_window']
                    if key in {p[0] for p in chosen} or (novel_only and phase in used):continue
                    chosen.append((key,a,b));used.add(phase)
            if len(chosen)!=each:raise ValueError('Insufficient distinct AIT pairs')
            for i,(key,a,b) in enumerate(chosen):output.append((split,env,i,a,b))
    return output

def archived_case(split,env,index,a,b):
    evidence=[x['projection'] for x in (a,b)];identifier='AIT-ARCHIVE-'+digest([env,a['key'],b['key']])[:12]
    question={'train':'이 과거 시험장 경보 두 건을 조사 인계로 정리해. 시간 순서·증거 ID·규칙/레벨·우선 확인 항목과 확정할 수 없는 결론을 보고해.', 'validation':'보관된 기관 시험장 로그를 교대 인계하려 해. 두 기록의 시간·식별자·심각도와 후속 조사를 증거 범위 안에서 작성해.', 'test':'아카이브 경보를 인수했어. 두 관측의 선후관계와 근거 식별자, 확인된 사실과 남은 조사 및 조치 한계를 전달해.'}[split]
    question+='\n공개 AIT 시험장 역사자료이며 현재 서버 조회가 아니다. phase_window는 labels.csv의 시간 구간 컨텍스트로 악성 정답이 아니다.\n'+canonical({'archive_case_id':identifier,'evidence':evidence})
    lines=[f"{v['timestamp_kst']} | 증거 {v['source_id']} | agent {v['agent_id']} | rule {v['rule_id']} | level {v['level']} | {v['description']} | 구간 {v['phase_window']}" for v in evidence]
    maximum=max(v['level'] for v in evidence)
    priority='높은 레벨 경보의 원문과 관련 호스트·인증 이력을 먼저 대조합니다.' if maximum>=10 else '레벨만으로 종결하지 않고 관련 인증·프로세스·네트워크 기록을 대조합니다.'
    answer=f'{identifier}: 제공 표본2건의 KST 시간 순서는 다음과 같습니다.\n'+'\n'.join(lines)+f'\n{priority} 기술 식별자나 시간 구간 일치는 공격 성공·동일 행위자·침해 확정의 근거가 아닙니다. phase_window의 normal도 정상 판정을 뜻하지 않습니다. 표본 밖 전체 사건 수·영향 범위·현재 운영 상태는 미확인입니다. 아카이브에 현재 MCP 조회·차단을 적용하지 않고 추가 증거 및 시험장 시나리오 기록을 조사해 인계합니다.\nMANAGEMENT_STATUS: needs_review'
    return {'id':f'soc-operator-v3-ait-{env}-{index:03}','dataset_version':'soc-reviewed-v3','split':split,'scenario_group':'ait-archive-environment-'+env,'template_family':'ait-archive-'+split,'capabilities':['archive_investigation'],'tool_names':[],'messages':[{'role':'system','content':SYSTEM},{'role':'user','content':question},{'role':'assistant','content':answer}],'checks':{'expected_calls':[],'required_facts':[[str(v[k])] for v in evidence for k in ('source_id','timestamp_kst','rule_id','level')]+[['미확인'],['needs_review']]},'source_uri':'https://doi.org/10.5281/zenodo.8263181','license':'CC-BY-4.0','review':{'status':'mechanically_verified_extraction','evidence_kind':'public_testbed_log','workflow':'archive_investigation','operator_stages':['investigation','evidence','decision','reporting'],'basis':'Two original AIT records projected without changing timestamps; IDs/fields mechanically checked. Korean investigation/priority prose is agent-authored, not expert ground truth. No phase-to-malicious mapping.','source_rows':[x['lineage'] for x in (a,b)],'ait_environment':env},'references':[{'uri':'https://doi.org/10.5281/zenodo.8263181','role':'original evidence'},{'uri':'https://doi.org/10.1145/3675741.3675748','role':'dataset paper; not expert certification of derived answers'},{'uri':'https://doi.org/10.6028/NIST.SP.800-61r3','elements':['RS.AN-03','RS.AN-06','RS.AN-07','RS.AN-08']}]}

def verify_originals(root,selected):
    pending=defaultdict(dict)
    for split,env,index,a,b in selected:
        for row in (a,b):
            raw=dict(row['raw']);raw.pop('ait_env');raw.pop('phase_window');pending[env][raw['id']]=sha(canonical(raw).encode())
    total=sum(map(len,pending.values()))
    with zipfile.ZipFile(root/'datasets/raw/ait-ads/ait_ads.zip') as archive:
        for env,rows in pending.items():
            with archive.open(env+'_wazuh.json') as stream:
                for line in stream:
                    raw=json.loads(line);identifier=raw.get('id')
                    if identifier in rows:
                        if sha(canonical(raw).encode())!=rows.pop(identifier):raise ValueError('AIT original object mismatch')
                    if not rows:break
            if rows:raise ValueError('AIT original records missing')
    return total

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--source-output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists() or args.source_output.exists():raise ValueError('Use immutable new output paths')
    catalog=json.loads((ROOT/'finetuning/mcp_contract.json').read_text());cases=build();previous=[]
    for path in (ROOT/'finetuning').glob('data-soc-source*/cases.jsonl'):previous.extend(c for c in map(json.loads,path.read_text().splitlines()) if c.get('split')=='test')
    checks=audit(cases,catalog,previous);selected=select_ait();verified=verify_originals(ROOT,selected)
    cases.extend(archived_case(*row) for row in selected)
    manifest=prepare(cases,catalog,args.output);data=''.join(canonical(c)+'\n' for c in cases).encode();args.source_output.parent.mkdir(parents=True,exist_ok=True);args.source_output.write_bytes(data)
    summary={'created_at_kst':datetime.now(KST).isoformat(),'source_cases_sha256':sha(data),'outputs':manifest['outputs'],'source_mix':{s:dict(Counter(c['review']['evidence_kind'] for c in cases if c['split']==s)) for s in ('train','validation','test')},'workflow_checks':checks,'ait_original_alerts_verified':verified,'ait_environment_disjoint':True,'legacy_v1_ait_rows_excluded':True,'toolace_included':False,'toolace_role':'auxiliary candidate only; no SOC semantic approval','source_projections':{p:sha((ROOT/p).read_bytes()) for p in ('infra/mcp/security-events-mcp.py','infra/mcp/system-diagnostics-mcp.py','infra/mcp/rule_change_executor.py')},'sources':[{'uri':'https://doi.org/10.5281/zenodo.8263181','license':'CC-BY-4.0'},{'uri':'https://doi.org/10.1145/3675741.3675748','scope':'dataset paper'},{'uri':'https://doi.org/10.6028/NIST.SP.800-61r3','scope':'procedure reference, no certification of synthetic labels'}],'limitations':['agent-authored procedure/reasoning, not independent expert-labelled SOC trajectories','synthetic workflow holdouts share generator/families; not unseen real incident proof','partial controlled responses beyond source projections, not full captured live responses','no GPU training/token audit/live action validated by preparation alone']}
    (args.output/'operator-audit.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n');print(json.dumps(summary,ensure_ascii=False))
if __name__=='__main__':main()
