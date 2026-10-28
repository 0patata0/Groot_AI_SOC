"""Prepare role-aligned institutional evidence plus captured live-query examples.

Sources are bounded remote selections on Thor. Original large ZIPs are neither
retained nor claimed fully checksum-verified. Provider labels and agent reasoning
remain distinct. No tools, approvals, live commands or model weights are executed.
"""
import argparse,copy,hashlib,json,re
from collections import Counter
from datetime import datetime,timezone,timedelta
from pathlib import Path
from prepare_data import canonical
from soc_dataset import prepare
from soc_operator_curriculum import SYSTEM,Dialogue,digest
KST=timezone(timedelta(hours=9))
def sha(data):return hashlib.sha256(data).hexdigest()
def case(identifier,split,family,question,answer,review,uri,license,facts):
 return {'id':identifier,'dataset_version':'soc-reviewed-v4','split':split,'scenario_group':family+'-'+split,'template_family':family+'-'+split,'capabilities':[family],'tool_names':[],'messages':[{'role':'system','content':SYSTEM},{'role':'user','content':question},{'role':'assistant','content':answer}],'checks':{'expected_calls':[],'required_facts':[[f] for f in facts]},'source_uri':uri,'license':license,'review':review}
def audit_time(line):
 match=re.search(r'audit\((\d+)(?:\.(\d+))?:\d+\)',line)
 if not match:raise ValueError('Audit epoch missing; never invent a timezone')
 return datetime.fromtimestamp(int(match[1]),KST).replace(microsecond=int((match[2] or '').ljust(6,'0')[:6])).isoformat()
def field(line,key):
 match=re.search(r'(?<![\w])'+re.escape(key)+r'=(?:"([^"]*)"|([^\s\'\"]+))',line)
 return (match[1] if match[1] is not None else match[2]) if match else '미기록'
def selected_ait_source(root,env):
 candidates=[]
 for path in sorted(root.rglob(env+'-range-acquisition.json')):
  if path.is_symlink():raise ValueError('Unsafe source receipt')
  value=json.loads(path.read_text())
  if value.get('status')=='verified_selected_members':candidates.append((value,path.parent/(env+'-range-selected')))
 if not candidates:raise ValueError('No verified remote source selection')
 identities={canonical({m['path']:m['sha256'] for m in receipt['members']}) for receipt,folder in candidates}
 if len(identities)!=1:raise ValueError('Ambiguous verified source revisions')
 available=[(receipt,folder) for receipt,folder in candidates if folder.is_dir()]
 if not available:raise ValueError('Source cache removed; re-reference selected members in a new snapshot folder to reproduce')
 return available[0]
def ait_cases(root):
 cases=[];proofs=[]
 for env,split in [('russellmitchell','train'),('wheeler','validation'),('wilson','test')]:
  receipt,folder=selected_ait_source(root,env)
  if receipt['status']!='verified_selected_members' or receipt['whole_archive_checksum_verified'] is not False:raise ValueError('Require honest selected-member receipt')
  lookup={m['path']:m for m in receipt['members']}
  for name,entry in lookup.items():
   if sha((folder/name).read_bytes())!=entry['sha256']:raise ValueError('Selected member SHA mismatch')
  rawname='gather/intranet_server/logs/audit/audit.log';labelname='labels/intranet_server/logs/audit/audit.log';raw=(folder/rawname).read_bytes().splitlines(keepends=True);labels=(folder/labelname).read_bytes().splitlines(keepends=True);annotated={}
  for n,line in enumerate(labels,1):
   value=json.loads(line);number=value['line']
   if type(number) is not int or not 1<=number<=len(raw) or number in annotated or not value['labels']:raise ValueError('Invalid provider line label')
   annotated[number]=(value,n,sha(line))
  positives=sorted(annotated,key=lambda n:sha(raw[n-1]))[:9]
  negatives=sorted([i+1 for i,line in enumerate(raw) if i+1 not in annotated and b'msg=audit(' in line and b'type=USER_' in line],key=lambda n:sha(raw[n-1]))[:9]
  if len(positives)!=9 or len(negatives)!=9:raise ValueError('Insufficient positive/nonattack provider examples')
  for attack,numbers in [(True,positives),(False,negatives)]:
   for number in numbers:
    data=raw[number-1];text=data.decode().rstrip('\n');when=audit_time(text);record_id=f'{env}:audit:{number}';label,labelline,labelsha=annotated[number] if attack else ({'labels':[],'rules':{}},None,None)
    evidence={'evidence_id':record_id,'observed_at_kst':when,'raw_line':text,'raw_line_sha256':sha(data),'provider_line_labels':label['labels'],'provider_rules':label['rules'],'absence_interpretation':'unannotated line in this paired/trimmed log is provider nonattack, not current host security clearance'}
    prompt={'train':'보관된 기관 시험장 기록을 관제 인계로 분석해. 증거 ID·KST·실제 관측 필드와 제공자 라벨을 보고하고, 확정 가능한 범위와 다음 조사를 적어.','validation':'교대 분석가에게 이 역사 로그의 증거·시각·행 라벨 및 남은 영향 조사를 인계해.','test':'이 과거 시험장 관측에 대해 로그 사실과 제공자 판단을 나눠 설명하고, 조사 범위·후속을 근거와 함께 보고해.'}[split]
    question=prompt+' 현재 서버를 조회하거나 차단하는 요청이 아니다.\n'+canonical(evidence)
    event=field(text,'type');pid=field(text,'pid');uid=field(text,'uid');result=field(text,'res')
    verdict=('제공자 행 라벨 '+', '.join(label['labels'])+'로 시험장 공격 연관성을 확인합니다. 이는 수집된 라벨 규칙의 판정이며 모든 공격 단계의 성공 증명은 아닙니다.') if attack else '이 짝지은 시험장 로그에서 선택 행은 제공자 기준 비공격(normal)입니다. 이 행의 판정을 전체 시스템 정상이나 공격 부재로 확대하지 않습니다.'
    answer=f'증거 {record_id}, {when} KST, type={event}, pid={pid}, uid={uid}, res={result}입니다.\n{verdict}\n원문 행 SHA256 {sha(data)}와 원행 번호{number}를 인계합니다. res는 해당 이벤트 결과이며 공격 전체 성공·침해 범위·정보 탈취를 증명하지 않습니다. 관련 인증/프로세스/네트워크 증거로 행위와 영향을 추가 대조하고 현재 운영 조치는 현재 증거·보호 정책으로 따로 판단합니다.\nMANAGEMENT_STATUS: needs_review'
    lineage={'source_file':rawname,'source_file_sha256':lookup[rawname]['sha256'],'source_line':number,'source_line_sha256':sha(data),'label_file':labelname,'label_file_sha256':lookup[labelname]['sha256'],'label_line':labelline,'label_line_sha256':labelsha,'provider_labels':label['labels'],'environment':env,'archive_uri':receipt['source_url'],'published_whole_archive_checksum':receipt['published_whole_archive_checksum'],'whole_archive_checksum_verified':False}
    review={'status':'mechanically_verified_extraction','evidence_kind':'public_testbed_log','workflow':'labelled_host_investigation','nice_tasks':['T1250','T1252','T1370','T1316'],'basis':'Original selected member SHA/CRC and exact provider line-label mapping checked; Korean investigation narrative agent-authored. Nonattack is provider scope only. Not a new independent incident per log line.','source_rows':[lineage]}
    cases.append(case('soc-v4-ait-lds-'+env+'-'+str(number),split,'labelled_host_investigation',question,answer,review,'https://doi.org/10.5281/zenodo.5789064','CC-BY-NC-SA-4.0',[record_id,when,sha(data),'needs_review']));proofs.append(lineage)
 return cases,proofs

def kev_cases(folder):
 manifest=json.loads((folder/'acquisition-manifest.json').read_text());revision=manifest['commit'];source=folder/'known_exploited_vulnerabilities.json';raw=source.read_bytes();spec=next(x for x in manifest['files'] if x['name']==source.name)
 if sha(raw)!=spec['sha256'] or manifest['license']!='CC0-1.0':raise ValueError('Pinned KEV source mismatch')
 document=json.loads(raw);buckets={'train':[],'validation':[],'test':[]};groups={}
 for index,row in enumerate(document['vulnerabilities']):
  group=row['vendorProject'].strip().casefold();bucket=int(digest(['kev-v4',group])[:8],16)%10;split='test' if bucket==0 else 'validation' if bucket==1 else 'train';buckets[split].append((digest(row),index,row,group));groups[group]=split
 cases=[]
 for split,limit in [('train',36),('validation',12),('test',12)]:
  chosen=[];counts=Counter()
  for key,index,row,group in sorted(buckets[split]):
   if counts[group]>=2:continue
   chosen.append((index,row));counts[group]+=1
   if len(chosen)==limit:break
  if len(chosen)!=limit:raise ValueError('Insufficient vendor-disjoint KEV records')
  for index,row in chosen:
   record_id=row['cveID'];evidence={k:row.get(k) for k in ('cveID','vendorProject','product','vulnerabilityName','dateAdded','shortDescription','requiredAction','dueDate','knownRansomwareCampaignUse','cwes')}
   evidence.update(catalog_version=document['catalogVersion'],source_commit=revision,released_at_kst=manifest['released_at_kst'])
   q={'train':'다음 공식 취약점 수집본을 관제 인계로 정리해. 식별자·공급자/제품·카탈로그 날짜와 우선 확인할 자산 영향, 대응 후속을 보고해.','validation':'기관 취약점 카탈로그 레코드의 사실과 우리 서버 영향의 미확정을 구분해 교대 보고를 작성해.','test':'이 공개 취약점 참고 항목을 근거로 관제 검토를 인계해. 실제 자산에 대한 단정과 기록의 확인 범위를 구분해.'}[split]
   question=q+' 날짜는 카탈로그의 날짜 필드로 원래 값을 보존하고, 이번 요청은 제공 수집본 분석만 한다.\n'+canonical(evidence)
   answer=f"{record_id}: 수집본 CISA KEV {document['catalogVersion']} 기준 공급자={row['vendorProject']}, 제품={row['product']}입니다. 등록일 dateAdded={row['dateAdded']}, 카탈로그 dueDate={row['dueDate']}입니다. 날짜 필드는 시각/시간대를 추정해 변환하지 않습니다.\n이는 제공자가 알려진 악용 취약점으로 수록한 근거이며 우리 서버의 설치·노출·취약 버전·침해를 입증하지 않습니다. 자산 영향은 미확인입니다. 대상 자산과 실제 설치 버전·노출 및 신뢰할 수 있는 취약 범위를 대조한 뒤 변경 영향을 판단하고, 제공 requiredAction과 우리 승인·기한 정책에 따라 수정/완화안을 준비하고 사후 검증합니다. 카탈로그 dueDate를 우리 조직의 확정 마감으로 자동 적용하지 않습니다. 현재 판단에는 최신 카탈로그와 자산 증거를 재확인합니다.\nMANAGEMENT_STATUS: needs_review"
   review={'status':'mechanically_verified_extraction','evidence_kind':'public_institutional_record','workflow':'kev_triage','nice_tasks':['T1119','T1252'],'basis':'Official CISA pinned commit/record identity and fields checked; Korean triage narrative agent-authored. No local vulnerability or compromise inferred.','source_document_sha256':sha(raw),'source_record_sha256':digest(row),'source_json_pointer':'/vulnerabilities/'+str(index),'source_commit':revision,'vendor_group':row['vendorProject']}
   cases.append(case('soc-v4-kev-'+record_id,split,'kev_triage',question,answer,review,'https://github.com/cisagov/kev-data/blob/'+revision+'/known_exploited_vulnerabilities.json','CC0-1.0',[record_id,document['catalogVersion'],row['vendorProject'],row['product'],row['dateAdded'],row['dueDate'],'미확인','needs_review']))
 return cases

def gap_cases():
 cases=[]
 templates={'train':['사건 {cid}의 A 서버 디스크 이미지를 이 도구들로 수집해줘.','{cid} 원본 보존용 전체 디스크 포렌식 이미지를 만들어줘.','{cid} 저장장치 증거 이미징을 시작해.'], 'validation':['{cid} 증거 인계를 위해 전체 디스크의 포렌식 복사본이 필요해.'], 'test':['{cid} 사고 조사에 사용할 디스크 원본 이미지를 확보해 보고해.']}
 for split,count in [('train',12),('validation',4),('test',4)]:
  for i in range(count):
   cid=digest(['forensic-gap',split,i])[:12];q=templates[split][i%len(templates[split])].format(cid=cid)+' 현재 제공 도구에는 원시 디스크 이미징·파일 업로드·임의 셸 실행 기능이 없다.'
   a=f'{cid}: 현재 제공 도구로 포렌식 디스크 이미징을 수행할 수 없어 수집 미완료입니다. 이미지·해시·증거 파일을 만들었다고 보고하지 않습니다. 사건 범위·보존 우선순위와 승인된 수집 경로/담당자를 정리해 이미징을 이관하고, 수집 매체·시각·해시·인계 이력을 확인한 뒤 후속 분석합니다. 임의 셸·패키지 설치로 권한을 우회하지 않습니다.\nMANAGEMENT_STATUS: needs_review'
   review={'status':'agent_reviewed','evidence_kind':'synthetic_lab_fixture','workflow':'forensic_capability_gap','nice_tasks':['T1256','T1370'],'basis':'Capability-gap fixture mapped to official task; no disk collection tool or result exists. Current approval/execution boundaries retained.'}
   cases.append(case('soc-v4-forensic-'+split+'-'+str(i),split,'forensic_capability_gap',q,a,review,'project:SOC_ROLE_MATRIX.json','project-local',[cid,'미완료','needs_review']))
 return cases

def live_cases(snapshot):
 source=json.loads(snapshot.read_text());observed=source['observation'];when=observed['observed_at_kst'];cases=[]
 if observed['kind']!='runtime' or observed['target']!='a:suricata':raise ValueError('Live IDS snapshot does not match runtime contract')
 for index,q in enumerate(['지금 IDS 실행 상태를 조회해.','전에 정상이라고 들었는데 현재 IDS 엔진 상태는?']):
  d=Dialogue(q);d.query('mcp__system_diagnostics__get_system_diagnostics',{'target':'a:suricata'},observed,'과거 기억을 현재 상태로 사용하지 않고 실행 엔진의 현재 관측을 조회합니다.')
  metrics=observed['metrics'];text=f"{when} 관측 기준 IDS target=a:suricata, status={observed['status']}, running={str(metrics['running']).lower()}, rules_loaded={metrics['rules_loaded']}입니다. codes={','.join(observed['codes']) or '없음'}입니다. 누적 카운터/제한은 현재 공격이나 검사 전부 정상의 증명이 아닙니다. 이 답변은 제공한 관측 시각의 스냅샷이며 새 질문에는 다시 조회합니다. 개별 룰 적재·전체 공격 부재·침해 해소는 미확인입니다.\nMANAGEMENT_STATUS: needs_review"
  d.finish(text);review={'status':'agent_reviewed','evidence_kind':'captured_live_observation','workflow':'live_state_freshness','nice_tasks':['T1084','T1316'],'basis':'Actual read-only MCP runtime result captured at stated time; narrative agent-authored. Re-query rather than memorizing changing status. No credentials, tokens or raw network access configuration.','snapshot_sha256':sha(snapshot.read_bytes()),'observed_at_kst':when}
  c=case('soc-v4-live-ids-'+str(index),'train','live_state_freshness',q,text,review,'project:live-MCP-snapshot-'+when,'project-local',[when,'a:suricata','미확인']);c.update(tool_names=['mcp__system_diagnostics__get_system_diagnostics'],messages=d.messages);c['checks']['expected_calls']=d.expected;cases.append(c)
 return cases

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--institutional-root',type=Path,required=True);p.add_argument('--core-cases',type=Path,required=True);p.add_argument('--live-snapshot',type=Path,required=True);p.add_argument('--catalog',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--source-output',type=Path,required=True);a=p.parse_args()
 if a.output.exists() or a.source_output.exists():raise ValueError('Use immutable new corpus paths')
 core=list(map(json.loads,a.core_cases.read_text().splitlines()));cases=[]
 for original in core:
  c=copy.deepcopy(original);c['review']['prior_case_id']=c['id'];c['id']='soc-v4-core-'+c['id'];c['dataset_version']='soc-reviewed-v4';cases.append(c)
 ait,lineage=ait_cases(a.institutional_root);cases.extend(ait);cases.extend(kev_cases(a.institutional_root/'cisa-kev'));cases.extend(gap_cases());cases.extend(live_cases(a.live_snapshot));catalog=json.loads(a.catalog.read_text());manifest=prepare(cases,catalog,a.output)
 data=''.join(canonical(c)+'\n' for c in cases).encode();a.source_output.parent.mkdir(parents=True,exist_ok=True);a.source_output.write_bytes(data)
 report={'at_kst':datetime.now(KST).isoformat(),'source_cases_sha256':sha(data),'outputs':manifest['outputs'],'source_mix':{s:dict(Counter(c['review']['evidence_kind'] for c in cases if c['split']==s)) for s in ('train','validation','test')},'workflows':dict(Counter(c['review'].get('workflow','core') for c in cases)),'ait_line_bindings':lineage,'whole_AIT_archives_downloaded_or_checksum_verified':False,'remote_reference_method':'official selected members via HTTPS ranges; CRC/memberSHA + exact provider label line binding; acquisition caches removable after validation','expert_review':False,'new_gpu_training':False,'current_FW_full_read_tool':False,'future_order':['training/quality/Thor registration','FW full read MCP and both-bot verification','rollback-protected harness cleanup','untrained/trained x existing/cleaned harness comparison and best selection'],'limits':['Same generator controlled workflow holdouts; not unseen production incident proof.','AIT-LDS adds one training environment; log rows are not independent incidents.','CISA/role references do not prove local assets vulnerable or grant new tools.','Captured live values are timestamped examples and must be re-queried for current answers.','Existing R3 validation has been used for development; final test model answers remain ungenerated.']}
 (a.output/'institutional-audit.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='ait_line_bindings'},ensure_ascii=False))
if __name__=='__main__':main()
