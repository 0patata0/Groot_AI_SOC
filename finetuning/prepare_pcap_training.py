"""Locally compose source-bound SOC evidence examples; never start training.

Eight distinct analyst tasks per CTU capture, not one sample per flow. All CTU
captures stay in training under one shared-infrastructure leakage group. Old
validation/test bytes are preserved. Provider labels never enter model inputs.
"""
import argparse
from collections import Counter
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import shutil
from zoneinfo import ZoneInfo

from audit_tools import audit_rows
from prepare_operator_release import input_identity, private_observations

ROOT=Path(__file__).resolve().parent

def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def rows(p):return [json.loads(s) for s in Path(p).read_text().splitlines() if s]
def dump(p,values):Path(p).write_text(''.join(canonical(x)+'\n' for x in values))
def port(text):
    try:return int(text,16) if text.startswith('0x') else int(text)
    except ValueError:return None


def summarize(path):
    protocols=Counter();n=packets=byte_count=dns=icmp=0;first=last=None;top=None;seen=set()
    with Path(path).open() as handle:
        for line in handle:
            r=json.loads(line);n+=1
            if r['id'] in seen:raise ValueError('duplicate evidence identifier')
            seen.add(r['id']);protocols[r['protocol']]+=1;packets+=r['packets'];byte_count+=r['bytes']
            if r['protocol'] in ('tcp','udp') and 53 in (port(r['source_port_raw']),port(r['destination_port_raw'])):dns+=1
            if r['protocol'] in ('icmp','ipv6-icmp'):icmp+=1
            time=r['observed_at_source'];first=time if first is None else min(first,time);last=time if last is None else max(last,time)
            if top is None or (r['packets'],r['id'])>(top['packets'],top['id']):top=r
    span=(datetime.fromisoformat(last)-datetime.fromisoformat(first)).total_seconds()
    result={'flow_records':n,'packet_count_bidirectional':packets,'byte_count_bidirectional':byte_count,
            'protocol_flow_counts':dict(sorted(protocols.items())),
            'port53_tcp_udp_flow_records':dns,'icmp_family_flow_records':icmp,
            'first_to_last_flow_start_span_seconds':span,'clock_timezone':'unverified',
            'highest_packet_flow':top}
    return result


def cases(source):
    source=Path(source);manifest=json.loads((source/'candidate_manifest.json').read_text());output=[];facts=[]
    assert manifest['schema']=='ctu13-curated-flow-candidate-v1' and manifest['training_input_allowlist']==[]
    system=('보안관제요원으로서 제공된 관측의 의미와 한계를 구분해 짧은 한국어로 답한다. '
            '수치·주체·기간을 근거와 연결하며 확인하지 않은 조치나 성공을 만들지 않는다. '
            '이 과제는 과거 오프라인 흐름 분석이며 사용할 도구는 없다. 현재 운영 변경은 수행하지 않는다. '
            '표는 Markdown 표로 쓰고 코드블록으로 감싸지 않는다. 필요한 추가 근거는 구체적으로 제시한다.')
    for case in manifest['cases']:
        identifier=case['case'];path=source/(identifier+'.observations.jsonl');f=summarize(path);facts.append({'case':identifier,**f})
        assert f['flow_records']==case['counts']['retained']
        top=f['highest_packet_flow'];name=top['id'];src=top['source_endpoint'];dst=top['destination_endpoint']
        brief=(f"| 항목 | 확인값 |\n|---|---|\n| 흐름 기록 | {f['flow_records']:,}개 |\n"
               f"| 양방향 패킷 합계 | {f['packet_count_bidirectional']:,}개 |\n"
               f"| TCP/UDP 53번 포트 연관 흐름 | {f['port53_tcp_udp_flow_records']:,}개 |\n"
               f"| ICMP 계열 흐름 | {f['icmp_family_flow_records']:,}개 |")
        tasks=[
          ('summary','이거 간단히 정리해줘.',brief+'\n\n과거 캡처의 집계입니다. 흐름 수는 공격 건수·피해 호스트 수가 아니며, 이 표만으로 현재 서버 상태를 판단할 수 없습니다.'),
          ('priority','어디부터 조사할까?',f"패킷 수가 가장 큰 흐름 {name}부터 통신량과 목적을 확인하겠습니다. 공격 위험도 1위로 확정했다는 뜻은 아닙니다.\n\n| 근거 | 확인값 |\n|---|---|\n| 프로토콜 | {top['protocol']} |\n| 양방향 패킷 | {top['packets']:,}개 |\n| 양방향 바이트 | {top['bytes']:,}B |\n\n해당 시각의 패킷·애플리케이션 로그와 같은 주체의 전후 흐름을 연결해 정상 대량 통신인지 조사해야 합니다. 전체 캡처 집계만으로 순간 초당 전송률을 만들지 않습니다."),
          ('dns','DNS 많으면 다 공격이야?',f"아닙니다. 여기서 확인되는 것은 TCP/UDP 53번 포트와 관련된 흐름 {f['port53_tcp_udp_flow_records']:,}개입니다. 실제 DNS 질의 수나 악성 도메인 수가 아닙니다.\n\n| 추가 확인 | 목적 |\n|---|---|\n| 질의명·응답코드·응답 IP | 서비스 목적과 오류/이상 응답 확인 |\n| 출발 호스트·프로세스·주기 | 승인된 확인 작업과 다른 행위 구분 |\n| 같은 시각의 후속 연결·센서 근거 | 의심 질의와 실제 행위 연결 |\n\n흐름 수나 포트만으로 전부 차단하거나 모든 DNS를 예외 처리하지 않습니다."),
          ('direction','누가 어디로 보낸 거야?',f"패킷 수가 가장 큰 기록 {name}의 주소 필드는 다음과 같습니다.\n\n| 항목 | 기록값 |\n|---|---|\n| 출발 식별자 | {src} |\n| 목적 식별자 | {dst} |\n| 프로토콜·방향 원문 | {top['protocol']} · {top['direction_raw']} |\n\n이는 기록상의 출발·목적입니다. 수집 서버나 로그의 agent 이름을 공격 출발지로 바꾸지 않습니다. 식별자는 가명이고 양방향 패킷 합계이므로 모든 패킷이 출발 측에서 발생했다고 해석하지 않습니다."),
          ('outcome','그럼 공격 성공한 거야?',f"공격 성공은 이 자료로 확인되지 않습니다. 최대 흐름 {name}의 상태 원문은 `{top['state_raw']}`이고 패킷 {top['packets']:,}개가 기록됐지만, 통신 상태와 애플리케이션 침해 성공은 다릅니다.\n\n| 확인할 근거 | 판단할 내용 |\n|---|---|\n| 대상 서비스의 요청·응답/오류 로그 | 실제 처리 및 오류·성공 응답 |\n| 인증·프로세스·파일 변경 기록 | 권한 획득이나 실행·변경 여부 |\n| 탐지·차단 당시 기록 | 시도/탐지/차단/침해를 구분 |\n\n침해가 없었다고 종결하지 않고 위 근거를 확보해 영향 범위를 확인해야 합니다."),
          ('containment','차단된 건지도 알려줘.',f"차단 여부는 미확인입니다. 제공된 {f['flow_records']:,}개 흐름에는 FW 집합·차단 작업 영수증·차단 시각이 없습니다.\n\n| 필요한 조회 | 대조할 내용 |\n|---|---|\n| 해당 시점의 방화벽 규칙/차단 이력 | 실제 주소·조건·기한·규칙 존재 |\n| 대응 작업 결과와 승인 기록 | 요청·승인·적용을 구분 |\n| 이후 연결·DROP 등 관측 | 조치 효과와 부작용 |\n\n가명 주소를 실IP로 추측해 차단하지 않습니다. 현재 상태를 요청하면 허가된 도구로 새로 확인해야 하며 이 오프라인 과제에서 조회·차단을 수행한 것은 아닙니다."),
          ('time','시간을 KST로 정리해줘.',f"원 흐름의 시간대가 검증되지 않아 사건 시각을 임의로 KST로 바꿀 수 없습니다.\n\n| 항목 | 상태 |\n|---|---|\n| 원 시각의 시간대 | 미확인 |\n| 첫~마지막 흐름 시작시각 차이 | {f['first_to_last_flow_start_span_seconds']}초 |\n| KST 변환 | 원 수집/내보내기 시간대 확인 후 가능 |\n\n상대 시간 차이는 공격 지속시간이나 특정 호스트의 가동시간이 아닙니다. 원본 캡처의 시간 기준을 확인한 뒤 +09:00으로 변환해야 합니다."),
          ('followup','그럼 뭘 더 보면 돼?',f"먼저 {name}을 원본 주소·시각에 연결하고 같은 주체의 전후 기록을 찾겠습니다.\n\n| 순서 | 확인할 것 |\n|---|---|\n| 1 | 원본 주소 대응과 캡처 시간대 |\n| 2 | 해당 흐름의 패킷/애플리케이션 내용 및 인접 흐름 |\n| 3 | 관련 DNS·인증·프로세스·서비스 기록 |\n| 4 | 탐지/대응 영수증과 현재 상태를 별도로 조회 |\n\n관측이 없으면 미확인 범위를 남기고 필요한 수집 경로를 점검합니다. 도구 오류나 조회 0건을 정상·복구·차단 성공으로 바꾸지 않습니다."),
        ]
        context=('다음은 과거 오프라인 캡처의 전수 집계와 원문 1행이다. 원 IP는 대체 식별자로 바뀌었고 현재 운영 서버의 상태가 아니다. '
                 '도메인·HTTP 본문·호스트 로그·방화벽 실행 결과는 제공되지 않았다. 포트53 집계는 DNS 질의 건수가 아니며 bytes/packets는 양방향 합계다.\n'+canonical(f))
        for task,question,answer in tasks:
            messages=[{'role':'system','content':system},{'role':'user','content':context+'\n\n'+question},{'role':'assistant','content':answer}]
            if task=='followup':
                messages=[{'role':'system','content':system},{'role':'user','content':context+'\n\n어디부터 조사할까?'},
                          {'role':'assistant','content':tasks[1][2]},{'role':'user','content':question},{'role':'assistant','content':answer}]
            row={'id':identifier+'-'+task+'-20261107','source':'ctu13-source-bound-investigation','messages':messages,'tools':[],
                 'provenance':{'source_uri':case['source']['url'],'source_sha256':case['source']['sha256'],
                   'observations_sha256':sha(path.read_bytes()),'source_rows':f['flow_records'],'selected_flow':name,
                   'facts_sha256':sha(canonical(f).encode()),'task':task,'scenario_group':manifest['leakage_group'],
                   'split':'train','authorship':'Project-authored Korean task/answer based on provider observations; not provider-written or independently expert-validated dialogue',
                   'license':manifest['permission'],'citation':manifest['citation'],'provider_label_used_in_input_or_target':False,
                   'production_tool_calls':0,'current_security_state_asserted':False}}
            if task=='followup':
                row['preserve_empty_thinking_history']=True
                row['provenance']['template_policy']='Preserve only empty reasoning wrappers across user turns for exact all-assistant prefix alignment; no nonempty reasoning supplied.'
            if private_observations(row):raise ValueError('unexpected credential marker')
            output.append(row)
    return output,facts


def build(source,baseline,output):
    output=Path(output);baseline=Path(baseline)
    if output.exists() or not output.name.startswith('data-'):raise ValueError('fresh data-* output required')
    old_manifest=json.loads((baseline/'manifest.json').read_text())
    for split in ('train','validation','test'):
        if sha((baseline/(split+'.jsonl')).read_bytes())!=old_manifest['outputs'][split]['sha256']:
            raise ValueError('baseline changed')
    additions,facts=cases(source)
    registry=json.loads((ROOT/'mcp_contract.20261107.json').read_text());tools={t['name']:t for t in registry['tools']}
    training=rows(baseline/'train.jsonl');updated=[]
    for row in training:
        if not row.get('tools'):continue
        original=sha(canonical(row).encode())
        for tool in row['tools']:
            fn=tool['function'];registered=tools[fn['name']]
            tool['function']={k:registered[k] for k in ('name','description','parameters')}
        row['provenance']['tool_contract_refresh']={'observed_at_kst':registry['observed_at_kst'],
            'original_row_sha256':original,'catalog_sha256':sha((ROOT/'mcp_contract.20261107.json').read_bytes()),
            'historical_result_unchanged':True,'result_not_relabelled_current':True}
        updated.append(row['id'])
    training.extend(additions)
    evaluations=rows(baseline/'validation.jsonl')+rows(baseline/'test.jsonl')
    inputs=[input_identity(r) for r in training];eval_inputs={input_identity(r) for r in evaluations}
    if len(inputs)!=len(set(inputs)) or set(inputs)&eval_inputs:raise ValueError('input duplicate/evaluation leakage')
    if {r['id'] for r in training}&{r['id'] for r in evaluations}:raise ValueError('evaluation ID overlap')
    if any(private_observations(r) for r in training):raise ValueError('explicit secret pattern')
    audit=audit_rows(training,registry)
    if audit['counts']['calls']!=audit['counts']['schema_valid_calls']:raise ValueError('unchecked current-schema call')
    output.mkdir()
    dump(output/'train.candidates.jsonl',training);dump(output/'ctu13-additions.jsonl',additions);dump(output/'facts.jsonl',facts)
    fallbacks=[]
    for row in training:
        if row['source']=='project_live_mcp' and not row['id'].endswith('-initial-call'):
            fallback=copy.deepcopy(row);fallback['id']+='-initial-call';fallback['messages']=fallback['messages'][:3]
            if fallback['messages'][-1].get('tool_calls'):
                fallback['provenance'].update(trajectory_scope='initial_tool_selection_only',parent_dialogue=row['id']);fallbacks.append(fallback)
    dump(output/'fallback.candidates.jsonl',fallbacks)
    for split in ('validation','test'):shutil.copyfile(baseline/(split+'.jsonl'),output/(split+'.jsonl'))
    shutil.copytree(baseline/'licenses',output/'licenses')
    (output/'licenses/CTU13_SOURCE_NOTICE.txt').write_text('Garcia, S.; Grill, M.; Stiborek, J.; Zunino, A. (2014). An empirical comparison of botnet detection methods. Computers & Security 45,100-123. DOI10.1016/j.cose.2014.05.011.\nSource: https://www.stratosphereips.org/datasets-ctu13\nPermission/citation: https://www.stratosphereips.org/datasets-faq and each capture README. No SPDX license inferred.\nThree 2011 controlled captures; provider-labelled flows are not independently validated enterprise incident answers. Korean tasks and bounded summaries are project-authored. Raw provider labels/addresses and malware binaries are not included. All CTU captures share one train group, no CTU final-test samples.\n')
    shutil.copyfile(ROOT/'mcp_contract.20261107.json',output/'mcp-contract.json')
    token_inputs=[{'split':split,'row':r} for split,rs in [('train',training),('fallback',fallbacks),('validation',rows(output/'validation.jsonl')),('test',rows(output/'test.jsonl'))] for r in rs]
    dump(output/'token-input.jsonl',token_inputs)
    composition={'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'status':'waiting_exact_token_receipt',
        'baseline_train_sha256':old_manifest['outputs']['train']['sha256'],'candidate_rows':len(training),
        'builder_sha256':sha(Path(__file__).read_bytes()),
        'new_ctu_dialogues':len(additions),'new_capture_groups':3,'new_independent_leakage_groups':1,
        'new_training_fraction':len(additions)/len(training),'new_rows_oversampled':False,
        'validation_rows':len(evaluations)//2,'test_rows':len(evaluations)//2,
        'frozen_evaluation_sha256':{s:sha((output/(s+'.jsonl')).read_bytes()) for s in ('validation','test')},
        'source_counts':dict(Counter(r['source'] for r in training)),
        'schema_audit':audit,'updated_tool_declaration_rows':updated,'historical_tool_results_changed':0,
        'exact_duplicate_inputs':0,'exact_evaluation_overlap':0,'independent_expert_review':False,
        'semantic_overlap_fully_ruled_out':False,'ctu_provider_labels_used_in_prompts':False,
        'ctu_task_scope':['evidence summary','direction','DNS flow-count meaning','investigation priority','success/containment boundaries','clock uncertainty','followup investigation'],
        'ready_for_gpu_training':False,'training_started':False,'cleansing_location':'local',
        'token_input_sha256':sha((output/'token-input.jsonl').read_bytes()),
        'files':{str(p.relative_to(output)):sha(p.read_bytes()) for p in output.rglob('*') if p.is_file()}}
    (output/'composition.json').write_text(json.dumps(composition,ensure_ascii=False,indent=2)+'\n')
    return {k:v for k,v in composition.items() if k not in ('files','updated_tool_declaration_rows')}

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--source',required=True);ap.add_argument('--baseline',required=True);ap.add_argument('--output',required=True)
    args=ap.parse_args();print(json.dumps(build(args.source,args.baseline,args.output),ensure_ascii=False,indent=2))
