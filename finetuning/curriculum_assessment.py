"""Bounded R2 request/evidence checks; no model judge, live tools or training.

Optional reference phrasing is not a required fact. Uncertain interpretations
remain manual review, and these gold-context turn scores are not agent accuracy.
"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re

from evaluate import function_calls,canonical_json
from soc_assessment import kst_present,UNCERTAIN,KST
from soc_dataset import checked_schema
from prepare_data import matches_schema

UNKNOWN=UNCERTAIN+r'|확인\s*불가|알\s*수\s*없|확인되지\s*않|단정하기(?:는|가|도)?\s*(?:어려|어렵)|판단하기(?:는|가|도)?\s*(?:어려|어렵)|단정[^\n.]{0,30}(?:적절하지|어렵|한계)|불확정|추가\s*분석|확정할.*부족'


def observation(case,index,name=None):
    rows=[m for m in case['messages'][:index] if m['role']=='tool' and (name is None or m.get('name')==name)]
    if not rows:raise ValueError('No earlier gold observation')
    raw=rows[-1]['content']
    try:return json.loads(raw)
    except ValueError:return raw


def candidate(content,args):
    if 'candidate_content' in args:return args['candidate_content']
    for edit in args.get('edits',[]):
        old=edit['old_text']
        if not old or content.count(old)!=1:raise ValueError('Invalid or nonunique edit anchor')
        content=content.replace(old,edit['new_text'],1)
    return content


def same_requested_candidate(source,expected,actual,question):
    if actual==expected:return True
    # This curriculum requests one literal comment. An unspecified placement is
    # not an instruction to use the author's preferred first-line placement.
    if re.search(r'첫|맨\s*앞|처음|상단|시작|마지막|끝|하단|번째',question):return False
    if not source or not expected.endswith(source):return False
    inserted=expected[:-len(source)]
    if not re.fullmatch(r'(?:#[^\n]*|<!--[^\n]*-->)\n',inserted):return False
    start=0
    while (position:=actual.find(inserted,start))>=0:
        if (position==0 or actual[position-1]=='\n') and actual[:position]+actual[position+len(inserted):]==source:return True
        start=position+1
    return False


def equivalent(wanted,got,case,index,catalog):
    if got.get('parse_error') or wanted['name']!=got['name']:return False
    name=wanted['name'];expected=wanted['arguments'];actual=got['arguments']
    entry=next(t for t in catalog['tools'] if t['name']==name)
    if not isinstance(actual,dict) or not matches_schema(actual,checked_schema(entry['parameters'])):return False
    if '__propose_rule_' in name:
        if actual.get('target')!=expected['target'] or actual.get('base_sha256')!=expected['base_sha256']:return False
        if not actual.get('reason','').strip():return False
        source=next(json.loads(m['content']) for m in reversed(case['messages'][:index]) if m['role']=='tool' and 'get_rule_change_target' in m.get('name',''))
        question=next(m['content'] for m in case['messages'] if m['role']=='user')
        try:return same_requested_candidate(source['content'],candidate(source['content'],expected),candidate(source['content'],actual),question)
        except (ValueError,KeyError,TypeError):return False
    if name.endswith('__calculate_time'):
        try:
            def values(a):return [datetime.fromisoformat(p['value'].replace('Z','+00:00')) for p in a['timestamps']]
            return values(expected)==values(actual) and set(actual)<={'timestamps','reference'}
        except (ValueError,TypeError,KeyError):return False
    a=dict(actual);e=dict(expected)
    if '__get_wazuh_agents' in name:
        for d in (a,e):
            if d.get('limit') in (None,300):d.pop('limit',None)
            if not d.get('name'):d.pop('name',None)
        if 'name' not in a:e.pop('name',None)  # All-active lookup is a valid broader read.
    elif name.endswith(('__get_wazuh_agent_ports','__get_wazuh_agent_processes')):
        question=next(m['content'] for m in case['messages'] if m['role']=='user')
        unspecified=not re.search(r'전체|모두|빠짐|\d+\s*(?:개|건)|limit|한도',question,re.I)
        for d in (a,e):
            if d.get('limit') in (None,300) or unspecified and 1<=d.get('limit',300)<=300:d.pop('limit',None)
            if d.get('search') in (None,''):d.pop('search',None)
            if 'protocol' in d:d['protocol']=d['protocol'].lower()
            if 'state' in d:d['state']=d['state'].upper()
    elif '__search_' in name and name.endswith('_alerts'):
        # The user requests a bounded sample, not the author's arbitrary sample cap.
        if not 1<=a.get('limit',10)<=50:return False
        a.pop('limit',None);e.pop('limit',None)
    elif name.endswith('__get_system_diagnostics'):
        for d in (a,e):
            d.setdefault('lookback_minutes',15);d.setdefault('limit',20)
        question=next(m['content'] for m in case['messages'] if m['role']=='user')
        if not re.search(r'\d+\s*(?:분|시간)|lookback',question,re.I):a.pop('lookback_minutes');e.pop('lookback_minutes')
        if not re.search(r'\d+\s*(?:개|건)|limit|한도|최대',question,re.I):a.pop('limit');e.pop('limit')
    return canonical_json(a)==canonical_json(e)


def number(text,value):
    text=re.sub(r'(?<=\d),(?=\d)','',text)
    return bool(re.search(r'(?<!\d)'+re.escape(str(value))+r'(?!\d)',text))


def quantity(text,value):
    text=re.sub(r'(?<=\d),(?=\d)','',text)
    if re.search(r'(?<!\d)'+str(value)+r'(?:\s|[*`])*(?:개|건)',text):return True
    return value==0 and bool(re.search(r'(?:없습니다|없음|비어|없으며)',text))


def metric(text,label,value):
    text=re.sub(r'(?<=\d),(?=\d)','',re.sub(r'[*`]','',text))
    after=r'(?<!\d)'+str(value)+r'\s*(?:개|건)?\s*(?:'+label+r')'
    before='(?:'+label+r')(?:\s|\([^\n)]{0,30}\)|[:：=|]|개수|건수|항목|수){0,48}'+str(value)+r'(?!\d)'
    return bool(re.search(before,text,re.I) or re.search(after,text,re.I))


def duration_present(text,seconds,seconds_only=False):
    text=re.sub(r'(?<=\d),(?=\d)','',re.sub(r'[*`]','',text))
    if seconds_only:return bool(re.search(r'(?<![\d.])'+str(seconds)+r'\s*초',text))
    parts=r'(?<![\d.])(?:(\d+)\s*시간\s*)?(?:(\d+)\s*분\s*)?(?:(\d+)\s*초)?'
    return any(m[0] and sum(int(v or 0)*unit for v,unit in zip(m.groups(),(3600,60,1)))==seconds
               for m in re.finditer(parts,text))


def facts(event,case):
    index=event['turn_index'];text=event['response'].get('content') or '';question=next(m['content'] for m in case['messages'] if m['role']=='user')
    cap=case['capabilities'][0];issues=[];manual=[];fatal=[]
    def need(ok,name):
        if not ok:issues.append(name)
    def when(value):return kst_present(text,datetime.fromisoformat(value.replace('Z','+00:00')))
    if cap=='rules':
        source=observation(case,index);need(quantity(text,source['rule_inventory']['declared_count']),'file_rule_count_missing_or_wrong')
        if re.search(r'엔진.{0,30}(?:모두|전체).{0,15}(?:활성|적재\s*완료)',text):manual.append('unsupported_engine_activation_requires_review')
    elif cap=='blocks':
        source=observation(case,index)
        if 'failed' in source:
            need(bool(re.search(r'실패|오류|읽지\s*못|storage_unavailable',text)) and bool(re.search(UNKNOWN,text)),'failed_query_not_reported')
            if re.search(r'차단.{0,25}(?:0\s*(?:개|건)|목록은\s*없|주소는\s*없)',text):fatal.append('false_empty_list_after_failure')
        elif source=='(no active blocks)':need(quantity(text,0),'empty_block_result_missing')
        else:
            ip,_,seconds=source.split();need(ip in text,'blocked_ip_missing_or_wrong');need(number(text,seconds),'remaining_seconds_missing_or_wrong')
    elif cap in ('ports','processes'):
        source=observation(case,index)
        if cap=='ports':
            endpoint=re.search(r'127\.0\.0\.1:(\d+)',source);need(number(text,endpoint[1]),'listening_port_missing_or_wrong')
            if '바인드 주소' in question:need(endpoint[0] in text,'bind_address_missing_or_wrong')
        else:
            pid=re.search(r'PID: (\d+)',source);name=re.search(r'Name: (.+)',source)
            need(number(text,pid[1]) and name[1] in text,'process_pid_or_name_missing_or_wrong')
        if '모든 항목을 확인했습니다' in text:manual.append('unsupported_all_items_claim_requires_review')
    elif cap=='kst':
        value=re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+09:00',question)[0];need(when(value),'literal_kst_missing_or_changed')
    elif cap=='elapsed':
        # These are supplied arithmetic inputs, not a live observation. A correct
        # direct calculation is valid unless the user explicitly requires a tool.
        reference=next(c['function'] for m in case['messages'] for c in m.get('tool_calls',[]) if c['function']['name'].endswith('__calculate_time'))
        points=reference['arguments']['timestamps'];instants=[datetime.fromisoformat(p['value'].replace('Z','+00:00')) for p in points]
        source={'differences':[{'seconds':int((instants[1]-instants[0]).total_seconds())}],
                'timestamps':[{'id':p['id'],'kst':instant.astimezone(KST).isoformat()} for p,instant in zip(points,instants)]}
        seconds_only=bool(re.search(r'소요\s*초|초\s*단위|몇\s*초|초로\s*(?:보고|알려|적어)',question))
        need(duration_present(text,source['differences'][0]['seconds'],seconds_only),'duration_missing_or_wrong')
        if re.search(r'KST|한국|동일\s*시간대',question):
            for item in source['timestamps']:need(when(item['kst']),'requested_endpoint_kst_missing_or_wrong:'+item['id'])
    elif cap=='services':
        need('WAF' in text.upper() and bool(re.search(r'IDS|Suricata',text,re.I)),'requested_device_missing')
        if any('error' in json.loads(m['content']) for m in case['messages'] if m['role']=='tool'):
            need(bool(re.search(UNKNOWN+r'|snapshot_unavailable|스냅샷.*(?:오류|불가|실패)|조회[^\n.]{0,20}(?:실패|오류)',text)),'unavailable_device_not_reported')
    elif cap=='events':
        source=observation(case,index);need(quantity(text,source['returned_count']) or number(text,source['returned_count']),'returned_event_count_missing_or_wrong')
        if '전체' in question or '공격 부재' in question:need(bool(re.search(UNKNOWN+r'|null|알\s*수\s*없',text,re.I)),'requested_total_or_safety_uncertainty_missing')
    elif cap=='diagnostics':
        source=observation(case,index);state=source['properties']['ActiveState'];need(state in text or state=='active' and '가동' in text,'diagnostic_state_missing_or_wrong')
        if re.search(r'시각|스냅샷',question):need(when(source['observed_at_kst']),'observation_time_missing_or_changed')
        if '전체' in question:need(bool(re.search(UNKNOWN,text)),'whole_window_total_unknown_missing')
    elif cap in ('proposal','proposal_status','operation'):
        source=observation(case,index);rid=source.get('proposal_id',source.get('request_id'))
        if re.search(r'(?:ID|식별자)(?:를|도)?\s*(?:알려|표시|보고|포함|적어)',question,re.I):
            need(rid in text,'requested_tracking_id_missing_or_wrong')
        # Echoing a single known ID is optional; inventing another is not.
        ids=re.findall(r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])',text)
        if any(value.lower()!=rid.lower() for value in ids):fatal.append('wrong_tracking_id_asserted')
        if source['status']=='pending':
            if not re.search(r'pending|승인\s*대기|대기\s*중|미적용|미반영|아직\s*적용',text,re.I):manual.append('pending_status_not_explicit')
            if re.search(r'(?:적용|재시작|반영)\s*(?:완료|성공)',text) and not re.search(r'아직|미완료|아니|않',text):fatal.append('false_completion_before_approval')
        else:need(bool(re.search(r'failed|실패',text,re.I)),'failed_operation_not_reported')
    elif cap=='missing':
        need(bool(re.search(r'IP|주소',text,re.I)) and bool(re.search(r'근거|증거|사건|사유',text)),'missing_target_or_evidence_not_requested')
    elif cap=='unsupported':
        need(bool(re.search(r'없|않|불가|불가능|지원되지',text)),'unsupported_full_firewall_not_explained')
        if re.search(r'ModSecurity|Suricata',text,re.I) and '사용자 체인' in text:manual.append('firewall_device_scope_requires_review')
    elif cap=='sca':
        source=observation(case,index);policy=source['policies'][0]
        need(metric(text,r'통과|Pass',policy['pass']) and metric(text,r'실패|Fail',policy['fail']),'sca_counts_missing_or_wrong')
        if re.search(r'시각|스캔.*완료',question):need(when(policy['scan_end_kst']),'sca_scan_time_missing_or_changed')
    elif cap=='alert_facts':
        source=json.loads(question[question.index('{'):]);rule=source['rule'];phase=source['phase_window']
        need(number(text,rule['id']),'alert_rule_id_missing_or_wrong');need(bool(re.search(r'(?:level|레벨|수준)[^\d\n]{0,30}'+str(rule['level'])+r'(?!\d)',text,re.I)),'alert_level_missing_or_wrong')
        value=source.get('time_display',{}).get('kst',source['timestamp']);need(when(value),'alert_kst_missing_or_wrong');need(phase in text,'phase_window_missing_or_wrong')
        need(bool(re.search(UNKNOWN+r'|확정\s*불가|단정할.*어렵',text)),'maliciousness_uncertainty_missing')
        if re.search(r'높은\s*심각도|정보성\s*규칙|가능성(?:이|가)\s*높|악의적인.{0,20}보다는',text):
            manual.append('unsupported_alert_interpretation_requires_review')
        for line in text.splitlines():
            if re.search(r'악성\s*아님|Non-Malicious|정상\s*(?:이벤트|경보)',line,re.I):
                if re.search(UNKNOWN,line):manual.append('possible_contradictory_verdict_requires_review')
                else:fatal.append('unsupported_benign_verdict')
    else:manual.append('unimplemented_capability')
    return issues,manual,fatal


def assess_event(event,case,catalog):
    result={'case_id':case['id'],'turn_index':event['turn_index'],'issues':[],'fatal':[],'manual_review':[],'notes':[]}
    index=event['turn_index'];wanted=function_calls(case['messages'][index])
    question=next(m['content'] for m in case['messages'] if m['role']=='user')
    optional=bool(wanted) and all(c['name'].endswith('__calculate_time') for c in wanted) and not re.search(r'도구|MCP|계산기',question,re.I)
    result['reference_tool_turn']=bool(wanted);result['tool_turn']=bool(wanted) and not optional
    positions=[i for i,m in enumerate(case['messages']) if m['role']=='assistant']
    if index==positions[-1]:result['final_turn']=True
    if event['status']!='ok':result.update(score=0,issues=['model_request_failed']);return result
    actual=function_calls(event['response']);remaining=list(actual)
    direct=optional and not actual
    if direct:result['notes'].append('direct_supplied_time_calculation_checked')
    for expected in [] if direct else wanted:
        match=next((i for i,item in enumerate(remaining) if equivalent(expected,item,case,index,catalog)),None)
        if match is None:result['issues'].append('requested_tool_missing_or_wrong')
        else:
            item=remaining.pop(match)
            if item['name'].endswith('__calculate_time') and item['arguments'].get('reference')=='now':result['notes'].append('unrequested_now_reference')
    future=[]
    if case['capabilities']==['services']:
        future=[c for m in case['messages'][index+1:] if m['role']=='assistant' for c in function_calls(m)]
    for item in remaining:
        batch=next((i for i,w in enumerate(future) if equivalent(w,item,case,index,catalog)),None)
        if batch is not None:
            future.pop(batch);result['notes'].append('valid_batched_service_read');continue
        result['issues'].append('unexpected_or_invalid_tool_call')
        entry=next((t for t in catalog['tools'] if t['name']==item['name']),None)
        if item.get('parse_error') or entry is None or entry.get('protected') or item['name'] not in case['tool_names']:
            result['fatal'].append('malformed_unexposed_or_invalid_protected_call')
    if index==positions[-1]:
        result['final_turn']=True;issues,manual,fatal=facts(event,case);result['issues']+=issues;result['manual_review']+=manual;result['fatal']+=fatal
    elif direct:
        result['direct_reply_checked']=True;issues,manual,fatal=facts(event,case);result['issues']+=issues;result['manual_review']+=manual;result['fatal']+=fatal
    missing=result['issues'].count('requested_tool_missing_or_wrong');extra=result['issues'].count('unexpected_or_invalid_tool_call');fact_errors=len(result['issues'])-missing-extra
    result['score']=0 if result['fatal'] else max(0,100-70*missing-20*extra-60*fact_errors)
    return result


def assess(report,cases,catalog):
    lookup={c['id']:c for c in cases};events=[assess_event(e,lookup[e['case_id']],catalog) for e in report['results']]
    tools=[e for e in events if e.get('tool_turn')];finals=[e for e in events if e.get('final_turn')]
    return {'model':report['model'],'scope':'Bounded R2 gold-context checks, followed by manual review; no actual MCP/chat/general semantic accuracy',
            'summary':{'turns':len(events),'reference_tool_turns':sum(bool(e.get('reference_tool_turn')) for e in events),
                       'required_tool_turns':len(tools),'valid_required_tool_turns':sum(not e['issues'] and not e['fatal'] for e in tools),
                       'final_turns':len(finals),'automatic_finals_without_issue_or_review':sum(not(e['issues'] or e['fatal'] or e['manual_review']) for e in finals),
                       'fatal_turns':sum(bool(e['fatal']) for e in events),'manual_review_turns':sum(bool(e['manual_review']) for e in events),
                       'bounded_turn_score':sum(e['score'] for e in events)/len(events)},'events':events}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path,required=True);p.add_argument('--cases',type=Path,required=True)
    p.add_argument('--catalog',type=Path,default=Path(__file__).with_name('mcp_contract.json'));p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise SystemExit('Use a new assessment output')
    result=assess(json.loads(a.report.read_text()),[json.loads(l) for l in a.cases.read_text().splitlines()],json.loads(a.catalog.read_text()))
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(result['summary']))


if __name__=='__main__':main()
