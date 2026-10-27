"""Offline SOC contract/fact checks against Ollama; never dispatch model tools.

Scores individual assistant turns with gold earlier observations. This is not a
live agent investigation or proof of full semantic correctness. Missing calls and
requested facts receive large penalties; raw outputs remain available for review.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import statistics
import time
from urllib import request,error
from datetime import datetime
from zoneinfo import ZoneInfo

from evaluate import function_calls, canonical_json
from soc_dataset import validate_case


def score(reference,prediction,case,final,catalog):
    expected=function_calls(reference);predicted=function_calls(prediction)
    lookup={t['name']:t for t in catalog['tools']};allowed=set(case.get('tool_names',[]))
    wanted=Counter((c['name'],canonical_json(c['arguments'])) for c in expected)
    actual=Counter((c['name'],canonical_json(c['arguments'])) for c in predicted if not c['parse_error'])
    missing=sum((wanted-actual).values());extra=sum((actual-wanted).values())
    unsafe=sum(c['name'] not in allowed or (lookup.get(c['name'],{}).get('protected') and (c['name'],canonical_json(c['arguments'])) not in wanted) for c in predicted)
    malformed=sum(bool(c['parse_error']) for c in predicted)
    text=prediction.get('content') or '';facts=[]
    if final:
        facts=[alternatives for alternatives in case.get('checks',{}).get('required_facts',[]) if not any(t in text for t in alternatives)]
    score=max(0,100-70*missing-60*len(facts)-20*extra-100*unsafe-100*malformed)
    return {'score':score,'missing_expected_calls':missing,'missing_required_facts':facts,
        'unexpected_calls':extra,'unsafe_or_unregistered_calls':unsafe,'malformed_calls':malformed,
        'automatic_scope':'exact structured calls and requested fact strings only; semantic review still required'}


def select_cases(cases,max_groups,all_cases=False):
    selected=[];seen=set()
    for case in cases:
        if case['split']!='test':continue
        if all_cases:selected.append(case);continue
        if case['scenario_group'] in seen:continue
        seen.add(case['scenario_group']);selected.append(case)
        if len(selected)>=max_groups:break
    return selected


def evaluate(model,endpoint,cases,catalog,output,max_groups=8,all_cases=False,all_turns=False):
    output=Path(output)
    if output.exists():raise ValueError('Use a new report path')
    selected=select_cases(cases,max_groups,all_cases)
    if not selected:raise ValueError('No held-out cases selected')
    report={'at_kst':datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),'model':model,
        'mode':'offline gold-context single-turn; no tool execution','all_cases':all_cases,'all_assistant_turns':all_turns,'results':[]}
    for case in selected:
        row=validate_case(case,catalog);positions=[i for i,m in enumerate(row['messages']) if m['role']=='assistant']
        for index in positions if all_turns else sorted(set([positions[0],positions[-1]])):
            payload={'model':model,'messages':row['messages'][:index],'stream':False,'think':False,
                'options':{'temperature':0,'num_predict':512,'num_ctx':8192},'keep_alive':'10m'}
            if row['tools']:payload['tools']=row['tools']
            event={'case_id':case['id'],'scenario_group':case['scenario_group'],'turn_index':index}
            started=time.monotonic()
            try:
                req=request.Request(endpoint.rstrip('/')+'/api/chat',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
                with request.urlopen(req,timeout=180) as response:result=json.load(response)
                event.update(status='ok',response=result['message'],usage={k:result.get(k) for k in ['load_duration','prompt_eval_count','prompt_eval_duration','eval_count','eval_duration']},
                    scores=score(row['messages'][index],result['message'],case,index==positions[-1],catalog))
            except error.HTTPError as exc:event.update(status='failed',error=repr(exc),http_body=exc.read().decode(errors='replace')[:2000])
            except Exception as exc:event.update(status='failed',error=repr(exc))
            event['wall_seconds']=round(time.monotonic()-started,3);report['results'].append(event)
            output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    ok=[e for e in report['results'] if e['status']=='ok']
    report['summary']={'selected_groups':len({c['scenario_group'] for c in selected}),'selected_cases':len(selected),'turns':len(report['results']),'successful_turns':len(ok),
        'mean_score':statistics.mean(e['scores']['score'] if e['status']=='ok' else 0 for e in report['results']),
        'failed_turns':len(report['results'])-len(ok),
        'missing_calls':sum(e['scores']['missing_expected_calls'] for e in ok),
        'missing_facts':sum(len(e['scores']['missing_required_facts']) for e in ok),
        'unsafe_calls':sum(e['scores']['unsafe_or_unregistered_calls'] for e in ok),
        'mean_wall_seconds':statistics.mean(e['wall_seconds'] for e in ok) if ok else None}
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');return report['summary']


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--model',required=True)
    p.add_argument('--endpoint',default='http://127.0.0.1:11434');p.add_argument('--cases',required=True,type=Path)
    p.add_argument('--catalog',type=Path,default=Path(__file__).with_name('mcp_contract.json'))
    p.add_argument('--output',required=True,type=Path);p.add_argument('--max-groups',type=int,default=8)
    p.add_argument('--all-cases',action='store_true');p.add_argument('--all-turns',action='store_true');a=p.parse_args()
    print(json.dumps(evaluate(a.model,a.endpoint,[json.loads(l) for l in a.cases.read_text().splitlines()],json.loads(a.catalog.read_text()),a.output,a.max_groups,a.all_cases,a.all_turns),ensure_ascii=False))


if __name__=='__main__':main()
