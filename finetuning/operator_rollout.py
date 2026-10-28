"""Closed-loop Ollama workflow evaluation against fixed offline observations.

Only a correct next call receives its fixture. Unexpected/missing calls fail
closed. NO MCP dispatch, approval, live containment or filesystem mutation occurs.
The automatic score is provisional; semantic review is required before promotion.
"""
import argparse,copy,hashlib,json,time
from collections import Counter
from datetime import datetime,timezone,timedelta
from pathlib import Path
from urllib import request
from evaluate import function_calls
from prepare_data import canonical,matches_schema
from soc_dataset import checked_schema,validate_case
from soc_evaluate import transport_tools

def edited_content(content,edits):
    spans=[]
    for edit in edits:
        old=edit['old_text']
        if content.count(old)!=1:raise ValueError('Edit anchor is not unique')
        start=content.index(old);spans.append((start,start+len(old),edit['new_text']))
    spans.sort()
    if any(a[1]>b[0] for a,b in zip(spans,spans[1:])):raise ValueError('Overlapping edits')
    for start,end,replacement in reversed(spans):content=content[:start]+replacement+content[end:]
    return content

def match_call(actual,expected,catalog,observations=()):
    entry=next((t for t in catalog['tools'] if t['name']==actual['name']),None)
    if actual.get('parse_error') or not entry or actual['name']!=expected['name']:return False
    args=actual['arguments']
    if not matches_schema(args,checked_schema(entry['parameters'])):return False
    # A reason is free prose, never a required memorized sentence. All scope,
    # IDs, exact edits and base hashes still have to match the reference.
    a={k:v for k,v in args.items() if k!='reason'};b={k:v for k,v in expected['arguments'].items() if k!='reason'}
    if actual['name'].endswith('propose_rule_edit') and {k:v for k,v in a.items() if k!='edits'}=={k:v for k,v in b.items() if k!='edits'}:
        for observation in reversed(observations):
            if observation['role']!='tool':continue
            value=json.loads(observation['content'])
            if value.get('target')==a['target'] and value.get('sha256')==a['base_sha256']:
                try:return edited_content(value['content'],a['edits'])==edited_content(value['content'],b['edits'])
                except ValueError:return False
    return a==b

def replay(case,catalog,generate,max_turns=8):
    validate_case(case,catalog);messages=copy.deepcopy(case['messages'][:2]);steps=[];trace=[]
    for i,m in enumerate(case['messages']):
        if m['role']=='assistant' and m.get('tool_calls'):
            if len(m['tool_calls'])!=1:raise ValueError('Fixture must use one serial observation per step')
            steps.append((m['tool_calls'][0]['function'],case['messages'][i+1]))
    done=0;issues=[];final='';unsupported=False;lookup={t['name']:t for t in catalog['tools']}
    tools=transport_tools([{'type':'function','function':{'name':t['name'],'description':t['description'],'parameters':t['parameters']}} for t in catalog['tools']])
    for turn in range(max_turns):
        response=generate(copy.deepcopy(messages),tools);prediction=response.get('message',response);calls=function_calls(prediction);trace.append({'turn':turn,'response':response,'parsed_calls':calls});messages.append(copy.deepcopy(prediction))
        if not calls:
            final=prediction.get('content') or ''
            if done!=len(steps):issues.append('required_call_omitted')
            break
        for index,call in enumerate(calls):
            if done>=len(steps) or not match_call(call,steps[done][0],catalog,messages):
                entry=lookup.get(call['name'])
                valid=entry and not call.get('parse_error') and matches_schema(call['arguments'],checked_schema(entry['parameters']))
                wanted=steps[done][0]['arguments'] if done<len(steps) else {}
                wrong_target=any(k in wanted and k in call['arguments'] and wanted[k]!=call['arguments'][k] for k in ('target','source_ip','request_id','proposal_id'))
                if wrong_target:issues.append('unexpected_or_wrong_call')
                elif valid and not entry.get('protected'):
                    # A reasonable alternative read is not equivalent to a
                    # wrong/unsafe action. No fixture exists for this branch;
                    # stop without feeding gold or assigning an accuracy score.
                    issues.append('unmodelled_read_branch');unsupported=True
                else:issues.append('invalid_or_unexpected_protected_call')
                break
            observed=copy.deepcopy(steps[done][1]);observed['name']=call['name']
            raw=prediction.get('tool_calls',[])
            observed['tool_call_id']=raw[index].get('id',str(done)) if index<len(raw) else str(done)
            messages.append(observed);done+=1
        if issues:break
    else:issues.append('turn_limit')
    missing=[alts for alts in case.get('checks',{}).get('required_facts',[]) if not any(s in final for s in alts)]
    if missing and not unsupported:issues.append('required_report_fact_omitted')
    return {'case_id':case['id'],'workflow':case['review']['workflow'],'expected_steps':len(steps),'observed_steps':done,'provisional_score':None if unsupported else 0 if issues else 100,'issues':issues,'missing_required_facts':[] if unsupported else missing,'final':final,'trace':trace,'semantic_review_required':True,'scope':'offline serial rollout, no actual MCP execution; equivalent exact rule candidate accepted; unmodelled read branches unscored'}

def select(cases,split,each):
    selected=[];counts=Counter()
    for case in cases:
        if case['split']!=split:continue
        kind=case['review']['workflow']
        if each and counts[kind]>=each:continue
        selected.append(case);counts[kind]+=1
    if not selected:raise ValueError('No cases selected')
    return selected

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--model',required=True);p.add_argument('--cases',type=Path,required=True);p.add_argument('--catalog',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--split',choices=['validation','test'],default='validation');p.add_argument('--each-workflow',type=int,default=1);p.add_argument('--num-ctx',type=int,default=16384);args=p.parse_args()
    if args.output.exists():raise ValueError('Use a fresh result file')
    cases=select(list(map(json.loads,args.cases.read_text().splitlines())),args.split,args.each_workflow);catalog=json.loads(args.catalog.read_text())
    report={'model':args.model,'split':args.split,'source_cases_sha256':hashlib.sha256(args.cases.read_bytes()).hexdigest(),'catalog_sha256':hashlib.sha256(args.catalog.read_bytes()).hexdigest(),'started_at_kst':datetime.now(timezone(timedelta(hours=9))).isoformat(),'status':'running','num_ctx_requested':args.num_ctx,'num_predict':768,'case_ids':[c['id'] for c in cases],'results':[]}
    def save():
        temp=args.output.with_suffix('.tmp');temp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');temp.replace(args.output)
    def generate(messages,tools):
        payload={'model':args.model,'messages':messages,'tools':tools,'stream':False,'think':False,'keep_alive':'10m','options':{'temperature':0,'seed':42,'num_ctx':args.num_ctx,'num_predict':768}}
        req=request.Request('http://127.0.0.1:11434/api/chat',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
        with request.urlopen(req,timeout=180) as r:return json.load(r)
    save();start=time.monotonic()
    try:
        for c in cases:report['results'].append(replay(c,catalog,generate));save()
        scores=[r['provisional_score'] for r in report['results'] if r['provisional_score'] is not None]
        report.update(status='completed',elapsed_seconds=round(time.monotonic()-start,2),provisional_score=sum(scores)/len(scores) if scores else None,scored_cases=len(scores),unscored_cases=len(cases)-len(scores),semantic_review_required=True)
    except BaseException as exc:report.update(status='failed',error_type=type(exc).__name__);raise
    finally:save()
    print(json.dumps({'status':report['status'],'cases':len(report['results']),'provisional_score':report.get('provisional_score')}))
if __name__=='__main__':main()
