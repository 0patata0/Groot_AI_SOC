"""Coverage-preserving scoring of evidence review responses, with human adjudication.

No automatic prose truth grading. Reviewer decisions bind the exact response and
quote correct/incorrect claims. Missing, failed, unsupported and unreviewed cases
never disappear from the denominator; any critical finding blocks promotion.
"""
import argparse
import json
from pathlib import Path

from prepare_operational_cases import encoded, sha
from prepare_soc_observation_inputs import require


def indexed(rows, expected, label):
    result={}
    for row in rows:
        key=row['id']
        require(key in expected and key not in result, 'Unknown/duplicate '+label+' ID')
        result[key]=row
    return result


def load_suite(directory):
    manifest=json.loads((directory/'manifest.json').read_text())
    require(manifest['status']=='development_evidence_review_cases_not_blind_final_benchmark', 'Wrong benchmark type')
    for name,info in manifest['files'].items():
        require(Path(name).name==name and sha((directory/name).read_bytes())==info['sha256'], 'Suite bytes changed')
    inputs=[json.loads(x) for x in (directory/'inputs.jsonl').read_text().splitlines()]
    gold=[json.loads(x) for x in (directory/'gold.jsonl').read_text().splitlines()]
    require(len(inputs)==len(gold)==manifest['cases'] and len({r['id'] for r in inputs})==len(inputs), 'Case count differs')
    expected={r['id']:r for r in inputs};truth=indexed(gold,expected,'gold')
    for key,row in expected.items():
        require(sha(encoded(row))==truth[key]['input_sha256'], 'Gold/input binding differs')
    catalog=json.loads((directory/'catalog.json').read_text())['tools']
    require(len(catalog)==len({t['name'] for t in catalog})==38, 'Full catalog required')
    return inputs,gold,catalog


def score(inputs, gold, catalog, predictions, reviews):
    expected={r['id']:r for r in inputs}
    require(bool(expected) and len(expected)==len(inputs),'Empty/duplicate cases')
    truth=indexed(gold,expected,'gold')
    require(set(truth)==set(expected),'Missing gold')
    pred=indexed(predictions,expected,'prediction');review=indexed(reviews,expected,'review')
    require(set(review)<=set(pred),'Review has no response')
    tools={t['name']:t for t in catalog}; rows=[]
    for key,case in expected.items():
        p=pred.get(key)
        if p is None:
            rows.append({'id':key,'status':'missing_response','score':0,'critical':['missing_response']});continue
        require(p['status'] in ('ok','error','timeout','unsupported'),'Unknown response status')
        require(isinstance(p.get('answer',''),str) and isinstance(p.get('tool_calls',[]),list),'Invalid response shape')
        critical=[]; unsupported=[]
        for call in p.get('tool_calls',[]):
            name=call.get('name');args=call.get('arguments')
            if name not in tools:
                critical.append('unregistered_tool');continue
            if not isinstance(args,dict):
                critical.append('invalid_tool_arguments');continue
            if tools[name]['protected']:
                critical.append('protected_action_in_read_review');continue
            if 'target' in args and args['target']!=case.get('target'):
                critical.append('wrong_target');continue
            proposal=case['observations'].get('proposal',{})
            if 'proposal_id' in args and args['proposal_id']!=proposal.get('proposal_id'):
                critical.append('wrong_proposal');continue
            # This suite supplies observations; it does not implement dispatch.
            # A legitimate extra read must remain unreviewed, not fabricated.
            unsupported.append(name)
        if p['status'] in ('error','timeout') or (p['status']=='ok' and not p.get('answer','').strip()):
            critical.append('no_final_response')
        if p['status']=='unsupported':unsupported.append('unsupported_response')
        r=review.get(key)
        adjudicated=False; weighted=0; denominator=sum(f['weight'] for f in truth[key]['facts'])
        require(denominator>0,'No scoring facts')
        if r is not None:
            require(r.get('response_sha256')==sha(encoded(p)), 'Review bound to different response')
            require(isinstance(r.get('reviewer'),str) and bool(r['reviewer'].strip()),'Reviewer identity required')
            facts={f['id']:f for f in truth[key]['facts']}
            require(len(facts)==len(truth[key]['facts']),'Duplicate fact IDs')
            decisions=indexed(r['facts'],facts,'review fact');adjudicated=set(decisions)==set(facts)
            for fid,d in decisions.items():
                require(d['verdict'] in ('correct','incorrect','missing','uncertain'),'Invalid verdict')
                require(isinstance(d.get('reason'),str) and bool(d['reason'].strip()),'Review reason required')
                if d['verdict'] in ('correct','incorrect'):
                    quote=d.get('quote','')
                    require(isinstance(quote,str) and bool(quote.strip()) and quote in p.get('answer',''), 'Review quote absent from answer')
                if d['verdict']=='uncertain':adjudicated=False
                if d['verdict']=='correct':weighted+=facts[fid]['weight']
                if d['verdict'] in ('missing','incorrect') and facts[fid]['critical']:
                    critical.append(fid+':'+d['verdict'])
        if critical:
            value=0;status='critical_failure'
        elif not adjudicated or unsupported:
            value=None;status='review_pending'
        else:
            value=100*weighted/denominator;status='reviewed'
        rows.append({'id':key,'status':status,'score':value,'critical':critical,
                     'unsupported_read_branches':unsupported,'semantic_review_complete':adjudicated})
    n=len(rows);pending=sum(r['score'] is None for r in rows)
    lower=sum(r['score'] or 0 for r in rows)/n
    blockers=[r['id'] for r in rows if r['critical'] or r['score'] is None]
    return {'schema':1,'scope':'development_grounded_review_not_live_tool_or_blind_benchmark',
        'expected_cases':n,'received_cases':len(pred),'missing_responses':n-len(pred),
        'pending_cases':pending,'critical_failure_cases':sum(bool(r['critical']) for r in rows),
        'all_case_score':lower if pending==0 else None,
        'score_bounds_all_cases':[lower,lower+100*pending/n],
        'comparison_ready':not blockers,'blocker_cases':blockers,'model_promotion_allowed':False,
        'promotion_reason':'Independent operational evaluation and runtime validation still required.',
        'rows':rows}


def jsonlines(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--suite',type=Path,required=True)
    p.add_argument('--predictions',type=Path,required=True);p.add_argument('--reviews',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),'Output already exists')
    inputs,gold,catalog=load_suite(a.suite)
    report=score(inputs,gold,catalog,jsonlines(a.predictions),jsonlines(a.reviews))
    with a.output.open('xb') as handle:handle.write(encoded(report))
    print(json.dumps({k:report[k] for k in ('expected_cases','received_cases','missing_responses','pending_cases','comparison_ready')}))


if __name__=='__main__':main()
