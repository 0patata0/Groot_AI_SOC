"""Case-level quality audit over frozen gold-context turns; no tools or model judge.

Any missing call/requested fact, failed request, or fatal error makes a case zero.
Extra calls cost 20 each. Every case requires an evidence-backed manual review.
These are bounded scenario scores, not real-world accuracy or a causal test.
"""
import argparse
import json
from pathlib import Path
from curriculum_assessment import assess


def aggregate(assessment,case_ids,reviews=None):
    groups={key:[] for key in case_ids}
    if len(groups)!=len(case_ids):raise ValueError('Duplicate case ID')
    for event in assessment['events']:
        if event['case_id'] not in groups:raise ValueError('Unknown assessed case')
        groups[event['case_id']].append(event)
    if any(not events for events in groups.values()):raise ValueError('Incomplete case coverage')
    if reviews is not None and set(reviews)!=set(groups):raise ValueError('Every case needs one manual review')
    rows=[]
    for key,events in groups.items():
        issues=[x for e in events for x in e['issues']];fatal=[x for e in events for x in e['fatal']]
        extra=issues.count('unexpected_or_invalid_tool_call');major=[x for x in issues if x!='unexpected_or_invalid_tool_call']
        review=reviews[key] if reviews is not None else None
        if review is not None:
            if review.get('severity') not in ['clear','minor','major','fatal'] or not review.get('evidence') or not review.get('rationale'):
                raise ValueError('Manual review needs severity, evidence and rationale')
        waived=[]
        if review is not None and review.get('waive_issues'):
            waived=review['waive_issues']
            if (not isinstance(waived,list) or set(waived)-set(major)
                    or set(waived)&{'requested_tool_missing_or_wrong','model_request_failed'}
                    or not review.get('waive_reason')):raise ValueError('Only evidenced fact-format false positives may be waived')
            major=[x for x in major if x not in waived]
        blocked=bool(major or fatal or review and review['severity'] in ['major','fatal'])
        provisional=0 if blocked else max(0,100-20*(extra+int(bool(review and review['severity']=='minor'))))
        rows.append({'case_id':key,'automatic_issues':issues,'waived_issues':waived,'major_issues':major,'fatal':fatal,'extra_calls':extra,
                     'manual_review':review,'score':provisional if review is not None else None,
                     'provisional_score':provisional,'all_automatic_turns_clean':not issues and not fatal})
    final=reviews is not None
    return {'model':assessment['model'],'finalized':final,'scope':__doc__.strip(),
            'summary':{'cases':len(rows),'case_score':sum(r['score'] for r in rows)/len(rows) if final else None,
                       'cases_scoring_100':sum(r['score']==100 for r in rows) if final else None,
                       'automatic_major_or_fatal_cases':sum(bool(r['major_issues'] or r['fatal']) for r in rows),
                       'automatic_all_turns_clean_cases':sum(r['all_automatic_turns_clean'] for r in rows),
                       'manual_major_or_fatal_cases':sum(r['manual_review']['severity'] in ['major','fatal'] for r in rows) if final else None},
            'turn_assessment':assessment['summary'],'cases':rows}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path,required=True);p.add_argument('--cases',type=Path,required=True);p.add_argument('--catalog',type=Path,required=True);p.add_argument('--reviews',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise ValueError('Use a new output path')
    cases=[json.loads(x) for x in a.cases.read_text().splitlines()];report=json.loads(a.report.read_text())
    expected={(c['id'],i) for c in cases for i,m in enumerate(c['messages']) if m['role']=='assistant'}
    actual=[(e['case_id'],e['turn_index']) for e in report['results']]
    if set(actual)!=expected or len(actual)!=len(expected):raise ValueError('Incomplete or duplicated turn coverage')
    reviews=json.loads(a.reviews.read_text()) if a.reviews else None
    if reviews is not None:
        for key,review in reviews.items():
            blobs=[(e['response'].get('content') or '')+'\n'+json.dumps(e['response'],ensure_ascii=False,sort_keys=True) for e in report['results'] if e['case_id']==key and e['status']=='ok']
            if review.get('evidence') not in '\n'.join(blobs):raise ValueError('Manual evidence must quote the actual response')
    result=aggregate(assess(report,cases,json.loads(a.catalog.read_text())),[c['id'] for c in cases],reviews)
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(result['summary']))


if __name__=='__main__':main()
