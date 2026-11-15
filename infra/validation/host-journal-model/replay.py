#!/usr/bin/env python3
"""Recheck private observed drafts against the exact frozen candidate; no API calls."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True,
                        help='Private collected out/candidate/result.json; never publish this file')
    args=parser.parse_args();root=args.candidate.resolve();here=Path(__file__).resolve().parent
    manifest=json.loads((here/'source-manifest.json').read_text())
    checked=0
    for name,digest in manifest['task_sources'].items():
        if not name.startswith('candidate/'):continue
        rel=Path(name).relative_to('candidate');assert not rel.is_absolute() and '..' not in rel.parts
        p=root/rel;assert p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root)
        assert hashlib.sha256(p.read_bytes()).hexdigest()==digest,name;checked+=1
    assert checked==59
    p=args.evidence;assert p.is_file() and not p.is_symlink() and p.stat().st_size<4194304
    frozen=json.loads((here/'validation.json').read_text())
    assert hashlib.sha256(p.read_bytes()).hexdigest()==frozen['private_result_sha256']
    result=json.loads(p.read_text());assert result['status']=='completed' and len(result['results'])==4
    expected={x['id']:x for x in frozen['cases']}
    sys.path.insert(0,str(root/'infra/ollama-trial'));import harness
    rows=[]
    for case in result['results']:
        entry=expected[case['case_id']]
        assert hashlib.sha256(case['final_response'].encode()).hexdigest()==entry['final_response_sha256']
        for draft in case.get('verification_claim_audit',[]):
            assert hashlib.sha256(draft['draft'].encode()).hexdigest()==draft['draft_sha256']
            issues=harness.violations(case['question'],draft['draft'],case['calls'])
            assert issues==draft['issues']
            rows.append({'case':case['case_id'],'draft_sha256':draft['draft_sha256'],'issues':issues})
    print(json.dumps({'verified_candidate_sources':checked,'draft_replays':rows,
        'scope':'Same consumed drafts, not independent cases or operating/model calls',
        'api_calls':0,'operating_changes':0},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
