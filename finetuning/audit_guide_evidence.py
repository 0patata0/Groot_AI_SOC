#!/usr/bin/env python3
"""Independently audit selected GUIDE rows and original-test overlap.

No model input or target is generated. Original test contents are not retained.
"""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect_guide_evidence as G

TEST_URL = G.BASE + 'GUIDE_Test.csv?datasetVersionNumber=2'
TEST_BYTES = 1087963831
TEST_PREFIX = 'e673efe6b1e88090726ffd2d25118310a75823e461d5907408da6640e936d554'


def audit_selected(root):
    manifest = json.loads((root/'manifest.json').read_text())
    if manifest['status'] != 'collected_for_review' or not manifest['source_eof_verified']:
        raise ValueError('Collection not complete')
    reserved = G.reserved_organizations((root/'rankings.csv').read_bytes())
    groups, digest, previous, count = {}, hashlib.sha256(), 0, 0
    with (root/'selected.jsonl').open('rb') as source:
        for line in source:
            digest.update(line)
            item = json.loads(line)
            ordinal, row = item['record_ordinal'], item['record']
            if not previous < ordinal <= manifest['source_records']:
                raise ValueError('Invalid source ordinal')
            previous = ordinal
            if set(row) != set(G.COLUMNS):
                raise ValueError('Selected fields changed')
            canonical = json.dumps(row, sort_keys=True, ensure_ascii=False,
                                   separators=(',', ':')).encode()
            if hashlib.sha256(canonical).hexdigest() != item['parsed_record_sha256']:
                raise ValueError('Selected record hash changed')
            key = (row['OrgId'], row['IncidentId'])
            if not G.selected_key(*key, reserved):
                raise ValueError('Selection or reserved-organization breach')
            group = groups.setdefault(key, {'rows':0, 'grades':Counter(),
                    'actions':Counter(), 'granular_actions':Counter(),
                    'action_pair_missing_rows':0})
            group['rows'] += 1
            group['grades'][row['IncidentGrade']] += 1
            group['actions'][row['ActionGrouped']] += 1
            group['granular_actions'][row['ActionGranular']] += 1
            group['action_pair_missing_rows'] += bool(row['ActionGrouped']) != bool(row['ActionGranular'])
            count += 1
    if digest.hexdigest() != manifest['selected_sha256'] or count != manifest['selected_records']:
        raise ValueError('Selected file digest/count mismatch')
    expected = {(g['org_id'],g['incident_id']):g for g in manifest['groups']}
    if groups.keys() != expected.keys():
        raise ValueError('Selected group keys mismatch')
    for key, group in groups.items():
        if any(group[field] != expected[key][field] for field in
               ('rows','grades','actions','granular_actions')):
            raise ValueError('Selected group summary mismatch')
    return manifest, groups


def task_indexes(groups, overlap):
    """Missing triage is not benign and does not erase an available action label."""
    triage, action, triage_reject, action_reject = [], [], Counter(), Counter()
    for key, group in sorted(groups.items()):
        known = set(group['grades'])-{''}
        common = ['original_test_overlap'] if key in overlap else []
        tr = list(common)
        if '' in group['grades']:tr.append('missing_triage')
        if len(known)>1:tr.append('conflicting_triage')
        if known-set(['TruePositive','FalsePositive','BenignPositive']):tr.append('unknown_triage')
        ar = list(common)
        observed_actions = set(group['actions'])-{''}
        if not observed_actions:ar.append('missing_action')
        if observed_actions-set(['ContainAccount','IsolateDevice','Stop Virtual Machines']):
            ar.append('unknown_action')
        if group['action_pair_missing_rows']:ar.append('incomplete_action_label_pair')
        row = {'org_id':key[0],'incident_id':key[1],**group}
        if tr:triage_reject.update(tr)
        else:triage.append(row)
        if ar:action_reject.update(ar)
        else:action.append(row)
    triage_keys={(g['org_id'],g['incident_id'])for g in triage}
    action_keys={(g['org_id'],g['incident_id'])for g in action}
    return {'scope':'Task-specific source review indexes, not approved model inputs or targets.',
            'triage_cases':triage,'action_cases':action,'training_examples_generated':0}, {
        'triage_eligible_incidents':len(triage),
        'triage_eligible_records':sum(g['rows']for g in triage),
        'triage_grade_counts':dict(Counter(next(iter(g['grades']))for g in triage)),
        'action_eligible_incidents':len(action),
        'action_eligible_records':sum(g['rows']for g in action),
        'action_cases_without_triage':sum(''in g['grades']for g in action),
        'eligible_for_both_tasks':len(triage_keys&action_keys),
        'unique_source_eligible_incidents':len(triage_keys|action_keys),
        'triage_exclusion_reasons':dict(triage_reject),
        'action_exclusion_reasons':dict(action_reject),
        'action_target_semantics':'Customer-reported action labels only; no execution success or permission inferred.'}


def scan_test(stream, selected, progress=None):
    reader = csv.reader(stream, strict=True)
    if next(reader, None) != G.COLUMNS + ['Usage']:
        raise ValueError('Unexpected GUIDE test schema')
    overlaps, orgs, usage, count = Counter(), set(), Counter(), 0
    for row in reader:
        count += 1
        if len(row) != len(G.COLUMNS)+1 or not row[1].isdecimal() or not row[2].isdecimal():
            raise ValueError('Malformed original test row')
        key = (row[1],row[2])
        orgs.add(row[1])
        usage[row[-1]] += 1
        if key in selected:
            overlaps[key] += 1
        if progress and count % 10000 == 0:
            progress({'test_records':count, 'overlap_incidents':len(overlaps)})
    return {'test_records':count, 'test_organizations':len(orgs),
            'usage_counts':dict(usage), 'overlap_incidents':len(overlaps),
            'overlap_rows':sum(overlaps.values()),
            'overlap_keys':[{'org_id':k[0],'incident_id':k[1],'test_rows':v}
                            for k,v in sorted(overlaps.items())],
            'selected_orgs_also_in_original_test':len({k[0]for k in selected}&orgs),
            'iterator_exhausted':True}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    os.umask(0o077)
    args.output.mkdir(exist_ok=False)
    state = {'started_at_kst':G.now(), 'status':'running',
             'source_url':TEST_URL, 'test_raw_saved':False, 'training_examples_generated':0}
    started = time.monotonic()
    def stop(signum, frame):
        raise TimeoutError('Audit deadline or interruption')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGALRM, stop)
    signal.alarm(600)
    try:
        manifest, groups = audit_selected(args.root)
        state.update(selected_source_sha256=manifest['selected_sha256'],
                     selected_records=manifest['selected_records'], selected_incidents=len(groups))
        G.atomic_json(args.output/'progress.json', state)
        with G.request(TEST_URL) as response:
            if response.status != 200 or int(response.headers.get('Content-Length','0')) != TEST_BYTES:
                raise ValueError('Expected pinned original test length')
            state['transport_headers'] = {k:response.headers.get(k)for k in
                                          ('ETag','Last-Modified','Content-Length','x-goog-hash')}
            raw = G.VerifiedReader(response, TEST_BYTES, TEST_PREFIX, deadline=started+600)
            def progress(counts):
                G.atomic_json(args.output/'progress.json',{**state,**counts,
                    'test_bytes_read':raw.bytes_read,'checked_at_kst':G.now()})
            result = scan_test(io.TextIOWrapper(io.BufferedReader(raw,1024*1024),
                              encoding='utf-8',newline=''),groups,progress)
            if not raw.complete:
                raise ValueError('Test EOF unverified')
            state.update(result,test_eof_verified=True,test_bytes_read=raw.bytes_read,
                         test_sha256=raw.digest.hexdigest(),test_md5=raw.md5.hexdigest())
        overlap = {(r['org_id'],r['incident_id'])for r in result['overlap_keys']}
        index, task_summary = task_indexes(groups, overlap)
        G.atomic_json(args.output/'review-index.json',index)
        state.update(status='audited_by_task_for_review',**task_summary,
                     review_index_sha256=G.sha((args.output/'review-index.json').read_bytes()),
                     pending=['Decision-time feature audit','Evidence sufficiency / task design',
                              'Organization split','Token budget without silent evidence truncation',
                              'Independent SOC/tool-use evaluation'])
    except BaseException as exc:
        state.update(status='failed',error=type(exc).__name__+': '+str(exc))
        raise
    finally:
        signal.alarm(0)
        state.update(finished_at_kst=G.now(),elapsed_seconds=round(time.monotonic()-started,3))
        G.atomic_json(args.output/'manifest.json',state)
        G.atomic_json(args.output/'progress.json',{k:v for k,v in state.items()if k!='overlap_keys'})


if __name__ == '__main__':
    main()
