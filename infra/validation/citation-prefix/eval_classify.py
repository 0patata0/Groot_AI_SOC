"""Classify the 2026-11-13 A/B generations with the production runner's own validators.

Local only. Inputs (eval-payloads.json, results.jsonl) are Git-excluded evidence.
Generation on Thor: /v1/chat/completions, same model, verify tools (36), max_tokens
4096, reasoning_effort medium, seeds 11/22/33, A/B order alternated per seed.
"""
import json, sys, os, re, collections
os.environ['CAPSTONE_MANAGEMENT_MODE'] = 'verify'
REPO = os.environ.get('CAPSTONE_REPO', os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
sys.path.insert(0, os.path.join(REPO, 'infra/hermes'))
import soc_management_run as R
ev = os.path.join(REPO, '대화기록/검증/2026-11-13-citation-eval/')  # local-only evidence (Git-excluded)
P = json.load(open(ev + 'eval-payloads.json'))
valid_names = {t['function']['name'] for t in P['tools']}
MARK = ('</parameter>', '<tool_call>', '<function=', '</function>', '<parameter=', '</tool_call>')
def classify(row):
    if row.get('error'): return {'kind': 'error'}
    reads = P['points'][row['point']]['successful_reads']
    c = row.get('content') or ''
    malformed = any(m in c for m in MARK) or (c.lstrip().startswith('{') and '"calls"' in c[:80])
    if row.get('tool_calls'):
        names = [t['name'] for t in row['tool_calls']]
        return {'kind': 'tool_call', 'malformed': malformed, 'invalid_tool': any(n not in valid_names for n in names), 'tools': names}
    status = R.management_status(c)
    disp, disp_err = R.parse_incident_disposition(c, reads)
    cites = R.disposition_citation_violations(c, reads)
    return {'kind': 'text', 'malformed': malformed, 'status': status, 'disposition_error': disp_err, 'citation_issues': cites,
            'truncated': row.get('finish') == 'length', 'chars': len(c)}
rows = [json.loads(l) for l in open(ev + 'results.jsonl')]
summary = collections.defaultdict(collections.Counter)
detail = []
for row in rows:
    r = classify(row); v = row['variant']; s = summary[v]
    s['samples'] += 1; s[r['kind']] += 1
    if r.get('malformed'): s['malformed'] += 1
    if r['kind'] == 'tool_call' and r.get('invalid_tool'): s['invalid_tool'] += 1
    if r['kind'] == 'text':
        if r['status'] is None: s['missing_or_invalid_status'] += 1
        if r['disposition_error']: s['disposition_' + r['disposition_error']] += 1
        if r['citation_issues']: s['citation_issue'] += 1
        if r['truncated']: s['truncated'] += 1
        if r['status'] and not r['disposition_error'] and not r['citation_issues'] and not r['malformed']: s['clean_final'] += 1
    s['seconds'] += row.get('seconds') or 0
    detail.append({'point': row['point'], 'variant': v, 'seed': row['seed'], 'seconds': row.get('seconds'), **{k: r[k] for k in r if k != 'tools'}, 'tools': r.get('tools')})
print(json.dumps({'rows': len(rows), 'summary': {k: dict(v) for k, v in sorted(summary.items())}}, ensure_ascii=False, indent=1))
for d in sorted(detail, key=lambda x: (x['point'], x['seed'], x['variant'])):
    print(d['point'], d['seed'], d['variant'], d['kind'], 'MAL' if d.get('malformed') else '', d.get('status'), d.get('disposition_error') or '', ','.join(d.get('citation_issues') or []), d.get('tools') or '', d.get('seconds'))
