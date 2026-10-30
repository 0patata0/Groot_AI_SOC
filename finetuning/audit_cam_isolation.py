"""Audit CAM source/log reuse without executing upstream code or a model.

Matches are review/blocking signals, not proof that an entire incident leaked.
Absence of exact text is not semantic independence or absence from pretraining.
The entire CAM corpus stays reserved, including all variants and attack steps.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re

from audit_cam_inputs import parse, require
from audit_soc_observation_history import safe_path
from score_cam_benchmark import load_bundle

SOURCE_MARKERS = ('attack-manifestations-interpretation', 'cam-lds',
                  'zenodo.18390560', 'zenodo.18390561', 'zenodo.18861762',
                  'zenodo.org/records/18390560', 'zenodo.org/records/18390561',
                  'zenodo.org/records/18861762', 'zenodo.org/api/records/18390560',
                  'zenodo.org/api/records/18390561', 'zenodo.org/api/records/18861762')
# Standard Python exception heading has no incident identity. Preserve and
# count it, but do not turn a shared heading into a CAM-source reuse claim.
COMMON_HEADERS = {'Traceback (most recent call last):'}


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode()).hexdigest()


def normalized(value):
    return ' '.join(value.split())


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def events(prompt):
    """Reverse only the pinned provider's indentation; retain ASCII GS in audit.

    splitlines() would split U+001D embedded in Linux audit records. Eight-space
    event prefixes must be checked before four-space source headers (an event
    itself may end in a colon). Unrecognized post-header content fails closed.
    """
    host = source = None
    result = []
    for number, line in enumerate(prompt.split('\n'), 1):
        if line.startswith('        '):
            require(host is not None and source is not None, 'Event without source header')
            result.append({'host': host, 'source': source, 'prompt_line': number, 'text': line[8:]})
        elif re.fullmatch(r'[A-Za-z0-9_.-]+:', line):
            host, source = line[:-1], None
        elif host is not None and line.startswith('    ') and line.endswith(':'):
            source = line[4:-1]
            require(source.startswith('logs/') and '\r' not in source, 'Unexpected source header')
        elif host is not None:
            require(not line.strip(), 'Unparsed content after source header')
    require(bool(result), 'No CAM events extracted')
    return result


def text_units(value, depth=0):
    """Visit all payload roles, nested objects and JSON strings, never execute."""
    require(depth <= 64, 'Payload nesting exceeds reviewed limit')
    if isinstance(value, dict):
        yield canonical(value)
        for item in value.values():
            yield from text_units(item, depth+1)
    elif isinstance(value, list):
        for item in value:
            yield from text_units(item, depth+1)
    elif isinstance(value, str):
        yield value
        lines = value.split('\n')
        if len(lines) > 1:
            yield from lines
        # JSON-encoded tool results may contain the original raw log in a
        # nested field; comparing only the first user prompt misses those.
        for text in dict.fromkeys([value, *lines]):
            if text.lstrip().startswith(('{', '[')):
                try:
                    obj = parse(text)
                except (ValueError, TypeError):
                    continue
                if isinstance(obj, (dict, list)):
                    yield from text_units(obj, depth+1)


def fingerprints(text):
    value = text.strip(' \t\r')
    keys = [('line', sha(value)), ('whitespace', sha(normalized(value)))]
    if value.startswith(('{', '[')):
        try:
            obj = parse(value)
            if isinstance(obj, (dict, list)):
                keys.append(('json', sha(canonical(obj))))
        except (ValueError, TypeError):
            pass
    return keys


def build_index(bundle):
    manifest, data = load_bundle(bundle)
    index = defaultdict(set)
    common = {}
    occurrences = defaultdict(list)
    prompt_hashes = {}
    counters = Counter()
    sources = Counter()
    for row, trace in zip(data['inputs.jsonl'], data['lineage.jsonl']):
        require(trace['eligible_for_training'] is False and
                trace['partition'] == 'reserved_external_benchmark_candidate', 'Reserved partition changed')
        require(len(row['messages']) == 1 and row['messages'][0]['role'] == 'user', 'CAM message shape changed')
        prompt = row['messages'][0]['content']
        require(sha(prompt) == trace['prompt_sha256'], 'Prompt lineage hash differs')
        prompt_hashes.setdefault(sha(normalized(prompt)), set()).add(row['id'])
        for event in events(prompt):
            counters['event_occurrences'] += 1
            sources[(event['host'], event['source'])] += 1
            raw_digest = sha(event['text'])
            occurrences[raw_digest].append({'input_id': row['id'], 'scenario': trace['scenario_group'],
                'step': trace['scenario_step'], 'host': event['host'], 'source': event['source'],
                'prompt_line': event['prompt_line']})
            if not event['text'].strip():
                counters['blank_event_occurrences'] += 1
            elif event['text'].strip() in COMMON_HEADERS:
                counters['common_header_occurrences'] += 1
                common[sha(event['text'].strip())] = raw_digest
            else:
                for key in fingerprints(event['text']):
                    index[key].add(raw_digest)
    shared = [{'event_sha256': digest, 'occurrences': refs} for digest, refs in sorted(occurrences.items())
              if len({r['step'] for r in refs}) > 1]
    summary = {'inputs': len(data['inputs.jsonl']), 'scenario_groups': manifest['counts']['scenario_groups'],
        'event_occurrences': counters['event_occurrences'], 'unique_exact_events': len(occurrences),
        'cross_step_exact_events': len(shared),
        'cross_scenario_exact_events': sum(len({x['scenario'] for x in v}) > 1 for v in occurrences.values()),
        'blank_event_occurrences_not_identity': counters['blank_event_occurrences'],
        'common_header_occurrences_not_identity': counters['common_header_occurrences'],
        'non_identity_rule': 'Only empty/whitespace lines and the exact standard Python traceback heading are nonblocking; retained in raw counts.',
        'source_paths': [{'host': h, 'source': s, 'occurrences': n} for (h,s),n in sorted(sources.items())],
        'shared_event_coordinates': shared,
        'scope': 'Selected source events in393 provided prompts, not the whole raw-log archive.'}
    return {'events': index, 'common': common, 'prompts': prompt_hashes, 'summary': summary,
            'manifest_sha256': sha((bundle/'manifest.json').read_bytes())}


def scan_row(row, index):
    matches = defaultdict(set)
    source_markers = set()
    for text in text_units(row):
        source_markers.update(m for m in SOURCE_MARKERS if m in text.lower())
        prompt_ids = index['prompts'].get(sha(normalized(text)))
        if prompt_ids:
            matches['whole_prompt'].update(prompt_ids)
        common = index.get('common', {}).get(sha(text.strip()))
        if common:
            matches['common_header_not_event_identity'].add(common)
        for kind, digest in fingerprints(text):
            matches[kind].update(index['events'].get((kind,digest), ()))
    return {k: sorted(v) for k,v in matches.items() if v}, sorted(source_markers)


def scan_file(path, index, expected_sha=None):
    require(path.is_file() and not path.is_symlink(), 'Missing/unsafe comparison input')
    digest = hashlib.sha256(); rows = 0; matches = []
    with path.open('rb') as handle:
        for rows, raw in enumerate(handle, 1):
            digest.update(raw)
            row = parse(raw)
            require(isinstance(row, dict), 'Non-object comparison row')
            found, markers = scan_row(row, index)
            if found or markers:
                matches.append({'row': rows, 'fingerprint_matches': found, 'source_markers': markers})
    actual = digest.hexdigest()
    require(rows > 0 and (expected_sha is None or actual == expected_sha), 'Comparison file empty/hash differs')
    blocking = sum(bool(x['source_markers']) or
                   any(k != 'common_header_not_event_identity' for k in x['fingerprint_matches'])
                   for x in matches)
    return {'rows': rows, 'bytes': path.stat().st_size, 'sha256': actual, 'matches': matches,
            'blocking_row_visits': blocking}


def guard_candidates(bundle, candidates):
    """Called by the pilot builder before output creation; any hit needs review."""
    index = build_index(bundle)
    checked = {p.name: scan_file(p, index) for p in candidates}
    require(len(checked) == len(candidates), 'Candidate filename collision')
    require(not any(x['blocking_row_visits'] for x in checked.values()), 'Reserved CAM evidence/source found in candidates')
    return {'reserved_manifest_sha256': index['manifest_sha256'], 'checked_files': checked,
            'method': 'All payload roles; whole prompt, log line, whitespace, canonical JSON and source identifiers',
            'entire_CAM_corpus_reserved': True, 'semantic_independence_proven': False}


def audit(root, bundle, inventory):
    root, bundle, inventory = root.resolve(), bundle.resolve(), inventory.resolve()
    require(inventory.is_relative_to(root), 'Inventory outside project data root')
    index = build_index(bundle)
    previous = json.loads((root/'SOC_OBSERVATION_GATE_REVIEW.json').read_text())
    historical = previous['historical_audit']['prompt_audit']['scanned']
    actual_paths = {str(p.relative_to(root)) for n in ('train.jsonl','validation.jsonl','test.jsonl')
                    for p in root.glob('data*/**/'+n)}
    require(actual_paths == {s['file'] for s in historical}, 'Historical file inventory changed; review before audit')
    manifest = json.loads((inventory/'manifest.json').read_text())
    specs = [(x['file'], 'historical_split', x['sha256']) for x in historical]
    for version in ('V4','V5'):
        spec = json.loads((root/(version+'_TRAINING_INPUTS.json')).read_text())
        specs.append((spec['source_cases'], 'frozen_source_cases', spec['source_cases_sha256']))
    specs += [(str((inventory/n).relative_to(root)), 'candidate_not_trained', v['sha256'])
              for n,v in manifest['pool_files'].items()]
    scans = [{'file': n, 'role': role, **scan_file(safe_path(root,n),index,digest)} for n,role,digest in specs]
    hits = sum(len(s['matches']) for s in scans)
    blocking = sum(s['blocking_row_visits'] for s in scans)
    return {'schema': 1, 'checked_at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
        'status': 'overlap_review_required' if blocking else 'scoped_exact_checks_passed_not_final_evaluation',
        'reserved_manifest_sha256': index['manifest_sha256'], 'CAM_events': index['summary'],
        'scans': scans, 'matching_row_visits': hits, 'blocking_row_visits': blocking,
        'row_visits': sum(s['rows'] for s in scans),
        'scope': 'All39 local historical split files, frozen V4/V5 source cases, full1197 candidate rows; versions repeat.',
        'policy': {'unit_reserved_from_training': 'entire CAM corpus across every scenario/variant/step',
            'reason': 'Upstream normal-behavior filtering uses all34 simulation runs; scenario splits do not isolate preprocessing.',
            'final_operational_evaluation_created': 0, 'independent_test_proven': False,
            'source_matches': 'Review/blocking signals; common lines alone do not prove incident reuse.',
            'no_match': 'Does not prove absence of paraphrase, semantically related events, upstream raw archives or model pretraining.'},
        'training_admitted': 0, 'model_called': False, 'auditor_sha256': sha(Path(__file__).read_bytes())}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a=p.parse_args();require(not a.output.exists(), 'Output already exists')
    result=audit(a.root,a.bundle,a.inventory)
    with a.output.open('x') as h:h.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('status','row_visits','matching_row_visits','blocking_row_visits')}))
    raise SystemExit(2 if result['blocking_row_visits'] else 0)


if __name__ == '__main__': main()
