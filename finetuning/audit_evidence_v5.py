"""Verify prepared labels against original provider objects and PDF table IDs."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

from cisa_tables import extract
from evidence_groups import report_key
from prepare_evidence_v5 import ROOT, SPLITS, observation_text, safe_bytes, sha, technique
from prepare_data import canonical


def pdf_ids(pdf, spec):
    raw = subprocess.check_output(['pdftotext', '-f', str(spec['first_page']), '-l', str(spec['last_page']),
                                   '-bbox-layout', str(pdf), '-'])
    pages = [p for p in ET.fromstring(raw).iter() if p.tag.rsplit('}', 1)[-1] == 'page']
    ids = Counter()
    for page_number, page in enumerate(pages, spec['first_page']):
        for word in page.iter():
            if word.tag.rsplit('}', 1)[-1] == 'word' and re.fullmatch(r'T\d{4}(?:\.\d{3})?', word.text or ''):
                ids[(page_number, word.text)] += 1
    return ids


def verify_record(case, row, source_labels):
    if row['id'] != case['id'] or row.get('tools') or any(m.get('tool_calls') for m in row['messages']):
        raise ValueError('Record identity or tool-free scope changed')
    answer = json.loads(row['messages'][-1]['content'])
    expected = {m['id']: m['name'] for m in source_labels}
    actual = {m['id']: m['name'] for m in answer['mappings']}
    if (len(actual) != len(answer['mappings']) or actual != expected or
        answer['mappings'] != case['mappings']):
        raise ValueError('Gold mapping differs from original provider labels')
    if answer.get('evidence_ref') != case['evidence_ref'] or answer.get('scope') != 'reported_mapping_only' or answer.get('local_status') != 'not_assessed':
        raise ValueError('Evidence attribution or uncertainty scope changed')
    question = row['messages'][-2]['content']
    provided = json.loads(question.split('\n', 1)[1])
    if provided != {k: case[k] for k in ('provider', 'entity', 'version', 'evidence_ref', 'observation')}:
        raise ValueError('Prompt does not match source observation')


def audit(source, dataset, cases_path, spec):
    manifest = json.loads((dataset / 'manifest.json').read_text())
    cases_raw = cases_path.read_bytes()
    if sha(cases_raw) != manifest['source_cases_sha256']:
        raise ValueError('Source cases hash differs')
    cases = [json.loads(line) for line in cases_raw.splitlines()]
    lookup = {c['id']: c for c in cases}
    if len(lookup) != len(cases):
        raise ValueError('Duplicate source observation identity')
    ledger = json.loads((ROOT / 'SOURCE_EXPANSION.json').read_text())['acquisition']
    original = ledger['mitre']
    artifact = next(f for f in original['files'] if f.get('path') == 'mitre/enterprise-attack.json')
    data = json.loads(safe_bytes(source, artifact['path'], artifact['sha256']))
    objects = {o['id']: o for o in data['objects']}
    historical = {}
    for version, item in spec['historical_taxonomies'].items():
        historical[version] = {technique(o)['id']: o for o in json.loads(safe_bytes(source, item['path'], item['sha256']))['objects']
                               if o['type'] == 'attack-pattern' and not o.get('revoked') and not o.get('x_mitre_deprecated')}
    cisa = {}; coverage = {}
    for identifier, entry in spec['cisa'].items():
        item = next(f for f in ledger['cisa_incidents']['files'] if f['advisory_id'] == identifier)
        safe_bytes(source, item['path'], item['sha256'])
        pdf = source / item['path']
        rows, extracted = extract(subprocess.check_output(['pdftotext', '-layout', '-enc', 'UTF-8', pdf, '-']).decode(), entry)
        independent = pdf_ids(pdf, entry)
        layout = Counter((r['page'], r['technique_id']) for r in rows)
        if independent != layout or extracted['rejected'] or sum(independent.values()) != entry['expected_rows']:
            raise ValueError('Independent PDF word and layout ID coverage differs: ' + identifier)
        coverage[identifier] = {'layout_rows': len(rows), 'independent_PDF_ID_words': sum(independent.values()), 'matched': True}
        for r in rows:
            cisa[(identifier, r['page'], r['table'], r['technique_id'], r['raw_row_sha256'])] = r
    source_seen, group_seen, report_seen, observation_seen, row_seen = {}, {}, {}, {}, set()
    counts = Counter(); labels = Counter()
    for split in SPLITS:
        raw = (dataset / (split + '.jsonl')).read_bytes()
        if sha(raw) != manifest['outputs'][split]['sha256']:
            raise ValueError('Prepared split checksum differs')
        rows = [json.loads(line) for line in raw.splitlines()]
        if len(rows) != manifest['outputs'][split]['records']:
            raise ValueError('Prepared split count differs')
        for row in rows:
            case = lookup[row['id']]
            if row['id'] in row_seen or case['split'] != split:
                raise ValueError('Duplicate or wrong-split observation')
            row_seen.add(row['id']); provider_labels = []
            for pointer in case['source_rows']:
                if 'relationship_id' in pointer:
                    rel = objects[pointer['relationship_id']]
                    if sha(canonical(rel).encode()) != pointer['relationship_sha256'] or pointer['source_file_sha256'] != artifact['sha256'] or pointer['source_commit'] != original['commit']:
                        raise ValueError('Original relationship identity differs')
                    if observation_text(rel['description']) != case['observation'] or objects[rel['source_ref']]['name'] != case['entity']:
                        raise ValueError('Original observation/entity differs')
                    provider_labels.append(technique(objects[rel['target_ref']]))
                    source_id = 'mitre:' + rel['id']
                    reports = [report_key(r['url']) for r in rel['external_references'] if r.get('url')]
                else:
                    identifier = pointer['advisory_id']; entry = spec['cisa'][identifier]
                    key = (identifier, pointer['page'], pointer['table'], pointer['technique_id'], pointer['raw_row_sha256'])
                    original_row = cisa[key]
                    source_artifact = next(f for f in ledger['cisa_incidents']['files'] if f['advisory_id'] == identifier)
                    if (pointer['pdf_sha256'] != source_artifact['sha256'] or pointer['url'] != source_artifact['url'] or
                        pointer['reported_title'] != original_row['title'] or case['entity'] != entry['entity'] or
                        case['provider'] != 'CISA ' + identifier or case['version'] != 'ATT&CK ' + entry['taxonomy_version']):
                        raise ValueError('CISA provenance differs from original report')
                    if observation_text(original_row['description']) != case['observation']:
                        raise ValueError('CISA observation differs from original table')
                    if any(x['page'] == pointer['page'] and x['id'] == pointer['technique_id'] for x in entry.get('quarantine', [])):
                        raise ValueError('Quarantined source row admitted')
                    provider_labels.append(technique(historical[entry['taxonomy_version']][pointer['technique_id']]))
                    source_id = canonical(key); reports = ['cisa:' + identifier]
                if source_id in source_seen:
                    raise ValueError('One original provider row reused in multiple observations')
                source_seen[source_id] = split
                for key in reports:
                    if key in report_seen and report_seen[key] != split:
                        raise ValueError('Cited report leaked across splits')
                    report_seen[key] = split
            verify_record(case, row, provider_labels)
            for registry, key in ((group_seen, case['group']), (observation_seen, case['observation'].casefold())):
                if key in registry and registry[key] != split:
                    raise ValueError('Related or identical observation leaked across splits')
                registry[key] = split
            counts[split] += 1; labels[split] += len(case['mappings'])
    if row_seen != set(lookup):
        raise ValueError('Source cases omitted from prepared splits')
    return {'status': 'passed', 'records': dict(counts), 'provider_label_assignments': dict(labels),
            'original_source_rows_verified': len(source_seen), 'independent_PDF_ID_coverage': coverage,
            'cross_split_shared_reports_or_groups_or_identical_observations': 0,
            'scope': 'mechanical provider-label/attribution consistency, not independent expert validation of incident truth'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('source-root', 'dataset', 'cases', 'spec', 'report'):
        p.add_argument('--' + option, type=Path, required=True)
    a = p.parse_args(); result = audit(a.source_root, a.dataset, a.cases, json.loads(a.spec.read_text()))
    a.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n'); print(json.dumps(result))


if __name__ == '__main__': main()
