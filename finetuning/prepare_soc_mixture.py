"""Build separate, NOT admitted candidate pools; never change a frozen split.

Institutional evidence is not the same as an institution-authored SOC answer.
This inventory is not a recommended sampling ratio or an executable train profile.
"""
import argparse
import ast
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import re

from audit_soc_observation_history import read_frozen, compare_groups
from check_soc_observation_tokens import load_candidates
from prepare_data import canonical, normalize_record
from prepare_soc_observation_inputs import require, verified

KST = timezone(timedelta(hours=9))
ISO = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+09:00')
IDENTITY = re.compile(r'SOC-OP-[0-9a-f]{10}|(?<![A-Za-z0-9])(?:[0-9a-f]{64}|[0-9a-f]{32}|[0-9a-f]{12})(?![A-Za-z0-9])|203\.0\.113\.\d+')
EPOCH_FIELDS = {'expires_at', 'owned_deadline', 'temporary_expires_at'}
FW = 'mcp__resp__get_firewall_rules'
FW_SCHEMA = '7fa8b4032b741e4f7304e0e29a295729f784a7fb8bb8ad096a0a7cfce0ffd4b9'
FW_CONTEXT = {FW, 'mcp__resp__list_blocks', 'mcp__rule_a__get_rule_change_target',
              'mcp__rule_b__get_rule_change_target', 'mcp__system_diagnostics__get_system_diagnostics',
              'mcp__wazuh_ro__get_wazuh_rules_summary'}


def sha(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value).encode()).hexdigest()


def synthetic_fingerprint(case):
    """Compare controlled fixtures only. Never rewrite the selected training row.

    Ignore consistently renamed opaque identities and shifted absolute times,
    retaining all time differences (including epoch deadlines), ID relationships,
    literal text, evidence, status, approval, TTL, severity and error fields.
    Generated rule IDs are normalized only for their original template index.
    """
    require(case['split'] == 'train'
            and case['review']['evidence_kind'] == 'synthetic_lab_fixture',
            'Only synthetic training fixtures may be grouped')
    values = {k: case.get(k) for k in ('messages', 'checks', 'tool_names',
              'template_family', 'capabilities', 'operator_stages')}
    values['protected_policy_reviewed'] = case['review'].get('protected_policy_reviewed', False)
    times = ISO.findall(canonical(values))
    base = min(map(datetime.fromisoformat, times)) if times else None
    generated = {}
    if case['template_family'].startswith('operator-'):
        match = re.fullmatch(r'soc-v4-core-soc-operator-v3-[a-z_]+-train-(\d{3})', case['id'])
        require(match is not None, 'Unknown synthetic generator identity')
        index = int(match[1])
        require(0 <= index < 24, 'Unknown synthetic template index')
        generated = {str(2100000 + index): '<GENERATED_ALERT_ID>',
                     str(1700000 + index): '<GENERATED_RULE_ID>'}
    ids = {}

    def identity(match):
        value = match[0]
        if value not in ids:
            ids[value] = '<IDENTITY_' + str(len(ids)) + '>'
        return ids[value]

    def visit(value, key=None):
        if isinstance(value, dict):
            return {k: visit(value[k], k) for k in sorted(value)}
        if isinstance(value, list):
            return [visit(v) for v in value]
        if type(value) is int:
            if key in EPOCH_FIELDS:
                require(base is not None and 1_000_000_000 <= value < 2_000_000_000,
                        'Unknown epoch representation')
                return '<EPOCH_REL_' + str(value - int(base.timestamp())) + '>'
            return generated.get(str(value), value)
        if not isinstance(value, str):
            return value
        # Tool arguments/results contain serialized JSON. Parse for field-specific
        # epoch handling, but keep the original-string versus object distinction.
        if value.lstrip().startswith(('{', '[')):
            try:
                decoded = json.loads(value)
            except (ValueError, TypeError):
                pass
            else:
                return {'<SERIALIZED_JSON>': visit(decoded)}
        if base:
            value = ISO.sub(lambda m: '<KST_REL_' + str(
                (datetime.fromisoformat(m[0]) - base).total_seconds()) + '>', value)
        value = IDENTITY.sub(identity, value)
        for number, alias in generated.items():
            value = re.sub(r'(?<!\d)' + number + r'(?!\d)', alias, value)
        return value

    return sha(visit(values))


def select_synthetic(cases):
    groups = defaultdict(list)
    for case in sorted(cases, key=lambda c: c['id']):
        groups[synthetic_fingerprint(case)].append(case)
    selected, ledger = [], []
    for fingerprint, group in sorted(groups.items(), key=lambda item: item[1][0]['id']):
        selected.append(group[0])
        ledger.append({'fingerprint': fingerprint, 'selected': group[0]['id'],
                       'members': [c['id'] for c in group],
                       'workflow': group[0]['review']['workflow'],
                       'template_family': group[0]['template_family']})
    require(Counter(c['template_family'] for c in selected).keys() ==
            Counter(c['template_family'] for c in cases).keys(), 'Template family lost')
    return selected, ledger


def fw_entry(source):
    """Read one literal TOOLS entry without importing/executing server code."""
    tree = ast.parse(source)
    entries = []
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'TOOLS' for t in stmt.targets):
            require(isinstance(stmt.value, ast.List), 'Unknown TOOLS layout')
            for node in stmt.value.elts:
                if not isinstance(node, ast.Dict):
                    continue
                names = [(k, v) for k, v in zip(node.keys, node.values)
                         if isinstance(k, ast.Constant) and k.value == 'name']
                if any(isinstance(v, ast.Constant) and v.value == 'get_firewall_rules' for _, v in names):
                    entries.append(ast.literal_eval(node))
    require(len(entries) == 1, 'Missing/ambiguous FW source tool')
    tool = entries[0]
    require(sha(tool['inputSchema']) == FW_SCHEMA, 'FW schema changed; review again')
    require(tool['annotations']['readOnlyHint'] is True and
            tool['annotations']['destructiveHint'] is False, 'FW read contract changed')
    return {'server': 'resp', 'name': FW, 'protected': False,
            'description': tool['description'], 'parameters': tool['inputSchema']}


def fw_candidate(catalog, entry, proof):
    require(FW not in {t['name'] for t in catalog['tools']}, 'FW already present; reassess delta')
    observed = proof['stages']['ollama']['result']
    catalog_matches = [t for t in observed['catalog'] if t['name'] == 'get_firewall_rules']
    require(len(catalog_matches) == 1 and catalog_matches[0]['schema_sha256'] == FW_SCHEMA,
            'Historical observed FW schema does not match source')
    calls = [c for c in observed['calls'] if c['name'] == 'get_firewall_rules']
    require(len(calls) == 1, 'Missing/ambiguous historical FW call')
    call = calls[0]
    require(call['arguments'] == {} and call['is_error'] is False and
            sha(call['result'].encode()) == call['result_sha256'], 'Unverified FW call/result')
    result = json.loads(call['result'])
    require(result['complete'] is True and result['next_offset'] is None and
            result['offset'] == 0 and len(result['objects']) == result['total_objects'],
            'Historical FW snapshot incomplete')
    # Preserve the full 38-entry catalog, but bound this training exercise's
    # context to six competing read tools. Full-catalog inference is a different
    # evaluation condition and must not be certified by this scoped example.
    combined = {**catalog, 'tools': [*catalog['tools'], entry],
                'scope': 'Candidate catalog: frozen historical base plus source/historical FW delta; not a current live roster',
                'fw_delta_observed_at_kst': observed['at_kst']}
    context = [t for t in combined['tools'] if t['name'] in FW_CONTEXT]
    require({t['name'] for t in context} == FW_CONTEXT and all(t.get('protected') is False for t in context),
            'Missing/non-read-only FW competitor context')
    tools = [{'type': 'function', 'function': {k: t[k] for k in ('name', 'description', 'parameters')}}
             for t in context]
    row = normalize_record({'id': 'SOC-FW-ROUTING-CANDIDATE-20261030', 'tools': tools,
        'messages': [
            {'role': 'system', 'content': '등록된 도구로 요청 범위만 조회한다. FW 룰은 호스트 nftables 전체 규칙이다. WAF·IDS 룰이나 임시 차단 목록으로 대신하지 않는다. 도구 결과 없이 현재 상태나 완료를 단정하지 않는다.'},
            {'role': 'user', 'content': 'fw 룰 보여줘'},
            {'role': 'assistant', 'content': '', 'tool_calls': [
                {'id': 'fw_read_1', 'type': 'function', 'function': {'name': FW, 'arguments': '{}'}}]}]},
        'soc-fw-routing-candidate', 1)
    row['id'] = 'SOC-FW-ROUTING-CANDIDATE-20261030'
    lineage = {'id': row['id'], 'authorship': 'project_authored_call_selection_prefix',
               'source': 'historical verified MCP call and current source schema',
               'historical_observed_at_kst': observed['at_kst'],
               'historical_result_sha256': call['result_sha256'],
               'historical_objects': result['total_objects'], 'schema_sha256': FW_SCHEMA,
               'tool_schema_count': len(tools), 'source_prompt_is_project_authored': True,
               'candidate_catalog_tools': len(combined['tools']),
               'tool_context_scope': 'Six read competitors only; not the full live or training catalog',
               'tool_result_copied': False, 'model_answer_used_as_gold': False,
               'scope': 'Call selection only; no result interpretation, pagination or completion target',
               'record_sha256': sha(row), 'training_admitted': False}
    return combined, row, lineage


def v5_group_audit(cases):
    groups = defaultdict(lambda: defaultdict(list))
    for case in cases:
        # Conservative entity grouping for MITRE and whole-report grouping for CISA.
        key = ('MITRE:' + case['entity']) if case['provider'] == 'MITRE ATT&CK' else case['provider']
        groups[key][case['split']].append(case['id'])
    return {'method': 'MITRE entity / CISA whole advisory', 'groups': len(groups),
            'cross_split_groups': {k: {s: len(ids) for s, ids in v.items()}
                                   for k, v in groups.items() if len(v) > 1},
            'limitation': 'Not a full audit of secondary incident reports, all earlier corpora or pretraining'}


def reviewed_v4(directory, public, originals):
    """Explicit replacement, never extra rows; retain IDs and withheld lineage."""
    raw_manifest = (directory / 'manifest.json').read_bytes()
    manifest = json.loads(raw_manifest)
    require(manifest['status'] == 'source_rechecked_refined_candidates_not_training_release'
            and manifest['training_admitted'] == 0, 'Unexpected V4 review release')
    raw = verified(directory/'candidate-dialogues.jsonl', manifest['dialogues_sha256'])
    trace_raw = verified(directory/'lineage.jsonl', manifest['lineage_sha256'])
    rows = [json.loads(x) for x in raw.splitlines()]
    traces = [json.loads(x) for x in trace_raw.splitlines()]
    expected = {c['id']: c for c in public}
    require(len(rows) == len(traces) == manifest['records'] == len(expected)
            and {r['id'] for r in rows} == set(expected), 'Refined V4 IDs/count differ')
    by_id, bindings = {}, {}
    for row, trace in zip(rows, traces):
        old = json.loads(originals[row['id']])
        require(trace['id'] == row['id'] and trace['record_sha256'] == sha(row)
                and trace['original_record_sha256'] == sha(old)
                and trace['source_case_sha256'] == sha(expected[row['id']])
                and trace['partition'] == 'historical_training_candidate_only'
                and trace['training_admitted'] is False, 'Refined V4 lineage differs')
        require(row['id'] == old['id'] and row['source'] == old['source'] and row['tools'] == old['tools'] == []
                and len(row['messages']) == 3 and [m['role'] for m in row['messages']] == ['system','user','assistant']
                and row['messages'][0] == old['messages'][0], 'Refined V4 scope/roles changed')
        by_id[row['id']] = (canonical(row)+'\n').encode()
        bindings[row['id']] = trace
    support = {name: verified(directory/name, digest) for name,digest in manifest['support_files'].items()
               if name in ('KEV_SOURCE_RECORDS.jsonl', 'AIT_NOTICE.txt', 'SOURCE_NOTICE.txt')}
    require(set(support) == {'KEV_SOURCE_RECORDS.jsonl', 'AIT_NOTICE.txt', 'SOURCE_NOTICE.txt'}, 'Missing revised source notice')
    return by_id, bindings, support, {'manifest_sha256': sha(raw_manifest),
        'dialogues_sha256': manifest['dialogues_sha256'], 'lineage_sha256': manifest['lineage_sha256'],
        'records': len(rows), 'findings': manifest['findings'], 'rows_added': 0,
        'replacement_only_not_admitted': True}


def build(root, observations, fw_proof, output, reviewed_v4_observations=None):
    require(not output.exists(), 'Output already exists')
    review = json.loads((root / 'V4_DATA_REVIEW.json').read_text())
    require(review['decision'] == 'withheld', 'Reassess changed V4 decision')
    cases, specs, integrity, raw_rows = {}, {}, {}, {}
    for version in ('V4', 'V5'):
        specs[version] = json.loads((root / (version + '_TRAINING_INPUTS.json')).read_text())
        cases[version], integrity[version] = read_frozen(root, specs[version])
        raw = verified(root / specs[version]['data_folder'] / 'train.jsonl',
                       specs[version]['data_sha256']['train'])
        raw_rows[version] = {json.loads(line)['id']: line + b'\n' for line in raw.splitlines()}
    old_catalog_raw = verified(root / 'mcp_contract.json', specs['V4']['catalog_sha256'])
    old_catalog = json.loads(old_catalog_raw)
    obs_manifest, obs_rows = load_candidates(observations)
    traces = [json.loads(x) for x in (observations / 'lineage.jsonl').read_text().splitlines()]
    group_audit = compare_groups(traces, cases['V4'], cases['V5'])
    require(not group_audit['known_held_out_group_conflicts'], 'Observation group crosses held-out split')
    v5_audit = v5_group_audit(cases['V5'])
    require(not v5_audit['cross_split_groups'], 'V5 entity/report crosses split')
    train = [c for c in cases['V4'] if c['split'] == 'train']
    synthetics = [c for c in train if c['review']['evidence_kind'] == 'synthetic_lab_fixture']
    selected, dedup = select_synthetic(synthetics)
    public = [c for c in train if c['review']['evidence_kind'] in ('public_testbed_log', 'public_institutional_record')]
    live = [c for c in train if c['review']['evidence_kind'] == 'captured_live_observation']
    require(len(public) + len(live) + len(synthetics) == len(train), 'Unclassified V4 train rows')
    source_path = root.parent / 'infra/mcp/response-mcp.py'
    entry = fw_entry(source_path.read_text())
    catalog, fw_row, fw_lineage = fw_candidate(old_catalog, entry, json.loads(fw_proof.read_text()))
    replacement, reviewed_bindings, reviewed_support, revision = {}, {}, {}, None
    if reviewed_v4_observations:
        replacement, reviewed_bindings, reviewed_support, revision = reviewed_v4(
            reviewed_v4_observations, public, raw_rows['V4'])
    pools = {
        'cti-replay-candidates.jsonl': b''.join(raw_rows['V5'].values()),
        'observation-candidates.jsonl': b''.join(replacement.get(c['id'], raw_rows['V4'][c['id']]) for c in public)
            + (observations / 'candidate-dialogues.jsonl').read_bytes(),
        'optional-harness-candidates.jsonl': b''.join(raw_rows['V4'][c['id']] for c in [*selected, *live])
            + (canonical(fw_row) + '\n').encode(),
    }
    lineage = []
    for version, selected_cases, pool in (
        ('V5', [c for c in cases['V5'] if c['split'] == 'train'], 'cti-replay-candidates.jsonl'),
        ('V4', public, 'observation-candidates.jsonl'),
        ('V4', [*selected, *live], 'optional-harness-candidates.jsonl')):
        for c in selected_cases:
            lineage.append({'id': c['id'], 'pool': pool, 'frozen_version': version,
                'frozen_split': 'train', 'source_case_sha256': sha(c),
                'record_line_sha256': sha(raw_rows[version][c['id']]),
                'source_uri': c.get('source_uri'), 'provider': c.get('provider'),
                'evidence_kind': c.get('review', {}).get('evidence_kind', 'provider_cti_mapping'),
                'institution_certified_SOC_answer': False,
                'withheld_V4_status_preserved': version == 'V4', 'training_admitted': False})
            if c['id'] in replacement:
                lineage[-1].update(record_line_sha256=sha(replacement[c['id']]),
                    original_frozen_record_line_sha256=sha(raw_rows[version][c['id']]),
                    refined_source_binding=reviewed_bindings[c['id']])
    lineage.extend({'id': t['record_id'], 'pool': 'observation-candidates.jsonl',
                    'origin_lineage_sha256': sha(t), 'group': t['leakage_group'],
                    'institution_certified_SOC_answer': False, 'training_admitted': False} for t in traces)
    lineage.append({**fw_lineage, 'pool': 'optional-harness-candidates.jsonl'})
    all_ids = [r['id'] for r in lineage]
    require(len(all_ids) == len(set(all_ids)), 'Candidate identity collision')
    withheld_ids = {c['id'] for cs in cases.values() for c in cs if c['split'] != 'train'}
    require(not withheld_ids.intersection(all_ids), 'Held-out record included')
    manifest = {
        'schema': 1, 'at_kst': datetime.now(KST).isoformat(),
        'status': 'separate_candidate_inventory_not_training_release', 'training_admitted': 0,
        'recommended_sampling_ratio': None, 'new_training_profile_created': False,
        'frozen_inputs': integrity,
        'pool_files': {name: {'rows': len(data.splitlines()), 'sha256': sha(data)} for name, data in pools.items()},
        'source_counts': {'V5_previously_trained_replay': len(raw_rows['V5']),
                          'V4_institutional_evidence_but_project_authored_targets': len(public),
                          'new_reviewed_observations': len(obs_rows),
                          'V4_synthetic_before': len(synthetics), 'V4_synthetic_selected': len(selected),
                          'V4_historical_live': len(live), 'new_FW_call_selection': 1},
        'V4_observation_revision': revision,
        'synthetic_workflow_coverage': dict(Counter(c['review']['workflow'] for c in selected)),
        'synthetic_group_sizes': dict(Counter(len(g['members']) for g in dedup)),
        'observation_manifest_sha256': sha((observations / 'manifest.json').read_bytes()),
        'observation_dialogues_sha256': obs_manifest['dialogues_sha256'],
        'known_held_out_environment_conflicts': group_audit['known_held_out_group_conflicts'],
        'V5_report_entity_split_audit': v5_audit,
        'fw': {**fw_lineage, 'source_file_sha256': sha(source_path.read_bytes()),
               'local_proof_sha256': sha(fw_proof.read_bytes()), 'entry': entry},
        'not_claimed': ['New independent incidents from wording or identity variants',
            'All provider evidence is real-world attacks (AIT is a research testbed)',
            'Institutional endorsement of project-authored Korean SOC responses',
            'All 1167 evidence candidates are new data or a suitable training ratio',
            'Current live MCP roster verification, full-catalog FW accuracy or complete pagination supervision'],
        'release_gates_remaining': [
            'Review withheld V4 factual targets against original evidence; do not override withheld decision',
            'Select role/task-balanced sampling; CTI replay must not dominate merely by row count',
            'Freeze unused source/incident-separated operational evaluation; CAM remains separate benchmark candidate',
            'Measure exact complete-dialogue tokens/masks before a training profile; do not truncate',
            'Additional authoritative unique operator evidence; 143 candidates is not 1024 new incidents',
            'Small training and omission-weighted quality comparison before any model promotion'],
        'preserved': ['V4/V5 train/validation/test and source cases', 'R2 observations',
                      'CAM benchmark excluded', 'Original model/harness and V4 withheld decision'],
    }
    pools.update({'lineage.jsonl': ''.join(canonical(x) + '\n' for x in lineage).encode(),
                  'synthetic-selection.json': (json.dumps(dedup, ensure_ascii=False, indent=2) + '\n').encode(),
                  'mcp-contract-candidate.json': (json.dumps(catalog, ensure_ascii=False, indent=2) + '\n').encode()})
    attribution_raw = (root / specs['V5']['data_folder'] / 'SOURCE_ATTRIBUTION.json').read_bytes()
    attribution = json.loads(attribution_raw)
    pools['MITRE-ATTACK-LICENSE.txt'] = verified(
        root / specs['V5']['data_folder'] / 'MITRE-ATTACK-LICENSE.txt', attribution['MITRE']['license']['sha256'])
    pools['V5_SOURCE_ATTRIBUTION.json'] = attribution_raw
    for name in ('AIT_NOTICE.txt', 'LINUX_APT_NOTICE.txt'):
        pools[name] = (observations / name).read_bytes()
    pools['SOURCE_NOTICE.txt'] = (
        'Internal capstone candidate inventory, NOT an admitted or portable training release.\n'
        'Frozen V5 CTI replay: MITRE mappings and CISA advisories; retain accompanying attribution/license.\n'
        'CISA KEV: https://github.com/cisagov/kev-data ; original V4 case source URI/commit retained.\n'
        'AIT ADS CC BY 4.0 / AIT LDS CC BY-NC-SA 4.0 / Linux-APT CC BY 4.0: see original notices.\n'
        'The original per-row provenance and source-case hashes are retained in lineage.\n'
        'Changes: subset selection, grouping of controlled synthetic identities/times, pool separation;\n'
        'no rewriting of selected frozen rows. Original source cases/specifications are prerequisites.\n'
        'Korean questions, SOC interpretations and synthetic/harness examples are project-authored.\n'
        'Institutional logs are not institution-certified SOC answers; no endorsement or warranty.\n'
        'FW prefix is project-authored call selection supported by a historical MCP execution;\n'
        'it does not include a captured user question, fabricated tool result or final model answer.\n'
        'CAM/evaluation files are excluded. All remaining evidence/quality/release gates still apply.\n'
    ).encode()
    if revision:
        for name, content in reviewed_support.items():
            pools['REVIEWED_V4_' + name] = content
        pools['SOURCE_NOTICE.txt'] += (
            'Follow-up: 126 V4 observation rows replaced by an explicitly source-rechecked version,\n'
            'with original IDs/splits and old/new hashes retained. See REVIEWED_V4_SOURCE_NOTICE.txt.\n'
            'The earlier byte-preservation statement applies to unrevised frozen rows only.\n').encode()
        manifest['release_gates_remaining'][0] = ('Source recheck and target refinements completed for the chosen126; '
            'project-authored targets remain subject to semantic/expert quality evaluation and V4 remains withheld')
    manifest['support_files'] = {name: sha(data) for name, data in pools.items() if name not in manifest['pool_files']}
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in pools.items():
        (output / name).write_bytes(raw)
    (output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--observations', type=Path, required=True)
    parser.add_argument('--fw-proof', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reviewed-v4-observations', type=Path)
    args = parser.parse_args()
    report = build(args.root, args.observations, args.fw_proof, args.output, args.reviewed_v4_observations)
    print(json.dumps({'status': report['status'], 'pools': report['pool_files'], 'counts': report['source_counts']}))


if __name__ == '__main__':
    main()
