#!/usr/bin/env python3
"""Preserve pinned AFB graph topology and explicit branches, without a timeline.

This is a reference projection, not a STIX exporter or training QA generator.
Original properties are retained except explicitly sensitive structured fields.
"""
import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONTROL = {'action', 'condition', 'AND_operator', 'OR_operator'}
NODE_TYPES = CONTROL | {
    'tool', 'malware', 'process', 'user_account', 'file', 'software',
    'windows_registry_key', 'directory', 'asset', 'vulnerability', 'infrastructure',
    'note', 'ipv4_addr', 'url', 'artifact', 'threat_actor', 'campaign',
    'course_of_action', 'detection', 'mitigation', 'domain_name', 'location',
    'identity', 'network_traffic', 'email_address',
}
ANCHORS = {'vertical_anchor', 'horizontal_anchor'}
TECHNICAL = ANCHORS | {'generic_latch', 'generic_handle', 'dynamic_line', 'flow'}
SENSITIVE_FIELDS = {'credential', 'decryption_key', 'payload_bin', 'contact_information'}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def properties(obj):
    pairs = obj.get('properties', [])
    require(isinstance(pairs, list) and all(isinstance(x, list) and len(x) == 2
            and isinstance(x[0], str) for x in pairs), 'Malformed properties')
    require(len({x[0] for x in pairs}) == len(pairs), 'Duplicate property names')
    return dict(pairs)


def redact(value, removed):
    """Retain null/false/zero; omit populated sensitive fields, including nested author."""
    if isinstance(value, list):
        result = []
        for item in value:
            is_pair = isinstance(item, list) and len(item) == 2 and isinstance(item[0], str)
            if is_pair and item[0] in SENSITIVE_FIELDS:
                key, child = item
                if child is not None and child != '':
                    removed[key] += 1
                    result.append([key, {'omitted': 'sensitive structured field; consult original source'}])
                else:
                    result.append(deepcopy(item))
            else:
                result.append(redact(item, removed))
        return result
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if key in SENSITIVE_FIELDS and child is not None and child != '':
                removed[key] += 1
                result[key] = {'omitted': 'sensitive structured field; consult original source'}
            else:
                result[key] = redact(child, removed)
        return result
    return deepcopy(value)


def project(document):
    require(document.get('schema') == 'attack_flow_v2', 'Unreviewed AFB schema')
    require(set(document) <= {'schema', 'objects', 'layout', 'camera', 'theme'}, 'Unreviewed AFB top-level field')
    objects = document['objects']
    require(isinstance(objects, list) and objects, 'No AFB objects')
    require(all(isinstance(o, dict) and isinstance(o.get('instance'), str) for o in objects),
            'Malformed AFB objects')
    by_id = {o['instance']: o for o in objects}
    require(len(by_id) == len(objects), 'Duplicate object instance')
    require(all(o.get('id') in NODE_TYPES | TECHNICAL for o in objects), 'Unreviewed AFB object type')
    flows = [o for o in objects if o['id'] == 'flow']
    require(len(flows) == 1, 'Expected one flow')
    flow = flows[0]
    meta = properties(flow)
    nodes = [o for o in objects if o['id'] in NODE_TYPES]
    lines = [o for o in objects if o['id'] == 'dynamic_line']
    members = flow['objects']
    require(len(members) == len(set(members)) and set(members) ==
            {o['instance'] for o in nodes + lines}, 'Root membership mismatch')
    anchor_owners, latch_owners = {}, {}
    for node in nodes:
        require(set(node) <= {'id', 'instance', 'properties', 'anchors'}, 'Unreviewed node field')
        props = properties(node)
        if node['id'] in {'AND_operator', 'OR_operator'}:
            require(props.get('operator') == node['id'].split('_')[0], 'Operator type/value mismatch')
        require(isinstance(node.get('anchors'), dict), 'Node anchors missing')
        for position, anchor_id in node['anchors'].items():
            require(isinstance(position, str) and anchor_id not in anchor_owners, 'Repeated anchor ownership')
            anchor = by_id.get(anchor_id, {})
            require(anchor.get('id') in ANCHORS, 'Missing/wrong anchor object')
            require(set(anchor) == {'id', 'instance', 'latches'}, 'Unreviewed anchor fields')
            if position.startswith('branch:'):
                require(node['id'] == 'condition' and position in {'branch:True', 'branch:False'},
                        'Unreviewed branch identifier')
            owner = {'node': node['instance'], 'position': position, 'anchor': anchor_id}
            anchor_owners[anchor_id] = owner
            for latch_id in anchor['latches']:
                require(latch_id not in latch_owners, 'Repeated latch ownership')
                require(by_id.get(latch_id, {}).get('id') == 'generic_latch', 'Missing/wrong latch object')
                latch_owners[latch_id] = owner
    require(set(anchor_owners) == {o['instance'] for o in objects if o['id'] in ANCHORS}, 'Orphan anchor')
    require(set(latch_owners) == {o['instance'] for o in objects if o['id'] == 'generic_latch'}, 'Orphan latch')
    removed, edges, used_latches, used_handles = Counter(), [], [], []
    for line in lines:
        require(set(line) <= {'id', 'instance', 'source', 'target', 'properties', 'handles'}, 'Unreviewed edge field')
        properties(line)
        endpoints = [latch_owners.get(line.get(k)) for k in ('source', 'target')]
        require(all(endpoints), 'Unresolved line endpoint')
        source, target = endpoints
        source_type = by_id[source['node']]['id']
        target_type = by_id[target['node']]['id']
        relation = 'context_relation'
        branch = None
        if source_type == 'condition' and source['position'] in {'branch:True', 'branch:False'}:
            branch = source['position'].split(':')[1].lower()
            if target_type in CONTROL:
                relation = 'on_' + branch
        elif source_type in {'action', 'AND_operator', 'OR_operator'} and target_type in CONTROL:
            relation = 'effect'
        # A condition's ordinary anchor is NOT implicitly a true branch.
        for handle_id in line.get('handles', []):
            require(by_id.get(handle_id, {}).get('id') == 'generic_handle', 'Missing/wrong line handle')
            used_handles.append(handle_id)
        used_latches.extend([line['source'], line['target']])
        edges.append({'id': line['instance'], 'source': source['node'], 'target': target['node'],
                      'source_route': deepcopy(source), 'target_route': deepcopy(target),
                      'source_latch': line['source'], 'target_latch': line['target'],
                      'relation': relation, 'condition_branch': branch,
                      'properties': redact(line.get('properties', []), removed),
                      'source_object_sha256': sha(canonical(line).encode())})
    require(len(used_latches) == len(set(used_latches)) and set(used_latches) == set(latch_owners),
            'Unused/repeated line latch')
    require(len(used_handles) == len(set(used_handles)) and set(used_handles) ==
            {o['instance'] for o in objects if o['id'] == 'generic_handle'}, 'Unused/repeated line handle')
    projected = [{'id': o['instance'], 'type': o['id'], 'properties': redact(o.get('properties', []), removed),
                  'source_object_sha256': sha(canonical(o).encode())} for o in nodes]
    metadata = redact(flow['properties'], removed)
    ambiguous = [e['id'] for e in edges if by_id[e['source']]['id'] == 'condition'
                 and by_id[e['target']]['id'] in CONTROL and e['condition_branch'] is None]
    return {'schema': 'soc-afb-graph-reference-v1', 'flow_id': flow['instance'],
            'scope': meta.get('scope'), 'metadata': metadata, 'nodes': projected, 'edges': edges,
            'counts': {'nodes': len(nodes), 'edges': len(edges),
                       'node_types': dict(Counter(o['id'] for o in nodes)),
                       'relations': dict(Counter(e['relation'] for e in edges)),
                       'sensitive_fields_omitted': dict(removed)},
            'review_flags': {'condition_control_links_without_explicit_branch': ambiguous},
            'interpretation': {'ordered_steps': False, 'source_order_is_chronology': False,
                               'branches_are_observed_success': False, 'is_STIX_export': False,
                               'training_admitted': False,
                               'omitted_fields': 'Rendering layout/camera/theme and transport scaffolding; populated sensitive fields explicitly marked.'}}


def prepare(source_dir, output, spec_path=ROOT / 'ATTACK_FLOW_SOURCE_SPEC.json'):
    source_dir, output, spec_path = Path(source_dir), Path(output), Path(spec_path)
    require(not output.exists(), 'Output already exists; use a new directory')
    spec = json.loads(spec_path.read_text())
    expected = {x['file']: x for x in spec['files']}
    require(len(expected) == len(spec['files']) == 41, 'Pinned corpus inventory differs')
    require({p.name for p in source_dir.glob('*.afb')} == set(expected), 'Unexpected/missing corpus files')
    rows, entries = [], []
    for name, item in expected.items():
        path = source_dir / name
        require(Path(name).name == name and not path.is_symlink(), 'Unsafe corpus path')
        raw = path.read_bytes()
        require(len(raw) == item['bytes'] and sha(raw) == item['sha256'], 'Corpus hash/size mismatch: ' + name)
        require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == item['git_blob'],
                'Upstream blob mismatch: ' + name)
        row = project(json.loads(raw))
        row['source'] = {'file': name, 'sha256': item['sha256'], 'git_blob': item['git_blob'],
                         'commit': spec['upstream_commit'], 'path': item['upstream_path'],
                         'license': spec['license'], 'repository': spec['upstream_repository']}
        rows.append(row)
        entries.append({'file': name, 'source_sha256': item['sha256'], 'graph_sha256': sha(canonical(row).encode())})
    license_path = ROOT / 'licenses/attack-flow-LICENSE.txt'
    license_item = next(x for x in spec['semantic_reference_sources'] if x['path'] == 'LICENSE')
    license_bytes = license_path.read_bytes()
    require(sha(license_bytes) == license_item['sha256'], 'Source license mismatch')
    data = ''.join(canonical(x) + '\n' for x in rows).encode()
    counts = Counter()
    relations, types, removed = Counter(), Counter(), Counter()
    for row in rows:
        counts[row['scope']] += 1
        relations.update(row['counts']['relations'])
        types.update(row['counts']['node_types'])
        removed.update(row['counts']['sensitive_fields_omitted'])
    report = {'schema': 1, 'prepared_at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
              'parser_sha256': sha(Path(__file__).read_bytes()), 'spec_sha256': sha(spec_path.read_bytes()),
              'output_sha256': sha(data), 'files': entries, 'flows': len(rows), 'scope_counts': dict(counts),
              'node_types': dict(types), 'nodes': sum(types.values()), 'relations': dict(relations),
              'edges': sum(relations.values()), 'sensitive_fields_omitted': dict(removed),
              'untyped_condition_control_links': sum(len(x['review_flags']['condition_control_links_without_explicit_branch']) for x in rows),
              'training_admitted': 0, 'new_independent_incidents': 0, 'upstream_commit': spec['upstream_commit']}
    output.mkdir(parents=True)
    (output / 'graphs.jsonl').write_bytes(data)
    (output / 'LICENSE').write_bytes(license_bytes)
    (output / 'NOTICE').write_text('Derived graph reference from MITRE CTID Attack Flow; Apache-2.0.\n'
                                  + spec['upstream_repository'] + '/tree/' + spec['upstream_commit'] + '\n'
                                  'Project modification: preserve graph routes; omit marked sensitive fields.\n'
                                  'This is not chronological ground truth, STIX export, or admitted training data.\n')
    (output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=ROOT / 'raw/attack-flow')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.source_dir, args.output)
    print(json.dumps({k: v for k, v in result.items() if k != 'files'}, ensure_ascii=False))
