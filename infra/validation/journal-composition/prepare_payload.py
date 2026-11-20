#!/usr/bin/env python3
"""Prepare the fixed static release payload from a pinned Git commit.

This operator-side producer never reads live credentials, grants approval,
contacts a server or applies files. Live-derived receipts and reader/launcher
barriers still need a separately observed, exact release plan.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


contract = module('payload_source_contract', Path(__file__).with_name('release_status.py'))
binding = module('payload_management_binding', ROOT / 'deployment/soc_runtime.py')
need = contract.need
sha = lambda raw: hashlib.sha256(raw).hexdigest()
RECEIPTS = frozenset(('/etc/capstone-ollama-trial/receipt.json',
                      '/etc/capstone-review-chat/receipt.json'))
UNITS = frozenset(('/etc/systemd/system/capstone-system-diagnostics.service',
                   '/etc/systemd/system/capstone-diagnostic-history-backfill.service'))
CONTROLLER = '/opt/capstone-management/soc_management_controller.py'
GATE = '/opt/capstone-management/soc_management_run.py'
GENERATOR = 'deployment/soc_diagnostics.py'


def source_map():
    """Fixed source-to-target mapping, independent of historical observations."""
    common = {target: 'infra/mcp/' + Path(target).name
              for target in contract.COMMON - UNITS}
    hermes = {
        'chat_contract.py': 'infra/hermes/chat_contract.py',
        'read_contract.py': 'infra/hermes/read_contract.py',
        'workflow_contract.py': 'infra/hermes/workflow_contract.py',
        'grounding.py': 'infra/hermes/soc_management_run.py',
        'skill-soc-query.md': 'infra/hermes/skills/soc-query/SKILL.md',
        'skill-soc-investigate.md': 'infra/hermes/skills/soc-investigate/SKILL.md',
    }
    b = dict(common)
    for prefix, names in (
        ('/opt/capstone-management/', ('workflow_contract.py', 'skill-soc-query.md', 'skill-soc-investigate.md')),
        ('/opt/capstone-ollama-trial/', tuple(hermes)),
        ('/opt/hermes-data/plugins/groot-query-completion/', tuple(hermes)),
    ):
        b.update({prefix + name: hermes[name] for name in names})
    b.update({
        CONTROLLER: 'infra/hermes/soc_management_controller.py',
        GATE: 'infra/hermes/soc_management_run.py',
        '/opt/hermes-data/management-code/run.py': 'infra/hermes/soc_management_run.py',
        '/opt/capstone-ollama-trial/query_grounding.py': 'infra/hermes/query-completion/__init__.py',
        '/opt/capstone-ollama-trial/harness.py': 'infra/ollama-trial/harness.py',
        '/opt/capstone-ollama-trial/runtime.py': 'infra/ollama-trial/runtime.py',
        '/opt/capstone-review-chat/review_channel_worker.py': 'infra/hermes/review_channel_worker.py',
        '/opt/hermes-data/plugins/groot-query-completion/__init__.py': 'infra/hermes/query-completion/__init__.py',
        '/opt/hermes-data/plugins/groot-query-completion/alignment.py': 'infra/hermes/query-completion/alignment.py',
        '/opt/hermes-data/plugins/groot-query-completion/chat_harness.py': 'infra/ollama-trial/harness.py',
        '/opt/mcp/system-diagnostics-mcp.py': 'infra/mcp/system-diagnostics-mcp.py',
    })
    result = {'a': dict(common), 'b': b, 'c': dict(common)}
    for role, paths in result.items():
        need(set(paths) == contract.TARGETS[role] - UNITS - RECEIPTS, 'static_source_footprint')
    return result


def unit_generator(raw):
    """Load just the pinned installer's pure unit generator and its constants."""
    constants = {'ROLE_HOST', 'COLLECTION_RESOURCES', 'SERVICE', 'BACKFILL_SERVICE', 'TIMER', 'JOURNAL_SERVICE'}
    selected = []
    seen = []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in constants:
                ast.literal_eval(node.value)
                selected.append(node)
                seen.append(node.targets[0].id)
        elif isinstance(node, ast.FunctionDef) and node.name == 'unit_documents':
            selected.append(node)
            seen.append(node.name)
    need(len(seen) == len(constants) + 1 and set(seen) == constants | {'unit_documents'},
         'unit_generator_source_shape')
    namespace = {'need': need}
    exec(compile(ast.Module(body=selected, type_ignores=[]), 'pinned-unit-generator', 'exec'), namespace)
    return namespace['unit_documents']


def build(read_source, source_commit):
    """Return bytes and provenance; read_source accepts only the fixed catalog."""
    need(isinstance(source_commit, str) and re.fullmatch('[0-9a-f]{40}', source_commit), 'source_commit')
    inputs = {}

    def read(path):
        if path not in inputs:
            raw = read_source(path)
            need(isinstance(raw, bytes) and 0 < len(raw) <= contract.MAX_SOURCE, 'source_bound')
            if path.endswith('.py'):
                compile(raw, path, 'exec')
            inputs[path] = raw
        return inputs[path]

    payloads = {role: {} for role in 'abc'}
    rows = {role: [] for role in 'abc'}
    mappings = source_map()
    for role, mapping in mappings.items():
        for target, path in sorted(mapping.items()):
            raw = read(path)
            payloads[role][target] = raw
            rows[role].append({'target': target, 'source': path, 'input_sha256': sha(raw),
                               'after_sha256': sha(raw), 'transform': 'identity'})

    # Bind the exact gate delivered to both the host reference and Hermes.
    # Fresh-profile rendering would also change identities/paths and is not an
    # existing-server update operation.
    raw = payloads['b'][CONTROLLER]
    gate = payloads['b'][GATE]
    need(gate == payloads['b']['/opt/hermes-data/management-code/run.py'], 'management_gate_copy_mismatch')
    bound = binding.bind_management_gate(raw, gate)
    need(0 < len(bound) <= contract.MAX_SOURCE, 'bound_controller_size')
    payloads['b'][CONTROLLER] = bound
    row = next(row for row in rows['b'] if row['target'] == CONTROLLER)
    row.update(after_sha256=sha(bound), transform='installation_bound_inline_management_gate',
               gate_source=mappings['b'][GATE], gate_sha256=sha(gate))

    generate = unit_generator(read(GENERATOR))
    for role, name in {'a': 'security', 'b': 'siem', 'c': 'service'}.items():
        units = generate(name)
        for target in sorted(UNITS):
            raw = units[Path(target).name]
            need(isinstance(raw, bytes) and 0 < len(raw) <= contract.MAX_SOURCE, 'unit_bound')
            payloads[role][target] = raw
            rows[role].append({'target': target, 'source': GENERATOR, 'input_sha256': sha(inputs[GENERATOR]),
                               'after_sha256': sha(raw), 'transform': 'unit_documents', 'role': name})
        need(set(payloads[role]) == contract.TARGETS[role] - RECEIPTS, 'static_payload_footprint')
        rows[role].sort(key=lambda row: row['target'])
    unique = {sha(raw): raw for values in payloads.values() for raw in values.values()}
    need(sum(map(len, unique.values())) <= 8 * 1024 * 1024, 'static_payload_total_bound')
    manifest = {'schema': 1, 'source_commit': source_commit,
                'scope': 'static payload only; no approval or operating deployment',
                'producer_sha256': sha(Path(__file__).read_bytes()),
                'management_binding_sha256': sha(Path(binding.__file__).read_bytes()),
                'source_contract_sha256': sha(Path(contract.__file__).read_bytes()),
                'source_files_sha256': {path: sha(raw) for path, raw in sorted(inputs.items())},
                'hosts': rows, 'payload_files': len(unique), 'payload_bytes': sum(map(len, unique.values())),
                'excluded': ['two live integrity receipts', 'three bound reader barriers', 'one bound MCP launcher']}
    return payloads, manifest


def git_reader(repository, source_commit):
    repository = Path(repository).resolve()
    need(re.fullmatch('[0-9a-f]{40}', source_commit) is not None, 'source_commit')
    allowed = {GENERATOR} | {path for mapping in source_map().values() for path in mapping.values()}

    def read(path):
        need(path in allowed, 'source_not_in_catalog')
        result = subprocess.run(['git', '--no-pager', 'show', source_commit + ':' + path],
                                cwd=repository, capture_output=True, timeout=15)
        need(result.returncode == 0, 'committed_source_unavailable')
        return result.stdout
    return read


def prepare_receipt(raw, target, before_digests, after_digests):
    """Update only current source hashes in a live integrity receipt.

    The caller pins the input receipt separately. Returning bytes is not
    permission to write them; an operator may keep them on the observed host
    and export only their digest and the non-secret change ledger.
    """
    need(target in RECEIPTS and isinstance(raw, bytes) and 0 < len(raw) <= 2 * 1024 * 1024,
         'integrity_receipt_scope')
    value = contract.parsed(raw)

    def no_credentials(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if re.search(r'(?i)(?:^|_)(?:password|passwd|token|secret|private_key|api_key)(?:$|_)', str(key)):
                    need(child is None or type(child) is bool, 'credential_field_in_source_receipt')
                no_credentials(child)
        elif isinstance(item, list):
            for child in item:
                no_credentials(child)
    no_credentials(value)
    field = 'sources' if target == '/etc/capstone-ollama-trial/receipt.json' else 'files'
    need(isinstance(value, dict) and isinstance(value.get(field), dict), 'integrity_receipt_shape')
    prefix = '/opt/capstone-ollama-trial/' if field == 'sources' else '/opt/capstone-review-chat/'
    changes = []
    for path, replacement in sorted(after_digests.items()):
        if not path.startswith(prefix):
            continue
        key = Path(path).name if field == 'sources' else path
        need(key in value[field], 'integrity_receipt_source_missing')
        original = value[field][key]
        actual = before_digests.get(path)
        need(all(isinstance(item, str) and re.fullmatch('[0-9a-f]{64}', item)
                 for item in (original, actual, replacement)), 'integrity_receipt_digest')
        value[field][key] = replacement
        changes.append({'receipt': target, 'entry': key, 'previous_receipt_sha256': original,
                        'observed_source_sha256': actual, 'after_sha256': replacement,
                        'preexisting_receipt_drift': original != actual})
    need(changes, 'integrity_receipt_no_sources')
    result = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    need(len(result) <= 2 * 1024 * 1024, 'integrity_receipt_bound')
    return result, changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=ROOT)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    payloads, manifest = build(git_reader(args.repository, args.source_commit), args.source_commit)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for values in payloads.values():
        for raw in values.values():
            target = args.output / (sha(raw) + '.data')
            if not target.exists():
                with target.open('xb') as stream:
                    stream.write(raw)
    (args.output / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'static_targets': {role: len(rows) for role, rows in manifest['hosts'].items()},
                      'payload_files': manifest['payload_files'], 'payload_bytes': manifest['payload_bytes'],
                      'manifest_sha256': sha((args.output / 'manifest.json').read_bytes())}))


if __name__ == '__main__':
    main()
