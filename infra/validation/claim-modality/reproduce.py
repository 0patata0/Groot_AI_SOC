#!/usr/bin/env python3
"""Reconstruct the frozen development comparison; no SSH, model, MCP or apply.

The prerequisite patch is an unapproved comparison baseline. It is never a
production installer, release plan or substitute for an exact approval.
"""
import argparse
import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    repo = args.repo.resolve()
    out = args.output.resolve()
    here = Path(__file__).resolve().parent
    frozen = json.loads((here / 'manifest.json').read_text())
    assert not out.exists() and out.parent.is_dir()
    assert not out.is_relative_to(repo), 'use a fresh isolated directory outside the worktree'
    for filename, field in (('prerequisite.patch', 'prerequisite_patch_sha256'),
                            ('candidate.patch', 'candidate_patch_sha256'),
                            ('test_claims.py', 'test_sha256')):
        assert sha((here / filename).read_bytes()) == frozen[field], filename
    run = lambda *a: subprocess.check_output(['git', '-C', str(repo), *a])
    records = run('ls-tree', '-rz', frozen['base_commit'], '--', *frozen['source_prefixes'])
    out.mkdir(mode=0o700)
    for arm in ('base', 'candidate'):
        dest = out / arm
        dest.mkdir()
        for record in records.rstrip(b'\0').split(b'\0'):
            metadata, name = record.split(b'\t', 1)
            mode, kind, blob = metadata.split()
            rel = Path(name.decode())
            assert mode in (b'100644', b'100755') and kind == b'blob'
            assert not rel.is_absolute() and '..' not in rel.parts
            raw = run('cat-file', 'blob', blob.decode())
            assert len(raw) < 2 * 1024 * 1024
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        patches = ('prerequisite.patch',) if arm == 'base' else ('prerequisite.patch', 'candidate.patch')
        for name in patches:
            subprocess.run(['git', 'apply', '--check', str(here / name)], cwd=dest, check=True)
            subprocess.run(['git', 'apply', str(here / name)], cwd=dest, check=True)
        field = 'before_sha256' if arm == 'base' else 'candidate_sha256'
        for name, item in frozen['sources'].items():
            assert sha((dest / name).read_bytes()) == item[field], (arm, name)
    for item in frozen['ast_scope']:
        defs = set(item['changed_named_definitions'])
        metadata = set(item['permitted_metadata_assignments'])
        def retained(path):
            body = ast.parse(path.read_text()).body
            return [ast.dump(node) for node in body
                if not (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in defs)
                and not (isinstance(node, ast.Assign) and any(isinstance(n, ast.Name) and n.id in metadata for n in node.targets))]
        assert retained(out / 'base' / item['source']) == retained(out / 'candidate' / item['source'])
    framework = repo / 'G_Harness2'
    pin = subprocess.check_output(['git', '-C', str(framework), 'rev-parse', 'HEAD'], text=True).strip()
    assert pin == frozen['framework_commit']
    subprocess.run(['git', '-C', str(framework), 'diff', '--exit-code', 'HEAD', '--', 'harness2'], check=True, capture_output=True)
    sys.path.insert(0, str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface = replace(OPENCODE_SURFACE, name='soc-claim-modality', stubs=(),
        always_on=('systemprompt.md', 'tool_descriptions/tool_guidance.md'), always_on_max=65536)
    index = ('Audit index only: workflow_contract selects soc-query, soc-investigate, soc-change, soc-recover. '
             'output_contract loads soc-output. No authority or production prompt is replaced.\n')
    models = {arm: {key: (out / arm / name).read_text() for key, name in frozen['component_mapping'].items()}
        | {'tool_descriptions/tool_guidance.md': index} for arm in ('base', 'candidate')}
    report = {'framework_commit': pin, 'census': {a: tree.validate(surface, v, allow_subagents=False) for a, v in models.items()},
        'diff': tree.diff_summary(surface, models['base'], models['candidate']), 'sources_verified_per_arm': len(frozen['sources']),
        'operating_changes': 0, 'model_calls': 0, 'mcp_calls': 0, 'chat_posts': 0,
        'scope': 'isolated structure/AST reconstruction; not semantic accuracy or an operating release'}
    (out / 'harness2.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
