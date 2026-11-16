#!/usr/bin/env python3
"""Restore the pinned collection candidate plus finite bootstrap limits."""
import argparse
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('limits_collection_replay', HERE / 'reproduce_collection.py')
collection = importlib.util.module_from_spec(spec); spec.loader.exec_module(collection)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    repo, out = args.repo.resolve(), args.output.resolve()
    manifest = json.loads((HERE / 'limits-manifest.json').read_text())
    base = json.loads((HERE / 'collection-manifest.json').read_text())
    original = json.loads((HERE / 'manifest.json').read_text())
    assert collection.sha(HERE / 'collection-manifest.json') == manifest['collection_manifest_sha256']
    assert collection.sha(HERE / 'limits.patch') == manifest['patch_sha256']
    for name, digest in manifest['tools_sha256'].items():
        assert collection.sha(HERE / name) == digest, name
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(repo)
    subprocess.run([sys.executable, '-B', str(HERE / 'reproduce_collection.py'),
                    '--repo', str(repo), '--output', str(out)], check=True, capture_output=True, timeout=90)
    candidate = out / 'candidate'
    assert collection.identity(candidate) == (base['candidate_tree_file_count'], base['candidate_tree_sha256'])
    mapping = dict(original['component_mapping'])
    mapping.update({'scripts/limits_test_bootstrap.py': 'deployment/tests/test_soc_diagnostics.py',
                    'scripts/limits_test_cli.py': 'infra/mcp/test_system_diagnostics.py',
                    'scripts/limits_test_factual_time.py': 'infra/validation/factual-service/test_factual_service.py'})
    before = {name: (candidate / path).read_text() for name, path in mapping.items()}
    before['tool_descriptions/tool_guidance.md'] = original['audit_index']
    for name, info in manifest['sources'].items():
        assert collection.sha(candidate / name) == info['before_sha256'], name
    for extra in (['--check'], []):
        subprocess.run(['git', 'apply', '--unidiff-zero', *extra, str(HERE / 'limits.patch')],
                       cwd=candidate, check=True, capture_output=True)
    assert collection.identity(candidate) == (manifest['candidate_tree_file_count'], manifest['candidate_tree_sha256'])
    for name, info in manifest['sources'].items():
        assert collection.sha(candidate / name) == info['candidate_sha256'], name
    framework = repo / 'G_Harness2'
    pin = subprocess.check_output(['git', '-C', str(framework), 'rev-parse', 'HEAD'], text=True).strip()
    assert pin == original['framework_commit'] == manifest['framework_commit']
    subprocess.run(['git', '-C', str(framework), 'diff', '--exit-code', 'HEAD', '--', 'harness2'], check=True, capture_output=True)
    sys.path.insert(0, str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface = replace(OPENCODE_SURFACE, name='soc-collector-limits', stubs=(),
                      always_on=('systemprompt.md', 'tool_descriptions/tool_guidance.md'), always_on_max=65536)
    after = {name: (candidate / path).read_text() for name, path in mapping.items()}
    after['tool_descriptions/tool_guidance.md'] = original['audit_index']
    report = {'framework_commit': pin, 'before': tree.validate(surface, before, allow_subagents=False),
              'candidate': tree.validate(surface, after, allow_subagents=False),
              'diff': tree.diff_summary(surface, before, after),
              'candidate_tree_sha256': manifest['candidate_tree_sha256'],
              'scope': 'Exact resource overlay restoration and official structure; not operating deployment, chat or SOC accuracy',
              'operating_changes': 0, 'model_calls': 0}
    (out / 'limits-harness2.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
