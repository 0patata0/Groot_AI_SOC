#!/usr/bin/env python3
"""Restore the frozen composition plus the bounded-collection overlay."""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(root):
    files = {}
    for p in sorted(root.rglob('*')):
        assert not p.is_symlink()
        if p.is_file():
            files[str(p.relative_to(root))] = sha(p)
        else:
            assert p.is_dir()
    raw = json.dumps(files, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    return len(files), hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    repo, out = args.repo.resolve(), args.output.resolve()
    manifest = json.loads((HERE / 'collection-manifest.json').read_text())
    original = json.loads((HERE / 'manifest.json').read_text())
    assert sha(HERE / 'manifest.json') == manifest['composition_manifest_sha256']
    assert sha(HERE / 'collection.patch') == manifest['patch_sha256']
    for name, digest in manifest['tests_sha256'].items():
        assert sha(HERE / name) == digest, name
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(repo)
    subprocess.run([sys.executable, '-B', str(HERE / 'reproduce.py'), '--repo', str(repo), '--output', str(out)], check=True, capture_output=True, timeout=60)
    candidate = out / 'candidate'
    assert identity(candidate) == (original['candidate_tree_file_count'], original['candidate_tree_sha256'])
    mapping = original['component_mapping']
    before = {name: (candidate / path).read_text() for name, path in mapping.items()}
    before['tool_descriptions/tool_guidance.md'] = original['audit_index']
    for name, info in manifest['sources'].items():
        assert sha(candidate / name) == info['before_sha256'], name
    # Exact whole-tree and per-source SHA checks precede the zero-context patch.
    for option in (['--check'], []):
        subprocess.run(['git', 'apply', '--unidiff-zero', *option, str(HERE / 'collection.patch')], cwd=candidate, check=True, capture_output=True)
    assert identity(candidate) == (manifest['candidate_tree_file_count'], manifest['candidate_tree_sha256'])
    for name, info in manifest['sources'].items():
        assert sha(candidate / name) == info['candidate_sha256'], name
    framework = repo / 'G_Harness2'
    pin = subprocess.check_output(['git', '-C', str(framework), 'rev-parse', 'HEAD'], text=True).strip()
    assert pin == original['framework_commit'] == manifest['framework_commit']
    subprocess.run(['git', '-C', str(framework), 'diff', '--exit-code', 'HEAD', '--', 'harness2'], check=True, capture_output=True)
    sys.path.insert(0, str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface = replace(OPENCODE_SURFACE, name='soc-journal-collection', stubs=(), always_on=('systemprompt.md', 'tool_descriptions/tool_guidance.md'), always_on_max=65536)
    after = {name: (candidate / path).read_text() for name, path in mapping.items()}
    after['tool_descriptions/tool_guidance.md'] = original['audit_index']
    report = {'framework_commit': pin, 'before': tree.validate(surface, before, allow_subagents=False), 'candidate': tree.validate(surface, after, allow_subagents=False), 'diff': tree.diff_summary(surface, before, after), 'candidate_tree_sha256': manifest['candidate_tree_sha256'], 'scope': 'Official structure and exact source restoration; not runtime accuracy, deployment or chat acceptance', 'operating_changes': 0, 'model_calls': 0}
    (out / 'collection-harness2.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
