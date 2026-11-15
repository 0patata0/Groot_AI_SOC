#!/usr/bin/env python3
"""Materialize a frozen, isolated read-contract candidate and audit its scope.

Uses an operator's local, credential-free source snapshot. No SSH, model call,
MCP invocation, package installation or production configuration is performed.
"""
import argparse
import base64
from dataclasses import replace
from datetime import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from zoneinfo import ZoneInfo


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--observed', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    repo = args.repo.resolve()
    here = Path(__file__).resolve().parent
    frozen = json.loads((here / 'manifest.json').read_text())
    observed = json.loads(args.observed.read_text())
    catalog = observed['catalog']
    assert catalog['status'] == 'discovered' and catalog['calls'] == catalog['model_calls'] == []
    assert catalog['protected_calls'] == catalog['chat_posts'] == 0
    assert observed['operating_changes'] == 0
    assert observed['model'] == frozen['model'] and observed['access_mode'] == frozen['access_mode']
    assert observed['config_sha256'] == frozen['configuration_sha256']
    assert sha(json.dumps(catalog['catalog'], ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()) == frozen['catalog_sha256']

    # Reuse the established SOC component mapping; its original editable scope
    # is unchanged. This audit explicitly allows only the eight frozen files.
    spec = importlib.util.spec_from_file_location('soc_harness_component_map', repo / 'infra/validation/harness2/audit.py')
    component_map = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(component_map)
    mapping = component_map.CONTEXT | component_map.EDITABLE
    assert set(observed['components']) == set(mapping)
    raw_sources = {}
    for key, name in mapping.items():
        item = observed['components'][key]
        assert item['source'] == name
        raw = base64.b64decode(item['base64'], validate=True)
        assert len(raw) <= 2 * 1024 * 1024
        assert sha(raw) == item['sha256'] == frozen['sources'][name]['before_sha256']
        raw_sources[name] = raw

    framework = repo / 'G_Harness2'
    pin = subprocess.check_output(['git', '-C', str(framework), 'rev-parse', 'HEAD'], text=True).strip()
    assert pin == frozen['framework_commit']
    subprocess.run(['git', '-C', str(framework), 'diff', '--exit-code', 'HEAD', '--', 'harness2'], check=True, capture_output=True)
    sys.path.insert(0, str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface = replace(OPENCODE_SURFACE, name='soc-common-read-audit', stubs=(),
                      always_on=('systemprompt.md', 'tool_descriptions/tool_guidance.md'), always_on_max=65536)
    index = ('Audit index only: workflow_contract selects soc-query, soc-investigate, soc-change, soc-recover. '
             'output_contract loads soc-output. No authority or production prompt is replaced.\n')
    before = {key: raw_sources[name].decode() for key, name in mapping.items()}
    before['tool_descriptions/tool_guidance.md'] = index
    before_census = tree.validate(surface, before, allow_subagents=False)

    out = args.output.resolve()
    assert not out.exists() and out.parent.is_dir(), 'use a new isolated output directory'
    assert not out.is_relative_to(repo), 'reproduce outside the project worktree'
    out.mkdir()
    names = subprocess.check_output(['git', '-C', str(repo), 'ls-tree', '-rz', frozen['base_commit'], '--',
        'infra/hermes', 'infra/ollama-trial', 'infra/mcp', 'deployment/tests', 'new_rule', 'infra/groot-b/local_rules.xml'])
    for arm in ('base', 'candidate'):
        dest = out / arm
        dest.mkdir()
        for record in names.rstrip(b'\0').split(b'\0'):
            metadata, name = record.split(b'\t', 1)
            mode, kind, blob = metadata.split()
            name = name.decode()
            rel = Path(name)
            assert mode in (b'100644', b'100755') and kind == b'blob'
            assert not rel.is_absolute() and '..' not in rel.parts
            raw = subprocess.check_output(['git', '-C', str(repo), 'cat-file', 'blob', blob.decode()])
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        for name, raw in raw_sources.items():
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
    patch = here / 'candidate.patch'
    assert sha(patch.read_bytes()) == frozen['patch_sha256']
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=out / 'candidate', check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=out / 'candidate', check=True)
    after = {}
    modified = set()
    for key, name in mapping.items():
        path = out / 'candidate' / name
        assert not path.is_symlink()
        raw = path.read_bytes()
        assert sha(raw) == frozen['sources'][name]['candidate_sha256']
        after[key] = raw.decode()
        if raw != raw_sources[name]:
            modified.add(name)
    assert modified == set(frozen['editable_sources'])
    after['tool_descriptions/tool_guidance.md'] = index
    report = {'at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
        'framework_commit': pin, 'live_observed_kst': observed['at_kst'],
        'snapshot_sha256': sha(args.observed.read_bytes()), 'patch_sha256': frozen['patch_sha256'],
        'census': {'base': before_census, 'candidate': tree.validate(surface, after, allow_subagents=False)},
        'diff': tree.diff_summary(surface, before, after),
        'operating_changes': 0, 'model_calls': 0, 'mcp_calls': 0,
        'scope': 'isolated reconstruction and official structural audit only; not semantic or live chat validation'}
    (out / 'harness2.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
