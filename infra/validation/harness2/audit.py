#!/usr/bin/env python3
"""Supplementary Harness2 tree validation and frozen SOC renderer regressions.

No model client, SSH client, proposer, production installer or credential loader.
The caller obtains a read-only live snapshot separately. A snapshot is historical
evidence, not a claim that the remote environment is still unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

EDITABLE = {
    'scripts/sdk_harness.py': 'infra/ollama-trial/harness.py',
    'scripts/chat_markdown.py': 'infra/hermes/chat_markdown.py',
    'scripts/soc_bot.py': 'infra/mcp/soc_bot.py',
    'skills/soc-output/SKILL.md': 'infra/hermes/skills/soc-output/SKILL.md',
    'skills/soc-query/SKILL.md': 'infra/hermes/skills/soc-query/SKILL.md',
    'scripts/sdk_runtime.py': 'infra/ollama-trial/runtime.py',
    'scripts/native_alignment.py': 'infra/hermes/query-completion/alignment.py',
    'scripts/channel_worker.py': 'infra/hermes/review_channel_worker.py',
}
CONTEXT = {
    'systemprompt.md': 'infra/hermes/SOUL.groot.md',
    'scripts/chat_contract.py': 'infra/hermes/chat_contract.py',
    'scripts/read_contract.py': 'infra/hermes/read_contract.py',
    'scripts/output_contract.py': 'infra/hermes/output_contract.py',
    'scripts/workflow_contract.py': 'infra/hermes/workflow_contract.py',
    'scripts/channel_policy.py': 'infra/hermes/review_channel_policy.py',
    'scripts/native_query.py': 'infra/hermes/query-completion/__init__.py',
    'scripts/evidence_gate.py': 'infra/hermes/soc_management_run.py',
    'scripts/management_controller.py': 'infra/hermes/soc_management_controller.py',
    'scripts/channel_controller.py': 'infra/hermes/review_channel.py',
    'scripts/sdk_chat.py': 'infra/ollama-trial/chat.py',
    'scripts/sdk_chat_policy.py': 'infra/ollama-trial/chat_policy.py',
    'scripts/sdk_authority.py': 'infra/ollama-trial/policy.py',
    **{'skills/'+n+'/SKILL.md': 'infra/hermes/skills/'+n+'/SKILL.md' for n in
       ('soc-investigate','soc-change','soc-recover')},
}
LIVE = {
    'infra/ollama-trial/harness.py': '/opt/capstone-ollama-trial/harness.py',
    'infra/hermes/chat_markdown.py': '/opt/capstone-ollama-trial/chat_markdown.py',
    'infra/mcp/soc_bot.py': '/opt/socbot/soc_bot.py',
    'infra/ollama-trial/runtime.py': '/opt/capstone-ollama-trial/runtime.py',
    'infra/hermes/chat_contract.py': '/opt/capstone-ollama-trial/chat_contract.py',
    'infra/hermes/read_contract.py': '/opt/capstone-ollama-trial/read_contract.py',
    'infra/hermes/SOUL.groot.md': '/opt/capstone-ollama-trial/soc_policy.md',
    'infra/hermes/review_channel_worker.py': '/opt/capstone-review-chat/review_channel_worker.py',
    'infra/hermes/soc_management_run.py': '/opt/capstone-management/soc_management_run.py',
    'infra/hermes/query-completion/__init__.py': '/opt/capstone-ollama-trial/query_grounding.py',
}
TESTS = ('infra/ollama-trial/test_harness.py', 'infra/hermes/test_chat_markdown.py',
         'infra/hermes/test_soc_output_contract.py', 'infra/mcp/test_report_policy_changes.py',
         'infra/ollama-trial/test_event_lookup.py', 'infra/hermes/test_review_channel.py')
PROFILES = {
    'sdk': ['infra/ollama-trial/test_harness.py', '-v'],
    'markdown': ['-m', 'unittest', 'test_chat_markdown', 'test_soc_output_contract', '-v'],
    'periodic_report': ['infra/mcp/test_report_policy_changes.py', '-v'],
    'event_lookup': ['infra/ollama-trial/test_event_lookup.py', '-v'],
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--base-ref', required=True)
    p.add_argument('--source-manifest', type=Path, required=True)
    p.add_argument('--snapshot', type=Path, required=True)
    p.add_argument('--catalog', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--test-python', type=Path, required=True)
    p.add_argument('--structure-only', action='store_true',
                   help='Freeze/review all components first; execute no regression tests.')
    args = p.parse_args()
    repo = args.repo.resolve()
    out = args.output.resolve()
    assert not out.exists(), 'use a new audit directory; never overwrite evidence'
    assert out.is_relative_to(repo / 'G_Harness2'), 'temporary evidence belongs inside G_Harness2'
    assert re.fullmatch(r'[0-9a-f]{40}', args.base_ref), 'pin a full Git commit'
    assert args.test_python.is_absolute() and args.test_python.is_file()
    snapshot = json.loads(args.snapshot.read_text())
    catalog = json.loads(args.catalog.read_text())
    assert snapshot['mutation_performed'] is False
    assert not snapshot['manifest_drift'] and not snapshot['sdk_drift']
    assert catalog['status'] == 'discovered'
    assert catalog['calls'] == catalog['model_calls'] == []
    assert catalog['protected_calls'] == catalog['chat_posts'] == 0
    framework = repo / 'G_Harness2'
    framework_commit = git(framework, 'rev-parse', 'HEAD').decode().strip()
    assert framework_commit == '6868817518876de8fd170c6a8354daca273b6191'
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    from dataclasses import replace
    surface = replace(OPENCODE_SURFACE, name='soc-audit', stubs=(),
                      always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),
                      always_on_max=65536)
    tracked = set(git(repo, 'ls-tree', '-r', '--name-only', args.base_ref).decode().splitlines())
    source_names = set(json.loads(args.source_manifest.read_text())) | set(EDITABLE.values()) | set(CONTEXT.values()) | set(TESTS)
    sources = {}
    for name in sorted(source_names):
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts
        assert (name in tracked or name in TESTS) and (name.startswith(('infra/', 'deployment/')) or name in
            {'deploy.sh', 'new_rule/GROOT_A_WAF.conf', 'new_rule/GROOT_A_local.rules'}), name
        assert not (repo / name).is_symlink(), name
        raw = git(repo, 'show', args.base_ref + ':' + name) if name in tracked else (repo/name).read_bytes()
        assert len(raw) <= 2 * 1024 * 1024, name
        sources[name] = raw
    for name, installed in LIVE.items():
        observed = snapshot['display_sources'].get(installed,{}).get('sha256') or snapshot['manifest'].get(installed)
        assert sha(sources[name]) == observed, name
    for name in CONTEXT.values():
        assert sha(sources[name]) == sha((repo/name).read_bytes()), 'immutable context drift: '+name
    skill = sources['infra/hermes/skills/soc-output/SKILL.md']
    assert sha(skill) == catalog['skills']['/opt/capstone-ollama-trial/SKILL.md']['sha256']
    # Tests are identical in both arms, including new counterexamples. Unrelated
    # worktree changes and the evaluator itself cannot enter the editable surface.
    tests = {name: (repo / name).read_bytes() for name in TESTS}
    candidate = {name: (repo / name).read_bytes() for name in EDITABLE.values()}
    out.mkdir(parents=True)
    tmp = out / '.tmp'; tmp.mkdir()
    report = {
        'schema': 1, 'at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
        'framework_commit': framework_commit, 'base_commit': args.base_ref,
        'scope': 'harness component review' if args.structure_only else 'frozen harness regression; not an agent/model/chat evaluation',
        'live_observed_at_kst': snapshot['observed_at_kst'],
        'snapshot_sha256': sha(args.snapshot.read_bytes()),
        'catalog_sha256': sha(args.catalog.read_bytes()),
        'production_mutations': 0, 'model_calls': 0, 'subagents': 0,
        'automatic_adoption': False, 'arms': {},
        'structure_only': args.structure_only, 'editable_mapping':EDITABLE, 'immutable_mapping':CONTEXT,
        'synthetic_trigger_index': True,
        'trigger_index_note': 'Audit-only index of workflow_contract selection; never injected into a live prompt.',
        'shared_test_sha256': {name: sha(raw) for name, raw in tests.items()},
    }
    trees = {}
    for arm in ('base', 'candidate'):
        files = {**sources, **tests, **(candidate if arm == 'candidate' else {})}
        dest = out / arm; dest.mkdir()
        for name, raw in files.items():
            target = dest / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        tree_data = {key: files[name].decode() for key,name in {**CONTEXT,**EDITABLE}.items()}
        tree_data['tool_descriptions/tool_guidance.md'] = (
            'Audit index only: workflow_contract selects soc-query, soc-investigate, soc-change, soc-recover. '
            'output_contract loads soc-output. No authority or production prompt is replaced.\n')
        assert all(tree.is_allowed(surface, key) for key in tree_data)
        census = tree.validate(surface, tree_data, allow_subagents=False)
        tree.write_tree(surface, tree_data, out / ('tree-' + arm), stubs=False)
        trees[arm] = tree_data
        results = {}
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'en_US.UTF-8',
               'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1', 'TMPDIR': str(tmp),
               'PYTHONPATH': str(dest / 'infra/hermes'), 'MCP_USE_ANONYMIZED_TELEMETRY': 'false',
               'DO_NOT_TRACK': '1'}
        for name, cmd in (() if args.structure_only else PROFILES.items()):
            result = subprocess.run([str(args.test_python), '-B', *cmd], cwd=dest, env=env,
                                    capture_output=True, text=True, timeout=45)
            text = result.stdout + result.stderr
            (dest / (name + '.log')).write_text(text)
            counts = re.findall(r'Ran (\d+) tests?', text)
            results[name] = {'rc': result.returncode, 'count': int(counts[-1]) if counts else None,
                'failures': re.findall(r'^(?:FAIL|ERROR): (.+)$', text, re.M),
                'log_sha256': sha(text.encode())}
        report['arms'][arm] = {'census': census, 'tests': results,
            'sources': {name: sha(raw) for name, raw in files.items()}}
    report['framework_diff'] = tree.diff_summary(surface, trees['base'], trees['candidate'])
    report['candidate_tests_pass'] = (None if args.structure_only else
        all(v['rc'] == 0 and v['count'] for v in report['arms']['candidate']['tests'].values()))
    report['changed_source_paths'] = sorted(name for name in sources if
        report['arms']['base']['sources'][name] != report['arms']['candidate']['sources'][name])
    assert set(report['changed_source_paths']) <= set(EDITABLE.values())
    (out / 'REPORT.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('scope', 'candidate_tests_pass', 'framework_diff')}, ensure_ascii=False))
    return 0 if args.structure_only or report['candidate_tests_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
