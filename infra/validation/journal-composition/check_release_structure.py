#!/usr/bin/env python3
"""Reproduce the pinned candidate and inspect the operator-only witness layer.

This calls official Harness2 structure validation; no model or operating host.
The existing collection candidate is restored, never edited in the workspace.
"""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();output=args.output.resolve()
    manifest=json.loads((HERE/'witness-manifest.json').read_text())
    assert HERE==(repo/'infra/validation/journal-composition').resolve()
    assert sha(HERE/'limits-manifest.json')==manifest['limits_manifest_sha256']
    assert sha(HERE/'manifest.json')==manifest['composition_manifest_sha256']
    for name,digest in manifest['source_sha256'].items():
        assert Path(name).name==name and sha(HERE/name)==digest,name
    assert not output.exists() and output.parent.is_dir() and not output.is_relative_to(repo)
    output.mkdir()
    subprocess.run([sys.executable,'-B',str(HERE/'reproduce_limits.py'),'--repo',str(repo),'--output',str(output/'replay')],
                   capture_output=True,check=True,timeout=100)
    original=json.loads((HERE/'manifest.json').read_text());limits=json.loads((HERE/'limits-manifest.json').read_text())
    framework=repo/'G_Harness2'
    pin=subprocess.check_output(['git','-C',str(framework),'rev-parse','HEAD'],text=True).strip()
    assert pin==manifest['framework_commit']==original['framework_commit']
    subprocess.run(['git','-C',str(framework),'diff','--exit-code','HEAD','--','harness2'],capture_output=True,check=True)
    sys.path.insert(0,str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface=replace(OPENCODE_SURFACE,name='soc-journal-release-readonly',stubs=(),
                    always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),always_on_max=65536)
    mapping=dict(original['component_mapping'])
    mapping.update({'scripts/limits_test_bootstrap.py':'deployment/tests/test_soc_diagnostics.py',
                    'scripts/limits_test_cli.py':'infra/mcp/test_system_diagnostics.py',
                    'scripts/limits_test_factual_time.py':'infra/validation/factual-service/test_factual_service.py'})
    before={name:(output/'replay/candidate'/path).read_text()for name,path in mapping.items()}
    before['tool_descriptions/tool_guidance.md']=original['audit_index']
    after=dict(before)
    for name,path in manifest['component_mapping'].items():
        assert name not in after and path in manifest['source_sha256']
        after[name]=(HERE/path).read_text()
    result={'framework_commit':pin,'before':tree.validate(surface,before,allow_subagents=False),
            'candidate':tree.validate(surface,after,allow_subagents=False),'diff':tree.diff_summary(surface,before,after),
            'base_candidate_tree_sha256':limits['candidate_tree_sha256'],'operator_source_sha256':manifest['source_sha256'],
            'scope':'Operator-only source witness, temporary reader relay and pure cohort gate. No coordinator/service/deployment/MCP/chat validation.',
            'operating_changes':0,'model_calls':0}
    (output/'release-harness2.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
