#!/usr/bin/env python3
"""Official Harness2 inspection of the operator lifecycle candidate.

Read-only inputs: the pinned restored collection tree and this manifest's
files. No model, SSH, root action, deployment or quality-score inference.
"""
import argparse
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--restored-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();restored=args.restored_root.resolve();out=args.output.resolve()
    assert HERE==(repo/'infra/validation/journal-composition').resolve()
    assert restored.is_dir()and not restored.is_relative_to(repo)
    assert not out.exists()and out.parent.is_dir()and not out.is_relative_to(repo)
    manifest=json.loads((HERE/'coordinator-manifest.json').read_text())
    witness=json.loads((HERE/'witness-manifest.json').read_text())
    limits=json.loads((HERE/'limits-manifest.json').read_text())
    original=json.loads((HERE/'manifest.json').read_text())
    assert manifest['witness_manifest_sha256']==sha(HERE/'witness-manifest.json')
    for name,digest in {**witness['source_sha256'],**manifest['source_sha256']}.items():
        assert Path(name).name==name and sha(HERE/name)==digest,name
    spec=importlib.util.spec_from_file_location('coordinator_restored_tree',HERE/'reproduce.py')
    replay=importlib.util.module_from_spec(spec);spec.loader.exec_module(replay)
    assert replay.identity(restored)==(limits['candidate_tree_file_count'],limits['candidate_tree_sha256'])
    framework=repo/'G_Harness2'
    pin=subprocess.check_output(['git','-C',str(framework),'rev-parse','HEAD'],text=True).strip()
    assert pin==manifest['framework_commit']==witness['framework_commit']==original['framework_commit']
    subprocess.run(['git','-C',str(framework),'diff','--exit-code','HEAD','--','harness2'],capture_output=True,check=True)
    sys.path.insert(0,str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface=replace(OPENCODE_SURFACE,name='soc-operator-coordinator',stubs=(),
                    always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),always_on_max=65536)
    mapping=dict(original['component_mapping'])
    mapping.update({'scripts/limits_test_bootstrap.py':'deployment/tests/test_soc_diagnostics.py',
                    'scripts/limits_test_cli.py':'infra/mcp/test_system_diagnostics.py',
                    'scripts/limits_test_factual_time.py':'infra/validation/factual-service/test_factual_service.py'})
    before={name:(restored/path).read_text()for name,path in mapping.items()}
    before['tool_descriptions/tool_guidance.md']=original['audit_index']
    for name,path in witness['component_mapping'].items():
        assert name not in before;before[name]=(HERE/path).read_text()
    parent_commit=manifest['parent_commit']
    assert isinstance(parent_commit,str)and len(parent_commit)==40 and all(ch in '0123456789abcdef'for ch in parent_commit)
    relative='infra/validation/journal-composition/'
    parent_raw=subprocess.check_output(['git','-C',str(repo),'show',parent_commit+':'+relative+'coordinator-manifest.json'])
    assert hashlib.sha256(parent_raw).hexdigest()==manifest['parent_manifest_sha256']
    parent=json.loads(parent_raw)
    assert parent['framework_commit']==manifest['framework_commit']and parent['witness_manifest_sha256']==manifest['witness_manifest_sha256']
    for name,path in parent['component_mapping'].items():
        assert name not in before and Path(path).name==path and path in parent['source_sha256']
        raw=subprocess.check_output(['git','-C',str(repo),'show',parent_commit+':'+relative+path])
        assert hashlib.sha256(raw).hexdigest()==parent['source_sha256'][path]
        before[name]=raw.decode()
    after=dict(before)
    for name,path in manifest['component_mapping'].items():
        assert path in manifest['source_sha256'];after[name]=(HERE/path).read_text()
    result={'framework_commit':pin,'before':tree.validate(surface,before,allow_subagents=False),
        'candidate':tree.validate(surface,after,allow_subagents=False),'diff':tree.diff_summary(surface,before,after),
        'base_candidate_tree_sha256':limits['candidate_tree_sha256'],'source_sha256':manifest['source_sha256'],
        'scope':manifest['scope'],'known_unfinished':manifest['known_unfinished'],'operating_changes':0,'model_calls':0}
    assert not result['before'].get('errors')and not result['candidate'].get('errors')
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'framework_commit':pin,'before':result['before'],'candidate':result['candidate'],
                      'diff':result['diff'],'operating_changes':0,'model_calls':0},ensure_ascii=False))


if __name__=='__main__':main()
