#!/usr/bin/env python3
"""Reconstruct and audit the frozen read-attempt candidate without remote I/O.

The parent is an unapproved source comparison, never an operating release.
"""
import argparse
import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();out=args.output.resolve();here=Path(__file__).resolve().parent
    frozen=json.loads((here/'manifest.json').read_text())
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(repo)
    assert sha((here/'candidate.patch').read_bytes())==frozen['patch_sha256']
    assert sha((here/'test_attempts.py').read_bytes())==frozen['test_sha256']
    out.mkdir(mode=0o700);dependency=out/'parent-artifacts';dependency.mkdir()
    for name,digest in frozen['parent_artifacts'].items():
        rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts
        raw=subprocess.check_output(['git','-C',str(repo),'show',frozen['base_commit']+':'+name])
        assert sha(raw)==digest,name
        path=dependency/rel.name;assert not path.exists();path.write_bytes(raw)
    run=subprocess.run([sys.executable,'-B',str(dependency/'reproduce.py'),'--repo',str(repo),'--output',str(out/'parent')],capture_output=True,text=True,timeout=60)
    (out/'parent-reconstruction.stdout').write_text(run.stdout);(out/'parent-reconstruction.stderr').write_text(run.stderr)
    assert run.returncode==0,'parent reconstruction failed; inspect local output'
    base=out/'parent/candidate';candidate=out/'candidate'
    for name,item in frozen['sources'].items():assert sha((base/name).read_bytes())==item['before_sha256'],name
    for p in base.rglob('*'):assert not p.is_symlink()
    shutil.copytree(base,candidate)
    subprocess.run(['git','apply','--check',str(here/'candidate.patch')],cwd=candidate,check=True)
    subprocess.run(['git','apply',str(here/'candidate.patch')],cwd=candidate,check=True)
    for name,item in frozen['sources'].items():assert sha((candidate/name).read_bytes())==item['candidate_sha256'],name
    for item in frozen['ast_scope']['files']:
        defs=set(item['permitted_definitions']);metadata=set(item['permitted_metadata'])
        def rest(path):
            return [ast.dump(n) for n in ast.parse(path.read_text()).body
                if not (isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name in defs)
                and not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in metadata for t in n.targets))]
        assert rest(base/item['source'])==rest(candidate/item['source']),item['source']
    def nested(root):
        main=next(n for n in ast.parse((root/'infra/hermes/soc_management_run.py').read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='main')
        return {n.name:n for n in main.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
    before,after=nested(base),nested(candidate)
    for name in set(before)-{'gated_dispatch','guarded_result','complete_chat_lookup'}:assert ast.dump(before[name])==ast.dump(after[name]),name
    assert set(after)-set(before)=={'remember_read_attempt','read_attempt_snapshot'}
    assert ast.dump(before['gated_dispatch'].body[1])==ast.dump(after['gated_dispatch'].body[1])
    framework=repo/'G_Harness2';pin=subprocess.check_output(['git','-C',str(framework),'rev-parse','HEAD'],text=True).strip();assert pin==frozen['framework_commit']
    subprocess.run(['git','-C',str(framework),'diff','--exit-code','HEAD','--','harness2'],check=True,capture_output=True)
    sys.path.insert(0,str(framework));from harness2.core import tree;from harness2.substrate.opencode import OPENCODE_SURFACE
    surface=replace(OPENCODE_SURFACE,name='soc-read-attempts',stubs=(),always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),always_on_max=65536)
    index=('Audit index only: workflow_contract selects soc-query, soc-investigate, soc-change, soc-recover. '
           'output_contract loads soc-output. No authority or production prompt is replaced.\n')
    models={arm:{key:(root/name).read_text() for key,name in frozen['component_mapping'].items()}
        |{'tool_descriptions/tool_guidance.md':index} for arm,root in (('base',base),('candidate',candidate))}
    result={'framework_commit':pin,'census':{a:tree.validate(surface,v,allow_subagents=False) for a,v in models.items()},
        'diff':tree.diff_summary(surface,models['base'],models['candidate']),'sources_verified_per_arm':len(frozen['sources']),
        'root_authority_and_other_nested_functions_unchanged':True,'operating_changes':0,'model_calls':0,'mcp_calls':0,'chat_posts':0,
        'scope':'frozen source/structure/AST reconstruction; not semantic quality, a live deployment or Mattermost delivery'}
    (out/'harness2.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
