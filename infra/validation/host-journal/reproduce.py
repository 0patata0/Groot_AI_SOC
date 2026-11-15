#!/usr/bin/env python3
"""Reconstruct and structurally audit the unapplied fixed-host journal candidate.

No network, model, package install, operating journal or service call is made.
The local, pinned official G_Harness2 checkout is required.
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


def changed_top(before, after):
    def top(path):
        return {getattr(n,'name',None) or ('assign:'+','.join(t.id for t in n.targets if isinstance(t,ast.Name))
            if isinstance(n,ast.Assign) else ast.dump(n)):ast.dump(n) for n in ast.parse(path.read_text()).body}
    a,b=top(before),top(after)
    return sorted(k for k in set(a)|set(b) if a.get(k)!=b.get(k))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();out=args.output.resolve();here=Path(__file__).resolve().parent
    frozen=json.loads((here/'manifest.json').read_text())
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(repo)
    assert sha((here/'candidate.patch').read_bytes())==frozen['patch_sha256']
    assert sha((here/'test_host_journal.py').read_bytes())==frozen['test_sha256']
    out.mkdir(mode=0o700);dependency=out/'parent-artifacts';dependency.mkdir()
    for name,digest in frozen['parent_artifacts'].items():
        rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts
        raw=subprocess.check_output(['git','-C',str(repo),'show',frozen['base_commit']+':'+name])
        assert sha(raw)==digest,name
        path=dependency/rel.name;assert not path.exists();path.write_bytes(raw)
    run=subprocess.run([sys.executable,'-B',str(dependency/'reproduce.py'),'--repo',str(repo),
        '--output',str(out/'parent')],capture_output=True,text=True,timeout=90)
    (out/'parent.stdout').write_text(run.stdout);(out/'parent.stderr').write_text(run.stderr)
    assert run.returncode==0,'parent reconstruction failed; inspect local output'
    source=out/'parent/candidate';base=out/'base';candidate=out/'candidate'
    shutil.copytree(source,base)
    for name,digest in frozen['extra_dependencies'].items():
        rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts
        path=base/rel;assert not path.exists()
        raw=subprocess.check_output(['git','-C',str(repo),'show',frozen['base_commit']+':'+name])
        assert sha(raw)==digest,name
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    for name,item in frozen['sources'].items():assert sha((base/name).read_bytes())==item['before_sha256'],name
    for p in base.rglob('*'):assert not p.is_symlink()
    shutil.copytree(base,candidate)
    subprocess.run(['git','apply','--check',str(here/'candidate.patch')],cwd=candidate,check=True)
    subprocess.run(['git','apply',str(here/'candidate.patch')],cwd=candidate,check=True)
    for name,item in frozen['sources'].items():assert sha((candidate/name).read_bytes())==item['candidate_sha256'],name
    for name,expected in frozen['ast_changes'].items():assert changed_top(base/name,candidate/name)==expected,name
    framework=repo/'G_Harness2'
    pin=subprocess.check_output(['git','-C',str(framework),'rev-parse','HEAD'],text=True).strip()
    assert pin==frozen['framework_commit']
    subprocess.run(['git','-C',str(framework),'diff','--exit-code','HEAD','--','harness2'],check=True,capture_output=True)
    sys.path.insert(0,str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface=replace(OPENCODE_SURFACE,name='soc-host-journal',stubs=(),
        always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),always_on_max=65536)
    models={arm:{k:(root/v).read_text() for k,v in frozen['component_mapping'].items()}
        |{'tool_descriptions/tool_guidance.md':frozen['audit_index']}
        for arm,root in (('base',base),('candidate',candidate))}
    result={'framework_commit':pin,'census':{a:tree.validate(surface,v,allow_subagents=False) for a,v in models.items()},
        'diff':tree.diff_summary(surface,models['base'],models['candidate']),
        'sources_verified_per_arm':len(frozen['sources']),'ast_scope_verified':True,
        'operating_changes':0,'model_calls':0,'mcp_calls':0,'chat_posts':0,
        'scope':'frozen source/structure reconstruction only; 24h errors remain failed and this is not an operating release'}
    (out/'harness2.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
