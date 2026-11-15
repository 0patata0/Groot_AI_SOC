#!/usr/bin/env python3
"""Reconstruct the frozen diagnostic candidate without network or deployment."""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def tree_identity(root):
    files={}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink()
        if path.is_file():
            files[str(path.relative_to(root))]=sha(path.read_bytes())
        else:
            assert path.is_dir()
    raw=json.dumps(files,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    return len(files),sha(raw)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    repo=args.repo.resolve();out=args.output.resolve();here=Path(__file__).resolve().parent
    frozen=json.loads((here/'manifest.json').read_text())
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(repo)
    assert sha((here/'candidate.patch').read_bytes())==frozen['patch_sha256']
    for name,digest in frozen['test_sha256'].items():
        assert sha((here/name).read_bytes())==digest,name
    out.mkdir(mode=0o700);artifacts=out/'parent-artifacts';artifacts.mkdir()
    for name,digest in frozen['parent_artifacts'].items():
        rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts
        raw=subprocess.check_output(['git','-C',str(repo),'show',frozen['base_commit']+':'+name])
        assert sha(raw)==digest,name
        target=artifacts/rel.name;assert not target.exists();target.write_bytes(raw)
    result=subprocess.run([sys.executable,'-B',str(artifacts/'reproduce.py'),'--repo',str(repo),
        '--output',str(out/'parent')],capture_output=True,text=True,timeout=120)
    (out/'parent.stdout').write_text(result.stdout);(out/'parent.stderr').write_text(result.stderr)
    assert result.returncode==0,'inspect parent reconstruction logs'
    base=out/'base';candidate=out/'candidate'
    shutil.copytree(out/'parent/candidate',base)
    assert tree_identity(base)==(frozen['tree_file_count'],frozen['base_tree_sha256'])
    shutil.copytree(base,candidate)
    subprocess.run(['git','apply','--check',str(here/'candidate.patch')],cwd=candidate,check=True)
    subprocess.run(['git','apply',str(here/'candidate.patch')],cwd=candidate,check=True)
    assert tree_identity(candidate)==(frozen['tree_file_count'],frozen['candidate_tree_sha256'])
    for name,item in frozen['sources'].items():
        assert sha((base/name).read_bytes())==item['before_sha256'],name
        assert sha((candidate/name).read_bytes())==item['candidate_sha256'],name
    framework=repo/'G_Harness2'
    pin=subprocess.check_output(['git','-C',str(framework),'rev-parse','HEAD'],text=True).strip()
    assert pin==frozen['framework_commit']
    subprocess.run(['git','-C',str(framework),'diff','--exit-code','HEAD','--','harness2'],check=True,capture_output=True)
    sys.path.insert(0,str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface=replace(OPENCODE_SURFACE,name='soc-read-boundaries',stubs=(),
        always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),always_on_max=65536)
    models={arm:{key:(root/value).read_text() for key,value in frozen['component_mapping'].items()}
        |{'tool_descriptions/tool_guidance.md':frozen['audit_index']}
        for arm,root in [('base',base),('candidate',candidate)]}
    report={'framework_commit':pin,'census':{arm:tree.validate(surface,value,allow_subagents=False)
        for arm,value in models.items()},'diff':tree.diff_summary(surface,models['base'],models['candidate']),
        'source_tree_count':frozen['tree_file_count'],'source_trees_verified':True,
        'operating_changes':0,'model_calls':0,'mcp_calls':0,'chat_posts':0,
        'scope':'source reconstruction and official structure only; not live quality or deployment'}
    (out/'harness2.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':
    main()
