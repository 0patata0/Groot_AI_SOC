#!/usr/bin/env python3
"""Restore frozen source, comparison inputs and official structure; no live calls."""
import argparse
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile


def sha(raw):return hashlib.sha256(raw).hexdigest()


def identity(root):
    files={}
    for p in sorted(root.rglob('*')):
        assert not p.is_symlink()
        if p.is_file():files[str(p.relative_to(root))]=sha(p.read_bytes())
        else:assert p.is_dir()
    return len(files),sha(json.dumps(files,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();out=args.output.resolve();here=Path(__file__).resolve().parent
    frozen=json.loads((here/'manifest.json').read_text())
    assert out.is_absolute() and not out.exists() and out.parent.is_dir() and not out.is_relative_to(repo)
    for name,key in [('candidate.patch','patch_sha256'),('comparison.patch','comparison_patch_sha256')]:
        assert sha((here/name).read_bytes())==frozen[key]
    for name,digest in frozen['tests_sha256'].items():assert sha((here/name).read_bytes())==digest,name
    raw=subprocess.check_output(['git','-C',str(repo),'archive','--format=tar',frozen['base_commit']])
    out.mkdir(mode=0o700);base=out/'base';base.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive.getmembers():
            rel=Path(member.name)
            assert not rel.is_absolute() and '..' not in rel.parts and (member.isfile() or member.isdir())
        archive.extractall(base,filter='data')
    assert identity(base)==(frozen['base_tree_file_count'],frozen['base_tree_sha256'])
    candidate=out/'candidate';shutil.copytree(base,candidate)
    subprocess.run(['git','apply','--check',str(here/'candidate.patch')],cwd=candidate,check=True)
    subprocess.run(['git','apply',str(here/'candidate.patch')],cwd=candidate,check=True)
    assert identity(candidate)==(frozen['candidate_tree_file_count'],frozen['candidate_tree_sha256'])
    for name,info in frozen['sources'].items():
        if info['before_sha256'] is None:assert not (base/name).exists()
        else:assert sha((base/name).read_bytes())==info['before_sha256'],name
        assert sha((candidate/name).read_bytes())==info['candidate_sha256'],name
    comparison=out/'comparison-base';comparison.mkdir()
    for name,info in frozen['comparison_sources'].items():
        assert sha((base/name).read_bytes())==info['before_sha256'],name
        p=comparison/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(base/name,p)
    subprocess.run(['git','apply','--check',str(here/'comparison.patch')],cwd=comparison,check=True)
    subprocess.run(['git','apply',str(here/'comparison.patch')],cwd=comparison,check=True)
    for name,info in frozen['comparison_sources'].items():
        assert sha((comparison/name).read_bytes())==info['comparison_sha256'],name
    framework=repo/'G_Harness2'
    pin=subprocess.check_output(['git','-C',str(framework),'rev-parse','HEAD'],text=True).strip()
    assert pin==frozen['framework_commit']
    subprocess.run(['git','-C',str(framework),'diff','--exit-code','HEAD','--','harness2'],capture_output=True,check=True)
    sys.path.insert(0,str(framework))
    from harness2.core import tree
    from harness2.substrate.opencode import OPENCODE_SURFACE
    surface=replace(OPENCODE_SURFACE,name='soc-journal-composition',stubs=(),
        always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),always_on_max=65536)
    models={arm:{name:(root/path).read_text()for name,path in frozen['component_mapping'].items()}
        |{'tool_descriptions/tool_guidance.md':frozen['audit_index']}
        for arm,root in [('base',base),('candidate',candidate)]}
    report={'framework_commit':pin,'census':{arm:tree.validate(surface,model,allow_subagents=False)
        for arm,model in models.items()},'diff':tree.diff_summary(surface,models['base'],models['candidate']),
        'base_files':frozen['base_tree_file_count'],'candidate_files':frozen['candidate_tree_file_count'],
        'comparison_files':len(frozen['comparison_sources']),'model_calls':0,'operating_changes':0,
        'scope':'Frozen source and official structure only; not operating accuracy or deployment'}
    (out/'harness2.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
