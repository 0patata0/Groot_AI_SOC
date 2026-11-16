#!/usr/bin/env python3
"""Reconstruct and structurally inspect the frozen candidate, without network or deployment."""
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


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(root):
    files={}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink()
        if path.is_file():files[str(path.relative_to(root))]=sha(path.read_bytes())
        else:assert path.is_dir()
    return len(files),sha(json.dumps(files,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();out=args.output.resolve();here=Path(__file__).resolve().parent
    frozen=json.loads((here/'manifest.json').read_text())
    assert not out.exists() and out.parent.is_dir() and not out.is_relative_to(repo)
    assert sha((here/'candidate.patch').read_bytes())==frozen['patch_sha256']
    for name,digest in frozen['tests_sha256'].items():assert sha((here/name).read_bytes())==digest,name
    raw=subprocess.check_output(['git','-C',str(repo),'archive','--format=tar',frozen['base_commit']])
    out.mkdir(mode=0o700);base=out/'base';candidate=out/'candidate';base.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive.getmembers():
            path=Path(member.name)
            assert not path.is_absolute() and '..' not in path.parts
            assert member.isfile() or member.isdir()
        archive.extractall(base,filter='data')
    assert identity(base)==(frozen['tree_file_count'],frozen['base_tree_sha256'])
    shutil.copytree(base,candidate)
    subprocess.run(['git','apply','--check',str(here/'candidate.patch')],cwd=candidate,check=True)
    subprocess.run(['git','apply',str(here/'candidate.patch')],cwd=candidate,check=True)
    assert identity(candidate)==(frozen['tree_file_count'],frozen['candidate_tree_sha256'])
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
    surface=replace(OPENCODE_SURFACE,name='soc-application-error-filter',stubs=(),
        always_on=('systemprompt.md','tool_descriptions/tool_guidance.md'),always_on_max=65536)
    models={arm:{name:(root/path).read_text() for name,path in frozen['component_mapping'].items()}
        |{'tool_descriptions/tool_guidance.md':frozen['audit_index']} for arm,root in [('base',base),('candidate',candidate)]}
    report={'framework_commit':pin,'census':{arm:tree.validate(surface,model,allow_subagents=False)
        for arm,model in models.items()},'diff':tree.diff_summary(surface,models['base'],models['candidate']),
        'verified_source_files':frozen['tree_file_count'],'model_calls':0,'mcp_calls':0,'chat_posts':0,'operating_changes':0,
        'scope':'Source reconstruction and official structure only, not operating quality or deployment'}
    (out/'harness2.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
