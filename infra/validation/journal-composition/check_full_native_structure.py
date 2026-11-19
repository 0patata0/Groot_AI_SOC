"""Pinned official structural check for the owned full-native integration."""
import argparse
import contextlib
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo',type=Path,required=True)
parser.add_argument('--restored-root',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
output=args.output.resolve()
assert not output.exists() and output.parent.is_dir()
here=Path(__file__).resolve().parent
baseline=output.with_name(output.stem+'.backends.json')
previous=sys.argv
try:
    sys.argv=[str(here/'check_private_backends_structure.py'),'--repo',str(args.repo),
              '--restored-root',str(args.restored_root),'--output',str(baseline)]
    with contextlib.redirect_stdout(io.StringIO()):
        original=runpy.run_path(str(here/'check_private_backends_structure.py'))
finally:
    sys.argv=previous
tree=original['tree']
surface=replace(original['surface'],name='soc-owned-full-native-root')
before=original['after'];after=dict(before)
names=('validate_full_native.py','private_full_fixture.py','private_full_native_probe.py',
       'private_apply_crash.py','check_full_native_structure.py','test_full_native_observation.py')
for name in names:
    after['scripts/'+name]=(here/name).read_text()
result={'framework_commit':original['result']['framework_commit'],
        'before':tree.validate(surface,before,allow_subagents=False),
        'candidate':tree.validate(surface,after,allow_subagents=False),
        'diff':tree.diff_summary(surface,before,after),
        'source_sha256':{name:hashlib.sha256((here/name).read_bytes()).hexdigest()for name in names},
        'scope':'Official structure only; native execution, operating acceptance and deployment require separate evidence',
        'operating_changes':0,'model_calls':0}
assert not result['before'].get('errors') and not result['candidate'].get('errors')
assert result['diff']['added']==sorted('scripts/'+name for name in names)
assert not result['diff']['modified'] and result['diff']['always_on_char_delta']==0
output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({key:result[key]for key in ('framework_commit','before','candidate','diff')},ensure_ascii=False))
