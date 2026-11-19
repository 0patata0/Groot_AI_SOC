"""Extend the pinned official PID-1 structure check with backend test sources."""
import argparse
import contextlib
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import runpy
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, required=True)
parser.add_argument('--restored-root', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
output = args.output.resolve()
assert not output.exists() and output.parent.is_dir()
baseline = output.with_name(output.stem + '.foundation.json')
assert not baseline.exists()
here = Path(__file__).resolve().parent
argv = sys.argv
try:
    sys.argv = [str(here / 'check_private_pid1_structure.py'), '--repo', str(args.repo),
                '--restored-root', str(args.restored_root), '--output', str(baseline)]
    with contextlib.redirect_stdout(io.StringIO()):
        original = runpy.run_path(str(here / 'check_private_pid1_structure.py'))
finally:
    sys.argv = argv
tree = original['tree']
surface = replace(original['surface'], name='soc-private-native-backends')
before = original['after']
after = dict(before)
names = ('validate_private_backends.py', 'private_backend_probe.py', 'check_private_backends_structure.py')
for name in names:
    after['scripts/' + name] = (here / name).read_text()
result = {
    'framework_commit': original['pin'],
    'before': tree.validate(surface, before, allow_subagents=False),
    'candidate': tree.validate(surface, after, allow_subagents=False),
    'diff': tree.diff_summary(surface, before, after),
    'source_sha256': {name: hashlib.sha256((here / name).read_bytes()).hexdigest() for name in names},
    'original_operator_pins_verified': len(original['pins']),
    'scope': 'Official structural check only; not native execution, root Lifecycle, operating deployment, SOC accuracy or bot acceptance.',
    'operating_changes': 0, 'model_calls': 0,
}
assert not result['before'].get('errors') and not result['candidate'].get('errors')
assert result['diff']['added'] == sorted('scripts/' + name for name in names)
assert not result['diff']['modified'] and result['diff']['always_on_char_delta'] == 0
output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps({key: result[key] for key in ('framework_commit', 'before', 'candidate', 'diff')}, ensure_ascii=False))
