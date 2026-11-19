"""Official, pinned Harness2 tree comparison including the new native verifier."""
import argparse
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, required=True)
parser.add_argument('--restored-root', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
REPO = args.repo.resolve()
HERE = Path(__file__).resolve().parent
RESTORED = args.restored_root.resolve()
OUTPUT = args.output.resolve()
assert HERE == REPO / 'infra/validation/journal-composition'
assert RESTORED.is_dir() and not RESTORED.is_relative_to(REPO)
assert not OUTPUT.exists() and OUTPUT.parent.is_dir() and not OUTPUT.is_relative_to(REPO)
manifest = json.loads((HERE / 'coordinator-manifest.json').read_text())
witness = json.loads((HERE / 'witness-manifest.json').read_text())
limits = json.loads((HERE / 'limits-manifest.json').read_text())
original = json.loads((HERE / 'manifest.json').read_text())
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
pins = {**witness['source_sha256'], **manifest['dependencies_sha256'], **manifest['source_sha256']}
assert len(pins) == 42 and all(digest(HERE / name) == value for name, value in pins.items())
spec = importlib.util.spec_from_file_location('private_pid1_replay', HERE / 'reproduce.py')
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)
assert replay.identity(RESTORED) == (limits['candidate_tree_file_count'], limits['candidate_tree_sha256'])
framework = REPO / 'G_Harness2'
pin = subprocess.check_output(['git', '-C', str(framework), 'rev-parse', 'HEAD'], text=True).strip()
assert pin == manifest['framework_commit'] == '6868817518876de8fd170c6a8354daca273b6191'
subprocess.run(['git', '-C', str(framework), 'diff', '--exit-code', 'HEAD', '--', 'harness2'], check=True, capture_output=True)
sys.path.insert(0, str(framework))
from harness2.core import tree
from harness2.substrate.opencode import OPENCODE_SURFACE

surface = replace(OPENCODE_SURFACE, name='soc-private-pid1-native-verifier', stubs=(),
                  always_on=('systemprompt.md', 'tool_descriptions/tool_guidance.md'), always_on_max=65536)
mapping = dict(original['component_mapping'])
mapping.update({'scripts/limits_test_bootstrap.py': 'deployment/tests/test_soc_diagnostics.py',
                'scripts/limits_test_cli.py': 'infra/mcp/test_system_diagnostics.py',
                'scripts/limits_test_factual_time.py': 'infra/validation/factual-service/test_factual_service.py'})
before = {name: (RESTORED / path).read_text() for name, path in mapping.items()}
before['tool_descriptions/tool_guidance.md'] = original['audit_index']
for name, path in {**witness['component_mapping'], **manifest['component_mapping']}.items():
    assert name not in before
    before[name] = (HERE / path).read_text()
after = dict(before)
for name in ('validate_private_pid1.py', 'check_private_pid1_structure.py'):
    after['scripts/' + name] = (HERE / name).read_text()
result = {'framework_commit': pin, 'before': tree.validate(surface, before, allow_subagents=False),
          'candidate': tree.validate(surface, after, allow_subagents=False),
          'diff': tree.diff_summary(surface, before, after),
          'source_sha256': {name: digest(HERE / name) for name in ('validate_private_pid1.py', 'check_private_pid1_structure.py')}, 'original_pins_verified': len(pins),
          'scope': 'Official structure only. Not operating deployment, root Lifecycle, SSH/Docker, SOC accuracy or bot acceptance.',
          'operating_changes': 0, 'model_calls': 0}
assert not result['before'].get('errors') and not result['candidate'].get('errors')
assert result['diff']['added'] == ['scripts/check_private_pid1_structure.py', 'scripts/validate_private_pid1.py'] and not result['diff']['modified']
assert result['diff']['always_on_char_delta'] == 0
OUTPUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(result, ensure_ascii=False))
