#!/usr/bin/env python3
"""Root-operated cold candidate/wheel test in disposable directories only.

Does not create/start/stop containers, run Hermes, or contact model/MCP/chat APIs.
Use on the approved B host with its existing running Hermes and native uv.
"""
from __future__ import annotations

import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

DOCKER = '/usr/local/bin/docker'
CID = '6c2ed13aea89404463061ea2032084bdd159ae784aff4e7bd9eea7406ba9b30b'
IMAGE = 'sha256:2fd023efbb8d3d2b0ce1a73d028b07370cff34f567cfe0e999553e8c327ea283'
BACKUP = Path('/var/backups/hermes-korean-guard-cooj_d_2/original')
SOURCE = Path('/opt/capstone-automation/hermes-guard/project/infra/hermes')
WHEEL_NAME = 'regex-2026.9.29-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl'
WHEEL = Path('/opt/capstone-automation/artifacts') / WHEEL_NAME
WHEEL_SHA = 'd49c18f1ea294cf4adde2e5ac256e98c82ea9d708462ce4bf799dffa7cfe8a2c'
ORIGINAL = {
    'plugins/platforms/mattermost/adapter.py': '4f05be68777068d7b454187c7323f2c471aac6412b830f11761b4013eed702c8',
    'gateway/run_turn.py': '5bdee5c82c00e02f664516f9da0af99674e23493ec2a30eff06cb03afc6718a0',
}
PATCHED = {
    'plugins/platforms/mattermost/adapter.py': '1bbe71e24cf7fd212f38b13cb421bb5b05c841ea4d70a061d6dcb57253e6c47b',
    'gateway/run_turn.py': 'd4dae0f3194f7b7d435aac2eb37d4697822612cd6955911d86bb61400ad2871a',
}
CORE_SHA = 'a6b977d2c670ded98f61639a480702ed06d4a866b705e7d10705a056b974895c'
PATCHER_SHA = 'd6e1ea2e594ae958a33005127a618d52907e93408b786a437e163214dfaec17b'


def require(value, code):
    if not value:
        raise ValueError(code)


def command(args, *, stdin=None, timeout=90):
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'subprocess_failed')
    require(len(result.stdout) <= 1024 * 1024, 'unexpected_output_size')
    return result.stdout.strip()


def checked_hash(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
            'unsafe_root_artifact')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity():
    info = json.loads(command([DOCKER, 'inspect', 'hermes']))[0]
    require(info['Id'] == CID and info['Image'] == IMAGE, 'container_identity_changed')
    require(info['State']['Running'] and not info['State']['OOMKilled'], 'container_not_healthy')
    return {'id': info['Id'], 'image': info['Image'], 'started_at': info['State']['StartedAt']}


def operational_snapshot():
    code = r'''
import hashlib,json,os
from pathlib import Path
files=['/opt/hermes/capstone_korean_output_guard.py',
'/opt/hermes/plugins/platforms/mattermost/adapter.py','/opt/hermes/gateway/run_turn.py',
'/opt/data/config.yaml','/opt/data/.env','/opt/data/SOUL.md']
data={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in files}
base=Path('/opt/capstone-guard-runtime/regex-2026.9.29')
rows=[]
for p in sorted(base.rglob('*')):
 if p.is_file():rows.append([str(p.relative_to(base)),hashlib.sha256(p.read_bytes()).hexdigest()])
data['operational_regex_tree']=hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
print(json.dumps(data,sort_keys=True))
'''
    return json.loads(command([DOCKER, 'exec', CID, '/opt/hermes/.venv/bin/python', '-I', '-B', '-c', code]))


def run():
    require(os.geteuid() == 0, 'root_operator_required')
    require(Path('/etc/machine-id').read_text().strip(), 'machine_id_missing')
    before_identity, before = identity(), operational_snapshot()
    require(checked_hash(WHEEL) == WHEEL_SHA, 'wheel_hash_mismatch')
    require(checked_hash(SOURCE / 'korean_output_guard.py') == CORE_SHA, 'core_hash_mismatch')
    require(checked_hash(SOURCE / 'patch_korean_output_guard.py') == PATCHER_SHA, 'patcher_hash_mismatch')
    for relative, expected in ORIGINAL.items():
        require(checked_hash(BACKUP / relative) == expected, 'original_hash_mismatch')
    container_stage = None
    report = {}
    try:
        with tempfile.TemporaryDirectory(prefix='hermes-guard-cold-', dir='/var/tmp') as temp:
            host_stage = Path(temp)
            (host_stage / 'candidate').mkdir(mode=0o700)
            for relative in ORIGINAL:
                target = host_stage / 'original' / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(BACKUP / relative, target)
            command(['/usr/bin/python3', '-B', str(SOURCE / 'patch_korean_output_guard.py'),
                     '--source-root', str(host_stage / 'original'),
                     '--output-root', str(host_stage / 'candidate')])
            candidates = {}
            for relative, expected in PATCHED.items():
                path = host_stage / 'candidate' / relative
                candidates[relative] = checked_hash(path)
                require(candidates[relative] == expected, 'candidate_hash_mismatch')
                compile(path.read_text(), relative, 'exec')
            pattern = None
            for node in ast.parse((SOURCE / 'korean_output_guard.py').read_text()).body:
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and
                        t.id == '_FOREIGN_SCRIPT' for t in node.targets):
                    pattern = ast.literal_eval(node.value)
            require(isinstance(pattern, str) and len(pattern) < 1024, 'engine_pattern_missing')
            container_stage = command([DOCKER, 'exec', CID, 'mktemp', '-d',
                                       '/tmp/capstone-guard-cold.XXXXXXXX'])
            require(re.fullmatch(r'/tmp/capstone-guard-cold[.][A-Za-z0-9]{8}', container_stage),
                    'unsafe_container_temporary_path')
            command([DOCKER, 'exec', CID, 'chmod', '0755', container_stage])
            command([DOCKER, 'exec', CID, 'mkdir', container_stage + '/tmp'])
            command([DOCKER, 'cp', str(WHEEL), CID + ':' + container_stage + '/' + WHEEL_NAME])
            requirements = host_stage / 'requirements.txt'
            requirements.write_text('regex==2026.9.29 --hash=sha256:' + WHEEL_SHA + '\n')
            command([DOCKER, 'cp', str(requirements), CID + ':' + container_stage + '/requirements.txt'])
            verify_wheel = 'import hashlib,sys; assert hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()==sys.argv[2]'
            command([DOCKER, 'exec', CID, '/opt/hermes/.venv/bin/python', '-I', '-B', '-c',
                     verify_wheel, container_stage + '/' + WHEEL_NAME, WHEEL_SHA])
            target = container_stage + '/runtime'
            command([DOCKER, 'exec', '-e', 'HOME=' + container_stage, '-e', 'TMPDIR=' + container_stage + '/tmp',
                     '-e', 'UV_CACHE_DIR=' + container_stage + '/unused-cache', '-e', 'UV_NO_CACHE=1',
                     '-e', 'PYTHONDONTWRITEBYTECODE=1', CID, '/usr/local/bin/uv', '--no-config', '--offline',
                     'pip', 'install', '--python', '/opt/hermes/.venv/bin/python', '--target', target,
                     '--no-deps', '--no-index', '--find-links', container_stage, '--only-binary=:all:',
                     '--require-hashes', '--no-cache', '--link-mode=copy', '-r',
                     container_stage + '/requirements.txt'], timeout=180)
            command([DOCKER, 'exec', CID, 'test', '!', '-e', container_stage + '/unused-cache'])
            engine_test = r'''
import importlib.machinery,json,os,platform,sys
from pathlib import Path
assert os.geteuid()==995 and sys.version_info[:2]==(3,13) and platform.machine()=='x86_64'
root=Path(sys.argv[1]).resolve();sys.path.insert(0,str(root))
import regex,regex._regex
assert regex.__version__=='2026.9.29'
backend=Path(regex._regex.__file__).resolve()
assert backend.is_relative_to(root)
assert any(str(backend).endswith(s) for s in importlib.machinery.EXTENSION_SUFFIXES)
pattern=regex.compile(sys.argv[2],regex.VERSION1)
positive=['\u65e5','\u3042','\u30a2','\uff71','\U00033400','\u3099','\uff9e','\u30fc']
negative=['정상 한국어 가 ㄱ','API 211.170.162.111:11434 pending','。、「」・','✅ 🐱 😀','\U0002ffff']
assert all(pattern.search(x) for x in positive)
assert not any(pattern.search(x) for x in negative)
print(json.dumps({'uid':os.geteuid(),'package':'regex','version':regex.__version__,
'backend':'regex._regex','origin':'disposable_cold_target','positive_passed':len(positive),
'negative_passed':len(negative),'production_guard_imported':False},sort_keys=True))
'''
            engine = json.loads(command([DOCKER, 'exec', '-u', '995:986', '-e', 'HOME=' + container_stage,
                                        '-e', 'HERMES_HOME=' + container_stage, CID,
                                        '/opt/hermes/.venv/bin/python', '-I', '-B', '-c', engine_test,
                                        target, pattern]))
            report = {'accepted_original': ORIGINAL, 'generated_candidates': candidates,
                      'wheel_sha256': WHEEL_SHA, 'wheel_bytes': WHEEL.stat().st_size,
                      'native_engine': engine, 'offline': True, 'no_persistent_cache': True,
                      'test_target_was_separate': True, 'core_sha256': CORE_SHA,
                      'patcher_sha256': checked_hash(SOURCE / 'patch_korean_output_guard.py')}
    finally:
        if container_stage and re.fullmatch(r'/tmp/capstone-guard-cold[.][A-Za-z0-9]{8}', container_stage):
            command([DOCKER, 'exec', CID, 'rm', '-rf', '--', container_stage])
            command([DOCKER, 'exec', CID, 'test', '!', '-e', container_stage])
        # A failed fixture must never be repaired by writing the operating paths.
        require(identity() == before_identity, 'operational_identity_changed')
        require(operational_snapshot() == before, 'operational_snapshot_changed')
    report.update(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  container=before_identity, operational_bytes_unchanged=True,
                  temporary_files_removed=True, real_container_recreated=False,
                  runtime_gateway_imported=False, model_mcp_chat_calls=0)
    return report


if __name__ == '__main__':
    try:
        print(json.dumps(run(), sort_keys=True))
    except Exception as exc:
        # Fixed classification only: native stderr and config are never printed.
        safe = str(exc) if type(exc) is ValueError and re.fullmatch('[a-z_]+', str(exc)) else type(exc).__name__
        print(json.dumps({'error': 'cold_fixture_failed', 'kind': safe}), file=__import__('sys').stderr)
        raise SystemExit(1)
