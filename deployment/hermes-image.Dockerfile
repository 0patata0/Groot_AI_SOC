# Manual Linux/amd64 prerequisite build only; deploy.sh never invokes this file.
# BuildKit's built-in Dockerfile frontend is required. No frontend image directive,
# networked RUN, apt, dependency resolution, or base-image update is performed.
ARG HERMES_BASE=capstone-hermes-base:reviewed-20260924
FROM ${HERMES_BASE}
USER root
WORKDIR /opt/hermes
ENV PYTHONDONTWRITEBYTECODE=1 UV_OFFLINE=1 PIP_NO_INDEX=1 TZ=Asia/Seoul

# The small input directory is a read-only build mount, not an image layer.
RUN --network=none --mount=type=bind,source=input,target=/tmp/capstone-image-input,readonly /opt/hermes/.venv/bin/python -B - <<'PY'
import hashlib, importlib.util, os, pathlib, platform, shutil, stat, subprocess, sys

assert sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 13)
assert platform.machine() == 'x86_64' and platform.libc_ver()[0] == 'glibc'
assert shutil.which('uv') and shutil.which('ssh'), 'base_image_tools_missing'
root = pathlib.Path('/opt/hermes')
inputs = pathlib.Path('/tmp/capstone-image-input')
pins = {
    'korean_output_guard.py': '860c0c15f5f328e7e70e0f8332663d7a0867a87f5d10012e22777b7d18761a35',
    'patch_korean_output_guard.py': 'd6e1ea2e594ae958a33005127a618d52907e93408b786a437e163214dfaec17b',
    'korean-output-guard-requirements.txt': '2a7835754a18465d6b7d9b891b239e48254c29fe8d703ff4bdafb99cf39115e2',
    'test_korean_output_guard.py': 'ca88119663ea306e9d5a93ce4911d554ccd07389665b6c03c55d16d7386cd2ed',
    'test_korean_output_guard_engine.py': 'a847a34c05b094552c38d8d56bc9f15d3ab76c98dd6af92de199fe4c0d2b3ddc',
    'verify_korean_output_guard_runtime.py': '7af8e0bb63cd9a4545d1d906c328a6ba43a1a71788efb652d42a8717d512fac9',
    'regex-2026.9.29-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl': 'd49c18f1ea294cf4adde2e5ac256e98c82ea9d708462ce4bf799dffa7cfe8a2c',
}
assert {p.name for p in inputs.iterdir()} == set(pins), 'exact_seven_inputs_required'
for name, expected in pins.items():
    p = inputs / name
    assert stat.S_ISREG(p.lstat().st_mode) and not p.is_symlink()
    assert hashlib.sha256(p.read_bytes()).hexdigest() == expected, 'input_SHA_mismatch'

spec = importlib.util.spec_from_file_location('capstone_image_patcher', inputs/'patch_korean_output_guard.py')
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)
sources = {}
for name in patcher.UPSTREAM_SHA256:
    p = root/name
    assert stat.S_ISREG(p.lstat().st_mode), 'integration_source_not_regular'
    sources[name] = p.read_text(encoding='utf-8')
# Unknown release/partial patches are rejected before any source replacement.
patched = patcher.patch_sources(sources)
target = pathlib.Path('/opt/capstone-guard-runtime/regex-2026.9.29/lib/python3.13/site-packages')
assert not target.exists(), 'base_already_contains_guard_runtime'
target.mkdir(parents=True, mode=0o755)
subprocess.run([
    shutil.which('uv'), '--no-config', 'pip', 'install', '--python', sys.executable,
    '--target', str(target), '--no-deps', '--no-index', '--find-links', str(inputs),
    '--only-binary=:all:', '--require-hashes', '--no-cache', '--link-mode=copy',
    '-r', str(inputs/'korean-output-guard-requirements.txt')], check=True)
for name, body in patched.items():
    p = root/name
    p.write_text(body, encoding='utf-8', newline='')
    os.chown(p, 0, 0); p.chmod(0o644)
    assert hashlib.sha256(p.read_bytes()).hexdigest() == patcher.PATCHED_SHA256[name]
guard = root/'capstone_korean_output_guard.py'
assert not guard.exists(), 'base_already_contains_guard_module'
guard.write_bytes((inputs/'korean_output_guard.py').read_bytes())
os.chown(guard, 0, 0); guard.chmod(0o644)
for p in pathlib.Path('/opt/capstone-guard-runtime').rglob('*'):
    assert not p.is_symlink(), 'runtime_package_symlink'
    os.chown(p, 0, 0); p.chmod(0o755 if p.is_dir() else 0o644)
for directory in [pathlib.Path('/opt/capstone-guard-runtime'), *target.parents]:
    if str(directory).startswith('/opt/capstone-guard-runtime'):
        os.chown(directory, 0, 0); directory.chmod(0o755)
print('capstone_image_patch_and_offline_regex_installed')
PY

# A non-root numeric user tests the installed image without the gateway entrypoint,
# host data, network, model request or real Mattermost transport. The deployment
# uses its newly allocated host UID/GID, not a hard-coded production UID 995.
USER 995:995
RUN --network=none --mount=type=bind,source=input,target=/tmp/capstone-image-input,readonly <<'SH'
set -eu
task_test_root=/tmp/capstone-image-test
export HERMES_HOME=$task_test_root
export PYTHONPATH=/opt/hermes PYTHONDONTWRITEBYTECODE=1
mkdir -p "$task_test_root"
/opt/hermes/.venv/bin/python -B - <<'PY'
import importlib, os, pathlib, stat, sys
assert os.geteuid() == 995
import capstone_korean_output_guard as guard
assert guard.detector_metadata()['origin'] == 'isolated_runtime'
assert guard.detector_metadata()['version'] == '2026.9.29'
for name in ['capstone_korean_output_guard.py', 'plugins/platforms/mattermost/adapter.py', 'gateway/run_turn.py']:
    p = pathlib.Path('/opt/hermes')/name
    assert p.stat().st_uid == 0 and stat.S_IMODE(p.stat().st_mode) == 0o644 and not os.access(p, os.W_OK)
    for directory in p.parents:
        assert directory.stat().st_uid == 0 and not os.access(directory, os.W_OK)
importlib.import_module('plugins.platforms.mattermost.adapter')
importlib.import_module('gateway.run_turn')
from hermes_cli.tools_config import _get_platform_tools
names = ['mcp-wazuh-ro', 'mcp-security-events']
config = {'platform_toolsets': {'mattermost': names}, 'mcp_servers': {k: {'command': 'ssh'} for k in ['wazuh-ro', 'security-events']}}
assert set(_get_platform_tools(config, 'mattermost')) == set(names), 'platform_tool_allowlist_incompatible'
print('capstone_nonroot_guard_and_platform_imports_passed')
PY
/opt/hermes/.venv/bin/python -B -m unittest discover -s /tmp/capstone-image-input -p 'test_korean_output_guard*.py' -v
/opt/hermes/.venv/bin/python -B /tmp/capstone-image-input/verify_korean_output_guard_runtime.py
rm -rf -- /tmp/capstone-image-test
SH

# Preserve the reviewed base entrypoint's UID/GID handoff. Do not start the
# gateway as UID 995 directly: the SIEM role supplies HERMES_UID/HERMES_GID.
USER root
WORKDIR /opt/hermes
CMD ["gateway", "run"]
