#!/usr/bin/env python3
"""Operator-only private native fixture. No live config write/restart/apply API.

Reads the fixed running WAF's public startup scripts and three configuration
inputs. Runs envsubst with private input/output paths, then the exact copy
script with only its two fixed path prefixes changed to private paths. Raw
configuration backups stay in the root-only A evidence directory.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

MID = '096e90b6243e438aa8a7b392be754732'
CID = '02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e'
PID = 647700
TARGET_SHA = '814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb'
OLD_SHA = '1063145a6a20922d17b7c75afee4938883d6d57f2b7584b33a085cf8291c3198'
ROOT_STAGE = Path('/var/tmp/capstone-resume-20261014/step3')
TEMPLATE = '/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template'
INTERMEDIATE = '/etc/nginx/modsecurity.d/modsecurity-override.conf'
TARGET = '/etc/modsecurity.d/modsecurity-override.conf'
SCRIPT20 = '/docker-entrypoint.d/20-envsubst-on-templates.sh'
SCRIPT90 = '/docker-entrypoint.d/90-copy-modsecurity-config.sh'
COPY_NAMES = ('modsecurity-override.conf', 'modsecurity.conf', 'setup.conf')
EXPECTED = {
    TEMPLATE: (OLD_SHA, 0, 0, 0o644),
    INTERMEDIATE: (OLD_SHA, 101, 101, 0o644),
    TARGET: (TARGET_SHA, 101, 101, 0o644),
    SCRIPT20: ('37eb458e54b5c3defd6cb62d15456ba961f5e322c6c50662b81f366a743614e9', 0, 0, 0o755),
    SCRIPT90: ('747bb477cf56d649c55f13db4d197066d68ca9ee37a1e7f7cdc452766ee3a2db', 0, 0, 0o755),
    '/etc/nginx/modsecurity.d/modsecurity.conf': ('a0dc08ae01c58b68e54a881a039359dc09008e50c101a2c4d4b01823b5a5e178', 101, 101, 0o644),
    '/etc/nginx/modsecurity.d/setup.conf': ('c84da809210e3be340262c741c8f0eb158da2d806c110087ba0814a0223f5870', 101, 101, 0o644),
    '/etc/nginx/conf.d/zz-capstone-evidence.conf': ('1e4c37a9bcedd730e693029fa4b40a6fd5e68a93b206ea161f458e11d7e6e212', 0, 0, 0o644),
}


class Refusal(Exception):
    pass


def require(value, code):
    if not value:
        raise Refusal(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def durable_new(path, data, mode=0o400, uid=0, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(path.parent)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_regular(root, relative):
    require(relative.startswith('/') and '..' not in relative.split('/'), 'invalid_fixed_path')
    parts = relative.strip('/').split('/')
    parent = root
    for part in parts[:-1]:
        parent = parent / part
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'source_parent_symlink_or_type')
    path = parent / parts[-1]
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 262144, 'source_file_metadata')
        data = os.read(fd, 262145)
        after = os.fstat(fd)
        def stable(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_uid, info.st_gid,
                    info.st_mode, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
        # Reading may update atime. It does not authorize any content/identity,
        # ownership, permissions, mtime or ctime change.
        require(stable(before) == stable(after) and len(data) == before.st_size and
                stable(path.lstat()) == stable(after), 'source_changed')
    finally:
        os.close(fd)
    return data, {'path': relative, 'sha256': sha(data), 'bytes': len(data), 'uid': before.st_uid,
                  'gid': before.st_gid, 'mode': stat.S_IMODE(before.st_mode), 'nlink': before.st_nlink,
                  'device': before.st_dev, 'inode': before.st_ino}


def snapshot(root):
    rows = {}
    content = {}
    for path, expected in EXPECTED.items():
        data, row = read_regular(root, path)
        require((row['sha256'], row['uid'], row['gid'], row['mode']) == expected, 'fixed_source_pin_conflict')
        content[path] = data
        rows[path] = row
    require(not re.search(rb'\$[A-Za-z_{]', content[TARGET]), 'target_has_template_variables')
    require(content[TARGET].count(b'Include /var/log/modsecurity/capstone-managed/audit-path.conf\n') == 1,
            'target_managed_include_missing')
    return content, rows


def docker_identity():
    template = '{"id":{{json .Id}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"started_at":{{json .State.StartedAt}},"image":{{json .Image}}}'
    value = subprocess.run(['/usr/local/bin/docker', 'inspect', '--format', template, CID],
                           capture_output=True, timeout=8, check=True)
    require(len(value.stdout) <= 4096, 'container_metadata_limit')
    result = json.loads(value.stdout)
    require(result['id'] == CID and result['pid'] == PID and result['running'] is True, 'container_identity_conflict')
    proc = Path('/proc') / str(PID)
    result['start_ticks'] = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()[19]
    result['mount_ns'] = os.readlink(proc / 'ns/mnt')
    result['pid_ns'] = os.readlink(proc / 'ns/pid')
    return result


def rendered_copy_script(data, temporary):
    require(re.fullmatch(r'/tmp/capstone-waf-coldstart-[0-9a-f]{32}', temporary), 'invalid_private_copy_path')
    require(sha(data) == EXPECTED[SCRIPT90][0], 'copy_script_pin_conflict')
    old_source = b'/etc/nginx/modsecurity.d'
    old_target = b'/etc/modsecurity.d'
    require(data.count(old_source) == 1 and data.count(old_target) == 4, 'copy_script_path_contract')
    result = data.replace(old_source, (temporary + '/output/modsecurity.d').encode())
    result = result.replace(old_target, (temporary + '/destination').encode())
    require(old_source not in result and old_target not in result, 'unreplaced_copy_path')
    return result


def native_run(argv, log):
    # A timeout runs inside the existing container and bounds the complete
    # script/process group. On any error the private tree is retained; the
    # controller never retries, restarts or kills the operating Nginx master.
    with log.open('xb') as stream:
        completed = subprocess.run(['/usr/local/bin/docker', 'exec', '--user', '101:101', *argv],
                                   stdout=stream, stderr=subprocess.STDOUT, timeout=25)
        stream.flush()
        os.fsync(stream.fileno())
    require(log.stat().st_size <= 65536, 'native_diagnostic_limit')
    require(completed.returncode == 0, 'private_native_failed')


def run(evidence):
    require(os.geteuid() == 0 and sys.platform == 'linux' and Path('/etc/machine-id').read_text().strip() == MID,
            'fixed_A_root_required')
    require(evidence.parent == ROOT_STAGE and re.fullmatch(r'waf-coldstart-[a-z0-9-]{6,48}', evidence.name), 'invalid_evidence_path')
    for path in [ROOT_STAGE.parent, ROOT_STAGE]:
        s = path.lstat()
        require(stat.S_ISDIR(s.st_mode) and not path.is_symlink() and s.st_uid == 0 and not s.st_mode & 0o022,
                'unsafe_evidence_parent')
    evidence.mkdir(mode=0o700)
    evidence.chmod(0o700)
    root = Path('/proc') / str(PID) / 'root'
    temporary = '/tmp/capstone-waf-coldstart-' + uuid.uuid4().hex
    scratch = root / temporary.lstrip('/')
    scratch_identity = None
    result = {'schema_version': 1, 'policy': 'waf-coldstart-template-verification-v1', 'status': 'failed',
              'operating_configuration_written': False, 'restart_requested': False, 'env_exported': False,
              'configuration_exported_to_mac': False, 'private_tree_removed': False, 'private_path': temporary}
    try:
        identity = docker_identity()
        contents, before = snapshot(root)
        protected = {}
        for path in ['/etc/capstone-vector/vector.toml', '/etc/capstone-vector/vector.env',
                     '/var/lib/capstone-raw-operations/suricata/state.json', '/var/lib/capstone-raw-operations/modsecurity/state.json']:
            protected[path] = read_regular(Path('/'), path)[1]
        durable_new(evidence / 'before.json', canonical({'container': identity, 'sources': before, 'protected': protected}))
        originals = evidence / 'originals'; originals.mkdir(mode=0o700)
        for i, path in enumerate([TEMPLATE, *['/etc/nginx/modsecurity.d/' + n for n in COPY_NAMES], TARGET, SCRIPT20, SCRIPT90]):
            durable_new(originals / ('%02d-' % i + Path(path).name), contents[path])
        scratch_parent = (root / 'tmp').lstat()
        require(stat.S_ISDIR(scratch_parent.st_mode) and not stat.S_ISLNK(scratch_parent.st_mode) and
                scratch_parent.st_uid == 0 and stat.S_IMODE(scratch_parent.st_mode) == 0o1777, 'unsafe_container_tmp')
        scratch.mkdir(mode=0o700); os.chown(scratch, 101, 101)
        scratch_identity = (scratch.stat().st_dev, scratch.stat().st_ino)
        for relative in ['templates', 'templates/modsecurity.d', 'output', 'output/modsecurity.d', 'destination']:
            path = scratch / relative; path.mkdir(mode=0o700); os.chown(path, 101, 101)
        for name in COPY_NAMES:
            durable_new(scratch / 'output/modsecurity.d' / name, contents['/etc/nginx/modsecurity.d/' + name], 0o600, 101, 101)
        durable_new(scratch / 'templates/modsecurity.d/modsecurity-override.conf.template', contents[TARGET], 0o400, 101, 101)
        copy_script = rendered_copy_script(contents[SCRIPT90], temporary)
        durable_new(scratch / 'copy-private.sh', copy_script, 0o500, 101, 101)
        durable_new(evidence / 'copy-private.sh', copy_script)
        native_run(['--env', 'NGINX_ENVSUBST_TEMPLATE_DIR=' + temporary + '/templates',
                    '--env', 'NGINX_ENVSUBST_OUTPUT_DIR=' + temporary + '/output',
                    '--env', 'NGINX_ENVSUBST_TEMPLATE_SUFFIX=.template',
                    '--env', 'NGINX_ENVSUBST_FILTER=^$',
                    '--env', 'NGINX_ENVSUBST_STREAM_TEMPLATE_SUFFIX=.stream-template',
                    '--env', 'NGINX_ENVSUBST_STREAM_OUTPUT_DIR=' + temporary + '/stream-unused',
                    '--env', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                    '--env', 'LC_ALL=C',
                    CID, '/usr/bin/timeout', '--signal=TERM', '--kill-after=1s', '12s', '/bin/sh', SCRIPT20],
                   evidence / 'native-envsubst.log')
        generated = (scratch / 'output/modsecurity.d/modsecurity-override.conf').read_bytes()
        require(sha(generated) == TARGET_SHA, 'rendered_override_mismatch')
        native_run([CID, '/usr/bin/timeout', '--signal=TERM', '--kill-after=1s', '12s', '/bin/sh', temporary + '/copy-private.sh'],
                   evidence / 'native-copy.log')
        for name in COPY_NAMES:
            expected = contents[TARGET] if name == COPY_NAMES[0] else contents['/etc/nginx/modsecurity.d/' + name]
            require((scratch / 'destination' / name).read_bytes() == expected, 'private_copy_mismatch')
        _, after = snapshot(root)
        require(after == before and docker_identity() == identity, 'operating_sources_changed')
        require({p: read_regular(Path('/'), p)[1] for p in protected} == protected, 'operating_state_or_config_changed')
        plan = {'schema_version': 1, 'policy': 'waf-coldstart-override-CAS-plan-v1', 'container': identity,
                'replacement_from_existing_target': TARGET, 'replacement_sha256': TARGET_SHA,
                'updates': [{'path': p, 'expected_before': before[p], 'replacement_sha256': TARGET_SHA,
                             'preserve_uid': before[p]['uid'], 'preserve_gid': before[p]['gid'],
                             'preserve_mode': before[p]['mode']} for p in (TEMPLATE, INTERMEDIATE)],
                'live_target_and_producer_unchanged': True, 'configuration_and_state_unchanged': True,
                'same_container_only': True, 'new_container_persistence_verified': False,
                'apply_implemented': False, 'backup_directory': str(originals)}
        durable_new(evidence / 'cas-plan.json', canonical(plan))
        require(not scratch.is_symlink() and (scratch.stat().st_dev, scratch.stat().st_ino) == scratch_identity,
                'private_tree_identity_changed')
        # Both synchronous timeout-contained commands returned. No background
        # process is started by these exact pinned startup snippets.
        shutil.rmtree(scratch)
        require(not scratch.exists(), 'private_cleanup_incomplete')
        result.update(status='passed', private_tree_removed=True, operating_sources_unchanged=True,
                      native_render_sha256=sha(generated), native_copied_files=3, cas_plan_sha256=sha(canonical(plan)),
                      actual_entrypoint_executed=False, current_service_coldstart_tested=False)
    except (Refusal, OSError, ValueError, subprocess.SubprocessError) as exc:
        result['failure_code'] = str(exc) if isinstance(exc, Refusal) else type(exc).__name__
        result['private_tree_preserved_or_removal_unconfirmed'] = scratch.exists()
    finally:
        result['completed_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        durable_new(evidence / 'result.json', canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = run(args.evidence)
    except (Refusal, OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {'status': 'failed', 'failure_code': str(exc) if isinstance(exc, Refusal) else type(exc).__name__,
                  'operating_configuration_written': False, 'restart_requested': False}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
