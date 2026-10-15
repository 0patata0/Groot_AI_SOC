#!/usr/bin/env python3
"""Finite administrator migration, not a runtime collector or MCP tool.

check is read-only. prepare writes ONLY a private backup/candidate tree and
runs native config tests in a new private mount+network namespace. Initial
production cutover commands are deliberately absent until separately reviewed.
No raw input/checkpoint/database is copied, rewritten, deleted or exported.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

MID = '096e90b6243e438aa8a7b392be754732'
BACKUP = Path('/var/backups/capstone-raw-operations-initial-20261014')
RUNTIME = Path('/usr/local/lib/capstone-raw-operations')
STATE = Path('/var/lib/capstone-raw-operations')
LOCK = Path('/var/lib/capstone-automation/ansible/vector.lock')
DOCKER = '/usr/local/bin/docker'
VECTOR = '/usr/local/bin/vector'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC',
       'PYTHONDONTWRITEBYTECODE': '1'}
BASE = Path('/home/groot_a/capstone/secstack/logs')
CONFIG = Path('/etc/capstone-vector')
BINDING = '3ae6308be37c1ab82ce62720e2b516c4c27190a9e043afe913b76bdf1da10637'
CONTAINERS = {
    'suricata': {
        'cid': '39ce628179fb39cac72fa59ccb562475a8f874a58eec401b6c6e187614bebd0d',
        'image': 'sha256:d4fd70f7955f1f9d5c8f54d0b91dd22e359bebce6fba5423d1182f33ae0d59ff',
        'exe': '/usr/bin/suricata', 'uid': 998,
        'raw': str(BASE / 'suricata/eve.json'), 'device': 64512, 'inode': 1441879},
    'waf': {
        'cid': '02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e',
        'image': 'sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650',
        'exe': '/usr/sbin/nginx', 'uid': 101,
        'raw': str(BASE / 'modsec/audit.log'), 'device': 64512, 'inode': 1441881}}
# These are reviewed initial-state pins, not an assertion that live still matches.
HOST = {
    'logrotate': ('/etc/logrotate.d/capstone-secstack', 'd352dd02da79da1da6c132cc1d7ca16dd8a19398d219547eea6fc18396a1ee3a', 0, 0, 0o644),
    'vector': (str(CONFIG / 'vector.toml'), '5ac09dd5cb708833fe0c2259c85aa0a587a42a67e78a1f507429dd9b825e56f7', 0, 0, 0o600),
    'environment': (str(CONFIG / 'vector.env'), 'f435a687b985f41c89e90ae1b36c63894a0cd96b337693b77b9017850dafc194', 0, 0, 0o600),
    'waf_binding': (str(CONFIG / 'waf-binding.json'), 'e11b0778f62478bc951a11fb93102f06f3f567aa1d9b91269f5a640c34109d95', 0, 0, 0o600),
    'line_binding': (str(CONFIG / 'raw-line-binding.json'), '0bd6e002aafd0ced247e0a25cee372685d364d544bc8bef20f22557e13fcfe41', 0, 0, 0o600),
    'wazuh': ('/var/ossec/etc/ossec.conf', 'b27ec250b19ef0fe9cc1f999467dc24176b82035e763080b33f037a063d4ce0a', 0, 110, 0o660),
    'compose': ('/home/groot_a/capstone/secstack/docker-compose.yml', '5f41d56c42f00d625b2ec3bec3f355f9599e8a38fa824f9baa193bcce2dd5d60', 1000, 1000, 0o644)}
ENGINE = {
    'suricata_yaml': ('suricata', '/etc/suricata/suricata.yaml', 'ecb52b0f86d1850b1780194ca53712a0684bd5447de5905d4b12f78781ca8400', 998, 998, 0o600),
    'waf_override': ('waf', '/etc/modsecurity.d/modsecurity-override.conf', '1063145a6a20922d17b7c75afee4938883d6d57f2b7584b33a085cf8291c3198', 101, 101, 0o644),
    'waf_producer': ('waf', '/etc/nginx/conf.d/zz-capstone-evidence.conf', '6b987c4684338e7c8210eeb7540f6ffb7b0a5e75f6b86e16f0671ceef8b99593', 0, 0, 0o644)}
BUNDLE = ('coordinator.sh', 'guard.sh', 'state-lib.sh', 'state.jq',
          'checkpoint-gates.sh', 'checkpoint-gates.jq', 'writer-gates.sh',
          'line-length-lib-v2.sh', 'raw-line-scan-v2.sh', 'vector-v2.toml',
          'zz-capstone-evidence-v2.conf', 'audit-context.vrl')
BASELINE_VRL = {
    'waf_access_part.vrl': '9f9700e970579ca1f2acc683fa6a12d6629a48088f780cde63877c49b0b288e5',
    'waf_audit_part.vrl': '18829d82be5ca8abcb1f11fa750d0f0f3a7eac49af6e22aa1eb131da637c44b8',
    'correlation.vrl': 'e8da4312819ca8442fb6183d40e7e1d14d8256bbcf2d6136c73e3aa69e92434d',
    'nftables.vrl': '8450cefe8d884522b6e817acd7fb963efccfb8a0c93a023a854befdc75c715e5',
    'waf_json_guard.vrl': 'd70de8b923c7cd31db1acd68404210a796ebe53e5d5de16737b5638c5680e898',
    'suricata.vrl': '861c998eb2ab3dc6c8902d405f4058dc69c7bb07ce1b0569359adba6e0e09dcc',
    'waf_pair_normalize.vrl': 'df6ddbc0d6773a94110e7edc0e21e6b68643030df8df11b05dd8da491cac1b0f'}


class Refused(RuntimeError):
    """Only a fixed code may cross the operator stdout boundary."""


def require(value, code):
    if not value:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode()


def parse(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def invalid(_):
        raise Refused('invalid_json_number')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refused('invalid_json') from error


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'links': info.st_nlink, 'bytes': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


@contextmanager
def parent_fd(path, root_fd=None):
    """Walk every real component with O_NOFOLLOW; proc-root is supplied by FD."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'invalid_fixed_path')
    fd = os.dup(root_fd) if root_fd is not None else os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        yield fd, path.name
    finally:
        os.close(fd)


def snapshot(path, root_fd=None, expected=None, max_bytes=1048576):
    with parent_fd(path, root_fd) as (directory, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    0 <= before.st_size <= max_bytes, 'configuration_metadata_invalid')
            if expected:
                digest, uid, gid, mode = expected
                require((before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) ==
                        (uid, gid, mode), 'configuration_permissions_changed')
            data = bytearray()
            while len(data) <= max_bytes:
                part = os.read(fd, min(65536, max_bytes + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            require(len(data) == before.st_size and len(data) <= max_bytes,
                    'configuration_size_changed')
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(identity(before) == identity(after) == identity(named),
                    'configuration_changed_during_read')
            raw = bytes(data)
            if expected:
                require(sha(raw) == digest, 'configuration_sha_changed')
            return raw, identity(before)
        finally:
            os.close(fd)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o400, root_fd=None):
    with parent_fd(path, root_fd) as (directory, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
        try:
            os.fchmod(fd, mode)
            os.fchown(fd, 0, 0)
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                require(count > 0, 'short_write')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)


def private_dir(path, root_fd=None):
    with parent_fd(path, root_fd) as (directory, name):
        os.mkdir(name, 0o700, dir_fd=directory)
        os.fsync(directory)
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700),
            'private_directory_invalid')


def command(argv, timeout=20, log=None):
    """Bound output to a private file when native diagnostics can be verbose."""
    if log is not None:
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        output = os.fdopen(fd, 'wb')
    else:
        output = tempfile.TemporaryFile()
    process = None
    reaped = False
    try:
        process = subprocess.Popen(argv, env=ENV, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        # Keep the leader unreaped until its whole process group is checked.
        # A reaped PID/PGID must never be signalled because it may be reused.
        deadline = time.monotonic() + timeout
        timed_out = False
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(.05)
        def live_group():
            members = []
            for item in Path('/proc').iterdir():
                if not item.name.isdigit():
                    continue
                try:
                    fields = (item / 'stat').read_text().rsplit(')', 1)[1].split()
                    if int(fields[2]) == process.pid and fields[0] not in ('Z', 'X'):
                        members.append(int(item.name))
                except FileNotFoundError:
                    pass
            return members
        if live_group():
            os.killpg(process.pid, signal.SIGTERM)
            until = time.monotonic() + 2
            while live_group() and time.monotonic() < until:
                time.sleep(.05)
            if live_group():
                os.killpg(process.pid, signal.SIGKILL)
                until = time.monotonic() + 3
                while live_group() and time.monotonic() < until:
                    time.sleep(.05)
        require(not live_group(), 'native_process_group_cleanup_uncertain')
        rc = process.wait(timeout=3)
        reaped = True
        if timed_out:
            raise Refused('native_command_timeout')
        output.flush()
        require(os.fstat(output.fileno()).st_size <= 4 * 1048576, 'native_output_limit')
        if log is not None:
            os.fsync(output.fileno())
            fsync_dir(Path(log).parent)
            return rc, b''
        output.seek(0)
        return rc, output.read(4 * 1048576 + 1)
    finally:
        if process is not None and not reaped:
            # On exceptional metadata/IO paths, the child is still unreaped.
            # Native checks additionally run in a disposable PID namespace.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
        if log is not None:
            output.flush()
            os.fsync(output.fileno())
        output.close()


def proc_identity(pid, expected_exe):
    require(type(pid) is int and 1 < pid < 2147483648, 'invalid_writer_pid')
    proc = Path('/proc') / str(pid)
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    require(fields[0] not in ('Z', 'X') and os.readlink(proc / 'exe') == expected_exe,
            'writer_process_changed')
    return {'pid': pid, 'start_ticks': int(fields[19]),
            'mount_ns': os.readlink(proc / 'ns/mnt'), 'pid_ns': os.readlink(proc / 'ns/pid'),
            'net_ns': os.readlink(proc / 'ns/net')}


def container(name):
    fixed = CONTAINERS[name]
    projection = '{"cid":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}'
    rc, raw = command([DOCKER, 'inspect', '--format', projection, fixed['cid']])
    require(rc == 0, 'container_inspect_failed')
    value = parse(raw)
    require(value['cid'] == fixed['cid'] and value['image'] == fixed['image'] and
            value['running'] is True, 'container_binding_changed')
    value['process'] = proc_identity(value['pid'], fixed['exe'])
    # Only mount metadata, no Config.Env, labels or application arguments.
    value['mounts'] = sorted([{key: m[key] for key in ('Type', 'Source', 'Destination', 'RW')}
                              for m in value['mounts']], key=lambda x: x['Destination'])
    expected = [(str(BASE / ('suricata' if name == 'suricata' else 'modsec')),
                 '/var/log/suricata' if name == 'suricata' else '/var/log/modsecurity')]
    for source, destination in expected:
        require(sum(m == {'Type': 'bind', 'Source': source, 'Destination': destination, 'RW': True}
                    for m in value['mounts']) == 1, 'raw_mount_changed')
    return value


@contextmanager
def container_root(name, expected):
    require(container(name) == expected, 'container_changed_before_root_open')
    # Deliberate procfs magic-link open after exact PID/start/CID validation.
    fd = os.open('/proc/%s/root' % expected['pid'], os.O_RDONLY | os.O_DIRECTORY)
    try:
        require(container(name) == expected, 'container_changed_after_root_open')
        yield fd
        require(container(name) == expected, 'container_changed_during_root_access')
    finally:
        os.close(fd)


def logrotate_candidate(raw):
    require(b'\r' not in raw and b'\x00' not in raw, 'logrotate_framing_invalid')
    old = (str(BASE / 'suricata/*.json') + '\n' + str(BASE / 'suricata/*.log') + '\n' +
           str(BASE / 'modsec/*.log') + ' {').encode()
    new = ('\n'.join(str(BASE / p) for p in ('suricata/fast.log', 'suricata/stats.log',
            'suricata/suricata.log', 'modsec/capstone-access.log')) + ' {').encode()
    require(raw.count(old) == 1, 'legacy_logrotate_header_changed')
    result = raw.replace(old, new, 1)
    directives = b'\n'.join(line for line in result.splitlines() if not line.lstrip().startswith(b'#'))
    require(directives.count(b'{') == directives.count(b'}') == 1 and
            b'*.json' not in directives and b'*.log' not in directives and
            b'eve.json' not in directives and b'audit.log' not in directives,
            'raw_copytruncate_not_excluded')
    return result


def yaml_candidate(raw):
    require(b'\r' not in raw and b'\x00' not in raw, 'yaml_framing_invalid')
    pattern = rb'(?m)^(\s*filename:[ \t]*)eve\.json([ \t]*(?:#[^\n]*)?)$'
    require(len(re.findall(pattern, raw)) == 1, 'eve_filename_ambiguous')
    return re.sub(pattern, rb'\1capstone-managed/active.jsonl\2', raw)


def override_candidate(raw):
    require(b'\r' not in raw and b'\x00' not in raw and
            all(not line.strip() or line.lstrip().startswith(b'#') for line in raw.splitlines()),
            'override_directives_changed')
    return raw + (b'' if raw.endswith(b'\n') else b'\n') + \
        b'Include /var/log/modsecurity/capstone-managed/audit-path.conf\n'


def environment_candidate(raw, producer):
    updates = {'WAF_INSTANCE_ID': CONTAINERS['waf']['cid'], 'WAF_CONFIG_SHA256': sha(producer),
               'WAF_DEPLOYMENT_BINDING': BINDING}
    require(b'\r' not in raw and b'\0' not in raw and raw.endswith(b'\n'), 'environment_framing_invalid')
    lines = raw.decode('ascii').splitlines(keepends=True)
    for key, value in updates.items():
        matches = [i for i, line in enumerate(lines) if line.startswith(key + '=')]
        require(len(matches) == 1 and re.fullmatch(r'[A-Z_][A-Z0-9_]*=([a-f0-9]{64})\n', lines[matches[0]]),
                'environment_binding_invalid')
        lines[matches[0]] = key + '=' + value + '\n'
    result = ''.join(lines).encode()
    for key, expected in [('WAF_AUDIT_PATH', str(BASE / 'modsec/audit.log')),
                          ('WAF_ACCESS_PATH', str(BASE / 'modsec/capstone-access.log'))]:
        require(result.splitlines().count((key + '=' + expected).encode()) == 1, 'environment_path_changed')
    return result


def waf_manifest_candidate(raw, producer):
    value = parse(raw)
    require(value.get('schema') == 'waf-producer-deployment-1' and
            value.get('machine_id') == MID and value.get('container_name') == 'waf' and
            value.get('instance_id') == CONTAINERS['waf']['cid'] and
            value.get('configuration_sha256') == ENGINE['waf_producer'][2] and
            value.get('audit_path') == str(BASE / 'modsec/audit.log') and
            value.get('access_path') == str(BASE / 'modsec/capstone-access.log'),
            'v1_waf_manifest_changed')
    value.update(schema='waf-producer-deployment-2', schema_version=2,
                 time_policy='context-created-fixed-offset-v2', deployment_binding=BINDING,
                 configuration_sha256=sha(producer))
    return canonical(value)


def bundle_sources(directory):
    for parent in (directory, *directory.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
                (str(parent) in ('/var/tmp', '/tmp') or not stat.S_IMODE(info.st_mode) & 0o022),
                'bundle_directory_untrusted')
    sources = {}
    for name in BUNDLE:
        data, info = snapshot(directory / name)
        require(info['uid'] == 0 and info['gid'] == 0 and not info['mode'] & 0o022,
                'bundle_permissions_invalid')
        sources[name] = data
    require(sha(sources['audit-context.vrl']) ==
            'bf858467aa62e3dd7da7e9135af8ac36d8bcee0e4d0415d7a13ff0dac52cd219',
            'v2_context_source_changed')
    require(('modsecurity_transaction_id "v2:' + BINDING + ':$request_id:$msec:$time_iso8601";').encode()
            in sources['zz-capstone-evidence-v2.conf'], 'v2_producer_binding_invalid')
    require(b'RLS_LIBRARY=/usr/local/lib/capstone-raw-operations\n' in sources['raw-line-scan-v2.sh'],
            'runtime_path_disagreement')
    return sources


def initial_snapshot(directory):
    require(os.geteuid() == 0 and sys.platform == 'linux' and
            Path('/etc/machine-id').read_text().strip() == MID, 'fixed_A_root_required')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
    require(re.fullmatch('[a-f0-9]{32}', boot), 'boot_id_invalid')
    for path in (STATE, RUNTIME, BASE / 'suricata/capstone-managed', BASE / 'modsec/capstone-managed'):
        require(not os.path.lexists(path), 'initial_destination_exists')
    require(not os.path.lexists('/var/lib/capstone-vector-maintenance/resume.pending'),
            'maintenance_rotation_pending')
    originals, files = {}, {}
    for key, (path, digest, uid, gid, mode) in HOST.items():
        originals[key], files[key] = snapshot(path, expected=(digest, uid, gid, mode))
        files[key]['sha256'] = digest
    for name, digest in BASELINE_VRL.items():
        data, info = snapshot(CONFIG / 'transforms' / name, expected=(digest, 0, 0, 0o600))
        files['vrl:' + name] = dict(info, sha256=sha(data))
    containers = {name: container(name) for name in CONTAINERS}
    for key, (name, path, digest, uid, gid, mode) in ENGINE.items():
        with container_root(name, containers[name]) as root:
            originals[key], files[key] = snapshot(path, root, (digest, uid, gid, mode))
            files[key]['sha256'] = digest
    raw_meta = {}
    for name, fixed in CONTAINERS.items():
        with parent_fd(fixed['raw']) as (fd, leaf):
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino, info.st_uid,
                    info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) ==
                    (fixed['device'], fixed['inode'], fixed['uid'], fixed['uid'], 0o644, 1),
                    'initial_raw_identity_changed')
            raw_meta[name] = identity(info)
    units = {}
    for unit in ('capstone-vector.service', 'wazuh-agent.service', 'logrotate.service'):
        rc, raw = command(['/usr/bin/systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'SubState',
                           '-p', 'InvocationID', '-p', 'MainPID', '-p', 'DropInPaths'])
        require(rc == 0, 'unit_metadata_unavailable')
        value = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines())
        require(value['ActiveState'] == ('inactive' if unit == 'logrotate.service' else 'active'),
                'unit_not_ready')
        require(value['DropInPaths'] == '', 'unexpected_reader_dropin')
        units[unit] = value
    require(os.statvfs(BACKUP.parent).f_bavail * os.statvfs(BACKUP.parent).f_frsize >= 2 * 1073741824,
            'backup_free_space_low')
    source = bundle_sources(directory)
    metadata = {'schema_version': 1, 'policy': 'initial-raw-operations-20261014', 'machine_id': MID,
                'boot_id': boot, 'observed_at_epoch': int(time.time()), 'containers': containers,
                'files': files, 'raw_metadata': raw_meta, 'units': units,
                'source_sha256': {name: sha(raw) for name, raw in source.items()},
                'raw_read_or_exported': False, 'operating_mutations': False}
    return metadata, originals, source


def candidates(originals, source):
    producer = source['zz-capstone-evidence-v2.conf']
    result = {'logrotate': logrotate_candidate(originals['logrotate']),
              'suricata_yaml': yaml_candidate(originals['suricata_yaml']),
              'waf_override': override_candidate(originals['waf_override']),
              'waf_producer': producer, 'vector': source['vector-v2.toml'],
              'environment': environment_candidate(originals['environment'], producer),
              'waf_binding': waf_manifest_candidate(originals['waf_binding'], producer),
              'audit_path': b'SecAuditLog /var/log/modsecurity/capstone-managed/generation-0000000001.jsonl\n',
              'waf_audit_context': source['audit-context.vrl']}
    result['line_binding'] = canonical({'schema_version': 1, 'policy': 'periodic-snapshot-tail-v1',
                                       'vector_config_sha256': sha(result['vector']),
                                       'vector_env_sha256': sha(result['environment'])})
    return result


# nsenter selects the existing mount/root view; unshare creates private
# namespaces before any mount operation. No production signal or daemon run.
SHADOW_SCRIPT = r'''set -euo pipefail
cd /
umask 077
ulimit -f 4096
stage=$1; engine=$2; expected_root=$3
[[ $(/usr/bin/stat -c '%d:%i' /) == "$expected_root" ]] || { echo private_root_identity_mismatch; exit 70; }
# nsenter has already entered the existing root; unshare created NEW namespaces
# before this script. No mount operation is executed in the operating namespace.
/usr/bin/mount --make-rprivate /
[[ -d /proc && ! -L /proc ]] || { echo private_proc_target_invalid; exit 70; }
# Install procfs BEFORE findmnt: the inherited procfs cannot describe this new
# PID namespace reliably. This procfs sees only the disposable native test.
/usr/bin/mount -t proc -o ro,nosuid,nodev,noexec proc /proc
/usr/bin/findmnt --submounts --noheadings --raw --output TARGET / > "$stage/mount-targets"
mapfile -t targets < "$stage/mount-targets"
(( ${#targets[@]} > 0 && ${#targets[@]} < 128 )) || { echo private_mount_count_invalid; exit 70; }
for (( i=${#targets[@]}-1; i>=0; i-- )); do
  target=${targets[$i]}
  [[ $target == /* && $target != *\\* && $target != *' '* ]] || { echo private_mount_path_invalid; exit 70; }
  # Old container proc mask mounts remain in mountinfo but are hidden by the
  # new procfs; do not try to remount those now-inaccessible targets.
  [[ $target != /proc && $target != /proc/* ]] || continue
  /usr/bin/mount -o remount,bind,ro "$target"
done
visible_readonly() {
  local point=$1 descriptor mount_id
  exec {descriptor}<"$point"
  mount_id=$(/usr/bin/awk '$1=="mnt_id:" {n++; id=$2} END {if(n==1)print id; else exit 1}' "/proc/$$/fdinfo/$descriptor") || return 1
  [[ $mount_id =~ ^[1-9][0-9]*$ ]] || return 1
  # Mountpoint listings can contain BOTH a hidden old rw proc and the new ro
  # proc. Only the mount ID of the actual opened directory is authoritative.
  /usr/bin/awk -v wanted="$mount_id" -v point="$point" '
    $1==wanted {n++; if($5==point && ("," $6 ",") ~ /,ro,/) good=1}
    END {exit !(n==1 && good==1)}' "/proc/$$/mountinfo"
  local status=$?
  exec {descriptor}<&-
  return "$status"
}
visible_readonly / || { echo private_root_not_readonly; exit 70; }
visible_readonly /proc || { echo private_proc_not_readonly; exit 70; }
if [[ $engine == waf ]]; then
  /usr/bin/mount --bind "$stage/candidate/waf_override" /etc/modsecurity.d/modsecurity-override.conf
  /usr/bin/mount -o remount,bind,ro /etc/modsecurity.d/modsecurity-override.conf
  /usr/bin/mount --bind "$stage/candidate/waf_producer" /etc/nginx/conf.d/zz-capstone-evidence.conf
  /usr/bin/mount -o remount,bind,ro /etc/nginx/conf.d/zz-capstone-evidence.conf
elif [[ $engine == suricata ]]; then
  /usr/bin/mount --bind "$stage/candidate/suricata_yaml" /etc/suricata/suricata.yaml
  /usr/bin/mount -o remount,bind,ro /etc/suricata/suricata.yaml
else exit 64; fi
parts=(var/log run)
[[ $engine != waf ]] || parts+=(var/cache/nginx)
# /tmp must be LAST: the script FD remains open, while its source path is masked.
parts+=(tmp)
for part in "${parts[@]}"; do
  [[ -d /$part && ! -L /$part ]] || { echo private_overlay_target_invalid; exit 70; }
  /usr/bin/mount --bind "$stage/private/${part//\//_}" "/$part"
  /usr/bin/mount -o remount,bind,rw "/$part"
done
if [[ $engine == waf ]]; then
  exec /usr/sbin/nginx -t -c /etc/nginx/nginx.conf
else
  exec /usr/bin/suricata -T -c /etc/suricata/suricata.yaml -S /rules/all.rules
fi
'''


def remove_private_tree(root_fd, path, expected):
    """Delete only the opened private test tree; never follow a symlink."""
    removed = 0
    def clear(directory):
        nonlocal removed
        entries = os.listdir(directory)
        require(len(entries) <= 128 and removed + len(entries) <= 256, 'private_cleanup_entry_limit')
        for name in entries:
            value = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(value.st_uid in (0, 101, 998), 'private_cleanup_owner_changed')
            removed += 1
            if stat.S_ISDIR(value.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    clear(child)
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=directory)
            else:
                require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1,
                        'private_cleanup_unknown_entry')
                os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    with parent_fd(path, root_fd) as (parent, leaf):
        directory = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            value = os.fstat(directory)
            require(value.st_uid == value.st_gid == 0 and stat.S_IMODE(value.st_mode) == 0o700,
                    'private_cleanup_root_changed')
            require((value.st_dev, value.st_ino) == expected,
                    'private_cleanup_root_identity_changed')
            clear(directory)
        finally:
            os.close(directory)
        os.rmdir(leaf, dir_fd=parent)
        os.fsync(parent)
        try:
            os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return removed
        raise Refused('private_cleanup_not_complete')


def native_shadow(name, observation):
    evidence = BACKUP / ('native-' + name)
    private_dir(evidence)
    native_log = evidence / 'native.log'
    stage = Path('/tmp/capstone-native-config-' + str(time.time_ns()))
    rc = None
    removed = False
    failure = None
    protected = False
    with container_root(name, observation) as root:
        expected_root = os.fstat(root)
        private_dir(stage, root)
        with parent_fd(stage, root) as (directory, leaf):
            stage_meta = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        try:
            for relative in ('private', 'candidate', 'private/var_log', 'private/run',
                             'private/tmp', 'private/var_cache_nginx', 'private/var_log/nginx',
                             'private/var_log/modsecurity', 'private/var_log/modsecurity/capstone-managed',
                             'private/var_log/suricata', 'private/var_log/suricata/capstone-managed'):
                private_dir(stage / relative, root)
            for relative in ('var_log', 'run', 'var_cache_nginx', 'var_log/nginx', 'var_log/modsecurity',
                             'var_log/modsecurity/capstone-managed', 'var_log/suricata', 'var_log/suricata/capstone-managed'):
                with parent_fd(stage / 'private' / relative, root) as (directory, leaf):
                    os.chmod(leaf, 0o755, dir_fd=directory)
                    if relative.startswith('var_log/suricata'):
                        os.chown(leaf, 998, 998, dir_fd=directory)
            with parent_fd(stage / 'private/tmp', root) as (directory, leaf):
                os.chmod(leaf, 0o1777, dir_fd=directory)
            for key in ('waf_override', 'waf_producer', 'suricata_yaml'):
                raw, _ = snapshot(BACKUP / 'candidate' / key)
                write_new(stage / 'candidate' / key, raw, root_fd=root)
            raw, _ = snapshot(BACKUP / 'candidate/audit_path')
            write_new(stage / 'private/var_log/modsecurity/capstone-managed/audit-path.conf', raw, 0o444, root)
            for relative, owner in (('modsecurity/capstone-managed/generation-0000000001.jsonl', 101),
                                    ('suricata/capstone-managed/active.jsonl', 998)):
                target = stage / 'private/var_log' / relative
                write_new(target, b'', 0o644, root)
                with parent_fd(target, root) as (directory, leaf):
                    os.chown(leaf, owner, owner, dir_fd=directory)
            write_new(stage / 'check.sh', SHADOW_SCRIPT.encode(), 0o500, root)
            require(container(name) == observation, 'native_writer_changed_before_check')
            # nsenter only chooses the root/mount view. The immediately executed
            # unshare creates private namespaces before our first mount call.
            rc, _ = command(['/usr/bin/nsenter', '--target', str(observation['pid']), '--mount',
                             '--root', '--wdns=/', '--', '/usr/bin/unshare', '--mount', '--net',
                             '--pid', '--fork', '--kill-child=KILL', '--', '/bin/bash', '--noprofile',
                             '--norc', str(stage / 'check.sh'), str(stage), name,
                             '%s:%s' % (expected_root.st_dev, expected_root.st_ino)], timeout=60, log=native_log)
            if rc != 0:
                failure = 'native_check_nonzero'
            require(container(name) == observation, 'native_writer_changed_after_check')
        except (Refused, OSError, subprocess.SubprocessError) as error:
            failure = str(error) if isinstance(error, Refused) else 'private_native_execution_failed'
        finally:
            # Preserve a fixed postcondition result even when native -t/-T or
            # the command deadline fails. Never delete an uncertain test tree.
            try:
                require(container(name) == observation, 'native_writer_changed_after_check')
                for _, (owner, path, digest, uid, gid, mode) in ENGINE.items():
                    if owner == name:
                        snapshot(path, root, (digest, uid, gid, mode))
                protected = True
            except (Refused, OSError, subprocess.SubprocessError):
                failure = failure or 'native_postcondition_unverified'
            try:
                targets, _ = snapshot(stage / 'mount-targets', root, max_bytes=65536)
                write_new(evidence / 'private-mount-targets.txt', targets)
            except FileNotFoundError:
                pass
            except (Refused, OSError):
                failure = failure or 'private_mount_diagnostic_preservation_failed'
            if rc == 0 and failure is None and protected:
                try:
                    remove_private_tree(root, stage, (stage_meta.st_dev, stage_meta.st_ino))
                    removed = True
                except (Refused, OSError):
                    failure = failure or 'private_cleanup_incomplete'
            # Write before container_root's final identity assertion, so even
            # that assertion's refusal leaves bounded evidence. This is only
            # the engine-specific check; prepare still compares all host pins.
            result = {'exit_code': rc, 'diagnostic_sha256': sha(native_log.read_bytes()) if native_log.exists() else None,
                      'private_namespace': True if rc == 0 else None,
                      'production_signals': 0, 'daemon_started': False,
                      'private_tmp_removed': removed, 'private_tmp_preserved': not removed,
                      'private_tmp_path': str(stage), 'operating_configuration_unchanged': protected,
                      'protection_scope': 'engine_configuration_and_container_identity',
                      'container_root_identity_verified': True if rc == 0 else None,
                      'failure_code': failure}
            write_new(evidence / 'result.json', canonical(result))
    require(rc == 0 and failure is None and protected, 'native_configuration_check_failed')
    return result


@contextmanager
def shared_lock():
    with parent_fd(LOCK) as (directory, name):
        fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, info.st_nlink,
                    stat.S_IMODE(info.st_mode)) == (0, 0, 1, 0o600), 'shared_lock_invalid')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)


def prepare(directory):
    before, originals, sources = initial_snapshot(directory)
    require(not os.path.lexists(BACKUP), 'prepare_evidence_already_exists_inspect_required')
    private_dir(BACKUP)
    for name in ('original', 'candidate', 'source'):
        private_dir(BACKUP / name)
    write_new(BACKUP / 'before.json', canonical(before))
    write_new(BACKUP / 'prepare-intent.json', canonical({'phase': 'prepare_started',
              'boot_id': before['boot_id'], 'production_mutations': False}))
    for key, data in originals.items():
        write_new(BACKUP / 'original' / key, data)
    generated = candidates(originals, sources)
    for key, data in generated.items():
        write_new(BACKUP / 'candidate' / key, data)
    for key, data in sources.items():
        write_new(BACKUP / 'source' / key, data)
    # Preserve the exact one-off installer, not only its dependency list.
    installer, _ = snapshot(Path(__file__).absolute())
    write_new(BACKUP / 'source/deploy-raw-operations-a.py', installer)
    native = {name: native_shadow(name, before['containers'][name]) for name in ('waf', 'suricata')}
    after, repeated, repeated_sources = initial_snapshot(directory)
    require(before['boot_id'] == after['boot_id'] and before['containers'] == after['containers'] and
            before['files'] == after['files'] and before['units'] == after['units'] and
            originals == repeated and sources == repeated_sources, 'prepare_operating_state_changed')
    for name in CONTAINERS:
        old, new = before['raw_metadata'][name], after['raw_metadata'][name]
        require(all(old[k] == new[k] for k in ('device', 'inode', 'uid', 'gid', 'links', 'mode')) and
                new['bytes'] >= old['bytes'], 'prepare_raw_identity_or_size_changed')
    plan = {'schema_version': 1, 'phase': 'prepared', 'machine_id': MID, 'boot_id': before['boot_id'],
            'before_sha256': sha(canonical(before)), 'source_sha256': before['source_sha256'],
            'installer_sha256': sha(installer), 'candidate_sha256': {k: sha(v) for k, v in generated.items()},
            'native': native, 'operating_mutations': False, 'cutover_implemented': False}
    write_new(BACKUP / 'plan.json', canonical(plan))
    write_new(BACKUP / 'after-prepare.json', canonical(after))
    return {'status': 'prepared', 'plan_sha256': sha(canonical(plan)), 'backup': str(BACKUP),
            'native_config_checks': len(native), 'operating_mutations': False,
            'cutover_implemented': False, 'raw_exported': False}


def main():
    require(sys.argv[1:] in (['check'], ['prepare']), 'operation_not_implemented_or_invalid')
    os.umask(0o077)
    require(os.geteuid() == 0 and sys.platform == 'linux', 'fixed_A_root_required')
    directory = Path(__file__).absolute().parent
    with shared_lock():
        if sys.argv[1] == 'check':
            metadata, originals, sources = initial_snapshot(directory)
            generated = candidates(originals, sources)
            result = {'status': 'checked', 'machine_id': MID, 'boot_id': metadata['boot_id'],
                      'candidate_sha256': {key: sha(value) for key, value in generated.items()},
                      'source_sha256': metadata['source_sha256'], 'operating_mutations': False,
                      'native_config_checks': 0, 'cutover_implemented': False, 'raw_exported': False}
        else:
            result = prepare(directory)
    print(canonical(result).decode(), end='')


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, Refused) else 'operator_preparation_failed'
        print(json.dumps({'status': 'refused', 'reason': code, 'raw_exported': False}))
        sys.exit(2)
