#!/usr/bin/env python3
"""Offline first install. Preflight only reads; no package manager or image pull."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import grp
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile

SOURCE = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(SOURCE))
from manifest import MAX_MANIFEST_BYTES, unique_object, validate_manifest
from guard import RULES

TARGET = Path('/opt/capstone-offline-labs')
CONFIG = Path('/etc/capstone-offline-labs')
STATE = Path('/var/lib/capstone-offline-labs')
UNIT_DIRECTORY = Path('/etc/systemd/system')
UNITS = ('capstone-offline-labs-guard.service', 'capstone-offline-labs-broker.service', 'capstone-offline-labs.service')
LOOPBACK_ORIGINS = ('http://127.0.0.1:18090', 'http://localhost:18090')
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root', 'PYTHONDONTWRITEBYTECODE': '1'}


class Failure(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'regular_file_required')
    return info


def no_symlink_path(path):
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink_path_rejected')


def root_directory(path):
    for part in (path, *path.parents):
        info = part.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'root_controlled_directory_required')


def public_origin(value):
    if value is None:
        return None
    require(isinstance(value, str) and len(value) <= 255 and value.isascii(), 'https_origin_required')
    parsed = urlsplit(value)
    require(parsed.scheme == 'https' and not parsed.username and not parsed.password
            and not parsed.path and not parsed.query and not parsed.fragment, 'https_origin_required')
    require(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?', parsed.netloc)
            and parsed.hostname and all(label and len(label) <= 63 for label in parsed.hostname.split('.')),
            'https_origin_host_invalid')
    try:
        require(parsed.port is None or 1 <= parsed.port <= 65535, 'https_origin_port_invalid')
    except ValueError:
        raise Failure('https_origin_port_invalid') from None
    return value


def key_bytes(path):
    if path is None:
        return None
    root_directory(path.parent)
    info = regular(path)
    require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 1025, 'private_root_key_file_required')
    raw = path.read_bytes()
    try:
        value = raw.decode('utf-8').removesuffix('\n')
    except UnicodeError:
        raise Failure('invalid_admin_key_file') from None
    require(8 <= len(value) <= 256 and len(value.encode()) <= 1024, 'invalid_admin_key_file')
    return raw


def source_files(source):
    no_symlink_path(source)
    require(source.is_dir(), 'source_directory_required')
    result = {}
    total = 0
    for path in source.rglob('*'):
        relative = path.relative_to(source)
        require(not path.is_symlink(), 'source_symlink_rejected')
        require(path.is_dir() or path.is_file(), 'source_special_file_rejected')
        # The rootless sudo installer independently owns nonweb/sudo. Inspect
        # its tree for symlinks, but never pre-create its managed destination.
        if path.is_dir() or {'wheels', 'vendor', '__pycache__', 'nonweb'} & set(relative.parts):
            continue
        info = regular(path)
        total += info.st_size
        require(total <= 64 * 1024 * 1024 and len(result) < 5000, 'source_size_limit')
        result[str(relative)] = path.read_bytes()
    needed = {'app.py', 'broker.py', 'guard.py', 'manifest.py', 'practice_mode.py', 'challenge.py', 'cve_list.json',
              'static/index.html', 'static/app.js', 'static/app.css', 'static/theme.js', 'static/theme.css',
              'wheel-inventory.json'} | {'scripts/bootstrap-units/' + name for name in UNITS}
    require(needed <= result.keys(), 'required_source_missing')
    return result


def wheel_files(directory, inventory_bytes):
    no_symlink_path(directory)
    require(directory.is_dir(), 'wheel_directory_required')
    rows = json.loads(inventory_bytes)
    require(isinstance(rows, list) and 0 < len(rows) <= 64, 'wheel_inventory_invalid')
    names, outputs, directories = set(), {}, set()
    total = 0
    for row in rows:
        require(isinstance(row, dict) and {'file', 'sha256', 'bytes'} <= row.keys(), 'wheel_inventory_invalid')
        name = row['file']
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+\.whl', name)
                and name not in names and re.fullmatch(r'[0-9a-f]{64}', row['sha256']), 'wheel_inventory_invalid')
        names.add(name)
        path = directory / name
        info = regular(path)
        require(type(row['bytes']) is int and 0 < row['bytes'] <= 32 * 1024 * 1024
                and info.st_size == row['bytes'], 'wheel_size_mismatch')
        blob = path.read_bytes()
        require(hashlib.sha256(blob).hexdigest() == row['sha256'], 'wheel_checksum_mismatch')
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            for item in archive.infolist():
                path = PurePosixPath(item.filename)
                kind = stat.S_IFMT(item.external_attr >> 16)
                require(item.filename and not path.is_absolute() and '..' not in path.parts
                        and '\\' not in item.filename and '\x00' not in item.filename
                        and kind in (0, stat.S_IFREG, stat.S_IFDIR)
                        and not any(part.endswith('.data') for part in path.parts), 'unsafe_wheel_entry')
                normalized = str(path)
                require(normalized not in ('.', '') and all(str(parent) not in outputs for parent in path.parents),
                        'wheel_path_collision')
                if item.is_dir():
                    require(normalized not in outputs, 'wheel_path_collision')
                    directories.add(normalized)
                    continue
                total += item.file_size
                require(item.file_size <= 64 * 1024 * 1024 and total <= 256 * 1024 * 1024,
                        'wheel_expansion_limit')
                require(normalized not in outputs and normalized not in directories, 'wheel_path_collision')
                outputs[normalized] = archive.read(item)  # Includes CRC validation before any mutation.
                directories.update(str(parent) for parent in path.parents if str(parent) != '.')
    require({p.name for p in directory.glob('*.whl')} == names, 'unexpected_wheel_inventory')
    return outputs, len(rows)


def listening_ports(text):
    result = set()
    for row in text.splitlines()[1:]:
        fields = row.split()
        if len(fields) > 3 and fields[3] == '0A':
            result.add(int(fields[1].rsplit(':', 1)[1], 16))
    return result


class Host:
    def run(self, args, input=None):
        result = subprocess.run(args, input=input, capture_output=True, text=True, env=ENV, timeout=30)
        require(result.returncode == 0, 'command_failed_' + Path(args[0]).name)
        require(len(result.stdout) <= 8 * 1024 * 1024, 'command_output_limit')
        return result.stdout

    def path(self, value):
        return Path(value)

    def account_exists(self):
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup('capstone-labs')
                return True
            except KeyError:
                pass
        return False

    def check_platform(self):
        require(os.geteuid() == 0, 'root_required')
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
                and sys.version_info[:2] == (3, 12), 'ubuntu24_amd64_python312_required')
        values = {}
        for line in self.path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                values[key] = value.strip('"')
        require(values.get('ID') == 'ubuntu' and values.get('VERSION_ID') == '24.04', 'ubuntu24_required')

    def tool(self, name):
        path = shutil.which(name, path=ENV['PATH'])
        require(path is not None, 'missing_tool_' + name)
        resolved = Path(path).resolve(strict=True)
        root_directory(resolved.parent)
        info = regular(resolved)
        require(info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe_tool_' + name)
        return path


def preflight(args, host=None):
    host = host or Host()
    host.check_platform()
    source = source_files(SOURCE)
    origin = public_origin(args.origin)
    manifest_path = Path(args.manifest).absolute() if args.manifest else SOURCE / 'cve_list.json'
    no_symlink_path(manifest_path)
    require(regular(manifest_path).st_size <= MAX_MANIFEST_BYTES, 'manifest_size_limit')
    manifest = manifest_path.read_bytes()
    labs = validate_manifest(json.loads(manifest, object_pairs_hook=unique_object))
    require(labs, 'empty_catalog')
    key = key_bytes(Path(args.admin_key_file).absolute()) if args.admin_key_file else None
    wheels, wheel_count = wheel_files(Path(args.wheel_directory).absolute(), source['wheel-inventory.json'])
    tools = {name: host.tool(name) for name in ('python3', 'docker', 'nft', 'systemctl', 'useradd', 'nologin')}
    require(tools['docker'] in ('/usr/bin/docker', '/usr/local/bin/docker'), 'trusted_docker_path_required')
    require(tools['nft'] == '/usr/sbin/nft', 'fixed_nft_path_required')
    require(tools['python3'] == '/usr/bin/python3', 'fixed_python_path_required')
    require(tools['nologin'] == '/usr/sbin/nologin', 'fixed_nologin_path_required')
    for path in (TARGET, CONFIG, Path('/run/capstone-offline-labs'),
                 STATE / 'runtime.json', STATE / 'broker.lock', STATE / 'install-state.json',
                 STATE / 'nonweb-status.json', Path('/sys/class/net/br-offline-labs')):
        require(not os.path.lexists(host.path(path)), 'existing_install_or_runtime_conflict')
    for parent in ('/opt', '/etc', '/etc/systemd/system', '/var/lib', '/run'):
        root_directory(host.path(parent))
    if host.path(STATE).exists():
        root_directory(host.path(STATE))  # Approved image archives may already be here.
    require(not host.account_exists(), 'account_or_group_conflict')
    for unit in UNITS:
        require(host.run([tools['systemctl'], 'show', '--property=LoadState', '--value', unit]).strip() == 'not-found',
                'systemd_unit_conflict')
        for folder in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
            require(not os.path.lexists(host.path(Path(folder) / unit))
                    and not os.path.lexists(host.path(Path(folder) / (unit + '.d'))), 'systemd_unit_file_conflict')
    docker = [tools['docker'], '--host', 'unix:///var/run/docker.sock']
    data = json.loads(host.run(docker + ['info', '--format', '{"version":{{json .ServerVersion}},"os":{{json .OSType}},"arch":{{json .Architecture}},"security":{{json .SecurityOptions}}}']))
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+].*)?', data['version'])
            and int(data['version'].split('.')[0]) >= 28 and data['os'] == 'linux'
            and data['arch'] in ('x86_64', 'amd64') and not any('rootless' in x for x in data['security']),
            'rootful_docker28_amd64_required')
    networks = host.run(docker + ['network', 'ls', '--format', '{{.Name}}']).splitlines()
    require('offline-labs' not in networks, 'network_conflict')
    tables = json.loads(host.run([tools['nft'], '-j', 'list', 'tables']))
    require(not any(x.get('table', {}).get('name') == 'capstone_offline_labs' for x in tables.get('nftables', [])),
            'nft_table_conflict')
    host.run([tools['nft'], '--check', '-f', '-'], input=RULES)
    managed = [lab for lab in labs if lab['type'] == 'managed-http']
    ports = {18090} | {lab['host_port'] for lab in managed}
    require(len(ports) == len(managed) + 1, 'console_port_conflict')
    occupied = set()
    for file in ('/proc/net/tcp', '/proc/net/tcp6'):
        occupied.update(listening_ports(host.path(file).read_text()))
    require(not ports & occupied, 'listening_port_conflict')
    names = {'offline-lab-' + lab['cve_id'].lower() for lab in managed}
    ids = host.run(docker + ['container', 'ls', '-aq', '--no-trunc']).splitlines()
    for cid in ids:
        require(re.fullmatch(r'[0-9a-f]{64}', cid), 'container_inventory_invalid')
        item = json.loads(host.run(docker + ['container', 'inspect', '--format', '{"name":{{json .Name}},"ports":{{json .HostConfig.PortBindings}}}', cid]))
        require(item['name'].lstrip('/') not in names, 'container_name_conflict')
        for entries in (item['ports'] or {}).values():
            require(not any(int(x['HostPort']) in ports for x in entries or []), 'published_port_conflict')
    for lab in managed:
        images = json.loads(host.run(docker + ['image', 'inspect', lab['image_tag']]))
        require(len(images) == 1 and images[0]['Id'] == lab['image_id'], 'pinned_image_missing_or_changed')
        require(images[0].get('Os') == 'linux' and images[0].get('Architecture') == 'amd64'
                and isinstance(images[0].get('Config'), dict) and not images[0]['Config'].get('Volumes'),
                'image_runtime_contract_invalid')
    require(shutil.disk_usage(host.path('/opt')).free >= sum(map(len, source.values())) + sum(map(len, wheels.values())) + 64 * 1024 * 1024,
            'insufficient_install_space')
    return {'source': source, 'manifest': manifest, 'labs': labs, 'key': key, 'wheels': wheels,
            'wheel_count': wheel_count, 'origin': origin, 'tools': tools, 'docker': docker}


def summary(plan):
    return {'catalog_count': len(plan['labs']), 'managed_images_checked': sum(x['type'] == 'managed-http' for x in plan['labs']),
            'wheel_count': plan['wheel_count'], 'origins': ([plan['origin']] if plan['origin'] else []) + list(LOOPBACK_ORIGINS),
            'admin_key_mode': 'provided_private_file' if plan['key'] is not None else 'generated_on_apply',
            'key_purpose': 'optional WAF blocking exception; not a login', 'lab_containers_started': False,
            'local_cli_preparation': 'separate; needs_setup until independently verified'}


def write_new(path, data, mode=0o644, group=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), 0, group)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def apply(plan, host=None):
    host = host or Host()
    stage = 'create_install_state'
    state = {'schema': 1, 'status': 'partial', 'stage': stage, 'automatic_cleanup': False}
    journal = STATE / 'install-state.json'
    journal_owned = False
    files = {}
    def install_file(path, data, mode=0o644, group=0):
        write_new(path, data, mode, group)
        files[str(path)] = {'sha256': hashlib.sha256(data).hexdigest(),
                            'mode': format(mode, '04o'), 'uid': 0, 'gid': group}
    def record(name):
        nonlocal stage
        stage = name
        state['stage'] = stage
        fd, name = tempfile.mkstemp(prefix='.install-state-', dir=STATE)
        try:
            with os.fdopen(fd, 'w') as stream:
                stream.write(json.dumps(state, sort_keys=True) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, journal)
        finally:
            Path(name).unlink(missing_ok=True)
    try:
        STATE.mkdir(mode=0o700, exist_ok=True)
        STATE.chmod(0o700)
        write_new(journal, json.dumps(state).encode(), 0o600)
        journal_owned = True
        record('create_account')
        host.run([plan['tools']['useradd'], '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'capstone-labs'])
        account = pwd.getpwnam('capstone-labs')
        record('copy_verified_source_and_wheels')
        TARGET.mkdir(mode=0o755)
        for relative, data in plan['source'].items():
            install_file(TARGET / relative, plan['manifest'] if relative == 'cve_list.json' else data)
        for relative, data in plan['wheels'].items():
            install_file(TARGET / 'vendor' / relative, data)
        for path in TARGET.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
        record('write_root_configuration')
        CONFIG.mkdir(mode=0o750)
        os.chown(CONFIG, 0, account.pw_gid)
        # Ensure /opt and /etc use the same administrator-selected catalog.
        install_file(CONFIG / 'cve_list.json', plan['manifest'], 0o640, account.pw_gid)
        key = plan['key'] if plan['key'] is not None else (secrets.token_urlsafe(32) + '\n').encode()
        write_new(CONFIG / 'admin-token', key, 0o640, account.pw_gid)
        settings = {'OFFLINE_LABS_MANIFEST': str(CONFIG / 'cve_list.json'), 'OFFLINE_LABS_TOKEN_FILE': str(CONFIG / 'admin-token'),
                    'OFFLINE_LABS_SOCKET': '/run/capstone-offline-labs/control.sock', 'OFFLINE_LABS_STATE': str(STATE / 'runtime.json'),
                    'OFFLINE_LABS_UID': str(account.pw_uid), 'OFFLINE_LABS_GID': str(account.pw_gid),
                    'OFFLINE_LABS_DOCKER': plan['tools']['docker'], 'OFFLINE_LABS_ORIGINS': ','.join(summary(plan)['origins'])}
        install_file(CONFIG / 'settings.env', ''.join(k + '=' + v + '\n' for k, v in settings.items()).encode(), 0o640, account.pw_gid)
        record('install_guard')
        host.run(['/usr/bin/python3', '-B', str(TARGET / 'guard.py'), 'install'])
        record('create_dedicated_network')
        host.run(plan['docker'] + ['network', 'create', '--driver', 'bridge', '--label', 'io.capstone.offline-labs=1',
                 '--opt', 'com.docker.network.bridge.name=br-offline-labs', '--opt', 'com.docker.network.bridge.enable_icc=false', 'offline-labs'])
        record('install_and_start_console_services')
        for unit in UNITS:
            install_file(UNIT_DIRECTORY / unit, plan['source']['scripts/bootstrap-units/' + unit])
        host.run([plan['tools']['systemctl'], 'daemon-reload'])
        host.run([plan['tools']['systemctl'], 'enable', '--now', *UNITS])
        record('verify_loopback_readiness')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(30):
            try:
                with opener.open('http://127.0.0.1:18090/api/list', timeout=1) as response:
                    require(json.load(response) == json.loads(plan['manifest']), 'installed_catalog_mismatch')
                with opener.open('http://127.0.0.1:18090/api/status', timeout=5) as response:
                    status = json.load(response)
                    require(status.get('deployment_allowed') is True and status.get('safety_error') is None
                            and {item['cve_id'] for item in status['labs']} == {item['cve_id'] for item in plan['labs']},
                            'broker_or_isolation_not_ready')
                break
            except (OSError, ValueError):
                if attempt == 29:
                    raise Failure('console_readiness_failed') from None
                time.sleep(1)
        host.run(['/usr/bin/python3', '-B', str(TARGET / 'guard.py'), 'check'])
        require(host.run([plan['tools']['systemctl'], 'is-active', *UNITS]).splitlines() == ['active'] * len(UNITS),
                'installed_service_not_active')
        state.update(status='installed', files=files,
                     key_file={'path': str(CONFIG / 'admin-token'), 'mode': '0640', 'uid': 0, 'gid': account.pw_gid})
        record('complete')
        return {'ok': True, 'action': 'apply', **summary(plan), 'state_file': str(journal),
                'admin_key_file': str(CONFIG / 'admin-token'),
                'public_proxy_setup': 'separate; configure TLS/WAF routing for the selected origin',
                'generated_key_notice': 'If using a shared Wazuh key, provision it privately; no automatic account synchronization.'}
    except BaseException:
        state['status'] = 'failed_partial'
        if journal_owned:
            record(stage)
        print(json.dumps({'ok': False, 'action': 'apply', 'stage': stage, 'partial_installation': True,
                          'state_file': str(journal), 'automatic_cleanup': False}), file=sys.stderr)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='Read-only preflight; creates no files or containers')
    mode.add_argument('--apply', action='store_true', help='First installation after all preflight checks pass')
    parser.add_argument('wheel_directory')
    parser.add_argument('--manifest', help='Reviewed catalog; default is the source cve_list.json')
    parser.add_argument('--origin', help='Explicit HTTPS origin, without path; default is loopback only')
    parser.add_argument('--admin-key-file', help='Existing root:root 0600 plain UTF-8 key file; never pass the key itself')
    args = parser.parse_args(argv)
    try:
        plan = preflight(args)
        result = {'ok': True, 'action': 'check', 'read_only': True, **summary(plan)} if args.check else apply(plan)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        # Never interpolate paths, user-supplied key material, or command stderr.
        code = str(error) if isinstance(error, Failure) else type(error).__name__
        print(json.dumps({'ok': False, 'error': code}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
