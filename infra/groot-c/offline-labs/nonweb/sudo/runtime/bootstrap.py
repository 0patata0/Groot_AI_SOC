#!/usr/bin/env python3
"""Offline, fixed-profile sudo lab bootstrap. Never run history/ scripts."""
import argparse
import base64
import fcntl
import grp
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True

PROFILE = 'ubuntu24.04-amd64-sudo-rootless-29.8.1-v1'
USER = 'capstone-sudo'
UID = GID = 1991
SUBID = 231072
SUBCOUNT = 65536
SOURCE = Path(__file__).absolute().parent.parent
STATE = Path('/var/lib/capstone-sudo-bootstrap')
HOME = Path('/var/lib/capstone-sudo-runtime')
BIN = Path('/opt/capstone-sudo-rootless/29.8.1/bin')
CONFIG = Path('/etc/capstone-sudo-lab')
INSTALLED = Path('/opt/capstone-offline-labs/nonweb/sudo')
WEBSTATE = Path('/var/lib/capstone-offline-labs')
RECOVERY_BUNDLE = WEBSTATE / 'offline-sudo-20261022/bootstrap-bundle'
AA = Path('/etc/apparmor.d/opt.capstone-sudo-rootless.29.8.1.bin.rootlesskit')
DROPIN = Path('/etc/systemd/system/user@1991.service.d/capstone-sudo.conf')
USER_UNIT = HOME / '.config/systemd/user/capstone-sudo-docker.service'
PUB_UNIT = Path('/etc/systemd/system/capstone-sudo-status.service')
PUB_TIMER = Path('/etc/systemd/system/capstone-sudo-status.timer')
IMAGE = 'sha256:90fd1384894d26e34c2364b0ff8fb8bdb92a3e9ebc3df5dee29a61b68bfcab2a'
OCI_IMAGE = 'sha256:3a7816fe014c0a9e33b36b869dcd65b0e9662cb51f78271254b396502dd53ab7'
DEB_SHA = 'de4106cd19a5b9f8acac9e0ab5f40f218d3ac321cc58143e051baab064a5fb36'
PREP_SHA = '8c69d341e14798ec161d093031f0ae54473d7d089166c3eedba6bbda0ce042ff'
KEYRING_SHA = '80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31'
DOCKER_KEY = '9DC858229FC7DD38854AE2D88D81803C0EBFCD88'
EXTRAS = 'docker-ce-rootless-extras_29.8.1-1~ubuntu.24.04~noble_amd64.deb'
PINS = {
    'sudo-image.tar': ('db6a201143ad6372d24c91fed6e04f58206abad535941d39e6f5ad2ac79c5389', 28681728),
    'preparation.json': (PREP_SHA, 973),
    'sudo.deb': (DEB_SHA, 512808),
    'ubuntu-archive-keyring.gpg': (KEYRING_SHA, None),
    'docker.asc': ('1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570', 3817),
    'docker.InRelease': ('086b344e5b421b8fc0379a50b46a1842ae52833f1ea8361ff6ebd58778d0d729', 48475),
    'docker.Packages.gz': ('cabe5c7534eb6e767d8dcf244d8567b161190b53dbf5e9f411067a3f791f62d7', 86848),
    EXTRAS: ('02897501837b7ff4fec8248decdd5828b7d40d7f591021a91f29673e02d0f982', 10177712),
}
BINARY_PINS = {
    'rootlesskit': ('d3193fceef47224470db5e9b85ed5725fc046279dfc4fb504c9310350efe6b21', 26014296),
    'dockerd-rootless.sh': ('200203633806081a401e60aefdf68a8fa73fc7dc80aa854c52a69d47710a3488', 10704),
    'dockerd-rootless-setuptool.sh': ('1c9f0dc93ebb3d75255254ec760d26a912affba7f329ab8abffe8e25eb0b3f94', 16631),
}
INPUTS = set(PINS) | {'sudo.InRelease', 'sudo.Packages.xz'}
SOURCE_FILES = ('lab.py', 'publish.py', 'prepare.py', 'source.json', 'runtime/bootstrap.py',
                'runtime/templates/daemon.json', 'runtime/templates/capstone-sudo-docker.service',
                'runtime/templates/user@1991.service.d/capstone-sudo.conf',
                'runtime/templates/opt.capstone-sudo-rootless.29.8.1.bin.rootlesskit',
                'runtime/templates/capstone-sudo-status.service', 'runtime/templates/capstone-sudo-status.timer')
ENV = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
       'DOCKER_CONFIG': '/nonexistent', 'LANG': 'C', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}


class Rejected(Exception):
    pass


def require(value, code):
    if not value:
        raise Rejected(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def parsed(data):
    return json.loads(data, object_pairs_hook=unique)


def metadata(meta, owner=0, mode=None):
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == owner and meta.st_nlink == 1
            and not meta.st_mode & 0o022 and (mode is None or stat.S_IMODE(meta.st_mode) == mode),
            'untrusted_file')


def parents(path, owners=frozenset({0}), staging=False, missing=False):
    require(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    stage = None
    if staging:
        match = re.match(r'^(/var/tmp/capstone-bootstrap-[a-f0-9]{24})/source(?:/|$)', str(path))
        stage = Path(match.group(1)) if match else None
    for item in (path,) + tuple(path.parents):
        if stage is not None and item == Path('/var/tmp'):
            m = item.lstat()
            require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and stat.S_IMODE(m.st_mode) == 0o1777,
                    'untrusted_staging_anchor')
            continue
        try:
            m = item.lstat()
        except FileNotFoundError:
            require(missing, 'required_directory_missing')
            continue
        require(stat.S_ISDIR(m.st_mode) and m.st_uid in owners and not m.st_mode & 0o022,
                'untrusted_directory')
        if item == stage:
            require(stat.S_IMODE(m.st_mode) == 0o700, 'untrusted_staging_directory')


def read(path, maximum=64 * 1024 * 1024, mode=None, staging=False):
    parents(path.parent, staging=staging)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        metadata(m, mode=mode)
        require(m.st_size <= maximum, 'input_size_limit')
        data = stream.read(maximum + 1)
        require(len(data) <= maximum and len(data) == m.st_size, 'input_changed_or_oversized')
        return data


def executable(candidates):
    for name in candidates:
        path = Path(name)
        try:
            m = path.lstat()
        except FileNotFoundError:
            continue
        parents(path.parent)
        require(m.st_uid == 0, 'untrusted_executable')
        target = path.resolve(strict=True)
        parents(target.parent)
        m = target.lstat()
        metadata(m)
        require(m.st_mode & 0o111, 'executable_required')
        return str(path)
    raise Rejected('required_tool_missing_' + Path(candidates[0]).name.replace('-', '_'))


def run(args, timeout=30, input_file=None, maximum=1024 * 1024):
    # File-backed output bounds parent memory, including image-load diagnostics.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(list(map(str, args)), stdin=input_file or subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.DEVNULL, env=ENV, timeout=timeout)
        require(result.returncode == 0, 'command_failed_' + Path(str(args[0])).name.replace('-', '_'))
        require(os.fstat(output.fileno()).st_size <= maximum, 'command_output_limit')
        output.seek(0)
        return output.read(maximum + 1)


def module(name):
    read(SOURCE / (name + '.py'), staging=True)
    spec = importlib.util.spec_from_file_location('sudo_bootstrap_' + name, SOURCE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def config():
    return {'schema': 1, 'operator_uid': UID, 'image_id': IMAGE,
            'deb_sha256': DEB_SHA, 'preparation_sha256': PREP_SHA}


def source_inputs():
    return {name: read(SOURCE / name, staging=True) for name in SOURCE_FILES}


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'profile', 'files'}
            and type(value['schema']) is int and value['schema'] == 1 and value['profile'] == PROFILE,
            'bundle_manifest_schema')
    require(isinstance(value['files'], dict) and set(value['files']) == INPUTS, 'bundle_file_set')
    for item in value['files'].values():
        require(isinstance(item, dict) and set(item) == {'sha256', 'size'}
                and isinstance(item['sha256'], str) and re.fullmatch('[a-f0-9]{64}', item['sha256'])
                and type(item['size']) is int and 0 < item['size'] <= 64 * 1024 * 1024,
                'bundle_file_record')


def read_bundle(bundle):
    require((re.fullmatch(r'/opt/[A-Za-z0-9._/-]+', str(bundle)) or bundle == RECOVERY_BUNDLE)
            and '..' not in bundle.parts,
            'bundle_must_be_absolute_opt_directory')
    parents(bundle)
    manifest_bytes = read(bundle / 'manifest.json', 32768)
    manifest = parsed(manifest_bytes)
    validate_manifest(manifest)
    require({p.name for p in bundle.iterdir()} == INPUTS | {'manifest.json'}, 'unexpected_bundle_files')
    files = {}
    for name, expected in manifest['files'].items():
        data = read(bundle / name)
        require(sha(data) == expected['sha256'] and len(data) == expected['size'], 'bundle_digest_mismatch')
        if name in PINS:
            digest, size = PINS[name]
            require(sha(data) == digest and (size is None or size == len(data)), 'reviewed_artifact_pin_mismatch')
        files[name] = data
    prep = parsed(files['preparation.json'])
    require(prep.get('schema') == 1 and prep.get('package') == 'sudo'
            and prep.get('package_version') == '1.8.31-1ubuntu1' and prep.get('architecture') == 'amd64'
            and prep.get('deb_sha256') == DEB_SHA and prep.get('keyring_sha256') == KEYRING_SHA
            and prep.get('release_signature_verified') is True, 'pinned_preparation_mismatch')
    require(sha(files['sudo.InRelease']) == prep.get('inrelease_sha256')
            and sha(files['sudo.Packages.xz']) == prep.get('packages_sha256'), 'preparation_input_mismatch')
    return manifest, files


def docker_key(armor):
    lines = armor.decode('ascii').splitlines()
    require(lines and lines[0] == '-----BEGIN PGP PUBLIC KEY BLOCK-----', 'docker_key_armor')
    body = ''.join(x for x in lines[1:] if x and not x.startswith(('Version:', 'Comment:', '=', '-----')))
    binary = base64.b64decode(body, validate=True)
    offset, primaries = 0, []
    while offset < len(binary):
        tag = binary[offset]
        offset += 1
        require(tag & 128, 'docker_key_packet')
        if tag & 64:
            tag &= 63
            size = binary[offset]
            offset += 1
            if size == 255:
                size = int.from_bytes(binary[offset:offset + 4], 'big')
                offset += 4
            elif 192 <= size < 224:
                size = ((size - 192) << 8) + binary[offset] + 192
                offset += 1
            else:
                require(size < 192, 'docker_key_partial_packet')
        else:
            kind = tag & 3
            tag = (tag >> 2) & 15
            require(kind != 3, 'docker_key_indefinite_packet')
            count = (1, 2, 4)[kind]
            size = int.from_bytes(binary[offset:offset + count], 'big')
            offset += count
        packet = binary[offset:offset + size]
        offset += size
        require(len(packet) == size, 'docker_key_truncated')
        if tag == 6:
            require(packet and packet[0] == 4 and size < 65536, 'docker_key_version')
            primaries.append(hashlib.sha1(b'\x99' + size.to_bytes(2, 'big') + packet).hexdigest().upper())
    require(primaries == [DOCKER_KEY], 'docker_key_fingerprint')
    return binary


def verify_signatures(files, tools):
    prepare = module('prepare')
    with tempfile.TemporaryDirectory(prefix='capstone-sudo-signatures-') as temporary:
        work = Path(temporary)
        for name, data in files.items():
            if name not in ('sudo-image.tar', EXTRAS):
                (work / name).write_bytes(data)
        (work / 'docker.gpg').write_bytes(docker_key(files['docker.asc']))
        releases = {}
        for repo, key in (('sudo', 'ubuntu-archive-keyring.gpg'), ('docker', 'docker.gpg')):
            run([tools['gpgv'], '--homedir', work, '--keyring', work / key,
                 '--output', work / (repo + '.Release'), work / (repo + '.InRelease')])
            releases[repo] = (work / (repo + '.Release')).read_text()
        source = parsed(read(SOURCE / 'source.json', staging=True))
        prepare.release_entry(releases['sudo'], source, files['sudo.Packages.xz'])
        prepare.package_entry(files['sudo.Packages.xz'], source, files['sudo.deb'])
        release = prepare.fields(releases['docker'])
        require(release.get('Origin') == 'Docker' and release.get('Suite') == 'noble'
                and release.get('Codename', 'noble') == 'noble', 'docker_release_identity')
        selected = [x.split() for x in release.get('SHA256', '').splitlines()
                    if len(x.split()) == 3 and x.split()[2] == 'stable/binary-amd64/Packages.gz']
        require(selected == [[sha(files['docker.Packages.gz']), str(len(files['docker.Packages.gz'])),
                              'stable/binary-amd64/Packages.gz']], 'docker_signed_index_mismatch')
        with gzip.GzipFile(fileobj=io.BytesIO(files['docker.Packages.gz'])) as packed:
            plain = packed.read(128 * 1024 * 1024 + 1)
        require(len(plain) <= 128 * 1024 * 1024, 'docker_index_size_limit')
        entries = [prepare.fields(x) for x in plain.decode().split('\n\n') if x.strip()]
        found = [x for x in entries if x.get('Package') == 'docker-ce-rootless-extras'
                 and x.get('Version') == '5:29.8.1-1~ubuntu.24.04~noble' and x.get('Architecture') == 'amd64']
        require(len(found) == 1 and found[0].get('Filename') == 'dists/noble/pool/stable/amd64/' + EXTRAS
                and found[0].get('SHA256') == PINS[EXTRAS][0]
                and found[0].get('Size') == str(PINS[EXTRAS][1]), 'docker_signed_package_mismatch')
    # These exact, reviewed historical bytes establish artifact authenticity;
    # this is not a claim that an old Release is a current package index.
    return {'ubuntu_signature_verified': True, 'docker_signature_verified': True,
            'scope': 'pinned_historical_artifact_authenticity'}


def tar_members(archive, maximum=256):
    entries = archive.getmembers()
    require(len(entries) <= maximum, 'archive_member_limit')
    found = {}
    for item in entries:
        path = Path(item.name)
        require(not path.is_absolute() and '..' not in path.parts
                and (item.isfile() or item.isdir()) and item.name not in found,
                'archive_path_or_type')
        found[item.name] = item
    return found


def verify_oci(blob, manifest_id=OCI_IMAGE, image_id=IMAGE):
    with tarfile.open(fileobj=io.BytesIO(blob), mode='r:') as archive:
        entries = tar_members(archive)
        def member(name, maximum):
            item = entries.get(name)
            require(item is not None and item.isfile() and 0 <= item.size <= maximum, 'oci_member_missing_or_oversized')
            return archive.extractfile(item).read(maximum + 1)
        index = parsed(member('index.json', 65536))
        require(len(index.get('manifests', [])) == 1 and index['manifests'][0].get('digest') == manifest_id,
                'oci_index_identity')
        raw = member('blobs/sha256/' + manifest_id[7:], 65536)
        require('sha256:' + sha(raw) == manifest_id, 'oci_manifest_digest')
        manifest = parsed(raw)
        require(manifest.get('config', {}).get('digest') == image_id, 'oci_config_identity')
        raw = member('blobs/sha256/' + image_id[7:], 1024 * 1024)
        require('sha256:' + sha(raw) == image_id, 'oci_config_digest')
        image = parsed(raw)
        require(image.get('architecture') == 'amd64' and image.get('os') == 'linux', 'oci_platform')
        require(isinstance(manifest.get('layers'), list) and 0 < len(manifest['layers']) <= 32, 'oci_layers')
        for layer in manifest['layers']:
            digest = layer.get('digest', '')
            require(re.fullmatch(r'sha256:[a-f0-9]{64}', digest) and type(layer.get('size')) is int
                    and 0 < layer['size'] <= 64 * 1024 * 1024, 'oci_layer_record')
            raw = member('blobs/sha256/' + digest[7:], 64 * 1024 * 1024)
            require(len(raw) == layer['size'] and 'sha256:' + sha(raw) == digest, 'oci_layer_digest')
        diffids = image.get('rootfs', {}).get('diff_ids')
        require(isinstance(diffids, list) and len(diffids) == len(manifest['layers'])
                and all(isinstance(x, str) and re.fullmatch(r'sha256:[a-f0-9]{64}', x) for x in diffids),
                'oci_rootfs_diffids')
        return image, diffids


def extract_binaries(files, tools):
    with tempfile.TemporaryDirectory(prefix='capstone-sudo-extras-') as temporary:
        package = Path(temporary) / EXTRAS
        package.write_bytes(files[EXTRAS])
        data = run([tools['dpkg-deb'], '--fsys-tarfile', package], maximum=64 * 1024 * 1024)
        result = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            for item in archive.getmembers():
                name = item.name.removeprefix('./')
                if name in {'usr/bin/' + x for x in BINARY_PINS}:
                    require(item.isfile(), 'extras_binary_type')
                    name = Path(name).name
                    require(name not in result and item.size == BINARY_PINS[name][1], 'extras_binary_size_or_duplicate')
                    value = archive.extractfile(item).read(item.size + 1)
                    require(sha(value) == BINARY_PINS[name][0], 'extras_binary_pin')
                    result[name] = value
        require(set(result) == set(BINARY_PINS), 'extras_binary_set')
        return result


def initial_namespace():
    for name in ('uid_map', 'gid_map'):
        require(Path('/proc/self/' + name).read_text().split() == ['0', '0', '4294967295'],
                'initial_host_namespace_required')


def subids(data, managed=False):
    own = []
    for line in data.splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split(':')
        require(len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit(), 'invalid_subid_file')
        who, start, count = fields[0], int(fields[1]), int(fields[2])
        require(count > 0 and start > 0 and start + count <= 4294967295, 'invalid_subid_range')
        if who == USER:
            own.append((start, count))
        else:
            require(max(start, SUBID) >= min(start + count, SUBID + SUBCOUNT), 'subid_range_conflict')
    require(own == ([(SUBID, SUBCOUNT)] if managed else []), 'dedicated_subid_state_conflict')


def operator(args):
    return ['/usr/sbin/runuser', '-u', USER, '--', '/usr/bin/env', '-i',
            'PATH=/opt/capstone-sudo-rootless/29.8.1/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME=' + str(HOME), 'XDG_RUNTIME_DIR=/run/user/1991',
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus',
            'LANG=C', 'LC_ALL=C', 'PYTHONDONTWRITEBYTECODE=1'] + list(map(str, args))


def lab_command(action):
    require(action in ('up', 'verify'), 'fixed_lab_action_required')
    return parsed(run(operator(['/usr/bin/python3', '-B', INSTALLED / 'lab.py', action]), timeout=90))


def account(managed):
    if not managed:
        for lookup, key in ((pwd.getpwnam, USER), (pwd.getpwuid, UID), (grp.getgrnam, USER), (grp.getgrgid, GID)):
            try:
                lookup(key)
            except KeyError:
                continue
            raise Rejected('dedicated_identity_conflict')
        return
    user = pwd.getpwnam(USER)
    group = grp.getgrnam(USER)
    require(user.pw_uid == UID and user.pw_gid == GID and group.gr_gid == GID
            and user.pw_dir == str(HOME) and user.pw_shell == '/usr/sbin/nologin'
            and os.getgrouplist(USER, GID) == [GID], 'dedicated_identity_changed')
    status = run(['/usr/bin/passwd', '-S', USER]).decode().split()
    require(len(status) >= 2 and status[1] == 'L', 'dedicated_password_not_locked')


def discover_tools():
    result = {}
    for name in ('gpgv', 'dpkg-deb', 'dpkg-query', 'systemctl', 'loginctl', 'runuser', 'groupadd',
                 'useradd', 'apparmor_parser', 'newuidmap', 'newgidmap', 'ip', 'nsenter', 'prlimit', 'passwd'):
        result[name] = executable(['/usr/bin/' + name, '/usr/sbin/' + name])
    result['docker'] = module('lab').docker_binary()
    result['dockerd'] = executable(['/usr/local/bin/dockerd', '/usr/bin/dockerd'])
    for name in ('newuidmap', 'newgidmap'):
        require(stat.S_IMODE(Path(result[name]).stat().st_mode) == 0o4755, 'setuid_mapping_helper_required')
    return result


def host_check(tools, managed=False):
    require(os.geteuid() == 0 and os.getuid() == 0 and platform.system() == 'Linux'
            and platform.machine() in ('x86_64', 'amd64'), 'root_ubuntu_amd64_required')
    initial_namespace()
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04',
            'ubuntu_24_04_required')
    require(Path('/proc/1/comm').read_text().strip() == 'systemd', 'systemd_pid1_required')
    require({'cpu', 'memory', 'pids'} <= set(Path('/sys/fs/cgroup/cgroup.controllers').read_text().split()),
            'cgroup_v2_controllers_required')
    require(Path('/proc/sys/kernel/unprivileged_userns_clone').read_text().strip() == '1'
            and Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns').read_text().strip() == '1'
            and Path('/sys/module/apparmor/parameters/enabled').read_text().strip() == 'Y',
            'supported_apparmor_userns_policy_required')
    require(Path('/etc/apparmor.d/abi/4.0').is_file(), 'apparmor_abi_4_required')
    for package in ('uidmap', 'libsubid4', 'dbus-user-session'):
        record = run([tools['dpkg-query'], '-W', '-f=${Status}|${Version}', package]).decode()
        require(record.startswith('install ok installed|'), 'os_package_required_' + package.replace('-', '_'))
        if package in ('uidmap', 'libsubid4'):
            require(record == 'install ok installed|1:4.13+dfsg1-4ubuntu3.2', 'reviewed_uidmap_version_required')
    version = run([tools['dockerd'], '--version']).decode()
    require(re.search(r'\b29\.8\.1\b', version), 'docker_29_8_1_required')
    info = parsed(run([tools['docker'], '--host', 'unix:///run/docker.sock', 'info', '--format', '{{json .}}']))
    require(info.get('ServerVersion') == '29.8.1' and 'name=rootless' not in info.get('SecurityOptions', []),
            'existing_rootful_docker_29_8_1_required')
    account(managed)
    for name in ('subuid', 'subgid'):
        subids(read(Path('/etc') / name, 1024 * 1024).decode(), managed)
    return info


def fresh_paths():
    for path in (STATE, HOME, BIN.parent, CONFIG, INSTALLED, AA, DROPIN.parent, PUB_UNIT, PUB_TIMER,
                 Path('/var/lib/systemd/linger') / USER):
        parents(path.parent, missing=True)
        require(not path.exists() and not path.is_symlink(), 'existing_unmanaged_path_refused')
    parents(WEBSTATE, missing=True)
    receipt = WEBSTATE / 'nonweb-status.json'
    if receipt.exists() or receipt.is_symlink():
        publisher = module('publish')
        value = parsed(read(receipt, 16384, mode=0o600))
        publisher.existing_contract(value)
        require(all(x['status'] == 'needs_setup' for x in value['labs'].values()), 'existing_ready_receipt_refused')


def baseline(tools):
    files = {}
    for name in ('/etc/docker/daemon.json', '/etc/systemd/system/docker.service', '/usr/lib/systemd/system/docker.service'):
        path = Path(name)
        files[name] = sha(read(path)) if path.exists() else None
    return {'host_sudo': run([tools['dpkg-query'], '-W', '-f=${Status}|${Version}', 'sudo']).decode(),
            'rootful_files': files,
            'containers': run([tools['docker'], '--host', 'unix:///run/docker.sock', 'ps', '-a', '--no-trunc',
                               '--format', '{{.ID}}|{{.State}}']).decode().splitlines(),
            'sysctl': {name: Path('/proc/sys/kernel/' + name).read_text()
                       for name in ('unprivileged_userns_clone', 'apparmor_restrict_unprivileged_userns')}}


def mkdir(path, mode=0o755, owner=0, group=0):
    parents(path.parent, missing=True)
    # remote.sh uses umask 077. Explicitly make every new root-owned parent
    # traversable so the dedicated account can reach its root-owned binaries.
    for parent in reversed(path.parents):
        if not parent.exists():
            parent.mkdir(mode=0o755)
            os.chmod(parent, 0o755)
            os.chown(parent, 0, 0)
    path.mkdir(mode=mode, exist_ok=False)
    os.chmod(path, mode)
    os.chown(path, owner, group)


def write_new(path, data, mode=0o644, owner=0, group=0):
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), owner, group)
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def append_subids(path, original):
    # The dedicated account is the only new allocation. Recheck the opened
    # root-owned inode and its bytes instead of following a path a second time.
    parents(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r+b') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        metadata(os.fstat(stream.fileno()))
        require(stream.read(1024 * 1024 + 1) == original, 'subid_file_changed')
        subids(original.decode())
        stream.write((b'' if not original or original.endswith(b'\n') else b'\n')
                     + (USER + ':231072:65536\n').encode())
        stream.flush()
        os.fsync(stream.fileno())


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def managed_files():
    return [BIN / x for x in BINARY_PINS] + [CONFIG / 'config.json', CONFIG / 'daemon.json', AA, DROPIN,
                                            USER_UNIT, PUB_UNIT, PUB_TIMER, INSTALLED / 'lab.py', INSTALLED / 'publish.py',
                                            STATE / 'recovery/sudo-image.tar', STATE / 'recovery/SHA256SUMS',
                                            STATE / 'preparation.json', STATE / 'bundle-manifest.json', STATE / 'verification.json']


def file_record(path):
    parents(path.parent, owners={0, UID} if path == USER_UNIT else {0})
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        metadata(m)
        return {'sha256': sha(stream.read(32 * 1024 * 1024)), 'mode': stat.S_IMODE(m.st_mode)}


def read_managed(source):
    m = STATE.lstat()
    require(stat.S_ISDIR(m.st_mode) and m.st_uid == m.st_gid == 0
            and stat.S_IMODE(m.st_mode) == 0o700, 'untrusted_state_directory')
    value = parsed(read(STATE / 'manifest.json', 65536, mode=0o600))
    require(set(value) == {'schema', 'profile', 'state', 'source_sha256', 'files', 'image_id',
                           'bundle_manifest_sha256', 'baseline', 'completed_at'}
            and type(value['schema']) is int and value['schema'] == 1 and value['profile'] == PROFILE
            and value['state'] == 'complete' and value['image_id'] == IMAGE, 'incomplete_or_foreign_bootstrap_state')
    require(value['source_sha256'] == {k: sha(v) for k, v in source.items()}, 'managed_source_changed')
    require(set(value['files']) == {str(p) for p in managed_files()}, 'managed_file_set_changed')
    for path in managed_files():
        require(file_record(path) == value['files'][str(path)], 'managed_file_changed')
    return value


def verify_runtime(tools, source):
    read_managed(source)
    host_check(tools, managed=True)
    require(stat.S_IMODE(HOME.stat().st_mode) == 0o700 and HOME.stat().st_uid == UID, 'runtime_home_changed')
    run([tools['systemctl'], 'is-active', 'user@1991.service'])
    run(operator([tools['systemctl'], '--user', 'is-active', 'capstone-sudo-docker.service']))
    run(operator([tools['systemctl'], '--user', 'is-enabled', 'capstone-sudo-docker.service']))
    pid = int(run([tools['systemctl'], 'show', 'user@1991.service', '-p', 'MainPID', '--value']))
    require(pid > 0 and not (Path('/proc') / str(pid) / 'root/sys/kernel/security/apparmor').exists(),
            'dedicated_securityfs_view_required')
    docker = module('lab').Docker(UID)
    info = parsed(docker.run(['info', '--format', '{{json .}}']))
    module('lab').daemon_contract(info)
    require(info.get('ServerVersion') == '29.8.1' and info.get('Driver') == 'vfs'
            and info.get('DockerRootDir') == str(HOME / 'docker') and info.get('Containers') == 1,
            'dedicated_daemon_contract_changed')
    result = lab_command('verify')
    publisher = module('publish')
    publisher.ready_contract(result, config(), int(time.time()))
    # This is a fresh root attestation; it writes no web receipt and cannot start/stop.
    require(publisher.attest() == 'ready', 'root_runtime_attestation_failed')
    for action in ('is-active', 'is-enabled'):
        run([tools['systemctl'], action, 'capstone-sudo-status.timer'])
    receipt = parsed(read(WEBSTATE / 'nonweb-status.json', 16384, mode=0o600))
    publisher.existing_contract(receipt)
    require(receipt['labs'] == {'CVE-2021-3156': {'status': 'ready'}}
            and receipt['checked_at'] <= time.time() < receipt['expires_at'], 'fresh_ready_receipt_required')
    return result


def install(tools, source, manifest, files, binaries, diffids, verification):
    before = baseline(tools)
    mkdir(STATE, 0o700)
    write_new(STATE / 'manifest.json', json_bytes({'schema': 1, 'profile': PROFILE, 'state': 'preparing'}), 0o600)
    write_new(STATE / 'baseline.json', json_bytes(before), 0o600)
    write_new(STATE / 'bundle-manifest.json', json_bytes(manifest), 0o600)
    write_new(STATE / 'preparation.json', files['preparation.json'], 0o600)
    write_new(STATE / 'verification.json', json_bytes(verification), 0o600)
    lockfd = os.open(STATE / 'operation.lock', os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run([tools['groupadd'], '--gid', GID, USER])
        run([tools['useradd'], '--system', '--uid', UID, '--gid', GID, '--no-create-home',
             '--home-dir', HOME, '--shell', '/usr/sbin/nologin', '--no-log-init', USER])
        mkdir(HOME, 0o700, UID, GID)
        for name in ('subuid', 'subgid'):
            path = Path('/etc') / name
            original = read(path, 1024 * 1024)
            subids(original.decode())
            write_new(STATE / (name + '.before'), original, 0o600)
            append_subids(path, original)
        mkdir(BIN)
        for name, data in binaries.items():
            write_new(BIN / name, data, 0o755)
        mkdir(CONFIG)
        write_new(CONFIG / 'config.json', json_bytes(config()))
        write_new(CONFIG / 'daemon.json', source['runtime/templates/daemon.json'])
        write_new(AA, source['runtime/templates/opt.capstone-sudo-rootless.29.8.1.bin.rootlesskit'])
        run([tools['apparmor_parser'], '-r', AA])
        mkdir(DROPIN.parent)
        write_new(DROPIN, source['runtime/templates/user@1991.service.d/capstone-sudo.conf'])
        for path in (HOME / '.config', HOME / '.config/systemd', USER_UNIT.parent):
            path.mkdir(mode=0o700)
            os.chown(path, UID, GID)
        unit = source['runtime/templates/capstone-sudo-docker.service'].decode()
        unit = unit.replace('Environment=DOCKERD=/usr/local/bin/dockerd', 'Environment=DOCKERD=' + tools['dockerd'])
        write_new(USER_UNIT, unit)
        mkdir(INSTALLED)
        for name in ('lab.py', 'publish.py'):
            write_new(INSTALLED / name, source[name], 0o755)
        if not WEBSTATE.exists():
            mkdir(WEBSTATE, 0o700)
        write_new(PUB_UNIT, source['runtime/templates/capstone-sudo-status.service'])
        write_new(PUB_TIMER, source['runtime/templates/capstone-sudo-status.timer'])
        run([tools['systemctl'], 'daemon-reload'])
        run([tools['loginctl'], 'enable-linger', USER])
        run([tools['systemctl'], 'start', 'user@1991.service'])
        run(operator([tools['systemctl'], '--user', 'daemon-reload']))
        run(operator([tools['systemctl'], '--user', 'enable', '--now', 'capstone-sudo-docker.service']), timeout=120)
        mkdir(STATE / 'recovery', 0o700)
        archive = STATE / 'recovery/sudo-image.tar'
        write_new(archive, files['sudo-image.tar'], 0o600)
        write_new(STATE / 'recovery/SHA256SUMS', PINS['sudo-image.tar'][0] + '  sudo-image.tar\n', 0o600)
        with archive.open('rb') as stream:
            run(operator([tools['docker'], '--host', 'unix:///run/user/1991/docker.sock', 'image', 'load']),
                timeout=300, input_file=stream)
        image = parsed(run(operator([tools['docker'], '--host', 'unix:///run/user/1991/docker.sock',
                                     'image', 'inspect', IMAGE])))[0]
        module('lab').image_contract(image, config())
        require(image.get('RootFS', {}).get('Layers') == diffids, 'loaded_image_diffids_mismatch')
        result = lab_command('up')
        module('publish').ready_contract(result, config(), int(time.time()))
        run([tools['systemctl'], 'start', 'capstone-sudo-status.service'], timeout=110)
        run([tools['systemctl'], 'enable', '--now', 'capstone-sudo-status.timer'])
        require(baseline(tools) == before, 'protected_host_state_changed')
        value = {'schema': 1, 'profile': PROFILE, 'state': 'complete', 'image_id': IMAGE,
                 'source_sha256': {k: sha(v) for k, v in source.items()},
                 'files': {str(p): file_record(p) for p in managed_files()}, 'baseline': before,
                 'bundle_manifest_sha256': sha(json_bytes(manifest)), 'completed_at': int(time.time())}
        write_new(STATE / 'manifest.next', json_bytes(value), 0o600)
        os.replace(STATE / 'manifest.next', STATE / 'manifest.json')
        try:
            verify_runtime(tools, source)
        except Exception:
            failed = dict(value, state='verification_failed')
            write_new(STATE / 'manifest.failed', json_bytes(failed), 0o600)
            os.replace(STATE / 'manifest.failed', STATE / 'manifest.json')
            raise
        return result


def execute(action, bundle):
    require(action in ('check', 'apply', 'verify'), 'invalid_action')
    require(os.geteuid() == 0 and os.getuid() == 0, 'root_required')
    source = source_inputs()
    tools = discover_tools()
    if STATE.exists() or STATE.is_symlink():
        result = verify_runtime(tools, source)
        return {'schema': 1, 'profile': PROFILE, 'action': action, 'status': 'ready',
                'managed_existing': True, 'environment_ready': True, 'attack_tested': False,
                'host_scenario_verified': False, 'container_id': result['container_id']}
    require(action != 'verify', 'managed_installation_missing')
    host_check(tools)
    fresh_paths()
    manifest, files = read_bundle(bundle)
    verification = verify_signatures(files, tools)
    raw_image, diffids = verify_oci(files['sudo-image.tar'])
    module('lab').image_contract({'Id': IMAGE, 'Os': raw_image['os'], 'Architecture': raw_image['architecture'],
                                  'Config': raw_image['config']}, config())
    binaries = extract_binaries(files, tools)
    if action == 'check':
        return {'schema': 1, 'profile': PROFILE, 'action': action, 'status': 'prerequisites_ready',
                'managed_existing': False, 'environment_ready': False, 'attack_tested': False,
                'host_scenario_verified': False, 'bundle_manifest_sha256': sha(json_bytes(manifest))}
    # Repeat ownership/conflict checks immediately before the first persistent write.
    host_check(tools)
    fresh_paths()
    result = install(tools, source, manifest, files, binaries, diffids, verification)
    return {'schema': 1, 'profile': PROFILE, 'action': action, 'status': 'ready',
            'managed_existing': False, 'environment_ready': True, 'attack_tested': False,
            'host_scenario_verified': False, 'container_id': result['container_id']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for mode in ('check', 'apply', 'verify'):
        modes.add_argument('--' + mode, action='store_const', const=mode, dest='action')
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(execute(args.action, args.bundle), sort_keys=True))
        return 0
    except (Rejected, OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError, tarfile.TarError):
        error = sys.exc_info()[1]
        code = str(error) if isinstance(error, Rejected) else 'bootstrap_verification_unavailable'
        print(json.dumps({'schema': 1, 'profile': PROFILE, 'action': args.action, 'status': 'needs_setup',
                          'environment_ready': False, 'attack_tested': False, 'host_scenario_verified': False,
                          'error': code}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
