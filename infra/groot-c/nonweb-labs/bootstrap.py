#!/usr/bin/env python3
"""Offline Redis/Samba extension bootstrap. Check never loads images or starts containers."""
import argparse
import ast
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import tarfile
import time

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('capstone_nonweb_runtime', Path(__file__).with_name('runtime.py'))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)
RECEIPT = r.STATE / 'bootstrap.json'
UNIT_ROOT = Path('/etc/systemd/system')
GUARD_UNIT = 'capstone-nonweb-guard.service'
PUB_UNIT = 'capstone-nonweb-status.service'
PUB_TIMER = 'capstone-nonweb-status.timer'
TERMINAL_UNIT = 'capstone-nonweb-terminal.service'
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024


def units(source):
    return {
        GUARD_UNIT: b'''[Unit]\nDescription=Fixed nonweb lab host and forwarding isolation\nAfter=docker.service\nRequires=docker.service\nBefore=capstone-nonweb-terminal.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -IB /opt/capstone-nonweb-labs/runtime.py guard-install\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n''',
        PUB_UNIT: b'''[Unit]\nDescription=Publish verified Redis and Samba environment status\nAfter=docker.service capstone-nonweb-guard.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -IB /opt/capstone-nonweb-labs/publish.py\nUMask=0077\nTimeoutStartSec=120\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=/var/lib/capstone-nonweb-labs /run/capstone-nonweb-labs\n''',
        PUB_TIMER: b'''[Unit]\nDescription=Refresh nonweb lab status each minute\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=60s\nAccuracySec=1s\nUnit=capstone-nonweb-status.service\n[Install]\nWantedBy=timers.target\n''',
        TERMINAL_UNIT: source['terminal.service'],
    }


def validate_manifest(value):
    r.require(isinstance(value, dict) and set(value) == {'schema', 'profile', 'images', 'provenance_sha256'}
              and type(value['schema']) is int and value['schema'] == 1 and value['profile'] == r.PROFILE
              and isinstance(value['provenance_sha256'], str)
              and re.fullmatch('[a-f0-9]{64}', value['provenance_sha256']), 'bundle_manifest_schema')
    r.require(isinstance(value['images'], dict) and set(value['images']) == set(r.LABS), 'bundle_image_set')
    for lab, item in value['images'].items():
        r.require(isinstance(item, dict) and set(item) == {'image_id', 'archive', 'archive_sha256',
                  'archive_size', 'software', 'version', 'start_sha256', 'verifier_sha256'}, 'bundle_image_record')
        r.require(item['software'] == r.LABS[lab]['software'] and item['version'] == r.LABS[lab]['version']
                  and item['archive'] == lab + '-image.tar'
                  and isinstance(item['image_id'], str) and re.fullmatch('sha256:[a-f0-9]{64}', item['image_id'])
                  and type(item['archive_size']) is int and 0 < item['archive_size'] <= MAX_ARCHIVE
                  and all(isinstance(item[k], str) and re.fullmatch('[a-f0-9]{64}', item[k])
                          for k in ('archive_sha256', 'start_sha256', 'verifier_sha256')), 'bundle_image_pin')
    r.require(value['images']['redis']['image_id'] != value['images']['samba']['image_id'], 'bundle_duplicate_image')
    return value


def stream_hash(stream):
    value = hashlib.sha256()
    total = 0
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        total += len(block)
        r.require(total <= MAX_ARCHIVE, 'archive_expanded_size_limit')
        value.update(block)
    return value.hexdigest()


def validate_archive(stream, image_id):
    """Read Docker save/OCI blobs without extracting paths or trusting archive tags."""
    stream.seek(0)
    with tarfile.open(fileobj=stream, mode='r:*') as archive:
        members = {}
        for item in archive:
            name = PurePosixPath(item.name)
            r.require(not name.is_absolute() and '..' not in name.parts and str(name) not in ('', '.')
                      and (item.isfile() or item.isdir()) and not item.issym() and not item.islnk()
                      and item.name not in members and item.size <= MAX_ARCHIVE, 'unsafe_archive_member')
            members[item.name] = item
        def blob(name, maximum=4 * 1024 * 1024):
            r.require(name in members and members[name].isfile() and members[name].size <= maximum,
                      'archive_blob_missing_or_large')
            with archive.extractfile(members[name]) as source:
                return source.read(maximum + 1)
        manifest = r.parsed(blob('manifest.json'))
        r.require(isinstance(manifest, list) and len(manifest) == 1 and isinstance(manifest[0], dict), 'archive_manifest')
        entry = manifest[0]
        r.require(set(entry) <= {'Config', 'RepoTags', 'Layers', 'LayerSources'}
                  and not entry.get('RepoTags') and isinstance(entry.get('Config'), str)
                  and isinstance(entry.get('Layers'), list) and 0 < len(entry['Layers']) <= 128,
                  'archive_tags_or_layers')
        config_raw = blob(entry['Config'])
        config_digest = r.digest(config_raw)
        config = r.parsed(config_raw)
        r.require(config.get('os') == 'linux' and config.get('architecture') == 'amd64'
                  and not config.get('config', {}).get('Volumes'), 'archive_platform_or_volumes')
        diffs = config.get('rootfs', {}).get('diff_ids')
        r.require(config.get('rootfs', {}).get('type') == 'layers' and isinstance(diffs, list)
                  and len(diffs) == len(entry['Layers']), 'archive_rootfs')
        compressed = []
        for name, expected in zip(entry['Layers'], diffs):
            r.require(isinstance(name, str) and name in members and members[name].isfile()
                      and isinstance(expected, str) and re.fullmatch('sha256:[a-f0-9]{64}', expected),
                      'archive_layer')
            with archive.extractfile(members[name]) as layer:
                actual_blob = stream_hash(layer)
            with archive.extractfile(members[name]) as layer:
                magic = layer.read(2); layer.seek(0)
                if magic == b'\x1f\x8b':
                    with gzip.GzipFile(fileobj=layer) as uncompressed:
                        actual_diff = stream_hash(uncompressed)
                else:
                    actual_diff = stream_hash(layer)
            r.require('sha256:' + actual_diff == expected, 'archive_layer_diff_mismatch')
            compressed.append(('sha256:' + actual_blob, members[name].size))
        reachable = {'sha256:' + config_digest}
        def oci(raw, depth=0):
            r.require(depth <= 3, 'archive_oci_depth')
            document = r.parsed(raw)
            reachable.add('sha256:' + r.digest(raw))
            if 'manifests' in document:
                descriptors = document['manifests']
                r.require(document.get('schemaVersion') == 2 and isinstance(descriptors, list)
                          and len(descriptors) == 1, 'archive_multiple_oci_images')
                descriptor = descriptors[0]
                expected = descriptor.get('digest')
                r.require(isinstance(expected, str) and re.fullmatch('sha256:[a-f0-9]{64}', expected),
                          'archive_oci_descriptor')
                nested = blob('blobs/sha256/' + expected[7:])
                r.require('sha256:' + r.digest(nested) == expected and len(nested) == descriptor.get('size'),
                          'archive_oci_descriptor_hash')
                oci(nested, depth + 1)
                return
            r.require(document.get('schemaVersion') == 2
                      and document.get('config', {}).get('digest') == 'sha256:' + config_digest
                      and document.get('config', {}).get('size') == len(config_raw), 'archive_oci_config')
            layers = document.get('layers')
            r.require(isinstance(layers, list)
                      and [(x.get('digest'), x.get('size')) for x in layers] == compressed,
                      'archive_oci_layers')
        # Docker's containerd importer can use index.json rather than manifest.json.
        # Bind both descriptions to exactly the same single config/layer chain.
        if 'index.json' in members:
            oci(blob('index.json'))
        elif image_id != 'sha256:' + config_digest:
            raw = blob('blobs/sha256/' + image_id.removeprefix('sha256:'))
            r.require('sha256:' + r.digest(raw) == image_id, 'archive_image_id')
            oci(raw)
        r.require(image_id in reachable, 'archive_image_id')
    return config_digest


def read_bundle(bundle):
    bundle = Path(bundle)
    r.require(bundle.is_absolute() and re.fullmatch(r'/opt/[A-Za-z0-9._/-]+', str(bundle))
              and '..' not in bundle.parts, 'bundle_must_be_opt_directory')
    r.parents(bundle)
    raw = r.read(bundle / 'manifest.json', 65536)
    manifest = validate_manifest(r.parsed(raw))
    r.require({p.name for p in bundle.iterdir()} == {'manifest.json', 'provenance.json',
              'redis-image.tar', 'samba-image.tar'}, 'unexpected_bundle_files')
    provenance = r.read(bundle / 'provenance.json', 2 * 1024 * 1024)
    r.require(r.digest(provenance) == manifest['provenance_sha256'] and isinstance(r.parsed(provenance), dict),
              'provenance_digest')
    for item in manifest['images'].values():
        path = bundle / item['archive']
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            m = os.fstat(stream.fileno())
            r.require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1
                      and not m.st_mode & 0o022 and m.st_size == item['archive_size'], 'unsafe_archive')
            r.require(stream_hash(stream) == item['archive_sha256'], 'archive_sha256')
            validate_archive(stream, item['image_id'])
    return manifest, r.digest(raw)


def source_inputs(source_root):
    r.parents(source_root, staging=True)
    result = {name: r.read(source_root / name, staging=True) for name in r.SOURCE_FILES}
    for name, value in result.items():
        if name.endswith('.py'):
            ast.parse(value, filename=name)
    r.require(b'/opt/capstone-nonweb-labs/terminal_server.py' in result['terminal.service'], 'terminal_unit_path')
    return result


def configuration(manifest, source):
    return {'schema': 1, 'profile': r.PROFILE,
            'images': {lab: {key: value[key] for key in ('image_id', 'start_sha256', 'verifier_sha256')}
                       for lab, value in manifest['images'].items()},
            'source_sha256': {name: r.digest(data) for name, data in source.items()}}


def platform_check(docker, account_required=True):
    r.require(os.geteuid() == 0 and sys.platform == 'linux' and platform.machine() == 'x86_64'
              and sys.version_info >= (3, 12), 'ubuntu24_amd64_python312_root_required')
    data = Path('/etc/os-release').read_text()
    r.require(re.search(r'^ID="?ubuntu"?$', data, re.M) and re.search(r'^VERSION_ID="?24\.04"?$', data, re.M),
              'ubuntu24_required')
    for name in ('nft', 'systemctl', 'systemd-analyze', 'bash', 'ip'):
        r.executable(name)
    version = docker.json('version', '--format', '{{json .Server}}')
    r.require(re.match(r'(?:2[89]|[3-9][0-9])\.', version.get('Version', '')), 'docker28_or_later_required')
    info = docker.json('info', '--format', '{{json .}}')
    r.require(info.get('OSType') == 'linux' and not any('rootless' in str(x) for x in info.get('SecurityOptions', [])),
              'system_docker_required')
    docker.run('compose', 'version')
    # The peer-checked terminal service uses the existing console account; never create a new login.
    import pwd
    try:
        user = pwd.getpwnam('capstone-labs')
    except KeyError:
        r.require(not account_required, 'console_account_required')
    else:
        r.require(user.pw_uid > 0 and user.pw_gid > 0 and user.pw_shell in ('/usr/sbin/nologin', '/sbin/nologin'),
                  'console_account_conflict')


def check_vacant(docker):
    for path in (r.BASE, r.CONFIG.parent, r.STATE, *(UNIT_ROOT / n for n in (GUARD_UNIT, PUB_UNIT, PUB_TIMER, TERMINAL_UNIT))):
        r.require(not path.exists() and not path.is_symlink(), 'unmanaged_install_path')
        parent = path.parent
        while not parent.exists():
            parent = parent.parent
        r.parents(parent)
    r.require(not docker.ids('container', 'ls', '-aq', '--no-trunc', '--filter',
                             'label=com.docker.compose.project=' + r.PROJECT), 'existing_project')
    r.require(not docker.ids('network', 'ls', '-q', '--no-trunc', '--filter',
                             'label=com.docker.compose.project=' + r.PROJECT), 'existing_project_network')
    links = r.parsed(r.command([r.executable('ip'), '-j', 'link', 'show']).stdout)
    r.require(not any(x.get('ifname') in {'br-cap-redis', 'br-cap-samba'} for x in links), 'bridge_collision')
    for lab in r.LABS:
        r.require(not docker.ids('container', 'ls', '-aq', '--no-trunc', '--filter',
                                 'name=^/capstone-nonweb-' + lab + '$'), 'container_name_collision')
        r.require(not docker.ids('network', 'ls', '-q', '--no-trunc', '--filter',
                                 'name=^' + r.network_name(lab) + '$'), 'network_name_collision')
    tables = r.parsed(r.command([r.executable('nft'), '-j', 'list', 'tables']).stdout)
    r.require(not any(x.get('table', {}).get('name') == r.TABLE for x in tables.get('nftables', [])), 'guard_table_collision')
    r.command([r.executable('nft'), '--check', '-f', '-'], data=r.guard_text())


def installed_state():
    if not RECEIPT.exists() and not RECEIPT.is_symlink():
        return None
    value = r.parsed(r.read(RECEIPT, 65536, mode=0o600))
    r.require(isinstance(value, dict) and value.get('schema') == 1 and value.get('state') == 'complete',
              'partial_install_requires_operator_review')
    return value


def verify_publication(require_stopped=False):
    value = r.parsed(r.read(r.STATE / 'status.json', 16384, mode=0o600))
    now = int(time.time())
    r.require(isinstance(value, dict) and set(value) == {'schema', 'checked_at', 'expires_at', 'labs'}
              and type(value['schema']) is int and value['schema'] == 1
              and type(value['checked_at']) is int and type(value['expires_at']) is int
              and value['checked_at'] <= now < value['expires_at']
              and 0 < value['expires_at'] - value['checked_at'] <= 300
              and isinstance(value['labs'], dict)
              and set(value['labs']) == {x['cve_id'] for x in r.LABS.values()}, 'publication_invalid_or_stale')
    allowed = {'needs_setup'} if require_stopped else {'ready', 'needs_setup'}
    r.require(all(isinstance(item, dict) and set(item) == {'status'}
                  and item['status'] in allowed for item in value['labs'].values()), 'publication_state_invalid')


def verify_installed(config, source, manifest_sha, docker):
    state = installed_state()
    r.require(state and state.get('config_sha256') == r.digest(r.json_bytes(config))
              and state.get('bundle_manifest_sha256') == manifest_sha, 'installed_profile_changed')
    r.require(r.load_config() == config, 'installed_config_changed')
    for name, data in units(source).items():
        r.require(r.read(UNIT_ROOT / name) == data, 'installed_unit_changed')
    for item in config['images'].values():
        r.require(r.image_present(docker, item['image_id']), 'installed_image_missing')
    r.guard()
    r.inventory(docker, config)
    for unit in (GUARD_UNIT, PUB_TIMER, TERMINAL_UNIT):
        r.command([r.executable('systemctl'), 'is-enabled', '--quiet', unit])
        r.command([r.executable('systemctl'), 'is-active', '--quiet', unit])
    verify_publication()
    return {'schema': 1, 'state': 'complete', 'profile': r.PROFILE, 'environment_only': True,
            'attack_tested': False, 'images': {lab: x['image_id'] for lab, x in config['images'].items()}}


def apply(bundle, manifest, manifest_sha, source, config, docker):
    phase = 'create_directories'
    r.BASE.mkdir(mode=0o755)
    r.CONFIG.parent.mkdir(mode=0o700)
    r.STATE.mkdir(mode=0o700)
    intent = {'schema': 1, 'state': 'partial', 'phase': phase,
              'bundle_manifest_sha256': manifest_sha, 'config_sha256': r.digest(r.json_bytes(config))}
    r.write(RECEIPT, r.json_bytes(intent))
    try:
        phase = 'install_source'
        for name, data in source.items():
            r.write(r.BASE / name, data, 0o644)
        r.write(r.CONFIG, r.json_bytes(config))
        phase = 'load_images'
        for lab, item in manifest['images'].items():
            if not r.image_present(docker, item['image_id']):
                # Revalidate the complete root-owned bundle immediately before Docker consumes it.
                repeated, repeated_sha = read_bundle(bundle)
                r.require(repeated == manifest and repeated_sha == manifest_sha, 'bundle_changed_before_load')
                fd = os.open(bundle / item['archive'], os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, 'rb') as stream:
                    p = subprocess.run([docker.binary, '--host', 'unix:///var/run/docker.sock', 'image', 'load'],
                                       stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       env=r.ENV, timeout=300)
                r.require(p.returncode == 0, 'image_load_failed')
            r.require(r.image_present(docker, item['image_id']), 'loaded_image_id_mismatch')
        phase = 'install_units'
        for name, data in units(source).items():
            r.write(UNIT_ROOT / name, data, 0o644)
        r.command([r.executable('systemd-analyze'), 'verify', *[str(UNIT_ROOT / name) for name in units(source)]])
        r.command([r.executable('systemctl'), 'daemon-reload'])
        phase = 'activate_guard'
        r.command([r.executable('systemctl'), 'enable', '--now', GUARD_UNIT])
        r.guard()
        # The caller still holds operation_lock. The publisher needs that same
        # lock, so it must only run after this installation critical section.
        intent.update(phase='initial_publication_pending')
        r.write(RECEIPT, r.json_bytes(intent))
        return intent
    except Exception:
        intent.update(state='partial', phase=phase)
        r.write(RECEIPT, r.json_bytes(intent))
        raise


def activate(intent, config, source, manifest_sha, docker):
    """Called outside operation_lock; no daemon/timer races with first publication."""
    phase = 'initial_publication'
    try:
        intent.update(phase=phase)
        r.write(RECEIPT, r.json_bytes(intent))
        r.command([r.executable('systemctl'), 'start', PUB_UNIT], timeout=120)
        verify_publication(require_stopped=True)
        phase = 'activate_terminal_and_publisher'
        intent.update(phase=phase)
        r.write(RECEIPT, r.json_bytes(intent))
        r.command([r.executable('systemctl'), 'enable', '--now', TERMINAL_UNIT, PUB_TIMER])
        intent.update(state='complete', phase='complete', installed_at=int(time.time()))
        r.write(RECEIPT, r.json_bytes(intent))
        return verify_installed(config, source, manifest_sha, docker)
    except Exception:
        intent.update(state='partial', phase=phase)
        r.write(RECEIPT, r.json_bytes(intent))
        raise


def main():
    p = argparse.ArgumentParser()
    mode = p.add_mutually_exclusive_group(required=True)
    for name in ('check', 'apply', 'verify'):
        mode.add_argument('--' + name, action='store_true')
    p.add_argument('--bundle', type=Path, default=Path('/opt/capstone-prereqs/nonweb'))
    p.add_argument('--source-root', type=Path, default=Path(__file__).absolute().parent)
    args = p.parse_args()
    source = source_inputs(args.source_root)
    manifest, manifest_sha = read_bundle(args.bundle)
    config = configuration(manifest, source)
    docker = r.Docker()
    platform_check(docker, account_required=not args.check)
    current = installed_state()
    if current:
        result = verify_installed(config, source, manifest_sha, docker)
    else:
        r.require(not args.verify, 'not_installed')
        check_vacant(docker)
        if args.check:
            result = {'schema': 1, 'state': 'checked', 'images_loaded': False,
                      'containers_created': 0, 'service_started': False, 'attack_tested': False}
        else:
            with r.operation_lock():
                check_vacant(docker)
                intent = apply(args.bundle, manifest, manifest_sha, source, config, docker)
            result = activate(intent, config, source, manifest_sha, docker)
    print(json.dumps({'ok': True, **result}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (r.Rejected, OSError, ValueError, KeyError, TypeError, SyntaxError, subprocess.TimeoutExpired, tarfile.TarError):
        error = sys.exc_info()[1]
        print(json.dumps({'ok': False, 'error': str(error) if isinstance(error, r.Rejected) else 'bootstrap_failed',
                          'partial_install_not_automatically_removed': True}))
        raise SystemExit(1)
