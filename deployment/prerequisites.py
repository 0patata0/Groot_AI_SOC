#!/usr/bin/env python3
"""Install administrator-prepared, hashed offline artifacts; no network fetches.

Input is /opt/capstone-prereqs/artifacts.json, root-owned and not writable by
others. Package archives must already have vendor signature/provenance review.
The manifest is an administrator trust boundary, not a vendor signature.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import shutil
import tempfile

class Refused(Exception): pass

# Host OS packages only. The isolated vulnerable sudo lab has its own signed
# bundle and is deliberately outside the host artifact manifest.
HOST_SECURITY_MINIMUM = {'sudo': '1.9.15p5-3ubuntu5.24.04.4'}

def need(ok, reason):
    if not ok: raise Refused(reason)

def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'duplicate manifest key')
        out[key] = value
    return out

def safe(path, directory=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'invalid artifact path')
    for parent in reversed(path.parents):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'unsafe artifact parent')
    s = path.lstat()
    need(s.st_uid == 0 and not s.st_mode & 0o022, 'unsafe artifact ownership')
    need(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'unsafe artifact type')
    return path

def run(args, *, check=True, timeout=120, input=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('APT_', 'DOCKER_', 'LD_', 'PYTHON'))}
    env.update(PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C', DEBIAN_FRONTEND='noninteractive')
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout)
    need(not check or result.returncode == 0, 'offline command failed: ' + Path(args[0]).name)
    return result

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''): h.update(block)
    return h.hexdigest()

def security_baseline(doc, *, installed=False):
    prepared = {item['package']: item['version'] for item in doc['packages']}
    minimums = dict(HOST_SECURITY_MINIMUM)
    if doc.get('role') == 'siem':
        minimums['nginx'] = '1.24.0-2ubuntu7.18'
    for name, minimum in minimums.items():
        version = None if installed else prepared.get(name)
        if version is None:
            result = run(['dpkg-query', '-W', '-f=${Status}\t${Version}', name], check=False)
            fields = result.stdout.decode().split('\t')
            need(result.returncode == 0 and len(fields) == 2 and fields[0] == 'install ok installed',
                 'host security package missing: ' + name)
            version = fields[1]
        need(run(['dpkg', '--compare-versions', version, 'ge', minimum], check=False).returncode == 0,
             'host security baseline requires ' + name + '>=' + minimum)

def read_manifest(path, role):
    path = safe(path)
    need(path.stat().st_size <= 1024 * 1024, 'manifest too large')
    doc = json.loads(path.read_bytes(), object_pairs_hook=pairs)
    need(set(doc) == {'schema', 'role', 'packages', 'images'} and doc['schema'] == 1 and doc['role'] == role, 'manifest role/schema mismatch')
    need(isinstance(doc['packages'], list) and isinstance(doc['images'], list), 'artifact lists required')
    need(len(doc['packages']) <= 512 and len(doc['images']) <= 64, 'too many artifacts')
    seen = set()
    for kind in ('packages', 'images'):
        for item in doc[kind]:
            fields = {'file', 'sha256', 'package', 'version', 'architecture'} if kind == 'packages' else {'file', 'sha256', 'tag', 'image_id'}
            need(isinstance(item, dict) and set(item) == fields, 'invalid artifact fields')
            need(all(isinstance(v, str) for v in item.values()), 'artifact values must be strings')
            need(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9_.+-]|%3a)*\.(deb|tar)', item['file']) is not None, 'artifact must be a flat filename')
            need(item['file'] not in seen, 'duplicate artifact')
            seen.add(item['file'])
            need(re.fullmatch(r'[a-f0-9]{64}', item['sha256']) is not None, 'invalid SHA256')
            artifact = safe(path.parent / item['file'])
            need(artifact.stat().st_size > 0 and sha(artifact) == item['sha256'], 'artifact checksum mismatch')
            if kind == 'packages':
                need(item['file'].endswith('.deb') and item['architecture'] in ('amd64', 'all'), 'unsupported package architecture')
                need(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', item['package']) is not None, 'invalid package name')
                need(re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,128}', item['version']) is not None, 'invalid package version')
                metadata = run(['dpkg-deb', '-f', str(artifact), 'Package', 'Version', 'Architecture']).stdout.decode().splitlines()
                actual = dict(line.split(': ', 1) for line in metadata)
                need(actual == {'Package': item['package'], 'Version': item['version'], 'Architecture': item['architecture']}, 'package metadata mismatch')
            else:
                need(item['file'].endswith('.tar'), 'Docker save tar required')
                need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/:@-]+', item['tag']) is not None and item['tag'] not in ('-',), 'invalid image tag')
                need(re.fullmatch(r'sha256:[a-f0-9]{64}', item['image_id']) is not None, 'invalid image identity')
    for kind, key in (('packages', 'package'), ('images', 'tag')):
        vals = [x[key] for x in doc[kind]]
        need(len(vals) == len(set(vals)), 'duplicate artifact identity')
    return doc

def install(path, doc):
    pending = []
    for item in doc['packages']:
        r = run(['dpkg-query', '-W', '-f=${Status}\t${Version}', item['package']], check=False)
        current = r.stdout.decode().split('\t')
        if r.returncode == 0 and len(current) == 2 and current[0] == 'install ok installed':
            if current[1] == item['version']: continue
            need(run(['dpkg', '--compare-versions', current[1], 'gt', item['version']], check=False).returncode != 0, 'refuse package downgrade')
        pending.append(str(path.parent / item['file']))
    # APT --no-download also skips copying file: URIs into its cache. Stage
    # approved bytes under APT's canonical names, including escaped epochs.
    # The cache and empty source files disappear even when simulation fails.
    if pending:
        with tempfile.TemporaryDirectory(prefix='capstone-apt-offline-') as scratch:
            cache = Path(scratch)
            source_list = cache / 'empty.list'; source_list.touch(mode=0o600)
            source_parts = cache / 'sources.d'; source_parts.mkdir(mode=0o700)
            staged = []
            for item in doc['packages']:
                original = path.parent / item['file']
                if str(original) not in pending: continue
                original = safe(original)
                need(sha(original) == item['sha256'], 'package changed before staging')
                version = item['version'].replace(':', '%3a')
                target = cache / (item['package'] + '_' + version + '_' + item['architecture'] + '.deb')
                shutil.copyfile(original, target); target.chmod(0o600)
                need(sha(target) == item['sha256'], 'staged package checksum mismatch')
                staged.append(str(target))
            command = ['apt-get', '-o', 'Dir::Cache::archives=' + str(cache),
                       '-o', 'Dir::Etc::sourcelist=' + str(source_list),
                       '-o', 'Dir::Etc::sourceparts=' + str(source_parts),
                       '--no-download', '--no-remove', '--no-install-recommends', '-y', 'install', *staged]
            simulation = run(command[:1] + ['--simulate'] + command[1:], timeout=300).stdout.decode()
            approved = {item['package'] for item in doc['packages']}
            additions = set(re.findall(r'^Inst ([a-z0-9+.-]+)(?::amd64)? ', simulation, re.M))
            need(additions <= approved and not re.search(r'^Remv ', simulation, re.M), 'APT selected an unlisted package/removal')
            for filename in staged:
                item = next(x for x in doc['packages'] if x['package'] == Path(filename).name.split('_')[0])
                need(sha(Path(filename)) == item['sha256'], 'staged package changed before installation')
            if doc.get('role') == 'siem' and any(x['package'] == 'nginx' for x in doc['packages']):
                # The binary is for a separate unprivileged TLS unit. Prevent
                # the distro postinst from exposing its unrelated port-80 site.
                run(['systemctl', 'mask', 'nginx.service'])
            run(command, timeout=1800)
    for item in doc['packages']:
        r = run(['dpkg-query', '-W', '-f=${Status}\t${Version}', item['package']])
        need(r.stdout.decode() == 'install ok installed\t' + item['version'], 'installed package version mismatch')
    if doc['images']:
        run(['systemctl', 'start', 'docker'], timeout=120)
    for item in doc['images']:
        r = run(['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', '--format', '{{.Id}} {{.Os}} {{.Architecture}}', item['tag']], check=False)
        expected = (item['image_id'] + ' linux amd64').encode()
        if r.returncode != 0:
            # Recheck bytes immediately before Docker reads the trusted root-only file.
            archive = safe(path.parent / item['file'])
            need(sha(archive) == item['sha256'], 'image changed before import')
            run(['docker', '--host', 'unix:///var/run/docker.sock', 'load', '--input', str(archive)], timeout=1800)
            r = run(['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', '--format', '{{.Id}} {{.Os}} {{.Architecture}}', item['tag']])
        need(r.stdout.strip() == expected, 'existing/imported image identity mismatch; refuse retagging')

def fresh_host_guard(role):
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    need(release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04'
         and os.uname().machine == 'x86_64', 'Ubuntu 24.04 amd64 required')
    legacy = ('/opt/hermes-data', '/opt/suricata', '/var/lib/capstone-raw-operations',
              '/var/lib/capstone-raw-migration', '/home/groot_a/capstone',
              '/home/groot_b/capstone', '/opt/capstone-offline-labs')
    role_file = Path('/opt/capstone/role')
    managed = role_file.exists()
    if managed:
        safe(role_file)
        need(role_file.read_text().strip() == role, 'existing different role')
    else:
        for name in legacy:
            need(not Path(name).exists() and not Path(name).is_symlink(), 'legacy deployment; no package installation allowed')
        containers = Path('/var/lib/docker/containers')
        if containers.exists():
            safe(containers, directory=True)
            need(not any(containers.iterdir()), 'existing Docker containers; fresh host required')
        agent_keys = Path('/var/ossec/etc/client.keys')
        need(not agent_keys.is_symlink() and (not agent_keys.exists() or agent_keys.stat().st_size == 0),
             'already enrolled agent; fresh host required')
    # Existing completed deployments are never upgraded by this fresh installer.
    return managed


def verify_existing(doc):
    for item in doc['packages']:
        r = run(['dpkg-query', '-W', '-f=${Status}\t${Version}', item['package']])
        need(r.stdout.decode() == 'install ok installed\t' + item['version'], 'managed package drift; separate update required')
    for item in doc['images']:
        r = run(['docker', '--host', 'unix:///var/run/docker.sock', 'image', 'inspect', '--format', '{{.Id}} {{.Os}} {{.Architecture}}', item['tag']])
        need(r.stdout.strip() == (item['image_id'] + ' linux amd64').encode(), 'managed image drift; separate update required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply'))
    parser.add_argument('role', choices=('security', 'siem', 'service'))
    parser.add_argument('--manifest', type=Path, default=Path('/opt/capstone-prereqs/artifacts.json'))
    args = parser.parse_args()
    need(os.geteuid() == 0, 'root required')
    managed = fresh_host_guard(args.role)
    doc = read_manifest(args.manifest, args.role)
    security_baseline(doc)
    if managed:
        verify_existing(doc)
    if args.action == 'apply' and not managed:
        install(args.manifest, doc)
        security_baseline(doc, installed=True)
        if args.role == 'siem':
            # The indexer's documented minimum, scoped to this explicit admin bootstrap.
            current = int(Path('/proc/sys/vm/max_map_count').read_text())
            if current < 262144:
                target = Path('/etc/sysctl.d/90-capstone-indexer.conf')
                need(not target.exists() and not target.is_symlink(), 'existing indexer sysctl file needs review')
                safe(target.parent, directory=True)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, 'w') as f: f.write('vm.max_map_count=262144\n'); f.flush(); os.fsync(f.fileno())
                run(['sysctl', '-p', str(target)])
    print(json.dumps({'role': args.role, 'action': args.action, 'packages': len(doc['packages']), 'images': len(doc['images']), 'network_downloads': 0}))

if __name__ == '__main__':
    try: main()
    except (Refused, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('prerequisites: ' + (str(exc) if isinstance(exc, Refused) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
