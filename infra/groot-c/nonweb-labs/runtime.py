#!/usr/bin/env python3
"""Root-only fixed Redis/Samba lifecycle. No user-selected image, mount or command."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
BASE = Path('/opt/capstone-nonweb-labs')
CONFIG = Path('/etc/capstone-nonweb-labs/config.json')
STATE = Path('/var/lib/capstone-nonweb-labs')
RUN = Path('/run/capstone-nonweb-labs')
PROJECT = 'capstone-nonweb-labs'
PROFILE = 'capstone-nonweb-v1'
TABLE = 'capstone_nonweb'
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent',
       'DOCKER_CONFIG': '/nonexistent', 'LANG': 'C', 'LC_ALL': 'C'}
SOURCE_FILES = ('lab.sh', 'compose.yaml', 'runtime.py', 'bootstrap.py', 'publish.py', 'README.md',
                'terminal_server.py', 'terminal.service', 'sudo_terminal.py')
LABS = {
    'redis': {'cve_id': 'CVE-2022-0543', 'software': 'Redis', 'version': '5.0.7',
              'package_version': '5:5.0.7-2', 'user': '65534:65534', 'memory': 268435456,
              'cpus': 500000000, 'pids': 64, 'caps': [],
              'tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=32m,mode=1777',
                        '/run': 'rw,nosuid,nodev,noexec,size=16m,mode=1777',
                        '/var/lib/redis': 'rw,nosuid,nodev,noexec,size=64m,mode=1777'}},
    'samba': {'cve_id': 'CVE-2017-7494', 'software': 'Samba', 'version': '4.6.3',
              'package_version': 'source-4.6.3', 'user': '0:0', 'memory': 536870912,
              'cpus': 1000000000, 'pids': 128, 'caps': ['CHOWN', 'DAC_OVERRIDE', 'SETUID', 'SETGID'],
              'tmpfs': {'/tmp': 'rw,nosuid,nodev,noexec,size=32m,mode=1777',
                        '/run': 'rw,nosuid,nodev,noexec,size=16m,mode=1777',
                        '/var/lib/samba': 'rw,nosuid,nodev,noexec,size=32m,mode=1777',
                        '/var/cache/samba': 'rw,nosuid,nodev,noexec,size=32m,mode=1777',
                        '/var/log/samba': 'rw,nosuid,nodev,noexec,size=16m,mode=1777',
                        '/share': 'rw,nosuid,nodev,size=64m,mode=1777'}},
}


class Rejected(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Rejected(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def parsed(data):
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise Rejected('invalid_json') from None


def parents(path, staging=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    stage = re.match(r'^(/var/tmp/capstone-bootstrap-[a-f0-9]{24})/source(?:/|$)', str(path)) if staging else None
    for item in (path,) + tuple(path.parents):
        m = item.lstat()
        if stage and item == Path('/var/tmp'):
            require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and stat.S_IMODE(m.st_mode) == 0o1777,
                    'unsafe_staging_anchor')
        else:
            require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022,
                    'unsafe_parent')
        if stage and str(item) == stage.group(1):
            require(stat.S_IMODE(m.st_mode) == 0o700, 'unsafe_staging_directory')


def read(path, maximum=2 * 1024 * 1024, staging=False, mode=None):
    path = Path(path)
    parents(path.parent, staging)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1
                and not m.st_mode & 0o022 and m.st_size <= maximum
                and (mode is None or stat.S_IMODE(m.st_mode) == mode), 'unsafe_file')
        data = stream.read(maximum + 1)
        require(len(data) == m.st_size and len(data) <= maximum, 'changed_or_large_file')
        return data


def write(path, data, mode=0o600):
    path = Path(path)
    parents(path.parent)
    if path.exists() or path.is_symlink():
        read(path, 4 * 1024 * 1024)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def executable(name):
    value = shutil.which(name, path=ENV['PATH'])
    require(value, 'missing_tool_' + name)
    path = Path(value).resolve(strict=True)
    parents(path.parent)
    m = path.lstat()
    require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022
            and m.st_mode & 0o111, 'unsafe_executable')
    return str(path)


def command(args, timeout=30, data=None, check=True, env=None):
    try:
        p = subprocess.run(list(map(str, args)), input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, env=env or ENV)
    except subprocess.TimeoutExpired:
        raise Rejected('command_timeout') from None
    require(len(p.stdout) <= 4 * 1024 * 1024 and len(p.stderr) <= 1024 * 1024, 'output_limit')
    if check:
        require(p.returncode == 0, 'command_failed_' + Path(str(args[0])).name)
    return p


class Docker:
    def __init__(self):
        self.binary = executable('docker')

    def run(self, *args, timeout=30, check=True):
        return command([self.binary, '--host', 'unix:///var/run/docker.sock', *args], timeout, check=check)

    def json(self, *args):
        return parsed(self.run(*args).stdout)

    def ids(self, *args):
        ids = self.run(*args).stdout.decode('ascii').split()
        require(all(re.fullmatch('[a-f0-9]{64}', x) for x in ids), 'invalid_docker_id')
        return ids

    def inspect(self, cid):
        require(re.fullmatch('[a-f0-9]{64}', cid), 'full_container_id_required')
        value = self.json('container', 'inspect', cid)
        require(len(value) == 1 and value[0].get('Id') == cid, 'container_identity_changed')
        return value[0]


def validate_config(value):
    require(isinstance(value, dict) and set(value) == {'schema', 'profile', 'images', 'source_sha256'}
            and type(value['schema']) is int and value['schema'] == 1 and value['profile'] == PROFILE,
            'config_schema')
    require(isinstance(value['images'], dict) and set(value['images']) == set(LABS), 'config_images')
    for lab, item in value['images'].items():
        require(isinstance(item, dict) and set(item) == {'image_id', 'start_sha256', 'verifier_sha256'}
                and isinstance(item['image_id'], str) and re.fullmatch('sha256:[a-f0-9]{64}', item['image_id'])
                and all(isinstance(item[k], str) and re.fullmatch('[a-f0-9]{64}', item[k])
                        for k in ('start_sha256', 'verifier_sha256')), 'config_image_pin')
    require(value['images']['redis']['image_id'] != value['images']['samba']['image_id'], 'images_not_distinct')
    require(isinstance(value['source_sha256'], dict) and set(value['source_sha256']) == set(SOURCE_FILES)
            and all(isinstance(x, str) and re.fullmatch('[a-f0-9]{64}', x)
                    for x in value['source_sha256'].values()), 'config_source_pins')
    return value


def load_config():
    config = validate_config(parsed(read(CONFIG, 65536, mode=0o600)))
    for name, expected in config['source_sha256'].items():
        require(digest(read(BASE / name)) == expected, 'installed_source_changed')
    return config


def receipt(lab):
    path = STATE / (lab + '.json')
    if not path.exists() and not path.is_symlink():
        return None
    value = parsed(read(path, 8192, mode=0o600))
    require(isinstance(value, dict) and set(value) == {'schema', 'lab', 'container_id', 'image_id', 'verified_at'}
            and type(value['schema']) is int and value['schema'] == 1 and value['lab'] == lab
            and isinstance(value['container_id'], str) and re.fullmatch('[a-f0-9]{64}', value['container_id'])
            and isinstance(value['image_id'], str) and re.fullmatch('sha256:[a-f0-9]{64}', value['image_id'])
            and type(value['verified_at']) is int and value['verified_at'] >= 0, 'invalid_runtime_receipt')
    return value


def record(lab, cid, config, verified_at=0):
    write(STATE / (lab + '.json'), json_bytes({'schema': 1, 'lab': lab, 'container_id': cid,
          'image_id': config['images'][lab]['image_id'], 'verified_at': verified_at}))


def validate_image(document, image_id):
    require(isinstance(document, list) and len(document) == 1 and document[0].get('Id') == image_id
            and document[0].get('Os') == 'linux' and document[0].get('Architecture') == 'amd64'
            and not document[0].get('Config', {}).get('Volumes'), 'image_contract')


def image_present(docker, image_id):
    result = docker.run('image', 'inspect', image_id, check=False)
    if result.returncode:
        return False
    validate_image(parsed(result.stdout), image_id)
    return True


def network_name(lab):
    return PROJECT + '_' + lab


def network_options(lab):
    return {'com.docker.network.bridge.name': 'br-cap-' + lab,
            'com.docker.network.bridge.enable_icc': 'false'}


def validate_network(value, lab, cid=None):
    require(value.get('Name') == network_name(lab) and value.get('Driver') == 'bridge'
            and value.get('Internal') is True and value.get('EnableIPv6') is False
            and value.get('Options') == network_options(lab), 'network_contract')
    labels = value.get('Labels') or {}
    require(labels.get('com.docker.compose.project') == PROJECT
            and labels.get('com.docker.compose.network') == lab
            and labels.get('io.capstone.managed') == 'nonweb-v1', 'network_ownership')
    require(set((value.get('Containers') or {})) <= ({cid} if cid else set()), 'foreign_network_member')


def validate_container(value, lab, config):
    spec, hc, conf = LABS[lab], value.get('HostConfig') or {}, value.get('Config') or {}
    require(value.get('Name') == '/capstone-nonweb-' + lab
            and value.get('Image') == config['images'][lab]['image_id'], 'container_image_or_name')
    labels = conf.get('Labels') or {}
    require(labels.get('com.docker.compose.project') == PROJECT
            and labels.get('com.docker.compose.service') == lab
            and labels.get('com.docker.compose.oneoff') == 'False'
            and labels.get('io.capstone.managed') == 'nonweb-v1'
            and labels.get('io.capstone.lab') == lab, 'container_ownership')
    require(conf.get('User') == spec['user'] and conf.get('WorkingDir') == '/lab'
            and conf.get('Entrypoint') == ['/lab/start.sh'] and not conf.get('Cmd'), 'container_command')
    require(hc.get('ReadonlyRootfs') is True and hc.get('Privileged') is False
            and hc.get('PublishAllPorts') is False and not hc.get('PortBindings')
            and not hc.get('Binds') and not value.get('Mounts')
            and hc.get('Tmpfs') == spec['tmpfs'], 'container_mount_or_ports')
    require(hc.get('NetworkMode') == network_name(lab)
            and set((value.get('NetworkSettings') or {}).get('Networks') or {}) == {network_name(lab)}
            and (hc.get('RestartPolicy') or {}).get('Name') == 'no'
            and hc.get('PidMode', '') == '' and hc.get('IpcMode', 'private') == 'private'
            and hc.get('UTSMode', '') == '' and hc.get('UsernsMode', '') == '', 'container_namespace')
    require(not any(hc.get(k) for k in ('Devices', 'DeviceRequests', 'VolumesFrom', 'Links', 'ExtraHosts',
                                      'Sysctls', 'Dns', 'DnsOptions', 'DnsSearch')),
            'container_extra_access')
    caps = hc.get('CapAdd')
    caps = [] if caps is None else caps
    require(isinstance(caps, list) and all(isinstance(value, str) for value in caps),
            'container_privileges')
    # Docker versions may render the same capability with a CAP_ prefix.
    # Normalize only that optional single prefix, preserving duplicate detection.
    caps = [value[4:] if value.startswith('CAP_') else value for value in caps]
    require(hc.get('CapDrop') == ['ALL'] and len(caps) == len(set(caps))
            and sorted(caps) == sorted(spec['caps'])
            and hc.get('SecurityOpt') == ['no-new-privileges:true'], 'container_privileges')
    require(hc.get('Memory') == spec['memory'] and hc.get('NanoCpus') == spec['cpus']
            and hc.get('PidsLimit') == spec['pids'], 'container_limits')
    log = hc.get('LogConfig') or {}
    require(log.get('Type') == 'json-file'
            and log.get('Config') == {'max-size': '10m', 'max-file': '3'}, 'container_log_limits')


def inventory(docker, config, allow_new=None):
    """Check *all* project members and reserved names; never adopt matching labels alone."""
    owned = docker.ids('container', 'ls', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=' + PROJECT)
    found = {}
    for cid in owned:
        item = docker.inspect(cid)
        lab = (item.get('Config', {}).get('Labels') or {}).get('com.docker.compose.service')
        require(lab in LABS and lab not in found, 'foreign_or_duplicate_project_service')
        validate_container(item, lab, config)
        rec = receipt(lab)
        if allow_new != lab:
            require(rec and rec['container_id'] == cid and rec['image_id'] == item['Image'], 'unrecorded_container')
        found[lab] = item
    project_networks = docker.ids('network', 'ls', '-q', '--no-trunc', '--filter',
                                 'label=com.docker.compose.project=' + PROJECT)
    known_networks = set()
    for lab in LABS:
        ids = docker.ids('container', 'ls', '-aq', '--no-trunc', '--filter', 'name=^/capstone-nonweb-' + lab + '$')
        require(ids == ([found[lab]['Id']] if lab in found else []), 'reserved_name_collision')
        nets = docker.ids('network', 'ls', '-q', '--no-trunc', '--filter', 'name=^' + network_name(lab) + '$')
        require(len(nets) <= 1, 'duplicate_network')
        if nets:
            known_networks.add(nets[0])
            values = docker.json('network', 'inspect', nets[0])
            require(len(values) == 1 and values[0].get('Id') == nets[0], 'network_identity')
            validate_network(values[0], lab, found.get(lab, {}).get('Id'))
        require(lab not in found or nets, 'network_missing')
    require(set(project_networks) == known_networks, 'foreign_project_network')
    return found


def interface_expr(key, lab):
    return {'match': {'op': '==', 'left': {'meta': {'key': key}}, 'right': 'br-cap-' + lab}}


def expected_guard_rules():
    result = {'input': [], 'forward': []}
    for lab in LABS:
        result['input'] += [[interface_expr('iifname', lab), {'match': {'op': 'in',
            'left': {'ct': {'key': 'state'}}, 'right': ['established', 'related']}}, {'accept': None}],
            [interface_expr('iifname', lab), {'drop': None}]]
        result['forward'] += [[interface_expr('iifname', lab), {'drop': None}],
                              [interface_expr('oifname', lab), {'drop': None}]]
    return result


def guard_text():
    sections = []
    for chain in ('input', 'forward'):
        lines = [f' chain {chain} {{', f'  type filter hook {chain} priority -20; policy accept;']
        for lab in LABS:
            bridge = 'br-cap-' + lab
            if chain == 'input':
                lines += [f'  iifname "{bridge}" ct state established,related accept', f'  iifname "{bridge}" drop']
            else:
                lines += [f'  iifname "{bridge}" drop', f'  oifname "{bridge}" drop']
        sections.append('\n'.join(lines + [' }']))
    return ('table inet ' + TABLE + ' {\n' + '\n'.join(sections) + '\n}\n').encode()


def validate_guard(document):
    tables, chains, rules = [], {}, {'input': [], 'forward': []}
    for item in document.get('nftables', []):
        if 'metainfo' in item:
            continue
        if 'table' in item:
            table = item['table']; tables.append((table.get('family'), table.get('name')))
        elif 'chain' in item:
            chain = item['chain']; name = chain.get('name')
            require(name in rules and name not in chains, 'guard_chain')
            chains[name] = {k: chain.get(k) for k in ('family', 'table', 'type', 'hook', 'prio', 'policy')}
        elif 'rule' in item:
            rule = item['rule']
            require(rule.get('family') == 'inet' and rule.get('table') == TABLE
                    and rule.get('chain') in rules, 'guard_rule')
            rules[rule['chain']].append(rule.get('expr'))
        else:
            raise Rejected('guard_unknown_object')
    require(tables == [('inet', TABLE)] and set(chains) == set(rules), 'guard_table_or_chain')
    for name, chain in chains.items():
        require(chain == {'family': 'inet', 'table': TABLE, 'type': 'filter', 'hook': name,
                          'prio': -20, 'policy': 'accept'}, 'guard_chain_contract')
    require(rules == expected_guard_rules(), 'guard_rules_changed')


def guard(install=False):
    nft = executable('nft')
    p = command([nft, '-j', 'list', 'table', 'inet', TABLE], check=False)
    if p.returncode:
        require(install, 'guard_missing')
        # Listing the entire table set must succeed; a daemon/permission error is not absence.
        tables = parsed(command([nft, '-j', 'list', 'tables']).stdout)
        require(not any(x.get('table', {}).get('name') == TABLE for x in tables.get('nftables', [])),
                'guard_table_conflict')
        command([nft, '--check', '-f', '-'], data=guard_text())
        command([nft, '-f', '-'], data=guard_text())
        p = command([nft, '-j', 'list', 'table', 'inet', TABLE])
    validate_guard(parsed(p.stdout))


@contextlib.contextmanager
def operation_lock():
    if not RUN.exists():
        parents(RUN.parent)
        RUN.mkdir(mode=0o750)
        import grp
        os.chown(RUN, 0, grp.getgrnam('capstone-labs').gr_gid)
    parents(RUN)
    import grp
    require(stat.S_IMODE(RUN.stat().st_mode) == 0o750
            and RUN.stat().st_gid == grp.getgrnam('capstone-labs').gr_gid, 'unsafe_run_directory')
    path = RUN / 'operation.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        m = os.fstat(fd)
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1
                and stat.S_IMODE(m.st_mode) == 0o600, 'unsafe_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Rejected('operation_in_progress') from None
        yield
    finally:
        os.close(fd)


def compose(docker, config, lab, reset=False):
    env = {**ENV, 'REDIS_IMAGE': config['images']['redis']['image_id'],
           'SAMBA_IMAGE': config['images']['samba']['image_id']}
    args = [docker.binary, '--host', 'unix:///var/run/docker.sock', 'compose', '--project-name', PROJECT,
            '--project-directory', str(BASE), '--env-file', '/dev/null', '-f', str(BASE / 'compose.yaml'),
            '--profile', lab, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never']
    if reset:
        args.append('--force-recreate')
    command(args + [lab], timeout=120, env=env)


def validate_verification(value, lab):
    require(isinstance(value, dict) and set(value) == {'schema', 'lab', 'software_version',
            'package_version', 'service_ready', 'attack_tested'} and type(value['schema']) is int
            and value['schema'] == 1 and value['lab'] == lab
            and value['software_version'] == LABS[lab]['version']
            and value['package_version'] == LABS[lab]['package_version']
            and value['service_ready'] is True and value['attack_tested'] is False,
            'image_verification_failed')


def verify_instance(docker, config, lab, cid):
    item = docker.inspect(cid)
    validate_container(item, lab, config)
    require(item.get('State', {}).get('Running') is True, 'lab_not_running')
    # Hash the executable bytes seen in the live container before invoking the pinned verifier.
    result = docker.run('exec', '--user', LABS[lab]['user'], cid, '/usr/bin/sha256sum',
                        '/lab/start.sh', '/lab/verify.sh', timeout=15).stdout.decode('ascii').splitlines()
    expected = [config['images'][lab]['start_sha256'] + '  /lab/start.sh',
                config['images'][lab]['verifier_sha256'] + '  /lab/verify.sh']
    require(result == expected, 'container_program_changed')
    result = docker.run('exec', '--user', LABS[lab]['user'], cid, '/lab/verify.sh', timeout=45).stdout
    require(len(result) <= 8192, 'verification_output_limit')
    validate_verification(parsed(result), lab)
    validate_container(docker.inspect(cid), lab, config)
    return int(time.time())


def status(docker, config, lab, found=None):
    found = inventory(docker, config) if found is None else found
    image = image_present(docker, config['images'][lab]['image_id'])
    item, rec = found.get(lab), receipt(lab)
    return {'schema': 1, 'lab': lab, 'cve_id': LABS[lab]['cve_id'],
            'status': ('running' if item.get('State', {}).get('Running') else 'stopped') if item else 'not_deployed',
            'container_id': item['Id'] if item else None, 'image_id': config['images'][lab]['image_id'],
            'image_present': image, 'verification': 'environment_only', 'attack_tested': False,
            'verified_at': rec['verified_at'] if rec and item else 0, 'exec_user': '10001:10001'}


def action(action_name, lab, config, docker, supplied_image=None):
    require(lab in LABS and action_name in ('check', 'up', 'reset', 'stop', 'down', 'status',
                                          'logs', 'verify', 'getcontainer'), 'unsupported_action')
    require(supplied_image is None or supplied_image == config['images'][lab]['image_id'], 'image_override_forbidden')
    found = inventory(docker, config)
    if action_name in ('stop', 'down'):
        if lab in found:
            cid = found[lab]['Id']
            validate_container(docker.inspect(cid), lab, config)
            docker.run('container', 'stop', '--time', '10', cid, timeout=30)
            validate_container(docker.inspect(cid), lab, config)
            docker.run('container', 'rm', cid)
        return status(docker, config, lab)
    if action_name == 'logs':
        require(lab in found, 'lab_not_created')
        raw = docker.run('logs', '--tail', '200', '--timestamps', found[lab]['Id']).stdout
        return {'schema': 1, 'lab': lab, 'logs': raw.decode('utf-8', 'replace')}
    if action_name == 'status':
        result = status(docker, config, lab, found)
        try:
            guard()
            result.update(deployment_allowed=True, safety_error=None)
        except Rejected as error:
            result.update(deployment_allowed=False, safety_error=str(error))
        return result
    guard()
    require(image_present(docker, config['images'][lab]['image_id']), 'image_missing')
    if action_name == 'check':
        return {**status(docker, config, lab, found), 'deployment_allowed': True, 'safety_error': None}
    if action_name in ('up', 'reset'):
        # Unknown containers are never adopted after an interrupted create/recreate.
        if action_name == 'reset' or lab not in found or not found[lab].get('State', {}).get('Running'):
            compose(docker, config, lab, reset=action_name == 'reset')
            after = inventory(docker, config, allow_new=lab)
            require(lab in after, 'created_container_missing')
            record(lab, after[lab]['Id'], config)
            found = inventory(docker, config)
    require(lab in found, 'lab_not_created')
    checked_at = verify_instance(docker, config, lab, found[lab]['Id'])
    record(lab, found[lab]['Id'], config, checked_at)
    result = status(docker, config, lab)
    result.update(deployment_allowed=True, safety_error=None)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('lab', nargs='?')
    parser.add_argument('image', nargs='?')
    args = parser.parse_args()
    require(os.geteuid() == 0 and sys.platform == 'linux', 'root_linux_required')
    config = load_config()
    if args.action == 'guard-install' and args.lab is None:
        guard(install=True)
        print(json.dumps({'guard_verified': True}))
        return
    if args.action == 'guard-check' and args.lab is None:
        guard()
        print(json.dumps({'guard_verified': True}))
        return
    docker = Docker()
    if args.action in ('check', 'status', 'logs'):
        result = action(args.action, args.lab, config, docker, args.image)
    else:
        with operation_lock():
            result = action(args.action, args.lab, config, docker, args.image)
    print(json.dumps({'ok': True, **result}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Rejected, OSError, ValueError, KeyError, TypeError):
        # Error codes contain no Docker stderr, service output, terminal input or credentials.
        error = sys.exc_info()[1]
        print(json.dumps({'ok': False, 'error': str(error) if isinstance(error, Rejected) else 'runtime_failed'}))
        raise SystemExit(1)
