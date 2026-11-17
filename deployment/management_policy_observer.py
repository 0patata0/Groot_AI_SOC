#!/usr/bin/env python3
"""Fixed, root-operator management-policy observation; no mutation or MCP entry.

Only the host role is selectable. No caller supplies a path, shell, successful
check or receipt. File declarations, kernel observations and effective sshd
settings are kept distinct from actual loaded engine and new-route proofs.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('_management_observation_render', Path(__file__).with_name('management_policy_render.py'))
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)
LIMIT = 4 * 1024 * 1024
FILES = {
    'a': (
        ('firewall', '/etc/nftables.d/capstone-fw.nft'),
        ('loader', '/usr/local/sbin/capstone-nat.sh'),
        ('proxy', '/home/groot_a/capstone/chatproxy/nginx.conf'),
        ('threshold', '/home/groot_a/capstone/suricata/ruleset/threshold.in'),
    ),
    'b': (('host_guard', '/etc/capstone-host-security/config.json'),),
    'c': (('host_guard', '/etc/capstone-host-security/config.json'),
          ('lab_environment', '/etc/capstone-offline-labs/settings.env')),
}
SSH_USERS = ('capstone-diagnostics', 'ruleview', 'rulechg', 'resp')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def error_code(error):
    value = str(error)
    return value if re.fullmatch(r'(?:management|fixed|source|unique|wazuh|proxy|host_guard)_[a-z0-9_]{1,75}', value) else type(error).__name__


def read_fixed(path):
    """No symlink components; pin the opened regular file and report ancestry.

    User-owned parent directories or a writable source are observations, not
    trusted preparation receipts. A future privileged worker must independently
    establish its installation manifest/ownership before authorizing changes.
    """
    parents_trusted = True
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('source_parent_not_directory')
        parents_trusted &= info.st_uid == 0 and not info.st_mode & 0o022
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > LIMIT or initial.st_nlink != 1:
        raise ValueError('source_regular_size_links')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
            raise ValueError('source_replaced_during_read')
        chunks, size = [], 0
        while True:
            piece = os.read(fd, min(65536, LIMIT + 1 - size))
            if not piece:
                break
            chunks.append(piece)
            size += len(piece)
            if size > LIMIT:
                raise ValueError('source_size')
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('source_changed_during_read')
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError('source_replaced_during_read')
    finally:
        os.close(fd)
    raw = b''.join(chunks)
    return raw, {'sha256': sha(raw), 'bytes': len(raw), 'uid': after.st_uid,
                 'gid': after.st_gid, 'mode': stat.S_IMODE(after.st_mode),
                 'trusted_ancestry': bool(parents_trusted),
                 'root_nonwritable_file': after.st_uid == 0 and not after.st_mode & 0o022}


def selected(kind, raw):
    """Never return complete config lines, environment entries or opaque values."""
    text = render.source_text(raw)
    if kind == 'firewall':
        return {name: row['cidrs'] for name, row in render.firewall_sets(raw).items()}
    if kind == 'loader':
        return {'administrator_cidrs': render.current_native_sources(raw)}
    if kind == 'proxy':
        found = {}
        def visit(nodes):
            for node in nodes:
                children = node['children']
                if node['head'] == ['server']:
                    names = [c['head'][1:] for c in children if c['head'][0] == 'server_name']
                    if any(set(nameset) & render.WAZUH_NAMES for nameset in names):
                        if len(names) != 1 or len(names[0]) != 1 or names[0][0] in found:
                            raise ValueError('proxy_names')
                        values = [c['head'][1] for c in children if c['head'][0] == 'allow' and len(c['head']) == 2]
                        found[names[0][0]] = render.contract.addresses(values)
                elif children is not None:
                    visit(children)
        visit(render.nginx_nodes(render.source_tokens(text)))
        if set(found) != render.WAZUH_NAMES or len({tuple(x) for x in found.values()}) != 1:
            raise ValueError('proxy_management_servers_inconsistent')
        values = next(iter(found.values()))
        render.proxy(raw, values, values)
        return {'management_servers': found, 'public_lab_acl': 'not_modified_or_certified'}
    if kind == 'threshold':
        values = [m[1] for line in text.splitlines() if (m := render.THRESHOLD.fullmatch(line)) is not None]
        values = render.contract.addresses(values)
        render.threshold(raw, values, values)
        return {'signature_id': 2001219, 'track': 'by_src', 'administrator_cidrs': values,
                'scope': 'one_ssh_syn_heuristic_not_all_attacks'}
    if kind == 'host_guard':
        # The existing renderer performs the full schema/role validation.
        value = json.loads(text)
        if not isinstance(value, dict):
            raise ValueError('host_guard_object_required')
        host = {'security': 'a', 'siem': 'b', 'service': 'c'}.get(value.get('role'))
        render.host_guard(raw, host, ['192.0.2.1/32'])
        names = ('role', 'security_host', 'siem_host', 'service_host', 'ssh_port',
                 'management_cidrs', 'dashboard_cidrs', 'dashboard_denied_cidrs', 'chat_cidrs')
        return {name: value.get(name, []) for name in names}
    if kind == 'lab_environment':
        values = [line.split('=', 1)[1] for line in text.splitlines() if line.startswith('OFFLINE_LABS_ADMIN_CIDRS=')]
        render.lab_environment(raw, ['192.0.2.1/32'])
        if not values:
            return {'administrator_cidrs': None, 'origin': 'not_explicit_in_file',
                    'default_or_running_value': 'not_verified'}
        return {'administrator_cidrs': render.contract.addresses(values[0].split(',')), 'origin': 'explicit_in_file'}
    if kind == 'wazuh':
        render.wazuh_global_span(raw)
        root = ET.fromstring(b'<root>' + raw + b'</root>')
        values = []
        for element in root.findall('.//global/white_list'):
            value = (element.text or '').strip()
            try:
                item = {'cidr': str(ipaddress.IPv4Network(value, strict=True))}
            except ValueError:
                item = {'local_name': value} if value in ('localhost', '^localhost$') else {'unrecognized_value_sha256': sha(value.encode())}
            values.append(item)
        return {'white_list': values, 'owned_management_block_present': render.WAZUH_BEGIN in text,
                'unmanaged_entries': 'retained; overlap cannot prove administrator removal'}
    raise ValueError('unknown_fixed_source')


def command(arguments, timeout=5):
    # Callers below use fixed command tuples and locally discovered, validated
    # container names/users. No shell, model command or network request.
    fixed_path = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    if arguments[0] == 'docker':
        binary = shutil.which('docker', path=fixed_path)
        if binary not in ('/usr/bin/docker', '/usr/local/bin/docker'):
            raise ValueError('fixed_local_docker_binary_required')
        arguments = [binary, '--host', 'unix:///var/run/docker.sock', *arguments[1:]]
    result = subprocess.run(arguments, capture_output=True, timeout=timeout,
                            env={'PATH': fixed_path, 'LANG': 'C.UTF-8'})
    if result.returncode or len(result.stdout) > LIMIT:
        raise ValueError('fixed_read_command_failed')
    return result.stdout


def wazuh_observation():
    # The live volume name differs from the fresh-install example. Identify one
    # running manager; never guess a host path or read credentials from inspect.
    names = command(['docker', 'ps', '--format', '{{.Names}}']).decode().splitlines()
    names = [name for name in names if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
             and 'wazuh' in name.lower() and 'manager' in name.lower()]
    if len(names) != 1:
        raise ValueError('unique_running_wazuh_manager_required')
    name = names[0]
    fmt = '{"id":{{json .Id}},"image":{{json .Image}},"started_at":{{json .State.StartedAt}}}'
    identity = json.loads(command(['docker', 'inspect', '--format', fmt, name]))
    raw = command(['docker', 'exec', name, 'cat', '/var/ossec/etc/ossec.conf'])
    if json.loads(command(['docker', 'inspect', '--format', fmt, name])) != identity:
        raise ValueError('wazuh_container_changed_during_read')
    return {'source': 'running_wazuh_manager:/var/ossec/etc/ossec.conf', 'status': 'configuration_observed',
            'sha256': sha(raw), 'container': identity, 'selected': selected('wazuh', raw),
            'runtime_verified': False}


def observe(host):
    if host not in FILES:
        raise ValueError('fixed_host_required')
    rows = []
    for kind, name in FILES[host]:
        try:
            raw, metadata = read_fixed(Path(name))
            value = selected(kind, raw)
            if kind == 'host_guard' and value['role'] != {'a': 'security', 'b': 'siem', 'c': 'service'}[host]:
                raise ValueError('host_guard_wrong_role')
            row = {'kind': kind, 'source': name, 'status': 'configuration_observed',
                   **metadata, 'selected': value, 'runtime_verified': False}
        except (OSError, ValueError) as error:
            row = {'kind': kind, 'source': name, 'status': 'unavailable',
                   'error_type': type(error).__name__, 'error_code': error_code(error), 'runtime_verified': False}
        rows.append(row)
    if host == 'b':
        try:
            rows.append({'kind': 'wazuh', **wazuh_observation()})
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            rows.append({'kind': 'wazuh', 'status': 'unavailable', 'error_type': type(error).__name__,
                         'error_code': error_code(error), 'runtime_verified': False})
    ssh = []
    binary = shutil.which('sshd')
    source = '10.200.10.10' if host == 'a' else '10.200.10.1'
    for user in SSH_USERS:
        try:
            pwd.getpwnam(user)
        except KeyError:
            continue
        row = {'user': user, 'source': source}
        try:
            lines = command([binary or '/usr/sbin/sshd', '-T', '-C', 'user=' + user + ',host=management-policy-observer,addr=' + source]).decode().splitlines()
            values = dict(line.split(' ', 1) for line in lines if ' ' in line)
            forced = values.get('forcecommand', 'none')
            row.update(status='effective_configuration_observed', forced_command=forced != 'none',
                       forcecommand_sha256=sha(forced.encode()),
                       forwarding=values.get('allowtcpforwarding'), password_authentication=values.get('passwordauthentication'))
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            row.update(status='unavailable', error_type=type(error).__name__, error_code=error_code(error))
        ssh.append(row)
    return {'schema': 1, 'host': host, 'observed_at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
            'sources': rows, 'existing_mcp_ssh_accounts': ssh, 'operating_changes': 0,
            'runtime_verified': False, 'prepared_or_approved': False,
            'scope': 'selected_fixed_configuration_only_not_engine_load_new_connection_or_global_coverage'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', choices=sorted(FILES))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root_operator_required')
    print(json.dumps(observe(args.host), ensure_ascii=False))


if __name__ == '__main__':
    main()
