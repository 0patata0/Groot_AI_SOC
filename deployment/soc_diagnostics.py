#!/usr/bin/env python3
"""Fresh-host installation of bounded, read-only A/B/C diagnostic snapshots.

This is an administrator bootstrap helper, never an MCP command executor.
Runtime collectors publish fixed summaries; the remote account can read one
snapshot only and receives no sudo, Docker, shell, port-forward or journal API.
"""
import argparse
import ast
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile

import soc_management as common

STATE = Path('/var/lib/capstone-diagnostics')
PRIVATE = STATE / 'installation'
CODE = Path('/opt/capstone-diagnostics')
MCP = Path('/opt/mcp')
KEYDIR = Path('/etc/mcp/system-diagnostics')
ROUTER_CONFIG = Path('/etc/mcp/system-diagnostics.json')
ACCOUNT = GROUP = 'capstone-diagnostics'
READER_HOME = STATE / 'reader'
MCP_USER = 'capstone-mcp'
ROLE_HOST = {'security': 'a', 'siem': 'b', 'service': 'c'}
HOST_ENV = {'security': 'SECURITY_HOST', 'siem': 'SIEM_HOST', 'service': 'SERVICE_HOST'}
SOURCES = ('system_diagnostics.py', 'system-diagnostics-mcp.py',
           'read-system-diagnostics.py', 'run-system-diagnostics.sh')
SERVICE = 'capstone-system-diagnostics.service'
TIMER = 'capstone-system-diagnostics.timer'
FIXED_ENV = common.FIXED_ENV
need = common.need


def settings(env=None):
    env = os.environ if env is None else env
    need(env.get('CAPSTONE_ROOT', '/opt/capstone') == '/opt/capstone', 'fixed_capstone_root_required')
    source = Path(env.get('CAPSTONE_SOURCE', ''))
    need(source.is_absolute(), 'source_required')
    hosts = {}
    for key in HOST_ENV.values():
        value = str(ipaddress.IPv4Address(env.get(key, '')))
        need(value == env[key] and any(ipaddress.ip_address(value) in net for net in common.PRIVATE),
             'private_diagnostic_host_required')
        hosts[key] = value
    need(len(set(hosts.values())) == 3, 'distinct_diagnostic_hosts_required')
    port = int(env.get('SSH_PORT', '22')); need(1 <= port <= 65535, 'SSH_port_invalid')
    return {'schema': 1, 'source': source, 'hosts': hosts, 'ssh_port': port}


def source_bundle(s):
    data = {name: common.read(s['source'] / 'infra/mcp' / name, 256 * 1024) for name in SOURCES}
    for name, raw in data.items():
        if name.endswith('.py'): ast.parse(raw)
    data['soc_diagnostics.py'] = common.read(s['source'] / 'deployment/soc_diagnostics.py')
    return data


def profile(s, role):
    need(role in ROLE_HOST, 'diagnostic_role_invalid')
    machine = common.read('/etc/machine-id', 128).decode().strip()
    need(re.fullmatch(r'[0-9a-f]{32}', machine), 'diagnostic_machine_id_invalid')
    return {'schema': 1, 'role': role, 'host': ROLE_HOST[role], 'hosts': s['hosts'],
            'ssh_port': s['ssh_port'], 'machine_id': machine,
            'source_sha256': {name: common.digest(raw) for name, raw in source_bundle(s).items()}}


def unit_documents(role):
    need(role in ROLE_HOST, 'diagnostic_role_invalid')
    service = ('[Unit]\nDescription=Bounded read-only Capstone system diagnostics\nAfter=systemd-journald.service\n'
        '[Service]\nType=oneshot\nUser=root\nGroup=capstone-diagnostics\n'
        'ExecStart=/usr/bin/python3 -IB /opt/capstone-diagnostics/system_diagnostics.py --collect --role ' + role + '\n'
        'UMask=0027\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
        'ReadWritePaths=/var/lib/capstone-diagnostics\nRestrictAddressFamilies=AF_UNIX\n'
        'ProtectKernelTunables=yes\nProtectControlGroups=yes\nKillMode=control-group\nTimeoutStartSec=55\nTimeoutStopSec=5\n')
    timer = ('[Unit]\nDescription=Refresh bounded Capstone diagnostic snapshots\n'
        '[Timer]\nOnBootSec=30s\nOnUnitActiveSec=60s\nAccuracySec=5s\nUnit=' + SERVICE + '\n'
        '[Install]\nWantedBy=timers.target\n')
    return {SERVICE: service.encode(), TIMER: timer.encode()}


def account_absent(name, kind):
    try:
        (grp.getgrnam if kind == 'group' else pwd.getpwnam)(name)
    except KeyError:
        return
    raise common.Refused('unmanaged_diagnostic_' + kind + '_exists')


def check(s, role):
    need(role in ROLE_HOST, 'diagnostic_role_invalid')
    source_bundle(s)
    need(sys.platform == 'linux' and os.geteuid() == 0, 'Linux_root_required')
    for binary in ('/usr/bin/python3', '/usr/bin/systemctl', '/usr/bin/journalctl', '/usr/bin/ssh',
                   '/usr/bin/ssh-keygen', '/usr/sbin/sshd', '/usr/sbin/groupadd', '/usr/sbin/useradd',
                   '/usr/sbin/usermod', '/usr/sbin/runuser', '/usr/bin/prlimit'):
        need(Path(binary).is_file(), 'diagnostic_binary_missing')
    common.public_key(common.read('/etc/ssh/ssh_host_ed25519_key.pub', 4096))
    if STATE.exists() or STATE.is_symlink():
        common.trusted_directory(STATE)
        need((PRIVATE / 'active.json').exists() or (role == 'siem' and (PRIVATE / 'prepared.json').exists()),
             'partial_diagnostic_installation_requires_review')
        return {'status': 'existing_requires_verify', 'role': role}
    for path in (CODE, ROUTER_CONFIG, KEYDIR, Path('/etc/systemd/system') / SERVICE,
                 Path('/etc/systemd/system') / TIMER, Path('/etc/ssh/sshd_config.d/63-capstone-diagnostics.conf')):
        need(not os.path.lexists(path), 'unmanaged_diagnostic_namespace_exists')
    account_absent(GROUP, 'group')
    if role != 'siem': account_absent(ACCOUNT, 'account')
    return {'status': 'prerequisites_checked', 'role': role, 'files_written': 0, 'services_started': 0}


def group_setup():
    account_absent(GROUP, 'group')
    common.run(['/usr/sbin/groupadd', '--system', GROUP])
    return grp.getgrnam(GROUP).gr_gid


def mcp_account():
    # The existing GROOT migration binds this constant explicitly to "mcp";
    # fresh deployment uses "capstone-mcp". Neither path may select root or an
    # arbitrary caller-provided account. This is an installation-only binding.
    need(MCP_USER in ('capstone-mcp', 'mcp'), 'fixed_nonroot_MCP_account_required')
    return MCP_USER


def installed_record(path):
    path = Path(path); common.trusted_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
             and not meta.st_mode & 0o022 and meta.st_size <= 4 * 1024 * 1024, 'diagnostic_installed_file_unsafe')
        return {'sha256': common.digest(stream.read()), 'mode': stat.S_IMODE(meta.st_mode), 'gid': meta.st_gid}


def install_common(s, role):
    check(s, role); need(not STATE.exists(), 'diagnostic_fresh_install_required')
    gid = group_setup()
    common.mkdir(STATE, 0o750, 0, gid); common.mkdir(PRIVATE)
    common.write(PRIVATE / 'intent.json', common.canonical(profile(s, role)))
    common.mkdir(CODE, 0o755)
    common.write(CODE / 'system_diagnostics.py', source_bundle(s)['system_diagnostics.py'], 0o644)
    for name, raw in unit_documents(role).items():
        common.write(Path('/etc/systemd/system') / name, raw, 0o644)
    common.run(['/usr/bin/systemctl', 'daemon-reload'])
    common.run(['/usr/bin/systemctl', 'start', SERVICE], timeout=70)
    common.run(['/usr/bin/systemctl', 'enable', '--now', TIMER])
    return gid


def export_key(s):
    saved = common.parse(common.read(PRIVATE / 'prepared.json', secret=True))
    need(saved['profile'] == profile(s, 'siem'), 'prepared_diagnostic_profile_changed')
    for path, record in saved['files'].items(): need(installed_record(path) == record, 'prepared_diagnostic_file_changed')
    return {'schema': 1, 'hosts': s['hosts'], 'ssh_port': s['ssh_port'],
            'reader_public_key': common.public_key(common.read(KEYDIR / 'id_ed25519.pub'))}


def prepare_siem(s):
    mcp_account()
    if (PRIVATE / 'prepared.json').exists():
        export_key(s)
        return {'status': 'prepared', 'role': 'siem'}
    gid = install_common(s, 'siem')
    mc = pwd.getpwnam(mcp_account())
    common.run(['/usr/sbin/usermod', '--append', '--groups', GROUP, mcp_account()])
    for parent in (Path('/etc/mcp'), MCP):
        if parent.exists(): common.trusted_directory(parent)
        else: common.mkdir(parent, 0o755)
    common.mkdir(KEYDIR, 0o750, 0, mc.pw_gid)
    common.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'capstone-diagnostics-readonly',
                '-f', str(KEYDIR / 'id_ed25519')])
    for name in ('id_ed25519', 'id_ed25519.pub'):
        os.chown(KEYDIR / name, 0, mc.pw_gid); os.chmod(KEYDIR / name, 0o640)
    bundle = source_bundle(s)
    for name in ('system-diagnostics-mcp.py', 'run-system-diagnostics.sh'):
        common.write(MCP / name, bundle[name], 0o550, 0, mc.pw_gid)
    files = [CODE / 'system_diagnostics.py', KEYDIR / 'id_ed25519', KEYDIR / 'id_ed25519.pub',
             MCP / 'system-diagnostics-mcp.py', MCP / 'run-system-diagnostics.sh']
    files += [Path('/etc/systemd/system') / n for n in unit_documents('siem')]
    saved = {'schema': 1, 'profile': profile(s, 'siem'), 'files': {str(p): installed_record(p) for p in files}}
    common.write(PRIVATE / 'prepared.json', common.canonical(saved))
    return {'status': 'prepared', 'role': 'siem', 'private_key_exported': False}


def public_stream(s, raw):
    need(len(raw) <= 16384, 'diagnostic_public_stream_limit')
    value = common.parse(raw)
    need(isinstance(value, dict) and set(value) == {'schema', 'hosts', 'ssh_port', 'reader_public_key'}
         and type(value['schema']) is int and value['schema'] == 1
         and value['hosts'] == s['hosts'] and type(value['ssh_port']) is int and value['ssh_port'] == s['ssh_port'],
         'diagnostic_public_stream_profile')
    return common.public_key(value['reader_public_key'].encode())


def reader_launcher():
    return b'''#!/bin/sh
set -eu
[ "$#" -eq 0 ] && [ -z "${SSH_ORIGINAL_COMMAND:-}" ] || exit 2
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/nonexistent \\
  LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1 \\
  /usr/bin/python3 -I -B /opt/capstone-diagnostics/read-system-diagnostics.py
'''


def reader_ssh_configuration():
    return ('Match User ' + ACCOUNT + '\n    ForceCommand ' + str(CODE / 'read-snapshot') + '\n'
        '    AuthenticationMethods publickey\n    PubkeyAuthentication yes\n'
        '    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n'
        '    DisableForwarding yes\n    PermitTTY no\n    X11Forwarding no\n'
        '    PermitUserRC no\nMatch all\n').encode()


def verify_ssh_policy(s, role):
    address = s['hosts'][HOST_ENV[role]]
    raw = common.run(['/usr/sbin/sshd', '-T', '-C', 'user=' + ACCOUNT + ',host=localhost,addr=' +
                      s['hosts']['SIEM_HOST'] + ',laddr=' + address + ',lport=' + str(s['ssh_port'])])
    values = dict(line.split(' ', 1) for line in raw.decode().splitlines() if ' ' in line)
    expected = {'pubkeyauthentication': 'yes', 'authenticationmethods': 'publickey',
                'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
                'disableforwarding': 'yes', 'permittty': 'no', 'x11forwarding': 'no',
                'permituserrc': 'no', 'permituserenvironment': 'no', 'usepam': 'yes',
                'forcecommand': str(CODE / 'read-snapshot')}
    need(all(values.get(key) == value for key, value in expected.items()), 'diagnostic_ssh_effective_policy_mismatch')


def apply_reader(s, role, raw):
    need(role in ('security', 'service'), 'reader_role_required')
    public = public_stream(s, raw)
    if (PRIVATE / 'active.json').exists():
        saved = common.parse(common.read(PRIVATE / 'active.json', secret=True))
        need(saved.get('reader_public_key') == public, 'diagnostic_reader_key_changed')
        verify(s, role)
        return reader_public(s, role)
    gid = install_common(s, role)
    common.run(['/usr/sbin/useradd', '--system', '--gid', GROUP, '--no-create-home',
                '--home-dir', str(READER_HOME), '--shell', '/bin/dash', ACCOUNT])
    common.run(['/usr/sbin/usermod', '--password', '*', ACCOUNT])
    common.mkdir(READER_HOME, 0o750, 0, gid); common.mkdir(READER_HOME / '.ssh', 0o750, 0, gid)
    reader = CODE / 'read-system-diagnostics.py'
    common.write(reader, source_bundle(s)['read-system-diagnostics.py'], 0o550, 0, gid)
    launcher = CODE / 'read-snapshot'
    common.write(launcher, reader_launcher(), 0o550, 0, gid)
    forced = str(launcher)
    keys = READER_HOME / '.ssh/authorized_keys'
    common.write(keys, ('from="' + s['hosts']['SIEM_HOST'] + '",restrict,command="' + forced + '" ' + public + '\n').encode(), 0o640, 0, gid)
    sshd = Path('/etc/ssh/sshd_config.d/63-capstone-diagnostics.conf')
    common.write(sshd, reader_ssh_configuration(), 0o644)
    common.run(['/usr/sbin/sshd', '-t']); verify_ssh_policy(s, role)
    common.run(['/usr/bin/systemctl', 'reload', 'ssh'])
    files = [CODE / 'system_diagnostics.py', reader, launcher, keys, sshd]
    files += [Path('/etc/systemd/system') / n for n in unit_documents(role)]
    common.write(PRIVATE / 'active.json', common.canonical({'schema': 1, 'profile': profile(s, role),
        'reader_public_key': public, 'files': {str(p): installed_record(p) for p in files}}))
    verify(s, role)
    return reader_public(s, role)


def reader_public(s, role):
    return {'schema': 1, 'status': 'ready', 'role': role, 'host': ROLE_HOST[role],
            'address': s['hosts'][HOST_ENV[role]],
            'ssh_host_ed25519': common.public_key(common.read('/etc/ssh/ssh_host_ed25519_key.pub'))}


def transport_config(s, identities):
    need(isinstance(identities, list) and len(identities) == 2, 'two_diagnostic_host_receipts_required')
    rows = {}
    for value in identities:
        need(isinstance(value, dict) and set(value) == {'schema', 'status', 'role', 'host', 'address', 'ssh_host_ed25519'}
             and type(value['schema']) is int and value['schema'] == 1 and value['status'] == 'ready'
             and value['role'] in ('security', 'service') and value['host'] == ROLE_HOST[value['role']]
             and value['address'] == s['hosts'][HOST_ENV[value['role']]] and value['host'] not in rows,
             'diagnostic_host_receipt_mismatch')
        rows[value['host']] = value
    need(set(rows) == {'a', 'c'}, 'diagnostic_host_set_changed')
    lines = []
    for key in ('a', 'c'):
        value = rows[key]
        public = common.public_key(value['ssh_host_ed25519'].encode())
        token = value['address'] if s['ssh_port'] == 22 else '[' + value['address'] + ']:' + str(s['ssh_port'])
        lines.append(token + ' ' + public)
    return {'schema': 1, 'hosts': {key: rows[key]['address'] for key in ('a', 'c')},
            'ssh_port': s['ssh_port']}, ('\n'.join(lines) + '\n').encode()


def hermes_configuration(value):
    need(isinstance(value, dict) and isinstance(value.get('mcp_servers'), dict)
         and set(value['mcp_servers']) == {'wazuh-ro', 'security-events', 'rule-a', 'rule-b', 'resp'},
         'diagnostic_requires_completed_SOC_activation')
    need(isinstance(value.get('platform_toolsets'), dict)
         and {'mattermost', 'cli'} <= set(value['platform_toolsets']), 'diagnostic_platform_toolsets_required')
    # JSON round-trip copies only data. Never evaluate a user-owned YAML file.
    result = json.loads(json.dumps(value))
    result['mcp_servers']['system-diagnostics'] = {'command': 'ssh',
        'args': ['-T', '-F', '/opt/data/home/.ssh/config', 'siem-readonly', 'system-diagnostics'],
        'connect_timeout': 30, 'timeout': 60, 'supports_parallel_tool_calls': False,
        'tools': {'resources': False, 'prompts': False}, 'trust': 'full'}
    for tools in [result.get('toolsets'), *result.get('platform_toolsets', {}).values()]:
        need(isinstance(tools, list) and all(isinstance(name, str) for name in tools), 'diagnostic_toolsets_invalid')
        need('mcp-system-diagnostics' not in tools, 'diagnostic_toolset_already_present')
        tools.append('mcp-system-diagnostics')
    return result


def owned_user_data(path, uid, gid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == uid and meta.st_gid == gid and meta.st_nlink == 1
             and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_size <= 2 * 1024 * 1024, 'unsafe_Hermes_configuration')
        raw = stream.read(2 * 1024 * 1024 + 1)
        need(len(raw) == meta.st_size, 'Hermes_configuration_changed')
        return raw


def ssh_argv(s, host):
    need(host in ('a', 'c'), 'fixed_diagnostic_remote_host_required')
    address = s['hosts']['SECURITY_HOST' if host == 'a' else 'SERVICE_HOST']
    need(str(ipaddress.IPv4Address(address)) == address and
         any(ipaddress.ip_address(address) in net for net in common.PRIVATE), 'private_diagnostic_host_required')
    return ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', str(s['ssh_port']),
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + str(KEYDIR / 'known_hosts'), '-o', 'ConnectTimeout=8',
            '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
            '-i', str(KEYDIR / 'id_ed25519'), ACCOUNT + '@' + address]


def bounded_reader(argv, account=None):
    account = mcp_account() if account is None else account
    need(account in (mcp_account(), ACCOUNT), 'fixed_diagnostic_reader_required')
    command = ['/usr/sbin/runuser', '-u', account, '--', '/usr/bin/env', '-i',
               'PATH=/usr/bin:/bin', 'LANG=C', 'LC_ALL=C', 'PYTHONDONTWRITEBYTECODE=1',
               '/usr/bin/prlimit', '--fsize=131073:131073', '--'] + argv
    with tempfile.TemporaryFile(dir=PRIVATE) as output:
        os.fchmod(output.fileno(), 0o600)
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.DEVNULL, env=FIXED_ENV, start_new_session=True)
        try:
            result = child.wait(timeout=40)
        except subprocess.TimeoutExpired:
            try: os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            child.wait(timeout=5)
            raise common.Refused('diagnostic_read_timeout') from None
        need(result == 0 and os.fstat(output.fileno()).st_size <= 131072, 'diagnostic_read_failed')
        output.seek(0)
        return output.read(131073)


def snapshot_module():
    import types
    module = types.ModuleType('installed_diagnostic_validation')
    module.__file__ = str(CODE / 'system_diagnostics.py')
    exec(compile(common.read(CODE / 'system_diagnostics.py'), module.__file__, 'exec'), module.__dict__)
    return module


def validate_remote_snapshots(s):
    # Compile only the root-installed, receipt-verified local validator. The
    # remote files are bounded JSON data, never imported or executed locally.
    module = snapshot_module()
    for host in ('a', 'c'):
        raw = bounded_reader(ssh_argv(s, host))
        module.validate_snapshot(common.parse(raw), expected_host=host)


def mcp_probe(container, hermes_uid, hermes_gid):
    # Installation-only SDK/SSH exercise: no model or chat request is made.
    code = """import asyncio,json,os
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
 server=StdioServerParameters(command='/usr/bin/ssh',args=['-T','-F','/opt/data/home/.ssh/config','siem-readonly','system-diagnostics'],env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
 with open(os.devnull,'w') as errors:
  async with stdio_client(server,errlog=errors) as (read,write):
   async with ClientSession(read,write) as session:
    await session.initialize()
    response=await session.list_tools()
    assert response.next_cursor is None and {x.name for x in response.tools}=={'get_system_diagnostics'}
    result=await session.call_tool('get_system_diagnostics',{'target':'b:soc-bot','lookback_minutes':15,'limit':1})
    assert not result.isError and len(result.model_dump_json())<=262144
asyncio.run(asyncio.wait_for(main(),timeout=45))
print(json.dumps({'tools':1,'bounded_read':True,'model_requests':0,'chat_messages':0}))
"""
    common.docker('exec', '--user', str(hermes_uid) + ':' + str(hermes_gid), container['Id'],
                  '/opt/hermes/.venv/bin/python', '-B', '-c', code, timeout=60)


def activate_siem(s, raw):
    need(len(raw) <= 32768, 'diagnostic_host_receipt_limit')
    identities = common.parse(raw); config, known = transport_config(s, identities)
    if (PRIVATE / 'active.json').exists():
        saved = common.parse(common.read(PRIVATE / 'active.json', secret=True))
        need(saved.get('reader_receipts') == identities, 'diagnostic_host_receipts_changed')
        return verify(s, 'siem')
    export_key(s)
    mc, hu = pwd.getpwnam(mcp_account()), pwd.getpwnam('capstone-hermes')
    common.write(ROUTER_CONFIG, common.canonical(config), 0o640, 0, mc.pw_gid)
    common.write(KEYDIR / 'known_hosts', known, 0o640, 0, mc.pw_gid)
    data = Path('/opt/capstone/siem/capstone-hermes')
    configs = [data / 'config.yaml', data / 'management/config.yaml']
    generated = []
    for index, path in enumerate(configs):
        before = owned_user_data(path, hu.pw_uid, hu.pw_gid)
        after = common.canonical(hermes_configuration(common.parse(before)))
        common.write(PRIVATE / ('Hermes-before-' + str(index) + '.json'), before)
        generated.append((path, after))
    for path, after in generated:
        common.hermes_file(path, after, hu.pw_uid, hu.pw_gid, True)
    container = common.inspect('capstone-hermes', 'capstone-siem')
    common.docker('restart', '--time', '30', container['Id'], timeout=90)
    prepared = common.parse(common.read(PRIVATE / 'prepared.json', secret=True))
    files = dict(prepared['files'])
    files.update({str(path): installed_record(path) for path in (ROUTER_CONFIG, KEYDIR / 'known_hosts')})
    common.write(PRIVATE / 'active.json', common.canonical({'schema': 1, 'profile': profile(s, 'siem'),
        'files': files, 'reader_receipts': identities, 'Hermes_container_id': container['Id'],
        'Hermes_config_sha256': {str(path): common.digest(after) for path, after in generated}}))
    return verify(s, 'siem')


def verify(s, role):
    saved = common.parse(common.read(PRIVATE / 'active.json', secret=True))
    need(saved['profile'] == profile(s, role), 'diagnostic_installation_profile_changed')
    for path, record in saved['files'].items():
        need(installed_record(path) == record, 'diagnostic_installed_file_changed')
    common.run(['/usr/bin/systemctl', 'is-enabled', TIMER])
    common.run(['/usr/bin/systemctl', 'is-active', TIMER])
    raw = common.run(['/usr/bin/python3', '-IB', str(CODE / 'system_diagnostics.py'), '--check', '--role', role], timeout=60)
    value = common.parse(raw)
    need(value.get('schema') == 1 and value.get('host') == ROLE_HOST[role] and value.get('status') == 'ready',
         'diagnostic_snapshot_not_ready')
    if role == 'siem':
        mc, hu = pwd.getpwnam(mcp_account()), pwd.getpwnam('capstone-hermes')
        need(mc.pw_name in grp.getgrnam(GROUP).gr_mem, 'MCP_diagnostic_read_group_missing')
        for path, expected in saved['Hermes_config_sha256'].items():
            need(common.digest(owned_user_data(path, hu.pw_uid, hu.pw_gid)) == expected, 'Hermes_diagnostic_configuration_changed')
        container = common.inspect('capstone-hermes', 'capstone-siem')
        need(container['Id'] == saved['Hermes_container_id'], 'Hermes_container_changed')
        validate_remote_snapshots(s)
        mcp_probe(container, hu.pw_uid, hu.pw_gid)
    else:
        user = pwd.getpwnam(ACCOUNT)
        need(user.pw_shell == '/bin/dash' and user.pw_dir == str(READER_HOME)
             and user.pw_gid == grp.getgrnam(GROUP).gr_gid, 'diagnostic_reader_account_changed')
        common.run(['/usr/sbin/sshd', '-t'])
        verify_ssh_policy(s, role)
        raw = bounded_reader([str(CODE / 'read-snapshot')], ACCOUNT)
        snapshot_module().validate_snapshot(common.parse(raw), expected_host=ROLE_HOST[role])
    return {'schema': 1, 'status': 'verified', 'role': role, 'host': ROLE_HOST[role],
            'snapshot_units': value.get('units'), 'arbitrary_commands': False, 'sudo_granted': False,
            'raw_journal_returned': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'prepare-siem', 'export-key', 'apply-reader', 'activate-siem', 'verify'))
    parser.add_argument('--role', choices=tuple(ROLE_HOST), required=True)
    args = parser.parse_args(); os.umask(0o077)
    try:
        need(sys.platform == 'linux' and os.geteuid() == 0, 'Linux_root_required')
        s = settings()
        if args.action in ('prepare-siem', 'export-key', 'activate-siem'):
            need(args.role == 'siem', 'siem_role_required')
        if args.action == 'check': value = check(s, args.role)
        elif args.action == 'prepare-siem': value = prepare_siem(s)
        elif args.action == 'export-key': value = export_key(s)
        elif args.action == 'apply-reader': value = apply_reader(s, args.role, sys.stdin.buffer.read(16385))
        elif args.action == 'activate-siem': value = activate_siem(s, sys.stdin.buffer.read(32769))
        else: value = verify(s, args.role)
        sys.stdout.buffer.write(common.canonical(value))
    except Exception as exc:
        code = str(exc) if isinstance(exc, common.Refused) else type(exc).__name__
        print(json.dumps({'status': 'failed', 'phase': args.action, 'reason': code,
                          'automatic_retry': False, 'partial_installation': STATE.exists()}), file=sys.stderr)
        raise SystemExit(78)


if __name__ == '__main__':
    main()
