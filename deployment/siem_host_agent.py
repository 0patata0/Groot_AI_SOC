#!/usr/bin/env python3
"""Administrator bootstrap of a distinct Ubuntu SIEM-host Wazuh agent.

Called by the siem role of deploy.sh after the local manager is healthy.
Packages must already be imported offline. No downloads, manager restart,
remote enrollment listener changes, or LLM execution privileges are added.
"""
import argparse
from datetime import datetime
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from zoneinfo import ZoneInfo

HOME = Path('/var/ossec')
STATE = Path('/var/lib/capstone-siem-host-agent')
LOCK = Path('/var/lib/.capstone-siem-host-agent.lock')
NAMES = {'groot': ('single-node-wazuh.manager-1', 'groot-siem-host'),
         'fresh': ('capstone-wazuh-manager', 'capstone-siem-host')}
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1',
       'DOCKER_HOST': 'unix:///var/run/docker.sock'}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(args, data=None, timeout=30, check=True):
    r = subprocess.run(args, input=data, capture_output=True, timeout=timeout, env=ENV)
    # Neither keys nor command output may enter exception messages or receipts.
    need(not check or r.returncode == 0, 'host_agent_command_failed:' + Path(args[0]).name)
    return r


def trusted(path, directory=False):
    path = Path(path)
    s = path.lstat()
    package_owned = path.is_relative_to(HOME) and s.st_uid == pwd.getpwnam('wazuh').pw_uid
    need(not path.is_symlink() and (s.st_uid == 0 or package_owned) and not s.st_mode & 0o002,
         'host_agent_untrusted_path')
    need(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
         'host_agent_unsafe_type')
    # Wazuh's package-owned etc directory may be group writable by wazuh.
    if s.st_mode & 0o020:
        need(s.st_gid == grp.getgrnam('wazuh').gr_gid and path.is_relative_to(HOME),
             'host_agent_unsafe_group_write')


def read(path):
    path = Path(path)
    for parent in reversed(path.parents):
        trusted(parent, True)
    trusted(path)
    need(path.stat().st_size <= 2 * 1024 * 1024, 'host_agent_file_bound')
    return path.read_bytes()


def atomic(path, data, gid=0):
    path = Path(path)
    trusted(path.parent, True)
    if path.exists() or path.is_symlink():
        trusted(path)
    fd, name = tempfile.mkstemp(prefix='.host-agent-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), 0, gid)
            os.fchmod(stream.fileno(), 0o640 if gid else 0o600)
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(name): os.unlink(name)


def candidate(raw, address='127.0.0.1'):
    ip = ipaddress.IPv4Address(address)
    need(str(ip) == address and not ip.is_multicast and not ip.is_unspecified, 'host_agent_invalid_endpoint')
    text = raw.decode()
    root = ET.fromstring('<root>' + text + '</root>')
    clients = root.findall('ossec_config/client')
    responses = root.findall('ossec_config/active-response')
    need(len(clients) == len(responses) == 1, 'host_agent_ambiguous_configuration')
    need(clients[0].findtext('server/address') == 'MANAGER_IP', 'host_agent_not_fresh_configuration')
    for path, expected in [('sca/enabled', 'yes'), ('sca/scan_on_start', 'yes'),
                           ('wodle[@name="syscollector"]/disabled', 'no'),
                           ('syscheck/disabled', 'no')]:
        need(root.findtext('ossec_config/' + path) == expected, 'host_agent_collection_disabled')
    need(any(x.findtext('log_format') == 'journald' for x in root.findall('ossec_config/localfile')),
         'host_agent_journald_missing')
    # Preserve package defaults, comments, log sources, SCA and inventory bytes.
    client = ('<client>\n    <server><address>' + address + '</address><port>1514</port>'
              '<protocol>tcp</protocol></server>\n'
              '    <config-profile>ubuntu, ubuntu24, ubuntu24.04</config-profile>\n'
              '    <notify_time>20</notify_time><time-reconnect>60</time-reconnect>\n'
              '    <auto_restart>yes</auto_restart><crypto_method>aes</crypto_method>\n'
              '    <enrollment><enabled>no</enabled></enrollment>\n  </client>')
    text, count = re.subn(r'<client>.*?</client>', lambda _: client, text, flags=re.S)
    need(count == 1, 'host_agent_client_replace_ambiguous')
    def disable(match):
        block, count = re.subn(r'<disabled>\s*(?:yes|no)\s*</disabled>',
                              '<disabled>yes</disabled>', match[0])
        need(count == 1, 'host_agent_response_replace_ambiguous')
        return block
    text, count = re.subn(r'<active-response>.*?</active-response>', disable, text, flags=re.S)
    need(count == 1, 'host_agent_response_missing')
    return text.encode()


def check():
    version = run(['dpkg-query', '-W', '-f=${Status}\t${Version}', 'wazuh-agent']).stdout
    need(version == b'install ok installed\t4.14.8-1', 'host_agent_version_4_14_8_1_required')
    need(not (HOME / 'bin/wazuh-analysisd').exists(), 'host_agent_native_manager_conflict')
    need(read(HOME / 'etc/client.keys').strip() == b'', 'host_agent_already_registered')
    need(run(['systemctl', 'is-active', 'wazuh-agent'], check=False).stdout.strip() == b'inactive',
         'host_agent_must_be_stopped')
    raw = read(HOME / 'etc/ossec.conf')
    candidate(raw)
    read(HOME / 'ruleset/sca/cis_ubuntu24-04.yml')
    return raw


def manager(layout):
    name, _ = NAMES[layout]
    row = json.loads(run(['docker', 'inspect', name]).stdout)[0]
    expected = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'wazuh/wazuh-manager:4.14.8']).stdout.decode().strip()
    need(row['State']['Running'] and row['Image'] == expected,
         'host_agent_manager_version_or_state')
    return row['Id'], row['State']['Pid']


def manager_endpoint(cid):
    row = json.loads(run(['docker', 'inspect', cid]).stdout)[0]
    ports = row['NetworkSettings']['Ports'].get('1514/tcp') or []
    choices = [p['HostIp'] for p in ports if p['HostPort'] == '1514' and ':' not in p['HostIp']]
    if '0.0.0.0' in choices or '127.0.0.1' in choices:
        return '127.0.0.1'
    local = json.loads(run(['ip', '-j', '-4', 'address', 'show']).stdout)
    local = {v['local'] for r in local for v in r.get('addr_info', [])}
    choices = set(choices) & local
    need(len(choices) == 1, 'host_agent_local_manager_port_ambiguous')
    return choices.pop()


def manager_keys(cid):
    # Private bytes stay on this host; never return them to a caller or log them.
    return run(['docker', 'exec', cid, 'cat', '/var/ossec/etc/client.keys']).stdout


def new_key(before, after, name):
    old = before.splitlines()
    added = [row for row in after.splitlines() if row not in old]
    need(len(added) == 1 and all(after.splitlines().count(row) == old.count(row) for row in set(old)),
         'host_agent_manager_keys_changed_unexpectedly')
    row = added[0]
    fields = row.split()
    need(len(fields) == 4 and re.fullmatch(rb'[0-9]{3,8}', fields[0]) and int(fields[0]) > 0
         and fields[1] == name.encode() and fields[2] == b'any'
         and re.fullmatch(rb'[A-Za-z0-9]{64,128}', fields[3]), 'host_agent_key_identity_invalid')
    return fields[0].decode(), row + b'\n'


def verify(layout):
    receipt = json.loads(read(STATE / 'receipt.json'))
    need(receipt['status'] == 'connected' and receipt['layout'] == layout, 'host_agent_receipt_incomplete')
    need(sha(read(HOME / 'etc/ossec.conf')) == receipt['config_sha256'], 'host_agent_configuration_drift')
    key = read(HOME / 'etc/client.keys')
    need(key.split()[:3] == [receipt['agent_id'].encode(), NAMES[layout][1].encode(), b'any'],
         'host_agent_identity_drift')
    cid, _ = manager(layout)
    need(key.strip() in manager_keys(cid).splitlines(), 'host_agent_key_mismatch')
    run(['systemctl', 'is-active', '--quiet', 'wazuh-agent'])
    run(['systemctl', 'is-enabled', '--quiet', 'wazuh-agent'])
    state = (HOME / 'var/run/wazuh-agentd.state').read_text()
    need("status='connected'" in state, 'host_agent_disconnected')
    need(time.time() - (HOME / 'var/run/wazuh-agentd.state').stat().st_mtime < 180,
         'host_agent_connection_state_stale')
    return {k: receipt[k] for k in ('status', 'agent_id', 'agent_name', 'config_sha256', 'registered_at_kst')}


def install(layout):
    if STATE.exists() or STATE.is_symlink():
        return verify(layout)
    raw = check()
    cid, pid = manager(layout); name = NAMES[layout][1]
    address = manager_endpoint(cid); proposed = candidate(raw, address)
    before = manager_keys(cid)
    need(not any(len(row.split()) >= 2 and row.split()[1] == name.encode() for row in before.splitlines()),
         'host_agent_name_already_registered')
    trusted(STATE.parent, True); STATE.mkdir(mode=0o700)
    atomic(STATE / 'ossec.conf.before', raw)
    atomic(STATE / 'pending.json', json.dumps({'layout': layout, 'agent_name': name}).encode())
    conf = HOME / 'etc/ossec.conf'; gid = grp.getgrnam('wazuh').gr_gid
    try:
        need(read(conf) == raw and not read(HOME / 'etc/client.keys').strip(), 'host_agent_concurrent_edit')
        atomic(conf, proposed, gid)
        for binary in ('wazuh-agentd', 'wazuh-logcollector', 'wazuh-modulesd', 'wazuh-syscheckd'):
            run([str(HOME / 'bin' / binary), '-t'])
        run(['docker', 'exec', '-i', cid, '/var/ossec/bin/manage_agents', '-a', 'any', '-n', name], data=b'y\n')
        agent_id, key = new_key(before, manager_keys(cid), name)
        need(not read(HOME / 'etc/client.keys').strip(), 'host_agent_key_concurrent_edit')
        atomic(HOME / 'etc/client.keys', key, gid)
        run(['systemctl', 'enable', '--now', 'wazuh-agent'], timeout=90)
        for _ in range(30):
            path = HOME / 'var/run/wazuh-agentd.state'
            if path.exists() and "status='connected'" in path.read_text(): break
            time.sleep(2)
        else: raise ValueError('host_agent_connection_timeout')
        need(manager(layout) == (cid, pid), 'host_agent_manager_restarted')
        receipt = {'status': 'connected', 'layout': layout, 'agent_id': agent_id, 'agent_name': name,
                   'manager_address': address,
                   'config_sha256': sha(proposed), 'registered_at_kst': datetime.now(ZoneInfo('Asia/Seoul')).isoformat(),
                   'active_response_disabled': True, 'enrollment_disabled': True}
        atomic(STATE / 'receipt.json', (json.dumps(receipt, indent=2) + '\n').encode())
        return verify(layout)
    except Exception:
        run(['systemctl', 'disable', '--now', 'wazuh-agent'], check=False, timeout=90)
        # Retain registration and private backup for explicit recovery; never
        # delete another agent or silently re-register after a partial failure.
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'install', 'verify'))
    parser.add_argument('--layout', choices=NAMES, default='fresh')
    args = parser.parse_args()
    need(os.geteuid() == 0, 'host_agent_root_required')
    if args.action == 'check':
        if STATE.exists(): result = verify(args.layout)
        else: check(); result = {'status': 'fresh_prerequisites_verified'}
    elif args.action == 'verify': result = verify(args.layout)
    else:
        trusted(LOCK.parent, True)
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'r+') as lock:
            trusted(LOCK); fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = install(args.layout)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc) if type(exc) is ValueError else type(exc).__name__) from None
