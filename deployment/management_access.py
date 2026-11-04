#!/usr/bin/env python3
"""Reviewed maintenance of the existing dual-NIC A management access policy.

This is an operator deployment tool, never an LLM/MCP shell capability. It does
not replace a ruleset, reload NAT, restart a container, or restore a live DB.
"""
import argparse
from datetime import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
from zoneinfo import ZoneInfo

ADMIN = '192.168.16.231'
MCP = '10.200.10.10'
STATE = Path('/var/lib/capstone-management-access')
PATHS = {
    'firewall': Path('/etc/nftables.d/capstone-fw.nft'),
    'loader': Path('/usr/local/sbin/capstone-nat.sh'),
    'dnat': Path('/etc/nftables.d/capstone-fwd.nft'),
    'proxy': Path('/home/groot_a/capstone/chatproxy/nginx.conf'),
}
DOMAINS = ('wazuh.groot.lab', 'wazuh.grootlab.duckdns.org')
OLD_SOURCE = '192.168.16.0/25'
COMMENTS = ('capstone-management-ext6', 'capstone-management-ext4',
            'capstone-management-int6', 'capstone-management-int4')
GUARDS = [
    'iifname "ens192" fib daddr type local meta nfproto ipv6 tcp dport { 22, 10443 } counter drop',
    'iifname "ens192" fib daddr type local ip saddr != @mgmt_src tcp dport { 22, 10443 } counter drop',
    'iifname "ens160" fib daddr type local meta nfproto ipv6 tcp dport 22 counter drop',
    f'iifname "ens160" fib daddr type local ip saddr != {MCP} tcp dport 22 counter drop',
]
GUARDS = [f'{rule} comment "{name}"' for rule, name in zip(GUARDS, COMMENTS)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('expected_unique_source_anchor')
    return text.replace(old, new, 1)


def proxy_policy(text):
    """Change only server-level ACLs of the two exact Wazuh virtual hosts."""
    for domain in DOMAINS:
        marker = f'server_name {domain};'
        if text.count(marker) != 1:
            raise ValueError('expected_unique_wazuh_server')
        end = text.index('location / {', text.index(marker))
        start = text.rfind('server {', 0, text.index(marker))
        if start < 0:
            raise ValueError('wazuh_server_boundary')
        prefix = text[start:end]
        acl = re.compile(r'^\s*(?:allow\s+[^;]+;|deny\s+all;|include\s+/etc/nginx/tls/wazuh-vpn-window.allow.conf;)[^\n]*\n', re.M)
        matches = list(acl.finditer(prefix))
        if not matches or len(re.findall(r'^\s*deny\s+all;', prefix, re.M)) != 1:
            raise ValueError('wazuh_server_acl_shape')
        changed = prefix[:matches[0].start()] + f'\n        allow {ADMIN}; # named administrator only\n        deny all;\n' + acl.sub('', prefix[matches[0].start():])
        text = text[:start] + changed + text[end:]
    return text


def candidates(before):
    fw = before['firewall'].decode()
    pattern = r'(set mgmt_src \{.*?elements = \{)(.*?)(\})'
    if len(re.findall(pattern, fw, re.S)) != 1:
        raise ValueError('management_set_shape')
    fw = re.sub(pattern, lambda m: m[1] + ' ' + ADMIN + ' ' + m[3], fw, count=1, flags=re.S)
    fw = once(fw, '        ip saddr @never_block accept',
              '        # Source checks precede exemptions and established sessions.\n' +
              '\n'.join('        ' + x for x in GUARDS) + '\n        ip saddr @never_block accept')
    fw = once(fw, 'iifname "ens160" tcp dport 22 accept',
              f'iifname "ens160" ip saddr {MCP} tcp dport 22 accept')
    fw = fw.replace('**초안 — 아직 미적용.**', '**2026-11-03 관리 ACL 적용.**', 1)
    fw = fw.replace('comment "mgmt SSH sources for ens192 (P4): VPN, dept LANs, ESXi. 192.168.16.0/25 excluded on purpose"',
                    'comment "named administrator only; containment exemptions do not grant management access"')
    loader = once(before['loader'].decode(), f'MGMT_DNAT_SRC="{OLD_SOURCE}"', f'MGMT_DNAT_SRC="{ADMIN}/32"')
    dnat = once(before['dnat'].decode(), f'ip saddr {OLD_SOURCE} tcp dport 10443', f'ip saddr {ADMIN}/32 tcp dport 10443')
    return {'firewall': fw.encode(), 'loader': loader.encode(), 'dnat': dnat.encode(),
            'proxy': proxy_policy(before['proxy'].decode()).encode()}


def run(args, data=None):
    p = subprocess.run(args, input=data, capture_output=True, text=True, timeout=35)
    if p.returncode:
        raise RuntimeError(f'command_failed:{shlex.join(args[:4])}:{p.stderr[-1200:]}')
    return p.stdout


def nft_json():
    return json.loads(run(['nft', '-j', '-a', 'list', 'ruleset']))['nftables']


def dnat_rule(rows):
    found = [r['rule'] for r in rows if 'rule' in r and r['rule'].get('table') == 'capstone_fwd'
             and r['rule'].get('chain') == 'prerouting' and '10443' in json.dumps(r['rule'])]
    if len(found) != 1:
        raise ValueError('unique_existing_management_dnat_required')
    return found[0]


def forward_spec(source):
    return ['-s', source, '-d', '10.200.10.10/32', '-i', 'ens192', '-o', 'ens160',
            '-p', 'tcp', '--dport', '443', '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT']


def forward_index(source):
    expected = forward_spec(source)
    lines = run(['iptables', '-S', 'CAPSTONE-FWD']).splitlines()
    found = []
    index = 0
    for line in lines:
        words = shlex.split(line)
        if words[:2] != ['-A', 'CAPSTONE-FWD']:
            continue
        index += 1
        words = words[2:]
        if words == expected or words == expected[:10] + ['-m', 'tcp'] + expected[10:]:
            found.append(index)
    if len(found) != 1:
        raise ValueError('unique_existing_management_forward_required')
    return found[0]


def guards(rows):
    return [r['rule'] for r in rows if 'rule' in r and r['rule'].get('table') == 'capstone_fw'
            and r['rule'].get('comment') in COMMENTS]


def kernel_change(rows, source, elements, remove=False):
    existing = guards(rows)
    if (not remove and existing) or (remove and len(existing) not in (0, 4)):
        raise ValueError('management_guard_drift')
    commands = [f'delete rule inet capstone_fw prerouting_block handle {r["handle"]}' for r in existing]
    if not remove:
        anchor = [r['rule']['handle'] for r in rows if 'rule' in r and r['rule'].get('table') == 'capstone_fw'
                  and r['rule'].get('chain') == 'prerouting_block'
                  and r['rule'].get('expr') == [{'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '@never_block'}}, {'accept': None}]]
        if len(anchor) != 1:
            raise ValueError('containment_exemption_anchor_drift')
        commands += [f'insert rule inet capstone_fw prerouting_block position {anchor[0]} {x}' for x in GUARDS]
    rule = dnat_rule(rows)
    commands += ['flush set inet capstone_fw mgmt_src',
                 'add element inet capstone_fw mgmt_src { ' + ', '.join(elements) + ' }',
                 f'replace rule ip capstone_fwd prerouting handle {rule["handle"]} iifname "ens192" ip saddr {source} tcp dport 10443 dnat to 10.200.10.10:443']
    return '\n'.join(commands) + '\n'


def checked_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular_file_required')
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError('root_owned_unwritable_source_required')
    return path.read_bytes()


def write_in_place(path, data, meta):
    # nginx uses a file bind mount; replacing its inode leaves stale content.
    with path.open('r+b') as out:
        out.write(data); out.truncate(); out.flush(); os.fsync(out.fileno())
        os.fchown(out.fileno(), meta['uid'], meta['gid']); os.fchmod(out.fileno(), meta['mode'])


def proxy_check(candidate, token):
    dest = '/tmp/capstone-management-' + token + '.conf'
    run(['docker', 'cp', str(candidate), 'chatproxy:' + dest])
    try:
        run(['docker', 'exec', 'chatproxy', 'nginx', '-t', '-c', dest])
    finally:
        run(['docker', 'exec', 'chatproxy', 'rm', '-f', dest])


def stamp():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat()


def load(directory):
    if directory.parent != STATE or not re.fullmatch(r'[0-9a-f]{16}', directory.name):
        raise ValueError('recovery_directory_scope')
    return json.loads(checked_file(directory / 'meta.json'))


def verify(directory):
    meta = load(directory)
    for key, path in PATHS.items():
        if sha(checked_file(path)) != meta['files'][key]['after']:
            raise ValueError('source_drift:' + key)
    rows = nft_json()
    if len(guards(rows)) != 4:
        raise ValueError('kernel_guard_count')
    sets = [x['set'] for x in rows if 'set' in x and x['set'].get('table') == 'capstone_fw' and x['set']['name'] == 'mgmt_src']
    if len(sets) != 1 or sets[0].get('elem') != [ADMIN]:
        raise ValueError('kernel_management_sources')
    forward_index(ADMIN + '/32')
    if ADMIN not in json.dumps(dnat_rule(rows)):
        raise ValueError('kernel_dnat_source')
    run(['docker', 'exec', 'chatproxy', 'nginx', '-t'])
    return {'status': 'verified', 'at_kst': stamp(), 'directory': str(directory)}


def apply():
    before = {key: checked_file(path) for key, path in PATHS.items()}
    after = candidates(before)
    # This tool is intentionally scoped to the recorded current A topology.
    addresses = run(['ip', '-j', '-4', 'addr'])
    if '192.168.16.230' not in addresses or '10.200.10.1' not in addresses:
        raise ValueError('existing_dual_nic_A_required')
    rows = nft_json()
    fwset = [x['set'] for x in rows if 'set' in x and x['set'].get('table') == 'capstone_fw' and x['set']['name'] == 'mgmt_src']
    if len(fwset) != 1:
        raise ValueError('management_set_missing')
    original = []
    for item in fwset[0].get('elem', []):
        if isinstance(item, dict) and 'prefix' in item:
            item = str(ipaddress.IPv4Network(f'{item["prefix"]["addr"]}/{item["prefix"]["len"]}'))
        original.append(str(ipaddress.IPv4Network(item, strict=False)) if '/' in item else str(ipaddress.IPv4Address(item)))
    index = forward_index(OLD_SOURCE)
    transaction = kernel_change(rows, ADMIN + '/32', [ADMIN])
    run(['nft', '-c', '-f', '-'], transaction)
    token = os.urandom(8).hex(); directory = STATE / token
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True); directory.mkdir(mode=0o700)
    meta = {'schema': 1, 'at_kst': stamp(), 'unit': 'capstone-management-' + token,
            'old_sources': original, 'files': {}}
    for key, path in PATHS.items():
        st = path.stat()
        meta['files'][key] = {'before': sha(before[key]), 'after': sha(after[key]), 'uid': st.st_uid, 'gid': st.st_gid, 'mode': st.st_mode & 0o777}
        for suffix, data in [('before', before[key]), ('after', after[key])]:
            p = directory / (key + '.' + suffix); p.write_bytes(data); p.chmod(0o600)
    recovery = directory / 'management_access.py'; recovery.write_bytes(Path(__file__).read_bytes()); recovery.chmod(0o600)
    mp = directory / 'meta.json'; mp.write_text(json.dumps(meta, indent=2)); mp.chmod(0o600)
    run(['bash', '-n', str(directory / 'loader.after')])
    run(['nft', '-c', '-f', '-'], 'delete table inet capstone_fw\n' + after['firewall'].decode())
    proxy_check(directory / 'proxy.after', token)
    run(['systemd-run', '--unit=' + meta['unit'], '--on-active=15m', '--timer-property=AccuracySec=1s',
         '/usr/bin/python3', '-I', '-B', str(recovery), 'recover', '--directory', str(directory)])
    # From this point the independent recovery is armed, including a partial apply.
    for key, path in PATHS.items():
        if checked_file(path) != before[key]:
            raise ValueError('source_changed_during_preparation')
        write_in_place(path, after[key], meta['files'][key])
    run(['nft', '-f', '-'], transaction)
    run(['iptables', '-R', 'CAPSTONE-FWD', str(index)] + forward_spec(ADMIN + '/32'))
    run(['docker', 'exec', 'chatproxy', 'nginx', '-t'])
    run(['docker', 'exec', 'chatproxy', 'nginx', '-s', 'reload'])
    result = verify(directory); result['status'] = 'applied_awaiting_external_verification'
    return result


def rollback(directory):
    meta = load(directory)
    # Recovery must be harmless if it ran already or apply stopped before changes.
    current = {key: sha(checked_file(path)) for key, path in PATHS.items()}
    if any(current[key] not in (v['before'], v['after']) for key, v in meta['files'].items()):
        raise ValueError('recovery_source_conflict')
    rows = nft_json()
    changed = bool(guards(rows))
    if not changed and all(current[k] == v['before'] for k, v in meta['files'].items()):
        return {'status': 'already_original', 'at_kst': stamp()}
    transaction = kernel_change(rows, OLD_SOURCE, meta['old_sources'], remove=True)
    run(['nft', '-c', '-f', '-'], transaction)
    for key, path in PATHS.items():
        write_in_place(path, checked_file(directory / (key + '.before')), meta['files'][key])
    run(['nft', '-f', '-'], transaction)
    try:
        index = forward_index(ADMIN + '/32')
    except ValueError:
        forward_index(OLD_SOURCE)
    else:
        run(['iptables', '-R', 'CAPSTONE-FWD', str(index)] + forward_spec(OLD_SOURCE))
    run(['docker', 'exec', 'chatproxy', 'nginx', '-t'])
    run(['docker', 'exec', 'chatproxy', 'nginx', '-s', 'reload'])
    return {'status': 'rolled_back', 'at_kst': stamp()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'verify', 'confirm', 'rollback', 'recover'))
    parser.add_argument('--directory', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('root_operator_required')
    with open('/run/lock/capstone-management-access.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'apply':
            result = apply()
        elif not args.directory:
            raise ValueError('directory_required')
        elif args.action in ('rollback', 'recover'):
            if args.action == 'recover' and (args.directory / 'confirmed.json').is_file():
                result = verify(args.directory)
                result['status'] = 'confirmed_recovery_noop'
            else:
                result = rollback(args.directory)
        else:
            result = verify(args.directory)
            if args.action == 'confirm':
                meta = load(args.directory)
                p = args.directory / 'confirmed.json'; p.write_text(json.dumps(result)); p.chmod(0o600)
                run(['systemctl', 'stop', meta['unit'] + '.timer'])
                result['status'] = 'confirmed'
        print(json.dumps(result))


if __name__ == '__main__':
    main()
