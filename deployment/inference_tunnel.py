#!/usr/bin/env python3
"""Optional administrator-owned SSH transport for an existing Ollama endpoint.

deploy.sh remains the fresh-install entrypoint. The external inference host,
restricted public-key authorization and root-only client key are prerequisites.
This module never downloads models, relaxes a firewall, or exports a key.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import urllib.request

ROOT = Path('/etc/capstone-inference')
UNIT = Path('/etc/systemd/system/capstone-inference-tunnel.service')
KEY = ROOT / 'id_ed25519'
KNOWN = ROOT / 'known_hosts'
SSH = ROOT / 'ssh_config'
RECEIPT = ROOT / 'receipt.json'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'PYTHONDONTWRITEBYTECODE': '1'}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def read(path, private=False):
    path = Path(path)
    for p in [path, *path.parents]:
        s = p.lstat()
        need(not p.is_symlink() and s.st_uid == 0 and not s.st_mode & 0o022,
             'inference_untrusted_path')
    s = path.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size < 65536,
         'inference_unsafe_file')
    need(not private or stat.S_IMODE(s.st_mode) == 0o600, 'inference_private_file_mode')
    return path.read_bytes()


def configuration(data):
    need(type(data) is dict and set(data) == {'schema', 'remote_host', 'remote_port',
         'remote_user', 'listen_host', 'listen_port', 'host_key'}, 'inference_config_fields')
    need(type(data['schema']) is int and data['schema'] == 1, 'inference_schema')
    for field in ('remote_host', 'listen_host'):
        address = ipaddress.IPv4Address(data[field])
        need(str(address) == data[field] and not address.is_multicast and
             not address.is_unspecified and str(address) != '255.255.255.255', 'inference_address')
    need(not ipaddress.IPv4Address(data['remote_host']).is_loopback, 'inference_remote_loopback')
    need(ipaddress.IPv4Address(data['listen_host']).is_private, 'inference_private_listener_required')
    for field in ('remote_port', 'listen_port'):
        need(type(data[field]) is int and 1024 <= data[field] <= 65535, 'inference_port')
    need(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', data['remote_user']) is not None,
         'inference_user')
    need(re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}', data['host_key']) is not None,
         'inference_pinned_ed25519_key')
    return data


def documents(c):
    pin = '[%s]:%d %s\n' % (c['remote_host'], c['remote_port'], c['host_key'])
    config = '''Host backend
    HostName {remote_host}
    Port {remote_port}
    User {remote_user}
    IdentityFile /etc/capstone-inference/id_ed25519
    IdentityAgent none
    IdentitiesOnly yes
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    StrictHostKeyChecking yes
    UserKnownHostsFile /etc/capstone-inference/known_hosts
    GlobalKnownHostsFile /dev/null
    RequestTTY no
    PermitLocalCommand no
    ControlMaster no
    ControlPath none
    ConnectTimeout 15
    ServerAliveInterval 15
    ServerAliveCountMax 3
    ExitOnForwardFailure yes
    LocalForward {listen_host}:{listen_port} 127.0.0.1:11434
'''.format(**c)
    unit = '''[Unit]
Description=Restricted SSH transport to the SOC inference API
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
User=root
ExecStart=/usr/bin/ssh -F /etc/capstone-inference/ssh_config -NT backend
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET
[Install]
WantedBy=multi-user.target
'''
    return {KNOWN: pin.encode(), SSH: config.encode(), UNIT: unit.encode()}


def run(args):
    p = subprocess.run(args, env=ENV, capture_output=True, timeout=30)
    need(p.returncode == 0, 'inference_command_failed:' + Path(args[0]).name)
    return p.stdout


def check(c):
    read(KEY, True)
    # Parsing the existing private key stays on B; no key bytes enter receipts.
    public = run(['/usr/bin/ssh-keygen', '-y', '-f', str(KEY)]).decode().split()
    need(len(public) >= 2 and public[0] == 'ssh-ed25519', 'inference_client_key_type')
    addresses = json.loads(run(['/usr/sbin/ip', '-j', '-4', 'address', 'show']))
    local = {a['local'] for i in addresses for a in i.get('addr_info', [])}
    need(c['listen_host'] in local, 'inference_listener_not_local')
    return documents(c)


def atomic(path, raw, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.inference-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode); os.fchown(f.fileno(), 0, 0)
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def verify(c):
    payload = check(c)
    for path, raw in payload.items():
        need(read(path) == raw, 'inference_installed_file_drift')
    run(['/usr/bin/systemctl', 'is-enabled', '--quiet', UNIT.name])
    run(['/usr/bin/systemctl', 'is-active', '--quiet', UNIT.name])
    url = 'http://%s:%d/api/version' % (c['listen_host'], c['listen_port'])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=10) as response:
        result = json.loads(response.read(8192))
    need(isinstance(result.get('version'), str), 'inference_api_unverified')
    return {'status': 'verified', 'ollama_version': result['version'],
            'listener': '%s:%d' % (c['listen_host'], c['listen_port'])}


def install(c):
    payload = check(c)
    if RECEIPT.exists():
        need(json.loads(read(RECEIPT))['configuration'] == c, 'inference_configuration_changed')
        return verify(c)
    need(all(not p.exists() and not p.is_symlink() for p in payload), 'inference_existing_files')
    for path, raw in payload.items(): atomic(path, raw, 0o644 if path == UNIT else 0o600)
    run(['/usr/bin/ssh', '-G', '-F', str(SSH), 'backend'])
    run(['/usr/bin/systemctl', 'daemon-reload'])
    run(['/usr/bin/systemctl', 'enable', '--now', UNIT.name])
    # Keep an explicit installation record even if the remote API is currently
    # unreachable; never turn an unavailable endpoint into a success result.
    atomic(RECEIPT, (json.dumps({'configuration': c, 'files': {
        str(p): hashlib.sha256(v).hexdigest() for p, v in payload.items()}}, indent=2)+'\n').encode())
    return {'status': 'started_verification_required'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('check', 'install', 'verify'))
    p.add_argument('--config', required=True)
    args = p.parse_args()
    need(os.geteuid() == 0, 'inference_root_required')
    c = configuration(json.loads(read(args.config, True)))
    if args.action == 'check': check(c); result = {'status': 'prerequisites_checked'}
    else: result = install(c) if args.action == 'install' else verify(c)
    print(json.dumps(result))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc) if type(exc) is ValueError else type(exc).__name__) from None
