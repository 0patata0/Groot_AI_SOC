#!/usr/bin/env python3
"""Optional operator-only, offline B-host trial. Never starts a chat gateway.

Fresh-install entry is deploy.sh with OLLAMA_TRIAL_ENABLE=1. Existing hosts use
this same bounded implementation for the incremental install, not full bootstrap.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone, timedelta

ROOT = Path('/opt/capstone-ollama-trial')
ETC = Path('/etc/capstone-ollama-trial')
STATE = Path('/var/lib/capstone-ollama-trial')
USER = 'soc-ollama'
PROFILES = {'rule-a': ('rule-a',), 'rule-b': ('rule-b',),
            'security-events': ('mcp-b', 'security-events'),
            'system-diagnostics': ('mcp-b', 'system-diagnostics'), 'wazuh-ro': ('mcp-b',)}
SOURCES = ('runtime.py', 'policy.py', 'requirements.lock', 'offline-manifest.json')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'Asia/Seoul',
       'PYTHONDONTWRITEBYTECODE': '1', 'PIP_NO_CACHE_DIR': '1',
       'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'DEBIAN_FRONTEND': 'noninteractive'}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def safe(path, directory=False):
    p = Path(path)
    need(p.is_absolute() and '..' not in p.parts, 'absolute_path_required')
    for parent in [*reversed(p.parents), p]:
        s = parent.lstat()
        sticky_parent = parent != p and str(parent) in ('/tmp', '/var/tmp') and bool(s.st_mode & stat.S_ISVTX)
        need(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and
             (not s.st_mode & 0o022 or sticky_parent), 'untrusted_path')
    need(p.is_dir() if directory else p.is_file(), 'path_type')
    return p


def run(args, *, input=None, timeout=180, check=True):
    p = subprocess.run([str(a) for a in args], input=input, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=ENV, timeout=timeout)
    need(not check or p.returncode == 0, 'command_failed_' + Path(str(args[0])).name)
    return p


def write(path, data, mode=0o640, gid=0, uid=0):
    path = Path(path)
    need(not path.is_symlink(), 'destination_symlink')
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
        os.fchmod(f.fileno(), mode); os.fchown(f.fileno(), uid, gid)


def bundle_check(source, bundle):
    expected = safe(source / 'offline-manifest.json')
    need(digest(expected) == digest(safe(bundle / 'offline-manifest.json')), 'bundle_manifest_mismatch')
    doc = json.loads(expected.read_text())
    need(doc['schema'] == 1 and len(doc['debs']) == 3 and 1 <= len(doc['wheels']) <= 160, 'manifest_schema')
    for kind, suffix in [('debs', '.deb'), ('wheels', '.whl')]:
        seen = set()
        for item in doc[kind]:
            name = item['filename']
            need(re.fullmatch(r'[A-Za-z0-9_.+%-]+', name) and name.endswith(suffix) and
                 name not in seen and re.fullmatch(r'[0-9a-f]{64}', item['sha256']), 'artifact_name')
            seen.add(name)
            p = safe(bundle / kind / name)
            need(p.stat().st_size == item['size'] and digest(p) == item['sha256'], 'artifact_hash')
        need({p.name for p in (bundle / kind).iterdir()} == seen, 'unexpected_artifact')
    need({x['package'] for x in doc['debs']} ==
         {'python3.12-venv', 'python3-pip-whl', 'python3-setuptools-whl'}, 'deb_allowlist')
    for item in doc['debs']:
        raw = run(['dpkg-deb', '-f', bundle / 'debs' / item['filename'], 'Package', 'Version', 'Architecture']).stdout.decode()
        info = dict(line.split(': ', 1) for line in raw.splitlines())
        need(info == {'Package': item['package'], 'Version': item['version'],
                      'Architecture': item['architecture']}, 'deb_metadata')
    return doc


def hostpath(path, home):
    need(path.startswith('/opt/data/'), 'unexpected_hermes_path')
    out = home / path[len('/opt/data/'):]
    need(out.resolve().is_relative_to(home.resolve()), 'hermes_path_escape')
    return out


def connection_plan(home):
    # Read operator-controlled config only; do not import an agent or environment.
    import yaml
    need(home.is_absolute() and not home.is_symlink(), 'hermes_home')
    config = yaml.safe_load((home / 'config.yaml').read_text())
    output = {}
    for key in ('rule-a', 'rule-b', 'wazuh-ro'):
        p = config['mcp_servers'][key]; args = p['args']
        need(p['command'] in ('ssh', '/usr/bin/ssh') and len(args) == 4 and
             args[:2] == ['-T', '-F'], 'ssh_profile_shape')
        sshconfig = hostpath(args[2], home)
        owner = pwd.getpwuid(sshconfig.stat().st_uid)
        need(owner.pw_uid != 0, 'hermes_config_unprivileged_owner')
        raw = run(['runuser', '-u', owner.pw_name, '--', 'ssh', '-G', '-F', sshconfig, args[3]], timeout=20).stdout.decode()
        values = {}
        for line in raw.splitlines():
            k, _, v = line.partition(' ')
            values.setdefault(k, []).append(v)
        one = lambda k: values[k][0]
        need(one('user') == 'ruleview' if key.startswith('rule-') else
             one('user') in ('mcp', 'capstone-mcp'), 'ssh_account_scope')
        need(re.fullmatch(r'[0-9.]+', one('hostname')) and one('port').isdigit(), 'ssh_host_shape')
        need(len(values['identityfile']) == 1, 'single_identity_required')
        if key.startswith('rule-'):
            need(Path(one('identityfile')).name in ('rule_readonly_ed25519', 'soc_readonly_ed25519'),
                 'readonly_key_required')
        output[key] = {'host': one('hostname'), 'port': one('port'), 'user': one('user'),
                       'key': hostpath(one('identityfile'), home),
                       'known': hostpath(one('userknownhostsfile'), home)}
    account = pwd.getpwnam(output['wazuh-ro']['user'])
    authorized = Path(account.pw_dir) / '.ssh/authorized_keys'
    # Match the installed forced-command restriction, never a shell credential.
    text = authorized.read_text()
    commands = set(re.findall(r'restrict,command="([^"\n]+)"\s+ssh-ed25519 ', text))
    allowed = {'/opt/mcp/run-wazuh-ro.sh', '/opt/capstone/siem/mcp/run-wazuh-ro.sh',
               '/opt/capstone/siem/mcp/run.sh'}
    need(len(commands) == 1 and commands <= allowed, 'readonly_forced_command_required')
    return config, output, authorized, commands.pop()


def verify():
    receipt = json.loads(safe(ETC / 'receipt.json').read_text())
    for name, expected in receipt['sources'].items():
        need(digest(safe(ROOT / name)) == expected, 'installed_source_changed')
    user = pwd.getpwnam(USER)
    need(user.pw_uid != 0 and user.pw_shell == '/usr/sbin/nologin', 'trial_identity')
    groups = run(['id', '-nG', USER]).stdout.decode().split()
    need(set(groups) == {USER}, 'trial_groups')
    for name in ('sudo', 'docker'):
        need(name not in groups, 'privileged_trial_group')
    result = run([ROOT / 'venv/bin/python', '-I', '-B', '-m', 'pip', 'check'])
    probe = run(['/usr/local/sbin/capstone-ollama-trial'], input=b'{"discover_only":true}\n', timeout=120)
    data = json.loads(probe.stdout)
    need(data['status'] == 'discovered' and len(data['catalog']) == 26 and
         data['model_calls'] == [] and data['protected_calls'] == 0, 'trial_discovery')
    return {'status': 'verified', 'readonly_tools': 26, 'servers': 5,
            'model_requests': 0, 'pip_check': result.returncode == 0, 'uid': user.pw_uid,
            'network_mode': 'host_process', 'daemon': False}


def install(source, bundle, home):
    if (ETC / 'receipt.json').exists():
        return verify()
    need(not ROOT.exists() and not ETC.exists() and not STATE.exists(), 'partial_install_requires_review')
    config, connections, authorized, force = connection_plan(home)
    doc = bundle_check(source, bundle)
    packages = []
    for item in doc['debs']:
        r = run(['dpkg-query', '-W', '-f=${Status}\t${Version}', item['package']], check=False)
        fields = r.stdout.decode().split('\t')
        if r.returncode == 0 and len(fields) == 2 and fields[0] == 'install ok installed':
            need(run(['dpkg', '--compare-versions', fields[1], 'ge', item['version']], check=False).returncode == 0,
                 'installed_package_version_requires_review')
            continue
        packages.append(bundle / 'debs' / item['filename'])
    if packages:
        # These three reviewed archives have no new service or maintainer fetch.
        run(['dpkg', '-i', *packages], timeout=180)
    try:
        pwd.getpwnam(USER)
        raise ValueError('trial_user_already_exists')
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', STATE,
             '--shell', '/usr/sbin/nologin', USER])
    user = pwd.getpwnam(USER)
    for path in (ROOT, ETC, ETC / 'ssh', STATE):
        path.mkdir(mode=0o750)
        os.chown(path, user.pw_uid if path == STATE else 0, user.pw_gid)
    for name in SOURCES:
        write(ROOT / name, safe(source / name).read_bytes(), gid=user.pw_gid)
    run(['python3', '-I', '-B', '-m', 'venv', ROOT / 'venv'])
    run([ROOT / 'venv/bin/python', '-I', '-B', '-m', 'pip', 'install', '--no-index',
         '--no-cache-dir', '--disable-pip-version-check', '--no-compile', '--require-hashes',
         '--find-links', bundle / 'wheels', '-r', ROOT / 'requirements.lock'], timeout=300)
    run([ROOT / 'venv/bin/python', '-I', '-B', '-m', 'pip', 'check'])
    # New B-only key; A/B ruleview key is already restricted to read-only calls.
    key = ETC / 'ssh/mcp_b_ed25519'
    run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'capstone-ollama-trial-readonly', '-f', key])
    os.chown(key, user.pw_uid, user.pw_gid); os.chmod(key, 0o600)
    pub = key.with_suffix('.pub').read_text().strip()
    line = 'restrict,command="' + force + '" ' + pub + '\n'
    old = authorized.read_bytes()
    backup = ETC / 'authorized_keys.before'
    write(backup, old, mode=0o600)
    st = authorized.stat()
    write(authorized, old + (b'' if old.endswith(b'\n') else b'\n') + line.encode(),
          mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)
    configtext = ''
    for name, con in connections.items():
        name = 'mcp-b' if name == 'wazuh-ro' else name
        targetkey = key if name == 'mcp-b' else ETC / ('ssh/' + name + '_ed25519')
        if name != 'mcp-b':
            write(targetkey, con['key'].read_bytes(), mode=0o600, uid=user.pw_uid, gid=user.pw_gid)
        known = ETC / ('ssh/' + name + '_known_hosts')
        write(known, con['known'].read_bytes(), gid=user.pw_gid)
        configtext += (f'Host {name}\n HostName {con["host"]}\n Port {con["port"]}\n User {con["user"]}\n'
                       f' IdentityFile {targetkey}\n UserKnownHostsFile {known}\n'
                       ' IdentitiesOnly yes\n BatchMode yes\n StrictHostKeyChecking yes\n'
                       ' ConnectTimeout 10\n ServerAliveInterval 15\n ServerAliveCountMax 2\n'
                       ' ForwardAgent no\n ClearAllForwardings yes\n')
    write(ETC / 'ssh/config', configtext.encode(), gid=user.pw_gid)
    profiles = {name: {'command': '/usr/bin/ssh', 'args': ['-T', '-F', str(ETC / 'ssh/config'), *args],
                       'env': {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}} for name, args in PROFILES.items()}
    base = config['model']['base_url'].rstrip('/')
    need(base.endswith('/v1'), 'hermes_endpoint_shape')
    cfg = {'schema': 1, 'base_url': base[:-3], 'model': config['model']['default'], 'mcpServers': profiles}
    write(ETC / 'config.json', json.dumps(cfg, indent=2).encode(), gid=user.pw_gid)
    wrapper = ('#!/bin/sh\nset -eu\numask 077\n'
               'exec /usr/sbin/runuser -u soc-ollama -- /usr/bin/env -i '
               'HOME=/var/lib/capstone-ollama-trial PATH=/usr/bin:/bin TZ=Asia/Seoul '
               'PYTHONDONTWRITEBYTECODE=1 /opt/capstone-ollama-trial/venv/bin/python -I -B '
               '/opt/capstone-ollama-trial/runtime.py "$@"\n')
    write('/usr/local/sbin/capstone-ollama-trial', wrapper.encode(), mode=0o755)
    receipt = {'schema': 1, 'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
               'sources': {name: digest(ROOT / name) for name in SOURCES},
               'offline_bundle': str(bundle), 'authorized_keys': str(authorized),
               'registered_public_key': pub, 'readonly_only': True, 'uid': user.pw_uid,
               'model_downloaded': False, 'new_listener': False}
    write(ETC / 'receipt.json', json.dumps(receipt, indent=2).encode(), mode=0o600)
    return verify()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=('check', 'install', 'verify'))
    p.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--bundle', type=Path, default=Path('/opt/capstone-prereqs/ollama-trial'))
    p.add_argument('--hermes-home', type=Path, default=Path('/opt/capstone/siem/capstone-hermes'))
    args = p.parse_args()
    need(os.geteuid() == 0, 'operator_root_required')
    source = args.source_root / 'infra/ollama-trial'
    if args.action == 'check':
        doc = bundle_check(source, args.bundle)
        result = {'status': 'checked', 'debs': len(doc['debs']), 'wheels': len(doc['wheels']), 'mutations': 0}
    elif args.action == 'install':
        result = install(source, args.bundle, args.hermes_home)
    else:
        result = verify()
    print(json.dumps(result))


if __name__ == '__main__':
    main()
