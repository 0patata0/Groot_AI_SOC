#!/usr/bin/env python3
"""Root maintenance: disable unused host IPv6 without recreating containers.

Invoked by deploy.sh --ipv4-only. No packages, arbitrary shell, or LLM sudo.
Each host is a separate transaction with a 15 minute independent recovery timer.
Docker live restore is enabled and verified before restarting only its daemon.
The saved recovery copy is deliberately independent of the installed source.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

STATE = Path('/var/lib/capstone-ipv4-only')
DAEMON = Path('/etc/docker/daemon.json')
SYSCTL = Path('/etc/sysctl.d/99-z-capstone-ipv4-only.conf')
SSH = Path('/etc/ssh/sshd_config.d/00-capstone-ipv4-only.conf')
SOCKET = Path('/etc/systemd/system/ssh.socket.d/99-capstone-ipv4-only.conf')
OPTIONS = {'live-restore': True, 'ipv6': False, 'ip6tables': False, 'userland-proxy': False}
SSH_DATA = b'AddressFamily inet\n'
SOCKET_DATA = b'[Socket]\nListenStream=\nListenStream=0.0.0.0:22\nBindIPv6Only=default\n'
SYSCTL_DATA = b'net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n'

def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result

def json_file(path):
    path = trusted(path)
    require(path.stat().st_size <= 1024 * 1024, 'JSON file too large')
    return json.loads(path.read_text(), object_pairs_hook=unique)

def fingerprint(path):
    path = trusted(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None

def recovery_files_match(doc):
    # The first successful rollout predates the per-write ledger. Its expected
    # candidates are derived only from saved original bytes, never current edits.
    expected = dict(doc.get('written', {}))
    if not expected:
        for name, saved in doc['files'].items():
            raw = base64.b64decode(saved['data']) if saved['exists'] else b''
            values = []
            if name == str(DAEMON):
                config = json.loads(raw, object_pairs_hook=unique) if raw else {}
                values = [(json.dumps(dict(config, **opts), sort_keys=True, indent=2) + '\n').encode()
                          for opts in ({'live-restore': True}, OPTIONS)]
            elif name == str(SYSCTL): values = [SYSCTL_DATA]
            elif name == str(SSH): values = [SSH_DATA]
            elif name == str(SOCKET): values = [SOCKET_DATA]
            elif name == '/etc/default/chrony':
                values = [re.sub(r'^DAEMON_OPTS="([^"\n]*)"$', lambda m: 'DAEMON_OPTS="' + m[1] + ' -4"', raw.decode(), flags=re.M).encode()]
            elif name == '/etc/apache2/ports.conf':
                values = [re.sub(r'(?m)^(\s*Listen\s+)(80|443)\s*$', r'\g<1>0.0.0.0:\2', raw.decode()).encode()]
            expected[name] = [hashlib.sha256(value).hexdigest() for value in values]
    for name, saved in doc['files'].items():
        original = hashlib.sha256(base64.b64decode(saved['data'])).hexdigest() if saved['exists'] else None
        require(fingerprint(Path(name)) in [original, *expected.get(name, [])], 'recovery file drift: ' + name)

def run(args, check=True, timeout=45, input=None):
    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    p = subprocess.run(args, input=input, capture_output=True, text=True, env=env, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('command failed: ' + args[0] + ': ' + p.stderr[-1200:])
    return p

def require(ok, message):
    if not ok: raise RuntimeError(message)

def trusted(path):
    path = Path(path)
    for parent in [*reversed(path.parents), path]:
        if parent.exists() or parent.is_symlink():
            s = parent.lstat()
            require(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'unsafe path: ' + str(parent))
            require(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'unsafe file type: ' + str(parent))
    return path

def write(path, data, mode=0o644):
    path = trusted(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    trusted(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.ipv4-')
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), mode); f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_DIRECTORY); os.fsync(d); os.close(d)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def read_state(path):
    path = trusted(path)
    require(path.parent == STATE and re.fullmatch(r'run-[0-9]+', path.name), 'invalid recovery directory')
    return path, json.loads(trusted(path / 'state.json').read_text())

def containers():
    ids = run(['docker', 'ps', '-aq', '--no-trunc']).stdout.split()
    if not ids: return {}
    rows = [json.loads(x) for x in run(['docker', 'inspect', '--format', '{{json .}}', *ids]).stdout.splitlines()]
    return {r['Id']: {'name': r['Name'], 'running': r['State']['Running'], 'pid': r['State']['Pid'], 'started': r['State']['StartedAt']} for r in rows}

def snapshot():
    return {'addresses': json.loads(run(['ip', '-j', '-6', 'addr']).stdout),
            'routes': json.loads(run(['ip', '-j', '-6', 'route', 'show', 'table', 'all']).stdout),
            'listeners': run(['ss', '-H', '-6', '-lntup']).stdout.splitlines(),
            'tables': [x['table'] for x in json.loads(run(['nft', '-j', 'list', 'tables']).stdout)['nftables'] if 'table' in x],
            'containers': containers(),
            'disabled': {p.parent.name: p.read_text().strip() for p in Path('/proc/sys/net/ipv6/conf').glob('*/disable_ipv6')},
            'live_restore': run(['docker', 'info', '--format', '{{.LiveRestoreEnabled}}']).stdout.strip()}

def verify(before=None):
    s = snapshot()
    require(not any(x.get('addr_info') for x in s['addresses']), 'IPv6 addresses remain')
    require(not s['routes'] and not s['listeners'], 'IPv6 routes/listeners remain')
    require(not any(x['family'] == 'ip6' for x in s['tables']), 'IPv6 tables remain')
    require(s['disabled'] and set(s['disabled'].values()) == {'1'}, 'IPv6 interface setting drift')
    require(s['live_restore'] == 'true', 'live restore disabled')
    require(all(json_file(DAEMON).get(k) == v for k, v in OPTIONS.items()), 'Docker setting drift')
    require(all(trusted(p).read_bytes() == data for p, data in ((SYSCTL, SYSCTL_DATA), (SSH, SSH_DATA), (SOCKET, SOCKET_DATA))), 'persistent configuration drift')
    if before is not None: require(s['containers'] == before['containers'], 'container identity/process changed')
    return s

def daemon_config(value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with tempfile.NamedTemporaryFile(dir=STATE, prefix='daemon-', delete=False) as f:
        tmp = Path(f.name); f.write(raw)
    try: run(['dockerd', '--validate', '--config-file', str(tmp)])
    finally: tmp.unlink()
    return raw

def restart_daemon(before):
    run(['systemctl', 'restart', 'docker.service'], timeout=60)
    require(containers() == before['containers'], 'Docker restart changed container process')

def rollback(directory, manual=False):
    directory, doc = read_state(directory)
    if (directory / 'confirmed').exists() and not manual: return {'state': 'confirmed_noop'}
    recovery_files_match(doc)
    # Keep live restore enabled through the recovery restart; original setting
    # is restored via reload only after the original networking options return.
    original = doc['files'][str(DAEMON)]
    config = json.loads(base64.b64decode(original['data'])) if original['exists'] else {}
    write(DAEMON, daemon_config(dict(config, **{'live-restore': True})))
    restart_daemon(doc['before'])
    for name, item in doc['files'].items():
        path = trusted(Path(name))
        if item['exists']: write(path, base64.b64decode(item['data']), item['mode'])
        elif path.exists(): path.unlink()
    for name, value in doc['before']['disabled'].items():
        p = Path('/proc/sys/net/ipv6/conf') / name / 'disable_ipv6'
        if p.exists(): p.write_text(value)
    for table in doc['ip6']:
        existing = run(['nft', 'list', 'table', 'ip6', table['name']], check=False)
        prefix = 'delete table ip6 ' + table['name'] + '\n' if existing.returncode == 0 else ''
        run(['nft', '-f', '-'], input=prefix + table['text'])
    run(['systemctl', 'reload', 'docker.service'])
    run(['sshd', '-t'])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'restart', 'ssh.socket', 'ssh.service'])
    for service in doc['services']: run(['systemctl', 'restart', service])
    write(directory / 'rolled-back.json', b'{"state":"rolled_back"}\n', 0o600)
    return {'state': 'rolled_back', 'containers_preserved': containers() == doc['before']['containers']}

def apply():
    if all(p.exists() for p in (SYSCTL, SSH, SOCKET)):
        return {'state': 'already_applied', 'after': verify()}
    before = snapshot()
    config = json_file(DAEMON) if DAEMON.exists() else {}
    require(type(config) is dict, 'Docker configuration must be an object')
    # Bridge IPv6 would require container/network recreation and is outside this
    # bounded maintenance transaction; refuse rather than silently disconnect.
    nets = run(['docker', 'network', 'ls', '-q']).stdout.split()
    require(all(not x.get('EnableIPv6') for x in json.loads(run(['docker', 'network', 'inspect', *nets]).stdout)), 'IPv6-enabled Docker network needs explicit migration')
    require('KillMode=process' in run(['systemctl', 'show', 'ssh.service', '-p', 'KillMode']).stdout, 'SSH child connection preservation unavailable')
    targets = [DAEMON, SYSCTL, SSH, SOCKET]
    services = []
    chrony = Path('/etc/default/chrony')
    apache = Path('/etc/apache2/ports.conf')
    if chrony.exists() and run(['systemctl', 'is-active', 'chrony.service'], check=False).returncode == 0:
        targets.append(chrony); services.append('chrony.service')
    if apache.exists() and run(['systemctl', 'is-active', 'apache2.service'], check=False).returncode == 0:
        targets.append(apache); services.append('apache2.service')
    require(not any(p.exists() for p in (SYSCTL, SSH, SOCKET)), 'existing IPv4-only configuration requires review')
    files = {}
    for p in targets:
        trusted(p)
        files[str(p)] = {'exists': p.exists(), 'mode': stat.S_IMODE(p.stat().st_mode) if p.exists() else 0o644, 'data': base64.b64encode(p.read_bytes()).decode() if p.exists() else ''}
    ip6 = []
    for table in before['tables']:
        if table['family'] == 'ip6':
            require(re.fullmatch(r'[A-Za-z0-9_-]+', table['name']), 'unexpected IPv6 table name')
            ip6.append({'name': table['name'], 'text': run(['nft', 'list', 'table', 'ip6', table['name']]).stdout})
    # Validate the final Docker configuration before creating a recovery timer.
    final = daemon_config(dict(config, **OPTIONS))
    directory = STATE / ('run-' + str(time.time_ns())); directory.mkdir(mode=0o700)
    doc = {'before': before, 'files': files, 'ip6': ip6, 'services': services, 'written': {}}
    def put(path, data):
        # Record the expected next state before replacing bytes. Recovery
        # accepts original/our own intermediate hashes, never a third edit.
        doc['written'].setdefault(str(path), []).append(hashlib.sha256(data).hexdigest())
        write(directory / 'state.json', (json.dumps(doc) + '\n').encode(), 0o600)
        write(path, data)
    write(directory / 'state.json', (json.dumps(doc) + '\n').encode(), 0o600)
    write(directory / 'recovery.py', Path(__file__).read_bytes(), 0o700)
    timer = 'capstone-ipv4-' + directory.name
    run(['systemd-run', '--quiet', '--unit=' + timer, '--on-active=15min', '/usr/bin/python3', '-IB', str(directory / 'recovery.py'), 'rollback', '--directory', str(directory)])
    try:
        put(DAEMON, daemon_config(dict(config, **{'live-restore': True})))
        run(['systemctl', 'reload', 'docker.service'])
        require(run(['docker', 'info', '--format', '{{.LiveRestoreEnabled}}']).stdout.strip() == 'true', 'live restore reload failed')
        require(containers() == before['containers'], 'container process changed during reload')
        put(DAEMON, final)
        restart_daemon(before)
        put(SSH, SSH_DATA)
        put(SOCKET, SOCKET_DATA)
        run(['sshd', '-t'])
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'restart', 'ssh.socket', 'ssh.service'])
        if chrony in targets:
            raw = chrony.read_text()
            raw, count = re.subn(r'^DAEMON_OPTS="([^"\n]*)"$', lambda m: 'DAEMON_OPTS="' + m[1] + ' -4"', raw, flags=re.M)
            require(count == 1, 'unexpected chrony options')
            put(chrony, raw.encode()); run(['systemctl', 'restart', 'chrony.service'])
        if apache in targets:
            raw, count = re.subn(r'(?m)^(\s*Listen\s+)(80|443)\s*$', r'\g<1>0.0.0.0:\2', apache.read_text())
            require(count >= 1, 'unexpected Apache listeners')
            put(apache, raw.encode()); run(['apache2ctl', 'configtest']); run(['systemctl', 'restart', 'apache2.service'])
        put(SYSCTL, SYSCTL_DATA)
        run(['sysctl', '-p', str(SYSCTL)])
        for p in Path('/proc/sys/net/ipv6/conf').glob('*/disable_ipv6'): p.write_text('1')
        # Existing port mappings can leave old IPv6-only proxy children after
        # live restore. Match executable, argument and start-time immediately
        # before terminating only those obsolete IPv6 proxies.
        killed = []
        for p in Path('/proc').iterdir():
            if not p.name.isdigit(): continue
            try:
                args = (p / 'cmdline').read_bytes().split(b'\0')
                if not args or Path(os.fsdecode(args[0])).name != 'docker-proxy': continue
                i = args.index(b'-host-ip')
                if args[i+1] != b'::': continue
                exe = (p / 'exe').resolve()
                require(exe.name == 'docker-proxy' and exe.stat().st_uid == 0, 'proxy identity mismatch')
                start = (p / 'stat').read_text().split(') ', 1)[1].split()[19]
                require((p / 'stat').read_text().split(') ', 1)[1].split()[19] == start, 'proxy PID reused')
                os.kill(int(p.name), signal.SIGTERM); killed.append(int(p.name))
            except (FileNotFoundError, ProcessLookupError, ValueError): continue
        for t in ip6:
            if run(['nft', 'list', 'table', 'ip6', t['name']], check=False).returncode == 0:
                run(['nft', 'delete', 'table', 'ip6', t['name']])
        time.sleep(1)
        after = verify(before)
        result = {'state': 'awaiting_confirmation', 'directory': str(directory), 'timer': timer + '.timer', 'after': after, 'obsolete_ipv6_proxies_removed': killed}
        write(directory / 'applied.json', (json.dumps(result) + '\n').encode(), 0o600)
        return result
    except BaseException as exc:
        write(directory / 'failure.txt', (str(exc) + '\n').encode(), 0o600)
        recovered = rollback(directory)
        raise RuntimeError(str(exc) + '; recovery=' + json.dumps(recovered)) from exc

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'verify', 'confirm', 'rollback'))
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--manual', action='store_true', help='root operator recovery after confirmation; requires exact saved/installed file hashes')
    args = parser.parse_args()
    require(not args.manual or args.action == 'rollback', '--manual is only valid with rollback')
    require(os.geteuid() == 0, 'root maintenance only')
    trusted(STATE); STATE.mkdir(mode=0o700, exist_ok=True)
    with open(trusted(STATE / 'lock'), 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'apply': result = apply()
        elif args.action == 'verify': result = {'state': 'verified', 'after': verify()}
        elif args.action == 'rollback': result = rollback(args.directory, args.manual)
        else:
            directory, doc = read_state(args.directory)
            verify(doc['before'])
            write(directory / 'confirmed', b'confirmed\n', 0o600)
            run(['systemctl', 'stop', 'capstone-ipv4-' + directory.name + '.timer'])
            result = {'state': 'confirmed', 'directory': str(directory)}
        print(json.dumps(result))

if __name__ == '__main__':
    try: main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('ipv4-only: ' + str(exc), file=sys.stderr); sys.exit(1)
