#!/usr/bin/env python3
"""Fixed rootless sudo adapter. No caller-selected commands or Docker options."""
import fcntl
from contextlib import contextmanager
import hashlib
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
import threading
import time
import types

CVE = 'CVE-2021-3156'
USER, UID = 'capstone-sudo', 1991
HOME = Path('/var/lib/capstone-sudo-runtime')
BASE = Path('/opt/capstone-offline-labs/nonweb/sudo')
CONFIG = Path('/etc/capstone-sudo-lab/config.json')
MANIFEST = Path('/var/lib/capstone-sudo-bootstrap/manifest.json')
OUTPUT = Path('/var/lib/capstone-nonweb-labs')
PROFILE = 'ubuntu24.04-amd64-sudo-rootless-29.8.1-v1'
SOURCE_PINS = {
    'lab.py': '9dcb05226db9fd5464cc0cb2168f4833b009f489171c65fadeaa3ace29378100',
    'publish.py': '4db72b8e3ce05b5adc4bbbe462203bf3bd73a0c96eb7a6039effa09569c6077b',
}
APPROVED_CONFIG = {
    'schema': 1, 'operator_uid': UID,
    'image_id': 'sha256:90fd1384894d26e34c2364b0ff8fb8bdb92a3e9ebc3df5dee29a61b68bfcab2a',
    'deb_sha256': 'de4106cd19a5b9f8acac9e0ab5f40f218d3ac321cc58143e051baab064a5fb36',
    'preparation_sha256': '8c69d341e14798ec161d093031f0ae54473d7d089166c3eedba6bbda0ce042ff',
}
SOCKET = 'unix:///run/user/1991/docker.sock'
HEX = re.compile(r'[0-9a-f]{64}\Z')
LIMIT = 131072
BUDGETS = {'status': 40, 'getcontainer': 40, 'stop': 40, 'up': 200}
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'HOME': '/nonexistent', 'DOCKER_CONFIG': '/nonexistent', 'LANG': 'C',
       'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}

# The operator lock covers expected-CID comparison and the stop itself. Calling
# the ordinary CLI after an unlocked comparison could stop a replacement CID.
# This code is a root-owned constant; only a validated hex CID is substituted
# as a separate argv item. It never evaluates browser terminal input.
EXACT_STOP = r'''
import fcntl,importlib.util,json,os,pwd,stat,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('fixed_sudo_exact_stop','/opt/capstone-offline-labs/nonweb/sudo/lab.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
uid=os.geteuid()
lab.require(uid==1991 and os.getuid()==uid and len(sys.argv)==2 and lab.HASH.fullmatch(sys.argv[1]),'invalid_exact_stop')
config=lab.config_at(Path('/etc/capstone-sudo-lab/config.json'),uid)
home=Path(pwd.getpwuid(uid).pw_dir);lab.trusted_parents(home,{0,uid})
state=home/'.local/state/capstone-sudo-lab';lab.trusted_parents(state,{0,uid})
lab.require(state.stat().st_uid==uid and stat.S_IMODE(state.stat().st_mode)==0o700,'private_state_required')
fd=os.open(state/'operation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'r+') as lock:
 meta=os.fstat(lock.fileno())
 lab.require(meta.st_uid==uid and meta.st_nlink==1 and stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode)==0o600,'unsafe_lock_file')
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 runtime=lab.Lab(config,lab.Docker(uid),state)
 current=runtime.inventory()
 lab.require(current is not None and current['Id']==sys.argv[1],'exact_container_changed')
 print(json.dumps(runtime.run('stop'),sort_keys=True))
'''


class Rejected(Exception):
    pass


def need(value, code):
    if not value:
        raise Rejected(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def root_parents(path):
    need(path.is_absolute() and '..' not in path.parts, 'untrusted_path')
    for item in (path, *path.parents):
        meta = item.lstat()
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
             'untrusted_parent')


def root_file(path, limit=LIMIT, private=False):
    root_parents(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == meta.st_gid == 0
             and meta.st_nlink == 1 and not meta.st_mode & (0o077 if private else 0o022)
             and 0 < meta.st_size <= limit, 'untrusted_file')
        return stream.read(limit + 1)


def executable(path):
    # /usr/bin/python3 is an administrator-owned distribution symlink. Resolve
    # it and validate both its root-owned parent and the executable target.
    source = Path(path)
    root_parents(source.parent)
    meta = source.lstat()
    need(meta.st_uid == 0 and (stat.S_ISLNK(meta.st_mode) or
         (stat.S_ISREG(meta.st_mode) and not meta.st_mode & 0o022)), 'untrusted_executable')
    resolved = source.resolve(strict=True)
    root_parents(resolved.parent)
    meta = resolved.stat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022
         and bool(meta.st_mode & 0o111), 'untrusted_executable')
    return str(source)


def operator_prefix():
    account = pwd.getpwuid(UID)
    need(account.pw_name == USER and account.pw_gid == UID and account.pw_dir == str(HOME)
         and account.pw_shell == '/usr/sbin/nologin', 'operator_identity_changed')
    return [executable('/usr/sbin/runuser'), '-u', USER, '--', executable('/usr/bin/env'), '-i',
            'PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME=' + str(HOME),
            'DOCKER_CONFIG=/nonexistent', 'XDG_RUNTIME_DIR=/run/user/1991',
            'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus',
            'LANG=C', 'LC_ALL=C', 'PYTHONDONTWRITEBYTECODE=1']


class Adapter:
    def __init__(self):
        self.lock = threading.RLock()
        self.modules = None
        self.module_hashes = None
        self.installation_mode = None
        self.deadline = None

    @contextmanager
    def _budget(self, seconds):
        # Public operations hold the same RLock. A nested exact stop or fresh
        # identity lookup must consume its caller's budget, never renew it.
        previous = self.deadline
        if previous is None:
            self.deadline = time.monotonic() + seconds
        try:
            self._probe_timeout(seconds)
            yield
            self._probe_timeout(seconds)
        finally:
            self.deadline = previous

    def _probe_timeout(self, limit):
        remaining = limit if self.deadline is None else min(limit, self.deadline - time.monotonic())
        need(remaining > 0, 'sudo_operation_timeout')
        return remaining

    def _context(self):
        need(os.getuid() == 0 and os.geteuid() == 0, 'root_adapter_required')
        source = {name: root_file(BASE / name) for name in ('lab.py', 'publish.py')}
        hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in source.items()}
        need(hashes == SOURCE_PINS, 'sudo_source_pin_mismatch')
        config_raw = root_file(CONFIG, 16384)
        # The first approved C installation predates the offline bootstrap
        # receipt. Recognize only its exact reviewed source/config/image pins;
        # this is not permission to adopt an arbitrary existing rootless lab.
        has_manifest = True
        try:
            value = json.loads(root_file(MANIFEST, 65536, private=True), object_pairs_hook=unique)
        except FileNotFoundError:
            value = None
            has_manifest = False
        if has_manifest:
            need(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1
                 and value.get('profile') == PROFILE and value.get('state') == 'complete'
                 and isinstance(value.get('source_sha256'), dict) and isinstance(value.get('files'), dict),
                 'unverified_sudo_bootstrap')
            need(all(value['source_sha256'].get(name) == digest for name, digest in hashes.items()),
                 'sudo_source_pin_mismatch')
            recorded = value['files'].get(str(CONFIG))
            need(isinstance(recorded, dict) and recorded.get('sha256') == hashlib.sha256(config_raw).hexdigest(),
                 'sudo_config_pin_mismatch')
        if self.modules is None or self.module_hashes != hashes:
            modules = {}
            for name, raw in source.items():
                module = types.ModuleType('fixed_sudo_terminal_' + name[:-3])
                module.__file__ = str(BASE / name)
                exec(compile(raw, str(BASE / name), 'exec'), module.__dict__)
                modules[name] = module
            self.modules, self.module_hashes = modules, hashes
        lab, publisher = self.modules['lab.py'], self.modules['publish.py']
        config = lab.config_at(CONFIG, UID)
        need(config == APPROVED_CONFIG, 'sudo_approved_config_required')
        if has_manifest:
            need(config['image_id'] == value.get('image_id'), 'sudo_image_pin_mismatch')
        self.installation_mode = 'managed_bootstrap' if has_manifest else 'approved_legacy'
        return lab, publisher, config

    def _operator(self, args, timeout=90):
        need(type(timeout) is int and 1 <= timeout <= 120, 'invalid_operation_timeout')
        root_parents(OUTPUT)
        command = operator_prefix() + [executable('/usr/bin/prlimit'), '--fsize=131072:131072', '--'] + args
        with tempfile.TemporaryFile(dir=OUTPUT) as output:
            os.fchmod(output.fileno(), 0o600)
            remaining = self._probe_timeout(timeout)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.DEVNULL, env=ENV, start_new_session=True)
            try:
                # Process creation itself also consumes the operation budget.
                code = process.wait(timeout=self._probe_timeout(remaining))
            except (subprocess.TimeoutExpired, Rejected):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                raise Rejected('sudo_operation_timeout') from None
            need(os.fstat(output.fileno()).st_size < LIMIT, 'sudo_probe_output_limit')
            output.seek(0)
            raw = output.read(LIMIT)
        try:
            value = json.loads(raw, object_pairs_hook=unique)
        except (ValueError, UnicodeError, RecursionError):
            raise Rejected('invalid_sudo_probe') from None
        return code, value

    def _cli(self, action):
        need(action in ('up', 'status', 'verify', 'stop'), 'invalid_sudo_action')
        code, value = self._operator([executable('/usr/bin/python3'), '-B', str(BASE / 'lab.py'), action])
        need(code == 0 and isinstance(value, dict) and value.get('schema') == 1
             and type(value['schema']) is int and value.get('cve_id') == CVE,
             'sudo_operation_failed')
        return value

    def _inspect(self, lab, kind, identifier):
        need(kind in ('image', 'container'), 'invalid_inspection')
        code, values = self._operator([lab.docker_binary(), '--host', SOCKET, kind, 'inspect', identifier], 15)
        need(code == 0 and isinstance(values, list) and len(values) == 1 and isinstance(values[0], dict),
             'sudo_inspection_failed')
        return values[0]

    def _status(self, verify_running=True):
        lab, publisher, config = self._context()
        value = self._cli('status')
        lab.image_contract(self._inspect(lab, 'image', config['image_id']), config)
        status = value.get('status')
        cid = value.get('container_id')
        need(status in ('not_created', 'running', 'stopped') and
             ((status == 'not_created' and cid is None) or
              (status != 'not_created' and isinstance(cid, str) and HEX.fullmatch(cid))),
             'invalid_sudo_identity')
        if cid:
            container = self._inspect(lab, 'container', cid)
            lab.container_contract(container, config, cid)
            need(container.get('State', {}).get('Running') is (status == 'running'),
                 'sudo_container_changed')
        if status == 'running' and verify_running:
            verified = self._cli('verify')
            publisher.ready_contract(verified, config, int(time.time()))
            need(verified.get('container_id') == cid, 'sudo_container_changed')
            container = self._inspect(lab, 'container', cid)
            lab.container_contract(container, config, cid)
            need(container.get('State', {}).get('Running') is True, 'sudo_container_stopped')
            need(lab.running_isolation(container, config) == verified.get('isolation'),
                 'sudo_root_attestation_mismatch')
        return {'ok': True, 'schema': 1, 'lab': 'sudo', 'cve_id': CVE,
                'status': 'not_deployed' if status == 'not_created' else status,
                'verification': 'environment_only', 'image_present': True,
                'container_id': cid, 'exec_user': '1000:1000', 'deployment_allowed': True}

    def _receipt(self, lab, config):
        # Root observes the dedicated operator's receipt but never accepts its
        # CID without inspecting the fixed rootless container contract too.
        state = HOME / '.local/state/capstone-sudo-lab'
        lab.trusted_parents(state, {0, UID})
        need(state.stat().st_uid == UID and stat.S_IMODE(state.stat().st_mode) == 0o700,
             'unsafe_sudo_state')
        value = lab.read_json(state / 'runtime.json', UID, private=True)
        need(isinstance(value, dict) and set(value) == {'schema', 'container_id', 'image_id'}
             and type(value['schema']) is int and value['schema'] == 1
             and isinstance(value['container_id'], str) and HEX.fullmatch(value['container_id'])
             and value['image_id'] == config['image_id'], 'invalid_sudo_receipt')
        return value

    def _stop_context(self, cid):
        lab, _, config = self._context()
        receipt = self._receipt(lab, config)
        need(receipt['container_id'] == cid, 'sudo_container_changed')
        code, info = self._operator([lab.docker_binary(), '--host', SOCKET,
                                     'info', '--format', '{{json .}}'], 15)
        need(code == 0 and isinstance(info, dict), 'sudo_daemon_unavailable')
        lab.daemon_contract(info, resources=False)
        container = self._inspect(lab, 'container', cid)
        lab.container_contract(container, config, cid)
        if container.get('State', {}).get('Running') is True:
            lab.running_isolation(container, config)
        return lab, config

    def runtime(self, action, lab='sudo'):
        need(lab == 'sudo' and action in ('up', 'status', 'stop', 'getcontainer'), 'invalid_sudo_action')
        with self.lock, self._budget(BUDGETS[action]):
            if action == 'up':
                self._context()
                self._cli('up')
            if action == 'stop':
                module, _, config = self._context()
                try:
                    cid = self._receipt(module, config)['container_id']
                except FileNotFoundError:
                    # The ordinary status path refuses an unreceipted named
                    # container instead of adopting or deleting it.
                    before = self._status()
                    need(before['container_id'] is None, 'sudo_container_changed')
                    return before
                self.stop_exact(cid)
                container = self._inspect(module, 'container', cid)
                module.container_contract(container, config, cid)
                need(container.get('State', {}).get('Running') is False, 'sudo_stop_unconfirmed')
                present = True
                try:
                    module.image_contract(self._inspect(module, 'image', config['image_id']), config)
                except Exception:
                    present = False
                return {'ok': True, 'schema': 1, 'lab': 'sudo', 'cve_id': CVE,
                        'status': 'stopped', 'verification': 'environment_only',
                        'image_present': present, 'container_id': cid,
                        'exec_user': '1000:1000', 'deployment_allowed': present}
            value = self._status()
            if action == 'getcontainer':
                need(value['status'] == 'running', 'sudo_terminal_not_running')
            return value

    def exec_argv(self, cid):
        need(isinstance(cid, str) and HEX.fullmatch(cid), 'invalid_sudo_container')
        with self.lock, self._budget(40):
            value = self.runtime('getcontainer')
            need(value['container_id'] == cid, 'sudo_container_changed')
            lab, _, _ = self._context()
            return operator_prefix() + [lab.docker_binary(), '--host', SOCKET, 'exec', '-i', '-t',
                '--user', '1000:1000', '--workdir', '/tmp', '--env', 'TERM=xterm-256color',
                '--env', 'HOME=/tmp', cid, '/usr/bin/timeout', '--foreground', '--signal=TERM',
                '--kill-after=2s', '1800s', '/bin/sh', '-i']

    def stop_exact(self, cid):
        need(isinstance(cid, str) and HEX.fullmatch(cid), 'invalid_sudo_container')
        with self.lock, self._budget(40):
            self._stop_context(cid)
            code, value = self._operator([executable('/usr/bin/python3'), '-B', '-c', EXACT_STOP, cid])
            need(code == 0 and isinstance(value, dict) and value.get('schema') == 1
                 and type(value['schema']) is int and value.get('cve_id') == CVE
                 and value.get('container_id') == cid and value.get('status') == 'stopped',
                 'sudo_exact_stop_failed')
            # Never stop again if another operator has already replaced the CID.
            return True


def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ('check', 'stop'), 'fixed_action_required')
    print(json.dumps(Adapter().runtime('status' if sys.argv[1] == 'check' else 'stop'), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'ok': False, 'error': 'sudo_terminal_unavailable'}))
        raise SystemExit(1)
