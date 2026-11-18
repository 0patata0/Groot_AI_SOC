#!/usr/bin/env python3
"""Exact two-file repair for the existing A certificate observer.

This is a manual, fixed-host change coordinator. It adds no MCP tool or general
root delegation. ``prepare`` stores the reviewed payload and original files;
``apply`` requires its exact plan digest. An independent five-minute timer
restores the originals unless ``confirm`` validates and commits the change.
It must never be used as a fresh-host installer.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

BASE = Path('/var/lib/capstone-cert-rollout')
EXECUTABLE = Path('/usr/local/sbin/capstone-cert-monitor')
UNIT = Path('/etc/systemd/system/capstone-cert-monitor.service')
TIMER = Path('/etc/systemd/system/capstone-cert-monitor.timer')
CERT = Path('/home/groot_a/capstone/chatproxy/tls/chatduck.crt')
STATUS = Path('/var/lib/capstone-cert-monitor/status.json')
SERVICE = 'capstone-cert-monitor.service'
MACHINE = '096e90b6243e438aa8a7b392be754732'
TARGETS = {
    'monitor.sh': (EXECUTABLE, 0o500,
        '91c0ed1025beb3f7bbc59ec38b58c705add1637c8e5c69216eb489d62e65a540',
        'ecc817ceb6dd8d6b24b3ab3087e9642631bea796fb2e3a4e18f81836091b77d8'),
    'capstone-cert-monitor.service': (UNIT, 0o644,
        'd8357b4979398ae4bc2e1f699c1513b5509c447ae0ebd563acf76a2a609e8f64',
        '9c9f50343d7671890e8218352fa69922144d9c34fd50f67d1348a2caa314e97c'),
}
PROTECTED = {
    str(TIMER): '1261726216beca13383a3ef3dcc071f0a9f347a4c90f1341788244a9a15f1703',
    str(CERT): '233bdb1c87014d9e87120e33c4fa648c206372ae361cb4d9e027d724d1117794',
}
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LC_ALL': 'C', 'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1'}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def read(path, mode=None):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
         and info.st_nlink == 1 and not info.st_mode & 0o022
         and 0 < info.st_size <= 131072, 'untrusted_file')
    need(mode is None or stat.S_IMODE(info.st_mode) == mode, 'unexpected_mode')
    return path.read_bytes()


def directory(path):
    need(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    for parent in (path, *path.parents):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'untrusted_directory')


def write(path, raw, mode):
    directory(path.parent)
    if path.exists() or path.is_symlink():
        read(path)
    fd, temporary = tempfile.mkstemp(prefix='.cert-change-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(args, timeout=40, accepted=(0,)):
    result = subprocess.run(args, capture_output=True, env=ENV, timeout=timeout)
    need(result.returncode in accepted, 'fixed_command_failed:' + Path(args[0]).name)
    return result.stdout


@contextmanager
def lock(block=False):
    directory(BASE)
    name = BASE / '.lock'
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
             and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if block else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def load(stage):
    need(stage.parent == BASE and re.fullmatch(r'change-[a-z0-9_]{8}', stage.name), 'invalid_stage')
    directory(stage)
    plan_raw = read(stage / 'plan.json', 0o600)
    plan = json.loads(plan_raw)
    need(plan['stage'] == str(stage) and plan['machine'] == MACHINE, 'plan_binding_changed')
    need(plan['controller_sha256'] == digest(read(stage / 'rollout.py', 0o500)), 'controller_changed')
    need(plan['controller_sha256'] == digest(read(Path(__file__))), 'running_controller_changed')
    need(plan['targets'] == {n: {'path': str(p), 'mode': oct(m), 'before': old, 'after': new}
                            for n, (p, m, old, new) in TARGETS.items()}, 'target_binding_changed')
    need(plan['protected'] == PROTECTED, 'protected_binding_changed')
    for name, (_, _, old, new) in TARGETS.items():
        need(digest(read(stage / ('before-' + name), 0o600)) == old, 'backup_changed')
        need(digest(read(stage / ('after-' + name), 0o600)) == new, 'candidate_changed')
    return plan, digest(plan_raw), json.loads(read(stage / 'state.json', 0o600))


def protected():
    for name, expected in PROTECTED.items():
        need(digest(read(Path(name))) == expected, 'protected_file_changed')


def state_write(stage, state):
    write(stage / 'state.json', canonical(state), 0o600)


def prepare(source):
    directory(source)
    protected()
    originals = {}
    candidates = {}
    for name, (path, mode, old, new) in TARGETS.items():
        originals[name] = read(path, mode)
        candidates[name] = read(source / name)
        need(digest(originals[name]) == old and digest(candidates[name]) == new, 'source_precondition_changed')
    if not BASE.exists():
        directory(BASE.parent)
        BASE.mkdir(mode=0o700)
    with lock():
        stage = Path(tempfile.mkdtemp(prefix='change-', dir=BASE))
        stage.chmod(0o700)
        directory(Path(__file__).parent)
        controller = read(Path(__file__))
        write(stage / 'rollout.py', controller, 0o500)
        for name in TARGETS:
            write(stage / ('before-' + name), originals[name], 0o600)
            write(stage / ('after-' + name), candidates[name], 0o600)
        plan = {'schema': 1, 'machine': MACHINE, 'stage': str(stage),
                'controller_sha256': digest(controller), 'protected': PROTECTED,
                'targets': {n: {'path': str(p), 'mode': oct(m), 'before': old, 'after': new}
                            for n, (p, m, old, new) in TARGETS.items()},
                'automatic_rollback_seconds': 300, 'http_requests': 0,
                'restarts': 'one observer oneshot; no proxy restart or certificate replacement'}
        write(stage / 'plan.json', canonical(plan), 0o600)
        state_write(stage, {'phase': 'prepared', 'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat()})
        return {'stage': str(stage), 'plan_sha256': digest(canonical(plan)), 'plan': plan}


def health(armed_epoch):
    fields = command(['systemctl', 'show', SERVICE, '--property=Result', '--property=ExecMainStatus']).decode()
    need('Result=success' in fields.splitlines() and 'ExecMainStatus=0' in fields.splitlines(), 'observer_result_unverified')
    event = json.loads(read(STATUS, 0o600))
    need(event['domain'] == 'chat.grootlab.duckdns.org' and event['probe_status'] == 'verified'
         and event['reason'] == 'verified' and event['certificate_sha256'] == event['served_certificate_sha256']
         and event['automatic_renewal'] is False, 'observer_status_unverified')
    observed = datetime.fromisoformat(event['observed_at_kst']).timestamp()
    need(observed >= int(armed_epoch) and observed <= time.time() + 1, 'observer_status_stale')
    return event


def mutate(stage, action, approved_plan=None):
    with lock(block=(action == 'rollback')):
        plan, plan_id, state = load(stage)
        timer = 'capstone-cert-' + stage.name + '-rollback'
        if action == 'apply':
            need(approved_plan == plan_id and state['phase'] == 'prepared', 'exact_approval_required')
            protected()
            for _, (path, mode, old, _) in TARGETS.items():
                need(digest(read(path, mode)) == old, 'operating_source_changed')
            active = command(['systemctl', 'show', SERVICE, '--property=ActiveState']).decode().strip()
            need(active == 'ActiveState=inactive', 'observer_must_be_inactive')
            # Arm before changing either operating file. The timer and controller
            # remain on A if the caller's SSH connection or laptop disappears.
            command(['systemd-run', '--quiet', '--unit=' + timer, '--on-active=300s',
                     '--timer-property=AccuracySec=1s', '--property=Type=oneshot',
                     '--property=TimeoutStartSec=120s',
                     '/usr/bin/python3', '-B', str(stage / 'rollout.py'), 'rollback', '--stage', str(stage)])
            command(['systemctl', 'is-active', '--quiet', timer + '.timer'])
            state = {'phase': 'armed', 'armed_epoch': time.time(), 'timer': timer, 'plan_sha256': plan_id}
            state_write(stage, state)
            for name, (path, mode, _, _) in TARGETS.items():
                write(path, read(stage / ('after-' + name), 0o600), mode)
            command(['systemctl', 'daemon-reload'])
            command(['systemctl', 'start', SERVICE])
            event = health(state['armed_epoch'])
            state['phase'] = 'applied'
            state_write(stage, state)
            return {'phase': 'applied', 'plan_sha256': plan_id, 'status': event, 'rollback_timer': timer + '.timer'}
        if action == 'confirm':
            need(state['phase'] == 'applied', 'applied_change_required')
            need(time.time() < state['armed_epoch'] + 300, 'confirmation_deadline_expired')
            protected()
            for _, (path, mode, _, new) in TARGETS.items():
                need(digest(read(path, mode)) == new, 'operating_candidate_changed')
            event = health(state['armed_epoch'])
            # Commit under the same lock before cancelling the timer. A waiting
            # rollback sees this terminal state and cannot undo a confirmation.
            state.update(phase='confirmed', at_kst=datetime.now(timezone(timedelta(hours=9))).isoformat())
            state_write(stage, state)
            command(['systemctl', 'stop', timer + '.timer'])
            command(['systemctl', 'is-active', '--quiet', timer + '.timer'], accepted=(3, 4))
            return {'phase': 'confirmed', 'plan_sha256': plan_id, 'status': event}
        need(action == 'rollback', 'unknown_action')
        if state['phase'] in ('confirmed', 'rolled_back', 'prepared'):
            return {'phase': state['phase'], 'changed': False}
        need(state['phase'] in ('armed', 'applied'), 'unknown_phase')
        # Inspect every target before writing any; never overwrite a later edit.
        for _, (path, mode, old, new) in TARGETS.items():
            need(digest(read(path, mode)) in (old, new), 'rollback_conflicting_edit')
        for name, (path, mode, _, _) in TARGETS.items():
            write(path, read(stage / ('before-' + name), 0o600), mode)
        command(['systemctl', 'daemon-reload'])
        state.update(phase='rolled_back', at_kst=datetime.now(timezone(timedelta(hours=9))).isoformat())
        state_write(stage, state)
        return {'phase': 'rolled_back', 'changed': True, 'status_requires_fresh_observation': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'apply', 'confirm', 'rollback'))
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--stage', type=Path)
    parser.add_argument('--approved-plan')
    args = parser.parse_args()
    need(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MACHINE, 'fixed_A_root_required')
    if args.action == 'prepare':
        need(args.source_root is not None and args.stage is None and args.approved_plan is None, 'prepare_arguments_required')
        result = prepare(args.source_root)
    else:
        need(args.stage is not None and args.source_root is None, 'stage_required')
        need(args.action == 'apply' or args.approved_plan is None, 'approval_only_for_apply')
        result = mutate(args.stage, args.action, args.approved_plan)
    print(json.dumps(result, ensure_ascii=False))
