#!/usr/bin/env python3
"""Compare the fixed A observer in disposable systemd mount namespaces.

The existing executable, state and certificate stay unchanged. Only ``check``
runs. This is a validation command, not an installer or an operating repair.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone, timedelta

MONITOR = Path('/usr/local/sbin/capstone-cert-monitor')
UNIT = Path('/etc/systemd/system/capstone-cert-monitor.service')
TIMER = Path('/etc/systemd/system/capstone-cert-monitor.timer')
STATE = Path('/var/lib/capstone-cert-monitor')
CERT = Path('/home/groot_a/capstone/chatproxy/tls/chatduck.crt')
FILES = (MONITOR, UNIT, TIMER, STATE / 'status.json', CERT)
EXPECTED = {
    str(MONITOR): '91c0ed1025beb3f7bbc59ec38b58c705add1637c8e5c69216eb489d62e65a540',
    str(UNIT): 'd8357b4979398ae4bc2e1f699c1513b5509c447ae0ebd563acf76a2a609e8f64',
    str(TIMER): '1261726216beca13383a3ef3dcc071f0a9f347a4c90f1341788244a9a15f1703',
    str(CERT): '233bdb1c87014d9e87120e33c4fa648c206372ae361cb4d9e027d724d1117794',
}
CANDIDATE = {
    'monitor.sh': 'ecc817ceb6dd8d6b24b3ab3087e9642631bea796fb2e3a4e18f81836091b77d8',
    'capstone-cert-monitor.service': '9c9f50343d7671890e8218352fa69922144d9c34fd50f67d1348a2caa314e97c',
    'test-monitor.sh': 'c742e7a5aa8174b84487e23a8a8d538801171682275f6db7a36be20d73ee270a',
}
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LC_ALL': 'C', 'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1'}


def run(args, timeout=20):
    return subprocess.run(args, capture_output=True, env=ENV, timeout=timeout)


def file_record(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
            or info.st_gid != 0 or info.st_mode & 0o022 or not 0 < info.st_size <= 131072):
        raise ValueError('untrusted_validation_file')
    raw = path.read_bytes()
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'mode': oct(stat.S_IMODE(info.st_mode)), 'uid': info.st_uid, 'gid': info.st_gid}


def properties(source, sandbox_state, allowed):
    """Retain the candidate sandbox, substituting private source and state."""
    return [
        'Type=oneshot', 'User=root', 'Group=root', 'UMask=0077',
        'TimeoutStartSec=30s', 'TimeoutStopSec=1s', 'SuccessExitStatus=2 75',
        'PrivateTmp=yes', 'NoNewPrivileges=yes', 'ProtectSystem=strict',
        'ProtectHome=read-only', 'ReadWritePaths=' + str(STATE),
        'InaccessiblePaths=-/home/groot_a/capstone/chatproxy/tls/chatduck.key',
        'RestrictAddressFamilies=AF_INET AF_UNIX', 'IPAddressDeny=any',
        'IPAddressAllow=' + allowed, 'ProtectKernelTunables=yes',
        'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
        'RestrictSUIDSGID=yes', 'LockPersonality=yes',
        'BindReadOnlyPaths=' + str(source) + ':' + str(MONITOR),
        'BindPaths=' + str(sandbox_state) + ':' + str(STATE),
    ]


def failed_units():
    result = run(['systemctl', 'list-units', '--failed', '--plain', '--no-legend', '--no-pager'])
    if result.returncode:
        raise RuntimeError('failed_unit_observation_failed')
    return sorted(line.split()[0] for line in result.stdout.decode().splitlines() if line.strip())


def check(source_root):
    if os.geteuid() != 0 or Path('/etc/machine-id').read_text().strip() != '096e90b6243e438aa8a7b392be754732':
        raise ValueError('fixed_A_root_required')
    before = {str(path): file_record(path) for path in FILES}
    if any(before[name]['sha256'] != digest for name, digest in EXPECTED.items()):
        raise ValueError('operating_precondition_changed')
    if not source_root.is_absolute() or '..' in source_root.parts:
        raise ValueError('absolute_source_required')
    for directory in (source_root, *source_root.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('untrusted_source_directory')
    candidate = source_root / 'monitor.sh'
    candidate_unit = source_root / 'capstone-cert-monitor.service'
    candidate_test = source_root / 'test-monitor.sh'
    source_records = {path.name: file_record(path) for path in (candidate, candidate_unit, candidate_test)}
    if any(source_records[name]['sha256'] != digest for name, digest in CANDIDATE.items()):
        raise ValueError('candidate_source_changed')
    expected_ip = 'IPAddressAllow=172.18.0.3/32'
    if expected_ip not in candidate_unit.read_text().splitlines():
        raise ValueError('candidate_exact_allow_missing')
    baseline_failures = failed_units()
    owned = Path(tempfile.mkdtemp(prefix='capstone-cert-native-check-', dir='/var/lib'))
    owned.chmod(0o700)
    cases = []
    units = []
    report = {'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(),
              'candidate_sources': source_records, 'operating_sources_before': before,
              'mode': 'check_only_private_bind_mounts', 'operating_changes': 0,
              'operating_status_or_journal_publications': 0, 'http_requests': 0}
    try:
        for path in (candidate, candidate_test):
            result = run(['/bin/bash', '-n', str(path)])
            if result.returncode:
                raise RuntimeError('shell_syntax_failed')
        result = run(['systemd-analyze', 'verify', str(candidate_unit)])
        if result.returncode:
            raise RuntimeError('candidate_unit_syntax_failed')
        result = run(['/bin/bash', str(candidate_test), str(candidate), str(owned)], timeout=65)
        if result.returncode:
            raise RuntimeError('native_regression_failed')
        report['regression'] = json.loads(result.stdout.decode().splitlines()[-1])
        if report['regression'].get('passed') != 26:
            raise RuntimeError('native_regression_incomplete')
        for label, raw, allow in [
            ('installed_baseline', MONITOR.read_bytes(), '127.0.0.1/32'),
            ('candidate', candidate.read_bytes(), '127.0.0.1/32 172.18.0.3/32'),
        ]:
            arm = owned / label
            arm.mkdir(mode=0o700)
            executable = arm / 'monitor'
            executable.write_bytes(raw)
            executable.chmod(0o500)
            state = arm / 'state'
            state.mkdir(mode=0o700)
            status = state / 'status.json'
            status.write_bytes((STATE / 'status.json').read_bytes())
            status.chmod(0o600)
            status_before = file_record(status)
            name = 'capstone-cert-check-' + secrets.token_hex(6) + '.service'
            units.append(name)
            argv = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + name]
            argv += ['--property=' + value for value in properties(executable, state, allow)]
            started = time.monotonic()
            result = run(argv + [str(MONITOR), 'check'], timeout=35)
            elapsed = time.monotonic() - started
            if result.returncode not in (0, 2):
                raise RuntimeError('isolated_entry_failed')
            event = json.loads(result.stdout)
            if label == 'installed_baseline' and (event['probe_status'], event['reason']) != ('unavailable', 'tls_timeout'):
                raise RuntimeError('baseline_did_not_reproduce')
            if label == 'candidate' and (result.returncode != 0 or event['probe_status'] != 'verified'
                                       or event['certificate_sha256'] != event['served_certificate_sha256']):
                raise RuntimeError('candidate_not_verified')
            if status_before != file_record(status) or list(state.glob('.probe.*')):
                raise RuntimeError('check_modified_private_status_or_left_scratch')
            result_state = run(['systemctl', 'show', name, '--property=LoadState', '--property=ActiveState'])
            if b'LoadState=not-found' not in result_state.stdout:
                raise RuntimeError('transient_not_collected')
            cases.append({'case': label, 'unit': name, 'exit': result.returncode,
                          'seconds': round(elapsed, 4), 'event': event, 'collected': True,
                          'private_status_unchanged': True, 'full_cm_main_check': True})
    finally:
        # Stop only this invocation's units before removing its private files.
        for name in units:
            run(['systemctl', 'stop', name], timeout=8)
            run(['systemctl', 'reset-failed', name], timeout=8)
        shutil.rmtree(owned)
    after = {str(path): file_record(path) for path in FILES}
    if before != after or failed_units() != baseline_failures:
        raise RuntimeError('operating_sources_or_failed_units_changed')
    report.update(cases=cases, owned_root_removed=not owned.exists(),
                  operating_sources_unchanged=True, failed_units_unchanged=True,
                  operating_failed_units=baseline_failures, full_installed_run_not_executed=True)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.source_root), ensure_ascii=False))
