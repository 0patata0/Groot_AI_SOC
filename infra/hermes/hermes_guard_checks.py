#!/usr/bin/env python3
"""Read-only, fixed-path checks for native Ansible orchestration.

No Docker invocation, file writes, package installation, restart or policy/DB
migration. Only hashes, counts and fixed status fields leave this process.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import stat
import sys
import time

DATA = Path('/opt/hermes-data')
SOURCE = Path('/opt/hermes')
CORE = 'capstone_korean_output_guard.py'
INTEGRATIONS = ('plugins/platforms/mattermost/adapter.py', 'gateway/run_turn.py')
PROTECTED = ('config.yaml', '.env', 'SOUL.md', 'cron/jobs.json', 'state.db', 'state.db-wal', 'state.db-shm')


def require(value, code):
    if not value:
        raise ValueError(code)


def metadata(path: Path, optional=False):
    try:
        before = path.lstat()
    except FileNotFoundError:
        if optional:
            return {'exists': False}
        raise ValueError('required_file_missing') from None
    require(stat.S_ISREG(before.st_mode), 'nonregular_file')
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), 'file_changed')
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    require((opened.st_size, opened.st_mtime_ns) == (after.st_size, after.st_mtime_ns), 'file_changed')
    return {'exists': True, 'sha256': digest.hexdigest(), 'size': after.st_size,
            'uid': after.st_uid, 'gid': after.st_gid, 'mode': stat.S_IMODE(after.st_mode)}


def snapshot(data=DATA):
    """Call only while stopped for the DB byte-preservation comparison."""
    return {name: metadata(data / name, name.endswith(('-wal', '-shm')))
            for name in PROTECTED}


def idle(data=DATA, now=None):
    now = time.time() if now is None else now
    metadata(data / 'gateway_state.json')
    state = json.loads((data / 'gateway_state.json').read_text())
    require(state.get('gateway_state') == 'running' and state.get('active_agents') == 0
            and not state.get('active_work'), 'gateway_busy_or_not_running')
    stamp = state.get('updated_at')
    if isinstance(stamp, (int, float)) and not isinstance(stamp, bool):
        stamp = float(stamp)
    else:
        parsed = datetime.datetime.fromisoformat(str(stamp).replace('Z', '+00:00'))
        require(parsed.tzinfo is not None, 'heartbeat_timezone_missing')
        stamp = parsed.timestamp()
    require(-5 <= now - stamp < 45, 'heartbeat_stale')
    metadata(data / 'state.db')
    with sqlite3.connect(f'file:{data}/state.db?mode=ro', uri=True, timeout=5) as db:
        require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'database_invalid')
        leases = db.execute('SELECT count(*) FROM session_turn_leases WHERE expires_at>?', (now,)).fetchone()[0]
        require(leases == 0, 'active_turn_lease')
    return {'idle': True, 'active_leases': leases, 'heartbeat_age_seconds': round(now - stamp, 3)}


def container():
    # Installed Hermes dependencies only; caller never installs PyYAML separately.
    import yaml
    require(sys.version_info[:2] == (3, 13) and platform.machine() == 'x86_64', 'unsupported_runtime')
    config_path = Path('/opt/data/config.yaml')
    config_before = metadata(config_path)
    config = yaml.safe_load(config_path.read_text())
    branch = config.get('display', {}).get('platforms', {}).get('mattermost', {})
    require(all(branch.get(key) is False for key in
                ('streaming', 'interim_assistant_messages', 'show_reasoning', 'thinking_progress')),
            'unsafe_draft_configuration')
    require(metadata(config_path) == config_before, 'config_changed')
    files = {name: metadata(SOURCE / name) for name in INTEGRATIONS}
    files[CORE] = metadata(SOURCE / CORE, optional=True)
    return {'python': list(sys.version_info[:3]), 'architecture': platform.machine(),
            'files': files, 'config': config_before, 'draft_surfaces_disabled': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('idle', 'snapshot', 'container'))
    args = parser.parse_args()
    try:
        result = {'idle': idle, 'snapshot': snapshot, 'container': container}[args.operation]()
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:
        # Exception messages/tracebacks can contain secrets from parsed files.
        safe_codes = {'required_file_missing', 'nonregular_file', 'file_changed',
                      'gateway_busy_or_not_running', 'heartbeat_timezone_missing',
                      'heartbeat_stale', 'database_invalid', 'active_turn_lease',
                      'unsupported_runtime', 'unsafe_draft_configuration', 'config_changed'}
        code = str(exc) if type(exc) is ValueError and str(exc) in safe_codes else 'guard_check_failed'
        print(json.dumps({'error': code, 'operation': args.operation}))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
