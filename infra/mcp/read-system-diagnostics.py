#!/usr/bin/env python3
"""Forced-command reader of one fixed, sanitized root-owned snapshot. No sudo."""
import json
import os
from pathlib import Path
import selectors
import stat
import sys
import syslog
import types
import time

LIBRARY = Path('/opt/capstone-diagnostics/system_diagnostics.py')


def load_library():
    for path in (LIBRARY.parent, *LIBRARY.parent.parents):
        meta = path.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise ValueError('unsafe_library_parent')
    meta = LIBRARY.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o022 or meta.st_size > 131072:
        raise ValueError('unsafe_library')
    module = types.ModuleType('fixed_diagnostics_reader')
    module.__file__ = str(LIBRARY)
    exec(compile(LIBRARY.read_bytes(), str(LIBRARY), 'exec'), module.__dict__)
    return module


def main():
    if len(sys.argv) != 1 or os.environ.get('SSH_ORIGINAL_COMMAND', ''):
        raise ValueError('reader_takes_no_command')
    d = load_library()
    raw_request = incoming()
    if raw_request:
        value = d.parsed(raw_request)
        history = d.history_library()
        target, _, _, _ = history.request(value)
        result = history.answer(value, target[0])
        raw = d.encode(result)
        d.need(len(raw) <= 65536, 'history_result_bound')
        syslog.syslog(syslog.LOG_NOTICE, json.dumps({'event':'system_diagnostics_history_read', 'target':target}))
        sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()
        return
    snapshot = d.read_snapshot()
    raw = d.encode(snapshot)
    d.need(len(raw) <= d.MAX_SNAPSHOT, 'snapshot_bound')
    syslog.syslog(syslog.LOG_NOTICE, json.dumps({'event': 'system_diagnostics_snapshot_read',
        'host': snapshot['host'], 'observed_at': snapshot['checked_at']}, sort_keys=True))
    sys.stdout.buffer.write(raw); sys.stdout.buffer.flush()


def incoming():
    """Empty EOF keeps the original snapshot protocol; a bounded JSON selects history."""
    selector = selectors.SelectSelector()
    fd = sys.stdin.fileno()
    selector.register(fd, selectors.EVENT_READ)
    raw = bytearray()
    deadline = time.monotonic() + 2
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ValueError('reader_input_timeout')
            chunk = os.read(fd, 4097 - len(raw))
            if not chunk:
                return bytes(raw)
            raw.extend(chunk)
            if len(raw) > 4096:
                raise ValueError('reader_input_bound')
    finally:
        selector.close()


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError):
        syslog.syslog(syslog.LOG_WARNING, 'system_diagnostics_snapshot_read unavailable')
        raise SystemExit(1) from None
