"""Stop only the training child if shared host memory approaches exhaustion."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from datetime import datetime
from zoneinfo import ZoneInfo


def available_bytes():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('Cannot read host MemAvailable')


def run(args, *, log, cwd, env, report, reserve_bytes=12 * 2**30, poll_seconds=0.25):
    if reserve_bytes <= 0 or not 0 < poll_seconds <= 1:
        raise ValueError('Positive reserve and at most one-second polling required')
    minimum = available_bytes()
    if minimum < reserve_bytes:
        raise RuntimeError('Host memory reserve unavailable before child launch')
    child = subprocess.Popen(args, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
    state = {'status':'running', 'reserve_bytes':reserve_bytes, 'child_pid':child.pid}
    try:
        while child.poll() is None:
            minimum = min(minimum, available_bytes())
            if minimum < reserve_bytes:
                state['status'] = 'memory_reserve_abort'
                raise RuntimeError('Training stopped before host memory reserve exhaustion')
            time.sleep(poll_seconds)
        if child.returncode:
            state['status'] = 'child_failed'
            raise subprocess.CalledProcessError(child.returncode, args)
        state['status'] = 'completed'
    finally:
        # A dedicated process group contains only this child and its descendants.
        if child.poll() is None:
            try: os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=5)
        state.update(minimum_available_bytes=minimum, returncode=child.returncode,
                     at_kst=datetime.now(ZoneInfo('Asia/Seoul')).isoformat())
        if state['status'] == 'running': state['status'] = 'guard_error'
        target=Path(report);temporary=target.with_suffix('.tmp')
        temporary.write_text(json.dumps(state,indent=2)+'\n');temporary.replace(target)
