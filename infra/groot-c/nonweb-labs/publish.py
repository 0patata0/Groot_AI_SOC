#!/usr/bin/env python3
"""Fixed root status publisher; writes only its own bounded, expiring receipt."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('capstone_nonweb_runtime', Path(__file__).with_name('runtime.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def publish():
    r.require(os.geteuid() == 0, 'root_required')
    config = r.load_config()
    docker = r.Docker()
    now = int(time.time())
    labs = {}
    with r.operation_lock():
        for lab, spec in r.LABS.items():
            try:
                result = r.action('status', lab, config, docker)
                if result['status'] == 'running' and result['deployment_allowed']:
                    r.action('verify', lab, config, docker)
                    state = 'ready'
                else:
                    state = 'needs_setup' if result['deployment_allowed'] else 'error'
            except (r.Rejected, OSError, ValueError, TypeError, KeyError):
                state = 'error'
            labs[spec['cve_id']] = {'status': state}
        # Timestamp after probes so publication TTL is never shortened by a slow service.
        now = int(time.time())
        value = {'schema': 1, 'checked_at': now, 'expires_at': now + 300, 'labs': labs}
        r.write(r.STATE / 'status.json', r.json_bytes(value))
    print(json.dumps({'ok': True, 'checked_at': now, 'labs': labs, 'attack_tested': False}))


if __name__ == '__main__':
    try:
        publish()
    except (r.Rejected, OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'ok': False, 'error': 'publication_failed'}))
        raise SystemExit(1)
