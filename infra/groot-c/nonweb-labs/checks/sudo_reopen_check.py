#!/usr/bin/env python3
"""One own UID1000 sudo reopen after P2-03, then own exact-session close.

No service/host restart and no CVE-wide stop fallback. Capabilities are memory
only; requests use the same verified HTTPS and anonymous normal mode.
"""
import argparse
import base64
import re
import time

from terminal_duration import Check, Failed, need, write_json
from sudo_restart_check import empty

CVE = 'CVE-2021-3156'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    for key in ('remote-helper', 'progress', 'report'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    client = Check(args)
    capability = owned = None
    result = {'schema': 1, 'scope': 'one normal sudo reopen after daemon restart',
              'started_at': int(time.time()), 'service_or_host_restarts': 0,
              'source_clock_or_config_changes': 0, 'capabilities_or_raw_PTY_retained': False}
    try:
        before = client.observe()
        need(empty(before) and before['lab_states']['sudo']['status'] == 'stopped'
             and before['lab_states']['sudo']['pid'] == 0, 'freshgate_not_idle')
        result['before'] = before
        code, body = client.api('deploy', {'cve_id': CVE}, 240)
        public = body.get('lab', {})
        short = public.get('container_id')
        need(code == 200 and isinstance(short, str) and re.fullmatch('[0-9a-f]{12}', short), 'sudo_deploy')
        active = client.observe()
        target = active['lab_states']['sudo']
        need(empty(active) and target['status'] == 'running' and target['container_id'].startswith(short), 'own_identity_unproven')
        owned = target['container_id']
        result['deployed'] = active
        code, body = client.api('terminal/open', {'cve_id': CVE, 'rows': 24, 'cols': 80}, 110)
        need(code == 200 and re.fullmatch('[0-9a-f]{64}', body.get('session_id', '')), 'sudo_open')
        capability = body['session_id']
        code, _ = client.api('terminal/input', {'session_id': capability,
            'data': base64.b64encode(b'id\r').decode()}, 15)
        need(code == 200, 'sudo_input')
        cursor, output, verified = 0, bytearray(), False
        for _ in range(3):
            code, body = client.api('terminal/poll', {'session_id': capability, 'cursor': cursor}, 20)
            need(code == 200 and not body['closed'], 'sudo_poll')
            cursor = body['cursor']
            output.extend(base64.b64decode(body['data'], validate=True))
            need(len(output) <= 65536, 'PTY_bound')
            if re.search(rb'uid=1000(?:\D|$)', output):
                verified = True
                break
        output.clear()
        need(verified, 'UID1000_unverified')
        result['UID1000_verified'] = True
        result['benign_input_count'] = 1
    except Exception as exc:
        result.update(status='needs_review', failure_class=type(exc).__name__)
        if isinstance(exc, Failed):
            result['failure_code'] = str(exc)
    finally:
        if capability:
            try:
                code, _ = client.api('terminal/close', {'session_id': capability}, 60)
                result['own_close_success'] = code == 200
            except Exception:
                result['own_close_success'] = False
        try:
            after = client.observe()
            result['after'] = after
            result['exact_owned_CID_stopped_PID0'] = bool(owned) and after['lab_states']['sudo']['container_id'] == owned and after['lab_states']['sudo']['status'] == 'stopped' and after['lab_states']['sudo']['pid'] == 0
            result['all_PTY_workers_and_lifecycle_zero'] = empty(after)
            result['daemon_not_restarted'] = after['terminal_daemon_main_pid'] == result['before']['terminal_daemon_main_pid']
            result['other_labs_unchanged'] = all(after['lab_states'][lab] == result['before']['lab_states'][lab] for lab in ('redis', 'samba'))
            result['guard_verified'] = all(after['lab_states'][lab]['deployment_allowed'] for lab in ('redis', 'samba'))
        except Exception as exc:
            result['observation_failure_class'] = type(exc).__name__
        result['owned_container_id'] = owned
        result['finished_at'] = int(time.time())
        result['status'] = 'pass' if all(result.get(key) is True for key in ('UID1000_verified', 'own_close_success', 'exact_owned_CID_stopped_PID0', 'all_PTY_workers_and_lifecycle_zero', 'daemon_not_restarted', 'other_labs_unchanged', 'guard_verified')) else 'needs_review'
        write_json(args.report, result)
        print(__import__('json').dumps({'status': result['status'], 'UID1000_verified': result.get('UID1000_verified', False), 'all_PTY_workers_and_lifecycle_zero': result.get('all_PTY_workers_and_lifecycle_zero', False)}, sort_keys=True), flush=True)
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
