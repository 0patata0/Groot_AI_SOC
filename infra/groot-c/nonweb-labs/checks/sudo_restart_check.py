#!/usr/bin/env python3
"""P2-03: own UID1000 HTTPS sudo terminal; root separately restarts daemon.

Never restarts services or hosts. Capabilities stay in memory. A fixed stopped
sudo baseline and zero other PTYs/workers are required immediately before up.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import signal
import time

from terminal_duration import Check, Failed, need, write_json

CVE = 'CVE-2021-3156'


def empty(value):
    return (not any(value['daemon_active_PTY_clients_by_lab'].values())
            and not value['other_daemon_PTY_clients']
            and not any(value['container_session_workers'].values())
            and value['daemon_lifecycle_mutations_in_progress'] == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, action='store_true')
    parser.add_argument('--remote-helper', required=True)
    parser.add_argument('--progress', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    client = Check(args)
    capability = owned_cid = None
    cursor = 0
    report = {'schema': 1, 'scope': 'P2-03 own sudo terminal across root-controlled daemon restart',
              'started_at': int(time.time()), 'product_source_clock_or_configuration_changes': 0,
              'capabilities_or_raw_PTY_retained': False, 'service_or_host_restart_by_this_worker': 0}
    restart_proven = False

    def progress(phase, **fields):
        write_json(args.progress, {'schema': 1, 'phase': phase, 'worker_pid': __import__('os').getpid(),
                                  'observed_at': int(time.time()), **fields})

    def poll():
        nonlocal cursor
        code, value = client.api('terminal/poll', {'session_id': capability, 'cursor': cursor}, 20)
        if code == 200:
            raw = base64.b64decode(value['data'], validate=True)
            need(len(raw) <= 24576, 'PTY_bound')
            cursor = value['cursor']
            return code, value, raw
        return code, value, b''

    try:
        before = client.observe()
        need(empty(before) and before['lab_states']['sudo']['status'] == 'stopped'
             and before['lab_states']['sudo']['pid'] == 0
             and before['lab_states']['samba']['status'] == 'not_deployed', 'freshgate_not_idle')
        report['before'] = before
        code, value = client.api('session')
        need(code == 200 and value.get('mode') == 'enforce', 'anonymous_enforce_required')
        code, value = client.api('deploy', {'cve_id': CVE}, 240)
        public = value.get('lab') if isinstance(value, dict) else None
        short = public.get('container_id') if isinstance(public, dict) else None
        need(code == 200 and isinstance(short, str) and re.fullmatch('[0-9a-f]{12}', short), 'sudo_up_response')
        deployed = client.observe()
        target = deployed['lab_states']['sudo']
        need(target['status'] == 'running' and target['pid'] > 0
             and target['container_id'].startswith(short) and empty(deployed), 'own_sudo_identity_unproven')
        owned_cid = target['container_id']
        report['deployed'] = deployed
        report['original_stopped_CID_retired_under_product_contract'] = before['lab_states']['sudo']['container_id'] != owned_cid
        code, opened = client.api('terminal/open', {'cve_id': CVE, 'rows': 24, 'cols': 80}, 110)
        need(code == 200 and re.fullmatch('[0-9a-f]{64}', opened.get('session_id', ''))
             and opened.get('expires_in') == 1800, 'sudo_terminal_open')
        capability = opened['session_id']
        code, _ = client.api('terminal/input', {'session_id': capability,
            'data': base64.b64encode(b'id\r').decode()}, 15)
        need(code == 200, 'sudo_benign_input')
        sample = bytearray()
        for _ in range(3):
            code, value, raw = poll()
            need(code == 200 and not value['closed'], 'sudo_closed_before_restart')
            sample.extend(raw)
            need(len(sample) <= 65536, 'initial_PTY_bound')
            if re.search(rb'uid=1000(?:\D|$)', sample):
                break
        else:
            raise Failed('UID1000_not_verified')
        sample.clear()
        ready = client.observe()
        need(ready['lab_states']['sudo']['container_id'] == owned_cid
             and ready['daemon_active_PTY_clients_by_lab'] == {'redis': 0, 'samba': 0, 'sudo': 1}
             and not ready['other_daemon_PTY_clients']
             and not any(ready['container_session_workers'].values())
             and ready['daemon_lifecycle_mutations_in_progress'] == 0, 'single_own_session_not_proven')
        report['ready'] = ready
        report['UID1000_verified'] = True
        report['benign_input_count'] = 1
        progress('ready_for_root_restart', owned_container_id=owned_cid,
                 daemon_main_pid=ready['terminal_daemon_main_pid'], UID1000_verified=True,
                 active_sudo_sessions=1)
        deadline, rejected, unavailable = time.monotonic() + 300, False, 0
        while time.monotonic() < deadline:
            try:
                code, value, _ = poll()
                if code == 409 and isinstance(value.get('detail'), dict) and value['detail'].get('code') == 'terminal_closed':
                    rejected = True
                elif code != 200:
                    unavailable += 1
                after = client.observe()
            except Exception:
                unavailable += 1
                time.sleep(2)
                continue
            target = after['lab_states']['sudo']
            if (rejected and after['terminal_daemon_main_pid'] != ready['terminal_daemon_main_pid']
                    and target['container_id'] == owned_cid and target['status'] == 'stopped'
                    and target['pid'] == 0 and empty(after)):
                need(all(after['lab_states'][lab] == before['lab_states'][lab] for lab in ('redis', 'samba')), 'other_lab_changed')
                need(all(after['lab_states'][lab]['deployment_allowed'] for lab in ('redis', 'samba')), 'guard_not_verified')
                report.update(status='pass', after=after, old_capability_rejected=True,
                              exact_owned_CID_stopped_PID0=True, other_labs_unchanged=True,
                              guard_verified=True, transient_unavailable_responses=unavailable)
                restart_proven = True
                break
            time.sleep(2)
        need(restart_proven, 'root_restart_observation_timeout')
    except BaseException as exc:
        report.update(status='needs_review', failure_class=type(exc).__name__)
        if isinstance(exc, Failed):
            report['failure_code'] = str(exc)
    finally:
        if capability:
            try:
                code, value = client.api('terminal/close', {'session_id': capability}, 60)
                report['own_close_after_observation'] = code == 200 or (code == 409
                    and isinstance(value.get('detail'), dict) and value['detail'].get('code') == 'terminal_closed')
            except Exception:
                report['own_close_after_observation'] = False
        report['owned_container_id'] = owned_cid
        report['finished_at'] = int(time.time())
        report['no_CVE_wide_stop_fallback'] = True
        write_json(args.report, report)
        progress('finished', status=report['status'], old_capability_rejected=restart_proven)
        print(json.dumps({'status': report['status'], 'UID1000_verified': report.get('UID1000_verified', False),
                          'exact_owned_CID_stopped_PID0': report.get('exact_owned_CID_stopped_PID0', False)}, sort_keys=True), flush=True)
    return 0 if restart_proven else 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda signum, frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    raise SystemExit(main())
