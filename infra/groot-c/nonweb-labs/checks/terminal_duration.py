#!/usr/bin/env python3
"""Real-time HTTPS Samba terminal limits, using existing tools and fixed limits.

Administrator integration check, never an MCP tool or bootstrap step. --run is
required. It creates only the fixed Samba lab from a not_deployed baseline,
keeps browser capabilities in memory, and refuses shared-container cleanup.
No source/clock/limit changes, bypass cookie, exploit, package or reboot.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ORIGIN = 'https://log4shell.grootlab.duckdns.org'
CVE = 'CVE-2017-7494'
IDLE, LIFETIME = 300, 1800
CAPABILITY = re.compile(r'[0-9a-f]{64}\Z')


class Failed(Exception):
    pass


def need(value, code):
    if not value:
        raise Failed(code)


def write_json(path, value):
    target = Path(path)
    temporary = target.with_name(target.name + '.tmp')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Check:
    def __init__(self, args):
        self.args = args
        self.context = ssl.create_default_context(cafile='/etc/ssl/cert.pem')
        self.stop = threading.Event()
        self.sessions = []
        self.owned_cid = None
        self.owned_clients = set()
        self.owned_workers = set()
        self.foreign_samba_seen = False
        self.started = time.monotonic()
        self.baseline = None
        self.last_observation = None
        self.report = {'schema': 1, 'scope': 'real-time HTTPS Samba terminal idle and hard lifetime',
                       'started_at': int(time.time()), 'idle_seconds': IDLE,
                       'lifetime_seconds': LIFETIME, 'source_or_clock_or_limit_changes': 0,
                       'bypass_or_admin_key_used': False, 'events': []}

    def api(self, action, body=None, timeout=20):
        path = '/log4shell/api/' + action
        data = None if body is None else json.dumps(body, separators=(',', ':')).encode()
        request = urllib.request.Request(ORIGIN + path, data=data,
            headers={'Origin': ORIGIN, 'Referer': ORIGIN + '/log4shell/',
                     'Content-Type': 'application/json', 'User-Agent': 'CapstoneDurationCheck/1.0'},
            method='GET' if data is None else 'POST')
        # No cookie jar, inherited proxy, redirect, authentication or raw log.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.context), NoRedirect())
        try:
            with opener.open(request, timeout=timeout) as response:
                need(response.geturl() == ORIGIN + path, 'unexpected_redirect')
                status, raw = response.status, response.read(262145)
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read(262145)
        need(len(raw) <= 262144, 'HTTP_response_bound')
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failed('HTTP_JSON_unavailable') from None
        return status, value

    def observe(self):
        probe = Path(__file__).with_name('terminal_duration_probe.py')
        child = subprocess.Popen([sys.executable, '-B', self.args.remote_helper, 'c', str(probe)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), start_new_session=True)
        try:
            raw, _ = child.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
            raise Failed('readonly_probe_timeout') from None
        need(child.returncode == 0 and len(raw) <= 262144, 'readonly_probe_unavailable')
        value = json.loads(raw)
        need(value.get('source_matches_reviewed') is True, 'source_preflight_failed')
        self.last_observation = value
        clients = self.identities(value, 'daemon_PTY_processes')
        workers = self.identities(value, 'container_worker_processes')
        if self.owned_clients and (clients - self.owned_clients or workers - self.owned_workers):
            self.foreign_samba_seen = True
        return value

    @staticmethod
    def identities(observation, name):
        return {(row['pid'], row['start_ticks']) for row in observation[name] if row['lab'] == 'samba'}

    def event(self, phase, **fields):
        row = {'phase': phase, 'elapsed_seconds': round(time.monotonic() - self.started, 3), **fields}
        self.report['events'].append(row)
        print(json.dumps(row, sort_keys=True), flush=True)

    def progress(self):
        value = {'schema': 1, 'elapsed_seconds': int(time.monotonic() - self.started),
                 'owned_Samba_container': self.owned_cid is not None,
                 'foreign_samba_seen': self.foreign_samba_seen,
                 'sessions': [s.safe() for s in self.sessions]}
        write_json(self.args.progress, value)
        return value

    def capture_ownership(self):
        value = self.observe()
        need(value['lab_states']['samba']['container_id'] == self.owned_cid, 'Samba_identity_changed')
        # Called only immediately after our first and second opens, with zero
        # clients/workers established by the baseline and deployment checks.
        clients = self.identities(value, 'daemon_PTY_processes')
        workers = self.identities(value, 'container_worker_processes')
        expected = len(self.sessions)
        need(len(clients) == expected and len(workers) == expected, 'unexpected_open_session_count')
        need(self.owned_clients <= clients and self.owned_workers <= workers, 'session_identity_changed')
        self.owned_clients, self.owned_workers = clients, workers
        self.foreign_samba_seen = False

    def cleanup(self):
        self.stop.set()
        for session in self.sessions:
            try:
                code, value = self.api('terminal/close', {'session_id': session.capability}, 25)
                session.close_request_ok = code == 200 or (code == 409
                    and isinstance(value.get('detail'), dict)
                    and value['detail'].get('code') == 'terminal_closed')
            except Exception:
                session.close_request_ok = False
        result = {'owned_session_close_requests': [s.close_request_ok for s in self.sessions],
                  'container_stop_attempted': False, 'baseline_restored': False}
        try:
            value = self.observe()
            samba = value['lab_states']['samba']
            clients = self.identities(value, 'daemon_PTY_processes')
            workers = self.identities(value, 'container_worker_processes')
            result['foreign_samba_seen'] = self.foreign_samba_seen
            if samba['status'] == 'not_deployed':
                result['baseline_restored'] = self.owned_cid is None
            elif (self.owned_cid and samba['container_id'] == self.owned_cid
                  and not self.foreign_samba_seen and not clients and not workers
                  and value['daemon_lifecycle_mutations_in_progress'] == 0):
                result['container_stop_attempted'] = True
                code, _ = self.api('stop', {'cve_id': CVE}, 90)
                need(code == 200, 'owned_Samba_cleanup_HTTP_failed')
                after = self.observe()
                result['baseline_restored'] = after['lab_states']['samba']['status'] == 'not_deployed'
                result['post_cleanup'] = after
            else:
                result['cleanup_deferred'] = 'foreign_session_or_identity_not_proven'
            final = result.get('post_cleanup', value)
            result['other_labs_unchanged'] = bool(self.baseline) and all(
                final['lab_states'][lab] == self.baseline['lab_states'][lab] for lab in ('redis', 'sudo'))
        except Exception as exc:
            result['failure_class'] = type(exc).__name__
        self.report['cleanup'] = result

    def run(self):
        try:
            self.baseline = self.observe()
            need(self.baseline['lab_states']['samba']['status'] == 'not_deployed', 'Samba_not_unused')
            need(self.baseline['lab_states']['samba']['deployment_allowed'] is True
                 and self.baseline['lab_states']['samba']['image_present'] is True, 'Samba_not_ready')
            need(not any(self.baseline['daemon_active_PTY_clients_by_lab'].values())
                 and not self.baseline['other_daemon_PTY_clients']
                 and not any(self.baseline['container_session_workers'].values())
                 and self.baseline['daemon_lifecycle_mutations_in_progress'] == 0, 'existing_sessions_or_operation')
            self.report['baseline'] = self.baseline
            code, value = self.api('session')
            need(code == 200 and value.get('mode') == 'enforce', 'anonymous_enforce_mode_required')
            self.event('preflight_ready')
            code, value = self.api('deploy', {'cve_id': CVE}, 240)
            public = value.get('lab') if isinstance(value, dict) else None
            short = public.get('container_id') if isinstance(public, dict) else None
            need(code == 200 and public.get('status') == 'running'
                 and isinstance(short, str) and re.fullmatch(r'[0-9a-f]{12}', short),
                 'Samba_deployment_identity_unavailable')
            observed = self.observe()
            cid = observed['lab_states']['samba']['container_id']
            need(isinstance(cid, str) and CAPABILITY.fullmatch(cid) and cid.startswith(short)
                 and observed['lab_states']['samba']['status'] == 'running'
                 and observed['lab_states']['samba']['image_id'] == self.baseline['lab_states']['samba']['image_id'], 'deployed_Samba_identity_mismatch')
            self.owned_cid = cid
            need(not self.identities(observed, 'daemon_PTY_processes')
                 and not self.identities(observed, 'container_worker_processes'), 'session_raced_deployment')
            self.event('owned_Samba_deployed')
            for name in ('idle', 'lifetime'):
                session = Session(self, name)
                self.sessions.append(session)
                session.open()
                self.capture_ownership()
                self.event('session_opened', name=name, UID10001_verified=session.uid_verified)
            for session in self.sessions:
                session.thread = threading.Thread(target=session.run, daemon=True)
                session.thread.start()
            last_observe = last_event = time.monotonic()
            deadline = time.monotonic() + 1860
            while any(s.thread.is_alive() for s in self.sessions):
                self.progress()
                need(time.monotonic() < deadline, 'duration_deadline_exceeded')
                need(not self.stop.wait(2), 'check_interrupted')
                now = time.monotonic()
                if now - last_event >= 40:
                    self.event('running', sessions=[s.safe() for s in self.sessions])
                    last_event = now
                if now - last_observe >= 45:
                    self.observe()
                    last_observe = time.monotonic()
                need(not any(s.error for s in self.sessions), 'session_observation_failed')
            need(all(s.passed for s in self.sessions), 'duration_assertion_failed')
            self.report['duration_passed'] = True
        except BaseException as exc:
            self.report['duration_passed'] = False
            self.report['failure_class'] = type(exc).__name__
            if isinstance(exc, Failed):
                self.report['failure_code'] = str(exc)
        finally:
            self.cleanup()
            self.report['sessions'] = [s.safe() for s in self.sessions]
            self.report['owned_container_id'] = self.owned_cid
            self.report['finished_at'] = int(time.time())
            self.report['elapsed_seconds'] = round(time.monotonic() - self.started, 3)
            self.report['status'] = 'pass' if (self.report.get('duration_passed') is True
                and self.report['cleanup'].get('baseline_restored') is True
                and self.report['cleanup'].get('other_labs_unchanged') is True) else 'needs_review'
            self.report['capabilities_cookies_or_PTY_output_retained'] = False
            write_json(self.args.report, self.report)
            self.progress()
            self.event('finished', status=self.report['status'],
                       baseline_restored=self.report['cleanup'].get('baseline_restored'))
        return 0 if self.report['status'] == 'pass' else 1


class Session:
    def __init__(self, check, name):
        self.check, self.name = check, name
        self.capability = None
        self.cursor = self.input_count = self.output_bytes = 0
        self.uid_verified = self.passed = self.closed = False
        self.close_request_ok = None
        self.error = None
        self.open_sent = self.open_ack = self.last_input_sent = self.last_input_ack = None
        self.closed_at = None

    def safe(self):
        now = time.monotonic()
        return {'name': self.name, 'state': 'error' if self.error else 'closed' if self.closed else 'running',
                'age_seconds': None if self.open_ack is None else round((self.closed_at or now) - self.open_ack, 3),
                'open_request_RTT_seconds': None if self.open_ack is None else round(self.open_ack - self.open_sent, 6),
                'input_count': self.input_count, 'last_input_age_seconds': None if self.last_input_ack is None else round((self.closed_at or now) - self.last_input_ack, 3),
                'last_input_request_RTT_seconds': None if self.last_input_ack is None else round(self.last_input_ack - self.last_input_sent, 6),
                'UID10001_verified': self.uid_verified, 'passed': self.passed,
                'error_class': self.error, 'output_byte_count_only': self.output_bytes}

    def input(self, raw):
        need(raw in (b'id\r', b'echo ttl_probe\r') and len(raw) <= 2048, 'fixed_benign_input_only')
        self.last_input_sent = time.monotonic()
        code, _ = self.check.api('terminal/input', {'session_id': self.capability,
            'data': base64.b64encode(raw).decode()}, 15)
        need(code == 200, 'benign_input_failed')
        self.last_input_ack = time.monotonic()
        self.input_count += 1

    def poll(self):
        code, value = self.check.api('terminal/poll', {'session_id': self.capability, 'cursor': self.cursor}, 20)
        if code == 409 and isinstance(value.get('detail'), dict) and value['detail'].get('code') == 'terminal_closed':
            return b'', True
        need(code == 200 and isinstance(value, dict), 'terminal_poll_failed')
        need(type(value.get('cursor')) is int and value['cursor'] >= self.cursor
             and type(value.get('closed')) is bool, 'terminal_poll_shape')
        raw = base64.b64decode(value['data'], validate=True)
        need(len(raw) <= 24576, 'terminal_output_bound')
        self.cursor = value['cursor']
        self.output_bytes += len(raw)
        return raw, value['closed']

    def open(self):
        self.open_sent = time.monotonic()
        code, value = self.check.api('terminal/open', {'cve_id': CVE, 'rows': 24, 'cols': 80}, 110)
        self.open_ack = time.monotonic()
        need(code == 200 and isinstance(value.get('session_id'), str)
             and CAPABILITY.fullmatch(value['session_id']) and value.get('expires_in') == LIFETIME,
             'terminal_open_failed')
        self.capability = value['session_id']
        self.input(b'id\r')
        sample = bytearray()
        for _ in range(3):
            raw, closed = self.poll()
            need(not closed, 'terminal_closed_during_start')
            sample.extend(raw)
            if re.search(rb'uid=10001(?:\D|$)', sample):
                self.uid_verified = True
                return
            need(len(sample) <= 65536, 'initial_output_bound')
        raise Failed('UID10001_not_verified')

    def run(self):
        try:
            next_input, final_input = self.open_ack + 240, False
            deadline = self.open_ack + 1850
            while not self.check.stop.is_set():
                now = time.monotonic()
                need(now < deadline, 'session_deadline_exceeded')
                if self.name == 'lifetime':
                    if now >= self.open_ack + 1740 and not final_input:
                        self.input(b'echo ttl_probe\r')
                        final_input = True
                    elif now >= next_input and now < self.open_ack + 1740:
                        self.input(b'echo ttl_probe\r')
                        next_input = now + 240
                _, closed = self.poll()
                if closed:
                    self.closed, self.closed_at = True, time.monotonic()
                    if self.name == 'idle':
                        lower = self.closed_at - self.last_input_ack
                        upper = self.closed_at - self.last_input_sent
                        self.passed = lower >= IDLE - 1 and upper <= IDLE + 25 and self.input_count == 1
                    else:
                        lower = self.closed_at - self.open_ack
                        upper = self.closed_at - self.open_sent
                        self.passed = lower >= LIFETIME - 1 and upper <= LIFETIME + 25 and final_input and self.closed_at - self.last_input_ack < IDLE
                    return
        except Exception as exc:
            self.error = type(exc).__name__


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--remote-helper', required=True)
    parser.add_argument('--progress', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    need(Path(args.remote_helper).is_file(), 'fixed_admin_transport_required')
    check = Check(args)
    def terminate(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, terminate)
    return check.run()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'status': 'unavailable', 'failure_class': type(exc).__name__}), flush=True)
        raise SystemExit(1)
