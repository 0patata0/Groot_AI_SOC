#!/usr/bin/env python3
"""Bounded PTY sessions for two fixed lab containers; Unix peers only."""
import base64
import binascii
from collections import deque
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import pwd
import re
import secrets
import select
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import termios
import threading
import time

LABS = {'redis': 'CVE-2022-0543', 'samba': 'CVE-2017-7494', 'sudo': 'CVE-2021-3156'}
ROOT = Path('/opt/capstone-nonweb-labs')
SOCKET = Path('/run/capstone-nonweb-labs/control.sock')
HEX = re.compile(r'[0-9a-f]{64}\Z')
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'HOME': '/nonexistent', 'DOCKER_CONFIG': '/nonexistent', 'LC_ALL': 'C',
       'PYTHONDONTWRITEBYTECODE': '1'}
MAX_AGE, IDLE, BUFFER, MAX_SESSIONS = 1800, 300, 262144, 8


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'invalid_request')
        result[key] = value
    return result


def trusted(path):
    path = Path(path)
    for parent in path.parents:
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'unsafe_runtime')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
         and not info.st_mode & 0o022, 'unsafe_runtime')
    return str(path)


def dimensions(body):
    rows, cols = body['rows'], body['cols']
    need(type(rows) is int and type(cols) is int and 2 <= rows <= 100 and 20 <= cols <= 300,
         'invalid_dimensions')
    return rows, cols


def call_runtime(action, lab):
    need(lab in LABS and action in ('up', 'stop', 'status', 'getcontainer'), 'invalid_lab')
    if lab == 'sudo':
        return sudo_adapter().runtime(action, lab)
    launcher = trusted(ROOT / 'lab.sh')
    result = subprocess.run(['/bin/bash', launcher, action, lab], env=ENV,
                            capture_output=True, timeout={'up': 210, 'getcontainer': 90}.get(action, 45))
    need(result.returncode == 0 and len(result.stdout) <= 32768, 'terminal_operation_failed')
    try:
        value = json.loads(result.stdout, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise Refused('terminal_operation_failed') from None
    need(isinstance(value, dict) and value.get('ok') is True and value.get('schema') == 1
         and value.get('lab') == lab and value.get('cve_id') == LABS[lab], 'terminal_operation_failed')
    return value


def sudo_adapter():
    # The rootless target and commands are code-owned, never request options.
    # Recheck the same installed source pins used by the existing runtime.
    for name in ('runtime', 'sudo_terminal'):
        path = trusted(ROOT / (name + '.py'))
        spec = importlib.util.spec_from_file_location('fixed_terminal_' + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if name == 'runtime':
            module.load_config()
        else:
            return module.Adapter()


def close_sessions(sessions):
    workers = [threading.Thread(target=item.close, daemon=True) for item in sessions]
    for worker in workers:
        worker.start()
    deadline = time.monotonic() + 12
    for worker in workers:
        worker.join(max(0, deadline - time.monotonic()))


class Session:
    def __init__(self, lab, owner, rows, cols, docker, runtime=call_runtime):
        self.lab, self.owner, self.runtime = lab, owner, runtime
        identity = runtime('getcontainer', lab)
        self.cid = identity.get('container_id')
        need(isinstance(self.cid, str) and HEX.fullmatch(self.cid)
             and identity.get('exec_user') == ('1000:1000' if lab == 'sudo' else '10001:10001'),
             'terminal_not_running')
        self.docker = docker
        self.tag = secrets.token_hex(32)  # Process tag is never the browser capability.
        self.created = self.activity = time.monotonic()
        self.condition = threading.Condition()
        self.write_lock = threading.Lock()
        self.chunks, self.first, self.end = deque(), 0, 0
        self.closed, self.exited = False, False
        master, slave = pty.openpty()
        self.master = master
        os.set_blocking(master, False)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        argv = [docker, '--host', 'unix:///var/run/docker.sock', 'exec', '-i', '-t',
                '--user', '10001:10001', '--workdir', '/tmp', '--env', 'TERM=xterm-256color',
                '--env', 'HOME=/tmp', self.cid, '/lab/terminal-session.sh', self.tag]
        try:
            if lab == 'sudo':
                argv = sudo_adapter().exec_argv(self.cid)
            self.process = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                            env=ENV, close_fds=True, start_new_session=True)
        except Exception:
            os.close(master)
            raise
        finally:
            os.close(slave)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            while not self.closed:
                if not select.select([self.master], [], [], 1)[0]:
                    if self.process.poll() is not None:
                        break
                    continue
                # select may return after close has invalidated this session.
                # Protect every actual FD access, including a delayed reader,
                # so a recycled descriptor can never target another PTY.
                with self.write_lock:
                    if self.closed:
                        break
                    raw = os.read(self.master, 8192)
                if not raw:
                    break
                with self.condition:
                    self.chunks.append(raw)
                    self.end += len(raw)
                    while self.end - self.first > BUFFER and self.chunks:
                        self.first += len(self.chunks.popleft())
                    self.condition.notify_all()
        except OSError:
            pass
        finally:
            with self.condition:
                self.exited = True
                self.condition.notify_all()

    def poll(self, cursor):
        need(type(cursor) is int and 0 <= cursor <= self.end, 'invalid_cursor')
        with self.condition:
            if cursor == self.end and not self.exited and not self.closed:
                self.condition.wait(10)
            start = max(cursor, self.first)
            raw = b''.join(self.chunks)[start - self.first:start - self.first + 24576]
            return {'data': base64.b64encode(raw).decode(), 'cursor': start + len(raw),
                    'truncated': cursor < self.first,
                    'closed': (self.exited or self.closed) and start + len(raw) == self.end}

    def input(self, encoded):
        need(isinstance(encoded, str) and len(encoded) <= 2732, 'invalid_input')
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise Refused('invalid_input') from None
        need(0 < len(raw) <= 2048, 'invalid_input')
        # User bytes are PTY input, never host command arguments.
        with self.write_lock:
            need(not self.closed and not self.exited, 'terminal_closed')
            self.activity = time.monotonic()
            deadline = time.monotonic() + 2
            while raw:
                remaining = deadline - time.monotonic()
                need(remaining > 0 and select.select([], [self.master], [], remaining)[1],
                     'terminal_operation_failed')
                try:
                    raw = raw[os.write(self.master, raw):]
                except BlockingIOError:
                    continue

    def resize(self, rows, cols):
        with self.write_lock:
            need(not self.closed and not self.exited, 'terminal_closed')
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
            os.killpg(self.process.pid, signal.SIGWINCH)

    def close(self):
        with self.condition:
            if self.closed:
                return
            self.closed = True
            self.condition.notify_all()
        failed = False
        try:
            if self.lab == 'sudo':
                # Setuid and new-SID descendants require the whole dedicated
                # rootless container as the cleanup boundary. Only one sudo
                # terminal may exist and lifecycle/close are serialized.
                sudo_adapter().stop_exact(self.cid)
            else:
                # Full CID, fixed UID and helper prevent host-shell dispatch.
                subprocess.run([self.docker, '--host', 'unix:///var/run/docker.sock', 'exec',
                                '--user', '10001:10001', self.cid, '/lab/terminal-close.sh', self.tag],
                               env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=8)
        except Exception:
            # Local descriptors must always retire, even when rootless cleanup
            # is refused. The manager then blocks another sudo terminal until
            # a successful explicit lab stop establishes the cleanup boundary.
            failed = self.lab == 'sudo'
        # Joining normally retires the reader promptly. Correctness does not
        # depend on scheduling it within this timeout: all delayed FD users
        # acquire the same lock and recheck closed before touching the FD.
        self.reader.join(timeout=1.2)
        with self.write_lock:
            try:
                os.close(self.master)
            except OSError:
                pass
        try:
            self.process.terminate()
            self.process.wait(timeout=3)
        except ProcessLookupError:
            pass
        except subprocess.SubprocessError:
            try:
                self.process.kill()
                self.process.wait(timeout=3)
            except (ProcessLookupError, subprocess.SubprocessError):
                pass
        need(not failed, 'terminal_operation_failed')


class Manager:
    def __init__(self, docker, runtime=call_runtime, factory=Session):
        self.docker, self.runtime, self.factory = docker, runtime, factory
        self.sessions, self.lock = {}, threading.RLock()
        self.runtime_lock = threading.Lock()
        self.sudo_cleanup_failed = False

    def prepare_sudo(self):
        # Every daemon start establishes a clean dedicated sudo container
        # boundary. A failed ExecStopPost or SIGKILL cannot erase a cleanup
        # failure merely by resetting the in-memory flag on restart. Failure
        # blocks sudo only; Redis/Samba remain available.
        with self.runtime_lock:
            self.sudo_cleanup_failed = True
            try:
                value = self.runtime('stop', 'sudo')
                need(value.get('ok') is True and type(value.get('schema')) is int and value['schema'] == 1
                     and value.get('lab') == 'sudo'
                     and value.get('cve_id') == LABS['sudo']
                     and value.get('status') in ('stopped', 'not_deployed'),
                     'terminal_operation_failed')
                self.sudo_cleanup_failed = False
            except Exception:
                pass

    def reap(self):
        while True:
            time.sleep(5)
            with self.lock:
                now = time.monotonic()
                stale = [key for key, item in self.sessions.items()
                         if now - item.created > MAX_AGE or now - item.activity > IDLE]
            for key in stale:
                # Keep the sudo lifecycle lock until full-container cleanup
                # finishes, so a new session cannot race an old close.
                with self.lock:
                    item = self.sessions.get(key)
                if item is None:
                    continue
                if item.lab == 'sudo':
                    with self.runtime_lock:
                        with self.lock:
                            item = self.sessions.pop(key, None)
                        if item is not None:
                            try:
                                item.close()
                            except Exception:
                                self.sudo_cleanup_failed = True
                else:
                    with self.lock:
                        item = self.sessions.pop(key, None)
                    if item is not None:
                        item.close()

    def handle(self, body):
        need(isinstance(body, dict) and isinstance(body.get('action'), str), 'invalid_request')
        action = body['action']
        if action in ('status', 'deploy', 'stop'):
            need(set(body) == {'action', 'lab'} and body['lab'] in LABS, 'invalid_request')
            lab = body['lab']
            need(self.runtime_lock.acquire(blocking=False), 'operation_in_progress')
            try:
                if action == 'stop':
                    with self.lock:
                        keys = [key for key, s in self.sessions.items() if s.lab == lab]
                        sessions = [self.sessions.pop(key) for key in keys]
                    if lab == 'sudo':
                        for item in sessions:
                            try:
                                item.close()
                            except Exception:
                                self.sudo_cleanup_failed = True
                    else:
                        close_sessions(sessions)
                value = self.runtime({'deploy': 'up'}.get(action, action), lab)
                need(value.get('ok') is True and value.get('schema') == 1 and value.get('cve_id') == LABS[lab], 'terminal_operation_failed')
                if action in ('status', 'deploy'):
                    need(value.get('deployment_allowed') is True, 'terminal_operation_failed')
                if action == 'stop' and lab == 'sudo':
                    self.sudo_cleanup_failed = False
                return {key: value[key] for key in ('ok','schema','lab','cve_id','status','verification','image_present','container_id')}
            finally:
                self.runtime_lock.release()
        need(action in ('terminal_open', 'terminal_poll', 'terminal_input', 'terminal_resize', 'terminal_close'),
             'invalid_request')
        common = {'action', 'owner'}
        need(isinstance(body.get('owner'), str) and HEX.fullmatch(body['owner']), 'invalid_owner')
        if action == 'terminal_open':
            need(set(body) == common | {'lab', 'rows', 'cols'} and body['lab'] in LABS, 'invalid_request')
            rows, cols = dimensions(body)
            need(self.runtime_lock.acquire(blocking=False), 'operation_in_progress')
            try:
                with self.lock:
                    need(len(self.sessions) < MAX_SESSIONS and
                         sum(s.owner == body['owner'] for s in self.sessions.values()) < 2, 'terminal_limit')
                    need(body['lab'] != 'sudo' or not any(s.lab == 'sudo' for s in self.sessions.values()),
                         'terminal_limit')
                    need(body['lab'] != 'sudo' or not self.sudo_cleanup_failed, 'terminal_operation_failed')
                # The lifecycle lock serializes opens/stops. Existing sessions
                # remain responsive while this lab's verifier checks readiness.
                identifier = secrets.token_hex(32)
                session = self.factory(body['lab'], body['owner'], rows, cols, self.docker, self.runtime)
                with self.lock:
                    self.sessions[identifier] = session
            finally:
                self.runtime_lock.release()
            return {'ok': True, 'session_id': identifier, 'expires_in': MAX_AGE}
        extras = {'terminal_poll': {'cursor'}, 'terminal_input': {'data'},
                  'terminal_resize': {'rows', 'cols'}, 'terminal_close': set()}[action]
        need(set(body) == common | {'session_id'} | extras, 'invalid_request')
        identifier = body['session_id']
        need(isinstance(identifier, str) and HEX.fullmatch(identifier), 'terminal_closed')
        with self.lock:
            session = self.sessions.get(identifier)
            need(session is not None and secrets.compare_digest(session.owner, body['owner']), 'terminal_closed')
            if action == 'terminal_close' and session.lab != 'sudo':
                del self.sessions[identifier]
        if action == 'terminal_close' and session.lab == 'sudo':
            need(self.runtime_lock.acquire(blocking=False), 'operation_in_progress')
            try:
                with self.lock:
                    need(self.sessions.get(identifier) is session, 'terminal_closed')
                    del self.sessions[identifier]
                try:
                    session.close()
                except Exception:
                    self.sudo_cleanup_failed = True
                    raise Refused('terminal_operation_failed') from None
            finally:
                self.runtime_lock.release()
            return {'ok': True}
        if action == 'terminal_poll':
            return {'ok': True, **session.poll(body['cursor'])}
        if action == 'terminal_input':
            session.input(body['data'])
        elif action == 'terminal_resize':
            session.resize(*dimensions(body))
        else:
            session.close()
        return {'ok': True}

    def shutdown(self):
        with self.runtime_lock:
            with self.lock:
                sessions, self.sessions = list(self.sessions.values()), {}
            for item in sessions:
                if item.lab == 'sudo':
                    try:
                        item.close()
                    except Exception:
                        self.sudo_cleanup_failed = True
            close_sessions([item for item in sessions if item.lab != 'sudo'])


def serve(manager, uid, gid):
    directory = SOCKET.parent.lstat()
    need(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and directory.st_gid == gid
         and stat.S_IMODE(directory.st_mode) == 0o750, 'unsafe_socket_directory')
    lock = os.open(str(SOCKET) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    meta = os.fstat(lock)
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
         and stat.S_IMODE(meta.st_mode) == 0o600, 'unsafe_socket_lock')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if SOCKET.exists() or SOCKET.is_symlink():
        meta = SOCKET.lstat()
        need(stat.S_ISSOCK(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == gid
             and stat.S_IMODE(meta.st_mode) == 0o660, 'unsafe_socket')
        SOCKET.unlink()
    slots = threading.BoundedSemaphore(32)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if not slots.acquire(blocking=False):
                return
            try:
                self.request.settimeout(15)
                _, peer_uid, peer_gid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(peer_uid == 0 or (peer_uid == uid and peer_gid == gid), 'peer_denied')
                frame = bytearray()
                while b'\n' not in frame:
                    data = self.request.recv(4097 - len(frame))
                    need(data and len(frame) + len(data) <= 4096, 'invalid_request')
                    frame.extend(data)
                need(frame.endswith(b'\n') and b'\n' not in frame[:-1], 'invalid_request')
                response = manager.handle(json.loads(frame, object_pairs_hook=unique))
            except Refused as exc:
                response = {'ok': False, 'error': str(exc)}
            except Exception:
                response = {'ok': False, 'error': 'terminal_operation_failed'}
            finally:
                slots.release()
            try:
                self.request.sendall(json.dumps(response, separators=(',', ':')).encode() + b'\n')
            except OSError:
                pass

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        request_queue_size = 16

    def terminate(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, terminate)
    try:
        with Server(str(SOCKET), Handler) as server:
            os.chown(SOCKET, 0, gid)
            os.chmod(SOCKET, 0o660)
            threading.Thread(target=manager.reap, daemon=True).start()
            server.serve_forever(poll_interval=1)
    finally:
        manager.shutdown()


if __name__ == '__main__':
    need(os.geteuid() == 0, 'root_required')
    user = pwd.getpwnam('capstone-labs')
    candidates = [p for p in ('/usr/local/bin/docker', '/usr/bin/docker') if Path(p).is_file()]
    need(bool(candidates), 'docker_missing')
    manager = Manager(trusted(candidates[0]))
    manager.prepare_sudo()
    serve(manager, user.pw_uid, user.pw_gid)
