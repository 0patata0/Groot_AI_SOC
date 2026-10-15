#!/usr/bin/env python3
"""Finite native logcollector restart experiment; never a collector service.

All input is generated here. Installed binaries and internal defaults are copied
to private prefixes; the operating queue/configuration/state are never written.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parent
MID = '096e90b6243e438aa8a7b392be754732'
OUTPUT_ROOT = Path('/var/tmp/capstone-sequential-20261014/step3/raw-restart')
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
LIMIT = 2 * 1024 * 1024


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode() + b'\n'


def compact(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        os.fchmod(handle.fileno(), mode)
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def atomic(path, value):
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    write_new(temporary, encode(value)); os.replace(temporary, path); sync_dir(path.parent)


def bounded(path, limit=LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'private_file_limit')
        raw = handle.read(limit + 1)
    need(len(raw) <= limit, 'private_file_grew_over_limit')
    return raw


def inode(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def offset(value):
    if isinstance(value, str):
        need(re.fullmatch(r'0|[1-9][0-9]{0,18}', value), 'checkpoint_offset_invalid')
        value = int(value)
    need(type(value) is int and 0 <= value <= 2**63 - 1, 'checkpoint_offset_invalid')
    return value


def checkpoint(path, source):
    raw = bounded(path)
    rows = json.loads(raw).get('files')
    need(isinstance(rows, list) and len(rows) <= 8, 'checkpoint_files_invalid')
    selected = [row for row in rows if isinstance(row, dict) and row.get('path') == str(source)]
    need(len(selected) == 1, 'checkpoint_source_count')
    row = selected[0]
    need(isinstance(row.get('hash'), str) and re.fullmatch('[a-f0-9]{40}', row['hash']), 'checkpoint_hash_invalid')
    return {'offset': offset(row.get('offset')), 'hash': row['hash'], 'file_sha256': sha(raw)}


def process_info(pid):
    try:
        raw = Path('/proc', str(pid), 'stat').read_text()
    except FileNotFoundError:
        return None
    fields = raw[raw.rfind(')') + 2:].split()
    return {'start_ticks': int(fields[19]), 'state': fields[0]}


def live_group_members(pgid):
    paths = list(Path('/proc').glob('[0-9]*/stat'))
    need(len(paths) <= 8192, 'startup_process_scan_limit')
    members = []
    for path in paths:
        try:
            raw = path.read_text()
        except FileNotFoundError:
            continue
        fields = raw[raw.rfind(')') + 2:].split()
        if int(fields[2]) == pgid and fields[0] != 'Z':
            members.append(int(path.parts[2]))
    return members


def kill_launch_group(process, expected_start):
    # This must run before wait()/poll(): an unreaped direct-child leader keeps
    # its PID/PGID reserved even after it has become a zombie.
    info = process_info(process.pid)
    need(process.returncode is None and info and info['start_ticks'] == expected_start,
         'startup_cleanup_identity_changed')
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 5
    while live_group_members(process.pid):
        need(time.monotonic() < deadline, 'startup_group_cleanup_timeout')
        time.sleep(.05)


class Child:
    def __init__(self, process, prefix):
        self.process, self.pid, self.prefix = process, process.pid, prefix
        info = process_info(self.pid)
        need(info is not None, 'child_identity_missing')
        self.start = info['start_ticks']
        self.pidfd = os.pidfd_open(self.pid)
        self.verified = False
        need(self.same(), 'child_identity_changed')

    def same(self):
        info = process_info(self.pid)
        return bool(info and info['start_ticks'] == self.start)

    def live(self):
        info = process_info(self.pid)
        return bool(info and info['start_ticks'] == self.start and info['state'] != 'Z')

    def signal(self, number, *, require_isolated=True):
        need(self.same(), 'signal_identity_changed')
        if require_isolated:
            self.verify()
        signal.pidfd_send_signal(self.pidfd, number)

    def verify(self):
        need(self.same(), 'private_identity_changed')
        need(os.readlink(f'/proc/{self.pid}/exe') == str(self.prefix / 'bin/wazuh-logcollector'), 'private_executable_mismatch')
        need(os.readlink(f'/proc/{self.pid}/cwd') == str(self.prefix), 'private_cwd_mismatch')
        need(inode(Path('/proc', str(self.pid), 'root/var/ossec')) == inode(self.prefix), 'private_root_mismatch')
        for kind in ('mnt', 'net'):
            need(os.readlink(f'/proc/{self.pid}/ns/{kind}') != os.readlink(f'/proc/self/ns/{kind}'), 'private_namespace_missing')
        need(inode(self.prefix / 'queue/sockets/queue') != inode(Path('/var/ossec/queue/sockets/queue')), 'operating_queue_alias')
        self.verified = True

    def has_input(self, source):
        target = inode(source)
        paths = list(Path('/proc', str(self.pid), 'fd').iterdir())
        need(len(paths) < 512, 'private_fd_limit')
        count = 0
        for path in paths:
            try:
                info = path.stat()
                if [info.st_dev, info.st_ino] == target:
                    flags = re.search(r'^flags:\s+([0-7]+)$', Path(f'/proc/{self.pid}/fdinfo/{path.name}').read_text(), re.M)
                    need(flags and int(flags.group(1), 8) & 3 == 0, 'private_input_not_readonly')
                    count += 1
            except FileNotFoundError:
                continue
        return count == 1

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd); self.pidfd = None


def command(argv, output, name, timeout=30):
    """Finite helper command, bounded disk output and unreaped leader cleanup."""
    outpath, errpath = output / (name + '.stdout'), output / (name + '.stderr')
    with outpath.open('xb') as out, errpath.open('xb') as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, env=ENV, start_new_session=True)
        deadline = time.monotonic() + timeout
        timed_out = False
        try:
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(.05)
        finally:
            # Leader is not reaped until the process group has been stopped.
            # This prevents a reused PID/group from receiving cleanup signals.
            try:
                os.killpg(process.pid, signal.SIGTERM)
                time.sleep(.1)
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    need(not timed_out, 'helper_command_timeout')
    raw, error = bounded(outpath), bounded(errpath)
    need(process.returncode == 0, 'helper_command_failed_' + name)
    return raw


def operating_snapshot(output, name):
    protected = {}
    for path in (Path('/var/ossec/bin/wazuh-logcollector'), Path('/var/ossec/etc/internal_options.conf'),
                 Path('/var/ossec/etc/local_internal_options.conf'), Path('/var/ossec/etc/ossec.conf'),
                 Path('/etc/capstone-vector/vector.toml')):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode), 'protected_file_not_regular')
        protected[str(path)] = {'sha256': sha(bounded(path, 32 * 1024 * 1024)), 'mode': stat.S_IMODE(info.st_mode),
                                'uid': info.st_uid, 'gid': info.st_gid, 'inode': inode(path)}
    pidrows = []
    for path in Path('/var/ossec/var/run').glob('wazuh-logcollector-*.pid'):
        match = re.fullmatch(r'wazuh-logcollector-([1-9][0-9]*)\.pid', path.name)
        if match:
            pid = int(match.group(1)); info = process_info(pid)
            if info and info['state'] != 'Z':
                need(os.readlink(f'/proc/{pid}/exe') == '/var/ossec/bin/wazuh-logcollector', 'operating_executable_mismatch')
                pidrows.append({'pid': pid, 'start_ticks': info['start_ticks']})
    need(len(pidrows) == 1, 'operating_logcollector_count')
    service = command(['/usr/bin/systemctl', 'show', 'wazuh-agent.service', 'capstone-vector.service',
                       '--property=Id,MainPID,InvocationID,ActiveState', '--no-pager'], output, name)
    need(service.count(b'ActiveState=active') == 2, 'operating_service_not_active')
    return {'protected': protected, 'logcollector': pidrows, 'services_sha256': sha(service),
            'wazuh_root_inode': inode(Path('/var/ossec')), 'operating_queue_inode': inode(Path('/var/ossec/queue/sockets/queue')),
            'host_mount_namespace': os.readlink('/proc/self/ns/mnt'), 'host_network_namespace': os.readlink('/proc/self/ns/net')}


def receipt_body(wire, source, expected):
    prefix = b'1:' + str(source).encode() + b':'
    need(wire.startswith(prefix) and wire.endswith(b'\0') and not wire.endswith(b'\0\0'), 'private_wire_framing')
    body = wire[len(prefix):-1]
    # Known synthetic cJSON input only: exact compact bytes, no arbitrary JSON
    # equivalence or whitespace cleanup that could conceal a transformation.
    row = json.loads(body)
    sequence = row.get('seq') if isinstance(row, dict) else None
    need(type(sequence) is int and sequence in expected, 'private_wire_sequence')
    need(body == expected[sequence], 'private_wire_payload_changed')
    return sequence, sha(body)


class Profile:
    def __init__(self, owner, name):
        self.owner, self.name = owner, name
        self.directory = owner.stage / name; self.directory.mkdir(mode=0o700)
        self.prefix = self.directory / 'wazuh'
        self.source = self.directory / 'reader.json'
        self.generation = self.directory / 'generation-0.json'
        self.evidence = owner.output / name; self.evidence.mkdir(mode=0o700)
        self.expected, self.receipts, self.handles = {}, [], []
        self.socket = None; self.child = None; self.start_number = 0
        self.pending_process = None; self.pending_start = None
        self.result = {'profile': name, 'only_future_events': 'unset_default_yes' if name == 'default' else 'no',
                       'max_size': 'native_default' if name == 'default' else '2GB', 'cases': [], 'stops': [], 'checkpoints': []}
        owner.result['profiles'].append(self.result)

    def row(self, sequence, padding=''):
        body = compact({'fixture': 'capstone-raw-restart-v1', 'run_id': self.owner.run_id,
                        'profile': self.name, 'seq': sequence, 'padding': padding})
        self.expected[sequence] = body
        return body + b'\n'

    def append(self, sequences):
        with self.source.open('ab') as handle:
            for number in sequences:
                handle.write(self.row(number))
            handle.flush(); os.fsync(handle.fileno())
        need(self.source.stat().st_size < 4096, 'synthetic_prefix_hash_size_limit')

    def collect(self, duration=.1):
        end = time.monotonic() + duration
        while time.monotonic() < end:
            readable, _, _ = select.select([self.socket], [], [], min(.1, max(0, end - time.monotonic())))
            if readable:
                wire, _, flags, _ = self.socket.recvmsg(65536)
                need(not flags & socket.MSG_TRUNC, 'private_datagram_truncated')
                need(len(self.receipts) < 200, 'private_receipt_limit')
                sequence, digest = receipt_body(wire, self.source, self.expected)
                entry = {'sequence': sequence, 'sha256': digest, 'reader_start': self.start_number,
                         'received_monotonic_ns': time.monotonic_ns()}
                self.receipts.append(entry)
                with (self.evidence / 'receipts.jsonl').open('ab') as handle:
                    handle.write(encode(entry)); handle.flush()

    def wait(self, predicate, code, timeout=12):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.collect(.1)
            if predicate():
                return
            need(self.child is None or self.child.live(), 'private_reader_exited_early')
        raise Refused(code)

    def counts(self):
        return Counter(row['sequence'] for row in self.receipts)

    def state(self):
        return checkpoint(self.prefix / 'queue/logcollector/file_status.json', self.source)

    def save_state(self, label):
        path = self.prefix / 'queue/logcollector/file_status.json'
        result = self.state()
        write_new(self.evidence / (label + '-file_status.json'), bounded(path), 0o400)
        self.result['checkpoints'].append({'label': label, **result})
        return result

    def exact_eof(self):
        value = self.state(); raw = bounded(self.source)
        return value['offset'] == len(raw) and value['hash'] == hashlib.sha1(raw).hexdigest()

    def start(self):
        self.start_number += 1
        log = (self.evidence / ('reader-' + str(self.start_number) + '.stderr')).open('xb')
        self.handles.append(log)
        process = subprocess.Popen(['/bin/bash', str(ROOT / 'wazuh-isolated.sh'), 'launch', str(self.prefix)],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=ENV, start_new_session=True)
        self.pending_process = process
        initial = process_info(process.pid)
        self.pending_start = initial['start_ticks'] if initial else None
        self.owner.registry()
        # Register the direct child before any fallible readiness checks. The
        # helper exec chain retains this PID; cleanup never searches by name.
        try:
            self.child = Child(process, self.prefix)
            self.pending_process = None
        except BaseException:
            # Popen's direct child remains unreaped here, so its process group
            # cannot be replaced by an unrelated reused PID during cleanup.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while live_group_members(process.pid):
                need(time.monotonic() < deadline, 'constructor_group_cleanup_timeout')
                time.sleep(.05)
            process.wait(timeout=5)
            self.pending_process = None
            raise
        self.owner.registry()
        pidpath = self.prefix / ('var/run/wazuh-logcollector-' + str(process.pid) + '.pid')
        self.wait(lambda: pidpath.exists(), 'private_reader_pid_missing')
        self.child.verify()
        self.wait(lambda: self.child.has_input(self.source), 'private_input_fd_missing')
        self.owner.registry()
        self.collect(1)

    def stop(self, *, force=False, require_eof=False):
        child = self.child
        if child is None:
            return
        started = time.monotonic(); sent = False; forced_cleanup = False
        try:
            if not child.verified:
                # Also clean a failed launch whose direct leader has already
                # exited: its mount/shell descendants can still hold the group.
                kill_launch_group(child.process, child.start)
                forced_cleanup = True
                sent = True
            elif child.live():
                child.signal(signal.SIGKILL if force else signal.SIGTERM)
                sent = True
            try:
                child.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                forced_cleanup = True
                if child.live():
                    child.signal(signal.SIGKILL, require_isolated=child.verified)
                child.process.wait(timeout=5)
        finally:
            row = {'reader_start': self.start_number, 'pid': child.pid, 'start_ticks': child.start,
                   'requested_signal': 'SIGKILL' if force else 'SIGTERM', 'signal_sent': sent,
                   'cleanup_forced': forced_cleanup, 'returncode': child.process.returncode,
                   'elapsed_seconds': round(time.monotonic() - started, 6)}
            try:
                row['checkpoint'] = self.state()
                row['checkpoint_exact_eof'] = self.exact_eof()
            except (FileNotFoundError, ValueError, Refused):
                row['checkpoint_exact_eof'] = False
            self.result['stops'].append(row); self.owner.save()
        need(not child.live(), 'private_child_remains')
        child.close(); self.child = None; self.owner.registry()
        self.collect(.5)
        need(sent and not forced_cleanup and row['returncode'] == (-signal.SIGKILL if force else 1), 'native_stop_contract_failed')
        need(not require_eof or row['checkpoint_exact_eof'], 'native_saved_checkpoint_not_at_eof')

    def marker(self, sequence):
        count = self.counts()[sequence]
        self.append([sequence])
        self.wait(lambda: self.counts()[sequence] > count, 'live_marker_missing')
        self.collect(2)

    def case(self, name, before, offline, **metadata):
        after = self.counts(); delta = after - before
        self.result['cases'].append({'name': name, 'received_counts': {str(k): v for k, v in sorted(delta.items())},
            'offline_sequences': offline, 'offline_missing': [n for n in offline if delta[n] == 0],
            'duplicate_sequences': sorted(n for n in delta if before[n] > 0 or delta[n] > 1),
            'prior_case_replays': sorted(n for n in delta if before[n] > 0),
            'within_case_repeats': {str(n): delta[n] for n in sorted(delta) if delta[n] > 1}, **metadata})
        self.owner.result['phase'] = self.name + ':' + name; self.owner.save()

    def switch(self, destination):
        previous = inode(self.source)
        temp = self.directory / '.next-reader.json'
        os.link(destination, temp); os.replace(temp, self.source); sync_dir(self.directory)
        need(inode(self.source) != previous, 'generation_inode_not_changed')
        return previous, inode(self.source)

    def execute(self):
        write_new(self.generation, self.row(1) + self.row(2))
        os.link(self.generation, self.source)
        command(['/bin/bash', str(ROOT / 'wazuh-isolated.sh'), 'prepare', str(self.prefix)], self.evidence, 'prepare', 45)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.socket.bind(str(self.prefix / 'queue/sockets/queue'))
        os.chmod(self.prefix / 'queue/sockets/queue', 0o600)
        before = self.counts(); self.start(); self.marker(3)
        self.stop(require_eof=True); self.save_state('initial')
        self.case('first_registration', before, [1, 2], expectation='observation_only_no_saved_cursor')

        before = self.counts(); self.append([4, 5]); self.start(); self.marker(6)
        self.stop(require_eof=True); baseline = self.save_state('graceful')
        self.case('graceful_stop_offline_append', before, [4, 5], native_cursor_used=True)

        self.start(); before = self.counts(); self.append([7, 8])
        self.wait(lambda: all(self.counts()[n] > before[n] for n in (7, 8)), 'prekill_input_missing')
        self.child.signal(signal.SIGSTOP)
        self.wait(lambda: process_info(self.child.pid)['state'] == 'T', 'private_stop_not_observed', 3)
        frozen = self.save_state('before-kill')
        stale = frozen['offset'] == baseline['offset'] and frozen['hash'] == baseline['hash']
        self.stop(force=True); killed = self.save_state('after-kill')
        need(killed == frozen, 'checkpoint_changed_after_frozen_kill')
        restart_before = self.counts(); self.append([9, 10]); self.start(); self.marker(11)
        self.stop(require_eof=True); self.save_state('postkill-restart')
        self.case('forced_stop_stale_native_checkpoint', restart_before, [9, 10],
                  stale_checkpoint_established=stale, memory_only_received_sequences=[7, 8],
                  replayed_memory_sequences=[n for n in (7, 8) if self.counts()[n] > restart_before[n]])

        old_raw = bounded(self.source)
        first, second = self.row(12), self.row(13)
        padding = len(old_raw) - len(first) - len(second)
        need(padding >= 0, 'equal_size_fixture_too_short')
        new_raw = self.row(12, 'x' * padding) + second
        need(len(new_raw) == len(old_raw) and sha(new_raw) != sha(old_raw), 'equal_size_fixture_invalid')
        new_path = self.directory / 'generation-1.json'; write_new(new_path, new_raw)
        previous, current = self.switch(new_path)
        before = self.counts(); self.start(); self.marker(14); self.stop(require_eof=True)
        self.save_state('new-generation')
        self.case('cold_new_inode_same_size_distinct_bytes', before, [12, 13], previous_inode=previous,
                  new_inode=current, equal_size=True, distinct_sha256=True, native_checkpoint_unmodified=True)

        # Identical bytes in a distinct generation intentionally reuse logical
        # IDs. Native pathname/prefix checkpoints may skip the new generation;
        # that is a measured limitation, not a reason to edit its checkpoint.
        copied = bounded(self.source)
        same_path = self.directory / 'generation-2.json'; write_new(same_path, copied)
        previous, current = self.switch(same_path)
        before = self.counts(); self.start(); self.marker(15); self.stop(require_eof=True)
        self.save_state('identical-generation')
        self.case('cold_new_inode_identical_bytes', before, [12, 13, 14], previous_inode=previous,
                  new_inode=current, identical_previous_bytes=True, expected='observe_generation_ambiguity')
        self.result['received_counts_total'] = {str(k): v for k, v in sorted(self.counts().items())}
        self.result['receipts'] = len(self.receipts)
        self.result['exact_synthetic_payloads'] = True
        self.result['completed'] = True
        self.owner.save()

    def preserve(self):
        for path in sorted(self.directory.glob('generation-*.json')):
            write_new(self.evidence / path.name, bounded(path), 0o400)
        for relative in ('etc/ossec.conf', 'etc/internal_options.conf', 'etc/local_internal_options.conf',
                         'prepared.sha256', 'logs/ossec.log', 'queue/logcollector/file_status.json'):
            source = self.prefix / relative
            if source.is_file() and not source.is_symlink():
                write_new(self.evidence / relative.replace('/', '--'), bounded(source), 0o400)
        for handle in self.handles:
            handle.flush(); os.fsync(handle.fileno()); handle.close()
        receipt = self.evidence / 'receipts.jsonl'
        if receipt.exists():
            fd = os.open(receipt, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        if self.socket is not None:
            self.socket.close()
        sync_dir(self.evidence)


class Probe:
    def __init__(self, output):
        self.output = output; self.run_id = uuid.uuid4().hex
        self.stage = Path(tempfile.mkdtemp(prefix='capstone-raw-restart.', dir='/var/tmp'))
        os.chmod(self.stage, 0o700)
        self.profiles = []
        self.result = {'schema_version': 1, 'kind': 'native_wazuh_raw_restart', 'run_id': self.run_id,
                       'status': 'running', 'phase': 'prepare', 'profiles': [],
                       'native_version_expected': '4.14.8', 'private_stage': str(self.stage),
                       'no_operating_source_input': True, 'manager_delivery': False,
                       'checkpoint_rewritten_by_fixture': False, 'power_failure_durability_tested': False,
                       'source_sha256': {name: sha(bounded(ROOT / name)) for name in ('run-probe-a.py', 'wazuh-isolated.sh')}}
        for name in ('run-probe-a.py', 'wazuh-isolated.sh'):
            write_new(output / name, bounded(ROOT / name), 0o400)
        self.save(); self.registry()

    def save(self):
        atomic(self.output / 'result.json', self.result)

    def registry(self):
        atomic(self.output / 'runtime.json', {'stage': str(self.stage), 'children': [
            {'pid': p.child.pid, 'start_ticks': p.child.start, 'prefix': str(p.prefix),
             'isolation_verified': p.child.verified} for p in self.profiles if p.child is not None],
             'pending_launches': [{'pid': p.pending_process.pid, 'start_ticks': p.pending_start,
                                  'prefix': str(p.prefix)} for p in self.profiles if p.pending_process is not None]})

    def execute(self):
        before = operating_snapshot(self.output, 'operating-before')
        self.result['operating_before'] = before; self.save()
        for name in ('default', 'recover'):
            profile = Profile(self, name); self.profiles.append(profile); profile.execute()
        self.result['status'] = 'completed_observations'

    def cleanup(self):
        errors = []
        for profile in self.profiles:
            if profile.pending_process is not None:
                try:
                    kill_launch_group(profile.pending_process, profile.pending_start)
                    profile.pending_process.wait(timeout=5)
                    profile.pending_process = None
                except BaseException as error:
                    errors.append({'phase': 'pending_launch', 'type': type(error).__name__})
            if profile.child is not None:
                try:
                    profile.stop()
                except BaseException as error:
                    errors.append({'phase': 'stop', 'type': type(error).__name__})
            try:
                profile.preserve()
            except BaseException as error:
                errors.append({'phase': 'preserve', 'type': type(error).__name__})
        live = [p.child.pid for p in self.profiles if p.child is not None and
                (p.child.live() or not p.child.verified)]
        live += [p.pending_process.pid for p in self.profiles if p.pending_process is not None]
        self.result['native_children_stopped'] = not live
        if not live and not errors:
            shutil.rmtree(self.stage)
        self.result['private_stage_removed'] = not self.stage.exists()
        self.result['cleanup_errors'] = errors
        try:
            after = operating_snapshot(self.output, 'operating-after')
            self.result['operating_after'] = after
            self.result['operating_unchanged'] = after == self.result.get('operating_before')
        except BaseException as error:
            self.result['operating_postflight_error'] = type(error).__name__
            self.result['operating_unchanged'] = False
        if errors or live or not self.result['operating_unchanged']:
            self.result['status'] = 'failed'
        self.registry(); self.save()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    need(sys.platform == 'linux' and os.geteuid() == 0, 'linux_root_required')
    need(Path('/etc/machine-id').read_text().strip() == MID, 'wrong_machine')
    output = Path(args.output)
    need(output.parent == OUTPUT_ROOT and re.fullmatch(r'run-[A-Za-z0-9_-]{1,40}', output.name), 'output_path_rejected')
    for parent in reversed(output.parent.parents):
        if parent == Path('/'):
            continue
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not stat.S_ISLNK(info.st_mode), 'output_ancestor_invalid')
    info = output.parent.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'output_parent_invalid')
    output.mkdir(mode=0o700)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    probe = Probe(output)
    def interrupted(_number, _frame):
        raise Refused('fixture_interrupted_or_deadline')
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(number, interrupted)
    signal.alarm(360)
    try:
        probe.execute()
    except BaseException as error:
        probe.result['status'] = 'failed'
        probe.result['failure_code'] = str(error) if isinstance(error, Refused) else type(error).__name__
        probe.result['failure_frames'] = [{'file': Path(f.filename).name, 'function': f.name, 'line': f.lineno}
                                          for f in traceback.extract_tb(error.__traceback__)[-12:]]
    finally:
        signal.alarm(0)
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, signal.SIG_IGN)
        probe.cleanup()
    print(json.dumps(probe.result, sort_keys=True))
    return 0 if probe.result['status'] == 'completed_observations' else 1


if __name__ == '__main__':
    sys.exit(main())
