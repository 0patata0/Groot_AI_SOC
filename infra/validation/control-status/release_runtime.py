"""Operator-only release template; not an installer or an MCP/agent tool.

The preparer binds BASE, hashes this file into the exact plan, and stages both
in a root-only directory. Running this unrendered template always refuses.
The operator supplies the approved full plan SHA. No credential is an argument.
"""
from contextlib import contextmanager, ExitStack
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

BASE = '__DEPLOYMENT_BASE__'
KST = timezone(timedelta(hours=9))
CHAT_UNITS = ('capstone-review-chat.service', 'capstone-ollama-chat.service')
TIMER = 'capstone-management.timer'
MANAGER = 'capstone-management.service'
QUEUES = ('/var/lib/capstone-review-chat/queue.sqlite',
          '/var/lib/capstone-ollama-trial/chat/queue.sqlite')
NATIVE_DB = '/opt/hermes-data/state.db'
DATABASES = (*QUEUES, NATIVE_DB, '/var/lib/capstone-management/state.sqlite3')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if not value:
        raise ValueError(code)


def run(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    need(result.returncode == 0, 'fixed_command_failed')
    return result.stdout


def read_private(path):
    p = Path(path); st = p.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == 0
         and not st.st_mode & 0o077 and st.st_size <= 2 * 1024 * 1024, 'private_file_invalid')
    return p.read_bytes()


def validate_chat_health(reports, identities, now, resumed_at):
    """A running unit alone does not prove its new chat process is ready."""
    for engine in ('review', 'ollama'):
        row = reports[engine]; expected = identities[engine]
        need(type(row.get('pid')) is int and row['pid'] == expected['pid']
             and type(row.get('process_start_ticks')) is int
             and row['process_start_ticks'] == expected['ticks'], 'chat_process_changed')
        stamp = row.get('last_poll') if engine == 'review' else row.get('checked_at')
        need(type(stamp) in (int, float) and resumed_at <= stamp <= now
             and now - stamp < 45, 'chat_heartbeat_stale')
        if engine == 'ollama':
            need(row.get('websocket_connected') is True and row.get('worker_alive') is True,
                 'ollama_chat_not_connected')


def execute_apply(actor, files):
    """State/service orchestration is separate from exact file replacement."""
    actor.preflight()
    files.check(('before_sha256',))
    try:
        actor.arm_rollback()
        actor.quiesce(emergency=False)
        snapshot = actor.database_snapshot()
        files.apply()
        actor.verify_database_snapshot(snapshot)
        actor.resume()
        actor.ready(candidate=True)
        files.check(('after_sha256',))
        actor.mark('APPLIED')
        return True
    except Exception as exc:
        if actor.stop_started:
            actor.quiesce(emergency=True)
            files.restore()
            actor.resume()
            actor.ready(candidate=False)
            files.check(('before_sha256',))
            actor.mark('APPLY_FAILED_ROLLED_BACK', error_type=type(exc).__name__)
        else:
            actor.resume_timer()
            actor.mark('DEFERRED', error_type=type(exc).__name__)
        actor.disarm()
        return False


def execute_rollback(actor, files):
    if actor.phase() == 'COMMITTED':
        return False
    actor.preflight(rollback=True)
    files.check(('before_sha256', 'after_sha256'))
    actor.quiesce(emergency=True)
    snapshot = actor.database_snapshot()
    restored = files.restore()
    actor.verify_database_snapshot(snapshot)
    actor.resume()
    actor.ready(candidate=False)
    files.check(('before_sha256',))
    actor.mark('ROLLED_BACK', restored_files=restored)
    actor.disarm()
    return True


class Actor:
    def __init__(self, approved_sha):
        need(os.geteuid() == 0, 'root_required')
        need(re.fullmatch(r'/var/lib/capstone-native-status/[0-9a-f]{16}', BASE), 'unbound_template')
        self.base = Path(BASE)
        for path in (self.base, *self.base.parents):
            st = path.lstat()
            need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'unsafe_release_directory')
        raw = read_private(self.base / 'plan.json')
        need(re.fullmatch('[0-9a-f]{64}', approved_sha) and sha(raw) == approved_sha, 'approval_plan_mismatch')
        self.plan_sha = approved_sha; self.plan = json.loads(raw)
        need(self.plan['schema'] == 1 and self.plan['base'] == BASE, 'plan_shape')
        need(sha(Path(__file__).read_bytes()) == self.plan['runtime_sha256'], 'runtime_changed')
        p = self.base / 'file_transaction.py'
        need(sha(read_private(p)) == self.plan['file_transaction_sha256'], 'transaction_module_changed')
        spec = importlib.util.spec_from_file_location('_reviewed_status_file_transaction', p)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.files = module.FileSet(self.plan['files'], self.base)
        self.stop_started = False

    @contextmanager
    def lock(self):
        fd = os.open(self.base / 'operator.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def state(self):
        return json.loads(read_private(self.base / 'state.json'))

    def phase(self):
        return self.state()['phase']

    def mark(self, phase, **details):
        value = self.state(); value.update(phase=phase, at_kst=datetime.now(KST).isoformat(), **details)
        p = self.base / ('state-' + uuid.uuid4().hex)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
        os.replace(p, self.base / 'state.json')
        print(json.dumps({'at_kst': value['at_kst'], 'phase': phase, **details}), flush=True)

    def container(self):
        value = json.loads(run(['/usr/local/bin/docker', 'inspect', self.plan['container']['id']]))[0]
        need(value['Id'] == self.plan['container']['id'] and value['Image'] == self.plan['container']['image'], 'container_changed')
        need(value['Name'] == '/hermes', 'container_name_changed')
        observed = [{k: m.get(k) for k in ('Type', 'Source', 'Destination', 'RW')} for m in value['Mounts']]
        need(observed == self.plan['container']['mounts'], 'container_mounts_changed')
        return value

    def preflight(self, rollback=False):
        self.container()
        for path, digest in self.plan['protected'].items():
            p = Path(path); need(p.is_file() and not p.is_symlink() and sha(p.read_bytes()) == digest, 'protected_configuration_changed')
        if not rollback:
            need(self.phase() in ('PREPARED', 'DEFERRED'), 'approval_already_used')
            need(self.container()['State']['Running'], 'container_not_running')
            for unit in (*CHAT_UNITS, TIMER):
                need(run(['/usr/bin/systemctl', 'is-active', unit]).strip() == 'active', 'original_service_not_active')
            self.files.payloads('candidates', 'after_sha256')

    def rollback_unit(self):
        unit = self.state().get('rollback_unit')
        need(isinstance(unit, str) and re.fullmatch('capstone-native-status-' + self.plan['source_bundle_id'][:16] + r'-[0-9a-f]{8}-rollback', unit), 'rollback_unit_invalid')
        return unit

    def arm_rollback(self):
        unit = 'capstone-native-status-' + self.plan['source_bundle_id'][:16] + '-' + uuid.uuid4().hex[:8] + '-rollback'
        self.mark('ARMING', rollback_unit=unit)
        run(['/usr/bin/systemd-run', '--unit=' + unit, '--on-active=15m', '--collect',
             '/usr/bin/python3', '-I', '-B', str(self.base / 'release_runtime.py'), 'rollback', self.plan_sha])
        need(run(['/usr/bin/systemctl', 'is-active', unit + '.timer']).strip() == 'active', 'rollback_timer_not_active')

    def disarm(self):
        result = subprocess.run(['/usr/bin/systemctl', 'stop', self.rollback_unit() + '.timer'],
                                capture_output=True, text=True, timeout=20)
        need(result.returncode in (0, 5), 'rollback_timer_cancel_failed')

    def resume_timer(self):
        run(['/usr/bin/systemctl', 'start', TIMER])

    @contextmanager
    def writer_leases(self):
        """Block new queue/turn writers, with no record updates by this owner."""
        with ExitStack() as stack:
            connections = []
            for path in (*QUEUES, NATIVE_DB):
                need(Path(path).is_file() and not Path(path).is_symlink(), 'queue_missing')
                db = sqlite3.connect(path, isolation_level=None, timeout=0)
                stack.callback(db.close); db.execute('BEGIN IMMEDIATE'); stack.callback(db.rollback)
                connections.append(db)
            for db in connections[:2]:
                need(db.execute("SELECT count(*) FROM jobs WHERE status NOT IN ('done','cancelled','abandoned')").fetchone()[0] == 0, 'queue_busy')
            need(connections[2].execute('SELECT count(*) FROM session_turn_leases WHERE expires_at>?', (time.time(),)).fetchone()[0] == 0, 'native_turn_busy')
            yield
            need(all(db.total_changes == 0 for db in connections), 'unexpected_database_write')

    def quiesce(self, emergency):
        run(['/usr/bin/systemctl', 'stop', TIMER])
        if emergency:
            self.stop_started = True
            run(['/usr/bin/systemctl', 'stop', MANAGER, *CHAT_UNITS], timeout=35)
            run(['/usr/local/bin/docker', 'stop', '--time', '20', self.plan['container']['id']], timeout=35)
        else:
            deadline = time.monotonic() + 30
            while run(['/usr/bin/systemctl', 'show', MANAGER, '-p', 'ActiveState', '--value']).strip() != 'inactive':
                need(time.monotonic() < deadline, 'manager_busy'); time.sleep(1)
            with self.writer_leases():
                self.stop_started = True; self.mark('STOPPING')
                run(['/usr/bin/systemctl', 'stop', *CHAT_UNITS], timeout=35)
                run(['/usr/local/bin/docker', 'stop', '--time', '20', self.plan['container']['id']], timeout=35)
        need(not self.container()['State']['Running'], 'container_not_stopped')

    def database_snapshot(self):
        out = {}
        for name in DATABASES:
            for suffix in ('', '-wal', '-shm'):
                p = Path(name + suffix)
                if p.exists():
                    need(not p.is_symlink() and p.is_file(), 'database_path_invalid')
                    digest = hashlib.sha256()
                    with p.open('rb') as stream:
                        for part in iter(lambda: stream.read(65536), b''): digest.update(part)
                    out[str(p)] = digest.hexdigest()
        return out

    def verify_database_snapshot(self, before):
        need(before == self.database_snapshot(), 'database_changed_while_stopped')

    def resume(self):
        self.resume_at = time.time()
        run(['/usr/local/bin/docker', 'start', self.plan['container']['id']], timeout=40)
        run(['/usr/bin/systemctl', 'start', *CHAT_UNITS], timeout=35)
        self.resume_timer()

    def ready(self, candidate):
        deadline = time.monotonic() + 120
        while True:
            try:
                need(self.container()['State']['Running'], 'container_not_running')
                for unit in CHAT_UNITS:
                    need(run(['/usr/bin/systemctl', 'is-active', unit]).strip() == 'active', 'chat_service_not_active')
                reports = {}; identities = {}
                for engine, unit, path in (
                    ('review', CHAT_UNITS[0], '/var/lib/capstone-review-chat/health.json'),
                    ('ollama', CHAT_UNITS[1], '/var/lib/capstone-ollama-trial/chat/health.json')):
                    pid = int(run(['/usr/bin/systemctl', 'show', unit, '-p', 'MainPID', '--value']).strip())
                    need(pid > 0, 'chat_pid_missing')
                    ticks = int((Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19])
                    identities[engine] = {'pid': pid, 'ticks': ticks}
                    reports[engine] = json.loads(Path(path).read_text())
                validate_chat_health(reports, identities, time.time(), self.resume_at)
                health = json.loads(Path('/opt/hermes-data/health/chat.json').read_text())
                need(health['websocket_connected'] is True and health['worker_alive'] is True
                     and 0 <= time.time() - health['checked_at'] < 45
                     and health['checked_at'] >= self.resume_at, 'gateway_not_ready')
                need(type(health['pid']) is int and health['pid'] > 1, 'gateway_pid_invalid')
                code = ("import json,os,sys;from pathlib import Path; p=Path('/proc')/sys.argv[1]; "
                        "print(json.dumps({'uid':p.stat().st_uid,'ticks':int((p/'stat').read_text().rsplit(')',1)[1].split()[19])}))")
                proc = json.loads(run(['/usr/local/bin/docker', 'exec', self.plan['container']['id'],
                    '/opt/hermes/.venv/bin/python', '-B', '-c', code, str(health['pid'])], timeout=15))
                native_uid = next(r['uid'] for r in self.plan['files'] if r['target'].endswith('/groot-query-completion/__init__.py'))
                need(proc['uid'] == native_uid and proc['ticks'] == health['process_start_ticks'], 'gateway_process_changed')
                if candidate:
                    receipt = json.loads(Path('/opt/hermes-data/health/query-completion.json').read_text())
                    need(receipt['schema_version'] == 1 and receipt['adapter_version'] == self.plan['query_version']
                         and receipt['aliases_installed'] is True and receipt['pid'] == health['pid']
                         and receipt['process_start_ticks'] == health['process_start_ticks'], 'loaded_adapter_not_confirmed')
                    observed = datetime.fromisoformat(receipt['observed_at_kst'])
                    need(observed.utcoffset() == timedelta(hours=9) and self.resume_at - 2 <= observed.timestamp() <= time.time() + 5, 'load_receipt_time_invalid')
                    expected = {Path(r['target']).name: r['after_sha256'] for r in self.plan['files']
                        if r['target'].startswith('/opt/hermes-data/plugins/groot-query-completion/')}
                    need(receipt['observed_sources_sha256'] == {k: expected[k] for k in receipt['observed_sources_sha256']}
                         and set(receipt['observed_sources_sha256']) == {'__init__.py','grounding.py','workflow_contract.py','skill-soc-investigate.md','chat_harness.py'}
                         and receipt['loaded_evidence_sha256'] == expected['grounding.py'], 'loaded_sources_changed')
                self.preflight(rollback=True)
                for path in DATABASES:
                    if Path(path).is_file():
                        with sqlite3.connect('file:' + path + '?mode=ro', uri=True, timeout=5) as db:
                            need(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'database_integrity_failed')
                return
            except Exception:
                need(time.monotonic() < deadline, 'startup_verification_timeout')
                time.sleep(2)


def main():
    need(len(sys.argv) == 3 and sys.argv[1] in ('apply', 'rollback', 'commit'), 'operator_arguments')
    actor = Actor(sys.argv[2])
    with actor.lock():
        action = sys.argv[1]
        if action == 'apply': execute_apply(actor, actor.files)
        elif action == 'rollback': execute_rollback(actor, actor.files)
        else:
            need(actor.phase() == 'APPLIED', 'not_waiting_for_commit')
            actor.resume_at = 0
            actor.ready(candidate=True); actor.files.check(('after_sha256',))
            actor.mark('COMMITTED'); actor.disarm()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'at_kst': datetime.now(KST).isoformat(), 'phase': 'REFUSED', 'error_type': type(exc).__name__}), flush=True)
        raise SystemExit(1)
