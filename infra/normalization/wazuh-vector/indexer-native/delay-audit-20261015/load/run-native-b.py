#!/usr/bin/env python3
"""One private native analysisd, 30,000 synthetic rows over 600 seconds.

Operator tool only. No production queue, service, checkpoint, Indexer or model
calls. Reuses frozen tested helpers in memory; never invokes their main().
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import time
import types
import uuid

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[2]
OUTPUT = Path('/var/tmp/capstone-delay-audit-20261015')
MID = '1e143067c98a44ffba6eaa925dc038d7'
EXECUTION_REVIEWED = True
PINS = {
    'correlation-fix/run-load-b.py': '69b7bd1aaa8bc5224da32978422b21b7ef8d20830dd35c0a43236206c965bc63',
    'correlation-diagnosis/run-isolated-b.py': '605f5296dc104c16b528cf6639dbe0a8167bdd5b0d13b8431b4d20f4759f3821',
    'fixtures/correlation/canary-repeat.jsonl': '6fd45116feb2d957a84b169eacceaed71bd290580b9274f4c2bc9bd46f0bd6bc',
    'fixtures/correlation/canary-cross.jsonl': '1ff2615c3c1cd8aa365d13c4125f86bdc5bf1dd5823b3c703c32e455a8359e7c',
    'fixtures/correlation/canary-repeat-duplicate.jsonl': '4660b20d4ef1233d9dbcff6f67da81b0261fc380e1a60ecfb9161cdcdc5eacc2',
    'fixtures/correlation/canary-historical.jsonl': 'dfeb3224ef59e47d20c7e6b1157dbe911d51b9dfadf333079d8dd850459633a3',
}
OPTIONS = {'analysisd.event_threads': 1, 'analysisd.rule_matching_threads': 1,
           'analysisd.decoder_order_size': 1024}


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def fields(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_uid, st.st_gid,
            st.st_mode, st.st_nlink, st.st_mtime_ns, st.st_ctime_ns)


def source_bytes(path, expected, owner=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and not before.st_mode & 0o022 and (not owner or before.st_uid == 0)
                and before.st_size <= 2 * 1024 * 1024, 'source_metadata')
        raw = b''
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw += block
        require(fields(before) == fields(os.fstat(fd)) == fields(path.lstat())
                and len(raw) == before.st_size, 'source_changed')
        require(hashlib.sha256(raw).hexdigest() == expected, 'source_sha')
        return raw
    finally:
        os.close(fd)


def patch(raw, replacements):
    text = raw.decode('utf-8')
    for old, new in replacements:
        require(text.count(old) == 1, 'frozen_patch_context')
        text = text.replace(old, new)
    return text.encode('utf-8')


def adapted_load(raw):
    return patch(raw, (
        ('GROUPS, ROWS_PER_GROUP, EPS, LOAD_SECONDS = 2000, 15, 500, 60',
         'GROUPS, ROWS_PER_GROUP, EPS, LOAD_SECONDS = 2000, 15, 50, 600'),
        ('next_sample, next_progress = start, start+10', 'next_sample, next_progress = start, start+30'),
        ('next_progress = now+10', 'next_progress = now+30'),
        ("'microburst_period_ms':30", "'microburst_period_ms':300"),
    ))


def adapted_base(raw):
    # Register the direct child before reading /proc, and bound two read-only
    # Docker postflight calls to 16 seconds total. Namespace/limits unchanged.
    return patch(raw, (('timeout=20).stdout', 'timeout=8).stdout'),
                       ('return p, proc_start(p.pid)', 'return p, None')))


def module(raw, path):
    result = types.ModuleType('load_audit_' + path.stem.replace('-', '_'))
    result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def parse_options(raw):
    found = {}
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if key in OPTIONS:
            require(sep and key not in found and re.fullmatch('[0-9]+', value), 'option_shape')
            found[key] = int(value)
    require(found == OPTIONS, 'current_options_not_1_1_1024')
    return found


def snapshot(base, expected_cid):
    original, result = base.production()
    require(result['cid'] == expected_cid, 'manager_cid_changed')
    extras = {}
    for rel in ('etc/local_internal_options.conf', 'etc/internal_options.conf'):
        path = original / rel
        st = path.stat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_size <= 1024 * 1024,
                'installed_options_metadata')
        raw = path.read_bytes()
        require(fields(st) == fields(path.stat()), 'installed_options_changed')
        extras[rel] = {'sha256': hashlib.sha256(raw).hexdigest(), 'identity': list(fields(st))}
        if rel.endswith('/local_internal_options.conf'):
            parse_options(raw)
    result['options'] = extras
    return original, result


def durable_save(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    temp = path.with_name(path.name + '.next')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as handle:
            handle.write(raw); handle.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def exact_result(result):
    require(result.get('errors') == [] and result.get('input_rows') == 30000
            and result.get('sent_rows') == 30000 and result.get('archive_rows') == 30000
            and result.get('archive_exact_payloads') is True
            and result.get('group_leaf_mismatches') == [] and result.get('exact_group_expectations') is True
            and result.get('alert_writer_drained') is True
            and result.get('archive_leaf_counts') == {'100293': 2000, '100294': 2000}
            and result.get('alert_leaf_counts') == {'100293': 2000, '100294': 2000}
            and result.get('scheduled_eps') == 50 and result.get('scheduled_load_seconds') == 600
            and result.get('fully_drained_stable_seconds', 0) >= 10, 'archive_or_group_result_incomplete')
    state = result.get('native_state_summary', {})
    counts = state.get('final_counters', {})
    require(state.get('available') is True and counts.get('events_received') == 30000
            and counts.get('total_events_decoded') == 30000 and counts.get('events_processed') == 30000
            and counts.get('events_dropped') == 0 and state.get('final_sampled_queues_zero') is True
            and 0 <= state.get('last_state_age_seconds', -1) <= 8, 'native_state_result_incomplete')


def group_members(pid):
    members = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            parts = (path / 'stat').read_text().rsplit(')', 1)[1].split()
        except FileNotFoundError:
            continue
        if int(parts[2]) == pid:
            require(int(parts[3]) == pid, 'child_process_group_session_changed')
            members.append({'pid': int(path.name), 'state': parts[0], 'start_ticks': parts[19]})
    return members


def stop_owned(p, start):
    # Do not poll/wait/reap before signalling: an unreaped direct child reserves
    # its PID/PGID. The trusted foreground helper normally has no descendants.
    require(p.returncode is None, 'direct_child_reaped_before_cleanup')
    os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    identity = Path(f'/proc/{p.pid}/stat').read_text().rsplit(')', 1)[1].split()
    require(int(identity[1]) == os.getpid(), 'not_owned_direct_child')
    require(start is None or identity[19] == start, 'direct_child_identity_changed')
    require(os.getpgid(p.pid) == p.pid and os.getsid(p.pid) == p.pid, 'child_group_identity')
    # A failed first /proc read must not abandon an already registered Popen.
    # It has never been reaped; PPID+new session/group prove this exact child.
    start = identity[19]
    os.killpg(p.pid, signal.SIGTERM)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and any(x['state'] != 'Z' for x in group_members(p.pid)):
        time.sleep(.05)
    remaining = group_members(p.pid)
    if any(x['state'] != 'Z' for x in remaining):
        os.killpg(p.pid, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and any(x['state'] != 'Z' for x in group_members(p.pid)):
            time.sleep(.05)
    require(not any(x['state'] != 'Z' for x in group_members(p.pid)), 'child_group_cleanup_unverified')
    p.wait(timeout=2)
    require(not Path(f'/proc/{p.pid}').exists(), 'child_reap_unverified')
    return {'pid': p.pid, 'start_ticks': start, 'exit_code': p.returncode,
            'direct_child_reaped': True, 'live_process_group_members': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--manager-cid', required=True)
    args = parser.parse_args()
    require(EXECUTION_REVIEWED, 'execution_review_pending')
    require(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'wrong_host_or_user')
    require(re.fullmatch('[0-9a-f]{64}', args.manager_cid), 'full_manager_cid_required')
    target = Path(args.output)
    require(target.parent == OUTPUT and re.fullmatch('load-[a-z0-9-]{1,40}', target.name), 'fixed_output_required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    raw = {rel: source_bytes(PROJECT / rel, sha) for rel, sha in PINS.items()}
    base = module(adapted_base(raw['correlation-diagnosis/run-isolated-b.py']), PROJECT / 'correlation-diagnosis/run-isolated-b.py')
    load = module(adapted_load(raw['correlation-fix/run-load-b.py']), PROJECT / 'correlation-fix/run-load-b.py')
    original_limits = base.limits
    def child_limits():
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGALRM, signal.SIGINT})
        original_limits()
    base.limits = child_limits
    # poll() in the frozen runner must observe without reaping so scoped cleanup
    # can also handle a dead leader with descendants. Its other Popen calls stay.
    class Unreaped:
        def __init__(self, p):
            self.p = p; self.pid = p.pid
        def poll(self):
            value = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            return None if value is None else value.si_status or 1
    if not OUTPUT.exists():
        OUTPUT.mkdir(mode=0o700)
    base.protected_dir(OUTPUT)
    base.protected_dir(target, create=True)
    load.TASK = OUTPUT
    began = time.monotonic()
    result = {'policy': 'private-analysisd-600s-v1', 'status': 'running', 'source_pins': PINS,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'production_inputs_written': False, 'production_checkpoints_written': False,
              'production_services_restarted': False, 'agent_id': '000', 'agent001_transport_test': False,
              'indexer_or_delivery_ack_test': False, 'native_children_cleaned': False,
              'load_verification_completed': False}
    child = None; start_ticks = None; before = None; errors = []
    def progress(value):
        result['progress'] = value
        durable_save(target / 'partial-result.json', result)
        print(json.dumps({'policy': result['policy'], 'elapsed_seconds': round(time.monotonic() - began, 3),
                          **value}, separators=(',', ':')), flush=True)
    def deadline(signum, frame):
        raise RuntimeError('trial_deadline_or_termination')
    signal.signal(signal.SIGALRM, deadline)
    signal.signal(signal.SIGTERM, deadline)
    signal.signal(signal.SIGINT, deadline)
    signal.alarm(675)
    try:
        capacity = load.host_capacity()
        require(capacity['cpu_affinity_count'] == 4 and capacity['MemAvailable'] >= 4 * 1024 * 1024
                and capacity['disk_free_bytes'] >= 2 * 1024 ** 3, 'initial_capacity_insufficient')
        original, before = snapshot(base, args.manager_cid)
        result.update(production_before=before, capacity_before=capacity, options=OPTIONS)
        progress({'phase': 'preparing_private_root'})
        arm = target / 'single'
        base.protected_dir(arm, create=True)
        prefix = arm / 'root'
        metadata = base.prepare(prefix, original, 'single')
        metadata.update(load.explicit_threads(prefix, base, 'single'))
        parse_options((prefix / 'etc/local_internal_options.conf').read_bytes())
        result['private_configuration'] = metadata
        _, unchanged = snapshot(base, args.manager_cid)
        require(before == unchanged, 'production_changed_during_copy')
        events = load.dataset(base, PROJECT / 'fixtures/correlation', uuid.uuid4().hex)
        with (target / 'synthetic-input.jsonl').open('x') as handle:
            for event in events:
                handle.write(event['text'] + '\n')
        result['input_sha256'] = base.digest(target / 'synthetic-input.jsonl')
        # Defer signals only across child creation/registration, never across the
        # workload. A pending TERM is delivered after child/start are registered.
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGALRM, signal.SIGINT})
        try:
            child, _ = base.launch(prefix, arm)
            start_ticks = base.proc_start(child.pid)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        observed_child = Unreaped(child)
        result['runtime'] = base.wait_ready(observed_child, prefix, before['analysisd_pid'])
        progress({'phase': 'ready', 'expected_rows': 30000, 'scheduled_eps': 50, 'duration_seconds': 600})
        result['load'] = load.run_arm(base, prefix, arm, events, observed_child, result['runtime'], progress)
        exact_result(result['load'])
        result['load_verification_completed'] = True
    except Exception as exc:
        errors.append(str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if not result['load_verification_completed']:
            errors.append('load_verification_incomplete')
        if child is not None:
            try:
                result['cleanup'] = stop_owned(child, start_ticks)
                result['native_children_cleaned'] = True
            except Exception as exc:
                errors.append('cleanup_' + type(exc).__name__)
        else:
            result['native_children_cleaned'] = True
        try:
            _, after = snapshot(base, args.manager_cid)
            result['production_after'] = after
            result['production_unchanged'] = before is not None and before == after
            require(result['production_unchanged'], 'production_postflight_changed')
            for rel, sha in PINS.items():
                source_bytes(PROJECT / rel, sha)
        except Exception as exc:
            errors.append('postflight_' + (str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__))
        result.update(status='passed' if not errors else 'failed', errors=errors,
                      elapsed_seconds=round(time.monotonic() - began, 3),
                      observed_at_kst=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat())
        durable_save(target / 'result.json', result)
        print(json.dumps({k: result[k] for k in ('policy', 'status', 'errors', 'elapsed_seconds',
                                                'native_children_cleaned', 'observed_at_kst')}, separators=(',', ':')), flush=True)
    require(not errors, 'load_trial_failed')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'unavailable', 'reason': str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__}), flush=True)
        raise SystemExit(2)
