#!/usr/bin/env python3
"""Fixed A, one operator transaction: size the Wazuh agent client buffer.

Same transaction shape as ../checkpoint-diagnosis/fix-stats-ignore-a.py, which
was applied on A on 2026-10-15: shared locks, the three raw/maintenance timers
paused, a temporary start barrier, one Wazuh stop, the reader guards, a
three-file CAS (ossec.conf plus the wazuh_config_sha256 pin of both raw states,
revision+1, originals kept in history), one start, then unit policy and timers
restored. No retry and no automatic rollback; a failure leaves an inspectable
record. prepare writes private evidence only; apply needs the exact plan SHA
and is single use; verify is read-only. Only <client_buffer> values change.

Why: Wazuh rule 203 "Agent event queue is full" on A (10-29 ~94 s, 11-02
~74 s, 11-05 ~46 s at the package default 5000 events / 500 per second).
A is the IDS/WAF sensor, so attack-time evidence was being dropped.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

# Operator approval 2026-11-13 ("A 버퍼 적용해줘"). The plan binds the
# controller SHA, so this value is fixed before prepare.
APPLY_REVIEWED = True
MID = '096e90b6243e438aa8a7b392be754732'
BASE = Path('/var/backups/capstone-agent-buffer-20261113')
RAW = Path('/var/lib/capstone-raw-operations')
LIB = Path('/usr/local/lib/capstone-raw-operations')
CONF = Path('/var/ossec/etc/ossec.conf')
ENGINES = ('suricata', 'modsecurity')
UNITS = ('capstone-vector.service', 'wazuh-agent.service')
TIMERS = ('capstone-raw-operations@suricata.timer', 'capstone-raw-operations@modsecurity.timer', 'capstone-vector-maintenance.timer')
LOCKS = (Path('/var/lib/rule-change/.lock'), Path('/var/lib/capstone-automation/ansible/vector.lock'))
BARRIERS = tuple(Path('/etc/systemd/system') / (unit + '.d/99-capstone-agent-buffer.conf') for unit in UNITS)
BLOCKED = b'[Service]\nExecStartPre=/usr/bin/false\nRestart=no\n'
START_ONCE = b'[Service]\nRestart=no\n'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1'}
# Live A observation 2026-11-13 02:21-02:24 KST (read-only).
CONF_EXPECTED = ('d65f9da4a3270e573f7505e2dd5cd0bfd0c79d554a73cafd6698d34489aa4b3e', 0, 110, 0o660)
STATE_CONTRACT = (0, 0, 0o600)
BUFFER_BEFORE = {'queue_size': '5000', 'events_per_second': '500'}
# Wazuh limits: queue_size 1..100000, events_per_second 0..1000. Worst case
# about 100000 x 1.6 KB queued (A had 4.5 GB available) and at most ~100 s of
# delivery delay while draining, instead of dropping sensor events.
BUFFER_AFTER = {'queue_size': '100000', 'events_per_second': '1000'}
RUNTIME = {
    'checkpoint-gates.jq': 'ebc3022b44dae2a79845e35b5b26439d369162715644a720ce35257a1e22d8e6',
    'checkpoint-gates.sh': '92acb7ce322d109bc7e70c32bb42a17cf5cddd1b7f5b6d7f23871e89cbaa4af6',
    'coordinator.sh': '9f9ad7996bc0bec3b6b35d00b0f6c7776b346d24c39aef8b7e74ebdd65049592',
    'guard.sh': '7f78865f4be32dbd647b46f15c4d5118471ef5eca607e6f966aa4579b9b3037e',
    'line-length-lib-v2.sh': '848acb15609d859d0643aebd02dd71554245ea5771cb80b6b9a4dec4b61dcf10',
    'state-lib.sh': 'd754d17726310a56c77e5d37c41f0ae3883881dfbc91bfa20b7ef916fe428f3a',
    'state.jq': '3db6baef5c679521bdc257cbe1aca66fd6884714f734a1778ca27b249e40a775',
    'waf-rebind-metadata.sh': 'ab576dc77b70893d82b435edda77f30ab2b6b873981b3d8d86360f0f09f2ff99',
    'writer-gates.sh': 'c8a4f766c8cff125115f4d6413b746309004d608fdc1db370ec4dfe456cb1667',
}
PHASE = 'entry'
ATTEMPTED = None
COMPLETED = []


class Refused(Exception):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def now():
    return datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat()


def parents(path):
    for p in (path, *path.parents):
        s = p.lstat()
        # This one installed Wazuh directory is owned/writable by wazuh. Its
        # parent remains root-protected. Do not extend this exception to any
        # other non-root/group-writable ancestor or follow a symlink.
        protected = (s.st_uid == 0 and not stat.S_IMODE(s.st_mode) & 0o022)
        if p == Path('/var/ossec/etc'):
            protected = (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (110, 110, 0o770)
        need(stat.S_ISDIR(s.st_mode) and protected,
             'parent_not_root_protected')


def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)


def read(path, limit=131072):
    parents(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= limit, 'file_metadata_invalid')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(limit + 1)
        need(len(raw) == s.st_size and identity(s) == identity(os.fstat(fd)) == identity(path.lstat()), 'file_changed')
        return raw, {'sha256': sha(raw), 'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
                     'bytes': len(raw), 'device': s.st_dev, 'inode': s.st_ino}
    finally:
        os.close(fd)


def directory_identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))


def read_relative(path, parent_fd, limit=131072):
    """Recheck a target through the already validated parent descriptor."""
    fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size <= limit, 'file_metadata_invalid')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(limit + 1)
        named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        need(len(raw) == s.st_size and identity(s) == identity(os.fstat(fd)) == identity(named), 'file_changed')
        return raw, {'sha256': sha(raw), 'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
                     'bytes': len(raw), 'device': s.st_dev, 'inode': s.st_ino}
    finally:
        os.close(fd)


def fsync_dir(path, held_fd=None):
    if held_fd is not None:
        os.fsync(held_fd)
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def exclusive(path, raw, mode=0o400):
    parents(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as f:
            f.write(raw); f.flush(); os.fchmod(fd, mode); os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(path.parent)


def record(name, value):
    exclusive(BASE / name, canonical(value))


def command(argv, seconds=20, log=None, accepted=(0,)):
    # timeout owns process-group termination; no retried state-changing call.
    run = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', str(seconds) + 's', *argv]
    if log:
        path = BASE / log
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            result = subprocess.run(run, stdin=subprocess.DEVNULL, stdout=fd, stderr=subprocess.STDOUT,
                                    env=ENV, timeout=seconds + 5, check=False, start_new_session=True)
            os.fsync(fd); os.fchmod(fd, 0o400)
        finally:
            os.close(fd)
        fsync_dir(BASE)
        need(path.stat().st_size <= 1048576, 'diagnostic_log_limit')
        need(result.returncode in accepted, 'native_command_refused_' + log)
        return b''
    result = subprocess.run(run, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=ENV, timeout=seconds + 5, check=False, start_new_session=True)
    need(len(result.stdout) <= 131072 and result.returncode in accepted, 'native_command_refused')
    return result.stdout


def unit(name):
    keys = (('ActiveState', 'SubState', 'UnitFileState', 'InvocationID', 'NeedDaemonReload')
            if name.endswith('.timer') else
            ('ActiveState', 'SubState', 'MainPID', 'InvocationID', 'Result', 'ExecMainStatus',
             'ExecMainStartTimestampMonotonic', 'UnitFileState', 'NeedDaemonReload', 'ExecStartPre', 'Restart'))
    if name in ('capstone-vector-maintenance.service', 'capstone-raw-operations@suricata.service', 'capstone-raw-operations@modsecurity.service'):
        keys = tuple(k for k in keys if k != 'ExecStartPre')
    raw = command(['/usr/bin/systemctl', 'show', name, '--all', '--no-pager', '--property=' + ','.join(keys)])
    result = {}
    for line in raw.decode().splitlines():
        need('=' in line, 'unit_line_invalid')
        key, value = line.split('=', 1)
        if key == 'ExecStartPre' and key in result:
            result[key] += '\n' + value
        else:
            need(key not in result, 'unit_duplicate_scalar')
            result[key] = value
    need(set(result) == set(keys), 'unit_shape_invalid')
    return result


def processes():
    rows = []
    for path in Path('/var/ossec/var/run').glob('wazuh-logcollector-*.pid'):
        match = re.fullmatch(r'wazuh-logcollector-([1-9][0-9]*)\.pid', path.name)
        if not match:
            continue
        pid = int(match[1]); proc = Path('/proc') / str(pid)
        try:
            s = (proc / 'stat').read_text(); parts = s[s.rfind(')') + 2:].split()
            if parts[0] != 'Z' and os.readlink(proc / 'exe') == '/var/ossec/bin/wazuh-logcollector':
                rows.append({'pid': pid, 'start_ticks': parts[19]})
        except FileNotFoundError:
            continue
    return rows


def process():
    rows = processes()
    need(len(rows) == 1, 'live_logcollector_count')
    return rows[0]


def active(value):
    return value['ActiveState'] == 'active' and value['SubState'] == 'running' and value['Result'] == 'success'


def stable_vector(plan):
    expected = plan['services'][UNITS[0]]
    current = unit(UNITS[0])
    need(active(current) and (current['MainPID'], current['InvocationID']) ==
         (expected['MainPID'], expected['InvocationID']), 'vector_changed')


def runtime():
    for name, digest in RUNTIME.items():
        _, meta = read(LIB / name)
        need((meta['sha256'], meta['uid'], meta['gid'], meta['mode']) == (digest, 0, 0, 0o400), 'runtime_source_changed')
    for path in (RAW / 'vector-stop-intent.json', RAW / 'suricata/writer-reopen-intent.json',
                 RAW / 'modsecurity/writer-reopen-intent.json', Path('/var/lib/capstone-vector-maintenance/resume.pending')):
        need(not path.exists() and not path.is_symlink(), 'pending_operation_present')


def guard():
    for role in ('vector', 'wazuh'):
        raw = command(['/bin/bash', str(LIB / 'guard.sh'), role], 115)
        need(json.loads(raw) == {'schema_version': 1, 'status': 'ready', 'reason': 'reader_start_guard',
             'engine': 'modsecurity', 'raw_deleted': False, 'checkpoint_rewritten': False,
             'delivery_acknowledged': False}, 'reader_guard_not_ready')



def build_config(raw):
    """Change only the two <client_buffer> values; everything else is kept."""
    need(b'\r' not in raw and b'\0' not in raw, 'config_framing')
    root = ET.fromstring(b'<fixture-root>' + raw + b'</fixture-root>')
    buffers = list(root.iter('client_buffer'))
    need(len(buffers) == 1, 'client_buffer_count')
    node = buffers[0]
    need(node.attrib == {} and len(node.findall('disabled')) == 1 and node.findtext('disabled') == 'no',
         'client_buffer_disabled_or_ambiguous')
    for key, value in BUFFER_BEFORE.items():
        found = node.findall(key)
        need(len(found) == 1 and found[0].attrib == {} and (found[0].text or '') == value,
             'client_buffer_value_unexpected')
    blocks = list(re.finditer(rb'<client_buffer>.*?</client_buffer>', raw, re.S))
    need(len(blocks) == 1, 'client_buffer_byte_count')
    block = blocks[0][0]
    for key, value in BUFFER_BEFORE.items():
        tag = key.encode()
        block, count = re.subn(rb'<' + tag + rb'>' + value.encode() + rb'</' + tag + rb'>',
                               b'<' + tag + b'>' + BUFFER_AFTER[key].encode() + b'</' + tag + b'>', block)
        need(count == 1, 'client_buffer_value_bytes')
    after = raw[:blocks[0].start()] + block + raw[blocks[0].end():]
    for key, value in BUFFER_AFTER.items():
        node.find(key).text = value
    def view(item):
        return (item.tag, item.attrib, (item.text or '').strip(), [view(x) for x in item])
    need(view(root) == view(ET.fromstring(b'<fixture-root>' + after + b'</fixture-root>')), 'config_other_content_changed')
    return after


def build_state(raw, engine, old_hash, new_hash):
    value = json.loads(raw)
    need(canonical(value) == raw and value['engine'] == engine and value['machine_id'] == MID and
         value['phase'] == 'active' and value['pending'] is None and
         value['source_pins']['wazuh_config_sha256'] == old_hash, 'state_not_fixed_active')
    value['revision'] += 1
    value['source_pins']['wazuh_config_sha256'] = new_hash
    return canonical(value)


def state_check(path):
    command(['/usr/bin/jq', '-e', '-f', str(LIB / 'state.jq'), str(path)])


def contract(meta):
    return [meta['sha256'], meta['uid'], meta['gid'], meta['mode']]


def snapshot_targets(expected):
    result = {}
    for path, want in expected.items():
        raw, meta = read(Path(path))
        need(contract(meta) == list(want), 'target_compare_conflict')
        result[path] = meta
    return result


def live_targets():
    """Config must be the reviewed bytes; states are bound at prepare time.
    Returns (contract per path, full metadata per path)."""
    contracts = {str(CONF): list(CONF_EXPECTED)}
    metas = {str(CONF): snapshot_targets(contracts)[str(CONF)]}
    for engine in ENGINES:
        path = RAW / engine / 'state.json'
        raw, meta = read(path)
        need((meta['uid'], meta['gid'], meta['mode']) == STATE_CONTRACT, 'state_metadata_changed')
        build_state(raw, engine, CONF_EXPECTED[0], '0' * 64)
        contracts[str(path)] = contract(meta); metas[str(path)] = meta
    return contracts, metas


def buffer_values(raw):
    root = ET.fromstring(b'<fixture-root>' + raw + b'</fixture-root>')
    nodes = list(root.iter('client_buffer'))
    need(len(nodes) == 1, 'client_buffer_count')
    return {key: nodes[0].findtext(key) for key in BUFFER_AFTER}


def agent_connected():
    raw, _ = read(Path('/var/ossec/var/run/wazuh-agentd.state'), 8192)
    need(b"status='connected'" in raw, 'agent_not_connected')


def prepare():
    runtime(); before_contract, before = live_targets()
    for barrier in BARRIERS:
        parents(barrier.parent); need(not barrier.exists() and not barrier.is_symlink(), 'barrier_already_present')
    services = {name: unit(name) for name in UNITS}
    need(all(active(v) for v in services.values()), 'reader_not_active')
    timers = {name: unit(name) for name in TIMERS}
    need(all(v['ActiveState'] == 'active' and v['UnitFileState'] == 'enabled' for v in timers.values()), 'timer_baseline_changed')
    current_process = process(); guard()
    parents(BASE.parent); BASE.mkdir(mode=0o700); fsync_dir(BASE.parent)
    original, _ = read(CONF); candidate = build_config(original)
    paths = [CONF] + [RAW / engine / 'state.json' for engine in ENGINES]
    after = {}
    for i, path in enumerate(paths):
        raw, meta = read(path)
        need(meta == before[str(path)], 'prepare_source_changed')
        new = candidate if i == 0 else build_state(raw, ENGINES[i - 1], CONF_EXPECTED[0], sha(candidate))
        exclusive(BASE / f'before-{i}', raw)
        exclusive(BASE / f'after-{i}', new)
        after[str(path)] = [sha(new), meta['uid'], meta['gid'], meta['mode']]
        if i:
            state_check(BASE / f'after-{i}')
            parents(path.parent / 'history')
            need(sum(1 for _ in (path.parent / 'history').iterdir()) < 1024, 'history_capacity_limit')
    command(['/var/ossec/bin/wazuh-agentd', '-t', '-c', str(BASE / 'after-0')], 30, 'config-test-agentd.log')
    command(['/var/ossec/bin/wazuh-logcollector', '-t', '-c', str(BASE / 'after-0')], 30, 'config-test-logcollector.log')
    snapshot_targets(before_contract)
    need(process() == current_process and all(unit(n)['InvocationID'] == services[n]['InvocationID'] for n in UNITS), 'reader_changed_during_prepare')
    plan = {'schema_version': 1, 'policy': 'fixed-A-agent-buffer-v1', 'machine_id': MID,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'created_epoch': int(time.time()),
            'created_at_kst': now(), 'controller_sha256': sha(Path(__file__).read_bytes()),
            'before': before, 'before_contract': before_contract, 'after': after, 'services': services, 'logcollector': current_process,
            'timers': timers, 'runtime': RUNTIME, 'paths': [str(x) for x in paths],
            'buffer_before': BUFFER_BEFORE, 'buffer_after': BUFFER_AFTER,
            'config_changes': ['client_buffer_queue_size', 'client_buffer_events_per_second']}
    record('plan.json', plan)
    return {'status': 'prepared', 'plan_sha256': sha(canonical(plan)), 'operating_mutations': False,
            'apply_reviewed': APPLY_REVIEWED}


def load_plan(digest):
    raw, meta = read(BASE / 'plan.json')
    need(meta['uid'] == meta['gid'] == 0 and meta['mode'] == 0o400 and sha(raw) == digest, 'plan_sha_or_metadata_changed')
    p = json.loads(raw)
    need(canonical(p) == raw and p['machine_id'] == MID and p['runtime'] == RUNTIME and
         p['controller_sha256'] == sha(Path(__file__).read_bytes()) and
         p['buffer_before'] == BUFFER_BEFORE and p['buffer_after'] == BUFFER_AFTER, 'plan_contract_changed')
    need(p['paths'] == [str(CONF)] + [str(RAW / e / 'state.json') for e in ENGINES], 'plan_target_list_changed')
    need(p['before_contract'][str(CONF)] == list(CONF_EXPECTED), 'plan_config_baseline_changed')
    need(all(p['before_contract'][x] == contract(p['before'][x]) for x in p['paths']), 'plan_before_inconsistent')
    for i, path in enumerate(p['paths']):
        old, _ = read(BASE / f'before-{i}'); new, _ = read(BASE / f'after-{i}')
        need(sha(old) == p['before'][path]['sha256'] and sha(new) == p['after'][path][0], 'artifact_changed')
        need(new == (build_config(old) if i == 0 else build_state(old, ENGINES[i - 1], CONF_EXPECTED[0], p['after'][str(CONF)][0])),
             'candidate_semantics_changed')
    return p


def replace(path, expected, raw, uid, gid, mode):
    global ATTEMPTED
    parents(path.parent)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    baseline_parent = directory_identity(os.fstat(parent_fd))
    temporary = '.agent-buffer-' + secrets.token_hex(12)
    created = False
    try:
        need(directory_identity(path.parent.lstat()) == baseline_parent, 'cas_parent_changed')
        _, current = read_relative(path, parent_fd)
        need(current == expected, 'cas_precondition_changed')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        created = True
        with os.fdopen(fd, 'wb') as f:
            f.write(raw); f.flush(); os.fchown(f.fileno(), uid, gid); os.fchmod(f.fileno(), mode); os.fsync(f.fileno())
        parents(path.parent)
        need(directory_identity(path.parent.lstat()) == directory_identity(os.fstat(parent_fd)) == baseline_parent,
             'cas_parent_changed')
        need(read_relative(path, parent_fd)[1] == expected, 'cas_before_rename_changed')
        ATTEMPTED = str(path)
        os.replace(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        created = False
        fsync_dir(path.parent, parent_fd)
        _, after = read_relative(path, parent_fd)
        need(directory_identity(path.parent.lstat()) == directory_identity(os.fstat(parent_fd)) == baseline_parent,
             'cas_parent_changed')
        need((after['sha256'], after['uid'], after['gid'], after['mode']) == (sha(raw), uid, gid, mode), 'cas_readback_failed')
        COMPLETED.append(str(path)); ATTEMPTED = None
        return after
    finally:
        try:
            if created:
                os.unlink(temporary, dir_fd=parent_fd); fsync_dir(path.parent, parent_fd)
        finally:
            os.close(parent_fd)


def effective_barrier(blocked):
    for unit_name, path in zip(UNITS, BARRIERS):
        raw, meta = read(path)
        need(raw == (BLOCKED if blocked else START_ONCE) and
             (meta['uid'], meta['gid'], meta['mode']) == (0, 0, 0o644), 'barrier_file_changed')
        status = unit(unit_name)
        need(status['NeedDaemonReload'] == 'no' and status['Restart'] == 'no' and
             status['ExecStartPre'].count('argv[]=/usr/bin/false') == int(blocked) and
             ('/usr/local/lib/capstone-raw-operations/guard.sh ' + ('vector' if unit_name == UNITS[0] else 'wazuh')) in status['ExecStartPre'],
             'effective_start_barrier_invalid')


def apply(digest):
    global PHASE
    need(APPLY_REVIEWED, 'apply_review_pending')
    p = load_plan(digest); runtime(); snapshot_targets(p['before_contract'])
    need(p['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip() and
         0 <= time.time() - p['created_epoch'] <= 1800, 'plan_stale')
    need(process() == p['logcollector'], 'logcollector_changed')
    for name in UNITS:
        current = unit(name)
        need(active(current) and current['InvocationID'] == p['services'][name]['InvocationID'] and
             current['MainPID'] == p['services'][name]['MainPID'], 'reader_baseline_changed')
    record('apply-intent.json', {'plan_sha256': digest, 'at_kst': now(), 'automatic_retry': False})
    PHASE = 'timer_pause'
    for timer in TIMERS:
        command(['/usr/bin/systemctl', 'disable', '--now', timer], 20)
    for timer in TIMERS:
        s = unit(timer); need(s['UnitFileState'] == 'disabled' and s['ActiveState'] == 'inactive', 'timer_pause_unconfirmed')
    for service in ('capstone-vector-maintenance.service', 'capstone-raw-operations@suricata.service', 'capstone-raw-operations@modsecurity.service'):
        need(unit(service)['ActiveState'] in ('inactive', 'failed'), 'operation_service_active')
    runtime(); snapshot_targets(p['before_contract']); guard()
    stable_vector(p)
    PHASE = 'start_barrier'
    for path in BARRIERS:
        exclusive(path, BLOCKED, 0o644)
    command(['/usr/bin/systemctl', 'daemon-reload']); effective_barrier(True)
    need(process() == p['logcollector'], 'logcollector_changed_before_stop')
    current = unit(UNITS[1])
    need(active(current) and current['InvocationID'] == p['services'][UNITS[1]]['InvocationID'],
         'wazuh_changed_before_stop')
    PHASE = 'stop_armed'
    record('stop-intent.json', {'at_kst': now(), 'plan_sha256': digest, 'process': process(), 'unit': unit(UNITS[1])})
    command(['/usr/bin/systemctl', 'stop', UNITS[1]], 90, 'stop.log')
    s = unit(UNITS[1])
    need(s['ActiveState'] == 'inactive' and s['SubState'] == 'dead' and s['MainPID'] == '0' and
         s['Result'] == 'success' and s['ExecMainStatus'] == '0', 'stop_not_confirmed')
    need(processes() == [], 'logcollector_still_live')
    PHASE = 'stopped_checkpoint_check'
    runtime(); snapshot_targets(p['before_contract']); stable_vector(p); guard()
    record('stopped-proof.json', {'at_kst': now(), 'wazuh': s, 'native_guard_passed': True, 'checkpoint_rewritten': False})
    PHASE = 'three_file_cas'
    effective_barrier(True)
    for i, path_string in enumerate(p['paths']):
        stable_vector(p); effective_barrier(True)
        path = Path(path_string); old, _ = read(BASE / f'before-{i}'); new, _ = read(BASE / f'after-{i}')
        if i:
            state = json.loads(old)
            history = path.parent / 'history' / f"{state['revision']}-{sha(old)}.json"
            if history.exists() or history.is_symlink():
                existing, meta = read(history)
                need(existing == old and (meta['uid'], meta['gid'], meta['mode']) == (0, 0, 0o400), 'history_conflict')
            else:
                exclusive(history, old)
        record(f'cas-{i}-intent.json', {'path': path_string, 'before': p['before'][path_string], 'after_sha256': sha(new)})
        expected = p['before'][path_string]
        after = replace(path, expected, new, expected['uid'], expected['gid'], expected['mode'])
        record(f'cas-{i}-result.json', after)
    snapshot_targets(p['after']); runtime(); guard()
    PHASE = 'start_once'
    # Drop only the false command; Restart=no remains until verified success.
    for path in BARRIERS:
        replace(path, read(path)[1], START_ONCE, 0, 0, 0o644)
    command(['/usr/bin/systemctl', 'daemon-reload']); effective_barrier(False)
    stable_vector(p)
    record('start-intent.json', {'at_kst': now(), 'plan_sha256': digest, 'start_calls_authorized': 1})
    command(['/usr/bin/systemctl', 'start', UNITS[1]], 155, 'start.log')
    # Read-only readiness polling only; the one start command is never retried.
    deadline = time.monotonic() + 30
    while True:
        try:
            result = verify(digest, restoring=True)
            break
        except Refused as error:
            need(str(error) in ('reader_not_active_after_start', 'live_logcollector_count', 'agent_not_connected') and
                 time.monotonic() < deadline, 'poststart_verification_failed_' + str(error))
            time.sleep(.5)
    PHASE = 'restore_unit_policy'
    for path in BARRIERS:
        need(read(path)[0] == START_ONCE, 'restart_policy_file_changed')
        path.unlink(); fsync_dir(path.parent)
    command(['/usr/bin/systemctl', 'daemon-reload'])
    for name in UNITS:
        s = unit(name)
        need(s['NeedDaemonReload'] == 'no' and s['Restart'] == p['services'][name]['Restart'], 'reader_policy_restore_failed')
    PHASE = 'restore_timers'
    for timer in TIMERS:
        command(['/usr/bin/systemctl', 'enable', '--now', timer])
        s = unit(timer); need(s['UnitFileState'] == 'enabled' and s['ActiveState'] == 'active', 'timer_restore_failed')
    result.update(status='applied', observed_at_kst=now(), timers_restored=True,
                  scheduled_execution_verified=False, native_stop_calls=1, native_start_calls=1)
    record('result.json', result)
    return result


def verify(digest, restoring=False):
    p = load_plan(digest); runtime(); snapshot_targets(p['after'])
    intent_raw, intent_meta = read(BASE / 'apply-intent.json')
    intent = json.loads(intent_raw)
    need(canonical(intent) == intent_raw and intent['plan_sha256'] == digest and
         (intent_meta['uid'], intent_meta['gid'], intent_meta['mode']) == (0, 0, 0o400), 'apply_intent_invalid')
    for engine in ENGINES:
        state_check(RAW / engine / 'state.json')
    services = {n: unit(n) for n in UNITS}
    need(all(active(s) for s in services.values()), 'reader_not_active_after_start')
    old = p['services'][UNITS[0]]; new = services[UNITS[0]]
    need((old['MainPID'], old['InvocationID']) == (new['MainPID'], new['InvocationID']), 'vector_changed')
    need(services[UNITS[1]]['InvocationID'] != p['services'][UNITS[1]]['InvocationID'], 'wazuh_new_invocation_missing')
    live = process(); need(live != p['logcollector'], 'wazuh_old_process_retained')
    need(buffer_values(read(CONF)[0]) == BUFFER_AFTER, 'live_buffer_values_unexpected')
    agent_connected()
    guard()
    if not restoring:
        need(all(not x.exists() and not x.is_symlink() for x in BARRIERS), 'temporary_barrier_present')
    return {'schema_version': 1, 'status': 'verified', 'plan_sha256': digest, 'observed_at_kst': now(),
            'buffer': BUFFER_AFTER, 'agent_connected': True,
            'logcollector': live, 'vector_main_pid': services[UNITS[0]]['MainPID'],
            'wazuh_invocation': services[UNITS[1]]['InvocationID'], 'guard_passed': True,
            'checkpoint_rewritten': False, 'raw_modified': False,
            'burst_absorption_verified': False}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('action', choices=('prepare', 'apply', 'verify'))
    ap.add_argument('--plan-sha256')
    args = ap.parse_args()
    need(sys.platform == 'linux' and os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'fixed_A_root_required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    locks = []
    try:
        for path in LOCKS:
            _, meta = read(path)
            need((meta['uid'], meta['gid'], meta['mode']) == (0, 0, 0o600), 'shared_lock_metadata')
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            locks.append(fd); fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            need((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (meta['device'], meta['inode']), 'shared_lock_changed')
        if args.action == 'prepare':
            need(args.plan_sha256 is None, 'prepare_argument_rejected')
            result = prepare()
        else:
            need(bool(re.fullmatch('[0-9a-f]{64}', args.plan_sha256 or '')), 'plan_sha_required')
            result = apply(args.plan_sha256) if args.action == 'apply' else verify(args.plan_sha256)
        print(json.dumps(result, sort_keys=True))
    finally:
        for fd in reversed(locks):
            os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        result = {'status': 'refused', 'reason': str(error) if isinstance(error, Refused) else type(error).__name__,
                  'phase': PHASE, 'attempted_path_outcome_unknown': ATTEMPTED,
                  'completed_changes': COMPLETED, 'automatic_retry': False, 'automatic_rollback': False,
                  'inspect_required': True, 'at_kst': now()}
        try:
            if BASE.exists():
                record('failure-' + str(time.time_ns()) + '.json', result)
        except Exception:
            pass
        print(json.dumps(result, sort_keys=True)); sys.exit(1)
