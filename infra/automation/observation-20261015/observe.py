#!/usr/bin/env python3
"""Fixed-host, one-off observations. No live SQLite connection or application calls."""
import argparse
import collections
import contextlib
import datetime as dt
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import sqlite3
import stat
import subprocess
import tempfile
import time

KST = dt.timezone(dt.timedelta(hours=9))
MIDS = {'a': '096e90b6243e438aa8a7b392be754732', 'b': '1e143067c98a44ffba6eaa925dc038d7'}
CIDS = {'a': '6c72d5a5b8229fc3b6e010c9d046d97ac5c13437cae045c72a330fe0d6d82f81',
        'b': '6c2ed13aea89404463061ea2032084bdd159ae784aff4e7bd9eea7406ba9b30b'}
AUDIT_ROOT = Path('/home/groot_a/capstone/secstack/logs/modsec')
HERMES_ROOT = Path('/opt/hermes-data')
SCRATCH = Path('/var/tmp/capstone-tools-followup-20261015/observation')
EXCEPTION = '/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf'
EXCEPTION_SHA = 'd95e75f39d082053543b04de10d538154da4ce8b25e9333014b3b2d858b65f8d'
GUARD_SOURCES = {
    '/opt/hermes/capstone_korean_output_guard.py': 'a6b977d2c670ded98f61639a480702ed06d4a866b705e7d10705a056b974895c',
    '/opt/hermes/plugins/platforms/mattermost/adapter.py': '1bbe71e24cf7fd212f38b13cb421bb5b05c841ea4d70a061d6dcb57253e6c47b',
    '/opt/hermes/gateway/run_turn.py': 'd4dae0f3194f7b7d435aac2eb37d4697822612cd6955911d86bb61400ad2871a',
}
OBSERVER = Path('/opt/capstone-automation/hermes-guard/guard-metadata.awk')
OBSERVER_SHA = '6865d2f3b259959b19f3f19acf5eb38f721aa2ef0252a6cd85fbfc35d15d2d08'
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_ROWS = 50000
TARGET = '211.170.162.9'


class Refused(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def kst(epoch):
    return dt.datetime.fromtimestamp(epoch, KST).isoformat(timespec='microseconds')


def meta(s):
    return {k: getattr(s, 'st_' + k) for k in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def parents(path):
    for p in reversed(Path(path).parents):
        need(stat.S_ISDIR(p.lstat().st_mode), 'parent_symlink_or_not_directory')


def read_file(path, limit=MAX_FILE, *, check_parents=True):
    """Exact stable whole-file read; no symlinks/FIFO, atime may advance."""
    path = Path(path)
    if check_parents:
        parents(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_size <= limit, 'file_type_or_bound')
    parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = nxt
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        need(meta(os.fstat(fd)) == meta(before), 'file_open_changed')
        chunks, left = [], before.st_size
        while left:
            data = os.read(fd, min(left, 1024 * 1024))
            need(data, 'file_short_read')
            chunks.append(data)
            left -= len(data)
        raw = b''.join(chunks)
        need(meta(os.fstat(fd)) == meta(before) == meta(path.lstat()), 'file_changed')
        return raw, dict(meta(before), sha256=sha(raw))
    finally:
        os.close(fd)


def command(argv, *, limit=65536, seconds=15):
    """Fixed caller commands, capped stdout; stderr never leaves the server."""
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, start_new_session=True,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'TZ': 'Asia/Seoul'})
    result = bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(proc.stdout, selectors.EVENT_READ)
            until = time.monotonic() + seconds
            while True:
                need(time.monotonic() < until, 'command_timeout')
                ready = sel.select(min(0.2, max(0, until - time.monotonic())))
                if not ready:
                    continue
                chunk = os.read(proc.stdout.fileno(), min(65536, limit + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                need(len(result) <= limit, 'command_output_bound')
        try:
            rc = proc.wait(timeout=max(0.1, until-time.monotonic()))
        except subprocess.TimeoutExpired:
            raise Refused('command_timeout') from None
        need(rc == 0, 'command_failed')
        return bytes(result)
    finally:
        # No PID-name matching or unrelated process signals. These fixed commands
        # do not daemonize. On errors the unreaped direct process owns its group.
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        proc.stdout.close()


def container(host):
    fmt = ('{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},'
           '"started_at":{{json .State.StartedAt}},"running":{{json .State.Running}}}')
    value = json.loads(command(['/usr/local/bin/docker', 'inspect', '--format', fmt, CIDS[host]]))
    need(value['id'] == CIDS[host] and value['running'] is True and type(value['pid']) is int and value['pid'] > 1,
         'container_identity_or_state')
    raw = Path('/proc/' + str(value['pid']) + '/stat').read_text()
    value['start_ticks'] = raw.rsplit(')', 1)[1].split()[19]
    return value


def fixed_source_alias(root_fd, path):
    """The one observed WAF image alias; other paths keep nofollow traversal."""
    if path != EXCEPTION:
        return path, None
    fd = os.dup(root_fd)
    try:
        for part in ('etc', 'modsecurity.d'):
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        before = os.stat('owasp-crs', dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISLNK(before.st_mode), 'waf_alias_type_changed')
        need(os.readlink('owasp-crs', dir_fd=fd) == '/opt/owasp-crs', 'waf_alias_target_changed')
        need(meta(before) == meta(os.stat('owasp-crs', dir_fd=fd, follow_symlinks=False)), 'waf_alias_changed')
        return '/opt/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf', meta(before)
    finally:
        os.close(fd)


def container_sources(identity, paths):
    result = {}
    root = Path('/proc') / str(identity['pid']) / 'root'
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        # /proc/PID/root is the one intentional magic link. Each path below it
        # is traversed relative to the pinned root with O_NOFOLLOW.
        for path, expected in paths.items():
            actual_path, alias_before = fixed_source_alias(root_fd, path)
            fd = os.dup(root_fd)
            try:
                parts = actual_path.lstrip('/').split('/')
                for part in parts[:-1]:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = nxt
                leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    before = os.fstat(leaf)
                    need(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE, 'source_bound')
                    raw = b''
                    while len(raw) < before.st_size:
                        block = os.read(leaf, min(1024*1024, before.st_size-len(raw)))
                        need(block, 'source_short_read')
                        raw += block
                    need(meta(before) == meta(os.fstat(leaf)) == meta(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)),
                         'source_changed')
                    result[path] = {'sha256': sha(raw), 'expected_match': sha(raw) == expected,
                                    'uid': before.st_uid, 'gid': before.st_gid, 'mode': oct(stat.S_IMODE(before.st_mode))}
                    need(fixed_source_alias(root_fd, path) == (actual_path, alias_before), 'waf_alias_changed')
                finally:
                    os.close(leaf)
            finally:
                os.close(fd)
    finally:
        os.close(root_fd)
    return result


def windows(cutoff):
    return {label: {'start_epoch': cutoff - hours*3600, 'end_epoch': cutoff,
                    'start_kst': kst(cutoff-hours*3600), 'end_kst': kst(cutoff)}
            for label, hours in (('recent5h', 5), ('recent24h', 24))}


class Pairs(list):
    pass


def obj(value):
    need(isinstance(value, Pairs), 'json_object_expected')
    keys = [k for k, _ in value]
    need(len(keys) == len(set(keys)), 'duplicate_structure_key')
    return dict(value)


def explicit_epoch(stamp):
    need(isinstance(stamp, str), 'timestamp_invalid')
    parsed = dt.datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    need(parsed.tzinfo is not None, 'timestamp_without_offset')
    return parsed.timestamp()


def audit_meta(raw):
    # Preserve duplicate header names; duplicate structure keys are refused.
    top = obj(json.loads(raw, object_pairs_hook=Pairs))
    tx = obj(top['transaction'])
    req = obj(tx['request'])
    headers = req.get('headers', Pairs())
    need(isinstance(headers, Pairs), 'headers_shape')
    hosts = [v for k, v in headers if k.lower() == 'host']
    framing = any(k.lower() in ('content-length', 'transfer-encoding') for k, _ in headers)
    protocol = str(req.get('http_version', ''))
    if not protocol.startswith('HTTP/'):
        protocol = 'HTTP/' + protocol
    shape = None
    if (tx.get('client_ip') == TARGET and tx.get('host_ip') == '172.18.0.2' and
            tx.get('host_port') == 8080 and req.get('method') == 'GET' and req.get('uri') == '/' and not framing):
        if protocol == 'HTTP/1.0' and not hosts:
            shape = '10020_audit_shape'
        if protocol == 'HTTP/1.1' and hosts == ['192.168.16.230']:
            shape = '10021_audit_shape'
    rules = []
    for message in tx.get('messages', []):
        details = obj(obj(message)['details'])
        rid = details.get('ruleId')
        need(isinstance(rid, str) and re.fullmatch(r'[0-9]{1,10}', rid), 'rule_id_invalid')
        rules.append(rid)
    epoch, basis = None, 'no_verified_offset'
    uid = tx.get('unique_id', '')
    match = re.fullmatch(r'v2:([0-9a-f]{64}):([0-9a-f]{32}):([0-9]{10,12}\.[0-9]{3}):(.+)', uid)
    if match:
        epoch = float(match[3])
        iso = dt.datetime.fromisoformat(match[4])
        need(iso.tzinfo is not None and 0 <= epoch-iso.timestamp() < 1, 'audit_v2_clock_mismatch')
        naive = dt.datetime.strptime(tx['time_stamp'], '%a %b %d %H:%M:%S %Y').replace(tzinfo=iso.tzinfo)
        need(abs(naive.timestamp()-epoch) <= 2, 'audit_v2_naive_clock_mismatch')
        basis = 'embedded_v2_context'
    return {'epoch': epoch, 'basis': basis, 'target': tx.get('client_ip') == TARGET,
            'shape': shape, 'rules': sorted(set(rules)), 'messages': len(rules)}


def access_meta(raw):
    value = obj(json.loads(raw, object_pairs_hook=Pairs))
    keys = {'capstone_waf_access_version', 'deployment_binding', 'request_id', 'time_iso8601',
            'msec', 'request_time', 'source_ip', 'destination_ip', 'source_port',
            'destination_port', 'http_method', 'http_status'}
    need(set(value) == keys and all(type(v) is str for v in value.values()), 'access_field_shape')
    need(value['capstone_waf_access_version'] in ('1', '2'), 'access_version')
    need(re.fullmatch(r'[0-9a-f]{32}', value['request_id']) and
         re.fullmatch(r'[0-9a-f]{64}', value['deployment_binding']), 'access_identity_format')
    need(re.fullmatch(r'[0-9]{10,12}\.[0-9]{3}', value['msec']) and
         re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}', value['time_iso8601']),
         'access_clock_format')
    epoch_ms = int(value['msec'].replace('.', ''))
    iso_ms = int(explicit_epoch(value['time_iso8601'])) * 1000
    need(0 <= epoch_ms-iso_ms < 1000, 'access_clock_mismatch')
    return {'epoch': epoch_ms/1000, 'target': value['source_ip'] == TARGET,
            'version': value['capstone_waf_access_version']}


def imperva(cutoff):
    identity = container('a')
    source_before = container_sources(identity, {EXCEPTION: EXCEPTION_SHA})
    host_raw, host_meta = read_file('/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf')
    need(sha(host_raw) == EXCEPTION_SHA and source_before[EXCEPTION]['expected_match'], 'exception_source_changed')
    ws = windows(cutoff)
    for w in ws.values():
        w.update(access_requests=0, target_access_requests=0, target_timed_audits=0,
                 target_rule_counts={}, target_audit_shape_counts={})
    inventory, seen, records, total, errors = [], set(), 0, 0, collections.Counter()
    target_untimed = 0
    files = []
    for p in AUDIT_ROOT.iterdir():
        if re.fullmatch(r'(audit\.log|capstone-access\.log)(\.[0-9]+(\.gz)?)?', p.name):
            files.append(p)
    managed = AUDIT_ROOT/'capstone-managed'
    need(stat.S_ISDIR(managed.lstat().st_mode), 'managed_directory_invalid')
    files += [p for p in managed.iterdir() if re.fullmatch(r'generation-[0-9]{4,20}\.jsonl', p.name)]
    need(len(files) <= 256, 'source_file_count_bound')
    for path in sorted(files):
        s = path.lstat()
        identity_key = (s.st_dev, s.st_ino)
        if identity_key in seen:
            continue
        seen.add(identity_key)
        try:
            raw, metadata = read_file(path)
            if path.suffix == '.gz':
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                    decoded = stream.read(MAX_FILE+1)
            else:
                decoded = raw
            need(len(decoded) <= MAX_FILE and total+len(decoded) <= MAX_TOTAL, 'decoded_byte_bound')
            total += len(decoded)
            lines = decoded.splitlines()
            need(records+len(lines) <= MAX_ROWS, 'record_count_bound')
            records += len(lines)
            entry = {'path': str(path), 'metadata': metadata, 'decoded_bytes': len(decoded), 'records': len(lines)}
            inventory.append(entry)
            if decoded and not decoded.endswith(b'\n'):
                errors['incomplete_last_line'] += 1
                lines = lines[:-1]
            for line in lines:
                try:
                    is_access = path.name.startswith('capstone-access.log')
                    row = access_meta(line) if is_access else audit_meta(line)
                    if row['epoch'] is None:
                        target_untimed += int(row['target'])
                        continue
                    for w in ws.values():
                        if not w['start_epoch'] <= row['epoch'] <= cutoff:
                            continue
                        if is_access:
                            w['access_requests'] += 1
                            w['target_access_requests'] += int(row['target'])
                        elif row['target']:
                            w['target_timed_audits'] += 1
                            for rid in row['rules']:
                                w['target_rule_counts'][rid] = w['target_rule_counts'].get(rid, 0)+1
                            if row['shape']:
                                key = row['shape']
                                w['target_audit_shape_counts'][key] = w['target_audit_shape_counts'].get(key, 0)+1
                except (Refused, ValueError, TypeError, KeyError, AttributeError):
                    errors['invalid_record'] += 1
        except (Refused, OSError, EOFError):
            errors['unreadable_changed_or_bounded_file'] += 1
    need(container('a') == identity, 'container_changed')
    need(container_sources(identity, {EXCEPTION: EXCEPTION_SHA}) == source_before, 'exception_source_changed')
    need(read_file('/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf')[1] == host_meta, 'host_exception_changed')
    return {'kind': 'imperva_retained_source_observation', 'container': identity, 'exception_sources': source_before,
            'windows': ws, 'source_inventory': inventory, 'hardlink_aliases_deduplicated': len(files)-len(seen),
            'target_audits_without_verified_offset': target_untimed, 'errors': dict(errors),
            'status': 'observed_subset' if not errors else 'partial_observation',
            'coverage_complete': False, 'source_records': records, 'decoded_bytes': total,
            'limits': ['Only bounded retained files; retention/copytruncate gaps are not disproved.',
                       'RelevantOnly may omit requests. Zero audit/alerts is not exception-effectiveness proof.',
                       'No offset is inferred for legacy audit time; these rows are outside timed counts.',
                       'Audit URI shape is not independent proof of REQUEST_URI_RAW. Minimal access lacks headers/URI.',
                       'Natural traffic provenance cannot be proved solely from an IP address. No requests were generated.']}


def quantile(values, q):
    if not values:
        return None
    values = sorted(values)
    at = (len(values)-1)*q
    low = math.floor(at)
    high = math.ceil(at)
    return round(values[low]+(values[high]-values[low])*(at-low), 6)


def stored_intervals(rows):
    """IDs stay in memory; only final aggregate intervals leave this function."""
    by_session = collections.defaultdict(list)
    for sid, role, stamp, has_tool_calls in rows:
        if type(stamp) not in (int, float) or not math.isfinite(stamp):
            continue
        by_session[sid].append((stamp, role, has_tool_calls))
    samples = []
    ambiguous = 0
    for messages in by_session.values():
        start, final, assistant_count = None, None, 0
        for stamp, role, has_tools in sorted(messages, key=lambda item: item[0]):
            if role == 'user':
                if start is not None and final is not None:
                    samples.append((final, final-start))
                    ambiguous += int(assistant_count > 1)
                start, final, assistant_count = stamp, None, 0
            elif role == 'assistant' and not has_tools and start is not None and stamp >= start:
                final = stamp
                assistant_count += 1
        if start is not None and final is not None:
            samples.append((final, final-start))
            ambiguous += int(assistant_count > 1)
    return sorted(samples), ambiguous


def db_metrics(db, cutoff):
    wanted = {'messages': {'id', 'session_id', 'role', 'timestamp', 'tool_calls', 'active'},
              'sessions': {'id', 'source'}, 'delivery_obligations': {'platform', 'state', 'created_at'}}
    for table, keys in wanted.items():
        actual = {row[1] for row in db.execute('PRAGMA table_info(' + table + ')')}
        need(keys <= actual, 'database_schema_changed')
    # No message text, user/chat/session IDs, models, tokens or tool arguments
    # are projected. Session IDs are temporary in-memory grouping keys only.
    rows = db.execute("SELECT m.session_id,m.role,m.timestamp,CASE WHEN m.tool_calls IS NOT NULL AND m.tool_calls NOT IN ('','[]','null') THEN 1 ELSE 0 END FROM messages m JOIN sessions s ON s.id=m.session_id WHERE s.source='mattermost' AND m.active=1 AND m.timestamp>=? AND m.timestamp<=? ORDER BY m.timestamp,m.id LIMIT ?",
                      (cutoff-86400, cutoff, MAX_ROWS+1)).fetchall()
    need(len(rows) <= MAX_ROWS, 'database_row_bound')
    samples, ambiguous = stored_intervals(rows)
    result = windows(cutoff)
    for w in result.values():
        selected = [r for r in rows if w['start_epoch'] <= r[2] <= cutoff]
        values = [x for x in samples if w['start_epoch'] <= x[0] <= cutoff]
        w['stored_roles'] = {key: sum(r[1] == key for r in selected) for key in ('user', 'assistant', 'tool')}
        w['delivery_obligation_states'] = {}
        for state_value, count in db.execute("SELECT state,count(*) FROM delivery_obligations WHERE platform='mattermost' AND created_at>=? AND created_at<=? GROUP BY state", (w['start_epoch'], cutoff)):
            key = state_value if state_value in ('pending', 'delivered', 'failed', 'sending', 'cancelled', 'completed') else 'other'
            w['delivery_obligation_states'][key] = w['delivery_obligation_states'].get(key, 0)+count
        w['stored_interval_proxy'] = {'samples': len(values), 'p50_seconds': quantile([x[1] for x in values], .5),
                                     'p95_seconds': quantile([x[1] for x in values], .95),
                                     'recent3_seconds': [round(x[1], 6) for x in values[-3:]],
                                     'basis': 'user_row_to_last_non_tool_assistant_row_before_next_user',
                                     'actual_delivery_or_approval_latency': False}
    return {'windows': result, 'rows_examined': len(rows), 'intervals_with_multiple_candidate_assistants': ambiguous,
            'content_queried': False, 'all_response_denominator_available': False}


def private_database(cutoff):
    parents(SCRATCH/'placeholder')
    st = SCRATCH.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700, 'private_scratch_required')
    before, originals = {}, {}
    for name in ('state.db', 'state.db-wal', 'state.db-shm'):
        path = HERMES_ROOT/name
        if not path.exists() and not path.is_symlink():
            before[name] = None
        else:
            originals[name], before[name] = read_file(path, 128*1024*1024)
    need('state.db' in originals and sum(len(x) for x in originals.values()) <= 128*1024*1024, 'database_snapshot_bound')
    with tempfile.TemporaryDirectory(prefix='private-db-', dir=SCRATCH) as temporary:
        private = Path(temporary)
        for name in ('state.db', 'state.db-wal'):
            if name in originals:
                with (private/name).open('xb') as stream:
                    stream.write(originals[name])
                (private/name).chmod(0o600)
        with contextlib.closing(sqlite3.connect(f'file:{private}/state.db?mode=ro', uri=True, timeout=3)) as db:
            deadline = time.monotonic()+15
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            need(db.execute('PRAGMA quick_check').fetchone() == ('ok',), 'private_database_quick_check_failed')
            result = db_metrics(db, cutoff)
        for name, expected in before.items():
            path = HERMES_ROOT/name
            if expected is None:
                need(not path.exists() and not path.is_symlink(), 'database_snapshot_changed')
            else:
                need(read_file(path, 128*1024*1024)[1] == expected, 'database_snapshot_changed')
    return dict(result, database_quick_check='ok', original_files=before, original_files_unchanged=True,
                private_copy_removed=True, original_sqlite_connections=0)


def guard_counts(raw, cutoff):
    ws = windows(cutoff)
    for w in ws.values():
        w['verdict_counts'] = {x: 0 for x in ('oversize', 'requested_foreign', 'retained', 'filtered')}
    lines = raw.splitlines()
    need(len(lines) <= 20000, 'journal_row_bound')
    ignored = 0
    for line in lines:
        value = json.loads(line)
        stamp = int(value['__REALTIME_TIMESTAMP'])/1000000
        message = value.get('MESSAGE')
        match = re.fullmatch(r'korean_output_guard verdict=(oversize|requested_foreign|retained|filtered) chars=([0-9]{1,10})', message or '') if isinstance(message, str) else None
        if not match:
            ignored += 1
            continue
        for w in ws.values():
            if w['start_epoch'] <= stamp <= cutoff:
                w['verdict_counts'][match[1]] += 1
    return {'windows': ws, 'other_tag_records_ignored': ignored, 'journal_records': len(lines),
            'all_response_denominator_available': False, 'correction_failures_separately_observable': False,
            'fallback_notices_separately_observable': False}


def hermes(cutoff):
    identity = container('b')
    sources = container_sources(identity, GUARD_SOURCES)
    observer, observer_meta = read_file(OBSERVER)
    need(all(v['expected_match'] for v in sources.values()) and sha(observer) == OBSERVER_SHA, 'guard_source_changed')
    result = {'kind': 'hermes_production_metadata_observation', 'container': identity, 'guard_sources': sources,
              'observer_source_sha256': sha(observer)}
    for name, action in (
        ('guard_journal', lambda: guard_counts(command(['/usr/bin/journalctl', '--identifier=capstone-hermes-guard',
            '--since=@'+str(int(cutoff-86400)), '--until=@'+str(int(cutoff)), '--output=json',
            '--output-fields=__REALTIME_TIMESTAMP,MESSAGE', '--no-pager', '--quiet', '-n', '20001'],
            limit=16*1024*1024, seconds=20), cutoff)),
        ('stored_metadata', lambda: private_database(cutoff))):
        try:
            result[name] = dict(action(), status='observed_subset')
        except (Refused, OSError, ValueError, sqlite3.Error) as exc:
            result[name] = {'status': 'unavailable', 'reason': str(exc) if isinstance(exc, Refused) else 'read_or_schema_failure'}
    units = {}
    for unit in ('capstone-hermes-guard-observe.service', 'capstone-hermes-guard-reapply.service', 'capstone-hermes-guard-reapply.timer'):
        props = command(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState,SubState,Result,ActiveEnterTimestampMonotonic'], limit=4096)
        units[unit] = dict(line.split('=', 1) for line in props.decode().splitlines() if '=' in line)
    result['units'] = units
    need(container('b') == identity and container_sources(identity, GUARD_SOURCES) == sources, 'container_or_guard_changed')
    need(read_file(OBSERVER)[1] == observer_meta, 'observer_source_changed')
    result['limits'] = ['Observer reports only guarded cases; zero filtered is not a full-response language contamination rate.',
                        'filtered combines correction and fallback; no transcript or fallback text is read.',
                        'retained/requested_foreign may be legitimate quoted or explicitly requested text.',
                        'Stored timestamp intervals are not measured send latency, model latency or approval duration.',
                        'Retained DB/journal may omit earlier/deleted data; no complete denominator or window coverage is claimed.']
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', choices=['a', 'b'])
    args = parser.parse_args()
    os.umask(0o077)
    need(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MIDS[args.host], 'fixed_host_root_required')
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Refused('overall_timeout')))
    signal.alarm(90)
    cutoff = time.time()
    result = imperva(cutoff) if args.host == 'a' else hermes(cutoff)
    result.update(schema_version=1, cutoff_epoch=cutoff, cutoff_kst=kst(cutoff),
                  operational_changes=False, generated_requests=0, chat_messages_sent=0,
                  model_calls=0, security_or_chat_raw_exported=False)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'unavailable', 'reason': str(exc) if isinstance(exc, Refused) else 'read_or_schema_failure',
                          'security_or_chat_raw_exported': False}, separators=(',', ':')))
        raise SystemExit(2)
