"""Private, fixed-unit/host journal source; never an MCP or shell executor.

Only masked canonical rows cross the child pipe. Worker parameters are the
existing journal request and its host, not paths, options, patterns or code.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time

core = journal = None
MAX_PACKET = 65536
MAX_JOB = 4096
MAX_HOST_JOURNAL_FILES = 256
MAX_METADATA_PACKET = 1048576
COLLECTION_QUERY_TIMEOUT = 16
ROW_FIELDS = ('_SYSTEMD_UNIT', 'UNIT', 'OBJECT_SYSTEMD_UNIT', 'PRIORITY', 'MESSAGE', '_TRANSPORT')


def key(row):
    return row['at_kst'], row['record_sha256']


def json_field(name, value):
    """systemd255 JSON's field size/Unicode/binary/multivalue representation."""
    if isinstance(value, list):
        return [json_field(name, item) for item in value]
    core.need(isinstance(value, bytes), 'journal_native_field_type')
    if len(name.encode()) + 1 + len(value) >= 4096:
        return None
    try:
        text = value.decode('utf-8')
    except UnicodeError:
        return list(value)
    for char in text:
        n = ord(char)
        if (n < 32 and n not in (9, 10) or 127 <= n <= 159
                or 0xFDD0 <= n <= 0xFDEF or n & 0xFFFF in (0xFFFE, 0xFFFF)):
            return list(value)
    return text


def reader_factory(*, system_only=False, source_fd=None):
    try:
        from systemd import journal as binding
    except ImportError:
        raise core.DiagnosticError('journal_native_dependency_unavailable') from None
    core.need(str(binding.__version__) == '235', 'journal_native_binding_version')
    if source_fd is not None:
        # The private caller obtains this fd from an already-open local/system
        # Reader. No fd or path is accepted in a worker job or MCP arguments.
        core.need(system_only is True and type(source_fd) is int and source_fd >= 3,
                  'journal_partition_source_invalid')
        meta = os.fstat(source_fd)
        path = os.readlink('/proc/self/fd/' + str(source_fd))
        core.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
            and not meta.st_mode & 0o022 and journal_path(path)
            and Path(path).name.startswith('system'), 'journal_partition_source_unsafe')
        # v255 open_files accepts flags=0 only. Selection was already performed
        # by the anchor's LOCAL_ONLY|SYSTEM_ONLY flags; the held fd pins its inode.
        return binding.Reader(flags=0, files=['/proc/self/fd/' + str(source_fd)])
    # Unit reads retain the previous local source. Fixed host aggregates match
    # journalctl --system and exclude per-user journals, without remote merge.
    flags = binding.LOCAL_ONLY | (binding.SYSTEM_ONLY if system_only else 0)
    return binding.Reader(flags=flags)


def journal_path(path):
    return (isinstance(path, str) and path.startswith(('/run/log/journal/', '/var/log/journal/'))
            and path.endswith(('.journal', '.journal~')))


def journal_fds():
    """Current process's journal inode identities, never arbitrary file inputs."""
    result = {}
    for name in os.listdir('/proc/self/fd'):
        if not name.isdigit():
            continue
        fd = int(name)
        try:
            meta = os.fstat(fd)
            path = os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError:
            continue  # The directory enumeration's own short-lived fd.
        except OSError as exc:
            if exc.errno == 9:
                continue
            raise
        if stat.S_ISREG(meta.st_mode) and journal_path(path):
            result[fd] = (meta.st_dev, meta.st_ino)
    return result


def opened_since(before, after):
    return {fd:identity for fd,identity in after.items() if before.get(fd) != identity}


def host_text_group(since, until, limit, priorities, literals, factory):
    """Same fixed filter over every source inode, without repeated multi-file walks.

    Keep an anchor selected by the native API for the entire read. An ambiguous
    embedded caller retains the original bounded reader instead of dropping data.
    Source rotation/vacuum that changes the available inode set fails the query.
    """
    before = journal_fds()
    anchor = factory(system_only=True)
    own_anchor = True
    try:
        sources = opened_since(before, journal_fds())
        if before or not sources:
            own_anchor = False  # read_group owns and closes this reader.
            return read_group(None, since, until, limit, priorities, literals,
                              lambda **unused: anchor)
        core.need(len(sources) <= MAX_HOST_JOURNAL_FILES, 'journal_partition_source_bound')
        rows = {}; seen = {}; limited = False
        for fd,identity in sources.items():
            core.need(journal_fds().get(fd) == identity, 'journal_partition_source_changed')
            def one_source(**unused):
                return factory(system_only=True, source_fd=fd)
            found, hit = read_group(None, since, until, limit, priorities, literals, one_source)
            limited |= hit
            for row in found:
                record = row['record_sha256']
                digest = hashlib.sha256(core.encode(row)).digest()
                core.need(record not in seen or seen[record] == digest, 'journal_cursor_conflict')
                seen[record] = digest
                journal.add_row(rows, row)
            ordered = sorted(rows.values(), key=key, reverse=True)
            limited |= len(ordered) > limit
            rows = {row['record_sha256']: row for row in ordered[:limit + 1]}
        # A new/deleted source cannot silently become a complete-looking sample.
        prior = journal_fds()
        check = factory(system_only=True)
        try:
            current = opened_since(prior, journal_fds())
            core.need(set(current.values()) == set(sources.values()),
                      'journal_partition_generation_changed')
        finally:
            check.close()
        return list(rows.values()), limited
    finally:
        if own_anchor:
            anchor.close()


def unit_matches(reader, unit):
    # Same system-unit expression as systemd255 add_matches_for_unit(). All
    # currently registered journal targets are services, never arbitrary globs.
    core.need(unit in core.TARGETS.values() and unit.endswith('.service'),
              'journal_native_unit_invalid')
    reader.add_match(_SYSTEMD_UNIT=unit)
    reader.add_disjunction()
    reader.add_match(MESSAGE_ID='fc2e22bc6ee647b6b90729ab34a250b1', _UID='0', COREDUMP_UNIT=unit)
    reader.add_disjunction()
    reader.add_match(_PID='1', UNIT=unit)
    reader.add_disjunction()
    reader.add_match(_UID='0', OBJECT_SYSTEMD_UNIT=unit)


def fixed_literals():
    # ERROR_PATTERN is currently a finite union of escaped ASCII literals.
    # Its uppercase characters make journalctl's automatic mode case-sensitive.
    # Refuse a future regex language change instead of narrowing it silently.
    pattern = core.ERROR_PATTERN
    core.need(pattern.isascii() and any('A' <= c <= 'Z' for c in pattern),
              'journal_native_pattern_unsupported')
    result = []
    for term in pattern.split('|'):
        literal = re.sub(r'\\(.)', r'\1', term)
        core.need(bool(literal) and re.escape(literal) == term,
                  'journal_native_pattern_unsupported')
        result.append(literal.encode())
    return tuple(result)


def reverse_stamps(reader, since, until):
    """Shared native cursor walk; supervised callers own time/memory bounds."""
    for name in ('_previous', '_get', '_get_all', '_get_realtime', '_get_cursor'):
        core.need(callable(getattr(reader, name, None)), 'journal_native_binding_api')
    reader.data_threshold = 0
    reader.seek_realtime(until + 1)
    previous = None
    while reader._previous():
        stamp = reader._get_realtime()
        core.need(type(stamp) is int and stamp >= 0, 'journal_native_timestamp')
        core.need(previous is None or stamp <= previous, 'journal_native_source_order')
        previous = stamp
        if stamp > until:
            continue
        if stamp < since:
            break
        yield stamp


def read_group(unit, since, until, limit, priorities, literals, factory):
    reader = factory(system_only=True) if unit is None else factory()
    try:
        # Match against the full MESSAGE, as journalctl --grep does. Memory/time
        # remain confined by the existing service and supervised child process.
        if unit is not None:
            unit_matches(reader, unit)
        if priorities is not None:
            if unit is not None:
                reader.add_conjunction()
            for priority in priorities:
                reader.add_match(PRIORITY=str(priority))
        rows = {}
        for stamp in reverse_stamps(reader, since, until):
            if literals is not None:
                try:
                    message = reader._get('MESSAGE')
                except KeyError:
                    continue  # native grep also skips an absent MESSAGE
                core.need(isinstance(message, bytes), 'journal_native_message_type')
                if not any(literal in message for literal in literals):
                    continue
                if not core.is_error_candidate(message.decode('utf-8', errors='replace'), '6', unit):
                    continue
            raw = reader._get_all()
            core.need(isinstance(raw, dict), 'journal_native_entry_invalid')
            item = {name: json_field(name, raw[name]) for name in ROW_FIELDS if name in raw}
            item['__REALTIME_TIMESTAMP'] = str(stamp)
            cursor = reader._get_cursor()
            if isinstance(cursor, bytes):
                cursor = cursor.decode('utf-8')
            item['__CURSOR'] = cursor
            row = journal.source_row(item, unit, since, until)
            core.need(row is not None, 'journal_native_entry_window')
            journal.add_row(rows, row)
            if len(rows) == limit + 1:
                break
        return list(rows.values()), len(rows) == limit + 1
    finally:
        reader.close()


def collection_request(job, now=None):
    """Private collector protocol, never accepted by the MCP/reader request."""
    core.need(isinstance(job, dict) and set(job) == {'role', 'since_us', 'until_us'},
              'journal_collection_job')
    role, since, until = (job[k] for k in ('role', 'since_us', 'until_us'))
    core.need(isinstance(role, str) and role in core.PROFILES
              and type(since) is type(until) is int and since > 0
              and since % 1000000 == until % 1000000 == 0
              and until - since == core.LOOKBACK * 60 * 1000000,
              'journal_collection_window')
    h = core.history_library(); clock = h.query_clock(now)
    core.need(clock.microseconds - h.RETENTION_DAYS * 86400 * 1000000 <= since
              and until <= clock.microseconds, 'journal_collection_time')
    return role, since, until


def metadata_row(raw, cursor, stamp, units):
    """Reuse the collector's fixed classification and journal JSON semantics."""
    core.need(isinstance(raw, dict), 'journal_collection_entry')
    fields = {name: json_field(name, raw[name]) for name in ROW_FIELDS if name in raw}
    matches = {fields[name] for name in ('_SYSTEMD_UNIT', 'UNIT', 'OBJECT_SYSTEMD_UNIT')
               if isinstance(fields.get(name), str) and fields[name] in units}
    priority = fields.get('PRIORITY')
    core.need(len(matches) == 1 and isinstance(priority, str) and priority in tuple('0123456'),
              'journal_collection_fields')
    if isinstance(cursor, bytes):
        cursor = cursor.decode('utf-8')
    core.need(isinstance(cursor, str) and 1 <= len(cursor) <= 2048, 'journal_collection_cursor')
    unit = matches.pop()
    error = core.classify_message(fields.get('MESSAGE'), unit, priority=int(priority))
    if int(priority) > 3 and error['kind'] == 'journal_error':
        return None
    return {'record_sha256': hashlib.sha256(cursor.encode()).hexdigest(), 'at_us': stamp,
            'unit': unit, 'error': {'at': stamp // 1000000, 'priority': int(priority), **error}}


def collection_worker(job, *, now=None, factory=reader_factory):
    role, since, until = collection_request(job, now)
    units = tuple(core.PROFILES[role].values())
    events = {}; truncated = False
    for priorities in (range(4), range(4, 7)):
        reader = factory()
        try:
            for index, unit in enumerate(units):
                if index:
                    reader.add_disjunction()
                unit_matches(reader, unit)
            reader.add_conjunction()
            for priority in priorities:
                reader.add_match(PRIORITY=str(priority))
            selected = {}
            for stamp in reverse_stamps(reader, since, until):
                if priorities.start == 4:
                    try:
                        message = reader._get('MESSAGE')
                    except KeyError:
                        continue
                    core.need(isinstance(message, bytes), 'journal_native_message_type')
                    if not core.is_error_candidate(message.decode('utf-8', errors='replace'), '6'):
                        continue
                row = metadata_row(reader._get_all(), reader._get_cursor(), stamp, units)
                if row is None:
                    continue
                core.need(row['error']['priority'] in priorities, 'journal_collection_priority')
                identity = row['record_sha256']
                core.need(identity not in events or events[identity] == row,
                          'journal_collection_cursor_conflict')
                events[identity] = selected[identity] = row
                if len(selected) == core.MAX_JOURNAL_ROWS:
                    truncated = True
                    break
        finally:
            reader.close()
    packet = {'schema': 1, **job, 'host': core.ROLE_HOST[role],
              'source_filter_policy': core.ERROR_POLICY_REVISION,
              'events': sorted(events.values(), key=lambda r: (r['at_us'], r['record_sha256']), reverse=True),
              'truncated': truncated}
    core.need(len(core.encode(packet)) <= MAX_METADATA_PACKET, 'journal_collection_packet_bound')
    return packet


def checked_collection_packet(raw, job, now=None):
    role, since, until = collection_request(job, now)
    core.need(len(raw) <= MAX_METADATA_PACKET, 'journal_collection_packet_bound')
    packet = core.parsed(raw)
    core.need(isinstance(packet, dict) and set(packet) == {
        'schema', 'role', 'host', 'since_us', 'until_us', 'source_filter_policy', 'events', 'truncated'}
        and type(packet['schema']) is int and packet['schema'] == 1
        and all(packet[k] == v for k, v in job.items())
        and packet['host'] == core.ROLE_HOST[role]
        and packet['source_filter_policy'] == core.ERROR_POLICY_REVISION
        and type(packet['truncated']) is bool and isinstance(packet['events'], list)
        and len(packet['events']) <= core.MAX_COMBINED_JOURNAL_ROWS,
        'journal_collection_packet')
    seen = set(); groups = [0, 0]
    for row in packet['events']:
        core.need(isinstance(row, dict) and set(row) == {'record_sha256', 'at_us', 'unit', 'error'}
            and isinstance(row['record_sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['record_sha256'])
            and row['record_sha256'] not in seen
            and type(row['at_us']) is int and since <= row['at_us'] <= until
            and isinstance(row['unit'], str) and row['unit'] in core.PROFILES[role].values(),
            'journal_collection_record')
        core.validate_error(row['error'], since // 1000000, until // 1000000)
        core.need(row['error']['at'] == row['at_us'] // 1000000
            and (row['error']['priority'] <= 3 or row['error']['kind'] != 'journal_error'),
            'journal_collection_error')
        groups[int(row['error']['priority'] > 3)] += 1
        seen.add(row['record_sha256'])
    core.need(all(count <= core.MAX_JOURNAL_ROWS for count in groups)
              and (packet['truncated'] or all(count < core.MAX_JOURNAL_ROWS for count in groups)),
              'journal_collection_group_bound')
    core.need(packet['events'] == sorted(packet['events'], key=lambda r: (r['at_us'], r['record_sha256']), reverse=True),
              'journal_collection_order')
    return {'events': packet['events'], 'truncated': packet['truncated']}


def collection_access(job, deadline):
    remaining = deadline - time.monotonic()
    core.need(remaining > 0, 'journal_collection_timeout')
    argv = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json', '--lines=0',
            '--since=@' + str(job['since_us'] // 1000000),
            '--until=@' + str(job['until_us'] // 1000000),
            *('--unit=' + unit for unit in core.PROFILES[job['role']].values())]
    code, raw = core.bounded_command(argv, 4096, min(journal.COMMAND_TIMEOUT, remaining))
    core.need(code == 0 and raw == b'', 'journal_collection_access')


def collect_metadata(role, since, until, now=None):
    core.need(os.getuid() == os.geteuid() == 0, 'journal_collection_root_required')
    job = {'role': role, 'since_us': since, 'until_us': until}
    collection_request(job, now)
    program = Path(__file__); core.root_file(program, 131072)
    deadline = time.monotonic() + COLLECTION_QUERY_TIMEOUT
    collection_access(job, deadline)
    body = core.encode(job); core.need(len(body) <= MAX_JOB, 'journal_native_job_bound')
    remaining = deadline - time.monotonic()
    core.need(remaining > 0, 'journal_collection_timeout')
    code, raw = core.bounded_command(['/usr/bin/python3', '-I', '-B', str(program), '--collector-worker'],
        MAX_METADATA_PACKET, min(journal.COMMAND_TIMEOUT, remaining), input_data=body)
    core.need(code == 0, 'journal_collection_worker_unavailable')
    result = checked_collection_packet(raw, job, now)
    collection_access(job, deadline)
    core.need(time.monotonic() <= deadline, 'journal_collection_timeout')
    return result


def worker(job, *, now=None, factory=reader_factory):
    core.need(isinstance(job, dict) and set(job) == {'value', 'host'}, 'journal_native_job')
    value, host = job['value'], job['host']
    target, since, until, limit, scope = journal.request(value, now)
    core.need(host in core.ROLE_HOST.values() and target[0] == host, 'journal_host_mismatch')
    core.need(until - since <= journal.QUERY_WINDOW_US, 'journal_native_slice_window')
    unit = core.TARGETS[target]
    groups = [(range(4), None), (range(4, 7), fixed_literals())] if scope == 'errors' else [(None, None)]
    rows = {}; limited = False
    for priorities, literals in groups:
        if unit is None and literals is not None:
            found, hit = host_text_group(since, until, limit, priorities, literals, factory)
        else:
            found, hit = read_group(unit, since, until, limit, priorities, literals, factory)
        limited |= hit
        for row in found:
            journal.add_row(rows, row)
    entries = sorted(rows.values(), key=key, reverse=True)
    packet = {'schema': 1, 'target': target, 'host': host,
        'since_kst': value['since_kst'], 'until_kst': value['until_kst'], 'scope': scope,
        'entries': entries, 'source_limited': limited, 'size_limited': False, 'cutoff': None}
    while len(core.encode(packet)) > MAX_PACKET and packet['entries']:
        removed = packet['entries'].pop()
        packet.update(source_limited=True, size_limited=True,
                      cutoff={'at_kst': removed['at_kst'], 'record_sha256': removed['record_sha256']})
    core.need(not packet['size_limited'] or bool(packet['entries']), 'journal_native_entry_bound')
    core.need(len(core.encode(packet)) <= MAX_PACKET, 'journal_native_packet_bound')
    return packet


def checked_packet(raw, value, host, now):
    core.need(len(raw) <= MAX_PACKET, 'journal_native_packet_bound')
    packet = core.parsed(raw)
    target, since, until, limit, scope = journal.request(value, now)
    core.need(isinstance(packet, dict) and set(packet) == {
        'schema', 'target', 'host', 'since_kst', 'until_kst', 'scope', 'entries',
        'source_limited', 'size_limited', 'cutoff'} and type(packet['schema']) is int
        and packet['schema'] == 1 and packet['target'] == target and packet['host'] == host
        and packet['since_kst'] == value['since_kst'] and packet['until_kst'] == value['until_kst']
        and packet['scope'] == scope and type(packet['source_limited']) is bool
        and type(packet['size_limited']) is bool, 'journal_native_packet_invalid')
    maximum = (2 if scope == 'errors' else 1) * (limit + 1)
    journal.validate_entries(packet['entries'], since, until, maximum,
                             host_journal=core.TARGETS[target] is None)
    core.need(packet['entries'] == sorted(packet['entries'], key=key, reverse=True),
              'journal_native_packet_order')
    h = core.history_library()
    for row in packet['entries']:
        core.need(h.shown(h.instant(row['at_kst'])) == row['at_kst'], 'journal_native_time_encoding')
    cutoff = packet['cutoff']
    if packet['size_limited']:
        core.need(packet['source_limited'] and packet['entries'] and isinstance(cutoff, dict)
            and set(cutoff) == {'at_kst', 'record_sha256'}
            and isinstance(cutoff['record_sha256'], str)
            and re.fullmatch('[0-9a-f]{64}', cutoff['record_sha256'])
            and since <= h.instant(cutoff['at_kst']) <= until
            and h.shown(h.instant(cutoff['at_kst'])) == cutoff['at_kst']
            and key(packet['entries'][-1]) > key(cutoff), 'journal_native_cutoff')
    else:
        core.need(cutoff is None, 'journal_native_cutoff')
    return packet


def access_check(value, unit, deadline):
    h = core.history_library()
    start, end = h.instant(value['since_kst']), h.instant(value['until_kst'])
    remaining = deadline - time.monotonic()
    core.need(remaining > 0, 'journal_query_timeout')
    args = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json', '--lines=0',
        '--since=@' + f'{start // 1000000}.{start % 1000000:06d}',
        '--until=@' + f'{end // 1000000}.{end % 1000000:06d}']
    args += ['--system'] if unit is None else ['--unit=' + unit]
    code, raw = core.bounded_command(args, 4096, min(journal.COMMAND_TIMEOUT, remaining))
    core.need(code == 0 and raw == b'', 'journal_native_access_check')


def answer(value, host, now):
    target, since, until, limit, scope = journal.request(value, now)
    core.need(host in core.ROLE_HOST.values() and target[0] == host, 'journal_host_mismatch')
    program = Path(__file__)
    core.root_file(program, 131072)
    deadline = time.monotonic() + journal.QUERY_TIMEOUT
    access_check(value, core.TARGETS[target], deadline)
    h = core.history_library(); jobs = []
    high = until
    while high > since:
        low = max(since, high - journal.QUERY_WINDOW_US)
        jobs.append(dict(value, since_kst=h.shown(low), until_kst=h.shown(high)))
        high = low
    executor = ThreadPoolExecutor(max_workers=2)
    tasks = {}; events = {}; rows = {}; packets = {}; limited = sized = False; cutoff = None

    def invoke(index):
        remaining = deadline - time.monotonic()
        core.need(remaining > 0, 'journal_query_timeout')
        body = core.encode({'value': jobs[index], 'host': host})
        core.need(len(body) <= MAX_JOB, 'journal_native_job_bound')
        code, raw = core.bounded_command(['/usr/bin/python3', '-I', '-B', str(program), '--worker'],
            MAX_PACKET, min(journal.COMMAND_TIMEOUT, remaining), input_data=body,
            cancel=events[index].is_set)
        core.need(code == 0, 'journal_native_worker_unavailable')
        return raw

    def submit(index):
        if index < len(jobs):
            events[index] = threading.Event()
            tasks[index] = executor.submit(invoke, index)

    try:
        submit(0); submit(1)
        for index, job in enumerate(jobs):
            remaining = deadline - time.monotonic()
            core.need(remaining > 0, 'journal_query_timeout')
            raw = tasks[index].result(timeout=remaining)
            packets[index] = raw
            # Even all four prefetched packets fit the former all-priority
            # 1MiB request budget; errors previously allowed 2MiB.
            core.need(sum(map(len, packets.values())) <= 1048576 * (2 if scope == 'errors' else 1),
                      'journal_output_total_bound')
            packet = checked_packet(raw, job, host, now)
            limited |= packet['source_limited']; sized |= packet['size_limited']
            for row in packet['entries']:
                journal.add_row(rows, row)
            if packet['cutoff'] is not None:
                cutoff = max((c for c in (cutoff, packet['cutoff']) if c is not None), key=key)
            if cutoff is not None:
                rows = {identity: row for identity, row in rows.items() if key(row) > key(cutoff)}
            ordered = sorted(rows.values(), key=key, reverse=True)
            if (cutoff is not None or len(ordered) > limit
                    and ordered[limit - 1]['at_kst'] > job['since_kst']):
                limited = True
                break
            submit(index + 2)
    finally:
        for event in events.values():
            event.set()
        for task in tasks.values():
            task.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
    access_check(value, core.TARGETS[target], deadline)
    core.need(time.monotonic() <= deadline, 'journal_query_timeout')
    return journal.finish(value, host, now, list(rows.values()), limited, sized)


def main():
    # No environment/argument can select another source tree. A root-owned
    # trusted staging copy is usable for isolated operator validation too.
    if os.getuid() != 0 or os.geteuid() != 0 or sys.argv[1:] not in (['--worker'], ['--collector-worker']):
        raise SystemExit(1)
    directory = Path(__file__).absolute().parent
    for path in (directory, *directory.parents):
        meta = path.lstat()
        if not path.is_dir() or path.is_symlink() or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise SystemExit(1)
    for name in ('system_diagnostics.py', 'diagnostic_journal.py',
                 'diagnostic_history.py', 'diagnostic_journal_native.py'):
        path = directory / name
        meta = path.lstat()
        if (path.is_symlink() or not path.is_file() or meta.st_uid != 0
                or meta.st_nlink != 1 or meta.st_mode & 0o022 or meta.st_size > 131072):
            raise SystemExit(1)
    sys.path.insert(0, str(directory))
    import system_diagnostics as system
    global core, journal
    core = system
    core.root_file(Path(__file__), 131072)
    journal = core.journal_library()
    raw = sys.stdin.buffer.read(MAX_JOB + 1)
    core.need(len(raw) <= MAX_JOB, 'journal_native_job_bound')
    packet = (collection_worker if sys.argv[1] == '--collector-worker' else worker)(core.parsed(raw))
    sys.stdout.buffer.write(core.encode(packet))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never print a journal message, traceback, supplied value or secret.
        sys.stderr.write('journal_native_worker_failed\n')
        raise SystemExit(1)
