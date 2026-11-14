"""Private, fixed-unit native journal source; never an MCP or shell executor.

Only masked canonical rows cross the child pipe. Worker parameters are the
existing journal request and its host, not paths, options, patterns or code.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

core = journal = None
MAX_PACKET = 65536
MAX_JOB = 4096
ROW_FIELDS = ('_SYSTEMD_UNIT', 'UNIT', 'OBJECT_SYSTEMD_UNIT', 'PRIORITY', 'MESSAGE')


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


def reader_factory():
    try:
        from systemd import journal as binding
    except ImportError:
        raise core.DiagnosticError('journal_native_dependency_unavailable') from None
    core.need(str(binding.__version__) == '235', 'journal_native_binding_version')
    # LOCAL_ONLY matches journalctl without --merge, not SYSTEM_ONLY.
    return binding.Reader(flags=binding.LOCAL_ONLY)


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


def read_group(unit, since, until, limit, priorities, literals, factory):
    reader = factory()
    try:
        for name in ('_previous', '_get', '_get_all', '_get_realtime', '_get_cursor'):
            core.need(callable(getattr(reader, name, None)), 'journal_native_binding_api')
        # Match against the full MESSAGE, as journalctl --grep does. Memory/time
        # remain confined by the existing service and supervised child process.
        reader.data_threshold = 0
        unit_matches(reader, unit)
        if priorities is not None:
            reader.add_conjunction()
            for priority in priorities:
                reader.add_match(PRIORITY=str(priority))
        reader.seek_realtime(until + 1)  # integer microseconds, no float conversion
        rows = {}; previous = None
        while reader._previous():
            stamp = reader._get_realtime()
            core.need(type(stamp) is int and stamp >= 0, 'journal_native_timestamp')
            core.need(previous is None or stamp <= previous, 'journal_native_source_order')
            previous = stamp
            if stamp > until:
                continue
            if stamp < since:
                break
            if literals is not None:
                try:
                    message = reader._get('MESSAGE')
                except KeyError:
                    continue  # native grep also skips an absent MESSAGE
                core.need(isinstance(message, bytes), 'journal_native_message_type')
                if not any(literal in message for literal in literals):
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
    journal.validate_entries(packet['entries'], since, until, maximum)
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
        '--until=@' + f'{end // 1000000}.{end % 1000000:06d}', '--unit=' + unit]
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
    if os.geteuid() != 0 or sys.argv[1:] != ['--worker']:
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
    packet = worker(core.parsed(raw))
    sys.stdout.buffer.write(core.encode(packet))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never print a journal message, traceback, supplied value or secret.
        sys.stderr.write('journal_native_worker_failed\n')
        raise SystemExit(1)
