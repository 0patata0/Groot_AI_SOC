"""Bounded, root-published journal metadata; readers have no journal privilege.

Loaded by system_diagnostics.history_library(), which binds the verified core.
Original journal messages/cursors never enter this cache or an MCP response.
"""
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

core = None
DATABASE = Path('/var/lib/capstone-diagnostics/journal-history.sqlite3')
MAX_DATABASE = 32 * 1024 * 1024
MAX_EVENTS = 100000
RETENTION_DAYS = 30
KST = timezone(timedelta(hours=9))
FIELDS = '__CURSOR,__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,UNIT,OBJECT_SYSTEMD_UNIT,PRIORITY,MESSAGE'


def instant(value):
    core.need(isinstance(value, str) and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+09:00', value),
        'history_timestamp_requires_kst')
    try:
        delta = datetime.fromisoformat(value).astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    except (ValueError, OverflowError):
        raise core.DiagnosticError('history_timestamp_invalid') from None


def shown(micros):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)).astimezone(KST).isoformat()


def request(value, now=None):
    now = int(time.time()) if now is None else now
    core.need(isinstance(value, dict) and {'target', 'since_kst', 'until_kst'} <= set(value)
              <= {'target', 'since_kst', 'until_kst', 'limit'}, 'history_arguments_invalid')
    target = value['target']
    core.need(isinstance(target, str) and isinstance(core.TARGETS.get(target), str), 'history_unit_target_required')
    since, until = instant(value['since_kst']), instant(value['until_kst'])
    core.need(0 < until - since <= 86400 * 1000000, 'history_window_must_be_at_most_24_hours')
    core.need((now - RETENTION_DAYS * 86400) * 1000000 <= since and until <= now * 1000000,
              'history_window_outside_retention_or_future')
    limit = value.get('limit', 20)
    core.need(type(limit) is int and 1 <= limit <= 50, 'limit must be an integer from 1 to 50')
    return target, since, until, limit


def normalize(raw, units, since, until):
    core.need(len(raw) <= core.MAX_JOURNAL_QUERY, 'history_journal_byte_bound')
    lines = raw.splitlines()
    core.need(len(lines) <= core.MAX_JOURNAL_ROWS, 'history_journal_row_bound')
    events = {}
    for line in lines:
        value = core.parsed(line)
        core.need(isinstance(value, dict), 'history_journal_format')
        matches = {value[k] for k in ('_SYSTEMD_UNIT', 'UNIT', 'OBJECT_SYSTEMD_UNIT')
                   if isinstance(value.get(k), str) and value[k] in units}
        core.need(len(matches) == 1, 'history_unit_mapping_unavailable')
        cursor, stamp, priority = value.get('__CURSOR'), value.get('__REALTIME_TIMESTAMP'), value.get('PRIORITY')
        core.need(isinstance(cursor, str) and 1 <= len(cursor) <= 2048
                  and isinstance(stamp, str) and re.fullmatch(r'[0-9]{1,20}', stamp)
                  and isinstance(priority, str) and priority in tuple('0123456'), 'history_journal_fields')
        at = int(stamp)
        core.need(since <= at <= until, 'history_journal_time')
        classified = core.classify_message(value.get('MESSAGE'),next(iter(matches)))
        if int(priority) > 3 and classified['kind'] == 'journal_error':
            continue  # Same fixed error-classifier scope as current diagnostics.
        record = {'at': at // 1000000, 'priority': int(priority), **classified}
        core.validate_error(record, since // 1000000, until // 1000000)
        key = hashlib.sha256(cursor.encode()).hexdigest()
        row = {'record_sha256': key, 'at_us': at, 'unit': matches.pop(), 'error': record}
        core.need(key not in events or events[key] == row, 'history_cursor_conflict')
        events[key] = row
    return list(events.values()), len(lines) == core.MAX_JOURNAL_ROWS


def _connection(write=False):
    core.trusted_parents(DATABASE.parent)
    gid = grp.getgrnam('capstone-diagnostics').gr_gid
    if write and not DATABASE.exists():
        core.need(os.getuid() == os.geteuid() == 0, 'history_publisher_root_required')
        fd = os.open(DATABASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        try:
            os.fchmod(fd, 0o640)
            os.fchown(fd, 0, gid)
        finally:
            os.close(fd)
    meta = DATABASE.lstat()
    core.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == gid and meta.st_nlink == 1
              and stat.S_IMODE(meta.st_mode) == 0o640 and meta.st_size <= MAX_DATABASE, 'history_file_unsafe')
    # The root-owned parent cannot be renamed/written by the reader. No caller
    # path, schema extension, SQL, unit or journal option reaches this connection.
    db = sqlite3.connect(DATABASE.as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True, timeout=2)
    try:
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA foreign_keys=ON')
        if write:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            page_size = db.execute('PRAGMA page_size').fetchone()[0]
            core.need(type(page_size) is int and 512 <= page_size <= 65536, 'history_page_size')
            db.execute('PRAGMA max_page_count=' + str(MAX_DATABASE // page_size))
            db.executescript('''CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, at_us INTEGER NOT NULL, unit TEXT NOT NULL, error TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS event_window ON events(unit,at_us,id);
            CREATE TABLE IF NOT EXISTS windows (since_us INTEGER NOT NULL, until_us INTEGER NOT NULL, truncated INTEGER NOT NULL,
                PRIMARY KEY(since_us,until_us));''')
        else:
            db.execute('PRAGMA query_only=ON')
        return db
    except BaseException:
        db.close()
        raise


@contextmanager
def connection(write=False):
    db = None
    try:
        db = _connection(write)
        yield db
    except sqlite3.Error:
        raise core.DiagnosticError('history_storage_unavailable') from None
    finally:
        if db is not None:
            db.close()


def collect(role, now=None, *, hours=4):
    core.need(os.getuid() == os.geteuid() == 0 and role in core.PROFILES, 'history_publisher_root_required')
    core.need(type(hours) is int and hours in (4, 24), 'history_fixed_window_required')
    now = int(time.time()) if now is None else now
    profile = core.PROFILES[role]
    total, failed, truncated = 0, 0, False
    # The initial backfill uses six bounded four-hour scans: a whole-day grep
    # can exceed the per-command budget on busy journals. This is root-only
    # installation work, never performed synchronously by an MCP reader.
    for since in range(now - hours * 3600, now, 4 * 3600):
        until = min(now, since + 4 * 3600)
        prefix = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json', '--output-fields=' + FIELDS,
                  '--since=@' + str(since), '--until=@' + str(until), '--lines=' + str(core.MAX_JOURNAL_ROWS),
                  *('--unit=' + unit for unit in profile.values())]
        events, clipped = [], False
        try:
            for filters in (['--priority=err'], ['--priority=warning..info', '--grep=' + core.ERROR_PATTERN]):
                code, raw = core.bounded_command(prefix + filters, core.MAX_JOURNAL_QUERY, 8)
                core.need(code == 0, 'history_journal_unavailable')
                rows, limited = normalize(raw, set(profile.values()), since * 1000000, until * 1000000)
                events.extend(rows)
                clipped |= limited
        except (core.DiagnosticError, OSError):
            failed += 1
            continue  # No coverage or zero-result publication for a failed scan.
        publish(core.ROLE_HOST[role], since * 1000000, until * 1000000, events, clipped)
        total += len(events)
        truncated |= clipped
    core.need(failed < hours // 4, 'history_no_window_available')
    return {'host': core.ROLE_HOST[role], 'observed_at_kst': shown(now * 1000000),
            'collected_rows': total, 'source_truncated': truncated, 'failed_window_count': failed}


def publish(host, since, until, events, truncated):
    core.need(os.getuid() == os.geteuid() == 0, 'history_publisher_root_required')
    core.need(host in core.ROLE_HOST.values() and type(truncated) is bool and type(since) is int
              and type(until) is int and 0 < until - since <= 86400 * 1000000
              and isinstance(events, list) and len(events) <= core.MAX_COMBINED_JOURNAL_ROWS, 'history_batch_invalid')
    with connection(True) as db, db:
        db.execute('BEGIN IMMEDIATE')
        previous = dict(db.execute('SELECT key,value FROM metadata'))
        core.need(not previous or previous.get('host') == host and previous.get('schema') == '1', 'history_host_mismatch')
        for row in events:
            core.need(set(row) == {'record_sha256', 'at_us', 'unit', 'error'}
                      and re.fullmatch('[0-9a-f]{64}', row['record_sha256'])
                      and row['unit'] in core.PROFILES[{v:k for k,v in core.ROLE_HOST.items()}[host]].values()
                      and type(row['at_us']) is int and since <= row['at_us'] <= until, 'history_record_invalid')
            core.validate_error(row['error'], since // 1000000, until // 1000000)
            encoded = core.encode(row['error']).decode()
            existing = db.execute('SELECT at_us,unit,error FROM events WHERE id=?', (row['record_sha256'],)).fetchone()
            core.need(existing is None or existing == (row['at_us'], row['unit'], encoded), 'history_cursor_conflict')
            db.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?)', (row['record_sha256'], row['at_us'], row['unit'], encoded))
        latest = max(until, int(previous.get('observed_at_us', '0')))
        cutoff = max(latest - RETENTION_DAYS * 86400 * 1000000, int(previous.get('retained_since_us', '0')))
        db.execute('DELETE FROM events WHERE at_us<?', (cutoff,))
        count = db.execute('SELECT count(*) FROM events').fetchone()[0]
        if count > MAX_EVENTS:
            # Bound this new metadata cache, never the original journal. Drop
            # the entire boundary instant so coverage does not hide tied rows.
            boundary = db.execute('SELECT at_us FROM events ORDER BY at_us DESC,id DESC LIMIT 1 OFFSET ?', (MAX_EVENTS,)).fetchone()[0]
            cutoff = max(cutoff, boundary + 1)
            db.execute('DELETE FROM events WHERE at_us<?', (cutoff,))
        db.execute('DELETE FROM windows WHERE until_us<?', (cutoff,))
        db.execute('UPDATE OR IGNORE windows SET since_us=? WHERE since_us<?', (cutoff, cutoff))
        if until >= cutoff:
            db.execute('INSERT OR REPLACE INTO windows VALUES(?,?,?)', (max(since, cutoff), until, int(truncated)))
        for key, value in {'schema':'1', 'host':host, 'observed_at_us':str(latest), 'retained_since_us':str(cutoff)}.items():
            db.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)', (key, value))


def answer(value, host, now=None):
    now = int(time.time()) if now is None else now
    target, since, until, limit = request(value, now)
    core.need(target.startswith(host + ':'), 'history_host_mismatch')
    with connection() as db:
        db.execute('BEGIN')  # One consistent read snapshot while the collector publishes.
        metadata = dict(db.execute('SELECT key,value FROM metadata'))
        core.need(metadata.get('schema') == '1' and metadata.get('host') == host, 'history_host_mismatch')
        observed, retained = int(metadata['observed_at_us']), int(metadata['retained_since_us'])
        core.need(observed <= (now + 5) * 1000000, 'history_future_publication')
        rows = db.execute('SELECT id,at_us,error FROM events WHERE unit=? AND at_us>=? AND at_us<=? ORDER BY at_us DESC,id DESC LIMIT ?',
                          (core.TARGETS[target], since, until, limit + 1)).fetchall()
        count = db.execute('SELECT count(*) FROM events WHERE unit=? AND at_us>=? AND at_us<=?',
                           (core.TARGETS[target], since, until)).fetchone()[0]
        windows = db.execute('SELECT since_us,until_us,truncated FROM windows WHERE until_us>=? AND since_us<=? ORDER BY since_us,until_us',
                            (since, until)).fetchall()
    scanned_until = since
    for start, stop, clipped in windows:
        if not clipped and max(start, retained) <= scanned_until:
            scanned_until = max(scanned_until, stop)
    covered = since >= retained and scanned_until >= until
    errors = []
    for digest, at, raw in rows[:limit]:
        item = core.parsed(raw)
        core.validate_error(item, since // 1000000, until // 1000000)
        core.need(re.fullmatch('[0-9a-f]{64}', digest) and item['at'] == at // 1000000, 'history_record_invalid')
        errors.append({'record_sha256':digest, 'observed_at_kst':shown(at), **{k:v for k,v in item.items() if k != 'at'}})
    return {'schema':1, 'kind':'journal_history', 'target':target, 'host':host, 'unit':core.TARGETS[target],
        'observed_at_kst':shown(observed), 'requested_since_kst':shown(since), 'requested_until_kst':shown(until),
        'age_seconds':max(0, now - observed // 1000000), 'publisher_stale':now * 1000000 - observed > core.TTL * 1000000,
        'recent_errors':errors, 'returned_error_count':len(errors), 'indexed_error_count':count,
        'requested_window_total_count':None, 'has_more':len(rows)>limit,
        'history_coverage':{'status':'scanned_sample' if covered else 'partial_or_unavailable',
            'retained_since_kst':shown(retained), 'source_filters':'priority0..3_or_fixed_error_classifier4..6',
            'scanned_window_count':len(windows), 'untruncated_requested_window_scanned':covered},
        'evidence_scope_ko':'정확 요청 구간으로 먼저 검색한 보관 오류 메타데이터입니다. 현재 서비스 상태·사건 당시 전체 journal·침해 부재의 증거가 아닙니다. '
            'indexed_error_count는 이 정제 색인의 일치 건수이며 전체 journal 오류 건수가 아닙니다. 표본0이나 구간 스캔 성공을 정상으로 판정하지 마세요.',
        'raw_messages_returned':False, 'mutation_performed':False, 'untrusted_evidence':True}


def validate_answer(result, value, host, now=None):
    now = int(time.time()) if now is None else now
    target, since, until, limit = request(value, now)
    fields = {'schema','kind','target','host','unit','observed_at_kst','requested_since_kst','requested_until_kst',
        'age_seconds','publisher_stale','recent_errors','returned_error_count','indexed_error_count',
        'requested_window_total_count','has_more','history_coverage','evidence_scope_ko',
        'raw_messages_returned','mutation_performed','untrusted_evidence'}
    core.need(isinstance(result, dict) and set(result) == fields and type(result['schema']) is int and result['schema'] == 1
              and result['kind'] == 'journal_history' and result['target'] == target and result['host'] == host
              and result['unit'] == core.TARGETS[target] and target.startswith(host + ':'), 'history_response_identity')
    core.need(instant(result['requested_since_kst']) == since and instant(result['requested_until_kst']) == until
              and instant(result['observed_at_kst']) <= (now + 5) * 1000000, 'history_response_time')
    errors, count, total = result['recent_errors'], result['returned_error_count'], result['indexed_error_count']
    core.need(isinstance(errors, list) and type(count) is int and len(errors) == count and 0 <= count <= limit
              and type(total) is int and count <= total <= MAX_EVENTS and result['requested_window_total_count'] is None
              and type(result['has_more']) is bool and result['has_more'] == (total > count), 'history_response_counts')
    core.need(type(result['age_seconds']) is int and result['age_seconds'] >= 0
              and type(result['publisher_stale']) is bool and result['publisher_stale'] == (result['age_seconds'] > core.TTL)
              and result['raw_messages_returned'] is False and result['mutation_performed'] is False
              and result['untrusted_evidence'] is True and isinstance(result['evidence_scope_ko'], str)
              and len(result['evidence_scope_ko']) <= 1024, 'history_response_scope')
    coverage = result['history_coverage']
    core.need(isinstance(coverage, dict) and set(coverage) == {'status','retained_since_kst','source_filters',
              'scanned_window_count','untruncated_requested_window_scanned'}
              and type(coverage['untruncated_requested_window_scanned']) is bool
              and coverage['status'] == ('scanned_sample' if coverage['untruncated_requested_window_scanned'] else 'partial_or_unavailable')
              and coverage['source_filters'] == 'priority0..3_or_fixed_error_classifier4..6'
              and type(coverage['scanned_window_count']) is int and 0 <= coverage['scanned_window_count'] <= 100000,
              'history_response_coverage')
    instant(coverage['retained_since_kst'])
    seen, previous = set(), None
    for row in errors:
        core.need(isinstance(row, dict) and {'record_sha256','observed_at_kst'} <= set(row), 'history_response_record')
        digest, at = row['record_sha256'], instant(row['observed_at_kst'])
        core.need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest) and digest not in seen
                  and since <= at <= until and (previous is None or at <= previous), 'history_response_record')
        core.validate_error({'at':at // 1000000, **{k:v for k,v in row.items() if k not in ('record_sha256','observed_at_kst')}},
                            since // 1000000, until // 1000000)
        seen.add(digest)
        previous = at
    return result
