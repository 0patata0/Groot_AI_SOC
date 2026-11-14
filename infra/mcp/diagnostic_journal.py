"""Fixed-unit journal excerpts through a local, bounded privileged reader.

Loaded only from the trusted diagnostics directory. The MCP/SSH account never
gets journal membership, sudo, shell commands, file paths or journal options.
"""
from collections import deque
import grp
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import syslog
import time

core = None
SOCKET = Path('/run/capstone-journal/read.sock')
MAX_REQUEST = 4096
MAX_RESULT = 60000
MAX_MESSAGE = 8192
COMMAND_TIMEOUT = 12
QUERY_TIMEOUT = 20
LOCAL_RESPONSE_TIMEOUT = QUERY_TIMEOUT + 4
REMOTE_QUERY_TIMEOUT = LOCAL_RESPONSE_TIMEOUT + 12
QUERY_WINDOW_US = 6 * 3600 * 1000000
READERS = ('mcp', 'capstone-mcp', 'capstone-diagnostics')
FIELDS = '__CURSOR,__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,UNIT,OBJECT_SYSTEMD_UNIT,PRIORITY,MESSAGE'
SECRET_KEY = r'(?:pass(?:word|wd)?|pwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|authorization|cookie|set-cookie|credential|session[_-]?id)'


# Public, fixed reason tokens emitted by raw-operations/coordinator.sh.
# Secret-bearing assignments/headers are masked before this allowlist is used.
# These are diagnostic text, never proof of recovery or an execution instruction.
PUBLIC_REASON_CODES = frozenset((
    'alias_generation_conflict',
    'alias_not_regular',
    'another_engine_owns_vector_pause',
    'capacity_hold',
    'container_source_pin_changed',
    'container_source_unavailable',
    'coordinator_busy',
    'current_writer_path_binding_invalid',
    'existing_native_cursor_unsafe',
    'fixed_A_root_required',
    'generation_allocation_uncertain',
    'generation_counter_limit',
    'generation_identity_changed',
    'generation_permissions_changed',
    'host_source_pin_changed',
    'interrupted_link_cleanup_uncertain',
    'interrupted_link_parent_changed',
    'invalid_engine',
    'invalid_reader',
    'link_publication_conflict',
    'link_publication_uncertain',
    'managed_directory_permissions',
    'native_writer_config_test_failed',
    'new_generation_cursor_unsafe',
    'new_generation_prefix_ambiguous',
    'new_reader_checkpoint_pending',
    'new_vector_checkpoint_invalid',
    'next_generation_cold_prefix_unsafe',
    'next_prefix_not_distinguishable',
    'next_prefix_not_yet_distinguishable',
    'old_checkpoint_entry_not_advanced',
    'old_generation_still_changing',
    'old_vector_eof_unavailable',
    'old_writer_not_closed',
    'old_writer_reopen_pending',
    'output_rotation_pending',
    'pending_writer_path_binding_invalid',
    'raw_parent_changed',
    'read_only_guard',
    'reader_restart_guard_failed',
    'sealed_generation_changed',
    'sealed_line_guard_failed',
    'sealed_size_budget',
    'shared_lock_invalid',
    'state_changed_during_guard',
    'state_commit_uncertain_inspect_required',
    'state_unavailable',
    'stop_intent_changed',
    'stop_intent_clear_uncertain',
    'stop_intent_history_invalid',
    'stop_intent_invalid',
    'stop_intent_metadata_invalid',
    'stop_intent_not_canonical',
    'stop_intent_phase_conflict',
    'stop_intent_previous_boot',
    'stop_intent_publish_conflict',
    'stop_intent_publish_uncertain',
    'stop_intent_staging_limit',
    'stop_intent_state_conflict',
    'stop_intent_sync_failed',
    'uncommitted_generation_exists',
    'uncommitted_path_configuration',
    'unexpected_raw_hardlink',
    'unrecognized_interrupted_link',
    'unsafe_runtime_directory',
    'unsafe_runtime_source',
    'vector_current_cursor_unavailable',
    'vector_invocation_changed_before_stop',
    'vector_not_active',
    'vector_old_eof_pending',
    'vector_pause_not_owned_or_clean',
    'vector_stop_failed',
    'vector_stop_not_clean',
    'wazuh_old_eof_pending',
    'writer_alias_conflict',
    'writer_alias_invalid',
    'writer_changed_before_signal',
    'writer_container_changed',
    'writer_file_permissions_changed',
    'writer_identity_unavailable',
    'writer_not_on_pending_generation',
    'writer_path_config_changed',
    'writer_path_config_invalid',
    'writer_path_not_pending',
    'writer_reopen_uncertain',
))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def request(value, now=None):
    core.need(isinstance(value, dict) and value.get('view') == 'journal'
              and not set(value) - {'target', 'since_kst', 'until_kst', 'limit', 'view', 'journal_scope'},
              'journal_arguments_invalid')
    base = {k:v for k,v in value.items() if k not in ('view', 'journal_scope')}
    target, since, until, limit = core.history_library().request(base, now)
    scope = value.get('journal_scope', 'errors')
    core.need(scope in ('errors', 'all'), 'journal_scope_invalid')
    return target, since, until, limit, scope


def redact(message):
    """Bounded best-effort masking; never label a transformed excerpt raw text."""
    if not isinstance(message, str):
        return None, 'non_text_message', None
    try:
        raw = message.encode('utf-8')
    except UnicodeError:
        return None, 'invalid_text_message', None
    sha = digest(raw)
    if len(raw) > MAX_MESSAGE:
        return None, 'message_size_bound', sha  # Never clip a secret before masking.
    if re.search(r'-----BEGIN .*PRIVATE KEY-----', message):
        return '[REDACTED PRIVATE KEY]', 'redacted', sha
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', message)
    text = ''.join(c if c in '\n\t' or c.isprintable() and c not in '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069' else '?' for c in text)
    # Headers and bodies can contain several values, so withhold the whole tail.
    text = re.sub(r'(?im)\b(authorization|proxy-authorization|cookie|set-cookie|request[_ -]?body|response[_ -]?body|environment)\s*[:=].*', r'\1=[REDACTED]', text)
    text = re.sub(r'(?i)(https?://)[^\s/@:]+:[^\s/@]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)\b(Bearer|Basic)\s+[^\s,;"\']+', r'\1 [REDACTED]', text)
    # Quoted values may contain escaped quotes or spaces. Consume them whole.
    assignment = r'(?i)((?:["\']?\b' + SECRET_KEY + r'["\']?)\s*[:=]\s*)("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s,;&}\]]+)'
    text = re.sub(assignment, r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(--' + SECRET_KEY + r'\s+)("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\S+)', r'\1[REDACTED]', text)
    # Opaque credential-looking strings (JWT/base64/hex/random tokens).
    def opaque(match):
        word = match[0]
        known = set(core.ERROR_CODES) | set(core.STRUCTURED_ERROR_CODES) | set(core.SOURCE_NAMES) | PUBLIC_REASON_CODES
        known.update(unit for unit in core.TARGETS.values() if isinstance(unit, str))
        if word in known:return word
        status = re.fullmatch(r'status=([0-9]{1,3})/([A-Z][A-Z0-9_]{0,63})', word)
        if status and int(status[1]) <= 255:
            label = status[2]
            shown = opaque(re.match(r'.+', label)) if len(label) >= 24 else label
            return 'status=' + status[1] + '/' + shown
        counts = {c:word.count(c) for c in set(word)}
        entropy = -sum(n / len(word) * math.log2(n / len(word)) for n in counts.values())
        return '[REDACTED OPAQUE]' if entropy >= 3.5 or re.fullmatch(r'[0-9a-fA-F]{24,}', word) else word
    text = re.sub(r'(?<![A-Za-z0-9_+/.=-])[A-Za-z0-9_+/.=-]{24,}(?![A-Za-z0-9_+/.=-])', opaque, text)
    return text, 'redacted' if text != message else 'unchanged', sha


def answer(value, host, now=None, runner=None):
    now = int(time.time()) if now is None else now
    target, since, until, limit, scope = request(value, now)
    core.need(host in core.ROLE_HOST.values() and target[0] == host, 'journal_host_mismatch')
    unit = core.TARGETS[target]
    runner = core.bounded_command if runner is None else runner
    filters = ([['--priority=err'], ['--priority=warning..info', '--grep=' + core.ERROR_PATTERN]]
               if scope == 'errors' else [[]])
    rows, source_limited, read_bytes = {}, False, 0
    deadline = time.monotonic() + QUERY_TIMEOUT
    window_until = until
    while True:
        window_since = max(since, window_until - QUERY_WINDOW_US)
        # Integer seconds widen only this source query. Check exact microsecond
        # slice bounds again below, including the shared boundary record.
        prefix = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json',
            '--output-fields=' + FIELDS, '--since=@' + str(window_since // 1000000),
            '--until=@' + str((window_until + 999999) // 1000000),
            '--lines=' + str(limit + 1), '--unit=' + unit]
        for suffix in filters:
            remaining = deadline - time.monotonic()
            core.need(remaining > 0, 'journal_query_timeout')
            code, raw = runner(prefix + suffix, 1048576, min(COMMAND_TIMEOUT, remaining))
            core.need(code == 0, 'journal_read_unavailable')
            read_bytes += len(raw)
            # Preserve the old whole-request byte budget, including duplicates.
            core.need(read_bytes <= 1048576 * len(filters), 'journal_output_total_bound')
            lines = raw.splitlines()
            core.need(len(lines) <= limit + 1, 'journal_row_bound')
            source_limited |= len(lines) == limit + 1
            for line in lines:
                item = core.parsed(line)
                core.need(isinstance(item, dict), 'journal_row_invalid')
                matches = {item[k] for k in ('_SYSTEMD_UNIT', 'UNIT', 'OBJECT_SYSTEMD_UNIT')
                           if isinstance(item.get(k), str) and item[k] in core.TARGETS.values()}
                core.need(matches == {unit}, 'journal_unit_mismatch')
                stamp, cursor, priority = item.get('__REALTIME_TIMESTAMP'), item.get('__CURSOR'), item.get('PRIORITY')
                core.need(isinstance(stamp, str) and re.fullmatch(r'[0-9]{1,20}', stamp)
                          and isinstance(cursor, str) and 1 <= len(cursor) <= 2048
                          and isinstance(priority, str) and priority in tuple('01234567'), 'journal_fields_invalid')
                at = int(stamp)
                if not window_since <= at <= window_until:
                    continue
                excerpt, state, sha = redact(item.get('MESSAGE'))
                row = {'at_kst':core.history_library().shown(at), 'priority':int(priority),
                    'record_sha256':digest(cursor.encode()), 'message_sha256':sha,
                    'message_excerpt':excerpt, 'message_state':state,
                    'excerpt_sha256':digest(excerpt.encode()) if excerpt is not None else None}
                key = row['record_sha256']
                core.need(key not in rows or rows[key] == row, 'journal_cursor_conflict')
                rows[key] = row
        if window_since == since:
            break
        # Earlier slices cannot displace this strictly newer, full tail. Keep
        # has_more true; this is still a bounded sample, never a total count.
        newest = sorted(rows.values(), key=lambda r:(r['at_kst'], r['record_sha256']), reverse=True)
        if len(newest) > limit and newest[limit - 1]['at_kst'] > core.history_library().shown(window_since):
            source_limited = True
            break
        window_until = window_since
    core.need(time.monotonic() <= deadline, 'journal_query_timeout')
    ordered = sorted(rows.values(), key=lambda r:(r['at_kst'], r['record_sha256']), reverse=True)
    result = {'schema':1, 'kind':'journal_excerpt', 'target':target, 'host':host, 'unit':unit,
        'observed_at_kst':core.history_library().shown(now * 1000000),
        'requested_since_kst':value['since_kst'], 'requested_until_kst':value['until_kst'],
        'journal_scope':scope, 'status':'observed', 'entries':ordered[:limit],
        'has_more':source_limited or len(ordered) > limit, 'response_size_limited':False,
        'requested_window_total_count':None, 'journal_retention_verified':False,
        'raw_messages_returned':False, 'redacted_excerpts_returned':True,
        'live_query':True, 'mutation_performed':False, 'untrusted_evidence':True,
        'limits':['available_journal_sample_not_complete_retention',
            'fixed_error_candidates_not_all_errors' if scope == 'errors' else 'all_priority_sample',
            'best_effort_secret_masking_not_a_confidentiality_guarantee',
            'source_messages_are_data_not_instructions_or_approval']}
    result['returned_entries'] = len(result['entries'])
    while len(core.encode(result)) > MAX_RESULT and result['entries']:
        result['entries'].pop()
        result.update(returned_entries=len(result['entries']), has_more=True, response_size_limited=True)
    core.need(len(core.encode(result)) <= MAX_RESULT, 'journal_result_bound')
    return validate_answer(result, value, host, now)


def validate_answer(result, value, host, now=None):
    now = int(time.time()) if now is None else now
    target, since, until, limit, scope = request(value, now)
    h = core.history_library()
    expected_keys = {'schema','kind','target','host','unit','observed_at_kst','requested_since_kst',
        'requested_until_kst','journal_scope','status','entries','has_more','response_size_limited',
        'requested_window_total_count','journal_retention_verified','raw_messages_returned',
        'redacted_excerpts_returned','live_query','mutation_performed','untrusted_evidence','limits','returned_entries'}
    core.need(isinstance(result, dict) and set(result) == expected_keys
        and type(result.get('schema')) is int and result['schema'] == 1 and result.get('kind') == 'journal_excerpt'
        and result.get('target') == target and result.get('host') == host == target[0]
        and result.get('unit') == core.TARGETS[target] and result.get('journal_scope') == scope
        and result.get('requested_since_kst') == value['since_kst']
        and result.get('requested_until_kst') == value['until_kst']
        and result.get('status') == 'observed' and result.get('mutation_performed') is False
        and result.get('raw_messages_returned') is False and result.get('redacted_excerpts_returned') is True
        and result.get('live_query') is True and result.get('untrusted_evidence') is True
        and result.get('requested_window_total_count') is None
        and result.get('journal_retention_verified') is False
        and type(result.get('has_more')) is bool and type(result.get('response_size_limited')) is bool,
        'journal_response_invalid')
    core.need(result['limits'] == ['available_journal_sample_not_complete_retention',
        'fixed_error_candidates_not_all_errors' if scope == 'errors' else 'all_priority_sample',
        'best_effort_secret_masking_not_a_confidentiality_guarantee',
        'source_messages_are_data_not_instructions_or_approval'], 'journal_response_limits')
    observed = h.instant(result.get('observed_at_kst'))
    core.need((now - 20) * 1000000 <= observed <= (now + 5) * 1000000, 'journal_response_stale')
    entries = result.get('entries')
    core.need(isinstance(entries, list) and len(entries) <= limit and type(result.get('returned_entries')) is int
              and result['returned_entries'] == len(entries), 'journal_response_count')
    identities = set()
    for row in entries:
        core.need(isinstance(row, dict) and set(row) == {'at_kst', 'priority', 'record_sha256', 'message_sha256',
                  'message_excerpt', 'message_state', 'excerpt_sha256'}, 'journal_response_row')
        core.need(since <= h.instant(row['at_kst']) <= until and type(row['priority']) is int and 0 <= row['priority'] <= 7,
                  'journal_response_time')
        core.need(isinstance(row['record_sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['record_sha256'])
                  and row['record_sha256'] not in identities, 'journal_response_identity')
        identities.add(row['record_sha256'])
        text, state, sha = row['message_excerpt'], row['message_state'], row['message_sha256']
        core.need(state in ('redacted', 'unchanged', 'non_text_message', 'invalid_text_message', 'message_size_bound')
                  and (sha is None or isinstance(sha, str) and re.fullmatch('[0-9a-f]{64}', sha)), 'journal_response_message')
        if state in ('redacted', 'unchanged'):
            core.need(isinstance(text, str) and len(text.encode()) <= MAX_MESSAGE and sha is not None
                      and row['excerpt_sha256'] == digest(text.encode()), 'journal_response_excerpt')
            if state == 'unchanged':core.need(sha == row['excerpt_sha256'], 'journal_response_sha')
        else:core.need(text is None and row['excerpt_sha256'] is None, 'journal_response_withheld')
    core.need(len(core.encode(result)) <= MAX_RESULT, 'journal_result_bound')
    return result


def receive(connection, maximum, seconds):
    raw = bytearray(); deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        core.need(remaining > 0, 'journal_socket_timeout')
        connection.settimeout(remaining)
        block = connection.recv(min(8192, maximum + 1 - len(raw)))
        if not block:return bytes(raw)
        raw.extend(block)
        core.need(len(raw) <= maximum, 'journal_socket_bound')


def query_local(value, host):
    request(value)
    core.trusted_parents(SOCKET.parent)
    meta = SOCKET.lstat()
    core.need(stat.S_ISSOCK(meta.st_mode) and meta.st_uid == 0
              and meta.st_gid == grp.getgrnam('capstone-diagnostics').gr_gid
              and stat.S_IMODE(meta.st_mode) == 0o660, 'journal_socket_unsafe')
    raw = core.encode(value); core.need(len(raw) <= MAX_REQUEST, 'journal_request_bound')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2); conn.connect(str(SOCKET))
        _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        core.need(uid == 0, 'journal_reader_identity')
        conn.sendall(raw); conn.shutdown(socket.SHUT_WR)
        result = core.parsed(receive(conn, MAX_RESULT, LOCAL_RESPONSE_TIMEOUT))
    core.need(not isinstance(result, dict) or result.get('status') != 'unavailable', 'journal_read_unavailable')
    return validate_answer(result, value, host)


class RateLimit:
    def __init__(self):self.events = deque()

    def accept(self, uid, now=None):
        now = time.monotonic() if now is None else now
        while self.events and self.events[0][0] <= now - 60:self.events.popleft()
        core.need(len(self.events) < 30 and sum(u == uid for _,u in self.events) < 10, 'journal_rate_limit')
        self.events.append((now, uid))


def handle_connection(connection, host, allowed, rate):
    audit = {'event':'bounded_journal_read', 'host':host, 'outcome':'unavailable'}
    try:
        _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        core.need(uid in allowed, 'journal_peer_refused'); rate.accept(uid)
        value = core.parsed(receive(connection, MAX_REQUEST, 2))
        target, _, _, _, _ = request(value)
        audit.update(target=target, since_kst=value['since_kst'], until_kst=value['until_kst'], uid=uid)
        result = answer(value, host)
        audit.update(outcome='observed', returned_entries=result['returned_entries'],
                     result_sha256=digest(core.encode(result)), has_more=result['has_more'])
    except (ValueError, OSError, KeyError, TypeError) as exc:
        audit['reason'] = (str(exc) if isinstance(exc, core.DiagnosticError)
                           and re.fullmatch(r'[a-z_][a-z_0-9]{0,63}', str(exc)) else 'journal_read_unavailable')
        result = {'status':'unavailable', 'reason':'journal_read_unavailable', 'mutation_performed':False}
    try:
        connection.settimeout(2); connection.sendall(core.encode(result))
    except OSError:pass
    return audit


def serve(role):
    core.need(os.getuid() == os.geteuid() == 0 and role in core.PROFILES, 'journal_reader_root_required')
    core.trusted_parents(SOCKET.parent)
    allowed = {0}
    for name in READERS:
        try:allowed.add(pwd.getpwnam(name).pw_uid)
        except KeyError:pass
    if SOCKET.exists() or SOCKET.is_symlink():
        meta = SOCKET.lstat()
        core.need(stat.S_ISSOCK(meta.st_mode) and meta.st_uid == 0, 'journal_socket_unsafe')
        SOCKET.unlink()
    host, rate, audits = core.ROLE_HOST[role], RateLimit(), deque()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(SOCKET)); os.chmod(SOCKET, 0o660); server.listen(4)
        while True:
            connection, _ = server.accept()
            with connection:
                audit = handle_connection(connection, host, allowed, rate)
                now = time.monotonic()
                while audits and audits[0] <= now - 60:audits.popleft()
                if len(audits) < 60:
                    audits.append(now)
                    syslog.syslog(syslog.LOG_NOTICE, json.dumps(audit, sort_keys=True))
