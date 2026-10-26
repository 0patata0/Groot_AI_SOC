#!/usr/bin/env python3
"""Fixed systemd observations. Journal bodies never leave the local collector."""
import argparse
import grp
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types

SNAPSHOT = Path('/var/lib/capstone-diagnostics/snapshot.json')
MAX_SNAPSHOT = 131072
MAX_JOURNAL_QUERY = 1048576
MAX_COMMAND_STDERR = 4096
MAX_JOURNAL = 2 * MAX_JOURNAL_QUERY
TTL = 180
LOOKBACK = 240
MAX_ERRORS = 50
MAX_RETAINED_ERRORS = 400
MAX_JOURNAL_ROWS = 1001
MAX_COMBINED_JOURNAL_ROWS = 2 * MAX_JOURNAL_ROWS
ROLE_HOST = {'security': 'a', 'siem': 'b', 'service': 'c'}
PROFILES = {
    'security': {
        'a:vector': 'capstone-vector.service', 'a:wazuh-agent': 'wazuh-agent.service',
        'a:rule-worker': 'rule-change-worker.service',
        'a:raw-waf': 'capstone-raw-operations@modsecurity.service',
        'a:raw-suricata': 'capstone-raw-operations@suricata.service',
        'a:certificate-monitor': 'capstone-cert-monitor.service',
        'a:storage-monitor': 'capstone-storage-monitor.service', 'a:docker': 'docker.service',
    },
    'siem': {
        'b:soc-bot': 'soc-bot.service', 'b:management': 'capstone-management.service',
        'b:rule-worker': 'rule-change-worker.service', 'b:vector': 'capstone-vector.service',
        'b:wazuh-agent': 'wazuh-agent.service', 'b:docker': 'docker.service',
    },
    'service': {
        'c:lab-api': 'capstone-offline-labs.service',
        'c:lab-broker': 'capstone-offline-labs-broker.service',
        'c:lab-guard': 'capstone-offline-labs-guard.service',
        'c:lab-terminal': 'capstone-nonweb-terminal.service',
        'c:terminal-guard': 'capstone-nonweb-guard.service',
        'c:terminal-status': 'capstone-nonweb-status.service',
        'c:sudo-status': 'capstone-sudo-status.service',
        'c:sudo-user-manager': 'user@1991.service', 'c:apache': 'apache2.service',
        'c:wazuh-agent': 'wazuh-agent.service', 'c:docker': 'docker.service',
    },
}
TARGETS = {target: unit for profile in PROFILES.values() for target, unit in profile.items()}
RUNTIME_TARGETS = {
    'security': ('a:waf', 'a:suricata', 'a:collection'),
    'siem': ('b:hermes', 'b:ollama', 'b:wazuh-manager', 'b:wazuh-indexer',
             'b:mattermost', 'b:llm', 'b:management-pipeline', 'b:ingestion'),
    'service': ('c:collection',),
}
TARGETS.update({t: None for values in RUNTIME_TARGETS.values() for t in values})
TARGETS['soc:coverage'] = None
_runtime = None


def runtime_library():
    global _runtime
    if _runtime is None:
        path = Path(__file__).with_name('runtime_health.py')
        source = root_file(path, 131072)
        module = types.ModuleType('fixed_runtime_health')
        module.__file__ = str(path)
        exec(compile(source, str(path), 'exec'), module.__dict__)
        need(module.ROLE_TARGETS == RUNTIME_TARGETS, 'runtime_catalog_mismatch')
        _runtime = module
    return _runtime
TEXT_PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'Result', 'UnitFileState', 'Type')
NUMBER_PROPERTIES = ('ExecMainCode', 'ExecMainStatus', 'NRestarts',
                     'ActiveEnterTimestampMonotonic', 'InactiveEnterTimestampMonotonic',
                     'ExecMainStartTimestampMonotonic', 'ExecMainExitTimestampMonotonic')
PROPERTIES = TEXT_PROPERTIES + NUMBER_PROPERTIES
KINDS = frozenset(('journal_error', 'python_traceback', 'python_exception', 'python_location',
                   'process_exit', 'unit_result', 'start_step', 'permission_denied',
                   'not_found', 'address_in_use', 'read_only_filesystem', 'operation_denied', 'known_error_code'))
ERROR_CODES = frozenset(('publication_failed', 'pam_uid_transition_failed', 'terminal_operation_failed',
                        'sudo_operation_failed', 'sudo_root_attestation_mismatch', 'diagnostics_unavailable'))
EXCEPTIONS = frozenset(('PermissionError', 'FileNotFoundError', 'ModuleNotFoundError',
    'ImportError', 'SyntaxError', 'IndentationError', 'TabError', 'ValueError', 'TypeError',
    'KeyError', 'IndexError', 'AttributeError', 'RuntimeError', 'OSError', 'TimeoutError',
    'ConnectionError', 'BrokenPipeError', 'AssertionError', 'MemoryError', 'SystemExit'))
SOURCE_NAMES = frozenset(('terminal_server.py', 'sudo_terminal.py', 'runtime.py', 'lab.py',
    'app.py', 'broker.py', 'publish.py', 'soc_bot.py', 'soc_management_controller.py',
    'soc_management_run.py', 'rule_change_executor.py', 'system_diagnostics.py'))
RESULTS = frozenset(('success', 'exit-code', 'signal', 'core-dump', 'watchdog', 'timeout',
    'start-limit-hit', 'resources', 'protocol', 'oom-kill', 'dependency', 'assert', 'condition'))
STEPS = frozenset(('CHDIR', 'EXEC', 'USER', 'GROUP', 'NAMESPACE', 'CAPABILITIES',
    'LIMITS', 'STDIN', 'STDOUT', 'STDERR', 'SECCOMP', 'APPARMOR', 'SELINUX_CONTEXT'))
ERROR_PATTERN = '|'.join(re.escape(item) for item in (*sorted(ERROR_CODES), *sorted(EXCEPTIONS), 'Traceback',
    'Main process exited', 'Failed with result', 'Failed at step', 'Permission denied',
    'No such file or directory', 'Address already in use', 'Read-only file system',
    'Operation not permitted', *sorted(SOURCE_NAMES)))
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/nonexistent', 'LANG': 'C',
       'LC_ALL': 'C', 'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat',
       'PYTHONDONTWRITEBYTECODE': '1'}


class DiagnosticError(ValueError):
    """A fixed code, without command output or journal text."""


def need(value, code):
    if not value:
        raise DiagnosticError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def encode(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def parsed(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise DiagnosticError('invalid_json') from None


def trusted_parents(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'unsafe_path')
    for item in (path, *path.parents):
        meta = item.lstat()
        need(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
             'unsafe_parent')


def root_file(path, maximum, mode=None, gid=None):
    path = Path(path)
    trusted_parents(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and not before.st_mode & 0o022 and 0 < before.st_size <= maximum
             and (mode is None or stat.S_IMODE(before.st_mode) == mode)
             and (gid is None or before.st_gid == gid), 'unsafe_file')
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(data) == before.st_size and all(getattr(before, key) == getattr(after, key) for key in fields), 'changed_file')
        return data


def bounded_command(argv, maximum, seconds, input_data=None):
    """No shell or inherited credentials. Never retain or return stderr."""
    checked_grep = (argv[:4] == ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json']
        and argv[-2:] == ['--priority=warning..info', '--grep=' + ERROR_PATTERN])
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE if checked_grep else subprocess.DEVNULL,
        env=ENV, close_fds=True, start_new_session=True)
    result = bytearray()
    stderr_bytes = 0
    deadline = time.monotonic() + seconds
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
    if checked_grep:
        selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
    try:
        if input_data is not None:
            need(len(input_data) <= 8192, 'input_bound')
            process.stdin.write(input_data)
            process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            need(remaining > 0, 'command_timeout')
            for key, _ in selector.select(min(remaining, 0.25)):
                available = maximum + 1 - len(result) if key.data == 'stdout' else MAX_COMMAND_STDERR + 1 - stderr_bytes
                chunk = os.read(key.fileobj.fileno(), min(8192, available))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == 'stdout':
                    result.extend(chunk)
                    need(len(result) <= maximum, 'command_output_bound')
                else:
                    stderr_bytes += len(chunk)
                    need(stderr_bytes <= MAX_COMMAND_STDERR, 'command_stderr_bound')
        remaining = deadline - time.monotonic()
        need(remaining > 0, 'command_timeout')
        code = process.wait(timeout=remaining)
        if checked_grep:
            need(stderr_bytes == 0, 'journal_query_stderr')
            # journalctl --grep returns 1 for no matching entries. Only the
            # fixed grep query with both output streams empty is a valid empty
            # observation; other failures keep their code and remain unavailable.
            if code == 1 and not result:
                code = 0
        return code, bytes(result)
    except (subprocess.TimeoutExpired, BrokenPipeError):
        raise DiagnosticError('command_failed') from None
    finally:
        selector.close()
        process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=3)


def parse_properties(raw, unit):
    need(len(raw) <= 8192, 'properties_bound')
    try:
        values = {}
        for line in raw.decode('utf-8', 'strict').splitlines():
            need('=' in line, 'properties_format')
            key, value = line.split('=', 1)
            need(key in ('Id', *PROPERTIES) and key not in values, 'properties_fields')
            values[key] = value
        need(values.get('Id') == unit and values.get('LoadState'), 'unit_identity')
        result = {}
        for key in PROPERTIES:
            value = values.get(key)
            if value in (None, ''):
                result[key] = None
            elif key in TEXT_PROPERTIES:
                need(re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value), 'property_value')
                result[key] = value
            else:
                need(re.fullmatch(r'[0-9]{1,20}', value) and int(value) <= 2**63 - 1,
                     'property_value')
                result[key] = int(value)
        return result
    except UnicodeError:
        raise DiagnosticError('properties_encoding') from None


def classify_message(message):
    # Never return raw MESSAGE, quoted command arguments, paths, headers,
    # HTTP bodies, credentials, or instructions carried in journal text.
    if not isinstance(message, str) or len(message) > 16384:
        return {'kind': 'journal_error'}
    text = message.strip()
    for code in sorted(ERROR_CODES):
        if re.search(r'(?<![A-Za-z0-9_])' + code + r'(?![A-Za-z0-9_])', text):
            return {'kind': 'known_error_code', 'code': code}
    if text.startswith('Traceback (most recent call last):'):
        for line in reversed(text.splitlines()):
            match = re.match(r'^([A-Za-z_][A-Za-z0-9_]{0,63})(?::|$)', line)
            if match and match[1] in EXCEPTIONS:
                return {'kind': 'python_exception', 'exception': match[1]}
        return {'kind': 'python_traceback'}
    match = re.match(r'^([A-Za-z_][A-Za-z0-9_]{0,63})(?::|$)', text)
    if match and match[1] in EXCEPTIONS:
        return {'kind': 'python_exception', 'exception': match[1]}
    match = re.fullmatch(r'File "[^"\n]*\/([A-Za-z0-9_.-]+)", line ([0-9]{1,6}), in [A-Za-z0-9_<>]+', text)
    if match and match[1] in SOURCE_NAMES:
        return {'kind': 'python_location', 'source': match[1], 'line': int(match[2])}
    match = re.search(r'Main process exited, code=(exited|killed|dumped), status=([0-9]{1,3})(?:/[A-Z0-9_]+)?(?:\s|$)', text)
    if match and int(match[2]) <= 255:
        return {'kind': 'process_exit', 'exit_code': int(match[2]), 'exit_kind': match[1]}
    match = re.search(r"Failed with result '([a-z-]+)'", text)
    if match and match[1] in RESULTS:
        return {'kind': 'unit_result', 'result': match[1]}
    match = re.search(r'Failed at step ([A-Z_]+)(?:\s|$)', text)
    if match and match[1] in STEPS:
        return {'kind': 'start_step', 'step': match[1]}
    for token, kind in (('Permission denied', 'permission_denied'),
                        ('No such file or directory', 'not_found'),
                        ('Address already in use', 'address_in_use'),
                        ('Read-only file system', 'read_only_filesystem'),
                        ('Operation not permitted', 'operation_denied')):
        if token in text:
            return {'kind': kind}
    return {'kind': 'journal_error'}


def journal_errors(raw, units, now, source_truncated=None):
    need(len(raw) <= MAX_JOURNAL, 'journal_byte_bound')
    lines = raw.splitlines()
    need(len(lines) <= MAX_COMBINED_JOURNAL_ROWS, 'journal_row_bound')
    by_unit = {unit: [] for unit in units}
    for line in lines:
        value = parsed(line)
        need(isinstance(value, dict), 'journal_format')
        matches = {item for key in ('_SYSTEMD_UNIT', 'UNIT', 'OBJECT_SYSTEMD_UNIT')
                   if isinstance((item := value.get(key)), str) and item in by_unit}
        if len(matches) != 1:
            continue
        unit = matches.pop()
        stamp, priority = value.get('__REALTIME_TIMESTAMP'), value.get('PRIORITY')
        need(isinstance(stamp, str) and re.fullmatch(r'[0-9]{1,20}', stamp)
             and isinstance(priority, str) and priority in tuple('0123456'), 'journal_fields')
        at = int(stamp) // 1000000
        need(now - LOOKBACK * 60 <= at <= now, 'journal_time')
        classified = classify_message(value.get('MESSAGE'))
        if int(priority) > 3 and classified['kind'] == 'journal_error':
            continue
        by_unit[unit].append({'at': at, 'priority': int(priority), **classified})
    truncated = len(lines) >= MAX_JOURNAL_ROWS if source_truncated is None else source_truncated
    newest = sorted(((row['at'], unit, index) for unit, rows in by_unit.items()
                     for index, row in enumerate(rows)), reverse=True)[:MAX_RETAINED_ERRORS]
    retained = {(unit, index) for _, unit, index in newest}
    result = {}
    for unit, rows in by_unit.items():
        selected = sorted((row for index, row in enumerate(rows) if (unit, index) in retained),
                          key=lambda row: row['at'], reverse=True)[:MAX_ERRORS]
        result[unit] = {'recent_errors': selected,
            'error_observations': {'count': len(rows), 'first_at': min((row['at'] for row in rows), default=None),
                'last_at': max((row['at'] for row in rows), default=None), 'scope': 'bounded_journal_sample'},
            'retained_errors_truncated': len(selected) < len(rows)}
    return result, truncated


def validate_error(value, since, until):
    need(isinstance(value, dict) and isinstance(value.get('kind'), str) and value['kind'] in KINDS, 'error_schema')
    base = {'at', 'priority', 'kind'}
    fields = {'python_exception': {'exception'}, 'python_location': {'source', 'line'},
              'process_exit': {'exit_code', 'exit_kind'}, 'unit_result': {'result'},
              'start_step': {'step'}, 'known_error_code': {'code'}}.get(value['kind'], set())
    need(set(value) == base | fields and type(value['at']) is int and since <= value['at'] <= until
         and type(value['priority']) is int and 0 <= value['priority'] <= 6, 'error_schema')
    if fields:
        if value['kind'] == 'python_exception': need(isinstance(value['exception'], str) and value['exception'] in EXCEPTIONS, 'error_value')
        if value['kind'] == 'python_location':
            need(isinstance(value['source'], str) and value['source'] in SOURCE_NAMES and type(value['line']) is int
                 and 0 <= value['line'] < 1000000, 'error_value')
        if value['kind'] == 'process_exit':
            need(type(value['exit_code']) is int and 0 <= value['exit_code'] <= 255
                 and isinstance(value['exit_kind'], str) and value['exit_kind'] in ('exited', 'killed', 'dumped'), 'error_value')
        if value['kind'] == 'unit_result': need(isinstance(value['result'], str) and value['result'] in RESULTS, 'error_value')
        if value['kind'] == 'start_step': need(isinstance(value['step'], str) and value['step'] in STEPS, 'error_value')
        if value['kind'] == 'known_error_code': need(isinstance(value['code'], str) and value['code'] in ERROR_CODES, 'error_value')


def validate_snapshot(value, expected_host=None, now=None, require_fresh=True):
    now = int(time.time()) if now is None else now
    need(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] in (1, 2)
         and set(value) == {'schema', 'host', 'checked_at', 'expires_at',
         'lookback_minutes', 'units'} | ({'runtime'} if value['schema'] == 2 else set()),
         'snapshot_schema')
    host = value['host']
    need(host in ROLE_HOST.values() and (expected_host is None or host == expected_host), 'snapshot_host')
    need(type(value['checked_at']) is int and type(value['expires_at']) is int
         and value['expires_at'] == value['checked_at'] + TTL and value['checked_at'] <= now + 5
         and type(value['lookback_minutes']) is int and value['lookback_minutes'] == LOOKBACK,
         'snapshot_time')
    need(not require_fresh or now <= value['expires_at'], 'snapshot_stale')
    expected = next(PROFILES[role] for role, item in ROLE_HOST.items() if item == host)
    need(isinstance(value['units'], dict) and set(value['units']) == set(expected), 'snapshot_targets')
    for target, row in value['units'].items():
        need(isinstance(row, dict) and set(row) == {'unit', 'status', 'properties', 'recent_errors',
             'journal_status', 'journal_truncated', 'error_observations', 'retained_errors_truncated'} and row['unit'] == expected[target]
             and row['status'] in ('observed', 'unavailable')
             and row['journal_status'] in ('observed', 'unavailable')
             and type(row['journal_truncated']) is bool and type(row['retained_errors_truncated']) is bool, 'unit_schema')
        props = row['properties']
        need(isinstance(props, dict) and set(props) == set(PROPERTIES), 'unit_properties')
        for key, item in props.items():
            need(item is None or (key in TEXT_PROPERTIES and isinstance(item, str)
                 and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', item)) or
                 (key in NUMBER_PROPERTIES and type(item) is int and 0 <= item <= 2**63 - 1), 'unit_property')
        need((row['status'] != 'observed' or props['LoadState'] is not None)
             and (row['status'] != 'unavailable' or all(item is None for item in props.values())),
             'unit_observation')
        need(isinstance(row['recent_errors'], list) and len(row['recent_errors']) <= MAX_ERRORS
             and (row['journal_status'] != 'unavailable' or not row['recent_errors']), 'unit_errors')
        counts = row['error_observations']
        need(isinstance(counts, dict) and set(counts) == {'count', 'first_at', 'last_at', 'scope'}
             and counts['scope'] == 'bounded_journal_sample', 'error_counts')
        if row['journal_status'] == 'unavailable':
            need(counts['count'] is None and counts['first_at'] is None and counts['last_at'] is None, 'error_counts')
        else:
            count = counts['count']
            need(type(count) is int and len(row['recent_errors']) <= count <= MAX_COMBINED_JOURNAL_ROWS, 'error_counts')
            if count == 0:
                need(counts['first_at'] is None and counts['last_at'] is None, 'error_counts')
            else:
                need(type(counts['first_at']) is int and type(counts['last_at']) is int
                     and value['checked_at'] - LOOKBACK * 60 <= counts['first_at'] <= counts['last_at'] <= value['checked_at'],
                     'error_counts')
        for error in row['recent_errors']:
            validate_error(error, value['checked_at'] - LOOKBACK * 60, value['checked_at'])
    if value['schema'] == 2:
        role = next(r for r, h in ROLE_HOST.items() if h == host)
        runtime_library().validate(value['runtime'], role, value['checked_at'])
    need(len(encode(value)) <= MAX_SNAPSHOT, 'snapshot_byte_bound')
    return value


def read_snapshot(expected_host=None, now=None):
    gid = grp.getgrnam('capstone-diagnostics').gr_gid
    return validate_snapshot(parsed(root_file(SNAPSHOT, MAX_SNAPSHOT, 0o640, gid)), expected_host, now)


def collect(role, runner=bounded_command, now=None, include_runtime=None):
    need(role in PROFILES, 'invalid_role')
    now = int(time.time()) if now is None else now
    profile = PROFILES[role]
    value = {'schema': 1, 'host': ROLE_HOST[role], 'checked_at': now, 'expires_at': now + TTL,
             'lookback_minutes': LOOKBACK, 'units': {}}
    for target, unit in profile.items():
        properties = dict.fromkeys(PROPERTIES)
        status = 'unavailable'
        try:
            code, raw = runner(['/usr/bin/systemctl', 'show', '--no-pager',
                '--property=' + ','.join(('Id', *PROPERTIES)), unit], 8192, 3)
            need(code in (0, 1), 'unit_query_failed')
            properties = parse_properties(raw, unit)
            status = 'observed'
        except (DiagnosticError, OSError):
            pass
        value['units'][target] = {'unit': unit, 'status': status, 'properties': properties,
            'recent_errors': [], 'journal_status': 'unavailable', 'journal_truncated': False,
            'error_observations': {'count': None, 'first_at': None, 'last_at': None, 'scope': 'bounded_journal_sample'},
            'retained_errors_truncated': False}
    try:
        prefix = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json',
            '--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,UNIT,OBJECT_SYSTEMD_UNIT,PRIORITY,MESSAGE',
            '--since=@' + str(now - LOOKBACK * 60), '--until=@' + str(now),
            '--lines=' + str(MAX_JOURNAL_ROWS), *('--unit=' + unit for unit in profile.values())]
        parts, truncated = [], False
        # Service stderr can have journal priority info. Keep that stream only
        # when a fixed error classifier pattern matches; ordinary bodies never
        # become error observations. The priority ranges are disjoint.
        for filters in (['--priority=err'], ['--priority=warning..info', '--grep=' + ERROR_PATTERN]):
            code, raw = runner(prefix + filters, MAX_JOURNAL_QUERY, 8)
            need(code == 0, 'journal_query_failed')
            lines = raw.splitlines()
            need(len(lines) <= MAX_JOURNAL_ROWS, 'journal_row_bound')
            truncated |= len(lines) == MAX_JOURNAL_ROWS
            parts.extend(lines)
        errors, truncated = journal_errors(b'\n'.join(parts), profile.values(), now, truncated)
        for row in value['units'].values():
            row.update(**errors[row['unit']], journal_status='observed', journal_truncated=truncated)
    except (DiagnosticError, OSError):
        pass
    if include_runtime is True or (include_runtime is None and runner is bounded_command and Path('/etc/capstone-diagnostics/runtime.json').exists()):
        value['schema'] = 2
        value['runtime'] = runtime_library().collect(role, runner, now)
    return validate_snapshot(value, ROLE_HOST[role], now)


def publish(value):
    need(os.getuid() == os.geteuid() == 0, 'collector_root_required')
    validate_snapshot(value)
    trusted_parents(SNAPSHOT.parent)
    gid = grp.getgrnam('capstone-diagnostics').gr_gid
    if SNAPSHOT.exists() or SNAPSHOT.is_symlink():
        root_file(SNAPSHOT, MAX_SNAPSHOT, 0o640, gid)
    descriptor, temporary = tempfile.mkstemp(prefix='.snapshot-', dir=SNAPSHOT.parent)
    try:
        with os.fdopen(descriptor, 'wb') as destination:
            os.fchmod(destination.fileno(), 0o640)
            os.fchown(destination.fileno(), 0, gid)
            destination.write(encode(value)); destination.flush(); os.fsync(destination.fileno())
        os.replace(temporary, SNAPSHOT)
        parent = os.open(SNAPSHOT.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--collect', action='store_true')
    action.add_argument('--check', action='store_true')
    parser.add_argument('--role', required=True, choices=tuple(PROFILES))
    args = parser.parse_args()
    if args.collect:
        need(os.getuid() == os.geteuid() == 0, 'collector_root_required')
        value = collect(args.role)
        publish(value)
    else:
        value = read_snapshot(ROLE_HOST[args.role])
    print(json.dumps({'schema': 1, 'host': value['host'], 'status': 'ready',
        'checked_at': value['checked_at'], 'expires_at': value['expires_at'], 'units': len(value['units'])}, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (DiagnosticError, OSError, KeyError):
        print('{"schema":1,"status":"unavailable","reason":"diagnostics_unavailable"}')
        raise SystemExit(1)
