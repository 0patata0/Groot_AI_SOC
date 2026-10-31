#!/usr/bin/env python3
"""Fixed, sanitized SOC runtime observations for the root diagnostic collector.

The model cannot select commands, paths, URLs or credentials. No remediation is
performed here. Missing evidence remains unavailable, including idle pipelines.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import pwd
import sqlite3
import ssl
import stat
import time
from urllib.parse import urlsplit

CONFIG = Path('/etc/capstone-diagnostics/runtime.json')
ROLE_TARGETS = {
    'security': ('a:waf', 'a:suricata', 'a:collection', 'a:systemd'),
    'siem': ('b:hermes', 'b:ollama', 'b:wazuh-manager', 'b:wazuh-indexer',
             'b:mattermost', 'b:llm', 'b:management-pipeline', 'b:ingestion', 'b:collection', 'b:systemd'),
    'service': ('c:collection', 'c:systemd'),
}
TARGETS = frozenset(t for values in ROLE_TARGETS.values() for t in values)
STATUSES = frozenset(('ok', 'degraded', 'unavailable', 'not_installed'))
CODES = frozenset(('container_stopped', 'container_unhealthy', 'container_restarting',
    'container_oom', 'process_missing', 'runtime_collection_failed', 'stats_stale',
    'agent_disconnected', 'queue_pressure', 'loss_counter_nonzero',
    'collection_telemetry_stale', 'collection_error_nonzero', 'collection_epoch_mismatch',
    'pipeline_probe_stale', 'pipeline_probe_mismatch', 'probe_unavailable',
    'model_not_loaded', 'model_request_failed', 'chat_disconnected',
    'chat_heartbeat_stale', 'job_stalled', 'case_stalled', 'report_delivery_pending',
    'not_installed', 'expected_agent_missing', 'runtime_not_configured', 'inspection_limit_reached', 'rules_failed', 'case_review_required', 'systemd_unit_failed'))
CONTAINERS = {
    'groot': {'a:waf': 'waf', 'a:suricata': 'suricata', 'b:hermes': 'hermes',
        'b:wazuh-manager': 'single-node-wazuh.manager-1',
        'b:wazuh-indexer': 'single-node-wazuh.indexer-1', 'b:mattermost': 'mm-app'},
    'fresh': {'a:waf': 'capstone-security-waf', 'a:suricata': 'capstone-security-suricata',
        'b:hermes': 'capstone-hermes', 'b:wazuh-manager': 'capstone-wazuh-manager',
        'b:wazuh-indexer': 'capstone-wazuh-indexer', 'b:mattermost': 'capstone-mattermost'},
}
CORE_WAZUH = ('wazuh-analysisd', 'wazuh-remoted', 'wazuh-db', 'wazuh-logcollector',
              'wazuh-modulesd', 'wazuh-apid')
LOSS_METRICS = frozenset(('component_discarded_events_total', 'buffer_discarded_events_total',
    'files_unwatched_bytes_unread_total', 'files_unwatched_with_unknown_bytes_total'))


def require(ok, code='invalid_runtime_evidence'):
    if not ok: raise ValueError(code)


def read_file(path, maximum=65536, tail=False, uid=0):
    """Bounded fixed-path read, with no symlink or mutable-file identity switch."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_nlink == 1
                and not before.st_mode & 0o022, 'unsafe_runtime_file')
        if tail: stream.seek(max(0, before.st_size - maximum))
        else: require(before.st_size <= maximum, 'runtime_file_bound')
        raw = stream.read(maximum)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino))
        return raw, before.st_mtime


def endpoint(value):
    u = urlsplit(value)
    require(u.scheme in ('http', 'https') and u.hostname and not u.username and not u.password
            and not u.query and not u.fragment and u.path in ('', '/'), 'runtime_endpoint')
    try: host = ipaddress.ip_address(u.hostname)
    except ValueError:
        # Hostnames come only from the root-installed endpoint configuration,
        # never tool arguments. Match the existing installer's DNS support.
        require(len(u.hostname)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label)
                for label in u.hostname.lower().rstrip('.').split('.')), 'runtime_endpoint')
    else: require(not host.is_multicast and not host.is_unspecified, 'runtime_endpoint')
    return u


def load_config(role):
    c = json.loads(read_file(CONFIG)[0])
    require(set(c) == {'schema', 'role', 'layout', 'llm_url', 'model', 'mattermost_url',
                       'hermes_home', 'ollama_enabled'} and c['schema'] == 1
            and c['role'] == role and c['layout'] in CONTAINERS, 'runtime_config')
    require(c['hermes_home'] in ('/opt/hermes-data', '/opt/capstone/siem/capstone-hermes')
            and type(c['ollama_enabled']) is bool, 'runtime_config')
    if role == 'siem':
        endpoint(c['llm_url']); endpoint(c['mattermost_url'])
        require(isinstance(c['model'], str) and re.fullmatch(r'[a-zA-Z0-9_.:/-]{1,80}', c['model']))
    return c


def observation(kind, now, metrics=None, codes=(), unavailable=False, limits=()):
    return {'kind': kind, 'status': 'unavailable' if unavailable else ('degraded' if codes else 'ok'),
            'observed_at': now, 'codes': sorted(set(codes)), 'metrics': metrics or {},
            'limits': list(limits)}


def validate(rows, role, now):
    require(isinstance(rows, dict) and set(rows) == set(ROLE_TARGETS[role]), 'runtime_targets')
    for target, row in rows.items():
        require(isinstance(row, dict) and set(row) == {'kind', 'status', 'observed_at', 'codes', 'metrics', 'limits'}
                and isinstance(row['status'], str) and row['status'] in STATUSES and type(row['observed_at']) is int
                and 0 <= row['observed_at'] <= now + 5, 'runtime_row')
        require(isinstance(row['kind'], str) and re.fullmatch(r'[a-z_]{1,32}', row['kind']))
        require(isinstance(row['codes'], list) and len(row['codes']) <= 16
                and all(isinstance(c, str) and c in CODES for c in row['codes']), 'runtime_codes')
        require(isinstance(row['limits'], list) and len(row['limits']) <= 12
                and all(isinstance(s, str) and re.fullmatch(r'[a-z_]{1,80}', s) for s in row['limits']))
        metrics = row['metrics']
        require(isinstance(metrics, dict) and len(metrics) <= 80, 'runtime_metrics')
        for key, value in metrics.items():
            require(isinstance(key, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', key))
            require(value is None or type(value) is bool or
                    type(value) in (int, float) and math.isfinite(value) and abs(value) <= 2**63 or
                    isinstance(value, str) and (re.fullmatch(r'[a-zA-Z0-9_.:+-]{1,80}', value) or
                        target.endswith(':systemd') and re.fullmatch(r'failed_unit_[0-9]+', key)
                        and re.fullmatch(r'[a-zA-Z0-9_.:@\\-]{1,255}', value)), 'runtime_metric_value')
    require(len(json.dumps(rows).encode()) <= 32768, 'runtime_size')
    return rows


def command(runner, argv, maximum=65536, seconds=4, allowed=(0,)):
    rc, raw = runner(argv, maximum, seconds)
    require(rc in allowed, 'runtime_command_failed')
    return raw.decode('utf-8', 'strict')


def request_json(url, path, timeout=4, body=None):
    u = endpoint(url)
    cls = http.client.HTTPSConnection if u.scheme == 'https' else http.client.HTTPConnection
    conn = cls(u.hostname, u.port, timeout=timeout)
    try:
        payload = None if body is None else json.dumps(body).encode()
        conn.request('GET' if body is None else 'POST', path, body=payload,
                     headers={'Content-Type': 'application/json'})
        response = conn.getresponse(); require(response.status == 200, 'runtime_http_status')
        raw = response.read(131073); require(len(raw) <= 131072, 'runtime_http_bound')
        return json.loads(raw)
    finally: conn.close()


def docker_binary(cfg):
    return '/usr/local/bin/docker' if cfg['layout']=='groot' else '/usr/bin/docker'


def container(target, cfg, runner, now):
    name = CONTAINERS[cfg['layout']][target]
    state = json.loads(command(runner, [docker_binary(cfg), 'inspect', '--format', '{{json .State}}', name]))
    metrics = {'running': bool(state['Running']), 'restarting': bool(state['Restarting']),
               'oom_killed': bool(state['OOMKilled']), 'exit_code': int(state['ExitCode'])}
    health = state.get('Health', {}).get('Status', 'not_reported')
    require(health in ('healthy', 'unhealthy', 'starting', 'not_reported'))
    metrics['docker_health'] = health
    codes = []
    if not metrics['running']: codes.append('container_stopped')
    if metrics['restarting']: codes.append('container_restarting')
    if metrics['oom_killed']: codes.append('container_oom')
    if health in ('unhealthy', 'starting'): codes.append('container_unhealthy')
    return observation('container', now, metrics, codes, limits=('container_state_is_not_end_to_end_health',))


def pairs(text):
    return {k: float(v) if '.' in v else int(v) for k, v in
        re.findall(r"^([a-zA-Z_][a-zA-Z_0-9]*)=['\"]?([0-9]+(?:\.[0-9]+)?)['\"]?\s*$", text, re.M)}


def wazuh(cfg, runner, now):
    row = container('b:wazuh-manager', cfg, runner, now)
    if not row['metrics']['running']: return row
    name = CONTAINERS[cfg['layout']]['b:wazuh-manager'];prefix = [docker_binary(cfg), 'exec', name]
    text = command(runner, prefix + ['/var/ossec/bin/wazuh-control', 'status'], allowed=(0, 1))
    codes = row['codes'];metrics = row['metrics']
    for proc in CORE_WAZUH:
        present = text.splitlines().count(proc + ' is running...') == 1
        metrics[proc.replace('-', '_') + '_running'] = present
        if not present: codes.append('process_missing')
    for short in ('analysisd', 'remoted'):
        path = '/var/ossec/var/run/wazuh-' + short + '.state'
        content = command(runner, prefix + ['cat', path]);values = pairs(content)
        age = max(0, now - int(command(runner, prefix + ['stat', '-c', '%Y', path]).strip()))
        metrics[short + '_state_age_seconds'] = age
        if age > 180: codes.append('stats_stale')
        required = ('events_received', 'events_processed', 'events_dropped', 'event_queue_usage') if short == 'analysisd' else ('queue_size', 'total_queue_size', 'discarded_count')
        require(all(k in values for k in required), 'runtime_missing_stats')
        for key in required: metrics[short + '_' + key] = values[key]
        losses = values['events_dropped' if short == 'analysisd' else 'discarded_count']
        if losses > 0: codes.append('loss_counter_nonzero')
        ratio = max((v for k, v in values.items() if k.endswith('_queue_usage')), default=0) if short == 'analysisd' else values['queue_size'] / max(1, values['total_queue_size'])
        metrics[short + '_max_queue_ratio'] = ratio
        if ratio >= .8: codes.append('queue_pressure')
    row.update(kind='wazuh_manager', status='degraded' if codes else 'ok', codes=sorted(set(codes)),
               limits=['counters_are_since_process_start', 'zero_drops_is_not_full_delivery_proof'])
    return row


def host_executable(pid, name):
    """Same executable inode, not a same-named process inside a container."""
    try:
        expected = Path('/var/ossec/bin', name).stat()
        actual = Path('/proc', str(pid), 'exe').stat()
        return (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino)
    except OSError:
        return False


def agent_collection(role, runner, now):
    metrics = {};codes = []
    for proc in ('wazuh-agentd', 'wazuh-logcollector'):
        text=command(runner,['/usr/bin/pgrep','-x',proc[:15]],allowed=(0,1))
        pids=[int(p) for p in text.split() if p.isdecimal()]
        present = sum(host_executable(pid, proc) for pid in pids[:128]) == 1
        if len(pids) > 128: codes.append('inspection_limit_reached')
        metrics[proc.replace('-', '_') + '_running']=present
        if not present: codes.append('process_missing')
    raw, mtime = read_file('/var/ossec/var/run/wazuh-agentd.state', uid=pwd.getpwnam('wazuh').pw_uid)
    body = raw.decode();values = pairs(body)
    metrics['agent_state_age_seconds'] = max(0, now - int(mtime))
    metrics['agent_connected'] = bool(re.search(r"^status=['\"]?connected['\"]?\s*$", body, re.M))
    if not metrics['agent_connected']: codes.append('agent_disconnected')
    if metrics['agent_state_age_seconds'] > 180: codes.append('stats_stale')
    for name in ('msg_buffer', 'msg_buffer_size', 'msg_count', 'msg_sent'):
        if name in values: metrics[name] = values[name]
    if role == 'security':
        raw, mtime = read_file('/var/log/capstone-vector/telemetry/health.jsonl', 1048576, tail=True)
        lines = raw.splitlines()[1:];records = []
        for line in lines:
            if not line: continue
            item = json.loads(line)['capstone_collection_health']
            require(isinstance(item, dict) and isinstance(item.get('observed_unix'), (int, float)))
            records.append(item)
        props = command(runner, ['/usr/bin/systemctl', 'show', 'capstone-vector.service', '--property=MainPID,InvocationID', '--no-pager'])
        current = dict(x.split('=', 1) for x in props.splitlines() if '=' in x)
        records = [r for r in records if str(r.get('vector_pid')) == current.get('MainPID') and r.get('invocation_id') == current.get('InvocationID')]
        heartbeat = max((r['observed_unix'] for r in records if r.get('metric') == 'uptime_seconds'), default=0)
        metrics['vector_heartbeat_age_seconds'] = max(0, now - int(heartbeat)) if heartbeat else None
        if not heartbeat or now - heartbeat > 180: codes.append('collection_telemetry_stale')
        latest = {}
        for r in records:
            key = (r.get('component'), r.get('metric'), json.dumps(r.get('labels', {}), sort_keys=True))
            if key not in latest or r['observed_unix'] > latest[key]['observed_unix']: latest[key] = r
        metrics['vector_loss_series_nonzero'] = sum(r.get('metric') in LOSS_METRICS and r.get('value', 0) > 0 for r in latest.values())
        metrics['vector_error_series_nonzero'] = sum(r.get('metric') == 'component_errors_total' and r.get('value', 0) > 0 for r in latest.values())
        if metrics['vector_loss_series_nonzero']: codes.append('loss_counter_nonzero')
        if metrics['vector_error_series_nonzero']: codes.append('collection_error_nonzero')
    if role == 'security':
        try:
            receipt = json.loads(read_file('/var/lib/capstone-diagnostics/canary-input.json')[0])
            require(re.fullmatch('[0-9a-f]{32}',receipt['run_id']) and type(receipt['checked_at']) is int)
            metrics.update(canary_run_id=receipt['run_id'],canary_input_at=receipt['checked_at'],canary_input_verified=receipt['success'] is True)
        except (OSError, ValueError, KeyError):
            metrics['canary_input_verified'] = False
        try:
            receipt=json.loads(read_file('/var/lib/capstone-diagnostics/observer.json')[0])
            metrics.update(observer_age_seconds=max(0,now-receipt['checked_at']),pending_notifications=receipt['pending_notifications'],observer_delivery_ok=receipt['delivery_ok'] is True)
            if receipt['delivery_ok'] is not True: codes.append('report_delivery_pending')
            if now-receipt['checked_at']>180: codes.append('stats_stale')
        except (OSError, ValueError, KeyError): codes.append('stats_stale')
    return observation('collection', now, metrics, codes, limits=('heartbeat_is_not_event_delivery_proof', 'idle_events_are_not_collection_health'))


def heartbeat(path, now, uid, engine, expected_pid=None, expected_start=None):
    path = Path(path);raw, _ = read_file(path, uid=uid)
    value = json.loads(raw)
    require(set(value) == {'schema', 'engine', 'pid', 'checked_at', 'websocket_connected', 'worker_alive', 'process_start_ticks'}
            and value['schema'] == 1 and value['engine'] == engine
            and type(value['pid']) is int and value['pid'] > 0
            and type(value['process_start_ticks']) is int
            and value['pid'] == expected_pid and value['process_start_ticks'] == expected_start
            and type(value['checked_at']) in (int, float) and value['checked_at'] <= now + 5
            and type(value['websocket_connected']) is bool and type(value['worker_alive']) is bool)
    metrics = {'heartbeat_age_seconds': max(0, now - int(value['checked_at'])),
               'websocket_connected': value['websocket_connected'], 'worker_alive': value['worker_alive']}
    codes = []
    if metrics['heartbeat_age_seconds'] > 90: codes.append('chat_heartbeat_stale')
    if not metrics['websocket_connected']: codes.append('chat_disconnected')
    if not metrics['worker_alive']: codes.append('job_stalled')
    return metrics, codes


def bot(target, cfg, runner, now):
    engine = target.split(':')[1]
    if engine == 'ollama' and not cfg['ollama_enabled']:
        row = observation('chat_gateway', now, codes=['not_installed']);row['status'] = 'not_installed';return row
    row = container(target, cfg, runner, now) if engine == 'hermes' else observation('chat_gateway', now)
    if engine == 'ollama':
        active = command(runner, ['/usr/bin/systemctl', 'is-active', 'capstone-ollama-chat.service'], allowed=(0, 3)).strip() == 'active'
        row['metrics']['service_active'] = active
        if not active: row['codes'].append('process_missing')
    path = cfg['hermes_home'] + '/health/chat.json' if engine == 'hermes' else '/var/lib/capstone-ollama-trial/chat/health.json'
    try:
        if engine == 'hermes':
            user = 'capstone-hermes' if cfg['layout'] == 'fresh' else 'hermes'
            # Namespace PID and start ticks are read from the current container,
            # so receipts from a previous container cannot appear healthy.
            identity = json.loads(command(runner, [docker_binary(cfg),'exec',CONTAINERS[cfg['layout']][target],
                'python','-I','-B','-c',
                "import json,pathlib;v=json.loads(pathlib.Path('/opt/data/health/chat.json').read_text());p=pathlib.Path('/proc')/str(v['pid'])/'stat';print(json.dumps([v['pid'],int(p.read_text().rsplit(')',1)[1].split()[19]),p.stat().st_uid]))"]))
            pid, start, uid = identity
        else:
            uid = pwd.getpwnam('soc-ollama').pw_uid
            pid = int(command(runner, ['/usr/bin/systemctl','show','capstone-ollama-chat.service','--property=MainPID','--value']).strip())
            start = int(Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19])
        metrics, codes = heartbeat(path, now, uid, engine, pid, start)
        row['metrics'].update(metrics);row['codes'] += codes
        database = cfg['hermes_home']+'/state.db' if engine=='hermes' else '/var/lib/capstone-ollama-trial/chat/queue.sqlite'
        with sqlite3.connect('file:'+database+'?mode=ro',uri=True,timeout=2) as db:
            if engine == 'hermes':
                jobs = db.execute('select count(*),min(acquired_at) from session_turn_leases where expires_at>?',(now,)).fetchone()
            else:
                jobs = db.execute("select count(*),min(json_extract(post,'$.create_at')/1000) from jobs where status not in ('done','abandoned')").fetchone()
        age = max(0,now-jobs[1]) if jobs[1] else 0
        row['metrics'].update(pending_jobs=jobs[0],oldest_job_seconds=age)
        if age > 1800: row['codes'].append('job_stalled')
    except (OSError, ValueError, KeyError, sqlite3.Error): row['codes'].append('chat_heartbeat_stale')
    row.update(kind='chat_gateway', status='degraded' if row['codes'] else 'ok', codes=sorted(set(row['codes'])),
               limits=['gateway_heartbeat_is_not_full_model_tool_delivery_proof'])
    return row


def process_start(pid):
    require(type(pid) is int and pid > 0)
    return int(Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19])


def review_chat(now, runner):
    value = json.loads(read_file('/var/lib/capstone-review-chat/health.json')[0])
    pid = int(command(runner, ['/usr/bin/systemctl','show','capstone-review-chat.service','--property=MainPID','--value']).strip())
    require(value['pid'] == pid and value['process_start_ticks'] == process_start(pid)
            and type(value['pending']) is int and value['pending'] >= 0
            and all(type(value[k]) in (int,float) and 0 < value[k] <= now+5 for k in ('at','last_poll')))
    oldest = value.get('oldest_pending_at')
    require(oldest is None or type(oldest) in (int,float) and 0 < oldest <= now+5)
    metrics = {'review_chat_installed': True, 'review_chat_poll_age_seconds': max(0, now-value['last_poll']),
               'review_chat_pending_jobs': value['pending'], 'review_chat_oldest_job_seconds': max(0,now-oldest) if oldest else 0}
    codes = []
    if now-value['at']>30 or metrics['review_chat_poll_age_seconds']>30: codes.append('chat_heartbeat_stale')
    if metrics['review_chat_oldest_job_seconds']>1800: codes.append('job_stalled')
    return metrics, codes


def management(now, runner=None):
    # SQLite may need its WAL/SHM sidecars even for a read-only connection.
    # The collector unit permits that one directory; SQL stays query-only.
    with sqlite3.connect('file:/var/lib/capstone-management/state.sqlite3?mode=ro', uri=True, timeout=2) as db:
        db.execute('pragma query_only=ON')
        pending = db.execute("select count(*),min(created) from report_outbox where delivery_state='pending'").fetchone()
        runs = db.execute("select count(*),min(started) from runs where state='running'").fetchone()
        due = db.execute("select count(*),min(due) from cases where state in ('ready','monitor','waiting_approval','review_ready') and due<?",(now,)).fetchone()
        review = db.execute("select count(*) from cases where state in ('needs_review','outcome_unknown','review_ready')").fetchone()[0]
    metrics = {'pending_reports': pending[0], 'oldest_report_seconds': max(0, now - pending[1]) if pending[1] else 0,
               'running_cases': runs[0], 'oldest_case_seconds': max(0, now - runs[1]) if runs[1] else 0,
               'overdue_cases':due[0], 'oldest_overdue_seconds':max(0,now-due[1]) if due[1] else 0, 'review_required_cases':review}
    codes = []
    if review: codes.append('case_review_required')
    if metrics['oldest_report_seconds'] > 180: codes.append('report_delivery_pending')
    if metrics['oldest_case_seconds'] > 900 or metrics['oldest_overdue_seconds'] > 900: codes.append('case_stalled')
    metrics['review_chat_installed'] = Path('/etc/capstone-review-chat/config.json').exists()
    if metrics['review_chat_installed']:
        try:
            extra, more = review_chat(now, runner);metrics.update(extra);codes.extend(more)
        except (OSError, ValueError, KeyError, TypeError):
            codes.append('chat_heartbeat_stale')
    return observation('management_pipeline', now, metrics, codes, limits=('no_pending_case_is_not_security_clearance',))


def probe_receipt(kind, now):
    value = json.loads(read_file('/var/lib/capstone-diagnostics/' + kind + '-probe.json')[0])
    require(value.get('schema') == 1 and type(value.get('checked_at')) is int and value['checked_at'] <= now + 5)
    metrics = {'probe_age_seconds': max(0, now - value['checked_at']), 'probe_succeeded': value.get('success') is True}
    codes = []
    if kind == 'ingestion':
        metrics['canary_allowed'] = value.get('canary_allowed') is True
        at=value.get('input_at')
        metrics['input_age_seconds'] = max(0,now-at) if type(at) is int and at>0 else None
        if metrics['input_age_seconds'] is None or metrics['input_age_seconds']>1200: codes.append('pipeline_probe_stale')
        if value.get('success') is True:
            require(isinstance(value.get('run_id'),str) and re.fullmatch('[0-9a-f]{32}',value['run_id']))
            metrics['verified_run_id']=value['run_id']
            require(value.get('manager_matches')==2 and value.get('indexer_matches')==2 and value.get('exact_tuples_match') is True)
    if metrics['probe_age_seconds'] > (1200 if kind == 'ingestion' else 600): codes.append('pipeline_probe_stale')
    if not metrics['probe_succeeded']: codes.append('pipeline_probe_mismatch' if kind == 'ingestion' else 'model_request_failed')
    return observation(kind + '_probe', now, metrics, codes, limits=('bounded_synthetic_probe_not_all_events',))


def systemd_failures(runner, now):
    """All loaded failed units, independent of the curated diagnostic catalog.

    Return identities and state only; descriptions/raw journal never leave the
    root collector. A failed command cannot turn into a zero-failure report.
    """
    text = command(runner, ['/usr/bin/systemctl', 'list-units', '--failed', '--all',
                           '--no-legend', '--no-pager', '--plain'], maximum=131072, seconds=6)
    units = {}
    for line in text.splitlines():
        if not line.strip(): continue
        fields = line.split(None, 4)
        require(len(fields) >= 4 and re.fullmatch(r'[a-zA-Z0-9_.:@\\-]{1,255}', fields[0])
                and fields[2] == 'failed' and fields[0] not in units, 'systemd_list_invalid')
        require(all(re.fullmatch(r'[a-z][a-z-]{0,47}', s) for s in fields[1:4]), 'systemd_state_invalid')
        units[fields[0]] = fields[1:4]
        require(len(units) <= 512, 'systemd_list_bound')
    metrics = {'failed_units_total': len(units), 'returned_units': min(len(units), 16),
               'unit_list_truncated': len(units) > 16}
    for i, (unit, states) in enumerate(sorted(units.items())[:16]):
        metrics['failed_unit_' + str(i)] = unit
        for key, value in zip(('load', 'active', 'sub'), states):
            metrics['unit_' + str(i) + '_' + key] = value
    codes = (['systemd_unit_failed'] if units else []) + (['inspection_limit_reached'] if len(units) > 16 else [])
    return observation('systemd_failed_units', now, metrics, codes,
        limits=['loaded_failed_units_only', 'not_a_historical_journal_query',
                'zero_failed_units_is_not_all_services_healthy', 'unit_detail_requires_registered_target'])


def collect_one(target, cfg, runner, now):
    if target.endswith(':systemd'): return systemd_failures(runner, now)
    if target == 'b:wazuh-manager': return wazuh(cfg, runner, now)
    if target in ('a:collection', 'b:collection', 'c:collection'): return agent_collection(cfg['role'], runner, now)
    if target in ('b:hermes', 'b:ollama'): return bot(target, cfg, runner, now)
    if target == 'b:management-pipeline': return management(now, runner)
    if target == 'b:ingestion': return probe_receipt('ingestion', now)
    if target == 'b:llm':
        models = request_json(cfg['llm_url'], '/api/ps').get('models', [])
        loaded = any(m.get('name') == cfg['model'] or m.get('model') == cfg['model'] for m in models)
        row = probe_receipt('model', now);row['metrics']['model_loaded'] = loaded
        # A model may unload between bounded probes; that is not a failure.
        return row
    row = container(target, cfg, runner, now)
    if target == 'a:suricata' and row['metrics']['running']:
        prefix=[docker_binary(cfg),'exec',CONTAINERS[cfg['layout']][target]]
        raw=command(runner,prefix+['tail','-c','2097152','/var/log/suricata/eve.json'],maximum=2097152)
        events=[]
        for line in raw.splitlines()[1:]:
            try:
                event=json.loads(line)
                if event.get('event_type')=='stats': events.append(event)
            except ValueError: pass
        require(bool(events),'suricata_stats_missing')
        event=events[-1];stats=event['stats'];capture=stats['capture'];detect=stats['detect']
        stamp=datetime.fromisoformat(event['timestamp'])
        require(stamp.utcoffset() is not None and stamp.timestamp()<=now+5)
        age=max(0,now-int(stamp.timestamp()))
        require(all(type(capture.get(k)) is int and capture[k]>=0 for k in ('kernel_packets','kernel_drops','errors')))
        metrics=row['metrics'];metrics.update(engine_stats_age_seconds=age,kernel_packets=capture['kernel_packets'],
            kernel_drops=capture['kernel_drops'],capture_errors=capture['errors'],engine_uptime_seconds=stats['uptime'])
        engines=detect['engines'];require(isinstance(engines,list) and 1<=len(engines)<=16)
        for key in ('rules_loaded','rules_failed','rules_skipped'):
            require(all(type(e.get(key)) is int and e[key]>=0 for e in engines));metrics[key]=sum(e[key] for e in engines)
        for key in ('ssn_memcap_drop','segment_memcap_drop','reassembly_gap','stream_depth_reached'):
            value=stats['tcp'][key];require(type(value) is int and value>=0);metrics['tcp_'+key]=value
        metrics['alert_queue_overflow']=detect['alert_queue_overflow']
        if age>180: row['codes'].append('stats_stale')
        if any(metrics[k]>0 for k in ('kernel_drops','tcp_ssn_memcap_drop','tcp_segment_memcap_drop','alert_queue_overflow')): row['codes'].append('loss_counter_nonzero')
        if capture['errors']>0: row['codes'].append('collection_error_nonzero')
        if metrics['rules_failed']>0: row['codes'].append('rules_failed')
        if metrics['tcp_stream_depth_reached']>0 or metrics['tcp_reassembly_gap']>0: row['codes'].append('inspection_limit_reached')
        row.update(kind='suricata_runtime',status='degraded' if row['codes'] else 'ok',
            limits=['counters_are_since_engine_start','depth_limit_counter_is_not_current_attack_proof','per_rule_detection_not_verified'])
    if target == 'b:wazuh-indexer':
        cert='/usr/share/wazuh-indexer/config/certs/'
        raw=command(runner,[docker_binary(cfg),'exec',CONTAINERS[cfg['layout']][target],
            'curl','--disable','--silent','--fail','--max-time','3','--max-filesize','65536',
            '--cacert',cert+'root-ca.pem','--cert',cert+'admin.pem','--key',cert+'admin-key.pem',
            'https://wazuh.indexer:9200/_cluster/health?timeout=2s'],seconds=4)
        health=json.loads(raw)
        require(health.get('status') in ('green','yellow','red') and health.get('timed_out') is False)
        row['metrics']['cluster_status']=health['status']
        if health['status']=='red': row['codes'].append('container_unhealthy');row['status']='degraded'
        row['limits']=['yellow_can_be_expected_for_single_node','cluster_health_is_not_delivery_proof']
    if target == 'b:mattermost':
        ping = request_json(cfg['mattermost_url'], '/api/v4/system/ping')
        require(ping.get('status') == 'OK');row['metrics']['api_ping_ok'] = True
    return row


def collect(role, runner, now):
    try: cfg = load_config(role)
    except (OSError, ValueError, KeyError):
        return {t: observation('runtime', now, codes=['runtime_not_configured'], unavailable=True) for t in ROLE_TARGETS[role]}
    def one(target):
        try: return target, collect_one(target, cfg, runner, now)
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, http.client.HTTPException, TimeoutError):
            return target, observation('runtime', now, codes=['runtime_collection_failed'], unavailable=True)
    with ThreadPoolExecutor(max_workers=4) as pool: rows = dict(pool.map(one, ROLE_TARGETS[role]))
    return validate(rows, role, now)
