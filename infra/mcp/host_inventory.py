"""Fixed root-collected inventory, read through an unprivileged snapshot.

No command arguments, file paths, environment, container commands or process
command lines are accepted or returned. Running is not functional health.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import grp
import json
import os
from pathlib import Path
import re
import tempfile
import time
import hashlib
import ipaddress
import stat

SNAPSHOT = Path('/var/lib/capstone-diagnostics/inventory.json')
MAX_BYTES = 2097152
MAX_ROWS = 4096
VIEWS = ('services', 'containers', 'ports', 'resources', 'processes',
         'container_details', 'container_stats', 'container_logs', 'service_details', 'network', 'storage')
COLUMNS = {
    'services': ('unit', 'load', 'active', 'sub'),
    'containers': ('id', 'name', 'image', 'state', 'status'),
    'ports': ('protocol', 'state', 'local', 'peer'),
    'resources': ('metric', 'value', 'unit'),
    'processes': ('pid', 'name', 'cpu_percent', 'memory_percent'),
    'container_details': ('name', 'field', 'value'),
    'container_stats': ('name', 'field', 'value'),
    'container_logs': ('name', 'at_kst', 'message', 'message_state', 'message_sha256'),
    'service_details': ('unit', 'field', 'value'),
    'network': ('category', 'name', 'value'),
    'storage': ('filesystem', 'type', 'total_bytes', 'used_bytes', 'available_bytes', 'usage_percent', 'mount'),
}


def request(value):
    core.need(isinstance(value, dict) and {'host', 'view'} <= set(value) <=
              {'host', 'view', 'state', 'limit', 'offset', 'container', 'unit'}, 'inventory_arguments')
    host, view = value['host'], value['view']
    state, limit, offset = value.get('state', 'all'), value.get('limit', 20), value.get('offset', 0)
    core.need(host in ('a', 'b', 'c', 'all') and view in VIEWS, 'inventory_scope')
    core.need(state in ('all', 'running', 'failed') and (state == 'all' or view in ('services', 'containers'))
              and (state != 'failed' or view == 'services'),
              'inventory_state')
    core.need(type(limit) is int and 1 <= limit <= 100 and type(offset) is int and 0 <= offset <= MAX_ROWS,
              'inventory_page')
    container = value.get('container')
    core.need((view == 'container_stats' and 'container' not in value) or
              (view.startswith('container_') and isinstance(container, str)
               and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', container))
              or (not view.startswith('container_') and container is None), 'inventory_container')
    unit = value.get('unit')
    core.need((view == 'service_details' and isinstance(unit, str) and
               re.fullmatch(r'[A-Za-z0-9_.@:\\-]{1,240}\.service', unit)) or
              (view != 'service_details' and unit is None), 'inventory_unit')
    return host, view, state, limit, offset


def safe(value):
    core.need(isinstance(value, str) and len(value) <= 1024 and not re.search(r'[\x00-\x1f\x7f]', value),
              'inventory_field')
    return value


def command(runner, argv):
    rc, raw = runner(argv, MAX_BYTES, 5)
    core.need(rc == 0, 'inventory_command_failed')
    return raw.decode('utf-8', errors='strict')


def collect_view(view, runner, docker):
    if view.startswith('container_'):
        return docker_view(view, runner, docker)
    if view == 'service_details':
        units = [row['unit'] for row in collect_view('services', runner, docker)]
        if not units: return []
        fields = ('Id','LoadState','ActiveState','SubState','Type','Result','MainPID','ExecMainCode','ExecMainStatus',
                  'NRestarts','UnitFileState','FragmentPath','MemoryCurrent','MemoryMax','TasksCurrent','TasksMax',
                  'CPUUsageNSec','Restart','RestartUSec','StartLimitBurst','StartLimitIntervalUSec')
        raw = command(runner, ['/usr/bin/systemctl', 'show', '--no-pager', '--property='+','.join(fields), '--', *units])
        rows = []; seen = set()
        for group in raw.strip().split('\n\n'):
            data = dict(line.split('=',1) for line in group.splitlines())
            unit = data['Id']; core.need(unit in units and unit not in seen and set(data) <= set(fields), 'service_detail_scope')
            seen.add(unit)
            rows.extend(dict(unit=unit, field=key, value=safe(data[key])) for key in fields[1:] if key in data)
        core.need(seen == set(units), 'service_detail_missing_units')
        # Many units, bounded fields per unit; separate limit from displayed rows.
        core.need(len(rows) <= 16384, 'service_detail_row_bound')
        return rows
    if view == 'network':
        rows = []
        for entry in json.loads(command(runner, ['/usr/sbin/ip', '-j', 'address', 'show'])):
            selected = {k:entry.get(k) for k in ('ifname','mtu','operstate','flags')}
            selected['addresses'] = [{k:a.get(k) for k in ('family','local','prefixlen','scope')} for a in entry.get('addr_info', [])]
            rows.append(dict(category='interface',name=safe(entry['ifname']),value=safe(json.dumps(selected,separators=(',',':')))))
        for index, entry in enumerate(json.loads(command(runner, ['/usr/sbin/ip', '-j', 'route', 'show', 'table', 'main']))):
            rows.append(dict(category='route',name=str(index),value=safe(json.dumps({k:entry.get(k) for k in
                ('dst','gateway','dev','protocol','scope','prefsrc','metric')},separators=(',',':')))))
        path = Path('/etc/resolv.conf').resolve()
        core.need(str(path) in ('/etc/resolv.conf','/run/systemd/resolve/stub-resolv.conf','/run/systemd/resolve/resolv.conf'), 'dns_file_scope')
        # systemd-resolved owns these data files. They are not executable code
        # or trusted configuration; accept only parsed numeric nameserver IPs.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as file:
            meta = os.fstat(file.fileno())
            core.need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= 16384, 'dns_file_type')
            raw = file.read(16385); core.need(len(raw) <= 16384, 'dns_file_bound')
        for line in raw.decode().splitlines():
            if line.startswith('nameserver '): rows.append(dict(category='dns',name='nameserver',value=str(ipaddress.ip_address(line.split()[1]))))
        return rows
    if view == 'storage':
        raw = command(runner, ['/usr/bin/df', '-PT', '-B1', '--local'])
        rows = []
        for line in raw.splitlines()[1:]:
            parts = line.split(None,6);core.need(len(parts)==7,'storage_row_shape')
            rows.append(dict(zip(COLUMNS[view],map(safe,parts))))
        return rows
    if view == 'services':
        data = json.loads(command(runner, ['/usr/bin/systemctl', 'list-units', '--all', '--type=service',
                                         '--no-pager', '--output=json']))
        core.need(isinstance(data, list), 'inventory_services_shape')
        rows = [{k: safe(row[k]) for k in COLUMNS[view]} for row in data]
        rows.sort(key=lambda row: row['unit'])
    elif view == 'containers':
        raw = command(runner, [docker, 'ps', '--all', '--no-trunc', '--format', '{{json .}}'])
        rows = [{dest: safe(row[src]) for dest, src in
                 zip(COLUMNS[view], ('ID', 'Names', 'Image', 'State', 'Status'))}
                for row in (json.loads(line) for line in raw.splitlines())]
        rows.sort(key=lambda row: row['name'])
    elif view == 'ports':
        rows = []
        for line in command(runner, ['/usr/bin/ss', '-H', '-lntu']).splitlines():
            parts = line.split()
            core.need(len(parts) == 6, 'inventory_ports_shape')
            rows.append(dict(zip(COLUMNS[view], map(safe, (parts[0], parts[1], parts[4], parts[5])))))
        rows.sort(key=lambda row: (row['protocol'], row['local']))
    elif view == 'processes':
        rows = []
        raw = command(runner, ['/usr/bin/ps', '-eo', 'pid=,comm=,pcpu=,pmem=', '--sort=-pcpu'])
        for line in raw.splitlines():
            match = re.fullmatch(r'\s*(\d+)\s+(.+?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s*', line)
            core.need(match is not None, 'inventory_process_shape')
            rows.append(dict(zip(COLUMNS[view], map(safe, match.groups()))))
    else:
        def cpu_sample():
            parts = Path('/proc/stat').read_text().splitlines()[0].split()
            core.need(parts[0] == 'cpu' and len(parts) >= 9, 'cpu_sample_shape')
            ticks = [int(x) for x in parts[1:9]]
            return sum(ticks), ticks[3] + ticks[4]
        first = cpu_sample(); start = time.monotonic(); time.sleep(0.25); last = cpu_sample()
        elapsed = time.monotonic() - start; total = last[0] - first[0]; idle = last[1] - first[1]
        core.need(total > 0 and 0 <= idle <= total, 'cpu_sample_interval')
        rows = [{'metric': 'logical_cpus', 'value': str(os.cpu_count()), 'unit': 'count'}]
        rows += [{'metric': 'cpu_busy_percent', 'value': format(100 * (total-idle) / total, '.1f'), 'unit': '%'},
                 {'metric': 'cpu_sample_seconds', 'value': format(elapsed, '.3f'), 'unit': 'seconds'}]
        rows += [{'metric': 'load_' + label, 'value': str(v), 'unit': 'runnable_tasks'}
                 for label, v in zip(('1m', '5m', '15m'), os.getloadavg())]
        raw = Path('/proc/meminfo').read_text()
        for name in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
            match = re.search(r'^' + name + r':\s+(\d+) kB$', raw, re.M)
            core.need(match is not None, 'inventory_memory_shape')
            rows.append({'metric': name, 'value': match[1], 'unit': 'KiB'})
        for path in ('/', '/var'):
            fs_stat = os.statvfs(path)
            for name, blocks in (('total', fs_stat.f_blocks), ('available', fs_stat.f_bavail)):
                rows.append({'metric': 'disk_' + path + '_' + name,
                             'value': str(blocks * fs_stat.f_frsize), 'unit': 'bytes'})
    core.need(len(rows) <= MAX_ROWS, 'inventory_row_bound')
    for row in rows:
        core.need(set(row) == set(COLUMNS[view]), 'inventory_columns')
        for value in row.values(): safe(value)
    return rows


def shown(stamp):
    core.need(isinstance(stamp, str) and stamp.endswith('Z'), 'container_timestamp')
    return datetime.fromisoformat(stamp[:-1] + '+00:00').astimezone(timezone(timedelta(hours=9))).isoformat()


def docker_view(view, runner, docker):
    """Fixed allowlist projection; never publish inspect's Env/Cmd/Labels."""
    listed = collect_view('containers', runner, docker)
    core.need(len(listed) <= 32 and all(re.fullmatch('[a-f0-9]{64}', row['id']) for row in listed), 'container_catalog_bound')
    if not listed: return []
    names = {row['id']: row['name'] for row in listed}
    if view == 'container_logs':
        redact = core.journal_library().redact
        def one(row):
            try:
                rc, raw = runner([docker, 'logs', '--since', '15m', '--tail', '20', '--timestamps', '--', row['id']],
                                 131072, 2, docker_logs=True)
                core.need(rc == 0, 'container_log_driver_unavailable')
                result = []
                for line in raw.decode('utf-8', errors='strict').splitlines():
                    stamp, sep, message = line.partition(' ')
                    core.need(sep and len(result) < 40, 'container_log_shape')
                    at = shown(stamp); text, state, sha = redact(message)
                    # Mask before shortening. Large bodies are withheld, not clipped raw.
                    text = text.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ') if text is not None else '[본문 제외]'
                    if len(text) > 1000: text = '[본문 길이 제한으로 제외]'; state = 'message_size_bound'
                    result.append(dict(name=row['name'], at_kst=at, message=text, message_state=state,
                                       message_sha256=sha or hashlib.sha256(message.encode()).hexdigest()))
                if not result: result = [dict(name=row['name'], at_kst='', message='최근15분 반환 표본 0건',
                    message_state='empty_sample', message_sha256='')]
                return result
            except (ValueError, OSError, TypeError, UnicodeError):
                return [dict(name=row['name'], at_kst='', message='컨테이너 로그 조회 불가',
                             message_state='unavailable', message_sha256='')]
        with ThreadPoolExecutor(max_workers=4) as pool: rows = [r for group in pool.map(one, listed) for r in group]
    elif view == 'container_stats':
        raw = command(runner, [docker, 'stats', '--no-stream', '--all', '--format', '{{json .}}'])
        rows = []; seen = set()
        for item in (json.loads(line) for line in raw.splitlines()):
            core.need(item['Name'] in names.values() and item['Name'] not in seen, 'container_stats_catalog')
            seen.add(item['Name'])
            for key in ('CPUPerc', 'MemUsage', 'MemPerc', 'NetIO', 'BlockIO', 'PIDs'):
                rows.append(dict(name=safe(item['Name']), field=key, value=safe(item[key])))
        core.need(seen == set(names.values()), 'container_stats_missing_objects')
    else:
        data = json.loads(command(runner, [docker, 'inspect', '--type', 'container', '--', *names]))
        core.need(isinstance(data, list) and len(data) == len(names) and {row['Id'] for row in data} == set(names), 'container_inspect_catalog')
        rows = []
        for item in data:
            name = names[item['Id']]; state = item['State']; hc = item['HostConfig']; net = item['NetworkSettings']
            details = {'container_id': item['Id'], 'image': item['Config']['Image'], 'image_id': item['Image'],
                       'status': state['Status'], 'running': state['Running'], 'paused': state['Paused'],
                       'restarting': state['Restarting'], 'oom_killed': state['OOMKilled'], 'exit_code': state['ExitCode'],
                       'restart_count': item['RestartCount'], 'started_at_kst': shown(state['StartedAt']) if not state['StartedAt'].startswith('0001-') else '시작 기록 없음',
                       'finished_at_kst': shown(state['FinishedAt']) if not state['FinishedAt'].startswith('0001-') else '종료 기록 없음',
                       'health': state.get('Health', {}).get('Status', '헬스체크 미설정'),
                       'health_failing_streak': state.get('Health', {}).get('FailingStreak', '미설정'),
                       'restart_policy': hc['RestartPolicy']['Name'], 'network_mode': hc['NetworkMode'],
                       'privileged': hc['Privileged'], 'read_only_rootfs': hc['ReadonlyRootfs'],
                       'memory_limit_bytes': hc['Memory'], 'nano_cpus_limit': hc['NanoCpus'],
                       'log_driver': hc['LogConfig']['Type']}
            for key, value in details.items(): rows.append(dict(name=name, field=key, value=safe(str(value))))
            for key, entries in (net.get('Ports') or {}).items():
                rows.append(dict(name=name, field='port:' + safe(key), value=safe(json.dumps(entries, ensure_ascii=False, separators=(',', ':')))))
            for key, entry in net['Networks'].items():
                rows.append(dict(name=name, field='network:' + safe(key), value=safe(json.dumps(
                    {k: entry.get(k) for k in ('IPAddress', 'Gateway', 'MacAddress')}, separators=(',', ':')))))
            for index, entry in enumerate(item.get('Mounts', [])):
                rows.append(dict(name=name, field='mount:' + str(index), value=safe(json.dumps(
                    {k: entry.get(k) for k in ('Type', 'Source', 'Destination', 'RW')}, ensure_ascii=False, separators=(',', ':')))))
    core.need(len(rows) <= MAX_ROWS, 'container_rows_bound')
    for row in rows:
        for value in row.values(): safe(value)
    return rows


def collect(role, runner, docker, now=None):
    core.need(role in core.ROLE_HOST, 'inventory_role')
    def one(view):
        at = int(time.time()) if now is None else now
        try:
            rows = collect_view(view, runner, docker)
            return {'status': 'observed', 'observed_at': at, 'rows': rows, 'reason': None}
        except (ValueError, OSError, KeyError, TypeError, UnicodeError):
            return {'status': 'unavailable', 'observed_at': at, 'rows': [], 'reason': 'inventory_collection_unavailable'}
    with ThreadPoolExecutor(max_workers=5) as pool:
        views = dict(zip(VIEWS, pool.map(one, VIEWS)))
    return {'schema': 1, 'host': core.ROLE_HOST[role], 'views': views}


def validate(snapshot, host):
    core.need(isinstance(snapshot, dict) and set(snapshot) == {'schema', 'host', 'views'}
              and type(snapshot['schema']) is int and snapshot['schema'] == 1 and snapshot['host'] == host
              and isinstance(snapshot['views'], dict) and set(snapshot['views']) == set(VIEWS), 'inventory_snapshot')
    for view, result in snapshot['views'].items():
        core.need(isinstance(result, dict) and set(result) == {'status', 'observed_at', 'rows', 'reason'}
                  and result['status'] in ('observed', 'unavailable') and type(result['observed_at']) is int
                  and result['observed_at'] > 0 and isinstance(result['rows'], list)
                  and len(result['rows']) <= (16384 if view == 'service_details' else MAX_ROWS), 'inventory_result')
        core.need((result['status'] == 'observed' and result['reason'] is None) or
                  (result['status'] == 'unavailable' and not result['rows']
                   and result['reason'] == 'inventory_collection_unavailable'), 'inventory_result_status')
        for row in result['rows']:
            core.need(isinstance(row, dict) and set(row) == set(COLUMNS[view]), 'inventory_columns')
            for value in row.values(): safe(value)
    core.need(len(core.encode(snapshot)) <= MAX_BYTES, 'inventory_snapshot_bound')
    return snapshot


def publish(snapshot):
    core.need(os.getuid() == os.geteuid() == 0, 'inventory_root_required')
    validate(snapshot, snapshot['host'])
    core.trusted_parents(SNAPSHOT.parent)
    gid = grp.getgrnam('capstone-diagnostics').gr_gid
    if SNAPSHOT.exists() or SNAPSHOT.is_symlink(): core.root_file(SNAPSHOT, MAX_BYTES, 0o640, gid)
    fd, path = tempfile.mkstemp(prefix='.inventory-', dir=SNAPSHOT.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            os.fchmod(file.fileno(), 0o640); os.fchown(file.fileno(), 0, gid)
            file.write(core.encode(snapshot)); file.flush(); os.fsync(file.fileno())
        os.replace(path, SNAPSHOT)
    finally:
        if os.path.exists(path): os.unlink(path)


def answer(value, expected_host, now=None, snapshot=None):
    host, view, state, limit, offset = request(value)
    core.need(host == expected_host and host in ('a', 'b', 'c'), 'inventory_host_mismatch')
    now = int(time.time()) if now is None else now
    if snapshot is None:
        snapshot = core.parsed(core.root_file(SNAPSHOT, MAX_BYTES, 0o640, grp.getgrnam('capstone-diagnostics').gr_gid))
    source = validate(snapshot, host)['views'][view]
    fresh = 0 <= now - source['observed_at'] <= core.TTL
    observed = fresh and source['status'] == 'observed'
    rows = source['rows'] if observed else []
    if view.startswith('container_') and 'container' in value:
        rows = [row for row in rows if row['name'] == value['container']]
        catalog = snapshot['views']['containers']
        catalog_known = catalog['status'] == 'observed' and 0 <= now - catalog['observed_at'] <= core.TTL
        present = True if rows else None
        if catalog_known:
            present = bool(rows) or value['container'] in {row['name'] for row in catalog['rows']}
        if observed and present is None:
            observed = False; source = {**source, 'reason': 'inventory_collection_unavailable'}
        if any(row.get('message_state') == 'unavailable' for row in rows):
            observed = False; rows = []; source = {**source, 'reason': 'container_logs_unavailable'}
    if view == 'service_details':
        rows = [row for row in rows if row['unit'] == value['unit']]
    if state != 'all':
        rows = ([row for row in rows if row['state'] == 'running'] if view == 'containers' else
                [row for row in rows if (row['sub'] == 'running' if state == 'running' else row['active'] == 'failed')])
    result = {'host': host, 'view': view, 'state': state, 'limit': limit, 'offset': offset,
              'status': 'observed' if observed else 'unavailable',
              'reason': None if observed else ('inventory_snapshot_stale' if not fresh else source['reason']),
              'observed_at_kst': datetime.fromtimestamp(source['observed_at'], timezone(timedelta(hours=9))).isoformat(),
              'age_seconds': now - source['observed_at'], 'live_query': False,
              'total': len(rows) if observed else None, 'rows': rows[offset:offset + limit],
              'has_more': offset + limit < len(rows) if observed else None,
              'next_offset': offset + limit if observed and offset + limit < len(rows) else None}
    if view.startswith('container_') and 'container' in value:
        result.update(container=value['container'], object_present=present if observed else None)
    if view == 'service_details': result.update(unit=value['unit'], object_present=bool(rows) if observed else None)
    return result
