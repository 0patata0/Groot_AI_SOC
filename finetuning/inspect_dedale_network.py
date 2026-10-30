"""Inspect DEDALE syslog alerts and the fields available for host correlation.

No time-only join, inferred transport/endpoint, incident verdict, or training.
Numeric alert timestamp units remain unverified unless a caller supplies a
separately justified contract. Sensor address never substitutes for an endpoint.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import re

from link_dedale_labels import parse

MESSAGE = re.compile(
    r'^\[(\d+):(\d+):(\d+)\] ([^\r\n]*?) '
    r'\[Classification: ([^\r\n]*?)\] \[Priority: (\d+)\] '
    r'\{(TCP|UDP)\} (\S+) -> (\S+)$')
KST = timezone(timedelta(hours=9))


def address(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('Invalid IP address')
    return ipaddress.ip_address(value)


def port(value):
    if type(value) is int:
        number = value
    elif isinstance(value, str) and re.fullmatch(r'[0-9]+', value):
        number = int(value)
    else:
        raise ValueError('Missing or invalid port')
    if not 0 <= number <= 65535:
        raise ValueError('Port outside range')
    return number


def endpoint(value):
    host, separator, service = value.rpartition(':')
    if not separator:
        raise ValueError('Missing endpoint port')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    return str(address(host)), port(service)


def alert_fields(row, *, timestamp_unit=None):
    if row.get('program') != 'suricata':
        raise ValueError('Not the inspected Suricata export profile')
    fields = [row.get(k) for k in ('@timestamp', 'timestamp', 'timestamp8601')]
    if any(type(v) is not int for v in fields) or len(set(fields)) != 1:
        raise ValueError('Missing, conflicting or noninteger timestamp')
    stamp = fields[0]
    at = None
    if timestamp_unit is not None:
        if timestamp_unit != 'epoch-ms':
            raise ValueError('Unsupported explicit timestamp contract')
        at = (datetime(1970, 1, 1, tzinfo=timezone.utc) +
              timedelta(milliseconds=stamp)).astimezone(KST).isoformat()
    text = row.get('message')
    if not isinstance(text, str):
        raise ValueError('Missing alert message')
    match = MESSAGE.fullmatch(text.rstrip('\r\n'))
    if match is None:
        raise ValueError('Unsupported or malformed alert message')
    gid, sid, rev, signature, classification, priority, protocol, src, dst = match.groups()
    src_ip, src_port = endpoint(src); dst_ip, dst_port = endpoint(dst)
    if address(src_ip).version != address(dst_ip).version:
        raise ValueError('Mixed address families')
    return {'sensor_ip': str(address(row.get('host'))),
            'timestamp_source_numeric': stamp, 'timestamp_unit': timestamp_unit,
            'timestamp_kst': at, 'gid': int(gid), 'sid': int(sid), 'rev': int(rev),
            'signature': signature, 'classification': classification,
            'alert_priority': int(priority), 'transport': protocol.lower(),
            'source_ip': src_ip, 'source_port': src_port,
            'destination_ip': dst_ip, 'destination_port': dst_port}


def host_transport_tuple(row):
    """Only explicit ECS transport endpoints qualify, never DNS answers or host.ip."""
    network = row.get('network')
    protocol = network.get('transport') if isinstance(network, dict) else None
    if not isinstance(protocol, str) or protocol.casefold() not in ('tcp', 'udp'):
        raise ValueError('Missing explicit TCP/UDP transport')
    values = []
    for key in ('source', 'destination'):
        value = row.get(key)
        if not isinstance(value, dict):
            raise ValueError('Missing connection endpoint')
        ip = address(value.get('ip'))
        if ip.is_unspecified:
            raise ValueError('Unspecified address is not a peer')
        values.append((str(ip), port(value.get('port'))))
    if address(values[0][0]).version != address(values[1][0]).version:
        raise ValueError('Mixed address families')
    return (protocol.casefold(), *values[0], *values[1])


def inspect_host_records(lines, *, source):
    counts = Counter({'records': 0, 'complete_explicit_ecs_transport_tuple': 0,
                      'sysmon_event_3': 0, 'has_source_ip': 0, 'has_destination_ip': 0,
                      'unspecified_destination_ip': 0, 'dns_event': 0,
                      'host_ip_present': 0, 'flow_id_present': 0, 'community_id_present': 0})
    codes = Counter(); digest = hashlib.sha256(); offset = 0; examples = []
    for number, line in enumerate(lines, 1):
        row = parse(line); counts['records'] += 1; digest.update(line)
        event = row.get('event', {}); network = row.get('network', {})
        codes[str(event.get('code'))] += 1
        counts['sysmon_event_3'] += event.get('module') == 'sysmon' and str(event.get('code')) == '3'
        counts['dns_event'] += event.get('action') == 'Dns query (rule: DnsQuery)'
        for key in ('source', 'destination'):
            v = row.get(key, {}).get('ip')
            if v is not None:
                ip = address(v); counts['has_'+key+'_ip'] += 1
                if key == 'destination':counts['unspecified_destination_ip'] += ip.is_unspecified
        counts['host_ip_present'] += bool(row.get('host', {}).get('ip'))
        counts['flow_id_present'] += 'flow_id' in row
        counts['community_id_present'] += 'community_id' in row or 'community_id' in network
        try:
            host_transport_tuple(row); counts['complete_explicit_ecs_transport_tuple'] += 1
        except ValueError:
            pass
        if ('ip' in row.get('source', {}) or 'ip' in row.get('destination', {})) and len(examples) < 8:
            examples.append({'source': source, 'line': number, 'byte_offset': offset,
                             'sha256': hashlib.sha256(line).hexdigest(),
                             'timestamp_source': row.get('@timestamp'),
                             'source_fields': sorted(row.get('source', {})),
                             'destination_fields': sorted(row.get('destination', {})),
                             'transport_explicit': 'transport' in network,
                             'action': event.get('action')})
        offset += len(line)
    return {'source': source, 'counts': dict(counts), 'event_code_counts': dict(codes),
            'bytes': offset, 'sha256': digest.hexdigest(), 'endpoint_evidence': examples,
            'scope': 'Provided label records only; not all original host logs or sensor configuration.'}


def inspect_alerts(lines, *, timestamp_unit=None, progress=None):
    counts = Counter({'records': 0, 'flow_id_present': 0, 'community_id_present': 0,
                      'time_regressions': 0, 'sensor_is_neither_endpoint': 0})
    sensors, protocols, sids, priorities = (Counter() for _ in range(4))
    digest = hashlib.sha256(); offset = 0; lo = hi = previous = None; samples = []
    seen_sensors = set()
    for number, line in enumerate(lines, 1):
        row = parse(line); item = alert_fields(row, timestamp_unit=timestamp_unit)
        digest.update(line); counts['records'] += 1
        counts['flow_id_present'] += 'flow_id' in row
        counts['community_id_present'] += 'community_id' in row
        stamp = item['timestamp_source_numeric']
        counts['time_regressions'] += previous is not None and stamp < previous
        previous = stamp; lo = stamp if lo is None else min(lo, stamp); hi = stamp if hi is None else max(hi, stamp)
        sensor = item['sensor_ip']; sensors[sensor] += 1; protocols[item['transport']] += 1
        sids[str(item['sid'])] += 1; priorities[str(item['alert_priority'])] += 1
        counts['sensor_is_neither_endpoint'] += sensor not in (item['source_ip'], item['destination_ip'])
        if sensor not in seen_sensors:
            seen_sensors.add(sensor)
            samples.append({'line': number, 'byte_offset': offset,
                            'raw_line_sha256': hashlib.sha256(line).hexdigest(), **item})
        offset += len(line)
        if progress and number % 250000 == 0:progress(dict(counts))
    return {'counts': dict(counts), 'sensor_counts': dict(sensors),
            'transport_counts': dict(protocols), 'signature_counts': dict(sids),
            'alert_priority_counts': dict(priorities), 'bytes': offset,
            'sha256': digest.hexdigest(), 'min_numeric_time': lo, 'max_numeric_time': hi,
            'timestamp_unit': timestamp_unit, 'samples': samples, 'iterator_exhausted': True,
            'confirmed_host_incident_links': 0, 'training_admitted': 0,
            'limits': ['No full sensor health, packet coverage, drop/block verdict or attack success inference.',
                       'Missing host tuple or shared ID cannot be replaced by time-only correlation.',
                       'Raw timestamp integers and syslog wrapper priority retain their own meaning.']}
