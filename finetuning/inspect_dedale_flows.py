"""Read DEDALE Zeek/label evidence without silently merging clock domains.

Source fields, raw coordinates and unset markers are retained. NTP packet
values are observations, never an automatic clock correction or verdict.
"""
import csv
from collections import Counter
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
import hashlib
import ipaddress
import json
import re

from compare_dedale_clocks import epoch_microseconds

RENAMES = {'ip_src': 'id.orig_h', 'port_src': 'id.orig_p',
           'ip_dst': 'id.resp_h', 'port_dst': 'id.resp_p'}
ANNOTATIONS = {'date', 'label', 'step', 'attack_step', 'tactic', 'technique', 'comments'}
KST = timezone(timedelta(hours=9))


def seconds_us(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+(?:\.\d{1,6})?', value):
        raise ValueError('Expected explicit nonnegative seconds with at most microsecond precision')
    return int(Decimal(value) * 1000000)


def kst_from_us(value):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value)).astimezone(KST).isoformat()


def labeled_seconds_us(value):
    """Accept the label CSV's decimal/exponent notation only if microseconds are exact."""
    if not isinstance(value, str) or len(value) > 64 or not re.fullmatch(r'\d+(?:\.\d+)?(?:[eE][+-]?\d+)?', value):
        raise ValueError('Invalid labeled time representation')
    with localcontext() as context:
        context.prec = 80
        number = Decimal(value)
        if not number.is_finite() or not 0 <= number <= Decimal('1000000000000'):
            raise ValueError('Labeled time outside supported range')
        scaled = number * 1000000
        if scaled != scaled.to_integral_value():
            raise ValueError('Labeled time would require precision loss')
        return int(scaled)


class ZeekTSV:
    def __init__(self, lines, *, path):
        self.lines = iter(lines); self.path = path; self.headers = {}
        self.rows = self.bytes = 0; self.digest = hashlib.sha256(); self.complete = False

    def __iter__(self):
        closed = False
        for number, line in enumerate(self.lines, 1):
            offset = self.bytes; self.bytes += len(line); self.digest.update(line)
            text = line.decode('utf-8').rstrip('\r\n')
            if closed:
                raise ValueError('Content after Zeek close marker')
            if text.startswith('#'):
                if text == r'#separator \x09': key, value = 'separator', '\t'
                else:
                    key, separator, value = text[1:].partition('\t')
                    if not separator: raise ValueError('Malformed Zeek header')
                if key in self.headers or key not in {'separator','set_separator','empty_field','unset_field','path','open','fields','types','close'}:
                    raise ValueError('Duplicate or unsupported Zeek header')
                if self.rows and key != 'close': raise ValueError('Header change within records')
                self.headers[key] = value
                if key == 'close': closed = True
                continue
            self._check_header()
            fields = self.headers['fields'].split('\t'); values = text.split('\t')
            if len(fields) != len(values): raise ValueError('Zeek row width mismatch')
            self.rows += 1
            yield {'line': number, 'byte_offset': offset,
                   'raw_line_sha256': hashlib.sha256(line).hexdigest(), 'fields': dict(zip(fields, values))}
        self._check_header()
        if not closed: raise ValueError('Missing Zeek close marker; incomplete source')
        self.complete = True

    def _check_header(self):
        h = self.headers
        if not {'separator','path','fields','types','open','unset_field','empty_field'} <= set(h):
            raise ValueError('Incomplete Zeek header')
        fields = h['fields'].split('\t'); types = h['types'].split('\t')
        if h['separator'] != '\t' or h['path'] != self.path or len(fields) != len(set(fields)) or len(fields) != len(types):
            raise ValueError('Invalid Zeek schema')

    def summary(self):
        return {'rows': self.rows, 'bytes': self.bytes, 'sha256': self.digest.hexdigest(),
                'headers': self.headers, 'complete': self.complete}


class CSVRecords:
    """Track physical byte/line ranges even when a quoted annotation spans lines."""
    def __init__(self, lines):
        self.lines = iter(lines); self.bytes = self.line = self.rows = 0
        self.digest = hashlib.sha256(); self.record_parts = []; self.fields = []; self.complete = False

    def _text_lines(self):
        for line in self.lines:
            self.record_parts.append(line); self.digest.update(line); self.bytes += len(line); self.line += 1
            yield line.decode('utf-8')

    def __iter__(self):
        reader = csv.reader(self._text_lines(), delimiter=';', strict=True)
        self.fields = next(reader)
        if len(self.fields) != len(set(self.fields)) or not ANNOTATIONS <= set(self.fields):
            raise ValueError('Invalid label CSV header')
        while True:
            offset, number = self.bytes, self.line + 1; self.record_parts = []
            try: values = next(reader)
            except StopIteration: break
            if len(values) != len(self.fields): raise ValueError('Label CSV width mismatch')
            row = dict(zip(self.fields, values))
            if row['label'] not in ('0', '1', '2'): raise ValueError('Unknown provider label')
            self.rows += 1
            yield {'line': number, 'end_line': self.line, 'byte_offset': offset,
                   'raw_line_sha256': hashlib.sha256(b''.join(self.record_parts)).hexdigest(), 'fields': row}
        self.complete = True

    def summary(self):
        return {'rows': self.rows, 'bytes': self.bytes, 'sha256': self.digest.hexdigest(),
                'fields': self.fields, 'complete': self.complete}


def connection_key(row, *, labeled=False, expected_fields=None):
    value = {RENAMES.get(k, k): v for k, v in row.items() if not labeled or k not in ANNOTATIONS}
    if expected_fields is not None and set(value) != set(expected_fields):
        raise ValueError('Connection field set changed between raw and labeled data')
    for name in ('ts', 'duration'):
        if value.get(name) != '-':
            value[name] = str((labeled_seconds_us if labeled else seconds_us)(value[name]))
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).digest()


def endpoint_tuple(row):
    result = []
    for side in ('orig', 'resp'):
        ip = ipaddress.ip_address(row['id.'+side+'_h'])
        port = row['id.'+side+'_p']
        if not re.fullmatch(r'\d+', port) or not 0 <= int(port) <= 65535 or ip.is_unspecified:
            raise ValueError('Invalid connection endpoint')
        result.extend((str(ip), int(port)))
    return tuple(result)


def assess_session(conn, ssh, *, host_timestamp):
    if conn['uid'] != ssh['uid'] or endpoint_tuple(conn) != endpoint_tuple(ssh) or conn['proto'] != 'tcp':
        raise ValueError('UID and both TCP endpoints must agree')
    start = seconds_us(conn['ts']); duration = seconds_us(conn['duration']); end = start + duration
    ssh_time = seconds_us(ssh['ts'])
    if not start <= ssh_time <= end: raise ValueError('SSH transaction lies outside connection interval')
    host_time = epoch_microseconds(host_timestamp)
    return {'network_logs_linked': True, 'connection_start_kst': kst_from_us(start),
            'connection_end_kst': kst_from_us(end), 'ssh_transaction_kst': kst_from_us(ssh_time),
            'host_timestamp_kst': kst_from_us(host_time), 'duration_us': duration,
            'host_inside_raw_network_interval': start <= host_time <= end,
            'host_after_network_end_us': host_time - end,
            'clock_adjustment_applied_us': 0,
            'host_to_network_confirmation': 'Requires independently justified clock alignment and process/session context.'}


def ntp_request_observation(row):
    if row['mode'] != '3': raise ValueError('Response clock must not be attributed to originator')
    return {'capture_kst': kst_from_us(seconds_us(row['ts'])),
            'declared_transmit_minus_capture_us': seconds_us(row['xmt_time']) - seconds_us(row['ts']),
            'stratum': row['stratum'], 'ref_id': row['ref_id'],
            'usable_as_authoritative_clock_correction': False,
            'reason': 'Packet header difference alone is not a verified synchronization result.'}


def compare_connections(conn_path, labels_path):
    """Compare complete raw fields with multiplicity; missing values never equal zero."""
    remaining = Counter()
    with open(conn_path, 'rb') as stream:
        raw = ZeekTSV(stream, path='conn')
        for record in raw:
            remaining[connection_key(record['fields'])] += 1
    expected_fields = raw.headers['fields'].split('\t')
    counts = Counter(); matched = unmatched = 0
    with open(labels_path, 'rb') as stream:
        labels = CSVRecords(stream)
        for record in labels:
            row = record['fields']
            key = connection_key(row, labeled=True, expected_fields=expected_fields)
            counts[row['label']] += 1
            if remaining[key]:
                remaining[key] -= 1; matched += 1
                if not remaining[key]: del remaining[key]
            else:
                unmatched += 1
    return {'raw': raw.summary(), 'labels': labels.summary(), 'label_counts': dict(counts),
            'full_core_matches': matched, 'unmatched_labels': unmatched,
            'unmatched_raw': sum(remaining.values()),
            'annotation_columns_excluded': sorted(ANNOTATIONS),
            'missing_values_replaced': False, 'source_order_required': False}


def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--conn', type=Path, required=True)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('Output already exists; preserve previous evidence')
    result = compare_connections(args.conn, args.labels)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2); stream.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('raw', 'labels')}))


if __name__ == '__main__':
    main()
