"""Synthetic documents/expected results for native isolated-index verification.

No network, packages, live records, or writes. cases(period_end_ms) yields one
case at a time so large boundary cases need not coexist in memory. Each case
has name, documents, expected (metric fields), and optional query_excluded.
Use a separate empty test index or delete/refresh between cases. Keep the
production monitor query/scripts unchanged except the test index name and
runtime period_end substitution. Multiple real shards are a separate test.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
KST = timezone(timedelta(hours=9))
LOCATION = '/var/log/capstone-vector/evidence/normalized.jsonl'


def digest(label):
    return hashlib.sha256(label.encode('ascii')).hexdigest()


def iso_us(value, *, kst=False):
    dt = EPOCH + timedelta(microseconds=value)
    return dt.astimezone(KST if kst else timezone.utc).isoformat(timespec='microseconds')


def document(end_ms, key, offset_us=-10_000_000, *, source='suricata', service='service-a', processing_offset_us=0):
    stable = digest(source + ':' + str(key))
    return {
        'timestamp': iso_us(end_ms * 1000 + processing_offset_us),
        'agent': {'id': '001'}, 'location': LOCATION,
        'rule': {'id': '100261' if source == 'suricata' else '100262', 'level': 3},
        'data': {'capstone_norm': {
            'schema_version': 'vector-1', 'pipeline': 'vector', 'sensor': 'groot-sec',
            'evidence_lane': 'indexer-observation-v1', 'source': source,
            'action': 'observed' if source == 'suricata' else 'logged_drop',
            'correlation_eligible': 'true', 'correlation_time_class': 'fresh',
            'protected_asset': 'false', 'correlation_policy': 'directional-service-v1',
            'source_ip': '198.18.0.10', 'destination_ip': '192.0.2.30',
            'destination_port': '8080', 'protocol': 'tcp',
            'event_time_kst': iso_us(end_ms * 1000 + offset_us, kst=True),
            'correlation_key': digest(service), 'correlation_dedupe_key': stable,
            'event_id': digest('event:' + stable), 'message_sha256': digest('message:' + stable),
        }},
    }


def expected(documents=0, unique=0, services=0, matched=0, repeat=0, cross=0, *, invalid=None):
    if invalid:
        return {'valid': False, 'reason': invalid, 'match': False, **{k: -1 for k in (
            'documents', 'unique_events', 'duplicate_documents', 'services',
            'matched_services', 'repeat_services', 'cross_source_services')}}
    return {'valid': True, 'reason': 'ok', 'match': matched > 0, 'documents': documents,
            'unique_events': unique, 'duplicate_documents': documents - unique, 'services': services,
            'matched_services': matched, 'repeat_services': repeat, 'cross_source_services': cross}


def case(name, docs, result, **metadata):
    return {'name': name, 'documents': docs, 'expected': result, **metadata}


def cases(period_end_ms):
    if type(period_end_ms) is not int or period_end_ms < 1_000_000:
        raise ValueError('period_end_ms_required')
    d = lambda key, offset=-10_000_000, **kw: document(period_end_ms, key, offset, **kw)
    yield case('empty', [], expected())
    yield case('four_distinct_not_five', [d(i) for i in range(4)], expected(4, 4, 1))
    yield case('five_same_timestamp', [d(i) for i in range(5)], expected(5, 5, 1, 1, 1))
    yield case('same_key_twenty_retransmissions', [d('same') for _ in range(20)], expected(20, 1, 1))
    yield case('four_a_one_b', [d('a') for _ in range(4)] + [d('b')], expected(5, 2, 1))
    yield case('five_over_240_seconds_not_a_window', [d(i, -250_000_000 + i * 60_000_000) for i in range(5)], expected(5, 5, 1))
    yield case('old_sixty_second_window_retained', [d(i, -100_000_000 + i * 15_000_000) for i in range(5)], expected(5, 5, 1, 1, 1))
    for span, title, matches in ((59_999_999, 'below', True), (60_000_000, 'equal', True), (60_000_001, 'above', False)):
        times = [-100_000_000, -90_000_000, -80_000_000, -70_000_000, -100_000_000 + span]
        yield case('repeat_microsecond_boundary_' + title, [d(i, t) for i, t in enumerate(times)], expected(5, 5, 1, int(matches), int(matches)))
        yield case('cross_microsecond_boundary_' + title,
                   [d('s', -100_000_000), d('n', -100_000_000 + span, source='nftables')],
                   expected(2, 2, 1, int(matches), 0, int(matches)))
    cross = [d('s', -250_000_000, processing_offset_us=-130_000_000),
             d('n', -195_000_000, source='nftables', processing_offset_us=-75_000_000)]
    yield case('delayed_companion_beyond_old_processing_120s', cross, expected(2, 2, 1, 1, 0, 1))
    yield case('reverse_arrival_order', list(reversed(cross)), expected(2, 2, 1, 1, 0, 1))
    yield case('two_sources_different_service', [d('s'), d('n', source='nftables', service='service-b')], expected(2, 2, 2))
    both = [d(i, -50_000_000 + i * 5_000_000) for i in range(5)] + [d('n', source='nftables')]
    yield case('repeat_and_cross_same_service', both, expected(6, 6, 1, 1, 1, 1))
    yield case('cross_duplicate_retransmissions', [deepcopy(x) for _ in range(10) for x in cross], expected(20, 2, 1, 1, 0, 1))
    same_pair = [d('conflict'), d('conflict', -9_999_999)]
    yield case('same_source_key_different_time', same_pair, expected(invalid='identity_conflict'))
    yield case('same_source_key_different_service', [d('conflict'), d('conflict', service='service-b')], expected(invalid='identity_conflict'))
    different_source_same_key = [d('s'), d('n', source='nftables')]
    different_source_same_key[1]['data']['capstone_norm']['correlation_dedupe_key'] = different_source_same_key[0]['data']['capstone_norm']['correlation_dedupe_key']
    yield case('identity_is_source_plus_key', different_source_same_key, expected(2, 2, 1, 1, 0, 1))
    yield case('event_at_lookback_edge', [d('edge', -300_000_000)], expected(1, 1, 1))
    yield case('event_older_than_lookback', [d('old', -300_000_001)], expected(), query_excluded=1)
    yield case('event_after_period_end', [d('future', 1)], expected(), query_excluded=1)
    precision = d('submicrosecond')
    # 2026-style six digits become nine, ending in one nanosecond beyond them.
    field = precision['data']['capstone_norm']['event_time_kst']
    precision['data']['capstone_norm']['event_time_kst'] = field[:-6] + '001' + field[-6:]
    yield case('submicrosecond_input_rejected', [precision], expected(), query_excluded=1)
    for name, field, value in (
        ('wrong_marker', 'evidence_lane', 'untrusted'),
        ('protected_source', 'source_ip', '211.170.162.110'),
        ('protected_destination', 'destination_ip', '211.170.162.111'),
        ('historical_class', 'correlation_time_class', 'historical'),
        ('bad_action', 'action', 'would_drop'),
        ('bad_port', 'destination_port', '0'),
        ('bad_key', 'correlation_dedupe_key', 'x' * 64),
    ):
        doc = d('excluded'); doc['data']['capstone_norm'][field] = value
        yield case(name, [doc], expected(), query_excluded=1)
    wrong = d('wrong-leaf'); wrong['rule']['id'] = '100262'
    yield case('source_leaf_mismatch', [wrong], expected(), query_excluded=1)
    wrong = d('wrong-location'); wrong['location'] = '/var/log/capstone-vector/ready/normalized.jsonl'
    yield case('wrong_location', [wrong], expected(), query_excluded=1)
    yield case('processing_older_than_360s', [d('old-processing', processing_offset_us=-361_000_000)], expected(), query_excluded=1)
    yield case('processing_more_than_5s_future', [d('future-processing', processing_offset_us=30_000_000)], expected(), query_excluded=1)
    yield case('hundred_services_allowed', [d(i, service='service-' + str(i)) for i in range(100)], expected(100, 100, 100))
    yield case('hundred_one_services_unavailable', [d(i, service='service-' + str(i)) for i in range(101)], expected(invalid='service_limit'))
    yield case('ten_thousand_retransmissions_allowed', [d('same') for _ in range(10000)], expected(10000, 1, 1))
    yield case('ten_thousand_distinct_allowed', [d(i) for i in range(10000)], expected(10000, 10000, 1, 1, 1))
    yield case('ten_thousand_one_documents_unavailable', [d(i) for i in range(10001)], expected(invalid='document_limit'))
