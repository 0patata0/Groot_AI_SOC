"""Synthetic boundary data only. timestamp is manager processing, not index ingest."""
from copy import deepcopy


def groups(v2, end_ms, *, event_age_s=10, processing_age_s=0, distinct=5, copies=1):
    rows = []
    for service in range(3):
        for key in range(distinct):
            row = v2.document(end_ms, 'g%d-k%d' % (service, key),
                              -int(event_age_s * 1_000_000),
                              service='delay-group-%d' % service,
                              processing_offset_us=-int(processing_age_s * 1_000_000))
            rows.extend(deepcopy(row) for _ in range(copies))
    return rows


def cases(v2, end_ms):
    e = v2.expected
    yield ('three_groups_five_unique', groups(v2, end_ms), e(15, 15, 3, 3, 3))
    yield ('three_groups_four_unique', groups(v2, end_ms, distinct=4), e(12, 12, 3))
    duplicate = []
    for service in range(3):
        for key in ('a', 'a', 'a', 'a', 'b'):
            duplicate.append(v2.document(end_ms, 'g%d-%s' % (service, key),
                                         service='delay-group-%d' % service))
    yield ('false_repeat_four_a_one_b', duplicate, e(15, 6, 3))
    yield ('same_events_different_index_document_ids', groups(v2, end_ms, copies=2), e(30, 15, 3, 3, 3))
    for age in (120, 300, 1800):
        included = age <= 300
        yield ('event_age_%ds_processing_now' % age,
               groups(v2, end_ms, event_age_s=age), e(15, 15, 3, 3, 3) if included else e())
    # The query compares this field against actual now, so use an unambiguous
    # 60-second margin around its 360-second boundary, not a fake frozen clock.
    for age in (120, 300, 1800):
        included = age <= 300
        yield ('processing_age_%ds_event_recent' % age,
               groups(v2, end_ms, processing_age_s=age), e(15, 15, 3, 3, 3) if included else e())
    yield ('event_older_than_300s_by_one_microsecond',
           groups(v2, end_ms, event_age_s=300.000001), e())
    historical = groups(v2, end_ms)
    for row in historical:
        row['data']['capstone_norm']['correlation_time_class'] = 'historical'
        row['data']['capstone_norm']['correlation_eligible'] = 'false'
    yield ('historical_marker_is_excluded', historical, e())


def span_groups(v2, end_ms):
    """Three real 60-second event windows: five distinct keys per service."""
    rows = groups(v2, end_ms, event_age_s=0)
    for index, row in enumerate(rows):
        row['data']['capstone_norm']['event_time_kst'] = v2.iso_us(
            end_ms * 1000 - (60 - (index % 5) * 15) * 1_000_000, kst=True)
    return rows
