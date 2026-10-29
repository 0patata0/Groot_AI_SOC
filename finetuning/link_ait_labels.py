"""Stream AIT LDS raw logs and provider line labels into bounded review evidence.

No tool execution, incident verdict, training output, or timezone inference.
Inputs are already opened streams; acquisition/integrity receipts are separate.
"""
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
import re

KST = timezone(timedelta(hours=9))


def sha(value):
    return hashlib.sha256(value).hexdigest()


def explicit_time(text):
    """Accept audit epochs and Apache offsets; never guess syslog year/zone."""
    # Match a log header, never a timestamp-like string in an attacker-supplied
    # URL, message or JSON body. Source content is untrusted evidence.
    match = re.match(r'^(?:node=\S+\s+)?type=[A-Z0-9_]+\s+msg=audit\((\d+(?:\.\d+)?):\d+\):', text)
    if match:
        return datetime.fromtimestamp(float(match[1]), timezone.utc), 'audit_epoch'
    match = re.match(r'^\S+\s+\S+\s+\S+\s+\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]', text)
    if match:
        return datetime.strptime(match[1], '%d/%b/%Y:%H:%M:%S %z'), 'apache_offset'
    if text.lstrip().startswith('{'):
        try:
            record = json.loads(text)
        except ValueError:
            return None, 'unresolved'
        for key in ('@timestamp', 'timestamp'):
            value = record.get(key) if isinstance(record, dict) else None
            if isinstance(value, str):
                try:
                    observed = datetime.fromisoformat(value.replace('Z', '+00:00'))
                except ValueError:
                    continue
                if observed.tzinfo is not None and observed.utcoffset() is not None:
                    return observed, 'json_explicit_offset'
    return None, 'unresolved'


def link_pair(raw_stream, label_stream, *, raw_name, label_name, windows, per_kind=2):
    if not 1 <= per_kind <= 10:
        raise ValueError('Review selection must be bounded')
    if any(not (0 < w['start_epoch'] < w['end_epoch']) for w in windows):
        raise ValueError('Invalid source interval')
    raw_hash, label_hash = hashlib.sha256(), hashlib.sha256()
    counts, label_counts, time_counts = Counter(), Counter(), Counter()
    gap_counts, gap_labelled = Counter(), Counter()
    selected, used = [], Counter()
    label_number, previous_reference = 0, 0

    def next_label():
        nonlocal label_number, previous_reference
        data = next(label_stream, None)
        if data is None:
            return None
        label_number += 1
        label_hash.update(data)
        value = json.loads(data)
        ref = value.get('line')
        if type(ref) is not int or ref <= previous_reference:
            raise ValueError('Provider line references must be positive, unique and sorted')
        if not isinstance(value.get('labels'), list) or not value['labels'] or not all(
                isinstance(x, str) and x for x in value['labels']):
            raise ValueError('Missing provider labels')
        previous_reference = ref
        return {'record': value, 'label_source_line': label_number,
                'label_source_line_sha256': sha(data)}

    current = next_label()
    for number, data in enumerate(raw_stream, 1):
        raw_hash.update(data)
        counts['raw_lines'] += 1
        text = data.decode('utf-8')
        observed, kind = explicit_time(text)
        time_counts[kind] += 1
        if current and current['record']['line'] < number:
            raise ValueError('Skipped provider line reference')
        binding = current if current and current['record']['line'] == number else None
        labels = binding['record']['labels'] if binding else []
        if binding:
            counts['labelled_raw_lines'] += 1
            label_counts.update(labels)
        matches = [w['phase'] for w in windows if observed is not None
                   and w['start_epoch'] <= observed.timestamp() <= w['end_epoch']]
        gap_counts.update(matches)
        if binding:
            gap_labelled.update(matches)
        reasons = ['label:' + label for label in labels] + ['interval:' + phase for phase in matches]
        retain = [reason for reason in reasons if used[reason] < per_kind]
        if retain:
            used.update(retain)
            selected.append({
                'raw_member': raw_name, 'raw_line': number, 'raw_line_sha256': sha(data),
                'raw_text': text, 'provider_binding': binding, 'label_member': label_name,
                'timestamp_kst': observed.astimezone(KST).isoformat() if observed else None,
                'timestamp_basis': kind, 'matching_gap_intervals': matches,
                'selected_for': retain,
                'conclusion': 'source_observation_only_not_incident_success_or_benign_verdict',
            })
        if binding:
            current = next_label()
    if current is not None:
        raise ValueError('Provider label points past end of raw log')
    return {
        'raw_member': raw_name, 'label_member': label_name,
        'raw_member_sha256': raw_hash.hexdigest(), 'label_member_sha256': label_hash.hexdigest(),
        'counts': dict(counts), 'provider_label_rows': label_number,
        'all_label_references_bound': counts['labelled_raw_lines'] == label_number,
        'provider_label_occurrences': dict(label_counts), 'timestamp_types': dict(time_counts),
        'gap_interval_raw_rows': dict(gap_counts), 'gap_interval_provider_labelled_rows': dict(gap_labelled),
        'sample_cap_per_label_or_interval': per_kind, 'selected': selected,
        'unlabelled_is_benign': False,
        'limits': 'Provider rule labels and source-time matches; no expert adjudication, causal chain, current-state or remediation proof.',
    }
