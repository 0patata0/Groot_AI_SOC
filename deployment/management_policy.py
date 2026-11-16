#!/usr/bin/env python3
"""Pure whole-device management-policy contract, not a privileged executor.

Only root-owned adapters may supply observations and prepared changes. This
module neither reads credentials nor changes a file, service, rule or address.
Its results are not operating receipts and it is not registered as an MCP tool.
The fixed coverage set prevents a successful one-device edit being reported as
a global whitelist change. Adapter implementation and deployment are separate.
"""
from datetime import datetime, timedelta
import hashlib
import ipaddress
import json
import re


SHA = re.compile(r'[0-9a-f]{64}')
KST = timedelta(hours=9)
FORBIDDEN = tuple(ipaddress.IPv4Network(n) for n in
                  ('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
                   '224.0.0.0/4', '240.0.0.0/4'))
# A different effect is required for access, containment and sensor noise.
# In particular an SSH-heuristic exception is not an attack-inspection bypass.
SURFACES = {
    'a:fw-access': ('a', 'management_access'),
    'a:fw-protection': ('a', 'automatic_block_protection'),
    'a:waf-management': ('a', 'management_access'),
    'a:suricata-management': ('a', 'bounded_management_event_exception'),
    'b:wazuh-response': ('b', 'automatic_block_protection'),
    'b:wazuh-management': ('b', 'management_access'),
    'b:wazuh-events': ('b', 'bounded_management_event_exception'),
    'a:host-ssh': ('a', 'management_access'),
    'b:host-ssh': ('b', 'management_access'),
    'c:host-ssh': ('c', 'management_access'),
    'a:mcp-route': ('a', 'fixed_mcp_route'),
    'b:mcp-route': ('b', 'fixed_mcp_route'),
    'c:mcp-route': ('c', 'fixed_mcp_route'),
    'c:lab-management': ('c', 'management_access'),
}
CHECKS = frozenset({'syntax', 'route', 'rollback', 'audit_preserved',
                    'public_inspection_preserved', 'block_ttl_preserved'})


class PolicyError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise PolicyError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def hash_value(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def addresses(values):
    """Do not turn an accidental host-bit /24 into a wider approved network."""
    need(isinstance(values, list) and 1 <= len(values) <= 128, 'administrator_address_count')
    networks = []
    for value in values:
        need(isinstance(value, str) and re.fullmatch(
            r'[0-9]+(?:\.[0-9]+){3}(?:/(?:[0-9]|[12][0-9]|3[0-2]))?', value),
            'administrator_ipv4_required')
        try:
            net = ipaddress.IPv4Network(value, strict=True)
        except ValueError:
            raise PolicyError('administrator_canonical_network_required') from None
        need(net.prefixlen > 0 and not any(net.overlaps(n) for n in FORBIDDEN),
             'administrator_forbidden_network')
        networks.append(net)
    return [str(n) for n in ipaddress.collapse_addresses(networks)]


def registry(value):
    fields = {'schema', 'revision', 'administrator_cidrs', 'audit', 'public_inspection'}
    need(isinstance(value, dict) and set(value) == fields, 'registry_fields')
    need(type(value['schema']) is int and value['schema'] == 1 and
         type(value['revision']) is int and 1 <= value['revision'] < 2**53,
         'registry_version')
    need(value['audit'] == 'retain' and value['public_inspection'] == 'enforce',
         'registry_protection_boundary')
    need(value['administrator_cidrs'] == addresses(value['administrator_cidrs']),
         'registry_canonical_addresses')
    return value


def next_registry(before, desired):
    registry(before)
    cidrs = addresses(desired)
    need(cidrs != before['administrator_cidrs'], 'management_policy_unchanged')
    value = {**before, 'revision': before['revision'] + 1, 'administrator_cidrs': cidrs}
    return registry(value)


def mapped_sources(row):
    """Internal MCP transports need not have a fabricated remote IPv4 source."""
    transport = row['source_transport']
    need(transport in ('ipv4', 'stdio', 'unix'), 'management_source_transport')
    values = row['effective_source_cidrs']
    if transport != 'ipv4':
        need(SURFACES[row['target']][1] == 'fixed_mcp_route' and values == [],
             'management_local_route_identity')
        return
    need(isinstance(values, list) and 1 <= len(values) <= 128,
         'management_source_mapping_required')
    nets = []
    for value in values:
        try:
            net = ipaddress.IPv4Network(value, strict=True)
        except (ValueError, TypeError):
            raise PolicyError('management_source_mapping_canonical') from None
        need(str(net) == value and net.prefixlen > 0 and
             not any(net.overlaps(n) for n in (FORBIDDEN[0], FORBIDDEN[3], FORBIDDEN[4])),
             'management_source_mapping_unicast')
        nets.append(net)
    need([str(n) for n in ipaddress.collapse_addresses(nets)] == values,
         'management_source_mapping_canonical')


def stamp(value, now, *, lifetime):
    need(isinstance(value, str) and isinstance(now, datetime) and now.utcoffset() == KST,
         'management_kst_clock_required')
    try:
        seen = datetime.fromisoformat(value)
    except ValueError:
        raise PolicyError('management_observation_time') from None
    need(seen.utcoffset() == KST and -2 <= (now - seen).total_seconds() <= lifetime,
         'management_observation_stale')
    return seen


def coverage(rows, *, expected_policy_sha256, now, mode):
    """Consume trusted adapter receipts; never infer success from missing rows.

    `prepared` checks the full candidate before a card may be requested.
    `verified` additionally requires the actual loaded result and management
    path proof. Receipt authenticity/collection belongs to the fixed adapters,
    not to a model-supplied boolean or this pure contract function.
    """
    need(mode in ('prepared', 'verified') and hash_value(expected_policy_sha256),
         'management_coverage_parameters')
    need(isinstance(rows, list) and len(rows) <= len(SURFACES), 'management_coverage_rows')
    by_target = {}
    fields = {'schema', 'target', 'host', 'effect', 'policy_sha256', 'base_policy_sha256', 'observed_at_kst',
              'status', 'source_sha256', 'candidate_source_sha256', 'adapter_sha256', 'evidence_sha256', 'checks',
              'runtime_verified', 'effective_source_cidrs', 'source_mapping_sha256', 'source_transport'}
    for row in rows:
        need(isinstance(row, dict) and set(row) == fields, 'management_receipt_fields')
        target = row['target']
        need(isinstance(target, str) and target in SURFACES and target not in by_target,
             'management_receipt_target')
        host, effect = SURFACES[target]
        need(type(row['schema']) is int and row['schema'] == 1 and
             row['host'] == host and row['effect'] == effect,
             'management_receipt_identity')
        need(row['status'] in ('prepared', 'verified', 'failed', 'unavailable', 'not_applicable')
             and type(row['runtime_verified']) is bool, 'management_receipt_status')
        need(isinstance(row['checks'], dict) and set(row['checks']) == CHECKS and
             all(type(v) is bool for v in row['checks'].values()), 'management_receipt_checks')
        stamp(row['observed_at_kst'], now, lifetime=60)
        success = row['status'] in ('prepared', 'verified')
        need(all(hash_value(row[k]) or not success and row[k] is None for k in
                 ('policy_sha256', 'base_policy_sha256', 'source_sha256', 'candidate_source_sha256', 'adapter_sha256', 'evidence_sha256',
                  'source_mapping_sha256')), 'management_receipt_hash')
        # Root adapters must pin the actual NAT/proxy/SSH source mapping.
        # A copy of the administrator address alone cannot certify this field.
        if success or row['effective_source_cidrs'] != []:
            mapped_sources(row)
        else:
            need(row['source_transport'] in ('ipv4', 'stdio', 'unix'), 'management_source_transport')
        reasons = []
        if row['policy_sha256'] != expected_policy_sha256:
            reasons.append('different_policy')
        if row['status'] != mode:
            reasons.append('wrong_status')
        if not all(row['checks'].values()):
            reasons.append('checks_incomplete')
        if mode == 'verified' and not row['runtime_verified']:
            reasons.append('runtime_unverified')
        by_target[target] = {'target': target, 'host': host, 'effect': effect,
                             'complete': not reasons, 'reasons': reasons,
                             'evidence_sha256': row['evidence_sha256']}
    output = []
    for target, (host, effect) in SURFACES.items():
        output.append(by_target.get(target, {'target': target, 'host': host, 'effect': effect,
                                            'complete': False, 'reasons': ['missing'],
                                            'evidence_sha256': None}))
    return {'schema': 1, 'policy_sha256': expected_policy_sha256, 'mode': mode,
            'complete': all(r['complete'] for r in output), 'required': len(SURFACES),
            'satisfied': sum(r['complete'] for r in output), 'surfaces': output,
            'scope': 'trusted_adapter_receipt_contract_not_independent_runtime_observation'}


def prepare(before, desired, receipts, *, now):
    """Freeze one exact global proposal; a partial set cannot request approval."""
    after = next_registry(before, desired)
    after_sha = digest(after)
    check = coverage(receipts, expected_policy_sha256=after_sha, now=now, mode='prepared')
    need(check['complete'], 'management_global_candidate_incomplete')
    need(all(r['base_policy_sha256'] == digest(before) for r in receipts),
         'management_prepared_base_policy_changed')
    times = [datetime.fromisoformat(r['observed_at_kst']) for r in receipts]
    need((max(times) - min(times)).total_seconds() <= 15, 'management_receipt_span')
    # Bind the exact root-prepared evidence, source and route mappings, not just
    # the desired IP list. Deterministic ordering prevents split approvals.
    plan = {'schema': 1, 'kind': 'global_management_policy',
            'before_policy_sha256': digest(before), 'after_policy_sha256': after_sha,
            'after_policy': after, 'surfaces': sorted(SURFACES),
            'prepared': sorted(receipts, key=lambda r: r['target']),
            'partial_success_is_global_success': False,
            'audit': 'retain', 'public_inspection': 'enforce'}
    return {'status': 'ready_for_exact_approval', 'plan': plan, 'plan_sha256': digest(plan),
            'operating_change_performed': False, 'approval_record_created': False}


def verify(plan, receipts, *, now, expected_plan_sha256):
    """Readback gate only; this does not apply or roll back a policy."""
    need(hash_value(expected_plan_sha256) and digest(plan) == expected_plan_sha256,
         'management_approved_plan_changed')
    fields = {'schema', 'kind', 'before_policy_sha256', 'after_policy_sha256',
              'after_policy', 'surfaces', 'prepared', 'partial_success_is_global_success',
              'audit', 'public_inspection'}
    need(isinstance(plan, dict) and set(plan) == fields and type(plan['schema']) is int
         and plan['schema'] == 1 and plan['kind'] == 'global_management_policy'
         and hash_value(plan['before_policy_sha256'])
         and plan['surfaces'] == sorted(SURFACES)
         and plan['partial_success_is_global_success'] is False
         and plan['audit'] == 'retain' and plan['public_inspection'] == 'enforce',
         'management_plan_contract')
    registry(plan['after_policy'])
    need(digest(plan['after_policy']) == plan['after_policy_sha256'], 'management_plan_policy_hash')
    result = coverage(receipts, expected_policy_sha256=plan['after_policy_sha256'],
                      now=now, mode='verified')
    # Prepared receipts are part of the hash-bound approved plan. Validate the
    # original structure without treating their old timestamp as a new probe.
    need(isinstance(plan['prepared'], list) and len(plan['prepared']) == len(SURFACES),
         'management_plan_prepared_targets')
    need(all(isinstance(r, dict) and isinstance(r.get('observed_at_kst'), str)
             for r in plan['prepared']), 'management_plan_prepared_fields')
    times = [datetime.fromisoformat(r['observed_at_kst']) for r in plan['prepared']]
    old = coverage(plan['prepared'], expected_policy_sha256=plan['after_policy_sha256'],
                   now=max(times), mode='prepared')
    need(old['complete'] and (max(times)-min(times)).total_seconds() <= 15 and
         all(r['base_policy_sha256'] == plan['before_policy_sha256'] for r in plan['prepared']),
         'management_plan_preparation_changed')
    prepared = {r['target']: r for r in plan['prepared']}
    need(set(prepared) == set(SURFACES), 'management_plan_prepared_targets')
    by_target = {r['target']: r for r in receipts}
    for row in result['surfaces']:
        actual = by_target.get(row['target'])
        if actual is not None and any(actual[k] != prepared[row['target']][k] for k in
                                      ('adapter_sha256', 'source_mapping_sha256',
                                       'effective_source_cidrs', 'source_transport')):
            row['complete'] = False
            row['reasons'].append('adapter_or_route_changed')
        if actual is not None and (actual['source_sha256'] != prepared[row['target']]['candidate_source_sha256']
                                   or actual['candidate_source_sha256'] != actual['source_sha256']
                                   or actual['base_policy_sha256'] != plan['before_policy_sha256']):
            row['complete'] = False
            row['reasons'].append('installed_candidate_or_base_changed')
    result['complete'] = all(r['complete'] for r in result['surfaces'])
    result['satisfied'] = sum(r['complete'] for r in result['surfaces'])
    if receipts:
        seen = [datetime.fromisoformat(r['observed_at_kst']) for r in receipts]
        if (max(seen)-min(seen)).total_seconds() > 15:
            result['complete'] = False
            for row in result['surfaces']:
                row['complete'] = False
                row['reasons'].append('readback_span')
            result['satisfied'] = 0
    return {**result, 'status': 'globally_verified' if result['complete'] else 'incomplete',
            'plan_sha256': digest(plan), 'mutation_performed': False}
