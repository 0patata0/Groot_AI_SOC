"""Bounded read composition; no risk, recovery, approval or action decisions.

The caller chooses event windows and optional diagnostics/web follow-up. A web
association is only a join of an observed path to a fixed configuration prefix.
Every underlying read keeps its exact arguments, result, time and error state.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import copy
import hashlib
import ipaddress
import json
import re

KST = timezone(timedelta(hours=9))
MAX_COMPONENTS = 32
MAX_COMPONENT_BYTES = 128 * 1024
MAX_RESULT_BYTES = 128 * 1024
FORMAT = 'incident_evidence_v1'
PREFIXES = {
    'c:dvwa': '/dvwa/', 'c:lab-console': '/_offline-labs/',
    'c:lab-java': '/_offline-lab-java/', 'c:lab-httpd49': '/_offline-lab-httpd49/',
    'c:lab-httpd50': '/_offline-lab-httpd50/',
}
EVENTS = {'modsecurity': 'search_modsecurity_alerts', 'suricata': 'search_suricata_alerts'}
READ_NAMES = frozenset((*EVENTS.values(), 'get_system_diagnostics',
                       'get_web_service_target', 'search_web_access', 'search_wazuh_alerts'))


def need(ok, code):
    if not ok:
        raise ValueError(code)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode()


def now():
    return datetime.now(KST).isoformat()


def instant(value):
    need(isinstance(value, str) and len(value) <= 40 and
         re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+09:00', value),
         'exact_kst_timestamp_required')
    return datetime.fromisoformat(value)


def window(value):
    start, end = instant(value.get('since_kst')), instant(value.get('until_kst'))
    need(0 < (end-start).total_seconds() <= 86400, 'invalid_event_window')
    need(type(value.get('limit')) is int and 1 <= value['limit'] <= 50, 'invalid_limit')


def request(value):
    need(isinstance(value, dict) and {'events'} <= set(value) <=
         {'events', 'diagnostics', 'web_context'}, 'invalid_bundle_arguments')
    events, diagnostics = value['events'], value.get('diagnostics', [])
    need(isinstance(events, list) and 1 <= len(events) <= 8, 'invalid_event_count')
    need(isinstance(diagnostics, list) and len(diagnostics) <= 4, 'invalid_diagnostic_count')
    seen, ips = set(), set()
    for event in events:
        need(isinstance(event, dict) and set(event) == {'sensor', 'arguments'} and
             isinstance(event['sensor'], str) and event['sensor'] in EVENTS, 'invalid_event')
        args = event['arguments']; sensor = event['sensor']
        required = {'since_kst', 'until_kst', 'source_ip', 'limit'}
        extra = 'rule_id' if sensor == 'modsecurity' else 'signature_id'
        need(isinstance(args, dict) and required <= set(args) <= required | {extra}, 'invalid_event_arguments')
        window(args)
        need(isinstance(args['source_ip'], str) and
             str(ipaddress.ip_address(args['source_ip'])) == args['source_ip'], 'invalid_source_ip')
        if extra in args:
            need(isinstance(args[extra], str) and re.fullmatch(r'[0-9]{1,10}', args[extra]), 'invalid_sensor_id')
        key = encoded(event); need(key not in seen, 'duplicate_event_query'); seen.add(key)
        ips.add(args['source_ip'])
    need(len(ips) == 1, 'one_source_ip_required')
    seen = set()
    for args in diagnostics:
        need(isinstance(args, dict) and {'target'} <= set(args) <=
             {'target', 'lookback_minutes', 'limit', 'since_kst', 'until_kst'}, 'invalid_diagnostic_arguments')
        need(isinstance(args['target'], str) and re.fullmatch(r'[abc]:[a-z0-9-]{1,40}', args['target']),
             'invalid_diagnostic_target')
        key = encoded(args); need(key not in seen, 'duplicate_diagnostic_query'); seen.add(key)
    web = value.get('web_context')
    if web is not None:
        need(isinstance(web, dict) and set(web) == {'since_kst', 'until_kst', 'limit'}, 'invalid_web_context')
        window(web)
        need(any(all(web[k] == e['arguments'][k] for k in web) for e in events), 'web_window_not_requested')
    need(len(encoded(value)) <= 8192, 'bundle_input_limit')
    return copy.deepcopy(value)


def tool():
    clock = {'type': 'string', 'description': 'Exact ISO8601 seconds and +09:00; interval at most24h, never future.'}
    interval = {'since_kst': clock, 'until_kst': clock,
                'limit': {'type': 'integer', 'minimum': 1, 'maximum': 50}}
    event_branches = []
    for sensor in EVENTS:
        properties = {**interval, 'source_ip': {'type': 'string'},
                      ('rule_id' if sensor == 'modsecurity' else 'signature_id'):
                          {'type': 'string', 'pattern': '^[0-9]{1,10}$'}}
        event_branches.append({'type': 'object', 'additionalProperties': False,
            'required': ['sensor', 'arguments'], 'properties': {
                'sensor': {'type': 'string', 'const': sensor},
                'arguments': {'type': 'object', 'additionalProperties': False,
                    'required': ['since_kst', 'until_kst', 'source_ip', 'limit'], 'properties': properties}}})
    return {'name': 'collect_incident_evidence',
        'description': 'Collect explicitly requested WAF/IDS windows and optional fixed system diagnostics in one read-only call. '
            'With web_context, join observed WAF paths to fixed C configuration candidates and read their registered agent alerts and backend access rows in that exact window. '
            'One source IP, up to8 event reads and4 diagnostic reads. Each component retains arguments, result, KST times and errors. '
            'Execution completeness is not safety, recovery, unique transaction count, frontend destination verification or approval. Additional investigation remains possible.',
        'inputSchema': {'type': 'object', 'additionalProperties': False, 'required': ['events'], 'properties': {
            'events': {'type': 'array', 'minItems': 1, 'maxItems': 8, 'items': {'anyOf': event_branches}},
            'diagnostics': {'type': 'array', 'maxItems': 4, 'items': {'type': 'object', 'additionalProperties': False,
                'required': ['target'], 'properties': {'target': {'type': 'string', 'pattern': '^[abc]:[a-z0-9-]{1,40}$',
                    'description': 'An existing fixed get_system_diagnostics target; no caller host, command or path.'},
                    'lookback_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 240},
                    **interval}}},
            'web_context': {'type': 'object', 'additionalProperties': False,
                'required': list(interval), 'properties': interval}}},
        'annotations': {'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True}}


def collect(value, read, validate, clock=now):
    """read/validate are fixed server functions, never supplied by a tool caller."""
    args = request(value); started = clock(); components = []
    first = [(EVENTS[e['sensor']], e['arguments']) for e in args['events']]
    first += [('get_system_diagnostics', a) for a in args.get('diagnostics', [])]
    # Validate the optional window before any I/O, even when no path will match.
    # The target is a fixed validator input only; this does not dispatch a read.
    if args.get('web_context'):
        validate('search_web_access', {'target': 'c:dvwa', **args['web_context']})

    def execute(job):
        name, params = job
        begin = clock()
        try:
            result = read(name, copy.deepcopy(params))
            need(isinstance(result, dict), 'component_result_type')
            if name in (*EVENTS.values(), 'search_wazuh_alerts') and not (result.get('error') or result.get('isError')):
                need(isinstance(result.get('alerts'), list), 'component_alert_rows_invalid')
            raw = encoded(result)
            need(len(raw) <= MAX_COMPONENT_BYTES, 'component_result_bound')
            error = bool(result.get('error') or result.get('isError'))
        except Exception as exc:
            # Exception text can include remote endpoints or credentials.
            result = {'error': 'component_read_failed', 'exception_class': type(exc).__name__}
            raw, error = encoded(result), True
        return {'tool': name, 'arguments': copy.deepcopy(params), 'started_at_kst': begin,
                'completed_at_kst': clock(), 'result': result, 'is_error': error,
                'result_sha256': hashlib.sha256(raw).hexdigest()}

    def phase(jobs):
        need(len(components) + len(jobs) <= MAX_COMPONENTS, 'component_count_bound')
        # Refuse the entire supplied plan before the first I/O. Derived reads
        # also pass the exact same component validators before dispatch.
        for name, params in jobs:
            need(name in READ_NAMES, 'read_not_allowed')
            validate(name, copy.deepcopy(params))
        if not jobs:
            return []
        with ThreadPoolExecutor(max_workers=min(4, len(jobs))) as pool:
            rows = list(pool.map(execute, jobs))
        for row in rows:
            row['index'] = len(components); components.append(row)
        return rows

    initial = phase(first)
    paths = sorted({row['request_path'] for part in initial
        if part['tool'] == 'search_modsecurity_alerts' and not part['is_error']
        for row in part['result'].get('alerts', []) if isinstance(row, dict)
        and isinstance(row.get('request_path'), str) and row['request_path'].startswith('/')
        and len(row['request_path']) <= 1024})
    candidates = [t for t, prefix in PREFIXES.items() if any(
        p.startswith(prefix) or p == prefix.rstrip('/') for p in paths)] if args.get('web_context') else []
    associations, skipped, follow = [], [], []
    for part in phase([('get_web_service_target', {'target': t}) for t in candidates]):
        target = part['arguments']['target']; result = part['result']
        service, agent = result.get('service', {}), result.get('agent', {})
        if (part['is_error'] or result.get('target') != target or not isinstance(service, dict)
                or not isinstance(agent, dict) or service.get('configured_in_file_snapshot') is not True
                or service.get('request_path_prefix') != PREFIXES[target]
                or not isinstance(agent.get('id'), str) or not re.fullmatch(r'[0-9]{3,8}', agent['id'])):
            skipped.append({'target': target, 'reason': 'configuration_or_agent_unverified',
                            'component_index': part['index']})
            continue
        associations.append({'target': target, 'agent_id': agent['id'], 'configuration_component': part['index'],
            'matching_observed_paths': [p for p in paths if p.startswith(PREFIXES[target]) or p == PREFIXES[target].rstrip('/')],
            'scope': 'configured_prefix_candidate_not_frontend_destination_or_impact_attestation'})
        web = args['web_context']
        # Proxy source preservation is unverified; never copy the attacker IP
        # into a backend filter or replace registered identity with an IP guess.
        follow.append(('search_web_access', {'target': target, **web}))
        alert_read = ('search_wazuh_alerts', {'agent_id': agent['id'], **web})
        if alert_read not in follow:
            follow.append(alert_read)
    phase(follow)
    result = {'format': FORMAT, 'request': args, 'started_at_kst': started, 'completed_at_kst': clock(),
        'components': components, 'candidate_associations': associations, 'unserved_candidates': skipped,
        'web_lookup': ('not_requested' if not args.get('web_context') else
                       'no_mapped_observed_path' if not candidates else 'configuration_candidates_checked'),
        'execution_complete': not skipped and all(not c['is_error'] for c in components),
        'execution_scope': 'only_listed_reads_not_complete_incident_coverage_or_judgment',
        'mutation_performed': False, 'untrusted_evidence': True}
    need(len(encoded(result)) <= MAX_RESULT_BYTES, 'bundle_result_bound_use_individual_reads')
    return result
