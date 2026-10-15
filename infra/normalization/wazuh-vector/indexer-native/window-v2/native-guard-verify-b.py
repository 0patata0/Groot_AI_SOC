#!/usr/bin/env python3
"""Finite native predicate checks; no index, monitor, stored-script, or service writes.

The exact frozen common source and both exact decision suffixes are wrapped in
test functions. Only synthetic ctx values are supplied to painless_test. This
checks guard decisions, not the behavior of a real partial search or an outage.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
import time

MID = '1e143067c98a44ffba6eaa925dc038d7'
DOCKER = '/usr/local/bin/docker'
CONTAINER = 'single-node-wazuh.indexer-1'
TASK = Path('/var/tmp/capstone-short-priority-20261014/step2/guard-test')
LIMIT = 262144
PINS = {
    'trigger-common.painless': 'fbf9bbb1a08f04119f39da17f1b5e9a95c763277f1b085780be8f491bd72e7ad',
    'monitor-match.painless': '982bb42c68e56fa463702175c281b2e3308333988fb8ad4258bdc71931cc1f03',
    'monitor-unavailable.painless': 'a7bf19d1a3a1d3dde69f34d900735c966bd9b24a781b2d566c8beff1d0b39abf',
    'monitor.json': 'acc8ac9649cc8b974872a30cf4bcc8f2e52adf0caf56ed197e8b95066d657c7f',
}


class Refused(Exception):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def invalid(_):
        raise Refused('invalid_json_number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def private(path, directory=False):
    s = path.lstat()
    require((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
            and s.st_uid == 0 and s.st_mode & 0o077 == 0
            and (directory or s.st_nlink == 1), 'unsafe_private_path')


def save(path, value):
    fd, temp = tempfile.mkstemp(prefix='.guard-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(encode(value) + b'\n'); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def source(root, live):
    blobs = {}
    for name, pin in PINS.items():
        path = root / name
        if live:
            private(path)
        raw = path.read_bytes()
        require(len(raw) < 65536 and hashlib.sha256(raw).hexdigest() == pin, 'source_pin_changed')
        blobs[name] = raw.decode('utf-8')
    common = blobs['trigger-common.painless']
    monitor = strict_json(blobs['monitor.json'])
    triggers = monitor['triggers']
    require(len(triggers) == 2 and all(x['query_level_trigger']['actions'] == [] for x in triggers),
            'candidate_action_boundary')
    suffixes = []
    for index, name in enumerate(('monitor-match.painless', 'monitor-unavailable.painless')):
        complete = blobs[name]
        require(complete.startswith(common) and
                triggers[index]['query_level_trigger']['condition']['script']['source'] == complete,
                'candidate_decision_source_mismatch')
        suffixes.append(complete[len(common):])
    # The common source and each decision body are unmodified. Only the test
    # context construction and enclosing function declarations are additional.
    wrapper = common + '\nboolean originalMatch(def ctx) {\n' + suffixes[0] + '\n}\n'
    wrapper += 'boolean originalUnavailable(def ctx) {\n' + suffixes[1] + '\n}\n'
    wrapper += '''
def ctx = params.synthetic_ctx;
if (params.period_mode == 'relative') {
    ctx.periodEnd = Instant.ofEpochMilli(new Date().getTime() + params.offset_ms);
} else if (params.period_mode == 'ancient') {
    ctx.periodEnd = Instant.ofEpochMilli(299999);
} else if (params.period_mode == 'invalid') {
    ctx.periodEnd = 'not-an-instant';
}
return [observationAvailable(ctx), originalMatch(ctx), originalUnavailable(ctx)];
'''
    return wrapper


def fixture_cases():
    metric = dict(policy='event-window-v2', precision='microseconds', valid=True,
                  reason='ok', match=True, documents=5, unique_events=5,
                  duplicate_documents=0, services=1, matched_services=1,
                  repeat_services=1, cross_source_services=0)
    ctx = {'error': None, 'results': [{'timed_out': False, 'terminated_early': False,
        '_shards': dict(total=2, successful=2, skipped=0, failed=0),
        'hits': {'total': {'relation': 'eq', 'value': 5}, 'hits': []},
        'aggregations': {'observation': {'value': metric}}}]}
    cases = []

    def case(name, path=None, value=None, expected=(False, False, True), *, delete=False,
             changes=None, offset=-1000, mode='relative'):
        item = copy.deepcopy(ctx)
        edits = ([] if path is None else [(path, value, delete)]) + (changes or [])
        for keys, new, remove in edits:
            target = item
            for key in keys[:-1]:
                target = target[key]
            if remove:
                del target[keys[-1]]
            else:
                target[keys[-1]] = new
        cases.append(dict(name=name, params=dict(synthetic_ctx=item, period_mode=mode,
                     offset_ms=offset), expected=list(expected)))

    result = ['results', 0]
    total = result + ['hits', 'total']
    shards = result + ['_shards']
    met = result + ['aggregations', 'observation', 'value']
    good = (True, True, False)
    empty_good = (True, False, False)
    case('valid_repeat', expected=good)
    case('valid_cross_source', changes=[(met + [k], v, False) for k, v in
         dict(documents=2, unique_events=2, repeat_services=0, cross_source_services=1).items()]
         + [(total + ['value'], 2, False)], expected=good)
    empty = {key: 0 for key in ('documents', 'unique_events', 'duplicate_documents', 'services',
             'matched_services', 'repeat_services', 'cross_source_services')}
    empty['match'] = False
    case('empty_valid_is_not_unavailable_or_match', changes=[(met + [k], v, False)
         for k, v in empty.items()] + [(total + ['value'], 0, False)], expected=empty_good)
    case('valid_unmatched_nonempty', changes=[(met + [k], v, False) for k, v in
         dict(match=False, matched_services=0, repeat_services=0).items()], expected=empty_good)
    case('exact_10000_documents_100_services_64_shards', changes=[
        (met + [k], v, False) for k, v in dict(documents=10000, unique_events=10000,
         services=100, matched_services=100, repeat_services=100).items()]
         + [(total + ['value'], 10000, False), (shards + ['total'], 64, False),
            (shards + ['successful'], 64, False)], expected=good)
    case('valid_duplicates_are_accounted', changes=[(met + ['documents'], 10000, False),
         (met + ['duplicate_documents'], 9995, False), (total + ['value'], 10000, False)], expected=good)
    case('valid_skipped_shards_count', shards + ['skipped'], 2, expected=good)
    case('valid_missing_terminated_early', result + ['terminated_early'], delete=True, expected=good)
    case('period_end_within_future_budget', expected=good, offset=4000)
    case('period_end_within_lag_budget', expected=good, offset=-14000)
    case('period_end_stale', offset=-16000)
    case('period_end_future', offset=6000)
    case('period_end_ancient', mode='ancient')
    case('period_end_missing', mode='missing')
    case('period_end_wrong_type', mode='invalid')
    case('ctx_error', ['error'], 'synthetic_error')
    case('results_missing', ['results'], delete=True)
    case('results_empty', ['results'], [])
    case('results_multiple', ['results'], [copy.deepcopy(ctx['results'][0])] * 2)
    case('results_wrong_type', ['results'], {})
    case('result_wrong_type', result, None)
    case('timed_out', result + ['timed_out'], True)
    case('timed_out_missing', result + ['timed_out'], delete=True)
    case('terminated_early', result + ['terminated_early'], True)
    case('terminated_early_null', result + ['terminated_early'], None)
    case('shards_missing', result + ['_shards'], delete=True)
    case('shards_zero', changes=[(shards + ['total'], 0, False), (shards + ['successful'], 0, False)])
    case('shards_65', changes=[(shards + ['total'], 65, False), (shards + ['successful'], 65, False)])
    case('shards_partial', shards + ['successful'], 1)
    case('shards_failed', shards + ['failed'], 1)
    case('shards_skipped_over_total', shards + ['skipped'], 3)
    case('shards_string_total', shards + ['total'], '2')
    case('shards_float_total', shards + ['total'], 2.0)
    case('shards_boolean_total', shards + ['total'], True)
    case('shards_negative_failed', shards + ['failed'], -1)
    case('hits_missing', result + ['hits'], delete=True)
    case('total_lower_bound', total + ['relation'], 'gte')
    case('total_negative', total + ['value'], -1)
    case('total_string', total + ['value'], '5')
    case('total_float', total + ['value'], 5.0)
    case('total_boolean', total + ['value'], True)
    case('10001_documents', changes=[(total + ['value'], 10001, False),
         (met + ['documents'], 10001, False), (met + ['unique_events'], 10001, False)])
    case('unexpected_hits_source', result + ['hits', 'hits'], [{}])
    case('aggregations_missing', result + ['aggregations'], delete=True)
    case('metric_missing', met, delete=True)
    case('metric_wrong_type', met, [])
    case('metric_extra_field', met + ['extra'], 0)
    case('metric_field_missing', met + ['reason'], delete=True)
    for name, value in [('policy', 'old'), ('precision', 'milliseconds'), ('valid', False),
        ('reason', 'identity_conflict'), ('match', 'true'), ('documents', 4),
        ('unique_events', 6), ('duplicate_documents', 1), ('services', 0),
        ('matched_services', 2), ('repeat_services', 2), ('cross_source_services', 2)]:
        case('metric_' + name + '_invalid', met + [name], value)
    case('metric_101_services', changes=[(total + ['value'], 505, False)] +
         [(met + [k], v, False) for k, v in dict(documents=505, unique_events=505,
             services=101, matched_services=101, repeat_services=101).items()])
    case('metric_no_matching_reason', met + ['repeat_services'], 0)
    case('metric_false_with_matched_service', met + ['match'], False)
    case('metric_repeat_with_under_five_unique', changes=[(total + ['value'], 4, False),
         (met + ['documents'], 4, False), (met + ['unique_events'], 4, False)])
    case('metric_cross_with_under_two_unique', changes=[(total + ['value'], 1, False)] +
         [(met + [k], v, False) for k, v in dict(documents=1, unique_events=1,
             repeat_services=0, cross_source_services=1).items()])
    case('metric_nonzero_documents_without_unique', changes=[(met + [k], v, False)
         for k, v in dict(unique_events=0, duplicate_documents=5, services=0,
             matched_services=0, repeat_services=0, match=False).items()])
    require(len({x['name'] for x in cases}) == len(cases), 'duplicate_fixture_name')
    return cases


def execute(cid, source_text, params, out):
    body = encode({'context': 'painless_test', 'script': {
        'lang': 'painless', 'source': source_text, 'params': params}})
    require(len(body) <= 65536, 'request_too_large')
    cert = '/usr/share/wazuh-indexer/config/certs/'
    cmd = [DOCKER, 'exec', '-i', cid, 'curl', '--disable', '--silent', '--show-error',
        '--max-time', '30', '--max-filesize', str(LIMIT), '--noproxy', '*',
        '--cacert', cert + 'root-ca.pem', '--cert', cert + 'admin.pem', '--key', cert + 'admin-key.pem',
        '-H', 'Content-Type: application/json', '-X', 'POST', '--data-binary', '@-',
        '-w', '\n%{http_code}', 'https://wazuh.indexer:9200/_scripts/painless/_execute']
    def limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT + 4096, LIMIT + 4096))
    with tempfile.TemporaryFile(dir=out) as reply, tempfile.TemporaryFile(dir=out) as error:
        r = subprocess.run(cmd, input=body, stdout=reply, stderr=error, timeout=40,
                           preexec_fn=limit, check=False)
        require(r.returncode == 0, 'native_request_failed')
        reply.seek(0); raw = reply.read(LIMIT + 1)
    require(len(raw) <= LIMIT, 'reply_too_large')
    content, status = raw.rsplit(b'\n', 1)
    value = strict_json(content)
    if status != b'200':
        # Synthetic source/context only, kept on B for compilation diagnosis.
        save(out / 'synthetic-native-error.json', value)
        raise Refused('native_http_' + status.decode('ascii'))
    require(set(value) == {'result'} and isinstance(value['result'], str), 'native_result_shape')
    require(re.fullmatch(r'\[(true|false), (true|false), (true|false)\]', value['result']),
            'native_predicate_result_shape')
    return strict_json(value['result'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    cases = fixture_cases()
    if args.self_test:
        script = source(root, False)
        print(json.dumps({'status': 'offline_structure_pass', 'cases': len(cases),
                          'wrapper_sha256': hashlib.sha256(script.encode()).hexdigest()}))
        return
    require(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'wrong_host_or_uid')
    require(args.output is not None and args.output.parent == TASK
            and re.fullmatch('run-[0-9]{2}', args.output.name), 'output_outside_test_scope')
    private(TASK, True); private(root, True)
    require(not args.output.exists(), 'output_already_exists')
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    private(args.output, True)
    script = source(root, True)
    result = {'schema_version': 1, 'status': 'running', 'started_at_epoch_ms': time.time_ns() // 1000000,
        'api': 'POST /_scripts/painless/_execute', 'context': 'painless_test',
        'index_monitor_stored_script_mutations': 0, 'strict_tls': True,
        'source_sha256': dict(PINS), 'verifier_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'wrapper_sha256': hashlib.sha256(script.encode()).hexdigest(), 'cases': [],
        'limitations': ['Synthetic ctx guard decisions; no real shard failure or outage was induced.',
          'Exact frozen common and decision bodies are wrapped in test functions, not edited.',
          'Clock checks use 1-second margin from bounds; exact equality is not a wall-clock timing claim.',
          'Availability and unavailability are complements; match is false for healthy empty/unmatched results.']}
    destination = args.output / 'validation.json'
    save(destination, result)
    try:
        r = subprocess.run([DOCKER, 'inspect', '--format', '{{.Id}} {{.State.Running}}', CONTAINER],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
        words = r.stdout.decode('ascii').strip().split()
        require(r.returncode == 0 and len(words) == 2 and re.fullmatch('[0-9a-f]{64}', words[0])
                and words[1] == 'true', 'indexer_not_running')
        result['indexer_container_id'] = words[0]
        for case in cases:
            decision = execute(words[0], script, case['params'], args.output)
            passed = decision == case['expected'] and decision[2] is not decision[0]
            result['cases'].append({'name': case['name'], 'expected': case['expected'],
                'observed': decision, 'passed': passed,
                'fixture_sha256': hashlib.sha256(encode(case['params'])).hexdigest()})
            save(destination, result)
            require(passed, 'native_guard_mismatch')
        result.update(status='pass', total_cases=len(cases), passed_cases=len(result['cases']),
                      native_calculations=len(result['cases']), candidate_unchanged=True)
        source(root, True)
    except BaseException as error:
        result.update(status='failed', error=(str(error) if isinstance(error, Refused) else type(error).__name__))
        raise
    finally:
        result['completed_at_epoch_ms'] = time.time_ns() // 1000000
        save(destination, result)
        print(json.dumps({'status': result['status'], 'completed_cases': len(result['cases']),
                          'output': str(destination), 'error': result.get('error')}))


if __name__ == '__main__':
    main()
