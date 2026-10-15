#!/usr/bin/env python3
"""One-shot, root-only native OpenSearch verifier. Synthetic test namespace only.

No service/production index/config writes; no packages. Every uncertain mutation
is recorded and never retried. Test monitor is disabled with no actions. Results
contain counts/decisions/owned IDs, never credentials or operating documents.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import time
import uuid

MID = '1e143067c98a44ffba6eaa925dc038d7'
DOCKER = '/usr/local/bin/docker'
CONTAINER = 'single-node-wazuh.indexer-1'
PREFIX = 'capstone-test-indexer-window-20261014-'
API = '/_plugins/_alerting/monitors'
MAX_RESPONSE = 4 * 1024 * 1024
MAX_REQUEST = 24 * 1024 * 1024
ROOT = Path(__file__).resolve().parent


class Refused(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def load(raw):
    def pairs(rows):
        out = {}
        for k, v in rows:
            require(k not in out, 'duplicate_json_key')
            out[k] = v
        return out
    def reject(_):
        raise Refused('nonfinite_json')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject)
    except (ValueError, UnicodeError) as error:
        raise Refused('invalid_json') from error


def private(path, directory=False):
    s = path.lstat()
    require((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
            and s.st_uid == 0 and s.st_mode & 0o077 == 0
            and (directory or s.st_nlink == 1), 'unsafe_private_path')


def atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(encode(data) + b'\n'); f.flush(); os.fsync(f.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Native:
    def __init__(self, out):
        self.out = out
        self.index = PREFIX + uuid.uuid4().hex
        self.monitor_id = None
        self.index_uuid = None
        self.result = {'schema_version': 1, 'status': 'running',
            'started_at_epoch_ms': time.time_ns() // 1000000,
            'index': self.index, 'monitor_id': None, 'mutations': [],
            'query_cases': [], 'v1_comparison': [], 'lifecycle': [],
            'strict_tls': True, 'production_inputs_written': False,
            'actions_configured': 0, 'cleanup': {}}
        r = subprocess.run([DOCKER, 'inspect', '--format', '{{.Id}} {{.State.Running}}', CONTAINER],
                           capture_output=True, timeout=10, check=False)
        words = r.stdout.decode('ascii', 'strict').strip().split()
        require(r.returncode == 0 and len(words) == 2 and re.fullmatch('[0-9a-f]{64}', words[0])
                and words[1] == 'true', 'indexer_not_running')
        self.cid = words[0]
        self.result['indexer_container_id'] = self.cid
        self.save()

    def save(self):
        atomic(self.out / 'validation.json', self.result)

    def request(self, method, path, body=None, expected=(200,), *, mutation=False, operation=None, ndjson=False):
        # No wildcard/index API, operating index, stored operating monitor, or notification API.
        indexpaths = {('/' + self.index), '/' + self.index + '/_bulk?refresh=true',
                      '/' + self.index + '/_delete_by_query?refresh=true',
                      '/' + self.index + '/_search', '/' + self.index + '/_settings'}
        allowed = path in indexpaths or re.fullmatch(re.escape(API) + r'/_execute\?dryrun=true&period_end=[0-9]+ms', path) is not None
        if method == 'POST' and path == API:
            allowed = True
        if self.monitor_id:
            allowed |= (method == 'POST' and re.fullmatch(re.escape(API + '/' + self.monitor_id) + r'/_execute\?period_end=[0-9]+ms', path) is not None)
            allowed |= (method == 'PUT' and re.fullmatch(re.escape(API + '/' + self.monitor_id) + r'\?if_seq_no=[0-9]+&if_primary_term=[1-9][0-9]*', path) is not None)
            allowed |= path in {API + '/' + self.monitor_id, API + '/' + self.monitor_id + '/_execute',
                API + '/alerts?monitorId=' + self.monitor_id + '&size=100&alertState=ALL'}
        require(allowed, 'api_path_outside_owned_namespace')
        raw = body if ndjson else (encode(body) if body is not None else None)
        require(raw is None or len(raw) <= MAX_REQUEST, 'request_too_large')
        entry = None
        if mutation:
            entry = {'operation': operation, 'method': method, 'path': path,
                     'request_sha256': hashlib.sha256(raw or b'').hexdigest(),
                     'started_at_epoch_ms': time.time_ns() // 1000000, 'outcome': 'pending'}
            self.result['mutations'].append(entry); self.save()
        cert = '/usr/share/wazuh-indexer/config/certs/'
        cmd = [DOCKER, 'exec', '-i', self.cid, 'curl', '--disable', '--silent', '--show-error',
               '--max-time', '40', '--max-filesize', str(MAX_RESPONSE), '--noproxy', '*',
               '--cacert', cert + 'root-ca.pem', '--cert', cert + 'admin.pem', '--key', cert + 'admin-key.pem',
               '-H', 'Content-Type: ' + ('application/x-ndjson' if ndjson else 'application/json'),
               '-X', method, '-w', '\n%{http_code}', 'https://wazuh.indexer:9200' + path]
        if raw is not None:
            cmd += ['--data-binary', '@-']
        def limit():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESPONSE + 4096, MAX_RESPONSE + 4096))
        try:
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                kw = {'stdin': subprocess.DEVNULL} if raw is None else {'input': raw}
                r = subprocess.run(cmd, **kw, stdout=output, stderr=errors, timeout=50,
                                   preexec_fn=limit, check=False)
                require(r.returncode == 0, 'request_failed_or_reply_uncertain')
                output.seek(0); answer = output.read(MAX_RESPONSE + 1)
            require(len(answer) <= MAX_RESPONSE, 'response_too_large')
            content, status = answer.rsplit(b'\n', 1); status = int(status)
            value = load(content)
            if entry is not None:
                entry.update(outcome='response_received', http_status=status, response_sha256=hashlib.sha256(content).hexdigest())
                self.save()
            require(status in expected, 'http_' + str(status))
            return status, value
        except BaseException:
            if entry is not None and entry['outcome'] == 'pending':
                entry['outcome'] = 'uncertain_no_retry'; self.save()
            raise

    def create_index(self):
        mapping = {'settings': {'number_of_shards': 2, 'number_of_replicas': 0},
            'mappings': {'date_detection': False, 'dynamic_templates': [
                {'strings': {'match_mapping_type': 'string', 'mapping': {'type': 'keyword'}}}],
                'properties': {'timestamp': {'type': 'date'}}}}
        _, v = self.request('PUT', '/' + self.index, mapping, (200,), mutation=True, operation='create_test_index')
        require(v.get('acknowledged') is True and v.get('index') == self.index, 'index_create_not_acknowledged')
        self.index_uuid = self.get_index_uuid()
        self.result['index_uuid'] = self.index_uuid; self.save()

    def get_index_uuid(self):
        _, value = self.request('GET', '/' + self.index + '/_settings')
        require(set(value) == {self.index}, 'index_settings_scope_changed')
        v = value[self.index]['settings']['index']['uuid']
        require(isinstance(v, str) and re.fullmatch('[A-Za-z0-9_-]{10,100}', v), 'index_uuid_invalid')
        return v

    def clear(self):
        require(self.get_index_uuid() == self.index_uuid, 'test_index_identity_changed')
        _, v = self.request('POST', '/' + self.index + '/_delete_by_query?refresh=true',
                            {'query': {'match_all': {}}}, mutation=True, operation='clear_owned_synthetic_documents')
        require(v.get('timed_out') is False and v.get('version_conflicts') == 0 and v.get('failures') == [],
                'test_clear_partial')

    def bulk(self, docs):
        require(len(docs) <= 10001, 'fixture_record_limit')
        if not docs:
            return
        raw = b''.join(encode({'index': {'_id': str(i)}}) + b'\n' + encode(doc) + b'\n'
                       for i, doc in enumerate(docs))
        _, v = self.request('POST', '/' + self.index + '/_bulk?refresh=true', raw,
                            mutation=True, operation='load_synthetic_fixture', ndjson=True)
        require(v.get('errors') is False and len(v.get('items', [])) == len(docs), 'bulk_partial')
        require(all(row.get('index', {}).get('status') in (200, 201)
                    and row['index'].get('_index') == self.index for row in v['items']), 'bulk_item_invalid')

    def template(self, candidate):
        monitor = copy.deepcopy(candidate)
        require(monitor.get('enabled') is False and len(monitor.get('inputs', [])) == 1, 'candidate_must_be_disabled')
        require(len(monitor.get('triggers', [])) == 2 and all(
            x['query_level_trigger']['actions'] == [] for x in monitor['triggers']), 'candidate_has_actions')
        monitor['name'] = self.index
        monitor['schema_version'] = 8  # Installed Alerting model version; no production monitor change.
        monitor['inputs'][0]['search']['indices'] = [self.index]
        return monitor

    def execute(self, candidate, end, saved=False):
        require(type(end) is int and end > 0, 'invalid_period_end')
        body = None if saved else self.template(candidate)
        path = (API + '/' + self.monitor_id + '/_execute?period_end=' + str(end) + 'ms' if saved
                else API + '/_execute?dryrun=true&period_end=' + str(end) + 'ms')
        _, value = self.request('POST', path, body, mutation=True,
                                operation='execute_saved_disabled_monitor' if saved else 'inline_native_dryrun')
        # Details are preserved only on B; console never prints script/query/error bodies.
        atomic(self.out / 'last-native-response.json', value)
        require(value.get('period_end') == end, 'native_period_end_not_applied')
        require(value.get('error') is None, 'native_execute_error')
        inputs = value.get('input_results', {})
        require(inputs.get('error') is None, 'native_input_error')
        results = inputs.get('results', [])
        require(len(results) == 1, 'native_result_count')
        result = results[0]
        shards = result.get('_shards', {})
        require(result.get('timed_out') is False and shards.get('total') == 2
                and shards.get('successful') == 2 and shards.get('failed') == 0, 'query_partial')
        require(result.get('hits', {}).get('hits') == [], 'unexpected_source_documents')
        triggers = value.get('trigger_results', {})
        decision = {}
        for item in candidate['triggers']:
            trigger = item['query_level_trigger']
            row = triggers.get(trigger['id'], {})
            require(row.get('error') is None and type(row.get('triggered')) is bool
                    and row.get('action_results') == {}, 'native_trigger_error_or_action')
            decision[trigger['name']] = row['triggered']
        return {'period_end_epoch_ms': end, 'metric': result.get('aggregations', {}).get('observation', {}).get('value'),
                'hits': result['hits']['total'], 'shards': shards,
                'terminated_early': result.get('terminated_early', False), **decision}

    def monitor_owned(self):
        _, value = self.request('GET', API + '/' + self.monitor_id)
        monitor = value.get('monitor', {})
        require(value.get('_id') == self.monitor_id and monitor.get('name') == self.index
                and monitor.get('enabled') is False
                and monitor.get('inputs', [{}])[0].get('search', {}).get('indices') == [self.index]
                and len(monitor.get('triggers', [])) == 2
                and all(x.get('query_level_trigger', x).get('actions') == [] for x in monitor['triggers']),
                'saved_monitor_identity_changed')
        return value

    def alerts(self):
        self.monitor_owned()
        _, value = self.request('GET', API + '/alerts?monitorId=' + self.monitor_id + '&size=100&alertState=ALL')
        rows = value.get('alerts')
        require(isinstance(rows, list) and len(rows) <= 10 and value.get('totalAlerts') == len(rows), 'alert_result_truncated')
        output = []
        for row in rows:
            require(row.get('monitor_id') == self.monitor_id and row.get('monitor_name') == self.index
                    and re.fullmatch('[A-Za-z0-9_-]{1,200}', row.get('id', ''))
                    and row.get('error_message') is None, 'alert_scope_or_error')
            output.append({key: row.get(key) for key in ('id', 'trigger_id', 'state', 'start_time', 'end_time')})
        return output

    def verify_saved_roundtrip(self, candidate):
        before = self.monitor_owned()
        manager = import_fixture(ROOT / 'manage-monitor-b.py')
        module = manager.module('v2')
        wanted = self.template(candidate)
        require(module.canonical_search(before['monitor']['inputs'][0]['search']) ==
                module.canonical_search(wanted['inputs'][0]['search']), 'v2_canonical_search_mismatch')
        body = copy.deepcopy(before['monitor']); body.pop('last_update_time', None)
        seq = before.get('_seq_no'); term = before.get('_primary_term')
        require(type(seq) is int and seq >= 0 and type(term) is int and term > 0, 'saved_cas_revision_missing')
        path = API + '/' + self.monitor_id + '?if_seq_no=' + str(seq) + '&if_primary_term=' + str(term)
        _, changed = self.request('PUT', path, body, mutation=True, operation='same_config_disabled_monitor_cas_roundtrip')
        after = self.monitor_owned()
        require(changed.get('_id') == self.monitor_id and after.get('_seq_no') == changed.get('_seq_no')
                and after['_seq_no'] > seq and changed.get('monitor') == after.get('monitor'), 'cas_readback_mismatch')
        require(manager.unchanged_fields(before['monitor'], after['monitor']), 'server_owned_fields_changed')
        require(module.canonical_search(after['monitor']['inputs'][0]['search']) ==
                module.canonical_search(wanted['inputs'][0]['search']), 'v2_canonical_search_changed')
        self.result['disabled_monitor_roundtrip'] = {'passed': True, 'canonical_v2_search_equal': True,
            'enabled_time_equal': before['monitor'].get('enabled_time') == after['monitor'].get('enabled_time'),
            'schema_user_permissions_schedule_equal': True, 'trigger_metadata_equal': True,
            'enabled': False, 'enabled_monitor_timestamp_behavior_proven': False,
            'before_seq_no': seq, 'after_seq_no': after['_seq_no']}
        self.save()

    def lifecycle(self, candidate, fixtures):
        self.clear()
        monitor = self.template(candidate)
        _, created = self.request('POST', API, monitor, (200, 201), mutation=True, operation='save_disabled_test_monitor')
        # Record server-issued ownership immediately, before validating additional fields.
        self.monitor_id = created.get('_id')
        require(isinstance(self.monitor_id, str) and re.fullmatch('[A-Za-z0-9_-]{1,200}', self.monitor_id), 'created_monitor_id_invalid')
        self.result['monitor_id'] = self.monitor_id; self.save(); self.monitor_owned()
        self.verify_saved_roundtrip(candidate)
        end = time.time_ns() // 1000000
        docs = [fixtures.document(end, i, -1_000_000) for i in range(5)]
        self.bulk(docs)
        first_id = None
        for step in ('true_first', 'true_same', 'false_complete', 'true_new'):
            if step == 'false_complete':
                self.clear()
            if step == 'true_new':
                end = time.time_ns() // 1000000
                self.bulk([fixtures.document(end, 'new-' + str(i), -1_000_000) for i in range(5)])
            got = self.execute(candidate, time.time_ns() // 1000000, saved=True)
            wanted = step != 'false_complete'
            require(got['observation_match'] is wanted and not got['observation_unavailable'], 'lifecycle_decision')
            # Reads may repeat; the stateful execute above never repeats.
            rows = []
            for _ in range(20):
                rows = self.alerts()
                active = [r for r in rows if r['state'] == 'ACTIVE']
                complete = [r for r in rows if r['state'] == 'COMPLETED']
                if ((wanted and len(active) == 1 and (step != 'true_new' or len(complete) == 1))
                        or (not wanted and not active and len(complete) == 1)):
                    break
                time.sleep(0.25)
            active = [r for r in rows if r['state'] == 'ACTIVE']
            complete = [r for r in rows if r['state'] == 'COMPLETED']
            require(all(r['trigger_id'] == candidate['triggers'][0]['query_level_trigger']['id'] for r in rows), 'unexpected_lifecycle_trigger')
            if step == 'true_first':
                require(len(rows) == 1 and len(active) == 1, 'first_alert_missing'); first_id = active[0]['id']
            elif step == 'true_same':
                require(len(rows) == 1 and len(active) == 1 and active[0]['id'] == first_id, 'repeat_alert_identity_changed')
            elif step == 'false_complete':
                require(len(rows) == 1 and len(complete) == 1 and complete[0]['id'] == first_id and complete[0]['end_time'] is not None, 'alert_not_completed')
            else:
                require(len(rows) == 2 and len(active) == 1 and len(complete) == 1
                        and complete[0]['id'] == first_id and active[0]['id'] != first_id, 'new_alert_lifecycle_invalid')
            self.result['lifecycle'].append({'step': step, 'decisions': got, 'alerts': rows, 'passed': True}); self.save()

    def cleanup(self):
        failures = []
        if self.monitor_id:
            try:
                self.monitor_owned()
                _, value = self.request('DELETE', API + '/' + self.monitor_id, mutation=True, operation='delete_owned_test_monitor')
                require(value.get('_id') == self.monitor_id, 'monitor_delete_identity')
                status, _ = self.request('GET', API + '/' + self.monitor_id, expected=(404,))
                self.result['cleanup']['monitor_deleted_verified'] = status == 404
            except BaseException as error:
                failures.append('monitor:' + (str(error) if isinstance(error, Refused) else type(error).__name__))
        if self.index_uuid:
            try:
                require(self.get_index_uuid() == self.index_uuid, 'cleanup_index_identity_changed')
                _, value = self.request('DELETE', '/' + self.index, mutation=True, operation='delete_owned_test_index')
                require(value.get('acknowledged') is True, 'index_delete_not_acknowledged')
                status, _ = self.request('GET', '/' + self.index, expected=(404,))
                self.result['cleanup']['index_deleted_verified'] = status == 404
            except BaseException as error:
                failures.append('index:' + (str(error) if isinstance(error, Refused) else type(error).__name__))
        self.result['cleanup']['failures'] = failures; self.save()


def import_fixture(path, raw=None):
    # Compile the bytes checked by the caller, without a second source read or pycache.
    import types
    module = types.ModuleType('native_fixture_' + path.stem.replace('-', '_'))
    module.__file__ = str(path)
    exec(compile(path.read_bytes() if raw is None else raw, str(path), 'exec'), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--fixtures-sha256', required=True)
    parser.add_argument('--v1', required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'wrong_host_or_uid')
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    out = Path(args.output)
    require(str(out).startswith('/var/tmp/capstone-short-priority-20261014/step2/native-test/')
            and not out.exists() and '..' not in out.parts, 'output_requires_new_private_directory')
    private(out.parent, True); out.mkdir(mode=0o700)
    source = ROOT / 'monitor.json'; fixture = ROOT / 'fixtures.py'
    for path in (source, fixture):
        s = path.lstat()
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and not s.st_mode & 0o022, 'unsafe_source')
    candidate_raw = source.read_bytes(); fixture_raw = fixture.read_bytes()
    require(hashlib.sha256(candidate_raw).hexdigest() == args.candidate_sha256, 'candidate_sha_changed')
    require(hashlib.sha256(fixture_raw).hexdigest() == args.fixtures_sha256, 'fixtures_sha_changed')
    candidate = load(candidate_raw); fixtures = import_fixture(fixture, fixture_raw)
    v1raw = Path(args.v1).read_bytes()
    require(hashlib.sha256(v1raw).hexdigest() == 'f0262be494e605edcb22fb32f71f4854014dd4f671b035803886a5b1036bafd1', 'v1_sha_changed')
    v1 = load(v1raw)
    native = Native(out)
    native.result['sources'] = {p.name: {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size}
                                for p in (source, fixture, Path(__file__), ROOT / 'manage-monitor-b.py', ROOT.parent / 'deploy-monitor-b.py')}
    native.result['primary_references'] = ['https://docs.opensearch.org/latest/observing-your-data/alerting/api/',
        'https://docs.opensearch.org/latest/observing-your-data/alerting/monitors/',
        'https://raw.githubusercontent.com/opensearch-project/alerting/main/alerting/src/main/kotlin/org/opensearch/alerting/resthandler/RestExecuteMonitorAction.kt']
    try:
        native.create_index()
        # Get names without retaining several large fixture arrays at once.
        names = [c['name'] for c in fixtures.cases(time.time_ns() // 1000000)]
        for name in names:
            native.clear()
            end = time.time_ns() // 1000000
            case = next(c for c in fixtures.cases(end) if c['name'] == name)
            native.bulk(case['documents'])
            got = native.execute(candidate, end)
            metric = got['metric']
            require(isinstance(metric, dict), 'metric_missing:' + name)
            matches = all(metric.get(k) == v for k, v in case['expected'].items())
            require(got['observation_match'] == case['expected']['match']
                    and got['observation_unavailable'] == (not case['expected']['valid']), 'trigger_mismatch:' + name)
            row = {'name': name, 'loaded_documents': len(case['documents']), 'expected': case['expected'],
                   'observed': got, 'passed': matches}
            native.result['query_cases'].append(row); native.save()
            require(matches, 'metric_mismatch:' + name)
            if name in ('old_sixty_second_window_retained', 'delayed_companion_beyond_old_processing_120s',
                        'five_over_240_seconds_not_a_window', 'five_same_timestamp'):
                old = native.execute(v1, end)
                native.result['v1_comparison'].append({'name': name, 'v1': old,
                    'v2': got, 'different_match': old['observation_match'] != got['observation_match']}); native.save()
        native.lifecycle(candidate, fixtures)
        native.result['status'] = 'passed'
    except BaseException as error:
        native.result['status'] = 'failed'
        native.result['failure_code'] = str(error) if isinstance(error, Refused) else type(error).__name__
    finally:
        native.cleanup()
        if native.result['cleanup'].get('failures'):
            native.result['status'] = 'failed'
        native.result['completed_at_epoch_ms'] = time.time_ns() // 1000000
        native.save()
    print(json.dumps({'status': native.result['status'], 'query_cases': len(native.result['query_cases']),
                      'lifecycle_steps': len(native.result['lifecycle']), 'failure_code': native.result.get('failure_code'),
                      'cleanup': native.result['cleanup'], 'result': str(out / 'validation.json')}))
    return 0 if native.result['status'] == 'passed' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refused as error:
        print(json.dumps({'status': 'refused', 'code': str(error)})); raise SystemExit(1)
