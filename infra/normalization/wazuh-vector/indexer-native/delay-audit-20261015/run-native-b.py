#!/usr/bin/env python3
"""Bounded operator test: owned synthetic index/disabled monitor, no services.

Age fixtures are not real outages. --timed additionally withholds index refresh
for 130 seconds and this test's evaluations for 180 seconds. Never restarts the
Indexer or changes production rules, inputs, monitors, settings, or checkpoints.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import time
import types

ROOT = Path(__file__).resolve().parent
V2 = ROOT.parent / 'window-v2'
PINS = {
    'native-verify-b.py': '4d596e890b32299b1a0a06eb39caa4e7386c3d3557954bcfd9ecc1dcb0304d3e',
    'fixtures.py': '3452610c790c8ca9b03d41d303c8c5f7f6d10b286f75e3b5da45a1ad956b3bcc',
    'monitor.json': 'acc8ac9649cc8b974872a30cf4bcc8f2e52adf0caf56ed197e8b95066d657c7f',
}
MID = '1e143067c98a44ffba6eaa925dc038d7'
PREFIX = 'capstone-test-indexer-delay-20261015-'
OUTPUT = Path('/var/tmp/capstone-delay-audit-20261015')
EXECUTION_REVIEWED = True


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def checked_bytes(path, wanted, *, owner=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (not owner or before.st_uid == 0) and not before.st_mode & 0o022,
                'source_metadata_invalid')
        require(before.st_size <= 2 * 1024 * 1024, 'source_size_bound')
        raw = b''
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw += block
        after = os.fstat(fd); named = path.lstat()
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
                            s.st_uid, s.st_gid, s.st_mode, s.st_nlink)
        require(fields(before) == fields(after) == fields(named), 'source_changed')
        require(len(raw) == before.st_size and hashlib.sha256(raw).hexdigest() == wanted,
                'source_sha_mismatch')
        return raw
    finally:
        os.close(fd)


def module(raw, path):
    result = types.ModuleType('delay_audit_' + path.stem.replace('-', '_'))
    result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def adapted_transport(raw):
    """Reuse pinned TLS/response/uncertain-mutation code with only these edits.

    Two owned-index paths permit delayed refresh. HTTP/process deadlines become
    per-request values capped at 10/12 seconds by the subclass. No auth or scope
    loosening for any production index, monitor, notification, or cluster API.
    """
    replacements = (
        ("indexpaths = {('/' + self.index), '/' + self.index + '/_bulk?refresh=true',",
         "indexpaths = {('/' + self.index), '/' + self.index + '/_bulk?refresh=true', '/' + self.index + '/_bulk?refresh=false', '/' + self.index + '/_refresh',"),
        ("'--max-time', '40',", "'--max-time', str(self.http_timeout),"),
        ('timeout=50,', 'timeout=self.process_timeout,'),
    )
    value = raw.decode('utf-8')
    for old, new in replacements:
        require(value.count(old) == 1, 'frozen_transport_patch_context')
        value = value.replace(old, new)
    return value.encode('utf-8')


def progress(phase, started):
    print(json.dumps({'policy': 'indexer-delay-audit-v1', 'phase': phase,
                      'elapsed_seconds': round(time.monotonic() - started, 3),
                      'synthetic_only': True}), flush=True)


def container_identity(cid):
    fmt = ('{"cid":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
           '"restarting":{{json .State.Restarting}},"pid":{{json .State.Pid}},'
           '"started_at":{{json .State.StartedAt}},"restart_count":{{json .RestartCount}}}')
    result = subprocess.run(['/usr/local/bin/docker', 'inspect', '--format',
                             fmt, cid], capture_output=True, timeout=10, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 4096,
            'container_inspect_failed')
    value = json.loads(result.stdout)
    require(value.get('cid') == cid and value.get('running') is True
            and value.get('restarting') is False and type(value.get('pid')) is int
            and value['pid'] > 0, 'indexer_identity_not_running')
    return {k: value[k] for k in ('cid', 'image', 'pid', 'started_at', 'restart_count')}


def metric_equal(got, wanted):
    metric = got.get('metric')
    require(isinstance(metric, dict) and all(metric.get(k) == v for k, v in wanted.items()),
            'metric_did_not_match_oracle')
    require(got['observation_match'] is wanted['match']
            and got['observation_unavailable'] is (not wanted['valid']), 'trigger_did_not_match_oracle')


def make_client(base):
    class Audit(base.Native):
        def request(self, method, path, body=None, expected=(200,), **kwargs):
            remaining = self.deadline - time.monotonic()
            require(remaining >= 2, 'audit_deadline')
            self.process_timeout = min(12, int(remaining))
            self.http_timeout = min(10, self.process_timeout - 1)
            if path.endswith('/_bulk?refresh=false'):
                require(method == 'POST' and kwargs.get('mutation') is True
                        and kwargs.get('ndjson') is True, 'delayed_bulk_contract')
            if path.endswith('/_refresh'):
                require(method == 'POST' and body is None and kwargs.get('mutation') is True,
                        'refresh_contract')
            return super().request(method, path, body, expected, **kwargs)

        def synthetic_bulk(self, docs, prefix, refresh=True):
            require(0 < len(docs) <= 60 and re.fullmatch('[a-z0-9-]{1,32}', prefix), 'bulk_input_bound')
            raw = b''.join(base.encode({'index': {'_id': prefix + '-' + str(i)}}) + b'\n'
                           + base.encode(doc) + b'\n' for i, doc in enumerate(docs))
            _, value = self.request('POST', '/' + self.index + '/_bulk?refresh=' + ('true' if refresh else 'false'),
                                    raw, mutation=True, ndjson=True, operation='synthetic_bulk_' + prefix)
            require(value.get('errors') is False and len(value.get('items', [])) == len(docs)
                    and all(r.get('index', {}).get('status') in (200, 201)
                            and r['index'].get('_index') == self.index for r in value['items']), 'bulk_partial')

        def visible_count(self):
            _, result = self.request('POST', '/' + self.index + '/_search',
                                    {'size': 0, '_source': False, 'track_total_hits': True,
                                     'query': {'match_all': {}}})
            shards = result.get('_shards', {})
            total = result.get('hits', {}).get('total', {})
            require(result.get('timed_out') is False and shards.get('total') == 2
                    and shards.get('successful') == 2 and shards.get('failed') == 0
                    and total.get('relation') == 'eq' and type(total.get('value')) is int
                    and 0 <= total['value'] <= 60, 'visibility_search_invalid')
            return total['value']

        def wait_for(self, seconds, phase, start):
            target = time.monotonic() + seconds
            require(target + 15 < self.deadline, 'wait_exceeds_work_deadline')
            while time.monotonic() < target:
                progress(phase, start)
                time.sleep(min(30, target - time.monotonic()))
            progress(phase + '_finished', start)

    return Audit


def saved_lifecycle(native, base, candidate, fixture, v2, start):
    native.clear()
    _, created = native.request('POST', base.API, native.template(candidate), (200, 201),
                                 mutation=True, operation='save_disabled_test_monitor')
    native.monitor_id = created.get('_id')
    require(isinstance(native.monitor_id, str) and re.fullmatch('[A-Za-z0-9_-]{1,200}', native.monitor_id),
            'monitor_id_invalid')
    native.result['monitor_id'] = native.monitor_id
    native.save(); native.monitor_owned()
    end = time.time_ns() // 1_000_000
    rows = fixture.groups(v2, end)
    match_id = candidate['triggers'][0]['query_level_trigger']['id']
    unavailable_id = candidate['triggers'][1]['query_level_trigger']['id']
    first = None
    for step in ('first_match', 'same_event_replay', 'fresh_client_readback', 'identity_conflict', 'same_events_after_unavailable'):
        if step == 'first_match':
            native.synthetic_bulk(rows, 'first')
        elif step == 'same_event_replay':
            native.synthetic_bulk(rows, 'replay')
        elif step == 'fresh_client_readback':
            # Rebuild only client state from a private durable ownership receipt.
            # This does not restart the Python process or the Indexer daemon.
            receipt = {'index': native.index, 'uuid': native.index_uuid,
                       'monitor': native.monitor_id, 'cid': native.cid}
            base.atomic(native.out / 'client-ownership.json', receipt)
            restored = base.load((native.out / 'client-ownership.json').read_bytes())
            require(restored == receipt, 'client_receipt_changed')
            reader = object.__new__(type(native))
            reader.__dict__.update(out=native.out, cid=restored['cid'], index=restored['index'],
                                   index_uuid=restored['uuid'], monitor_id=restored['monitor'],
                                   result=native.result, deadline=native.deadline)
            require(reader.get_index_uuid() == native.index_uuid, 'fresh_client_index_changed')
            reader.monitor_owned()
            sort = lambda alerts: sorted(alerts, key=lambda row: row['id'])
            require(sort(reader.alerts()) == sort(native.alerts()), 'fresh_client_alert_readback_changed')
        elif step == 'identity_conflict':
            conflict = deepcopy(rows[0])
            conflict['data']['capstone_norm']['event_time_kst'] = v2.iso_us((end - 9000) * 1000, kst=True)
            native.synthetic_bulk([conflict], 'conflict')
        else:
            native.clear(); native.synthetic_bulk(rows, 'restored')
        got = native.execute(candidate, time.time_ns() // 1_000_000, saved=True)
        wanted = (v2.expected(invalid='identity_conflict') if step == 'identity_conflict' else
                  v2.expected(30 if step in ('same_event_replay', 'fresh_client_readback') else 15, 15, 3, 3, 3))
        metric_equal(got, wanted)
        expected_active = unavailable_id if step == 'identity_conflict' else match_id
        alerts = []
        for _ in range(12):
            alerts = native.alerts()
            active = [r for r in alerts if r['state'] == 'ACTIVE']
            if len(active) == 1 and active[0]['trigger_id'] == expected_active:
                break
            time.sleep(.25)
        active = [r for r in alerts if r['state'] == 'ACTIVE']
        require(len(active) == 1 and active[0]['trigger_id'] == expected_active, 'episode_state_invalid')
        if step == 'first_match':
            first = active[0]['id']
        elif step in ('same_event_replay', 'fresh_client_readback'):
            require(active[0]['id'] == first, 'continuous_match_episode_changed')
        elif step == 'identity_conflict':
            require(any(r['id'] == first and r['state'] == 'COMPLETED' for r in alerts),
                    'unavailable_did_not_complete_match')
        else:
            require(active[0]['id'] != first and any(r['id'] == first and r['state'] == 'COMPLETED' for r in alerts),
                    'same_events_did_not_create_new_episode')
        native.result['lifecycle'].append({'step': step, 'observed': got, 'alerts': alerts, 'passed': True})
        native.save(); progress(step, start)


def timed_visibility(native, base, candidate, fixture, v2, start):
    native.clear()
    require(native.get_index_uuid() == native.index_uuid, 'timed_index_identity')
    _, value = native.request('PUT', '/' + native.index + '/_settings',
                             {'index': {'refresh_interval': '-1'}}, mutation=True,
                             operation='disable_refresh_owned_test_index_only')
    require(value.get('acknowledged') is True, 'test_refresh_setting_not_acknowledged')
    end = time.time_ns() // 1_000_000
    docs = fixture.span_groups(v2, end)
    native.synthetic_bulk(docs, 'delayed', refresh=False)
    accepted = time.monotonic()
    require(native.visible_count() == 0, 'test_documents_visible_before_delayed_refresh')
    native.wait_for(130, 'waiting_visibility_130s', start)
    require(native.visible_count() == 0, 'documents_became_visible_without_explicit_refresh')
    _, value = native.request('POST', '/' + native.index + '/_refresh', mutation=True,
                             operation='publish_owned_synthetic_index_after_130s')
    shards = value.get('_shards', {})
    require(shards.get('total') == 2 and shards.get('successful') == 2 and shards.get('failed') == 0,
            'refresh_partial')
    delay = time.monotonic() - accepted
    require(delay >= 130 and native.visible_count() == 15, 'visibility_delay_not_established')
    first = native.execute(candidate, time.time_ns() // 1_000_000)
    metric_equal(first, v2.expected(15, 15, 3, 3, 3))
    successful_at = time.monotonic()
    native.result['timed'] = {'phase': 'visible_after_130s', 'visibility_delay_seconds': round(delay, 3),
                              'after_refresh': first, 'actual_service_outage': False,
                              'production_monitor_paused': False}
    native.save()
    native.wait_for(180, 'waiting_test_evaluation_gap_180s', start)
    last = native.execute(candidate, time.time_ns() // 1_000_000)
    metric_equal(last, v2.expected())
    require(native.visible_count() == 15, 'documents_not_retained_after_gap')
    native.result['timed'].update(phase='completed', evaluation_gap_seconds=round(time.monotonic() - successful_at, 3),
                                  after_evaluation_gap=last, underlying_visible_documents=15,
                                  valid_empty_does_not_prove_coverage=True, passed=True)
    native.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--indexer-cid', required=True)
    parser.add_argument('--fixtures-sha256', required=True)
    parser.add_argument('--timed', action='store_true')
    args = parser.parse_args()
    require(EXECUTION_REVIEWED, 'execution_review_pending')
    require(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'wrong_host_or_uid')
    require(re.fullmatch('[0-9a-f]{64}', args.indexer_cid) and re.fullmatch('[0-9a-f]{64}', args.fixtures_sha256),
            'invalid_pin')
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    out = Path(args.output)
    require(out.parent == OUTPUT and re.fullmatch('run-[a-z0-9-]{1,40}', out.name)
            and not out.exists() and not out.is_symlink(), 'exclusive_output_required')
    parent = OUTPUT.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0
            and stat.S_IMODE(parent.st_mode) == 0o700, 'unsafe_output_parent')
    sources = {name: checked_bytes(V2 / name, sha) for name, sha in PINS.items()}
    fixture_raw = checked_bytes(ROOT / 'fixtures.py', args.fixtures_sha256)
    candidate = json.loads(sources['monitor.json'])
    fixture = module(fixture_raw, ROOT / 'fixtures.py')
    v2 = module(sources['fixtures.py'], V2 / 'fixtures.py')
    adapted = adapted_transport(sources['native-verify-b.py'])
    base = module(adapted, V2 / 'native-verify-b.py'); base.PREFIX = PREFIX
    before = container_identity(args.indexer_cid)
    start = time.monotonic()
    out.mkdir(mode=0o700)
    native = make_client(base)(out)
    require(native.cid == args.indexer_cid, 'fixed_indexer_cid_changed')
    native.deadline = start + 410
    native.result.update(policy='indexer-delay-audit-v1', source_sha256=PINS,
                         fixture_sha256=args.fixtures_sha256,
                         adapted_helper_sha256=hashlib.sha256(adapted).hexdigest(),
                         production_service_restart_performed=False, client_process_restart_performed=False,
                         indexer_restart_persistence_proven=False, actual_1800s_outage_tested=False,
                         age_fixture_is_wallclock_delay=False, initial_identity=before,
                         timed_requested=args.timed, timed=None)
    native.save()
    error = None
    try:
        native.create_index()
        for name in [r[0] for r in fixture.cases(v2, time.time_ns() // 1_000_000)]:
            native.result['current_case'] = name; native.save()
            native.clear()
            end = time.time_ns() // 1_000_000
            name, docs, wanted = next(r for r in fixture.cases(v2, end) if r[0] == name)
            native.synthetic_bulk(docs, 'age')
            got = native.execute(candidate, end)
            row = {'name': name, 'loaded_documents': len(docs), 'expected': wanted,
                   'observed': got, 'passed': False}
            native.result['query_cases'].append(row); native.save()
            metric_equal(got, wanted); row['passed'] = True
            native.save(); progress(name, start)
        saved_lifecycle(native, base, candidate, fixture, v2, start)
        if args.timed:
            timed_visibility(native, base, candidate, fixture, v2, start)
        require(container_identity(args.indexer_cid) == before, 'indexer_identity_changed')
        native.result['status'] = 'passed'
    except BaseException as exc:
        error = str(exc) if isinstance(exc, (RuntimeError, base.Refused)) else type(exc).__name__
        native.result.update(status='failed', failure_code=error)
    finally:
        native.deadline = min(start + 470, time.monotonic() + 55)
        native.cleanup()
        try:
            native.result['final_identity'] = container_identity(args.indexer_cid)
            require(native.result['final_identity'] == before, 'postcleanup_identity_changed')
            for name, sha in PINS.items():
                checked_bytes(V2 / name, sha)
            checked_bytes(ROOT / 'fixtures.py', args.fixtures_sha256)
            native.result['sources_unchanged'] = True
        except BaseException as exc:
            native.result['cleanup']['failures'].append(str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__)
        uncertain = [m['operation'] for m in native.result['mutations'] if m['outcome'] != 'response_received']
        native.result['uncertain_mutations'] = uncertain
        if native.result['cleanup']['failures'] or uncertain:
            native.result['status'] = 'failed'
        native.result.update(elapsed_seconds=round(time.monotonic() - start, 3),
                             completed_at_epoch_ms=time.time_ns() // 1_000_000)
        native.save()
    print(json.dumps({k: native.result.get(k) for k in ('status', 'failure_code', 'elapsed_seconds', 'cleanup',
                                                       'sources_unchanged', 'uncertain_mutations')}), flush=True)
    return 0 if native.result['status'] == 'passed' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(json.dumps({'status': 'refused', 'reason': str(error)}), flush=True)
        raise SystemExit(2)
