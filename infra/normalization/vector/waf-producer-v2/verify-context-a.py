#!/usr/bin/env python3
"""One-shot native v2 audit archive verification on A; never a live collector."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parent
PAIR_SHA = '71261731b8d8a881118b742db005347d1e54c46eca0370c7bbf5cf1aae140f58'
CONTEXT_SHA = 'bf858467aa62e3dd7da7e9135af8ac36d8bcee0e4d0415d7a13ff0dac52cd219'
GUARD_SHA = 'd70de8b923c7cd31db1acd68404210a796ebe53e5d5de16737b5638c5680e898'
PROBE_SHA = '68c8556b36432d6f355fba0752a5ecbdaba4a4f92e5d8412a6e14ad75944b61c'
HELPER_SHA = '73a520416dff0f40e3b32e6914260ef23a29e0c1ee68d2cc243e7250f83619db'
BASE_SHA = 'ae12559a4641e596c647bc009a7f0d68906e2890d8201d18fca75537e324f7fe'
EVIDENCE = re.compile(r'/var/tmp/capstone-sequential-20261014/step3/producer-v2/run-[A-Za-z0-9_-]{1,48}/evidence\Z')
IDENTITY = re.compile(r'v2:(?P<binding>[a-f0-9]{64}):(?P<request_id>[a-f0-9]{32}):(?P<msec>[0-9]{10}\.[0-9]{3}):(?P<iso>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2})\Z')
MAX_FILE = 4 * 1024 * 1024
KST = dt.timezone(dt.timedelta(hours=9))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def load_utilities():
    path = ROOT.parent / 'waf-rotation/verify-pairs-a.py'
    raw = path.read_bytes()
    need(sha(raw) == PAIR_SHA, 'verification_utility_changed')
    module = types.ModuleType('frozen_pair_utilities')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def expected_rows(util, manifest, generation, windows):
    root = Path(manifest['evidence_root'])
    for field, digest in [('config_path', 'config_sha256'), ('archive_audit_path', 'audit_sha256'),
                          ('archive_access_path', 'access_sha256'), ('generation_path_config', 'generation_path_sha256')]:
        raw = util.read_bounded(Path(generation[field]), root=root, immutable=True)
        need(sha(raw) == generation[digest], 'archive_configuration_hash')
    need(generation['config_sha256'] == manifest['stable_format_sha256'], 'stable_configuration_binding')
    util.metadata_path(generation['original_audit_path'])
    ids = generation['expected_request_ids']
    need(isinstance(ids, list) and len(ids) in (1, 2) and len(set(ids)) == len(ids) and
         all(isinstance(x, str) and util.HEX32.fullmatch(x) for x in ids), 'manifest_request_ids')
    expected = {}
    raw = util.read_bounded(Path(generation['archive_audit_path']), root=root, immutable=True)
    for line in util.lines(raw):
        duplicates = {'server': 0}
        tx = util.strict_object(line, allow_server=True, duplicate_stats=duplicates)['transaction']
        unique = tx['unique_id']
        match = IDENTITY.fullmatch(unique)
        need(match is not None, 'producer_identity_format')
        fields = match.groupdict()
        request = fields['request_id']
        binding = fields['binding']
        key = binding + '-' + request
        need(binding == generation['binding'] and request in ids and key not in expected, 'producer_identity_binding')
        epoch_ms = int(fields['msec'].replace('.', ''))
        iso = dt.datetime.fromisoformat(fields['iso'])
        iso_ms = int(iso.timestamp()) * 1000
        need(0 <= epoch_ms - iso_ms < 1000 and len(unique.encode()) == 141, 'producer_clock_identity')
        naive = dt.datetime.strptime(tx['time_stamp'], '%a %b %d %H:%M:%S %Y').replace(tzinfo=iso.tzinfo)
        need(abs(int(naive.timestamp()) * 1000 - epoch_ms) <= 2000, 'audit_context_clock')
        window = windows[request]
        need(window['generation'] == generation['generation'] and
             window['start_epoch_ms'] - 2000 <= epoch_ms <= window['end_epoch_ms'] + 2000, 'request_time_window')
        if 'released_epoch_ms' in window:
            need(epoch_ms <= window['accepted_epoch_ms'] + 1000 and
                 epoch_ms <= window['released_epoch_ms'] - 1500, 'late_request_context_clock')
        timestamp = (dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(milliseconds=epoch_ms)).astimezone(KST).isoformat(timespec='microseconds')
        eid = sha(json.dumps([manifest['sensor'], 'modsecurity', manifest['instance_id'], binding, request], separators=(',', ':')).encode())
        expected[key] = {
            'schema_version': 'vector-1', 'pipeline': 'vector', 'source': 'modsecurity',
            'producer_format_version': '2', 'sensor': manifest['sensor'], 'record_id': key, 'event_id': eid,
            'message_sha256': sha(line), 'producer_time_evidence_sha256': sha(unique.encode()),
            'producer_time_hash_scope': 'exact_audit_unique_id_utf8', 'hash_scope': 'vector_message_without_line_delimiter',
            'identity_scope': 'deployment_binding_request_id', 'provenance_level': 'collector_embedded_producer_time',
            'writer_instance_id': manifest['instance_id'], 'configuration_sha256': generation['config_sha256'],
            'configuration_hash_scope': 'exact_stable_producer_format_configuration', 'deployment_binding': binding,
            'event_time_kst': timestamp, 'time_status': 'trusted_context_creation',
            'rule_ids': list(dict.fromkeys(str(x['details']['ruleId']) for x in tx['messages'])),
            'native_severity_value': list(dict.fromkeys(str(x['details']['severity']) for x in tx['messages'])),
            'native_severity_scale': 'modsecurity_0_7', 'source_ip': tx['client_ip'], 'destination_ip': tx['host_ip'],
            'source_port': tx['client_port'], 'destination_port': tx['host_port'],
            'http_method': tx['request']['method'], 'http_status': tx['response']['http_code'],
            'protocol': 'tcp', 'direction': 'unknown', 'action': 'observed', 'engine_mode': tx['producer']['secrules_engine'],
            'quality_flags': [], 'time_basis': 'nginx_modsecurity_context_creation', 'source_replay_deduplicated': False,
            'omitted_response_server_duplicates': duplicates['server'],
            'protected_asset': any(x in ('211.170.162.110', '211.170.162.111') for x in (tx['client_ip'], tx['host_ip'])),
        }
    need({x.split('-')[-1] for x in expected} == set(ids), 'archive_request_set')
    return expected


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))


def run_vector(util, work, config, env, expected_count):
    path = work / 'vector.json'
    path.write_text(json.dumps(config, indent=2) + '\n')
    def execute(argv, log_name, collect):
        process = None
        pidfd = None
        namespace_verified = False
        with (work / log_name).open('xb') as log:
            try:
                process = subprocess.Popen(['/usr/bin/unshare', '--net', '--'] + argv,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    env=env, start_new_session=True, preexec_fn=limits)
                pidfd = os.pidfd_open(process.pid)
                deadline = time.monotonic() + (20 if collect else 15)
                while True:
                    try:
                        namespace_verified |= os.readlink('/proc/' + str(process.pid) + '/ns/net') != os.readlink('/proc/self/ns/net')
                    except FileNotFoundError:
                        pass
                    rc = process.poll()
                    if rc is not None:
                        need(not collect and rc == 0, 'vector_unexpected_exit')
                        break
                    need(time.monotonic() < deadline, 'vector_case_timeout')
                    if collect:
                        output = read_outputs(util, work)
                        need(len(output['ready']) <= expected_count and len(output['quarantine']) == 0, 'unexpected_output')
                        if len(output['ready']) == expected_count:
                            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                            need(process.wait(timeout=8) == 0, 'vector_graceful_shutdown')
                            break
                    time.sleep(0.05)
                if collect:
                    need(namespace_verified, 'private_vector_network_namespace')
            finally:
                if process is not None and process.poll() is None:
                    if pidfd is not None:
                        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                    else:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if pidfd is not None:
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait(timeout=3)
                if pidfd is not None:
                    os.close(pidfd)
    execute(['/usr/local/bin/vector', 'validate', '--no-environment', str(path)], 'validate.log', False)
    execute(['/usr/local/bin/vector', '--config', str(path), '--log-format', 'json'], 'vector.log', True)
    output = read_outputs(util, work)
    need(len(output['ready']) == expected_count and not output['quarantine'], 'final_output_count')
    for lane in ('ready', 'quarantine'):
        final_path = work / (lane + '.jsonl')
        if final_path.exists():
            final_raw = util.read_bounded(final_path)
            need(not final_raw or final_raw.endswith(b'\n'), 'incomplete_final_output')
    return output['ready']


def read_outputs(util, work):
    out = {}
    for lane in ('ready', 'quarantine'):
        path = work / (lane + '.jsonl')
        raw = util.read_bounded(path, append_snapshot=True) if path.exists() else b''
        out[lane] = [util.strict_object(line) for line in raw.split(b'\n')[:-1]]
        need(len(out[lane]) <= 8, 'output_record_limit')
    return out


def render(work, generation):
    audit = generation['archive_audit_path']
    transform = {'type': 'remap', 'drop_on_error': True, 'drop_on_abort': True, 'reroute_dropped': True}
    return {'data_dir': str(work / 'data'), 'timezone': 'Asia/Seoul', 'api': {'enabled': False},
        'sources': {'audit': {'type': 'file', 'include': [audit], 'read_from': 'beginning', 'ignore_checkpoints': False,
            'file_key': '_archive_path', 'max_line_bytes': 1048576, 'max_read_bytes': 262144, 'fingerprint': {'strategy': 'device_and_inode'}}},
        'transforms': {
            'metadata': dict(transform, inputs=['audit'], source='assert!(._archive_path == ' + json.dumps(audit) + ', "archive_source")\n.source_file = ' + json.dumps(generation['original_audit_path']) + '\ndel(._archive_path)'),
            'guard': dict(transform, inputs=['metadata'], file=str(work.parent / 'waf_json_guard.vrl')),
            'context': dict(transform, inputs=['guard'], file=str(work.parent / 'audit-context.vrl'))},
        'sinks': {lane: {'type': 'file', 'inputs': inputs, 'path': str(work / (lane + '.jsonl')),
            'encoding': {'codec': 'json'}, 'buffer': {'type': 'memory', 'max_events': 64, 'when_full': 'block'}}
            for lane, inputs in [('ready', ['context']), ('quarantine', ['metadata.dropped', 'guard.dropped', 'context.dropped'])]}}


def run(manifest_path):
    need(sys.platform.startswith('linux') and os.geteuid() == 0 and
         Path('/etc/machine-id').read_text().strip() == '096e90b6243e438aa8a7b392be754732', 'fixed_A_root_required')
    os.umask(0o077)
    util = load_utilities()
    version = subprocess.run(['/usr/local/bin/vector', '--version'], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True).stdout
    need(len(version) <= 1024 and re.search(rb'\b0\.59\.0\b', version), 'vector_version')
    root = manifest_path.parent
    need(EVIDENCE.fullmatch(str(root)) and manifest_path.name == 'manifest.json', 'manifest_path')
    raw = util.read_bounded(manifest_path, root=root, immutable=True, limit=65536)
    manifest = util.strict_object(raw)
    result_path = root.parent / 'result.json'
    result_raw = util.read_bounded(result_path, root=root.parent, limit=262144)
    result = util.strict_object(result_raw)
    need(result['status'] == 'passed' and result['kind'] == 'native_uid101_waf_v2_producer' and
         result['source_sha256'] == {'frozen_base': BASE_SHA, 'driver': PROBE_SHA, 'wazuh_helper': HELPER_SHA} and
         result['evidence']['manifest_sha256'] == sha(raw) and result['evidence']['manifest_path'] == str(manifest_path), 'successful_pinned_producer_result')
    need(manifest['schema_version'] == 2 and manifest['evidence_root'] == str(root) and manifest['sensor'] == 'groot-sec' and
         util.HEX64.fullmatch(manifest['instance_id']) and manifest['writer_uid'] == manifest['writer_gid'] == 101 and
         manifest['time_basis'] == 'nginx_modsecurity_context_creation' and
         manifest['configuration_hash_scope'] == 'exact_stable_producer_format_configuration', 'manifest_contract')
    generations = manifest['generations']
    counts = [len(g['expected_request_ids']) for g in generations]
    need((result['mode'] == 'rotate' and counts == [2, 1]) or (result['mode'] == 'smoke' and counts == [1]), 'request_distribution')
    need([g['generation'] for g in generations] == list(range(1, len(generations) + 1)) and
         len({g['binding'] for g in generations}) == 1 and all(util.HEX64.fullmatch(g['binding']) for g in generations), 'same_binding_generation_order')
    windows = {}
    for window in result['request_context_windows'].values():
        need(window['request_id'] not in windows, 'duplicate_request_window')
        windows[window['request_id']] = window
    ids = [x for g in generations for x in g['expected_request_ids']]
    need(len(set(ids)) == len(ids) and set(ids) == set(windows), 'request_window_set')
    sources = {'audit-context.vrl': (ROOT / 'audit-context.vrl', CONTEXT_SHA),
               'waf_json_guard.vrl': (Path('/etc/capstone-vector/transforms/waf_json_guard.vrl'), GUARD_SHA)}
    captured = {name: util.read_bounded(path) for name, (path, _) in sources.items()}
    need(all(sha(captured[name]) == digest for name, (_, digest) in sources.items()), 'vrl_source_pin')
    prepared = [expected_rows(util, manifest, generation, windows) for generation in generations]
    workroot = root / 'context-tests'
    workroot.mkdir(mode=0o700)
    for name, source in captured.items():
        (workroot / name).write_bytes(source)
        os.chmod(workroot / name, 0o400)
    cases = []
    for generation, expected in zip(generations, prepared):
        work = workroot / ('generation-' + str(generation['generation']))
        work.mkdir(mode=0o700); (work / 'data').mkdir(mode=0o700)
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'Asia/Seoul',
            'CAPSTONE_SENSOR': manifest['sensor'], 'WAF_INSTANCE_ID': manifest['instance_id'],
            'WAF_CONFIG_SHA256': generation['config_sha256'], 'WAF_DEPLOYMENT_BINDING': generation['binding'],
            'WAF_AUDIT_PATH': generation['original_audit_path']}
        ready = run_vector(util, work, render(work, generation), env, len(expected))
        actual = {}
        for row in ready:
            need(set(row) == {'capstone_norm'}, 'ready_envelope')
            norm = dict(row['capstone_norm'])
            observed = dt.datetime.fromisoformat(norm.pop('observed_at_kst'))
            need(observed.utcoffset() == dt.timedelta(hours=9), 'observed_not_kst')
            key = norm['record_id']
            need(key not in actual and key in expected and norm == expected[key], 'normalized_exact_tuple')
            actual[key] = norm
        need(set(actual) == set(expected), 'normalized_request_set')
        cases.append({'generation': generation['generation'], 'ready': len(ready), 'quarantine': 0,
                      'exact_all_fields': True, 'vector_exit': 0, 'private_network_namespace': True, 'child_reaped': True})
    for generation in generations:
        expected_rows(util, manifest, generation, windows)
    need(util.read_bounded(manifest_path, root=root, immutable=True, limit=65536) == raw and
         util.read_bounded(result_path, root=root.parent, limit=262144) == result_raw, 'producer_evidence_changed')
    need(all(util.read_bounded(path) == captured[name] for name, (path, _) in sources.items()), 'vrl_source_changed')
    report = {'status': 'passed', 'kind': 'native_v2_actual_audit_context_verification',
        'at_kst': dt.datetime.now(KST).isoformat(), 'vector_version': version.decode().strip(),
        'generations': len(generations), 'ready': len(ids),
        'missing': 0, 'duplicates': 0, 'quarantine': 0, 'producer_format_version': '2',
        'time_status': 'trusted_context_creation', 'time_basis': 'nginx_modsecurity_context_creation',
        'manifest_sha256': sha(raw), 'producer_result_sha256': sha(result_raw), 'source_sha256': {
            'verifier': sha(Path(__file__).read_bytes()), 'utility': PAIR_SHA, 'audit_context': CONTEXT_SHA, 'json_guard': GUARD_SHA},
        'cases': cases, 'request_time_windows_exact': True, 'original_archives_unchanged': True,
        'exact_identity_raw_hash_producer_hash_time_all_fields': True,
        'original_source_metadata_reconstructed_for_private_replay': True,
        'access_file_input_used': False, 'operating_pipeline_changed': False,
        'proves_live_rotation_recovery': False, 'raw_or_request_ids_exported': False, 'packages_installed': 0}
    (workroot / 'context-validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    try:
        report = run(args.manifest)
    except Exception as exc:
        # Values/raw/VRL diagnostics remain inside the private A evidence tree.
        code = str(exc) if isinstance(exc, Refused) else type(exc).__name__
        print(json.dumps({'status': 'not_verified', 'error_code': code, 'raw_or_request_ids_exported': False}))
        return 1
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
