#!/usr/bin/env python3
"""One-shot A-only native Vector pair verification; never a collector/service."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

VECTOR = Path('/usr/local/bin/vector')
TRANSFORMS = Path('/etc/capstone-vector/transforms')
VRL_SHA = {
    'waf_json_guard.vrl': 'd70de8b923c7cd31db1acd68404210a796ebe53e5d5de16737b5638c5680e898',
    'waf_audit_part.vrl': '18829d82be5ca8abcb1f11fa750d0f0f3a7eac49af6e22aa1eb131da637c44b8',
    'waf_access_part.vrl': '9f9700e970579ca1f2acc683fa6a12d6629a48088f780cde63877c49b0b288e5',
    'waf_pair_normalize.vrl': 'df6ddbc0d6773a94110e7edc0e21e6b68643030df8df11b05dd8da491cac1b0f',
}
EVIDENCE = re.compile(r'/var/tmp/capstone-sequential-20261014/step1/run-[A-Za-z0-9_-]{1,80}/evidence\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
MAX_FILE = 4 * 1024 * 1024
MAX_LINE = 131072
KST = dt.timezone(dt.timedelta(hours=9))


class PairProbeError(Exception):
    pass


def require(value, code):
    if not value:
        raise PairProbeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Pairs(list):
    pass


def strict_object(raw, *, allow_server=False, duplicate_stats=None):
    def nonfinite(_):
        raise PairProbeError('nonfinite_json')
    try:
        parsed = json.loads(raw.decode('utf-8'), object_pairs_hook=Pairs, parse_constant=nonfinite)
    except (ValueError, UnicodeError):
        raise PairProbeError('invalid_json') from None
    def walk(value, path=(), depth=0):
        require(depth <= 32, 'json_depth')
        if isinstance(value, Pairs):
            out = {}
            for key, child in value:
                if key in out:
                    require(allow_server and path == ('transaction', 'response', 'headers') and
                            key == 'Server' and isinstance(out[key], str) and isinstance(child, str), 'duplicate_json_key')
                    if duplicate_stats is not None:
                        duplicate_stats['server'] = duplicate_stats.get('server', 0) + 1
                out[key] = walk(child, path + (key,), depth + 1)
            return out
        if isinstance(value, list):
            return [walk(x, path + ('[]',), depth + 1) for x in value]
        require(not isinstance(value, float) or math.isfinite(value), 'nonfinite_json')
        return value
    value = walk(parsed)
    require(isinstance(value, dict), 'json_object_required')
    return value


def private_path(path, root):
    require(path.is_absolute() and str(path).isascii() and '..' not in path.parts, 'path_shape')
    require(path == root or root in path.parents, 'path_outside_evidence')
    # A fixed root-owned private task ancestor closes access beneath /var/tmp.
    start = Path('/var/tmp/capstone-sequential-20261014')
    require(start == root or start in root.parents, 'task_root')
    p = start
    for part in path.relative_to(start).parts:
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o077, 'private_directory')
        p /= part
    require(not path.is_symlink(), 'symlink_path')


def read_bounded(path, *, root=None, immutable=False, limit=MAX_FILE, append_snapshot=False):
    if root is not None:
        private_path(path, root)
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_uid == 0 and s.st_size <= limit, 'file_metadata')
    if immutable:
        require(stat.S_IMODE(s.st_mode) == 0o400, 'archive_not_immutable')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        require(a.st_size <= limit, 'file_limit')
        raw = bytearray()
        while len(raw) < a.st_size:
            chunk = os.read(fd, min(65536, a.st_size - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        b = os.fstat(fd)
        require(len(raw) == a.st_size <= limit and b.st_size <= limit and
                (a.st_dev, a.st_ino) == (s.st_dev, s.st_ino) and
                (a.st_size <= b.st_size if append_snapshot else
                 (a.st_size, a.st_mtime_ns) == (b.st_size, b.st_mtime_ns)), 'file_changed')
        return bytes(raw)
    finally:
        os.close(fd)


def lines(raw):
    require(not raw or raw.endswith(b'\n'), 'incomplete_jsonl')
    result = raw.split(b'\n')[:-1] if raw else []
    require(len(result) <= 16 and all(0 < len(row) <= MAX_LINE and not row.endswith(b'\r') for row in result), 'jsonl_bounds')
    return result


def metadata_path(value):
    require(isinstance(value, str) and value.isascii() and len(value) <= 512 and
            value.startswith('/') and '..' not in Path(value).parts and
            re.fullmatch(r'[A-Za-z0-9_./-]+', value) is not None and
            'capstone-waf-rotation.' in value, 'original_metadata_path')
    return value


def expected_generation(root, manifest, generation):
    required = {'generation', 'binding', 'config_sha256', 'config_path', 'original_audit_path',
                'original_access_path', 'writer_audit_path', 'writer_access_path', 'archive_audit_path',
                'archive_access_path', 'audit_sha256', 'access_sha256', 'expected_request_ids'}
    require(required <= set(generation), 'generation_fields')
    require(type(generation['generation']) is int and 1 <= generation['generation'] <= 4, 'generation_number')
    for key in ('binding', 'config_sha256', 'audit_sha256', 'access_sha256'):
        require(isinstance(generation[key], str) and HEX64.fullmatch(generation[key]), 'generation_hash')
    for key in ('original_audit_path', 'original_access_path', 'writer_audit_path', 'writer_access_path'):
        metadata_path(generation[key])
    ids = generation['expected_request_ids']
    require(isinstance(ids, list) and 1 <= len(ids) <= 3 and all(isinstance(x, str) and HEX32.fullmatch(x) for x in ids) and len(set(ids)) == len(ids), 'expected_ids')
    config = read_bounded(Path(generation['config_path']), root=root, immutable=True)
    require(sha(config) == generation['config_sha256'], 'producer_config_sha')
    audit_raw = read_bounded(Path(generation['archive_audit_path']), root=root, immutable=True)
    access_raw = read_bounded(Path(generation['archive_access_path']), root=root, immutable=True)
    require(sha(audit_raw) == generation['audit_sha256'] and sha(access_raw) == generation['access_sha256'], 'archive_sha')
    audits = {}
    accesses = {}
    for raw in lines(audit_raw):
        duplicates = {'server': 0}
        obj = strict_object(raw, allow_server=True, duplicate_stats=duplicates)
        tx = obj['transaction']
        prefix = generation['binding'] + '-'
        require(isinstance(tx['unique_id'], str) and tx['unique_id'].startswith(prefix), 'audit_binding')
        request_id = tx['unique_id'][len(prefix):]
        require(HEX32.fullmatch(request_id) and request_id not in audits, 'audit_identity')
        audits[request_id] = (raw, tx, duplicates['server'])
    for raw in lines(access_raw):
        obj = strict_object(raw)
        request_id = obj['request_id']
        require(isinstance(request_id, str) and HEX32.fullmatch(request_id) and request_id not in accesses and
                obj['deployment_binding'] == generation['binding'], 'access_identity')
        accesses[request_id] = (raw, obj)
    require(set(audits) == set(accesses) == set(ids), 'generation_request_set')
    expected = {}
    for request_id in ids:
        audit_line, tx, duplicates = audits[request_id]
        access_line, ac = accesses[request_id]
        require(re.fullmatch(r'[0-9]{10,12}\.[0-9]{3}', ac['msec']) is not None, 'expected_msec')
        epoch_ms = int(ac['msec'].replace('.', ''))
        when = (dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(milliseconds=epoch_ms)).astimezone(KST).isoformat(timespec='microseconds')
        eid = sha(json.dumps([manifest['sensor'], 'modsecurity', manifest['instance_id'], generation['binding'], request_id], separators=(',', ':')).encode())
        messages = tx['messages']
        expected[generation['binding'] + '-' + request_id] = {
            'event_id': eid, 'message_sha256': sha(audit_line), 'time_evidence_sha256': sha(access_line),
            'event_time_kst': when, 'source_ip': tx['client_ip'], 'destination_ip': tx['host_ip'],
            'source_port': int(tx['client_port']), 'destination_port': int(tx['host_port']),
            'http_method': tx['request']['method'], 'http_status': int(tx['response']['http_code']),
            'rule_ids': list(dict.fromkeys(str(x['details']['ruleId']) for x in messages)),
            'native_severity_value': list(dict.fromkeys(str(x['details']['severity']) for x in messages)),
            'native_severity_scale': 'modsecurity_0_7',
            'engine_mode': tx['producer']['secrules_engine'], 'writer_instance_id': manifest['instance_id'],
            'configuration_sha256': generation['config_sha256'], 'deployment_binding': generation['binding'],
            'sensor': manifest['sensor'], 'time_status': 'trusted_access_completion',
            'time_basis': 'nginx_access_completion', 'quality_flags': [], 'action': 'observed',
            'identity_scope': 'deployment_binding_request_id', 'provenance_level': 'collector_paired_observation',
            'hash_scope': 'vector_message_without_line_delimiter', 'source_replay_deduplicated': False,
            'omitted_response_server_duplicates': duplicates,
            'protected_asset': tx['client_ip'] in ('211.170.162.110', '211.170.162.111') or
                               tx['host_ip'] in ('211.170.162.110', '211.170.162.111'),
        }
    return expected, audits, accesses


def render_config(work, audit, access, original_audit, original_access):
    config = {'data_dir': str(work / 'data'), 'timezone': 'Asia/Seoul', 'api': {'enabled': False},
              'acknowledgements': {'enabled': True}, 'sources': {}, 'transforms': {}, 'sinks': {}}
    t = config['transforms']
    for lane, path, original in (('audit', audit, original_audit), ('access', access, original_access)):
        config['sources'][lane] = {'type': 'file', 'include': [str(path)], 'read_from': 'beginning',
            'ignore_checkpoints': False, 'max_line_bytes': 1048576, 'max_read_bytes': 262144,
            'file_key': '_pair_archive_path', 'offset_key': 'source_offset', 'fingerprint': {'strategy': 'device_and_inode'}}
        # Only this test adapter reconstructs original source metadata; VRL is unchanged.
        t[lane + '_metadata'] = {'type': 'remap', 'inputs': [lane], 'source':
            'assert!(._pair_archive_path == ' + json.dumps(str(path)) + ', "pair_archive_path")\n.source_file = ' + json.dumps(original) + '\ndel(._pair_archive_path)',
            'drop_on_error': True, 'drop_on_abort': True, 'reroute_dropped': True}
        for stage, filename, inputs in ((lane + '_guard', 'waf_json_guard.vrl', [lane + '_metadata']),
                                       (lane + '_part', 'waf_' + lane + '_part.vrl', [lane + '_guard'])):
            t[stage] = {'type': 'remap', 'inputs': inputs, 'file': str(TRANSFORMS / filename),
                        'drop_on_error': True, 'drop_on_abort': True, 'reroute_dropped': True}
    t['waf_join'] = {'type': 'reduce', 'inputs': ['audit_part', 'access_part'], 'group_by': ['waf_join_key'],
        'merge_strategies': {'waf_parts': 'array'}, 'expire_after_ms': 2000,
        'end_every_period_ms': 5000, 'flush_period_ms': 100, 'max_events': 4}
    t['pair'] = {'type': 'remap', 'inputs': ['waf_join'], 'file': str(TRANSFORMS / 'waf_pair_normalize.vrl'),
                 'drop_on_error': True, 'drop_on_abort': True, 'reroute_dropped': True}
    t['ready'] = {'type': 'filter', 'inputs': ['pair'], 'condition': '.capstone_norm.source == "modsecurity"'}
    t['ignored'] = {'type': 'filter', 'inputs': ['pair'], 'condition': '.ignored_waf_access == true'}
    drops = [name + '.dropped' for name in ('audit_metadata', 'access_metadata', 'audit_guard', 'access_guard', 'audit_part', 'access_part', 'pair')]
    for name, inputs in (('ready', ['ready']), ('ignored', ['ignored']), ('quarantine', drops)):
        config['sinks'][name + '_file'] = {'type': 'file', 'inputs': inputs, 'path': str(work / (name + '.jsonl')),
                                          'encoding': {'codec': 'json'}, 'buffer': {'type': 'memory', 'max_events': 64, 'when_full': 'block'}}
    return config


def read_outputs(work):
    result = {}
    for lane in ('ready', 'ignored', 'quarantine'):
        path = work / (lane + '.jsonl')
        # Only our append-only native file sinks use this bounded prefix read.
        # Input archives and final integrity checks retain strict stable reads.
        raw = read_bounded(path, append_snapshot=True) if path.exists() else b''
        require(len(raw) <= MAX_FILE, 'output_limit')
        # A sink may be partway through an append while polling; only full lines.
        result[lane] = [strict_object(row) for row in raw.split(b'\n')[:-1]]
        require(len(result[lane]) <= 32, 'output_record_limit')
    return result


def execute_case(work, manifest, generation, audit, access, expect_counts, *, delayed_access=None):
    work.mkdir(mode=0o700)
    (work / 'data').mkdir(mode=0o700)
    config = render_config(work, audit, access, generation['original_audit_path'], generation['original_access_path'])
    config_path = work / 'vector.json'
    config_path.write_text(json.dumps(config, indent=2) + '\n')
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'Asia/Seoul',
           'CAPSTONE_SENSOR': manifest['sensor'], 'WAF_INSTANCE_ID': manifest['instance_id'],
           'WAF_CONFIG_SHA256': generation['config_sha256'], 'WAF_DEPLOYMENT_BINDING': generation['binding'],
           'WAF_AUDIT_PATH': generation['original_audit_path'], 'WAF_ACCESS_PATH': generation['original_access_path']}
    with (work / 'validate.log').open('xb') as log:
        checked = subprocess.run([str(VECTOR), 'validate', '--no-environment', str(config_path)],
                                 stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env, timeout=15)
    require(checked.returncode == 0, 'vector_validate_failed')
    started = time.monotonic()
    delivered_after = None
    process = None
    try:
        with (work / 'vector.log').open('xb') as log:
            process = subprocess.Popen([str(VECTOR), '--config', str(config_path), '--log-format', 'json'],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
            deadline = time.monotonic() + 16
            while True:
                require(process.poll() is None, 'vector_early_exit')
                require((work / 'vector.log').stat().st_size <= MAX_FILE, 'vector_log_limit')
                output = read_outputs(work)
                counts = {k: len(v) for k, v in output.items()}
                if delayed_access is not None and delivered_after is None and counts['quarantine'] >= 1:
                    require(time.monotonic() - started >= 2, 'delayed_probe_not_expired')
                    with access.open('ab') as f:
                        f.write(delayed_access + b'\n'); f.flush(); os.fsync(f.fileno())
                    delivered_after = time.monotonic() - started
                if counts == expect_counts and (delayed_access is None or delivered_after is not None):
                    break
                require(time.monotonic() < deadline, 'pair_output_timeout')
                time.sleep(0.1)
            process.terminate()
            rc = process.wait(timeout=8)
            require(rc == 0, 'vector_shutdown_failed')
    finally:
        # Only our still-live child is signalled; no systemd/container operations.
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
    output = read_outputs(work)
    require({k: len(v) for k, v in output.items()} == expect_counts, 'final_counts_mismatch')
    for lane in output:
        p = work / (lane + '.jsonl')
        if p.exists():
            require(read_bounded(p).endswith(b'\n'), 'output_partial_line')
    return output, {'name': work.name, 'counts': expect_counts, 'vector_validate_exit': 0,
                    'vector_exit': 0, 'elapsed_seconds': round(time.monotonic() - started, 3),
                    'access_append_after_quarantine_seconds': round(delivered_after, 3) if delivered_after is not None else None,
                    'config_sha256': sha(config_path.read_bytes()), 'child_reaped': process.poll() is not None}


def verify_ready(output, expected):
    rows = output['ready']
    require(all(set(row) == {'capstone_norm'} for row in rows), 'ready_envelope')
    observed = {}
    for row in rows:
        norm = row['capstone_norm']
        key = norm['record_id']
        require(key not in observed and key in expected, 'ready_identity_set')
        require(set(norm) == set(expected[key]) | {'record_id', 'schema_version', 'pipeline', 'source',
                'protocol', 'direction', 'observed_at_kst'}, 'ready_field_set')
        require(all(norm.get(k) == v for k, v in expected[key].items()), 'ready_field_mismatch')
        require(norm['schema_version'] == 'vector-1' and norm['pipeline'] == 'vector' and
                norm['source'] == 'modsecurity' and norm['protocol'] == 'tcp' and norm['direction'] == 'unknown', 'ready_schema')
        stamp = dt.datetime.fromisoformat(norm['observed_at_kst'])
        require(stamp.utcoffset() == dt.timedelta(hours=9), 'observed_time_not_kst')
        observed[key] = norm
    require(set(observed) == set(expected), 'ready_identity_set')


def verify_drop(row, component, marker):
    metadata = row.get('metadata', {})
    require(isinstance(metadata, dict), 'quarantine_metadata')
    dropped = metadata.get('dropped', {})
    require(isinstance(dropped, dict) and dropped.get('component_id') == component and
            dropped.get('component_type') == 'remap' and dropped.get('component_kind') == 'transform' and
            dropped.get('reason') == 'error' and dropped.get('message') == marker, 'quarantine_reason_mismatch')


def verify_wrong_binding(output, audits, accesses):
    expected = {}
    for lane, source in [('audit', audits), ('access', accesses)]:
        for parts in source.values():
            key = (lane + '_part', sha(parts[0]))
            require(key not in expected, 'quarantine_expected_duplicate')
            expected[key] = parts[0]
    actual = set()
    for row in output['quarantine']:
        component = row.get('metadata', {}).get('dropped', {}).get('component_id')
        require(component in ('audit_part', 'access_part') and isinstance(row.get('message'), str), 'quarantine_wrong_stage')
        verify_drop(row, component, 'waf_' + component.removesuffix('_part') + '_producer_binding')
        raw = row['message'].encode('utf-8')
        key = (component, sha(raw))
        require(key in expected and key not in actual and expected[key] == raw, 'quarantine_raw_identity_mismatch')
        actual.add(key)
    require(actual == set(expected), 'quarantine_raw_identity_set')


def run(manifest_path):
    require(os.name == 'posix' and sys.platform.startswith('linux') and os.geteuid() == 0 and
            Path('/etc/machine-id').read_text().strip() == '096e90b6243e438aa8a7b392be754732', 'fixed_A_root_required')
    os.umask(0o077)
    require(EVIDENCE.fullmatch(str(manifest_path.parent)) and manifest_path.name == 'manifest.json', 'manifest_path_shape')
    manifest_raw = read_bounded(manifest_path, root=manifest_path.parent, immutable=True, limit=65536)
    manifest = strict_object(manifest_raw)
    root = Path(manifest['evidence_root'])
    require(EVIDENCE.fullmatch(str(root)) and manifest_path.parent == root, 'evidence_root_shape')
    private_path(manifest_path, root)
    require(manifest.get('schema_version') == 1 and isinstance(manifest.get('instance_id'), str) and
            HEX64.fullmatch(manifest['instance_id']) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', manifest.get('sensor', '')), 'manifest_identity')
    generations = manifest['generations']
    require(isinstance(generations, list) and [g['generation'] for g in generations] == [1, 2, 3, 4] and
            len({g['binding'] for g in generations}) == 4 and len({g['config_sha256'] for g in generations}) == 4, 'generation_chain')
    version = subprocess.run([str(VECTOR), '--version'], capture_output=True, text=True, timeout=5, check=True).stdout.strip()
    require(re.search(r'\b0\.59\.0\b', version) is not None, 'vector_version')
    for filename, expected in VRL_SHA.items():
        require(sha(read_bounded(TRANSFORMS / filename)) == expected, 'installed_vrl_changed')
    prepared = [expected_generation(root, manifest, generation) for generation in generations]
    ids = [x for g in generations for x in g['expected_request_ids']]
    require(len(ids) == len(set(ids)) == 6 and [len(g['expected_request_ids']) for g in generations] == [2, 1, 1, 2], 'six_unique_requests_required')
    workroot = root / 'pair-tests'
    workroot.mkdir(mode=0o700)
    results = []
    for generation, (expected, _, _) in zip(generations, prepared):
        output, result = execute_case(workroot / ('generation-' + str(generation['generation'])), manifest, generation,
            Path(generation['archive_audit_path']), Path(generation['archive_access_path']),
            {'ready': len(expected), 'ignored': 0, 'quarantine': 0})
        verify_ready(output, expected)
        result.update({'scope': 'generation_archive_replay_with_manifest_source_metadata', 'exact_identity_time_hash_tuple_match': True})
        results.append(result)
    old = generations[0]; new = dict(generations[1])
    new['original_audit_path'] = old['original_audit_path']; new['original_access_path'] = old['original_access_path']
    output, result = execute_case(workroot / 'old-binding-new-environment', manifest, new,
        Path(old['archive_audit_path']), Path(old['archive_access_path']),
        {'ready': 0, 'ignored': 0, 'quarantine': 2 * len(old['expected_request_ids'])})
    verify_wrong_binding(output, prepared[0][1], prepared[0][2])
    result.update({'scope': 'old_producer_binding_rejected_with_new_binding_config_environment',
                   'exact_raw_identity_and_binding_failure_marker': True}); results.append(result)
    first_id = old['expected_request_ids'][0]
    audit_line = prepared[0][1][first_id][0]; access_line = prepared[0][2][first_id][0]
    delayed_inputs = workroot / 'delayed-inputs'; delayed_inputs.mkdir(mode=0o700)
    audit_path = delayed_inputs / 'audit.jsonl'; access_path = delayed_inputs / 'access.jsonl'
    audit_path.write_bytes(audit_line + b'\n'); access_path.write_bytes(b'')
    output, result = execute_case(workroot / 'pair-after-expiration', manifest, old, audit_path, access_path,
                                 {'ready': 0, 'ignored': 1, 'quarantine': 1}, delayed_access=access_line)
    parts = output['quarantine'][0]['waf_parts']
    verify_drop(output['quarantine'][0], 'pair', 'waf_pair_cardinality')
    require(isinstance(parts, list) and len(parts) == 1 and parts[0]['kind'] == 'audit' and
            parts[0]['raw'].encode() == audit_line, 'expired_audit_not_preserved')
    require(output['ignored'] == [{'ignored_waf_access': True}], 'late_access_not_ignored')
    result.update({'scope': 'actual_private_reduce_TTL_with_staggered_file_appends', 'expired_audit_retained': True,
                   'late_access_ignored': True, 'proves_original_live_pipeline_pair_continuity': False}); results.append(result)
    for generation in generations:
        for key, digest in [('archive_audit_path', 'audit_sha256'), ('archive_access_path', 'access_sha256'), ('config_path', 'config_sha256')]:
            require(sha(read_bounded(Path(generation[key]), root=root, immutable=True)) == generation[digest], 'archive_changed_after_verification')
    for filename, expected in VRL_SHA.items():
        require(sha(read_bounded(TRANSFORMS / filename)) == expected, 'installed_vrl_changed_after_verification')
    report = {'status': 'passed', 'kind': 'native_generation_pair_verification', 'manifest_sha256': sha(manifest_raw),
              'at_kst': dt.datetime.now(KST).isoformat(), 'vrl_sha256': VRL_SHA, 'vector_version': version,
              'generations': 4, 'requests': 6, 'cases': results, 'original_archives_unchanged': True,
              'production_vrl_unchanged': True, 'original_metadata_reconstructed_from_manifest': True,
              'proves_real_time_pair_continuity_across_rotation': False, 'runtime_source': 'private archive file inputs only',
              'operating_ready_or_checkpoints_written': False, 'services_changed': False,
              'raw_or_request_ids_exported': False, 'packages_installed': 0, 'child_processes_reaped': True}
    (workroot / 'pair-validation.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    try:
        report = run(args.manifest)
    except Exception as exc:
        code = str(exc) if isinstance(exc, PairProbeError) else type(exc).__name__
        print(json.dumps({'status': 'not_verified', 'error_code': code, 'raw_or_request_ids_exported': False}))
        return 1
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
