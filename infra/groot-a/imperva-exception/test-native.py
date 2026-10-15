#!/usr/bin/env python3
"""Root-operated existing-engine test in an anonymous, loopback-only netns.

Never reloads the production WAF. Only the generated foreground nginx processes
and private /tmp tree are changed. No packages, new container, proxy or backend.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

DOCKER = '/usr/local/bin/docker'
CID = '02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e'
IMAGE = 'sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650'


class ProbeError(Exception):
    def __init__(self, code, diagnostic=None):
        super().__init__(code)
        self.diagnostic = diagnostic


def run(argv, **kw):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=15, **kw)


def inspect():
    row = json.loads(run([DOCKER, 'inspect', 'waf']).stdout)[0]
    if row['Id'] != CID or row['Image'] != IMAGE or not row['State']['Running']:
        raise ProbeError('production_identity_mismatch')
    return {k: row[k] for k in ('Id', 'Image')} | {
        'pid': row['State']['Pid'], 'started_at': row['State']['StartedAt']}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def policy_hashes(root):
    # pathlib does not follow the image's CRS directory symlink here. This is
    # deliberately only the base/setup/override/nginx/unicode hash inventory;
    # loading CRS in nginx is tested separately, not a full CRS hash snapshot.
    files = sorted((root / 'etc/modsecurity.d').rglob('*.conf'))
    files += [root / 'etc/nginx/nginx.conf']
    files += [root / 'etc/modsecurity.d/unicode.mapping']
    return {str(p.relative_to(root)): sha(p.read_bytes()) for p in files if p.is_file()}


def cases():
    result = []
    for kind, version, headers, target in (
            ('missing-host', 'HTTP/1.0', [], 920280),
            ('numeric-host', 'HTTP/1.1', ['Host: 192.168.16.230'], 920350)):
        baseline = dict(name=kind, source='211.170.162.9', destination='172.18.0.2', port=8080,
                        method='GET', uri='/', version=version, headers=headers,
                        target=target, mode='exception')
        result.append(baseline)
        variants = {
            'neighbor-source': {'source': '211.170.162.8'},
            'post': {'method': 'POST'},
            'nonroot': {'uri': '/other'},
            'query': {'uri': '/?probe=1'},
            'content-length-zero': {'headers': headers + ['Content-Length: 0']},
            'other-destination': {'destination': '172.18.0.3'},
            'other-port': {'port': 8081},
        }
        if kind == 'numeric-host':
            variants.update({'other-protocol': {'version': 'HTTP/1.0'},
                             'other-host': {'headers': ['Host: 192.168.16.231']},
                             'transfer-encoding': {'headers': headers + ['Transfer-Encoding: chunked'],
                                                   'body': b'0\r\n\r\n'}})
        for suffix, changes in variants.items():
            case = copy.deepcopy(baseline)
            case.update(changes, name=kind + '-' + suffix, mode='must_remain')
            result.append(case)
        attack = copy.deepcopy(baseline)
        attack.update(name=kind + '-xss-control', mode='xss',
                      headers=headers + ['User-Agent: <script>alert(1)</script>'])
        result.append(attack)
    return result


def request(case):
    headers = case['headers'] + ['Connection: close']
    payload = (f"{case['method']} {case['uri']} {case['version']}\r\n" +
               '\r\n'.join(headers) + '\r\n\r\n').encode('ascii') + case.get('body', b'')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.bind((case['source'], 0))
        sock.connect((case['destination'], case['port']))
        sock.sendall(payload)
        response = bytearray()
        while len(response) < 65536:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response.extend(chunk)
    match = re.match(br'HTTP/1\.[01] ([0-9]{3}) ', response)
    if not match:
        raise ProbeError('synthetic_http_response_invalid')
    return int(match.group(1))


def descendants(pid):
    result = {pid}
    pending = [pid]
    while pending:
        current = pending.pop()
        try:
            children = Path(f'/proc/{current}/task/{current}/children').read_text().split()
        except FileNotFoundError:
            continue
        for child in map(int, children):
            if child not in result:
                result.add(child)
                pending.append(child)
    return result


def assert_private_writers(pids, private):
    count = 0
    for pid in pids:
        for fd in Path(f'/proc/{pid}/fd').iterdir():
            try:
                target = os.readlink(fd)
                flags = re.search(r'^flags:\s+([0-7]+)$',
                                  Path(f'/proc/{pid}/fdinfo/{fd.name}').read_text(), re.M)
            except FileNotFoundError:
                continue
            if flags and int(flags.group(1), 8) & 3 in (1, 2):
                if target.startswith('/') and target != '/dev/null':
                    if not target.startswith(private + '/'):
                        raise ProbeError('nonprivate_writer_detected')
                    count += 1
    if count < 1:
        raise ProbeError('private_writer_missing')
    return count


def wait_audit(path, expected):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if path.exists() and path.stat().st_size <= 2 * 1024 * 1024:
            data = path.read_bytes()
            lines = data.splitlines()
            if len(lines) == expected and data.endswith(b'\n'):
                try:
                    return json.loads(lines[-1])
                except json.JSONDecodeError:
                    pass
        time.sleep(0.025)
    raise ProbeError('synthetic_audit_count_mismatch')


def inner(candidate):
    if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise ProbeError('isolated_root_netns_required')
    production = inspect()
    root = Path('/proc') / str(production['pid']) / 'root'
    before = policy_hashes(root)
    netns = os.readlink('/proc/self/ns/net')
    ip = shutil.which('ip')
    if not ip:
        raise ProbeError('existing_ip_binary_missing')
    run([ip, 'link', 'set', 'lo', 'up'])
    for addr in ['211.170.162.9', '211.170.162.8', '172.18.0.2', '172.18.0.3']:
        run([ip, 'address', 'add', addr + '/32', 'dev', 'lo'])
    links = json.loads(run([ip, '-j', 'link']).stdout)
    if [x['ifname'] for x in links] != ['lo']:
        raise ProbeError('nonloopback_interface_detected')
    work = Path(tempfile.mkdtemp(prefix='capstone-imperva-native-', dir=root / 'tmp'))
    private = '/tmp/' + work.name
    all_pids = set()
    result = {'kind': 'existing_engine_isolated_netns', 'container_id': CID,
              'image': IMAGE, 'production': production, 'candidate_sha256': sha(candidate.read_bytes()),
              'test_script_sha256': sha(Path(__file__).read_bytes()),
              'at_kst': datetime.now(timezone(timedelta(hours=9))).isoformat(timespec='seconds'),
              'netns': netns, 'interfaces': ['lo'], 'proxy_backend': False,
              'cases': [], 'json_raw_payload_exported': False}
    try:
        original_setup = (root / 'etc/modsecurity.d/setup.conf').read_text()
        original_base = (root / 'etc/modsecurity.d/modsecurity.conf').read_text()
        if 'Include /etc/modsecurity.d/modsecurity.conf' not in original_setup:
            raise ProbeError('unexpected_setup_include')
        if not re.search(r'^SecRuleEngine DetectionOnly$', original_base, re.M):
            raise ProbeError('unexpected_production_engine_mode')
        if (root / 'etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf').exists():
            raise ProbeError('candidate_already_installed')
        for mode in ('baseline', 'candidate'):
            stage = work / mode
            stage.mkdir(mode=0o700)
            p = private + '/' + mode
            (stage / 'html').mkdir()
            (stage / 'html/index.html').write_text('isolated native fixture\n')
            # Parse a private copy of base configuration; never even reference
            # production audit/debug/data/temp/upload destinations in this copy.
            clean = re.sub(r'^\s*Sec(?:AuditLog(?:StorageDir)?|DebugLog|TmpDir|DataDir|UploadDir)\s+.*$',
                           '', original_base, flags=re.M)
            for name in ('tmp', 'data', 'upload', 'audit-storage'):
                (stage / name).mkdir()
            clean += f'\nSecTmpDir {p}/tmp\nSecDataDir {p}/data\nSecUploadDir {p}/upload\n'
            clean += f'SecAuditLogStorageDir {p}/audit-storage\nSecDebugLog {p}/modsec-debug.log\n'
            (stage / 'base.conf').write_text(clean)
            shutil.copyfile(root / 'etc/modsecurity.d/unicode.mapping', stage / 'unicode.mapping')
            setup = original_setup.replace('Include /etc/modsecurity.d/modsecurity.conf',
                                            f'Include {p}/base.conf')
            if mode == 'candidate':
                (stage / 'candidate.conf').write_bytes(candidate.read_bytes())
                needle = 'Include /etc/modsecurity.d/owasp-crs/rules/*.conf'
                if setup.count(needle) != 1:
                    raise ProbeError('unexpected_crs_rule_include')
                setup = setup.replace(needle, f'Include {p}/candidate.conf\n' + needle)
            setup += f'\nSecAuditEngine On\nSecAuditLogType Serial\nSecAuditLogFormat JSON\nSecAuditLog {p}/audit.json\n'
            (stage / 'setup.conf').write_text(setup)
            config = f'''load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
user root;
worker_processes 1;
pid {p}/nginx.pid;
error_log {p}/nginx-error.log warn;
events {{ worker_connections 32; }}
http {{
 access_log off;
 client_body_temp_path {p}/tmp;
 proxy_temp_path {p}/tmp;
 fastcgi_temp_path {p}/tmp;
 uwsgi_temp_path {p}/tmp;
 scgi_temp_path {p}/tmp;
 modsecurity on;
 modsecurity_rules_file {p}/setup.conf;
 server {{
  listen 172.18.0.2:8080;
  listen 172.18.0.3:8080;
  listen 172.18.0.2:8081;
  server_name _;
  root {p}/html;
  location / {{ }}
 }}
}}
'''
            (stage / 'nginx.conf').write_text(config)
            prefix = ['nsenter', '--target', str(production['pid']), '--mount', '--root', '--wd=/',
                      '--', '/usr/sbin/nginx', '-e', p + '/initial-error.log', '-c', p + '/nginx.conf']
            try:
                run(prefix + ['-t'])
            except subprocess.CalledProcessError as error:
                # This configuration is generated by the test, never nginx -T
                # or a production request. Bounded diagnostics aid safe cleanup.
                raise ProbeError('private_nginx_config_invalid',
                                 error.stderr.decode(errors='replace')[-1500:]) from None
            output = (stage / 'process.log').open('wb')
            proc = subprocess.Popen(prefix + ['-g', 'daemon off;'], stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 5
                master = None
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise ProbeError('private_nginx_failed_start')
                    pid_file = stage / 'nginx.pid'
                    value = pid_file.read_text().strip() if pid_file.exists() else ''
                    if value.isdecimal():
                        master = int(value)
                        break
                    time.sleep(0.025)
                if master is None or master != proc.pid or master <= 1 or master == production['pid']:
                    raise ProbeError('private_pid_mismatch')
                for _ in range(100):
                    pids = descendants(master)
                    if len(pids) >= 2:
                        break
                    time.sleep(0.01)
                all_pids.update(pids)
                for pid in pids:
                    if os.readlink(f'/proc/{pid}/ns/net') != netns:
                        raise ProbeError('private_process_wrong_netns')
                writers = assert_private_writers(pids, private)
                for index, case in enumerate(cases(), 1):
                    status = request(case)
                    event = wait_audit(stage / 'audit.json', index)
                    transaction = event['transaction']
                    if transaction['client_ip'] != case['source'] or transaction['host_ip'] != case['destination'] or int(transaction['host_port']) != case['port']:
                        raise ProbeError('native_tuple_mismatch')
                    ids = sorted({int(x['details']['ruleId']) for x in transaction.get('messages', [])})
                    result['cases'].append({'phase': mode, 'name': case['name'], 'http_status': status,
                                            'target_rule': case['target'], 'mode': case['mode'],
                                            'rule_ids': ids})
                assert_private_writers(descendants(master), private)
                result[mode] = {'nginx_test': True, 'private_writable_fd_count': writers,
                                'setup_sha256': sha(setup.encode()), 'nginx_sha256': sha(config.encode())}
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGQUIT)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=3)
                output.close()
                deadline = time.monotonic() + 2
                while any(Path(f'/proc/{pid}').exists() for pid in all_pids) and time.monotonic() < deadline:
                    time.sleep(0.025)
                for pid in all_pids:
                    if Path(f'/proc/{pid}').exists():
                        raise ProbeError('private_process_cleanup_failed')
        baseline = {x['name']: x for x in result['cases'] if x['phase'] == 'baseline'}
        checks = []
        for row in (x for x in result['cases'] if x['phase'] == 'candidate'):
            previous = baseline[row['name']]
            if row['target_rule'] not in previous['rule_ids']:
                raise ProbeError('baseline_target_rule_missing_' + row['name'])
            if row['mode'] in ('exception', 'xss') and row['target_rule'] in row['rule_ids']:
                raise ProbeError('candidate_exception_failed_' + row['name'])
            if row['mode'] == 'must_remain' and row['target_rule'] not in row['rule_ids']:
                raise ProbeError('candidate_negative_bypass_' + row['name'])
            if row['mode'] == 'must_remain' and row['rule_ids'] != previous['rule_ids']:
                raise ProbeError('candidate_unrelated_rule_change_' + row['name'])
            if row['mode'] == 'xss' and not {10300, 949110}.issubset(row['rule_ids']):
                raise ProbeError('xss_control_suppressed_' + row['name'])
            if row['mode'] == 'xss' and set(row['rule_ids']) != set(previous['rule_ids']) - {row['target_rule']}:
                raise ProbeError('xss_unrelated_rule_change_' + row['name'])
            checks.append(row['name'])
        result['passed'] = len(checks)
        result['failed'] = 0
        result['policy_files_sha256'] = before
        result['policy_hash_scope'] = 'base_setup_override_nginx_unicode_only_not_CRS_symlink_tree'
        result['production_identity_unchanged'] = production == inspect()
        result['production_policy_unchanged'] = before == policy_hashes(root)
        if not result['production_identity_unchanged'] or not result['production_policy_unchanged']:
            raise ProbeError('production_changed_during_probe')
    finally:
        shutil.rmtree(work)
        result['private_container_tmp_removed'] = not work.exists()
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        print(json.dumps(inner(args.candidate), separators=(',', ':')))
        return
    if os.geteuid() != 0:
        raise ProbeError('root_operator_required')
    child = subprocess.Popen(['unshare', '--net', '--', sys.executable, '-B', str(Path(__file__).resolve()),
                              '--inside', '--candidate', str(args.candidate.resolve())],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = child.communicate(timeout=150)
        if child.returncode:
            try:
                failure = json.loads(err.splitlines()[-1])
                code = failure['error_code']
                if code == 'probe_internal_failure':
                    code += '_' + str(failure.get('error_type', 'unknown'))
            except (ValueError, KeyError, IndexError):
                failure = {}
                code = 'isolated_driver_failed'
            if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', code):
                code = 'isolated_driver_failed'
            raise ProbeError(code, failure.get('diagnostic'))
        report = json.loads(out)
    finally:
        # Never address a reaped child's old PGID. A later process could reuse
        # it. Normal completion already proves explicit nginx cleanup inside.
        # On an outer timeout this emergency kill cannot promise inner finally
        # ran; inspect/remove this invocation's private files separately.
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
    lingering = 0
    for path in Path('/proc').glob('[0-9]*/ns/net'):
        try:
            lingering += os.readlink(path) == report['netns']
        except (FileNotFoundError, PermissionError):
            pass
    if lingering:
        raise ProbeError('temporary_netns_process_remaining')
    report['namespace_processes_after_cleanup'] = 0
    report['production_after_outer_cleanup'] = inspect()
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ProbeError, subprocess.SubprocessError, OSError, ValueError, KeyError) as error:
        code = str(error) if isinstance(error, ProbeError) else 'probe_internal_failure'
        report = {'passed': False, 'error_code': code, 'error_type': type(error).__name__}
        if isinstance(error, ProbeError) and error.diagnostic:
            report['diagnostic'] = error.diagnostic[:1500]
        print(json.dumps(report), file=sys.stderr)
        raise SystemExit(1)
