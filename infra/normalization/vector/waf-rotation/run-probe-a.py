#!/usr/bin/env python3
"""One-shot native WAF rotation fixture; never an operational collector/rotator.

Uses installed nginx/ModSecurity in the existing image, a private loopback-only
network namespace, and installed Vector/Wazuh readers with private state/queue.
Only synthetic requests are emitted. Immutable generation evidence remains on A.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parent
MID = '096e90b6243e438aa8a7b392be754732'
DOCKER = '/usr/local/bin/docker'
CID = '02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e'
IMAGE = 'sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650'
MAX_BYTES = 2 * 1024 * 1024


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode() + b'\n'


def write_new(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value):
    tmp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    write_new(tmp, encode(value)); os.replace(tmp, path); sync_dir(path.parent)


def bounded(path):
    s = path.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_size <= MAX_BYTES, 'private_file_limit')
    with path.open('rb') as f:
        data = f.read(MAX_BYTES + 1)
    need(len(data) <= MAX_BYTES, 'private_file_grew_over_limit')
    return data


def failure_frames(error):
    # Keep code locations only. Exception values, source lines and locals may
    # contain server-only material and must never enter exported metadata.
    return [{'file': Path(frame.filename).name, 'function': frame.name,
             'line': frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)[-16:]]


def private_pid_ready(path, expected_pid):
    try:
        with path.open('rb') as handle:
            value = handle.read(65)
    except FileNotFoundError:
        return False
    need(len(value) <= 64, 'private_nginx_pid_invalid')
    # nginx -t can leave an empty pid file; the foreground writer also creates
    # it before completing the PID write. A pathname alone is not readiness.
    if not value or not value.endswith(b'\n'):
        return False
    need(re.fullmatch(rb'[1-9][0-9]{0,9}\n', value), 'private_nginx_pid_invalid')
    need(int(value) == expected_pid, 'private_nginx_pid_mismatch')
    return True


def logical_offset(value):
    # Wazuh 4.14.8 serializes file_status offsets as decimal strings. Do not
    # accept coercions from booleans, floats, signs, whitespace or Unicode digits.
    if isinstance(value, str):
        need(re.fullmatch(r'0|[1-9][0-9]{0,18}', value), 'private_wazuh_offset_invalid')
        value = int(value)
    need(type(value) is int and 0 <= value <= 9223372036854775807,
         'private_wazuh_offset_invalid')
    return value


def file_status_metadata(path):
    data = json.loads(bounded(path)); rows = data.get('files')
    need(isinstance(rows, list) and len(rows) <= 16, 'private_wazuh_status_invalid')
    return {'files': [{key: row.get(key) for key in ('path', 'offset', 'hash')}
                      for row in rows]}


COMMAND_DIAGNOSTICS = None
COMMAND_SEQUENCE = 0


def run(argv, *, timeout=15, tag=None, **kwargs):
    global COMMAND_SEQUENCE
    COMMAND_SEQUENCE += 1
    tag = tag or Path(argv[0]).name
    need(re.fullmatch('[A-Za-z0-9_-]{1,100}', tag), 'invalid_command_tag')
    failure = None
    returncode = None
    # Inherit the outer 16 MiB per-file ceiling. A 2 MiB RLIMIT here would
    # incorrectly prevent preparation from copying the 12 MiB installed .so.
    # Only captured response buffers/diagnostic copies are capped at 2 MiB each.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            p = subprocess.run(argv, stdout=out, stderr=err, timeout=timeout,
                               check=False, **kwargs)
            returncode = p.returncode
            if returncode != 0:
                failure = 'bounded_command_failed'
        except subprocess.TimeoutExpired:
            failure = 'bounded_command_timeout'
        stdout_size = os.fstat(out.fileno()).st_size
        stderr_size = os.fstat(err.fileno()).st_size
        out.seek(0); stdout = out.read(MAX_BYTES)
        err.seek(0); stderr = err.read(MAX_BYTES)
        if stdout_size > MAX_BYTES or stderr_size > MAX_BYTES:
            failure = 'bounded_command_output_limit'
    if failure:
        if COMMAND_DIAGNOSTICS is not None:
            directory = COMMAND_DIAGNOSTICS
            directory.mkdir(mode=0o700, exist_ok=True)
            name = 'command-' + str(COMMAND_SEQUENCE).zfill(3) + '-' + tag
            write_new(directory / (name + '.stdout'), stdout, 0o400)
            write_new(directory / (name + '.stderr'), stderr, 0o400)
            write_new(directory / (name + '.json'), encode({
                'tag': tag, 'returncode': returncode, 'failure_code': failure,
                'argv_sha256': sha(encode(argv)), 'stdout_bytes': stdout_size,
                'stderr_bytes': stderr_size, 'captured_limit_each': MAX_BYTES,
                'stdout_truncated': stdout_size > MAX_BYTES,
                'stderr_truncated': stderr_size > MAX_BYTES,
                'diagnostics_exported_to_Mac': False}), 0o400)
            sync_dir(directory)
        raise Refused(failure + '_' + tag)
    return stdout


def proc_info(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        values = raw[raw.rfind(')') + 2:].split()
        return {'pid': pid, 'start_ticks': int(values[19]), 'state': values[0]}
    except FileNotFoundError:
        return None


def stable_info(pid):
    value = proc_info(pid)
    need(value is not None and value['state'] != 'Z', 'operating_process_not_live')
    return {k: value[k] for k in ('pid', 'start_ticks')}


def devino(path):
    s = path.stat(); return (s.st_dev, s.st_ino)


def descendants(pid):
    out, todo = {pid}, [pid]
    while todo:
        p = todo.pop()
        try:
            children = Path(f'/proc/{p}/task/{p}/children').read_text().split()
        except FileNotFoundError:
            continue
        for item in map(int, children):
            if item not in out:
                need(len(out) < 32, 'private_process_count_limit')
                out.add(item); todo.append(item)
    return out


class Identity:
    def __init__(self, pid, *, netns=None):
        info = proc_info(pid)
        need(info and info['state'] != 'Z', 'process_not_live')
        self.pid, self.start = pid, info['start_ticks']
        self.fd = os.pidfd_open(pid)
        need(self.same(), 'process_changed_during_pidfd_open')
        self.netns = os.readlink(f'/proc/{pid}/ns/net')
        need(netns is None or self.netns == netns, 'process_wrong_network_namespace')

    def same(self):
        info = proc_info(self.pid)
        return bool(info and info['start_ticks'] == self.start)

    def live(self):
        info = proc_info(self.pid)
        return bool(info and info['start_ticks'] == self.start and info['state'] != 'Z')

    def send(self, sig):
        need(self.same(), 'signal_process_identity_changed')
        signal.pidfd_send_signal(self.fd, sig)

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None


def fd_records(identity):
    if not identity.live():
        return []
    rows = []
    try:
        paths = list(Path(f'/proc/{identity.pid}/fd').iterdir())
    except FileNotFoundError:
        return []
    need(len(paths) <= 512, 'private_fd_count_limit')
    for p in paths:
        try:
            target = os.readlink(p)
            st = p.stat()
            text = Path(f'/proc/{identity.pid}/fdinfo/{p.name}').read_text()
        except FileNotFoundError:
            continue
        # EACCES and all other errors must propagate, never mean zero FDs.
        flags = re.search(r'^flags:\s+([0-7]+)$', text, re.M)
        pos = re.search(r'^pos:\s+([0-9]+)$', text, re.M)
        need(flags is not None and pos is not None, 'fd_metadata_invalid')
        rows.append({'fd': int(p.name), 'devino': (st.st_dev, st.st_ino),
                     'access': int(flags.group(1), 8) & 3, 'position': int(pos.group(1)), 'target': target})
    need(identity.same() or not identity.live(), 'fd_process_identity_changed')
    return rows


def count_fd(identity, path, writable=False):
    target = devino(path)
    return sum(x['devino'] == target and ((x['access'] in (1, 2)) if writable else x['access'] == 0)
               for x in fd_records(identity))


def operating_snapshot():
    row = json.loads(run([DOCKER, 'inspect', 'waf']))[0]
    need(row['Id'] == CID and row['Image'] == IMAGE and row['State']['Running'], 'operating_waf_identity_mismatch')
    pid = row['State']['Pid']; root = Path('/proc') / str(pid) / 'root'
    paths = ['etc/nginx/nginx.conf', 'etc/nginx/conf.d/zz-capstone-evidence.conf',
             'etc/modsecurity.d/modsecurity.conf', 'etc/modsecurity.d/setup.conf',
             'etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf',
             'etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf']
    # Resolve image symlinks inside the pinned container, never against the host.
    lines = run([DOCKER, 'exec', CID, 'sha256sum', *['/' + p for p in paths]]).decode('ascii').splitlines()
    need(len(lines) == len(paths), 'operating_config_hash_count')
    config = {}
    for name, line in zip(paths, lines):
        parts = line.split()
        need(len(parts) == 2 and re.fullmatch('[a-f0-9]{64}', parts[0]) and parts[1] == '/' + name,
             'operating_config_hash_shape')
        config[name] = parts[0]
    config['host-waf-binding'] = sha(Path('/etc/capstone-vector/waf-binding.json').read_bytes())
    config['host-vector-config'] = sha(Path('/etc/capstone-vector/vector.toml').read_bytes())
    vector = int(run(['systemctl', 'show', 'capstone-vector.service', '--property=MainPID', '--value']).strip())
    pids = list(Path('/var/ossec/var/run').glob('wazuh-logcollector-*.pid'))
    need(len(pids) == 1, 'operating_logcollector_pid_ambiguous')
    wazuh = int(pids[0].read_text())
    source = {}
    for name in ('audit.log', 'capstone-access.log'):
        path = root / 'var/log/modsecurity' / name
        st = path.stat(); limit = min(st.st_size, MAX_BYTES)
        with path.open('rb') as f:
            prefix = f.read(limit)
        source[name] = {'devino': list(devino(path)), 'prefix_bytes': limit, 'prefix_sha256': sha(prefix)}
    return {'container_id': CID, 'image_id': IMAGE, 'container_init': stable_info(pid),
            'container_started_at': row['State']['StartedAt'], 'config_sha256': config,
            'vector': stable_info(vector), 'wazuh': stable_info(wazuh),
            'vector_netns': os.readlink(f'/proc/{vector}/ns/net'),
            'wazuh_mountns': os.readlink(f'/proc/{wazuh}/ns/mnt'),
            'wazuh_root': list(devino(Path('/var/ossec'))),
            'wazuh_queue': list(devino(Path('/var/ossec/queue/sockets/queue'))), 'sources': source}


def verify_operating(before):
    after = operating_snapshot()
    for key in before:
        if key != 'sources':
            need(after[key] == before[key], 'operating_boundary_changed_' + key)
    root = Path('/proc') / str(before['container_init']['pid']) / 'root'
    for name, prior in before['sources'].items():
        path = root / 'var/log/modsecurity' / name
        need(list(devino(path)) == prior['devino'] and path.stat().st_size >= prior['prefix_bytes'], 'operating_log_identity_changed')
        with path.open('rb') as f:
            need(sha(f.read(prior['prefix_bytes'])) == prior['prefix_sha256'], 'operating_log_prefix_changed')
    return {'identity_config_service_pids_equal': True, 'operating_raw_inode_prefix_equal': True,
            'scope': 'eight_explicit_config_hashes_and_bounded_raw_prefixes_not_entire_CRS_tree'}


class WazuhJSON:
    # Exact installed native serialization oracle. No whitespace heuristics,
    # duplicate-key collapse, custom JSON parser, or replacement collector.
    def __init__(self):
        path = Path('/var/ossec/lib/libwazuhext.so')
        st = path.stat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_size < 64 * MAX_BYTES,
             'wazuh_native_json_library_not_trusted')
        self.sha256 = sha(path.read_bytes())
        try:
            self.lib = ctypes.CDLL(str(path))
            self.lib.cJSON_ParseWithOpts.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]
            self.lib.cJSON_ParseWithOpts.restype = ctypes.c_void_p
            self.lib.cJSON_PrintUnformatted.argtypes = [ctypes.c_void_p]
            self.lib.cJSON_PrintUnformatted.restype = ctypes.c_void_p
            self.lib.cJSON_Delete.argtypes = [ctypes.c_void_p]
            self.lib.cJSON_Delete.restype = None
            self.lib.cJSON_free.argtypes = [ctypes.c_void_p]
            self.lib.cJSON_free.restype = None
        except (OSError, AttributeError) as error:
            raise Refused('wazuh_native_json_oracle_unavailable') from error

    def digest(self, raw):
        need(len(raw) <= 131072 and b'\x00' not in raw, 'audit_native_json_input_limit')
        tree = self.lib.cJSON_ParseWithOpts(raw, None, 1)
        need(bool(tree), 'wazuh_native_json_parse_failed')
        printed = None
        try:
            printed = self.lib.cJSON_PrintUnformatted(tree)
            need(bool(printed), 'wazuh_native_json_print_failed')
            normalized = ctypes.string_at(printed)
            need(len(normalized) <= 131072, 'wazuh_native_json_output_limit')
            return sha(normalized)
        finally:
            if printed:
                self.lib.cJSON_free(printed)
            self.lib.cJSON_Delete(tree)


class Probe:
    def __init__(self, output):
        self.output = output
        self.stage = None; self.writer_root = None; self.pending = None
        self.master = self.master_proc = self.vector = self.vector_proc = None
        self.wazuh = self.wazuh_proc = self.naive = self.naive_proc = None
        self.writer_ids = {}; self.children = {}; self.handles = []; self.generations = []
        self.result = {'schema_version': 1, 'status': 'running', 'phase': 'construction', 'cleanup': {}}
        self.save()
        self.before = operating_snapshot()
        self.wazuh_json = WazuhJSON()
        self.stage = Path(tempfile.mkdtemp(prefix='capstone-waf-rotation.', dir='/var/tmp'))
        self.result['private_host_path'] = str(self.stage); self.save()
        self.init = self.before['container_init']['pid']
        self.container_root = Path('/proc') / str(self.init) / 'root'
        need(not (self.container_root / 'tmp').is_symlink(), 'container_tmp_symlink')
        self.writer_root = Path(tempfile.mkdtemp(prefix='capstone-waf-rotation.', dir=self.container_root / 'tmp'))
        self.cname = self.writer_root.name
        self.cprivate = '/tmp/' + self.cname
        self.result['private_container_path'] = self.cprivate; self.save()
        for d in ('reader', 'naive', 'html', 'tmp', 'data', 'upload'):
            (self.writer_root / d).mkdir(mode=0o700)
        (self.writer_root / 'html' / 'index.html').write_text('private native rotation fixture\n')
        self.netns = os.readlink('/proc/self/ns/net')
        need(self.netns != os.readlink('/proc/1/ns/net'), 'dedicated_network_namespace_required')
        run(['ip', 'link', 'set', 'lo', 'up'])
        need([x['ifname'] for x in json.loads(run(['ip', '-j', 'link']))] == ['lo'], 'nonloopback_interface')
        self.port = 18998
        self.master = None; self.master_proc = None; self.writer_ids = {}
        self.vector = None; self.vector_proc = None; self.wazuh = None; self.wazuh_proc = None
        self.naive = None; self.naive_proc = None; self.pending = None
        self.generations = []; self.current = None; self.published = 1; self.vector_stopped = False
        self.handles = []
        (self.stage / 'data').mkdir(); (self.stage / 'observed').mkdir()
        self.result = {'schema_version': 1, 'status': 'running', 'phase': 'initialization',
            'synthetic_only': True, 'normal_http_only': True, 'separate_network_namespace': self.netns,
            'interfaces': ['lo'], 'test_writer_uid': 0, 'operating_writer_uid_reproduction': False,
            'production_rotator_deployed': False, 'manager_or_indexer_ack': False,
            'realtime_pair_join_proven': False, 'wazuh_serialization_library_sha256': self.wazuh_json.sha256,
            'wazuh_comparison': 'exact_installed_cJSON_PrintUnformatted_bytes_not_original_JSONL_bytes', 'request_cases': [], 'publications': [],
            'before': self.before, 'source_sha256': {p.name: sha(p.read_bytes()) for p in
                (Path(__file__), ROOT / 'wazuh-isolated.sh')}, 'private_host_path': str(self.stage),
            'private_container_path': self.cprivate, 'cleanup': {}}
        self.save()
        self.runtime_registry()

    def save(self):
        atomic(self.output / 'result.json', self.result)

    def runtime_registry(self):
        rows = []
        for name, item in self.children.items():
            info = proc_info(item['process'].pid)
            if info and info['start_ticks'] == item['start_ticks']:
                rows.append({'kind': name, 'pid': info['pid'], 'start_ticks': info['start_ticks'],
                             'netns': os.readlink(f'/proc/{info["pid"]}/ns/net')})
        for pid, identity in self.writer_ids.items():
            if identity.live() and pid not in [r['pid'] for r in rows]:
                rows.append({'kind': 'nginx_worker', 'pid': pid, 'start_ticks': identity.start,
                             'netns': identity.netns})
        atomic(self.output / 'runtime-processes.json', {'rows': rows,
            'fixture_netns': getattr(self, 'netns', os.readlink('/proc/self/ns/net')),
            'private_host_path': str(self.stage) if self.stage else None,
            'private_container_path': getattr(self, 'cprivate', None)})

    def spawn(self, name, argv, log, env=None, expected_netns=None):
        need(name not in self.children, 'private_child_name_in_use')
        def private_file_limit():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BYTES, MAX_BYTES))
        process = subprocess.Popen(argv, stdout=log, stderr=log, env=env, start_new_session=True, preexec_fn=private_file_limit)
        # The unreaped direct child cannot have its PID reused. Register before
        # any fallible readiness/namespace/executable checks.
        info = proc_info(process.pid)
        need(info is not None, 'spawned_child_identity_missing')
        self.children[name] = {'process': process, 'start_ticks': info['start_ticks'], 'identity': None}
        self.runtime_registry()
        identity = Identity(process.pid, netns=expected_netns)
        self.children[name]['identity'] = identity
        self.runtime_registry()
        return process, identity

    def stop_registered(self):
        failures = []
        for name, item in list(self.children.items()):
            process, identity = item['process'], item['identity']
            try:
                if identity is not None:
                    self.stop_child(process, identity)
                else:
                    # Direct child still has not been reaped; address this
                    # owned process group before wait, never after a poll.
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                self.children.pop(name, None)
            except BaseException as error:
                failures.append(name + ':' + type(error).__name__)
        self.runtime_registry()
        return failures

    def phase(self, name):
        self.result['phase'] = name; self.save()

    def wait(self, check, code, timeout=100):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if check():
                return
            time.sleep(0.1)
        raise Refused(code)

    def write_generation(self, number):
        need(number == len(self.generations) + 1 and 1 <= number <= 4, 'generation_not_adjacent')
        p = self.writer_root / ('g' + str(number)); p.mkdir(mode=0o700)
        cp = self.cprivate + '/g' + str(number)
        binding = uuid.uuid4().hex + uuid.uuid4().hex
        producer = f'''log_format capstone_private escape=json
 '{{"capstone_waf_access_version":"1","deployment_binding":"{binding}",'
 '"request_id":"$request_id","time_iso8601":"$time_iso8601","msec":"$msec",'
 '"request_time":"$request_time","source_ip":"$remote_addr","destination_ip":"$server_addr",'
 '"source_port":"$remote_port","destination_port":"$server_port",'
 '"http_method":"$request_method","http_status":"$status"}}';
access_log {cp}/access.json capstone_private;
modsecurity_transaction_id "{binding}-$request_id";
'''
        modsec = f'''SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine On
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLogParts ABIJDEFHZ
SecAuditLog {cp}/audit.json
SecAuditLogStorageDir {self.cprivate}/data
SecDebugLog {self.cprivate}/modsecurity-debug.log
SecDebugLogLevel 0
SecTmpDir {self.cprivate}/tmp
SecDataDir {self.cprivate}/data
SecUploadDir {self.cprivate}/upload
SecAction "id:9900992,phase:1,pass,log,auditlog,msg:'CAPSTONE_PRIVATE_ROTATION_FIXTURE',severity:5"
'''
        config = f'''load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;
user root;
worker_processes 1;
pid {self.cprivate}/nginx.pid;
error_log {self.cprivate}/nginx-error.log warn;
events {{ worker_connections 64; }}
http {{
 client_body_temp_path {self.cprivate}/tmp;
 proxy_temp_path {self.cprivate}/tmp;
 fastcgi_temp_path {self.cprivate}/tmp;
 uwsgi_temp_path {self.cprivate}/tmp;
 scgi_temp_path {self.cprivate}/tmp;
 client_body_timeout 300s;
 send_timeout 300s;
 keepalive_timeout 1s;
 include {cp}/producer.conf;
 modsecurity on;
 modsecurity_rules_file {cp}/modsecurity.conf;
 server {{
  listen 127.0.0.1:{self.port};
  server_name localhost;
  root {self.cprivate}/html;
  add_header X-Capstone-Test-Request-ID $request_id always;
  location / {{ }}
 }}
}}
'''
        write_new(p / 'producer.conf', producer.encode())
        write_new(p / 'modsecurity.conf', modsec.encode())
        write_new(p / 'nginx.conf', config.encode())
        for name in ('audit.json', 'access.json'):
            write_new(p / name, b'')
        row = {'generation': number, 'binding': binding, 'config_sha256': sha(producer.encode()),
               'directory': p, 'container_directory': cp, 'config': config.encode(), 'expected': []}
        self.generations.append(row)
        # Native -t uses only private log destinations and exits before writer FD checks.
        run(self.nginx_command(cp + '/nginx.conf') + ['-t'], tag='validate_private_nginx_' + str(number))
        tmp = self.writer_root / '.next-nginx.conf'
        write_new(tmp, config.encode()); os.replace(tmp, self.writer_root / 'nginx.conf'); sync_dir(self.writer_root)
        return row

    def nginx_command(self, config=None):
        return ['nsenter', '--target', str(self.init), '--mount', '--root', '--wd=/', '--',
                '/usr/sbin/nginx', '-e', self.cprivate + '/initial-error.log', '-c',
                config or self.cprivate + '/nginx.conf']

    def refresh_writers(self):
        if self.master and self.master.live():
            for pid in descendants(self.master.pid):
                if pid not in self.writer_ids:
                    self.writer_ids[pid] = Identity(pid, netns=self.netns)
            self.runtime_registry()
        return [i for i in self.writer_ids.values() if i.live()]

    def private_writes_only(self):
        total = 0
        for identity in self.refresh_writers():
            for fd in fd_records(identity):
                if fd['access'] in (1, 2) and fd['target'].startswith('/') and fd['target'] != '/dev/null':
                    need(fd['target'].startswith(self.cprivate + '/'), 'writer_outside_private_tree')
                    total += 1
        need(total > 0, 'private_writer_fd_missing')

    def writer_opened(self, generation):
        writers = self.refresh_writers()
        p = generation['directory']
        return (len(writers) >= 2 and all(sum(count_fd(i, p / name, True) for i in writers) >= 2
                                        for name in ('audit.json', 'access.json')))

    def writer_closed(self, generation):
        p = generation['directory']; self.refresh_writers()
        return all(sum(count_fd(i, p / name, True) for i in self.writer_ids.values()) == 0
                   for name in ('audit.json', 'access.json'))

    def start_writer(self, generation):
        log = (self.writer_root / 'stdout.log').open('wb'); self.handles.append(log)
        self.master_proc, self.master = self.spawn('nginx_master', self.nginx_command() + ['-g', 'daemon off;'], log, expected_netns=self.netns)
        self.writer_ids[self.master.pid] = self.master
        need(self.master.pid != self.init, 'private_nginx_pid_mismatch')
        self.wait(lambda: private_pid_ready(self.writer_root / 'nginx.pid', self.master.pid),
                  'private_nginx_pid_incomplete', 10)
        self.wait(lambda: self.writer_opened(generation), 'private_writer_not_opened', 10)
        self.private_writes_only(); self.current = generation

    def reload_writer(self, generation):
        previous = set(i.pid for i in self.refresh_writers())
        self.master.send(signal.SIGHUP)
        self.wait(lambda: self.writer_opened(generation) and any(i.pid not in previous for i in self.refresh_writers()),
                  'new_writer_generation_missing', 15)
        self.private_writes_only(); self.current = generation

    def start_readers(self, initial=False):
        alias = self.writer_root / 'reader' / 'audit.json'
        naive = self.writer_root / 'naive' / 'audit.json'
        prefix = self.stage / 'wazuh'; np = self.stage / 'naive-wazuh'
        if initial:
            run(['bash', str(ROOT / 'wazuh-isolated.sh'), 'prepare', str(prefix), str(alias)], tag='prepare_wazuh_good')
            run(['bash', str(ROOT / 'wazuh-isolated.sh'), 'prepare', str(np), str(naive)], tag='prepare_wazuh_naive')
            self.vector_config()
            run(['/usr/local/bin/vector', 'validate', '--no-environment', str(self.stage / 'vector.toml')], tag='validate_private_vector')
        log = (self.stage / 'vector.log').open('ab'); self.handles.append(log)
        self.vector_proc, self.vector = self.spawn('vector', ['/usr/bin/nice', '-n', '10', '/usr/local/bin/vector', '--config', str(self.stage / 'vector.toml')], log, env={**os.environ, 'VECTOR_LOG': 'warn'}, expected_netns=self.netns)
        self.wait(lambda: (prefix / 'queue/sockets/queue').is_socket() and (np / 'queue/sockets/queue').is_socket(), 'private_queue_missing', 10)
        self.wazuh_proc, self.wazuh = self.start_wazuh(prefix)
        self.wait(lambda: count_fd(self.wazuh, alias) == 1, 'wazuh_initial_fd_missing')
        if initial:
            self.naive_proc, self.naive = self.start_wazuh(np)
            self.wait(lambda: count_fd(self.naive, naive) == 1, 'naive_initial_fd_missing')

    def start_wazuh(self, prefix):
        log = (prefix / 'stderr').open('ab'); self.handles.append(log)
        p, identity = self.spawn(prefix.name, ['bash', str(ROOT / 'wazuh-isolated.sh'), 'launch', str(prefix)], log)
        self.wait(lambda: (prefix / f'var/run/wazuh-logcollector-{p.pid}.pid').exists(), 'private_wazuh_startup', 10)
        need(os.readlink(f'/proc/{p.pid}/ns/net') != self.netns, 'wazuh_private_network_namespace_missing')
        need(os.readlink(f'/proc/{p.pid}/exe') == str(prefix / 'bin/wazuh-logcollector'), 'private_wazuh_exe')
        need(os.readlink(f'/proc/{p.pid}/cwd') == str(prefix), 'private_wazuh_cwd')
        need(devino(Path(f'/proc/{p.pid}/root/var/ossec')) == devino(prefix), 'private_wazuh_root_bind')
        need(os.readlink(f'/proc/{p.pid}/ns/mnt') != os.readlink('/proc/self/ns/mnt'), 'private_wazuh_mount_namespace')
        self.runtime_registry()
        return p, identity

    def vector_config(self):
        audit = str(self.writer_root / 'reader/audit.json'); access = str(self.writer_root / 'reader/access.json')
        prefix = str(self.stage / 'wazuh'); naive = str(self.stage / 'naive-wazuh')
        text = f'''data_dir = "{self.stage}/data"
[sources.audit]
type = "file"
include = ["{audit}"]
read_from = "beginning"
fingerprint.strategy = "device_and_inode"
max_line_bytes = 131072
max_read_bytes = 262144
[sources.access]
type = "file"
include = ["{access}"]
read_from = "beginning"
fingerprint.strategy = "device_and_inode"
max_line_bytes = 131072
max_read_bytes = 262144
[sources.wazuh]
type = "socket"
mode = "unix_datagram"
path = "{prefix}/queue/sockets/queue"
socket_file_mode = 384
[sources.naive]
type = "socket"
mode = "unix_datagram"
path = "{naive}/queue/sockets/queue"
socket_file_mode = 384
[transforms.audit_marker]
type = "remap"
inputs = ["audit"]
source = ''' + "'''" + '''
raw = string!(.message)
event = parse_json!(raw)
id = string!(event.transaction.unique_id)
. = {"lane":"vector_audit", "identity":id, "raw_sha256":sha2(raw, variant:"SHA-256")}
''' + "'''" + f'''
[transforms.access_marker]
type = "remap"
inputs = ["access"]
source = ''' + "'''" + '''
raw = string!(.message)
event = parse_json!(raw)
id = string!(event.deployment_binding) + "-" + string!(event.request_id)
. = {"lane":"vector_access", "identity":id, "raw_sha256":sha2(raw, variant:"SHA-256")}
''' + "'''" + f'''
[transforms.wazuh_marker]
type = "remap"
inputs = ["wazuh", "naive"]
drop_on_error = true
drop_on_abort = true
source = ''' + "'''" + f'''
parts = parse_regex!(string!(.message), r'^[^:]+:(?P<path>[^:]+):(?P<body>.*)$')
lane = if parts.path == "{audit}" {{ "wazuh_audit" }} else if parts.path == "{self.writer_root}/naive/audit.json" {{ "naive_wazuh" }} else {{ abort }}
raw = replace(string!(parts.body), r'\\x00$', "")
event = parse_json!(raw)
id = string!(event.transaction.unique_id)
. = {{"lane":lane, "identity":id, "raw_sha256":sha2(raw, variant:"SHA-256")}}
''' + "'''" + f'''
[sinks.observed]
type = "file"
inputs = ["audit_marker", "access_marker", "wazuh_marker"]
path = "{self.stage}/observed/{{{{ lane }}}}.jsonl"
encoding.codec = "json"
'''
        write_new(self.stage / 'vector.toml', text.encode())

    def request(self, label, *, pending=False):
        sock = socket.socket(); sock.settimeout(180); sock.connect(('127.0.0.1', self.port))
        method = 'POST' if pending else 'GET'
        headers = f'{method} /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'
        if pending:
            headers += 'Content-Length: 2\r\nContent-Type: application/octet-stream\r\n'
        sock.sendall((headers + '\r\n').encode() + (b'A' if pending else b''))
        if pending:
            self.pending = sock
            self.wait(lambda: self.accepted_by_old_worker(sock), 'pending_request_old_worker_not_proven', 10)
            self.pending_generation = self.current
            self.pending_counts = self.raw_counts(self.current)
            need(self.pending_counts == (1, 1), 'pending_request_logged_prematurely')
            self.result['pending_request'] = {'accepted_by_old_worker': True,
                'worker_pid': self.pending_worker.pid, 'worker_start_ticks': self.pending_worker.start,
                'generation': self.current['generation'], 'audit_access_counts_before_hup': list(self.pending_counts),
                'client_body_timeout_seconds': 300}
            self.save(); return
        return self.finish_request(sock, label, self.current)

    def accepted_by_old_worker(self, sock):
        client_port = sock.getsockname()[1]; wanted = None
        for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[1].split(':')[1], 16) == self.port and int(fields[2].split(':')[1], 16) == client_port and fields[3] == '01':
                wanted = fields[9]; break
        if wanted is None:
            return False
        for i in self.refresh_writers():
            if i.pid != self.master.pid and any(x['target'] == 'socket:[' + wanted + ']' for x in fd_records(i)):
                need(all(count_fd(i, self.current['directory'] / name, True) > 0 for name in ('audit.json', 'access.json')), 'pending_worker_old_fd_missing')
                self.pending_worker = i; return True
        return False

    def finish_request(self, sock, label, generation):
        response = bytearray()
        try:
            while len(response) <= 65536:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response.extend(chunk)
        finally:
            sock.close()
        need(len(response) <= 65536, 'private_http_reply_limit')
        status = re.match(br'HTTP/1\.[01] ([0-9]{3}) ', response)
        match = re.search(br'^X-Capstone-Test-Request-ID: ([a-f0-9]{32})\r?$', response, re.M | re.I)
        need(status and match, 'generated_http_request_id_missing')
        request_id = match.group(1).decode(); code = int(status.group(1))
        need(code == (405 if label == 'late_old' else 200), 'unexpected_synthetic_http_status')
        need(all(request_id not in g['expected'] for g in self.generations), 'request_id_repeated')
        generation['expected'].append(request_id)
        self.result['request_cases'].append({'case': label, 'generation': generation['generation'],
            'request_id': request_id, 'http_status': code})
        self.save()
        self.wait(lambda: self.raw_counts(generation) == (len(generation['expected']), len(generation['expected'])), 'writer_audit_access_count')
        return request_id

    def raw_rows(self, generation, kind):
        raw = bounded(generation['directory'] / (kind + '.json'))
        if not raw:
            return []
        need(raw.endswith(b'\n'), 'partial_synthetic_json_line')
        rows = []
        for line in raw.splitlines():
            event = json.loads(line)
            if kind == 'audit':
                identity = event['transaction']['unique_id']
            else:
                identity = event['deployment_binding'] + '-' + event['request_id']
            need(re.fullmatch('[a-f0-9]{64}-[a-f0-9]{32}', identity) and identity.startswith(generation['binding'] + '-'), 'raw_generation_binding_mismatch')
            row = {'identity': identity, 'raw_sha256': sha(line)}
            if kind == 'audit':
                row['wazuh_serialized_sha256'] = self.wazuh_json.digest(line)
            rows.append(row)
        return rows

    def raw_counts(self, generation):
        return len(self.raw_rows(generation, 'audit')), len(self.raw_rows(generation, 'access'))

    def observed(self, lane):
        p = self.stage / 'observed' / (lane + '.jsonl')
        if not p.exists():
            return []
        raw = bounded(p)
        need(not raw or raw.endswith(b'\n'), 'partial_marker_output')
        return [{k: row[k] for k in ('identity', 'raw_sha256')} for row in map(json.loads, raw.splitlines())]

    def reader_exact(self, generation, *, lane, kind):
        expected = [{"identity": r['identity'], "raw_sha256": r['wazuh_serialized_sha256' if 'wazuh' in lane else 'raw_sha256']}
                    for r in self.raw_rows(generation, kind)]
        actual = [r for r in self.observed(lane) if r['identity'].startswith(generation['binding'] + '-')]
        return sorted(actual, key=lambda x: x['identity']) == sorted(expected, key=lambda x: x['identity']) and len(actual) == len(generation['expected'])

    def wait_generation(self, generation):
        for lane, kind in (('vector_audit', 'audit'), ('vector_access', 'access'), ('wazuh_audit', 'audit')):
            self.wait(lambda: self.reader_exact(generation, lane=lane, kind=kind), 'reader_generation_incomplete_' + lane)

    def wait_eof(self, generation):
        alias = self.writer_root / 'reader/audit.json'
        raw = bounded(alias); size = len(raw); checksum = hashlib.sha1(raw).hexdigest()
        path = str(alias); status = self.stage / 'wazuh/queue/logcollector/file_status.json'
        def check():
            if not status.exists():
                return False
            try:
                data = json.loads(bounded(status)); rows = [x for x in data['files'] if x['path'] == path]
            except (ValueError, KeyError):
                return False
            return (len(rows) == 1 and logical_offset(rows[0]['offset']) == size
                    and rows[0]['hash'] == checksum and count_fd(self.wazuh, alias) == 1)
        need(devino(alias) == devino(generation['directory'] / 'audit.json'), 'reader_alias_generation_mismatch')
        self.wait(check, 'wazuh_logical_eof_sha_mismatch')
        return {'bytes': size, 'sha1': checksum}

    def alias(self, kind, generation, lane='reader'):
        directory = self.writer_root / lane
        target = directory / (kind + '.json'); tmp = directory / ('.next-' + kind)
        need(not tmp.exists(), 'alias_temporary_exists')
        os.link(generation['directory'] / (kind + '.json'), tmp)
        os.replace(tmp, target); sync_dir(directory)

    def publish(self, next_generation):
        need(next_generation['generation'] == self.published + 1, 'alias_generation_skip')
        old = self.generations[self.published - 1]
        self.wait(lambda: self.writer_closed(old), 'old_writer_not_closed')
        self.wait_generation(old); eof = self.wait_eof(old)
        closed = {kind: {'devino': list(devino(old['directory'] / (kind + '.json'))),
                  'bytes': len(bounded(old['directory'] / (kind + '.json'))),
                  'sha256': sha(bounded(old['directory'] / (kind + '.json')))} for kind in ('audit', 'access')}
        need(self.writer_closed(old), 'old_writer_reappeared_before_publish')
        self.vector.send(signal.SIGSTOP); self.vector_stopped = True
        try:
            self.alias('audit', next_generation); self.alias('access', next_generation)
        finally:
            self.vector.send(signal.SIGCONT); self.vector_stopped = False
        self.published += 1
        self.wait(lambda: count_fd(self.wazuh, self.writer_root / 'reader/audit.json') == 1, 'new_wazuh_inode_missing')
        for kind in ('audit', 'access'):
            need(sha(bounded(old['directory'] / (kind + '.json'))) == closed[kind]['sha256'], 'closed_generation_changed')
        self.result['publications'].append({'from_generation': old['generation'], 'to_generation': self.published,
            'both_writer_fds_zero': True, 'both_vector_lanes_exact': True, 'wazuh_audit_exact': True,
            'wazuh_logical_eof': eof, 'closed': closed,
            'two_path_update': 'private_Vector_paused_during_two_renames_not_filesystem_multi_path_atomicity'})
        self.save()

    def stop_child(self, process, identity, *, graceful=False):
        if identity is None:
            return
        started = time.monotonic()
        name = next((key for key, item in self.children.items()
                     if item['process'] is process), 'unregistered')
        forced = False; term_sent = False
        try:
            if identity.live():
                identity.send(signal.SIGCONT); identity.send(signal.SIGTERM)
                term_sent = True
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forced = True
                if identity.live():
                    identity.send(signal.SIGKILL)
                process.wait(timeout=5)
        finally:
            state_sha = None; state_error = None; state_exact = False
            if name in ('wazuh', 'naive-wazuh'):
                state_path = self.stage / name / 'queue/logcollector/file_status.json'
                try:
                    if state_path.exists():
                        state_sha = sha(bounded(state_path))
                        alias = self.writer_root / ('reader' if name == 'wazuh' else 'naive') / 'audit.json'
                        raw = bounded(alias)
                        rows = [row for row in file_status_metadata(state_path)['files']
                                if row['path'] == str(alias)]
                        state_exact = (len(rows) == 1 and logical_offset(rows[0]['offset']) == len(raw)
                                       and rows[0]['hash'] == hashlib.sha1(raw).hexdigest())
                except BaseException as error:
                    state_error = type(error).__name__
            self.result.setdefault('stop_results', []).append({
                'name': name, 'pid': identity.pid, 'start_ticks': identity.start,
                'graceful_required': graceful, 'term_sent': term_sent,
                'forced': forced, 'returncode': process.returncode,
                'elapsed_seconds': round(time.monotonic() - started, 6),
                'file_status_sha256_after_stop': state_sha,
                'file_status_exact_final_eof': state_exact,
                'file_status_read_error': state_error})
            self.save()
        need(not identity.live(), 'private_child_not_stopped')
        identity.close()
        for child_name, item in list(self.children.items()):
            if item['process'] is process:
                del self.children[child_name]
        self.runtime_registry()
        # Wazuh v4.14.8 StartSIG/HandleSIG exits(1) on SIGTERM, then its
        # atexit handler writes file_status. Require that exact signal contract
        # and final cursor/SHA, not a blanket acceptance of any nonzero exit.
        # https://github.com/wazuh/wazuh/blob/v4.14.8/src/shared/sig_op.c#L44-L69
        graceful_ok = (term_sent and not forced and process.returncode == 1 and state_exact
                       if name in ('wazuh', 'naive-wazuh')
                       else term_sent and not forced and process.returncode == 0)
        need(not graceful or graceful_ok, 'graceful_reader_stop_failed')

    def stop_readers(self, *, graceful=False):
        self.stop_child(self.naive_proc, self.naive, graceful=graceful); self.naive_proc = self.naive = None
        self.stop_child(self.wazuh_proc, self.wazuh, graceful=graceful); self.wazuh_proc = self.wazuh = None
        self.stop_child(self.vector_proc, self.vector, graceful=graceful); self.vector_proc = self.vector = None
        self.vector_stopped = False

    def stop_writer(self):
        if not self.master:
            return
        self.refresh_writers()
        if self.master.live():
            self.master.send(signal.SIGQUIT)
        try:
            self.master_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            for i in self.writer_ids.values():
                if i.live():
                    i.send(signal.SIGKILL)
            self.master_proc.wait(timeout=5)
        self.wait(lambda: not any(i.live() for i in self.writer_ids.values()), 'private_writer_children_remain', 5)

    def preserve(self):
        evidence = self.output / 'evidence'; evidence.mkdir(mode=0o700)
        records = []
        for generation in self.generations:
            directory = evidence / ('generation-' + str(generation['generation'])); directory.mkdir(mode=0o700)
            hashes = {}
            for name in ('audit.json', 'access.json', 'producer.conf', 'modsecurity.conf', 'nginx.conf'):
                raw = bounded(generation['directory'] / name)
                write_new(directory / name, raw, 0o400); hashes[name] = sha(raw)
                need(sha((directory / name).read_bytes()) == hashes[name], 'archive_copy_hash_mismatch')
            records.append({'generation': generation['generation'], 'binding': generation['binding'],
                'config_sha256': generation['config_sha256'], 'config_path': str(directory / 'producer.conf'),
                'original_audit_path': str(self.writer_root / 'reader/audit.json'),
                'original_access_path': str(self.writer_root / 'reader/access.json'),
                'writer_audit_path': generation['container_directory'] + '/audit.json',
                'writer_access_path': generation['container_directory'] + '/access.json',
                'archive_audit_path': str(directory / 'audit.json'), 'archive_access_path': str(directory / 'access.json'),
                'audit_sha256': hashes['audit.json'], 'access_sha256': hashes['access.json'],
                'expected_request_ids': generation['expected']})
            sync_dir(directory)
        manifest = {'schema_version': 1, 'evidence_root': str(evidence), 'instance_id': CID,
            'sensor': 'groot-sec', 'generations': records, 'live_source_paths_currently_present': False,
            'purpose': 'root_verified_private_generation_replay_not_live_binding_issuance_or_realtime_pair_join'}
        write_new(evidence / 'manifest.json', encode(manifest), 0o400); sync_dir(evidence)
        # Reader metadata includes synthetic IDs/hashes only. It stays on A too.
        for path in (self.stage / 'observed').glob('*.jsonl'):
            write_new(evidence / path.name, bounded(path), 0o400)
        self.result['evidence'] = {'manifest_path': str(evidence / 'manifest.json'),
            'manifest_sha256': sha((evidence / 'manifest.json').read_bytes()), 'generations': len(records),
            'request_counts': [len(g['expected']) for g in self.generations], 'immutable_raw_preserved_on_A': True}
        self.save()

    def execute(self):
        self.phase('first_generation_and_private_readers')
        g1 = self.write_generation(1)
        self.alias('audit', g1); self.alias('access', g1); self.alias('audit', g1, 'naive')
        self.start_readers(initial=True); self.start_writer(g1)
        self.request('first_normal'); self.wait_generation(g1)
        self.wait(lambda: self.reader_exact(g1, lane='naive_wazuh', kind='audit'), 'naive_initial_marker')
        self.phase('old_request_accepted_then_new_path_reload')
        self.request('late_old', pending=True)
        g2 = self.write_generation(2); self.reload_writer(g2)
        need(self.pending_worker.live() and all(count_fd(self.pending_worker, g1['directory'] / name, True) > 0
             for name in ('audit.json', 'access.json')), 'old_request_writer_closed_before_completion')
        need(self.raw_counts(g1) == self.pending_counts, 'pending_request_completed_before_release')
        self.alias('audit', g2, 'naive')
        self.wait(lambda: count_fd(self.naive, self.writer_root / 'naive/audit.json') == 1, 'naive_switched_fd_missing')
        self.request('new_generation')
        self.wait(lambda: self.reader_exact(g2, lane='naive_wazuh', kind='audit'), 'naive_new_generation_marker')
        self.pending.sendall(b'B'); self.finish_request(self.pending, 'late_old', g1); self.pending = None
        self.wait(lambda: self.writer_closed(g1), 'old_delayed_writer_fd_not_closed')
        self.wait_generation(g1)
        naive_rows = self.observed('naive_wazuh')
        late = g1['binding'] + '-' + g1['expected'][-1]
        need(all(r['identity'] != late for r in naive_rows), 'naive_control_did_not_demonstrate_late_loss')
        self.result['naive_control'] = {'late_old_row_absent_after_early_switch': True,
            'new_inode_open_before_old_completion': True, 'received_rows': len(naive_rows)}
        self.stop_child(self.naive_proc, self.naive); self.naive_proc = self.naive = None
        self.publish(g2); self.wait_generation(g2)
        self.phase('two_rotations_while_two_good_readers_paused')
        self.vector.send(signal.SIGSTOP); self.vector_stopped = True; self.wazuh.send(signal.SIGSTOP)
        g3 = self.write_generation(3); self.reload_writer(g3); self.request('intermediate_generation')
        self.wait(lambda: self.writer_closed(g2), 'generation_two_writer_not_closed')
        g4 = self.write_generation(4); self.reload_writer(g4); self.request('last_generation')
        self.wait(lambda: self.writer_closed(g3), 'generation_three_writer_not_closed')
        self.vector.send(signal.SIGCONT); self.vector_stopped = False; self.wazuh.send(signal.SIGCONT)
        self.phase('adjacent_generation_catchup')
        self.publish(g3); self.wait_generation(g3); self.publish(g4); self.wait_generation(g4)
        self.phase('graceful_reader_restart')
        self.wait_eof(g4); self.stop_readers(graceful=True); self.start_readers()
        self.request('after_reader_restart'); self.wait_generation(g4); self.wait_eof(g4)
        self.phase('final_exact_raw_and_reader_comparison')
        need([len(g['expected']) for g in self.generations] == [2, 1, 1, 2], 'six_request_generation_distribution')
        for generation in self.generations:
            wanted = sorted(generation['binding'] + '-' + item for item in generation['expected'])
            for kind in ('audit', 'access'):
                need(sorted(r['identity'] for r in self.raw_rows(generation, kind)) == wanted, 'raw_not_exact_http_response_ids')
        for lane, kind in (('vector_audit', 'audit'), ('vector_access', 'access'), ('wazuh_audit', 'audit')):
            actual = self.observed(lane)
            expected = [{'identity': r['identity'], 'raw_sha256': r['wazuh_serialized_sha256' if 'wazuh' in lane else 'raw_sha256']}
                        for g in self.generations for r in self.raw_rows(g, kind)]
            need(len(actual) == len(expected) == 6 and sorted(actual, key=lambda x:x['identity']) == sorted(expected, key=lambda x:x['identity']), 'final_reader_exact_comparison_' + lane)
        self.stop_writer()
        need(all(self.writer_closed(g) for g in self.generations), 'final_writer_fd_remains')
        self.stop_readers(); self.preserve()
        self.result['verification'] = {'raw_audit_records': 6, 'raw_access_records': 6,
            'vector_audit_exact_records': 6, 'vector_access_exact_records': 6, 'wazuh_audit_exact_records': 6,
            'all_http_response_and_reader_request_ids_equal': True,
            'vector_original_message_sha256_equal': True, 'wazuh_native_serialized_message_sha256_equal': True, 'duplicates': 0,
            'two_pending_generations_in_order': True, 'graceful_reader_restart': True,
            'old_audit_and_access_write_fds_zero': True, 'generation_bindings_distinct': len({g['binding'] for g in self.generations}) == 4}
        self.result['operating_after'] = verify_operating(self.before)
        self.result['status'] = 'passed'; self.result['phase'] = 'verified'; self.save()

    def cleanup(self):
        errors = []
        if self.stage is None or self.writer_root is None:
            self.result['cleanup'] = {'errors': [], 'construction_failed_before_writer_spawn': True,
                'private_runtime_paths_removed': False}
            if self.stage and self.stage.exists():
                shutil.rmtree(self.stage)
            self.result['cleanup']['private_runtime_paths_removed'] = not self.stage or not self.stage.exists()
            self.save(); return
        if self.pending:
            try:
                self.pending.close(); self.pending = None
            except OSError:
                pass
        try:
            self.stop_readers()
        except BaseException as error:
            errors.append('readers:' + type(error).__name__)
        try:
            self.stop_writer()
        except BaseException as error:
            errors.append('writer:' + type(error).__name__)
        errors.extend(self.stop_registered())
        for handle in self.handles:
            handle.close()
        for identity in self.writer_ids.values():
            if identity.live():
                errors.append('live_private_writer')
            identity.close()
        # Preserve failure diagnostics/raw on A, never print them or erase evidence.
        if self.result['status'] != 'passed' and not (self.output / 'evidence').exists() and not errors:
            try:
                self.preserve()
            except BaseException as error:
                errors.append('evidence:' + type(error).__name__)
        diagnostics = self.output / 'diagnostics'
        diagnostics.mkdir(mode=0o700, exist_ok=True)
        for name, path in (
                ('vector.toml', self.stage / 'vector.toml'),
                ('vector.log', self.stage / 'vector.log'),
                ('wazuh.log', self.stage / 'wazuh/stderr'),
                ('naive-wazuh.log', self.stage / 'naive-wazuh/stderr'),
                ('nginx.log', self.writer_root / 'nginx-error.log'),
                ('nginx-initial.log', self.writer_root / 'initial-error.log'),
                ('nginx-stdout.log', self.writer_root / 'stdout.log')):
            if path.exists():
                try:
                    write_new(diagnostics / name, bounded(path), 0o400)
                except BaseException as error:
                    errors.append('diagnostic:' + type(error).__name__)
        for name, directory in (('wazuh-file-status.json', 'wazuh'),
                                ('naive-wazuh-file-status.json', 'naive-wazuh')):
            path = self.stage / directory / 'queue/logcollector/file_status.json'
            if path.exists():
                try:
                    write_new(diagnostics / name, encode(file_status_metadata(path)), 0o400)
                except BaseException as error:
                    errors.append('status_diagnostic:' + type(error).__name__)
        sync_dir(diagnostics)
        if not errors:
            shutil.rmtree(self.writer_root); shutil.rmtree(self.stage)
        self.result['cleanup'] = {'errors': errors, 'private_runtime_paths_removed': not self.writer_root.exists() and not self.stage.exists(),
                                  'test_writer_processes_remaining': sum(i.live() for i in self.writer_ids.values())}
        if errors:
            self.result['status'] = 'failed'
        self.save()


def inner(output):
    global COMMAND_DIAGNOSTICS
    COMMAND_DIAGNOSTICS = output / 'command-diagnostics'
    def interrupted(_signal, _frame):
        raise Refused('supervisor_requested_cleanup')
    signal.signal(signal.SIGTERM, interrupted)
    probe = None
    try:
        probe = Probe.__new__(Probe)
        probe.__init__(output); probe.execute()
    except BaseException as error:
        if probe is None:
            atomic(output / 'result.json', {'status': 'failed', 'phase': 'construction', 'error_type': type(error).__name__,
                                          'failure_code': str(error) if isinstance(error, Refused) else 'construction_error',
                                          'failure_frames': failure_frames(error), 'cleanup_verified': False})
        else:
            probe.result['status'] = 'failed'; probe.result['failure_code'] = str(error) if isinstance(error, Refused) else type(error).__name__
            probe.result['failure_frames'] = failure_frames(error)
            probe.save()
    finally:
        if probe:
            probe.cleanup()
    value = json.loads((output / 'result.json').read_bytes())
    return 0 if value['status'] == 'passed' else 1


def emergency_cleanup(output, inner_identity):
    # Last-resort recovery after TERM/finally did not finish. Do not delete files.
    # Registry is written by this root-only invocation, never by a log producer.
    path = output / 'runtime-processes.json'
    report = {'attempted': True, 'runtime_paths_deleted': False, 'signaled': [], 'errors': []}
    candidates = {}
    fixture_ns = None
    if path.exists():
        state = json.loads(bounded(path))
        fixture_ns = state.get('fixture_netns')
        need(isinstance(fixture_ns, str) and fixture_ns.startswith('net:[')
             and fixture_ns != os.readlink('/proc/self/ns/net'), 'recovery_namespace_not_private')
        rows = state.get('rows', [])
        need(isinstance(rows, list) and len(rows) <= 32, 'recovery_registry_limit')
        private_namespaces = {fixture_ns}
        for row in rows:
            if type(row.get('pid')) is int and type(row.get('start_ticks')) is int:
                candidates[row['pid']] = row['start_ticks']
                info = proc_info(row['pid'])
                if info and info['start_ticks'] == row['start_ticks']:
                    current_ns = os.readlink(f'/proc/{row["pid"]}/ns/net')
                    need(current_ns != os.readlink('/proc/self/ns/net'), 'recovery_child_not_private')
                    private_namespaces.add(current_ns)
        processes = list(Path('/proc').glob('[0-9]*/ns/net'))
        need(len(processes) <= 8192, 'recovery_process_scan_limit')
        # Includes new/private workers whose parent failed before its next save.
        for ns in processes:
            try:
                if os.readlink(ns) in private_namespaces:
                    pid = int(ns.parts[2]); info = proc_info(pid)
                    if info:
                        candidates[pid] = info['start_ticks']
            except FileNotFoundError:
                continue
    candidates[inner_identity.pid] = inner_identity.start
    need(len(candidates) <= 40, 'recovery_owned_process_limit')
    for pid, start in candidates.items():
        info = proc_info(pid)
        if not info or info['start_ticks'] != start or info['state'] == 'Z':
            continue
        identity = None
        try:
            identity = Identity(pid)
            need(identity.start == start and identity.netns != os.readlink('/proc/self/ns/net'),
                 'recovery_identity_or_namespace_mismatch')
            identity.send(signal.SIGCONT); identity.send(signal.SIGKILL)
            report['signaled'].append({'pid': pid, 'start_ticks': start})
        except FileNotFoundError:
            pass
        except BaseException as error:
            report['errors'].append(type(error).__name__)
        finally:
            if identity:
                identity.close()
    time.sleep(0.2)
    report['remaining_live_known_processes'] = sum(bool((info := proc_info(pid)) and
        info['start_ticks'] == start and info['state'] != 'Z') for pid, start in candidates.items())
    atomic(output / 'timeout-recovery.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(); output = args.output
    need(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'wrong_host_or_uid')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); os.umask(0o077)
    need(re.fullmatch('/var/tmp/capstone-sequential-20261014/step1/run-[A-Za-z0-9_-]{1,48}', str(output)), 'output_not_task_scope')
    if args.inside:
        return inner(output)
    need(not output.exists() and not output.is_symlink(), 'one_shot_output_already_exists')
    st = output.parent.lstat(); need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o077 == 0, 'unsafe_output_parent')
    output.mkdir(mode=0o700)
    # Retain the exact helper/driver used; no recovery or automatic rerun.
    source = output / 'source'; source.mkdir(mode=0o700)
    for path in (Path(__file__), ROOT / 'wazuh-isolated.sh'):
        write_new(source / path.name, path.read_bytes(), 0o400)
    log = (output / 'supervisor.log').open('wb')
    def supervisor_file_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * MAX_BYTES, 8 * MAX_BYTES))
    child = subprocess.Popen(['unshare', '--net', '--', sys.executable, '-B', str(Path(__file__).resolve()),
                              '--inside', '--output', str(output)], stdout=log, stderr=log, start_new_session=True, preexec_fn=supervisor_file_limit)
    ident = Identity(child.pid)
    try:
        # Installed default reader scans/status writes can each wait ~64 s.
        # Four EOF gates, three inode handoffs, bootstrap and restart already
        # approached the old 600 s ceiling. Keep a finite 900 s whole-test bound.
        child.wait(timeout=900)
    except subprocess.TimeoutExpired:
        # Ask the inner handler to enter finally while all child pidfds exist.
        if ident.live():
            ident.send(signal.SIGTERM)
        try:
            child.wait(timeout=45)
        except subprocess.TimeoutExpired:
            emergency_cleanup(output, ident)
            child.wait(timeout=5)
            raise Refused('supervisor_timeout_runtime_files_preserved_for_review')
    finally:
        log.close(); ident.close()
    result = json.loads((output / 'result.json').read_bytes())
    # Only numeric/boolean diagnostic summary crosses SSH/Mac. Synthetic raw/IDs remain on A.
    print(json.dumps({'status': result['status'], 'phase': result.get('phase'),
        'failure_code': result.get('failure_code'), 'verification': result.get('verification'),
        'cleanup': result.get('cleanup'), 'result_path': str(output / 'result.json'),
        'manifest_path': result.get('evidence', {}).get('manifest_path')}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refused as error:
        print(json.dumps({'status': 'refused', 'failure_code': str(error)})); raise SystemExit(1)
