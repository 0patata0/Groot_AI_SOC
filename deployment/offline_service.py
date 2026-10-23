#!/usr/bin/env python3
"""Schema 9 service preflight, fixed gateway render and read-only verification.

No image build/download, lab start/stop, package installation or shell evaluation.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.parse
import urllib.request

IDS = {'CVE-2021-44228', 'CVE-2021-41773', 'CVE-2021-42013', 'CVE-2021-3156',
       'CVE-2022-0543', 'CVE-2017-7494'}
TERMINAL = {'CVE-2022-0543': 'Ubuntu focal Redis 5:5.0.7-2', 'CVE-2017-7494': 'Samba 4.6.3',
            'CVE-2021-3156': 'Ubuntu focal sudo 1.8.31-1ubuntu1'}
WEB = {'CVE-2021-44228': (18081, 8080, '/log4shell/', '2.14.1'),
       'CVE-2021-41773': (18082, 8080, '/', '2.4.49'),
       'CVE-2021-42013': (18083, 8080, '/', '2.4.50')}
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
TMPFS = {'/tmp': 'rw,nosuid,nodev,noexec,size=32m,mode=1777'}
RUNTIME_REQUIRED = {'app.py', 'broker.py', 'guard.py', 'manifest.py', 'practice_mode.py', 'challenge.py',
                    'terminal_api.py', 'static/index.html', 'static/app.js', 'static/style.css',
                    'static/theme.js', 'static/theme.css', 'static/favicon.svg', 'static/favicon.png',
                    'static/favicon.ico', 'static/lab-console-icon.ico', 'static/apple-touch-icon.png', 'static/terminal.html',
                    'static/terminal.js', 'static/terminal.css', 'static/terminal-vendor/xterm.js',
                    'static/terminal-vendor/xterm.css', 'static/terminal-vendor/addon-fit.js',
                    'static/terminal-vendor/xterm.LICENSE', 'static/terminal-vendor/addon-fit.LICENSE',
                    'static/terminal-vendor/provenance.json'}
NONWEB_REQUIRED = {'lab.sh', 'compose.yaml', 'runtime.py', 'bootstrap.py', 'publish.py', 'README.md',
                   'terminal_server.py', 'terminal.service', 'sudo_terminal.py'}


class Refused(RuntimeError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def unique(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, 'duplicate_json_key')
        out[key] = value
    return out


def trusted(path, directory=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute_trusted_path_required')
    for part in reversed((path,) + tuple(path.parents)):
        meta = part.lstat()
        need(meta.st_uid == 0 and not meta.st_mode & 0o022 and not stat.S_ISLNK(meta.st_mode), 'untrusted_path')
        need(stat.S_ISDIR(meta.st_mode) if part != path or directory else
             stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1, 'unsafe_file_type')
    return path


def origin(value):
    url = urllib.parse.urlsplit(value)
    need(url.scheme == 'https' and url.hostname and not url.username and not url.password
         and not url.path and not url.query and not url.fragment and
         re.fullmatch(r'[a-z0-9.-]+(?::[1-9][0-9]{0,4})?', url.netloc), 'https_origin_required')
    need(url.port is None or 1 <= url.port <= 65535, 'invalid_origin_port')
    need('.' in url.hostname and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                                    for x in url.hostname.split('.')), 'invalid_origin_host')
    return url.netloc


def settings(env=os.environ):
    data = {key: env[key] for key in ('CAPSTONE_SOURCE', 'SECURITY_HOST', 'SERVICE_HOST',
                                     'LAB_MANIFEST', 'LAB_PUBLIC_ORIGIN', 'LAB_GATEWAY_PORT', 'GATEWAY_ID')}
    for key in ('SECURITY_HOST', 'SERVICE_HOST'):
        address = ipaddress.IPv4Address(data[key])
        need(not address.is_loopback and not address.is_unspecified and not address.is_multicast,
             'usable_ipv4_required')
    need(data['SECURITY_HOST'] != data['SERVICE_HOST'], 'distinct_hosts_required')
    need(re.fullmatch(r'[1-9][0-9]{3,4}', data['LAB_GATEWAY_PORT']), 'invalid_gateway_port')
    port = int(data['LAB_GATEWAY_PORT'])
    need(1024 <= port <= 65535 and port not in (1514, 1515, 18081, 18082, 18083, 18090)
         and port != int(env.get('WEB_BACKEND_PORT', '80')), 'reserved_gateway_port')
    need(IMAGE.fullmatch(data['GATEWAY_ID']), 'pinned_gateway_required')
    data['host'] = origin(data['LAB_PUBLIC_ORIGIN'])
    return data


def catalog(source, path):
    # This is the reviewed shared validator, never a module selected by a request.
    sys.path.insert(0, str(Path(source) / 'infra/groot-c/offline-labs'))
    from manifest import load_manifest
    labs = load_manifest(path, require_root=True)
    need(len(labs) == 6 and {x['cve_id'] for x in labs} == IDS, 'exact_six_lab_catalog_required')
    for item in labs:
        if item['cve_id'] in WEB:
            expected = WEB[item['cve_id']]
            need(item['type'] == 'managed-http' and
                 tuple(item[x] for x in ('host_port', 'container_port', 'path', 'vulnerable_version')) == expected,
                 'fixed_web_lab_contract_required')
        elif item['cve_id'] in TERMINAL:
            need(item['type'] == 'managed-terminal' and item['vulnerable_version'] == TERMINAL[item['cve_id']],
                 'fixed_terminal_lab_contract_required')
        else:
            raise Refused('unsupported_lab_contract')
    return labs


def run(args):
    result = subprocess.run(args, capture_output=True, timeout=40,
                            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C'})
    need(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024, 'local_command_failed')
    return result.stdout


def docker_args():
    path = os.environ.get('DOCKER', '/usr/bin/docker')
    need(path in ('/usr/bin/docker', '/usr/local/bin/docker'), 'trusted_docker_required')
    trusted(path)
    return [path, '--host', 'unix:///var/run/docker.sock']


def image_check(docker, ref, expected):
    values = json.loads(run(docker + ['image', 'inspect', ref]), object_pairs_hook=unique)
    need(isinstance(values, list) and len(values) == 1, 'image_inspect_invalid')
    value = values[0]
    need(value.get('Id') == expected and value.get('Os') == 'linux' and
         value.get('Architecture') == 'amd64' and not value.get('Config', {}).get('Volumes'),
         'preloaded_image_contract_mismatch')
    return value


def source_file(path, root):
    need(path.is_file() and not path.is_symlink() and not root.is_symlink(), 'runtime_source_missing')
    parent = path.parent
    while parent != root:
        need(root in parent.parents and not parent.is_symlink(), 'runtime_source_invalid')
        parent = parent.parent


def console_source_files(source):
    root = Path(source)
    base = root / 'infra/groot-c/offline-labs'
    paths = list(base.glob('*.py'))
    for path in (base / 'static').rglob('*'):
        need(not path.is_symlink() and (path.is_file() or path.is_dir()), 'runtime_source_invalid')
        if path.is_file():
            paths.append(path)
    need(RUNTIME_REQUIRED <= {str(path.relative_to(base)) for path in paths}, 'runtime_source_missing')
    for path in paths:
        source_file(path, root)
    return paths


def source_hash(source):
    root = Path(source)
    base = root / 'infra/groot-c/offline-labs'
    files = console_source_files(source)
    for path in (base / 'scripts').rglob('*'):
        need(not path.is_symlink() and (path.is_file() or path.is_dir()), 'runtime_source_invalid')
        if path.is_file():
            files.append(path)
    files += [base / 'wheel-inventory.json', base / 'requirements.lock', root / 'deployment/offline_service.py']
    files += [root / 'infra/groot-c/nonweb-labs' / name for name in NONWEB_REQUIRED]
    files += [base / 'nonweb/sudo' / name for name in ('lab.py', 'publish.py', 'runtime/bootstrap.py')]
    result = hashlib.sha256()
    for path in sorted(files):
        source_file(path, root)
        result.update(str(path.relative_to(root)).encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return result.hexdigest()


def profile(data, labs, docker):
    for item in labs:
        if item['type'] == 'managed-http':
            image_check(docker, item['image_tag'], item['image_id'])
    image_check(docker, data['GATEWAY_ID'], data['GATEWAY_ID'])
    return {'schema': 9, 'manifest_sha256': hashlib.sha256(Path(data['LAB_MANIFEST']).read_bytes()).hexdigest(),
            'runtime_source_sha256': source_hash(data['CAPSTONE_SOURCE']),
            'gateway_image_id': data['GATEWAY_ID'], 'gateway_port': int(data['LAB_GATEWAY_PORT']),
            'origin': data['LAB_PUBLIC_ORIGIN'], 'lab_ids': sorted(IDS)}


def render(data):
    port = data['LAB_GATEWAY_PORT']
    # No inherited WAF includes, entrypoint templating, writable cache or root worker.
    result = f'''worker_processes 1;
pid /tmp/nginx.pid;
error_log stderr warn;
events {{ worker_connections 128; }}
http {{
  access_log off;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  server {{
    listen {data['SERVICE_HOST']}:{port};
    listen 127.0.0.1:{port};
    server_name _;
    allow {data['SECURITY_HOST']};
    allow 127.0.0.1;
    deny all;
    client_max_body_size 8k;
    proxy_connect_timeout 3s;
    proxy_read_timeout 75s;
    proxy_set_header Host {data['host']};
    location / {{ return 404; }}
'''
    for path, backend in (('_offline-labs', '18090/'), ('_offline-lab-java', '18081/log4shell/'),
                          ('_offline-lab-httpd49', '18082/'), ('_offline-lab-httpd50', '18083/')):
        timeout = 'proxy_read_timeout 275s; ' if path == '_offline-labs' else ''
        result += f'    location ^~ /{path}/ {{ {timeout}proxy_pass http://127.0.0.1:{backend}; }}\n'
    return result + '  }\n}\n'


def gateway_contract(value, data, role, image):
    config, host = value['Config'], value['HostConfig']
    need(value['State']['Running'] and not value['State']['Restarting'] and value['Image'] == data['GATEWAY_ID'], 'gateway_not_running')
    need(config['Labels'].get('com.docker.compose.project') == 'capstone-service' and
         config['Labels'].get('com.docker.compose.service') == 'gateway', 'gateway_owner_mismatch')
    need(config['User'] == '65532:65532' and config['Entrypoint'] == ['nginx'] and
         config['Cmd'] == ['-c', '/etc/capstone-gateway.conf', '-g', 'daemon off;'] and
         config.get('Healthcheck', {}).get('Test') == ['NONE'] and config.get('WorkingDir') == '/tmp', 'gateway_command_mismatch')
    need(host['ReadonlyRootfs'] and not host['Privileged'] and host['NetworkMode'] == 'host' and
         host['CapDrop'] == ['ALL'] and not host.get('CapAdd') and host['Memory'] == 134217728 and
         host['NanoCpus'] == 500000000 and host['PidsLimit'] == 64 and host['Tmpfs'] == TMPFS and
         not host.get('PortBindings') and host['RestartPolicy']['Name'] == 'unless-stopped' and
         host['SecurityOpt'] in (['no-new-privileges:true'], ['no-new-privileges']) and
         not host.get('Devices') and not host.get('PidMode') and
         host.get('IpcMode') == 'private', 'gateway_isolation_mismatch')
    need(host.get('LogConfig') == {'Type': 'json-file', 'Config': {'max-size': '10m', 'max-file': '3'}}, 'gateway_logs_mismatch')
    mounts = [{key: m[key] for key in ('Type', 'Source', 'Destination', 'RW')}
              for m in value['Mounts'] if m['Type'] != 'tmpfs']
    need(mounts == [{'Type': 'bind', 'Source': str(Path(role) / 'config/gateway.conf'),
                     'Destination': '/etc/capstone-gateway.conf', 'RW': False}] and
         all(m['Type'] != 'tmpfs' or m['Destination'] == '/tmp' for m in value['Mounts']), 'gateway_mount_mismatch')
    need(host.get('Binds') in (None, [], [str(Path(role) / 'config/gateway.conf') + ':/etc/capstone-gateway.conf:ro']),
         'gateway_bind_changed')
    need(config.get('Env') == image['Config'].get('Env'), 'gateway_environment_changed')
    need(set(value['NetworkSettings']['Networks']) == {'host'}, 'gateway_network_mismatch')


def http(path, data):
    request = urllib.request.Request('http://127.0.0.1:' + data['LAB_GATEWAY_PORT'] + path,
                                     headers={'Host': data['host'], 'Accept': 'application/json'})
    # Ignore controller/host proxy environment. No external request or redirect.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None
    timeout = 150 if path == '/_offline-labs/api/status' else 8
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=timeout) as response:
        need(response.status == 200, 'gateway_http_failed')
        raw = response.read(1048577)
        need(len(raw) <= 1048576, 'gateway_response_too_large')
        return raw


def key_check():
    path = trusted(os.environ['LAB_ADMIN_KEY_FILE'])
    metadata = path.stat()
    need(metadata.st_gid == 0 and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 1025,
         'private_common_key_required')
    raw = path.read_bytes().removesuffix(b'\n')
    need(8 <= len(raw.decode('utf-8')) <= 256 and len(raw) <= 1024, 'common_key_length_invalid')
    return raw


def verify_installation(data):
    state_path = trusted('/var/lib/capstone-offline-labs/install-state.json')
    meta = state_path.stat()
    need(meta.st_gid == 0 and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_size < 4 * 1024 * 1024,
         'install_receipt_permissions')
    state = json.loads(state_path.read_bytes(), object_pairs_hook=unique)
    need(state.get('schema') == 1 and state.get('status') == 'installed' and state.get('stage') == 'complete'
         and state.get('automatic_cleanup') is False, 'installation_incomplete')
    files = state.get('files')
    need(isinstance(files, dict) and 5 <= len(files) <= 20000, 'install_receipt_files_invalid')
    required = {'/etc/capstone-offline-labs/cve_list.json', '/etc/capstone-offline-labs/settings.env'}
    units = ('capstone-offline-labs', 'capstone-offline-labs-broker', 'capstone-offline-labs-guard')
    required |= {'/etc/systemd/system/' + unit + '.service' for unit in units}
    required |= {'/opt/capstone-offline-labs/' + name for name in RUNTIME_REQUIRED}
    need(required <= files.keys(), 'install_receipt_missing_file')
    for name, info in files.items():
        need(name.startswith('/opt/capstone-offline-labs/') or name in required, 'install_receipt_path_outside_scope')
        need(set(info) == {'sha256', 'mode', 'uid', 'gid'} and info['uid'] == 0 and
             re.fullmatch('[0-9a-f]{64}', info['sha256']), 'install_receipt_metadata_invalid')
        path = trusted(name)
        current = path.stat()
        need(current.st_uid == info['uid'] and current.st_gid == info['gid'] and
             format(stat.S_IMODE(current.st_mode), '04o') == info['mode'] and
             hashlib.sha256(path.read_bytes()).hexdigest() == info['sha256'], 'installed_file_changed')
    source = Path(data['CAPSTONE_SOURCE']) / 'infra/groot-c/offline-labs'
    for path in console_source_files(data['CAPSTONE_SOURCE']):
        name = str(Path('/opt/capstone-offline-labs') / path.relative_to(source))
        need(name in files and hashlib.sha256(path.read_bytes()).hexdigest() == files[name]['sha256'],
             'installed_source_different')
    key = state.get('key_file')
    need(isinstance(key, dict) and key.get('path') == '/etc/capstone-offline-labs/admin-token'
         and key.get('mode') == '0640' and key.get('uid') == 0, 'installed_key_metadata_invalid')
    target = trusted(key['path']); metadata = target.stat()
    need(metadata.st_uid == 0 and metadata.st_gid == key['gid'] and stat.S_IMODE(metadata.st_mode) == 0o640,
         'installed_key_permissions')
    need(target.stat().st_size <= 1025 and key_check() == target.read_bytes().removesuffix(b'\n'), 'common_key_changed')
    for unit in units:
        need(run(['systemctl', 'show', '-p', 'DropInPaths', '--value', unit]).strip() == b'', 'unexpected_service_override')
        need(run(['systemctl', 'show', '-p', 'FragmentPath', '--value', unit]).strip().decode() ==
             '/etc/systemd/system/' + unit + '.service', 'unexpected_service_source')


def verify(data, labs, docker):
    verify_installation(data)
    run(['/usr/bin/python3', '-B', '/opt/capstone-offline-labs/guard.py', 'check'])
    for unit in ('capstone-offline-labs', 'capstone-offline-labs-broker', 'capstone-offline-labs-guard'):
        run(['systemctl', 'is-active', '--quiet', unit])
        run(['systemctl', 'is-enabled', '--quiet', unit])
    installed = catalog(data['CAPSTONE_SOURCE'], '/etc/capstone-offline-labs/cve_list.json')
    need(installed == labs, 'installed_catalog_changed')
    actual = json.loads(http('/_offline-labs/api/list', data))
    need(actual == json.loads(Path(data['LAB_MANIFEST']).read_bytes()), 'served_catalog_changed')
    status = json.loads(http('/_offline-labs/api/status', data))
    need(status.get('deployment_allowed') is True and len(status.get('labs', [])) == 6 and
         {x.get('cve_id') for x in status['labs']} == IDS, 'broker_status_unverified')
    for item in status['labs']:
        if item['cve_id'] in WEB:
            need(item.get('image_present') is True and item.get('status') in ('running', 'stopped', 'not_deployed'), 'web_lab_unverified')
        elif item['cve_id'] in TERMINAL:
            need(item.get('type') == 'managed-terminal' and item.get('image_present') is True
                 and item.get('deployment_allowed') is True
                 and item.get('status') in ('running', 'stopped', 'not_deployed')
                 and item.get('verification') == 'environment_only'
                 and item.get('attack_tested') is False, 'terminal_lab_unverified')
    base = Path(data['CAPSTONE_SOURCE']) / 'infra/groot-c/offline-labs/static'
    for name in ('theme.js', 'theme.css', 'favicon.svg', 'favicon.png', 'favicon.ico', 'lab-console-icon.ico', 'apple-touch-icon.png', 'terminal.html', 'terminal.js', 'terminal.css',
                 'terminal-vendor/xterm.js', 'terminal-vendor/xterm.css', 'terminal-vendor/addon-fit.js'):
        need(http('/_offline-labs/static/' + name, data) == (base / name).read_bytes(), 'theme_asset_changed')
    return {'schema': 9, 'status': 'verified', 'catalog_items': 6, 'managed_web_labs': 3,
            'managed_terminal_labs': 3, 'labs_started': 0}


def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ('profile', 'render', 'gateway-contract', 'verify', 'key-check'), 'invalid_action')
    data = settings()
    if sys.argv[1] == 'render':
        print(render(data), end='')
        return
    need(os.geteuid() == 0, 'root_required')
    if sys.argv[1] == 'key-check':
        key_check()
        print('{"status":"key_precondition_verified"}')
        return
    docker = docker_args()
    labs = catalog(data['CAPSTONE_SOURCE'], data['LAB_MANIFEST'])
    if sys.argv[1] == 'profile':
        result = profile(data, labs, docker)
    elif sys.argv[1] == 'gateway-contract':
        raw = sys.stdin.buffer.read(262145)
        need(len(raw) <= 262144, 'gateway_inspect_too_large')
        gateway_contract(json.loads(raw, object_pairs_hook=unique), data, os.environ['ROLE'],
                         image_check(docker, data['GATEWAY_ID'], data['GATEWAY_ID']))
        result = {'status': 'verified'}
    else:
        result = verify(data, labs, docker)
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('{"error":"offline_service_validation_failed"}', file=sys.stderr)
        sys.exit(1)
