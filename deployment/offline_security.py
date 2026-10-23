#!/usr/bin/env python3
"""Fresh security role TLS/WAF rendering and fixed runtime verification.

No downloads, rule updates, attack execution, or modifications to existing roles.
Only the explicit render/native actions write within a newly created role.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from validate_lab_site import validate

SOURCES = ('nginx-log4shell-server.conf', 'waf-log4shell-server.conf', 'REQUEST-900-CAPSTONE-LABS.conf')
EDGE = 'capstone-security-lab-edge'
NETWORK = 'capstone-security_waf'
TMPFS = {'/tmp': 'rw,nosuid,nodev,noexec,size=32m,mode=1777'}
ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def run(args, *, data=None, timeout=30):
    value = subprocess.run(args, input=data, capture_output=True, timeout=timeout, env=ENV)
    need(value.returncode == 0 and len(value.stdout) <= 8 * 1024 * 1024, 'command_failed')
    return value.stdout


def trusted(path, *, private=False, limit=2 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute_path_required')
    source = Path(os.environ.get('CAPSTONE_SOURCE', '/nonexistent'))
    staged = re.fullmatch(r'/var/tmp/capstone-bootstrap-[a-f0-9]{24}/source', str(source)) and path.is_relative_to(source)
    for parent in path.parents:
        info = parent.lstat()
        anchor = staged and str(parent) == '/var/tmp' and stat.S_IMODE(info.st_mode) == 0o1777
        audit_parent = (not private and path == Path('/opt/capstone/security/logs/modsecurity/capstone-managed/audit-path.conf')
                        and parent == Path('/opt/capstone/security/logs/modsecurity')
                        and info.st_uid == 101 and info.st_gid == 101 and stat.S_IMODE(info.st_mode) == 0o755)
        need(stat.S_ISDIR(info.st_mode) and (info.st_uid == 0 or audit_parent)
             and (anchor or not info.st_mode & 0o022), 'untrusted_parent')
        if staged and parent == source.parent:
            need(stat.S_IMODE(info.st_mode) == 0o700, 'untrusted_stage')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
         and not info.st_mode & 0o022 and 0 < info.st_size <= limit, 'untrusted_file')
    if private:
        need(info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 16384, 'private_key_permissions')
    return path


def docker():
    value = shutil.which('docker', path=ENV['PATH'])
    need(value in ('/usr/bin/docker', '/usr/local/bin/docker'), 'local_docker_path_required')
    trusted(Path(value).resolve(), limit=128 * 1024 * 1024)
    return [value, '--host', 'unix:///var/run/docker.sock']


def settings(env=os.environ):
    result = validate(*(env[key] for key in ('LAB_PUBLIC_ORIGIN', 'LAB_HTTPS_PORT', 'LAB_ALLOWED_CIDRS', 'LAB_PROXY_SUBNET')))
    for key in ('SERVICE_HOST', 'SECURITY_HOST'):
        address = ipaddress.IPv4Address(env[key])
        need(not address.is_loopback and not address.is_unspecified and not address.is_multicast, 'usable_host_required')
        need(address not in ipaddress.ip_network(result['subnet']), 'host_overlaps_proxy_network')
        result[key] = str(address)
    need(result['SERVICE_HOST'] != result['SECURITY_HOST'], 'distinct_hosts_required')
    result['gateway_port'] = int(env['LAB_GATEWAY_PORT'])
    need(1024 <= result['gateway_port'] <= 65535, 'gateway_port_invalid')
    need(result['port'] not in (22, 1514, 1515, int(env['WAF_PORT'])), 'tls_port_reserved')
    result['backend'] = result['SERVICE_HOST'] + ':' + str(result['gateway_port'])
    result['source'] = Path(env['CAPSTONE_SOURCE'])
    result['role'] = Path(env['ROLE_DIR'])
    result['cert'] = Path(env['LAB_TLS_CERT'])
    result['key'] = Path(env['LAB_TLS_KEY'])
    result['image'] = env['WAF_ID']
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', result['image']), 'immutable_image_required')
    return result


def certificate(data):
    cert, key = trusted(data['cert']), trusted(data['key'], private=True)
    run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '86400'])
    san = run(['openssl', 'x509', '-in', str(cert), '-noout', '-ext', 'subjectAltName'])
    need(b'DNS:' in san, 'certificate_dns_san_required')
    matched = run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkhost', data['hostname']])
    need(matched.decode().strip() == 'Hostname ' + data['hostname'] + ' does match certificate', 'certificate_hostname_mismatch')
    public = run(['openssl', 'x509', '-in', str(cert), '-noout', '-pubkey'])
    private_public = run(['openssl', 'pkey', '-in', str(key), '-passin', 'pass:', '-pubout'])
    need(public == private_public, 'certificate_key_mismatch')
    return {'certificate_sha256': hashlib.sha256(cert.read_bytes()).hexdigest(),
            'public_key_sha256': hashlib.sha256(public).hexdigest()}


def source_files(data):
    base = data['source'] / 'infra/groot-c/offline-labs'
    result = {name: trusted(base / name).read_text() for name in SOURCES}
    for name in ('deployment/offline_security.py', 'deployment/validate_lab_site.py'):
        result[name] = trusted(data['source'] / name).read_text()
    return result


def identity(data, sources, tls):
    public = {key: data[key] for key in ('origin', 'hostname', 'authority', 'port', 'allowed', 'subnet', 'waf_ip', 'edge_ip', 'backend', 'image')}
    public.update(tls)
    public['sources'] = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in sources.items()}
    return hashlib.sha256(json.dumps(public, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def conflicts(data, command, existing=False):
    wanted = ipaddress.ip_network(data['subnet'])
    ignored = set()
    ids = run(command + ['network', 'ls', '-q', '--no-trunc']).decode().splitlines()
    for nid in ids:
        network = json.loads(run(command + ['network', 'inspect', nid]))[0]
        owned = existing and network['Name'] == NETWORK
        for entry in network.get('IPAM', {}).get('Config', []):
            value = entry.get('Subnet')
            if value:
                subnet = ipaddress.ip_network(value)
                if subnet.version == 4 and wanted.overlaps(subnet):
                    need(owned and subnet == wanted and network.get('Labels', {}).get('com.docker.compose.project') == 'capstone-security', 'docker_subnet_conflict')
                    ignored.add(network.get('Options', {}).get('com.docker.network.bridge.name', 'br-' + nid[:12]))
    for interface in json.loads(run(['ip', '-j', 'address', 'show'])):
        for address in interface.get('addr_info', []):
            if address.get('family') == 'inet':
                actual = ipaddress.ip_network(address['local'] + '/' + str(address['prefixlen']), strict=False)
                need(not actual.overlaps(wanted) or interface['ifname'] in ignored, 'interface_subnet_conflict')
    for route in json.loads(run(['ip', '-j', 'route', 'show', 'table', 'all'])):
        destination = route.get('dst', 'default')
        if destination == 'default':
            continue
        actual = ipaddress.ip_network(destination, strict=False)
        if actual.version == 4:
            need(not actual.overlaps(wanted) or route.get('dev') in ignored, 'route_subnet_conflict')
    if not existing:
        for filename in ('/proc/net/tcp', '/proc/net/tcp6'):
            for line in Path(filename).read_text().splitlines()[1:]:
                fields = line.split()
                need(not (fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == data['port']), 'tls_port_occupied')
        ids = run(command + ['container', 'ls', '-aq', '--no-trunc']).decode().splitlines()
        for cid in ids:
            info = json.loads(run(command + ['inspect', '--format', '{"name":{{json .Name}},"ports":{{json .HostConfig.PortBindings}}}', cid]))
            need(info['name'] not in ('/' + EDGE, '/capstone-security-edgecheck', '/capstone-security-wafcheck'), 'edge_name_conflict')
            for rows in (info['ports'] or {}).values():
                need(not any(int(row['HostPort']) == data['port'] for row in rows or []), 'tls_publish_conflict')


def image_check(data, command):
    images = json.loads(run(command + ['image', 'inspect', data['image']]))
    need(len(images) == 1 and images[0]['Id'] == data['image'] and images[0].get('Os') == 'linux'
         and images[0].get('Architecture') == 'amd64' and not images[0].get('Config', {}).get('Volumes'),
         'preloaded_image_contract_mismatch')
    return images[0]


def render(data, sources):
    edge = sources[SOURCES[0]]
    waf = sources[SOURCES[1]]
    policy = sources[SOURCES[2]]
    old = 'log4shell.grootlab.duckdns.org'
    edge = edge.replace('https://' + old, data['origin']).replace(old, data['authority'])
    edge = edge.replace('server_name ' + data['authority'] + ';', 'server_name ' + data['hostname'] + ';\n        if ($http_host != "' + data['authority'] + '") { return 421; }')
    edge = edge.replace('/etc/nginx/tls/chatduck.crt', '/etc/capstone-tls/lab.crt').replace('/etc/nginx/tls/chatduck.key', '/etc/capstone-tls/lab.key')
    edge, count = re.subn(r'(?:        allow [^;]+;\n)+        deny all;', ''.join('        allow ' + net + ';\n' for net in data['allowed']) + '        deny all;', edge)
    need(count == 1, 'edge_acl_template_changed')
    edge = edge.replace('10.200.10.20:80', data['backend']).replace('192.168.16.230:80', data['waf_ip'] + ':8080')
    edge = '''worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 256; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    client_body_temp_path /tmp/client;
    proxy_temp_path /tmp/proxy;
    fastcgi_temp_path /tmp/fastcgi;
    uwsgi_temp_path /tmp/uwsgi;
    scgi_temp_path /tmp/scgi;
''' + edge + '\n}\n'
    # Keep the reviewed normalized Nginx locations and Host-only ModSecurity
    # scope. Repeating raw REQUEST_URI checks would reopen normalization bypasses.
    waf = waf.replace('https://' + old, data['origin']).replace(old, data['authority'])
    waf = waf.replace('server_name ' + data['authority'] + ';', 'server_name ' + data['hostname'] + ';')
    waf = waf.replace('172.18.0.1', data['edge_ip']).replace('10.200.10.20:80', data['backend'])
    waf = re.sub(r'^.*capstone_waf_evidence;\n', '', waf, flags=re.M)
    # Comments describe the portable setup, not the previous SNAT deployment.
    waf = waf[waf.index('map $realip_remote_addr'):]
    policy = policy.replace(old, data['authority'])
    need('capstone_waf_evidence' not in waf and 'REQUEST_URI' not in '\n'.join(x for x in policy.splitlines() if not x.startswith('#')), 'fresh_waf_contract_changed')
    for text in (edge, waf, policy):
        need((data['backend'].startswith('10.200.10.20:') or '10.200.10.20' not in text)
             and '192.168.16.230' not in text and (data['authority'] == old or old not in text), 'unrendered_site_constant')
    return {'config/lab-edge.conf': edge.encode(), 'config/lab-waf.conf': waf.encode(), 'config/lab-policy.conf': policy.encode()}


def bind(source, destination):
    return {'type': 'bind', 'source': str(source), 'target': destination, 'read_only': True, 'bind': {'create_host_path': False}}


def enhance_compose(compose, data, profile):
    role = data['role']
    need(set(compose['services']) == {'waf', 'suricata'}, 'unexpected_base_services')
    compose['services']['waf']['networks'] = {'waf': {'ipv4_address': data['waf_ip']}}
    compose['services']['waf']['volumes'] += [
        bind(role / 'config/lab-waf.conf', '/etc/nginx/conf.d/zz-capstone-labs.conf'),
        bind(role / 'config/lab-policy.conf', '/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-LABS.conf')]
    compose['services']['waf']['pull_policy'] = 'never'
    compose['networks']['waf'] = {'driver': 'bridge', 'ipam': {'config': [{'subnet': data['subnet']}]}}
    compose['services']['lab-edge'] = {
        'image': data['image'], 'pull_policy': 'never', 'container_name': EDGE, 'restart': 'always',
        'user': '101:101', 'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        'entrypoint': ['nginx'], 'command': ['-c', '/etc/capstone/nginx.conf', '-g', 'daemon off;'],
        'working_dir': '/tmp', 'healthcheck': {'disable': True}, 'tmpfs': ['/tmp:' + TMPFS['/tmp']],
        'mem_limit': '128m', 'cpus': 0.5, 'pids_limit': 64,
        'labels': {'io.capstone.portable.role': 'security', 'io.capstone.portable.profile': profile},
        'ports': [data['SECURITY_HOST'] + ':' + str(data['port']) + ':8443'],
        'networks': {'waf': {'ipv4_address': data['edge_ip']}},
        'volumes': [bind(role / 'config/lab-edge.conf', '/etc/capstone/nginx.conf'), bind(role / 'tls', '/etc/capstone-tls')],
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}
    return compose


def write_config(data, sources, tls):
    need(identity(data, sources, tls) == os.environ['LAB_PROFILE'], 'preflight_inputs_changed')
    role = data['role']
    for relative, content in render(data, sources).items():
        path = role / relative
        with path.open('xb') as stream:
            stream.write(content)
        path.chmod(0o444)
    directory = role / 'tls'; directory.mkdir(mode=0o711)
    for source, target, uid, mode in ((data['cert'], 'lab.crt', 0, 0o444), (data['key'], 'lab.key', 101, 0o400)):
        path = directory / target
        with path.open('xb') as stream:
            stream.write(source.read_bytes())
        os.chown(path, uid, uid)
        path.chmod(mode)
    need(hashlib.sha256((directory / 'lab.crt').read_bytes()).hexdigest() == tls['certificate_sha256'], 'copied_certificate_changed')
    public = run(['openssl', 'pkey', '-in', str(directory / 'lab.key'), '-passin', 'pass:', '-pubout'])
    need(hashlib.sha256(public).hexdigest() == tls['public_key_sha256'], 'copied_private_key_changed')
    compose_path = role / 'compose.json'
    value = enhance_compose(json.loads(compose_path.read_text()), data, os.environ['PROFILE'])
    compose_path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    manifest_path = role / 'manifest.json'; manifest = json.loads(manifest_path.read_text())
    manifest['schema_version'] = 2
    paths = [role / name for name in render(data, sources)] + list(directory.iterdir()) + [compose_path]
    manifest['files'].update({str(path.relative_to(role)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
    for path in paths + [manifest_path]:
        with path.open('rb') as stream:
            os.fsync(stream.fileno())


def native(data, command):
    role, profile = data['role'], os.environ['PROFILE']
    compose = json.loads((role / 'compose.json').read_text())
    for service, name in (('lab-edge', 'capstone-security-edgecheck'), ('waf', 'capstone-security-wafcheck')):
        spec = compose['services'][service]
        args = command + ['create', '--pull', 'never', '--name', name, '--network', 'none', '--label', 'io.capstone.portable.labcheck=' + profile,
                          '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '256m',
                          '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=32m,mode=1777']
        if service == 'lab-edge':
            args += ['--read-only', '--user', '101:101', '--workdir', '/tmp', '--entrypoint', 'nginx']
        else:
            args += ['--tmpfs', '/var/log/modsecurity:rw,nosuid,nodev,noexec,size=32m,mode=1777']
            if (role / 'log-pipeline/receipt.json').exists():
                # The producer override includes this immutable pointer. Its
                # target is created solely inside the probe's private tmpfs;
                # never mount an operational audit stream into a syntax test.
                pointer = trusted(role / 'logs/modsecurity/capstone-managed/audit-path.conf')
                args += ['--tmpfs', '/var/log/modsecurity/capstone-managed:rw,nosuid,nodev,noexec,size=8m,mode=1777',
                         '--mount', 'type=bind,source=' + str(pointer) +
                         ',target=/var/log/modsecurity/capstone-managed/audit-path.conf,readonly']
        for key, value in spec.get('environment', {}).items():
            args += ['--env', key + '=' + str(value)]
        for mount in spec['volumes']:
            if isinstance(mount, str):
                if '/logs/' in mount:
                    continue
                args += ['--volume', mount]
            else:
                args += ['--mount', 'type=bind,source=' + mount['source'] + ',target=' + mount['target'] + ',readonly']
        args += [data['image']] + (['-t', '-c', '/etc/capstone/nginx.conf'] if service == 'lab-edge' else ['nginx', '-t'])
        cid = run(args).decode().strip()
        need(re.fullmatch('[a-f0-9]{64}', cid), 'native_container_identity_invalid')
        (role / (name + '.cid')).write_text(cid + '\n')
        try:
            with (role / (name + '.log')).open('xb') as output:
                tested = subprocess.run(command + ['start', '--attach', cid], stdout=output, stderr=output, timeout=90, env=ENV)
            info = json.loads(run(command + ['inspect', cid]))[0]
            need(tested.returncode == 0 and not info['State']['Running'] and info['State']['ExitCode'] == 0, 'private_nginx_test_failed')
        finally:
            info = json.loads(run(command + ['inspect', cid]))[0]
            need(info['Id'] == cid and info['Image'] == data['image'] and info['Config']['Labels'].get('io.capstone.portable.labcheck') == profile, 'native_cleanup_ownership_changed')
            if info['State']['Running']:
                run(command + ['kill', cid])
            run(command + ['rm', cid])


def edge_contract(info, data, image):
    config, host = info['Config'], info['HostConfig']
    need(info['State']['Running'] and not info['State']['Restarting'] and info['RestartCount'] == 0 and info['Image'] == data['image'], 'edge_not_running')
    need(config['Labels'].get('com.docker.compose.project') == 'capstone-security' and config['Labels'].get('com.docker.compose.service') == 'lab-edge'
         and config['Labels'].get('io.capstone.portable.profile') == os.environ['PROFILE'], 'edge_ownership_changed')
    need(config['User'] == '101:101' and config['Entrypoint'] == ['nginx'] and config['Cmd'] == ['-c', '/etc/capstone/nginx.conf', '-g', 'daemon off;']
         and config['WorkingDir'] == '/tmp' and config.get('Healthcheck', {}).get('Test') == ['NONE'] and config.get('Env') == image['Config'].get('Env'), 'edge_command_changed')
    need(host['ReadonlyRootfs'] and not host['Privileged'] and host['CapDrop'] == ['ALL'] and not host.get('CapAdd')
         and host['Memory'] == 134217728 and host['NanoCpus'] == 500000000 and host['PidsLimit'] == 64 and host['Tmpfs'] == TMPFS
         and host['SecurityOpt'] in (['no-new-privileges:true'], ['no-new-privileges']) and not host.get('Devices') and not host.get('PidMode')
         and host.get('IpcMode') == 'private' and host['RestartPolicy']['Name'] == 'unless-stopped', 'edge_isolation_changed')
    need(host['NetworkMode'] == NETWORK and host['PortBindings'] == {'8443/tcp': [{'HostIp': data['SECURITY_HOST'], 'HostPort': str(data['port'])}]}, 'edge_ports_changed')
    need(host.get('LogConfig') == {'Type': 'json-file', 'Config': {'max-size': '10m', 'max-file': '3'}}, 'edge_log_contract_changed')
    mounts = [{key: item[key] for key in ('Type', 'Source', 'Destination', 'RW')} for item in info['Mounts'] if item['Type'] != 'tmpfs']
    expected = [{'Type': 'bind', 'Source': str(data['role'] / path), 'Destination': target, 'RW': False}
                for path, target in (('config/lab-edge.conf', '/etc/capstone/nginx.conf'), ('tls', '/etc/capstone-tls'))]
    need(sorted(mounts, key=lambda x: x['Destination']) == sorted(expected, key=lambda x: x['Destination'])
         and all(item['Type'] != 'tmpfs' or item['Destination'] == '/tmp' for item in info['Mounts']), 'edge_mounts_changed')


def verify(data, command):
    role = data['role']
    image = image_check(data, command)
    edge = json.loads(run(command + ['inspect', EDGE]))[0]
    edge_contract(edge, data, image)
    network = json.loads(run(command + ['network', 'inspect', NETWORK]))[0]
    need(network['Driver'] == 'bridge' and not network['Internal'] and not network['EnableIPv6']
         and network['IPAM']['Config'] == [{'Subnet': data['subnet'], 'Gateway': str(ipaddress.ip_network(data['subnet']).network_address + 1)}]
         and network.get('Labels', {}).get('com.docker.compose.project') == 'capstone-security', 'proxy_network_changed')
    expected = {}
    for name, address in (('capstone-security-waf', data['waf_ip']), (EDGE, data['edge_ip'])):
        info = json.loads(run(command + ['inspect', name]))[0]
        need(set(info['NetworkSettings']['Networks']) == {NETWORK} and info['NetworkSettings']['Networks'][NETWORK]['IPAddress'] == address, 'fixed_proxy_address_changed')
        expected[info['Id']] = address + '/29'
    need({cid: row['IPv4Address'] for cid, row in network['Containers'].items()} == expected, 'unexpected_proxy_network_member')
    for filename, uid, mode in (('lab.crt', 0, 0o444), ('lab.key', 101, 0o400)):
        info = (role / 'tls' / filename).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == uid and info.st_gid == uid and stat.S_IMODE(info.st_mode) == mode, 'installed_tls_permissions_changed')
    run(command + ['exec', edge['Id'], 'nginx', '-t', '-c', '/etc/capstone/nginx.conf'])
    # Public TLS identity and management path only; no lab is automatically started.
    code = run(['curl', '--noproxy', '*', '--silent', '--show-error', '--max-time', '15', '--cacert', str(data['cert']),
                '--resolve', data['hostname'] + ':' + str(data['port']) + ':' + data['SECURITY_HOST'],
                '--output', '/dev/null', '--write-out', '%{http_code}', data['origin'] + '/log4shell/api/list'])
    # Host-to-own-published-port traffic can be SNATed to the bridge gateway.
    # Do not weaken the explicit client ACL merely to permit this local probe.
    need(code in (b'200', b'403'), 'edge_tls_or_management_probe_failed')
    return {'role': 'lab-edge', 'status': 'verified', 'tls_identity_verified': True,
            'local_http_probe_code': int(code), 'management_http_verified': code == b'200',
            'allowed_client_e2e_verified': False}


def main():
    need(len(sys.argv) == 2 and sys.argv[1] in ('profile', 'render', 'native', 'verify'), 'invalid_action')
    need(os.geteuid() == 0, 'root_required')
    data = settings(); command = docker()
    if sys.argv[1] in ('profile', 'render'):
        sources = source_files(data); tls = certificate(data)
        if sys.argv[1] == 'profile':
            image_check(data, command)
            conflicts(data, command, existing=(data['role'] / 'deployment.json').exists())
            print(identity(data, sources, tls))
        else:
            write_config(data, sources, tls)
    elif sys.argv[1] == 'native':
        native(data, command)
    else:
        print(json.dumps(verify(data, command), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('{"error":"offline_security_validation_failed"}', file=sys.stderr)
        sys.exit(1)
