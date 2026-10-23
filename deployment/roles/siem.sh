#!/usr/bin/env bash
# Fresh Ubuntu 24.04/amd64 SIEM bootstrap. Packages/artifacts are operator supplied.
# No package installation, image pull, legacy deployment script or chat probe.
set -euo pipefail
[[ $# == 1 && $1 =~ ^(check|apply|verify)$ ]] || { echo 'usage: siem.sh check|apply|verify' >&2; exit 64; }
exec python3 -B - "$1" <<'PY'
import ast, base64, copy, datetime, grp, hashlib, http.client, ipaddress, json, os, pathlib, pwd
import re, secrets, shutil, socket, ssl, stat, subprocess, sys, time, urllib.error
import urllib.parse, urllib.request, xml.etree.ElementTree as ET

MODE = sys.argv[1]
os.umask(0o077)
ROOT = pathlib.Path(os.environ.get('CAPSTONE_ROOT', '/opt/capstone'))
SOURCE = pathlib.Path(os.environ.get('CAPSTONE_SOURCE', ''))
PRE = pathlib.Path('/opt/capstone-prereqs')
TREE = PRE / 'wazuh-docker/single-node'
DEST = ROOT / 'siem'
STATE = DEST / 'deployment.json'
PROJECT = 'capstone-siem'
HOSTS = {k: os.environ.get(k, '') for k in ('SECURITY_HOST', 'SIEM_HOST', 'SERVICE_HOST')}
IP = HOSTS['SIEM_HOST']
LLM = os.environ.get('LLM_BASE_URL', '')
MODEL = os.environ.get('LLM_MODEL', '')
SSH_PORT = os.environ.get('SSH_PORT', '22')
MCP_USER, HERMES_USER = 'capstone-mcp', 'capstone-hermes'
NAMES = {'wazuh.manager': 'capstone-wazuh-manager', 'wazuh.indexer': 'capstone-wazuh-indexer',
         'wazuh.dashboard': 'capstone-wazuh-dashboard', 'postgres': 'capstone-postgres',
         'mattermost': 'capstone-mattermost', 'hermes': 'capstone-hermes'}
IMAGES = {'wazuh.manager': 'wazuh/wazuh-manager:4.14.8', 'wazuh.indexer': 'wazuh/wazuh-indexer:4.14.8',
          'wazuh.dashboard': 'wazuh/wazuh-dashboard:4.14.8',
          'postgres': 'postgres:16-alpine', 'mattermost': 'mattermost/mattermost-team-edition:11.11.1'}
KEYS = {'schema_version', 'wazuh_api_username', 'wazuh_api_password', 'indexer_username',
        'indexer_password', 'mattermost_admin_username', 'mattermost_admin_email',
        'mattermost_admin_password', 'postgres_password', 'hermes_image'}
phase = 'preflight'
changed = False
cfg = None

class Refused(Exception): pass
def need(ok, reason):
    if not ok: raise Refused(reason)
def digest(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
def pairs(items):
    d = {}
    for k, v in items:
        need(k not in d, 'duplicate_json_key'); d[k] = v
    return d
def parse(data): return json.loads(data, object_pairs_hook=pairs)
def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)
def directory(path, private=False):
    path = pathlib.Path(path)
    for p in [path, *path.parents]:
        st = p.lstat()
        anchor = p == pathlib.Path('/var/tmp') and stat.S_IMODE(st.st_mode) == 0o1777
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and (anchor or not st.st_mode & 0o022),
             'unsafe_directory_' + p.name)
    if private: need(stat.S_IMODE(path.stat().st_mode) == 0o700, 'private_directory_required')
def read(path, cap=4*1024*1024, secret=False):
    path = pathlib.Path(path); directory(path.parent)
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022,
         'unsafe_file_' + path.name)
    if secret: need(stat.S_IMODE(st.st_mode) == 0o600, 'secret_file_requires_root_0600_' + path.name)
    need(st.st_size <= cap, 'file_too_large_' + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(fd)) == identity(st), 'file_changed_before_read')
        data = os.read(fd, cap + 1)
        need(len(data) == st.st_size and identity(os.fstat(fd)) == identity(st) and
             identity(path.lstat()) == identity(st), 'file_changed_during_read')
        return data
    finally: os.close(fd)
def publish(path, data, mode=0o600, uid=0, gid=0):
    path = pathlib.Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode); os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb', closefd=False) as f: f.write(data); f.flush(); os.fsync(fd)
    finally: os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
def mkdir(path, mode=0o700, uid=0, gid=0):
    pathlib.Path(path).mkdir(mode=mode); os.chmod(path, mode); os.chown(path, uid, gid)
def run(argv, timeout=30, data=None):
    # Command output is private; exceptions never interpolate argv or response values.
    r = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                            'LC_ALL': 'C', 'TZ': 'Asia/Seoul', 'PYTHONDONTWRITEBYTECODE': '1',
                                            'DOCKER_HOST':'unix:///var/run/docker.sock'})
    need(len(r.stdout) <= 16*1024*1024 and len(r.stderr) <= 2*1024*1024, 'command_output_limit')
    if r.returncode:
        if changed:
            p = DEST / ('diagnostic-' + str(time.time_ns()) + '.log')
            publish(p, r.stderr[:2*1024*1024])
        raise Refused('command_failed_' + pathlib.Path(argv[0]).name + '_rc_' + str(r.returncode))
    return r.stdout
def compose_args(file):
    return ['docker', 'compose', '--project-name', PROJECT, '--project-directory', str(file.parent), '-f', str(file)]
def log_pipeline(action):
    values=dict(HOSTS, CAPSTONE_SOURCE=str(SOURCE), CAPSTONE_ROOT=str(ROOT), LLM_BASE_URL=LLM,
                LOG_PROTECTED_IPS=os.environ.get('LOG_PROTECTED_IPS',''))
    # Activation includes four sequential native logtest groups (180 s each)
    # plus bounded Docker/source checks. Do not kill a valid child at 120 s.
    timeout = 900 if action == 'activate' else 120
    return run(['env',*[k+'='+v for k,v in values.items()],
                'python3','-B',str(SOURCE/'deployment/log_pipeline.py'),action,'siem'],timeout)
def docker_inspect(name): return parse(run(['docker', 'inspect', name]))[0]
def image_id(ref):
    d = parse(run(['docker', 'image', 'inspect', ref]))[0]
    need(d['Os'] == 'linux' and d['Architecture'] == 'amd64', 'image_architecture_not_linux_amd64')
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', d['Id']), 'invalid_image_id')
    return d['Id']
def tree_snapshot(root):
    out = {}; count = size = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        directory(parent)
        for d in dirs: directory(pathlib.Path(parent) / d)
        for name in files:
            path = pathlib.Path(parent) / name; data = read(path, 32*1024*1024)
            count += 1; size += len(data)
            need(count <= 2048 and size <= 128*1024*1024, 'prerequisite_tree_limit')
            out[str(path.relative_to(root))] = digest(data)
    need(out, 'empty_prerequisite_tree')
    return out
def cert_check(cert, key, ca):
    run(['openssl', 'verify', '-CAfile', str(ca), str(cert)])
    answer = run(['openssl', 'x509', '-in', str(cert), '-noout', '-checkip', IP]).decode().strip()
    need(answer == 'IP ' + IP + ' does match certificate', 'certificate_ip_san_mismatch')
    pub = run(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'])
    kpub = run(['openssl', 'pkey', '-in', str(key), '-pubout'])
    need(pub == kpub, 'certificate_private_key_mismatch')
    run(['openssl', 'x509', '-in', str(cert), '-checkend', '2592000', '-noout'])
def hermes_extension_files():
    base = 'infra/hermes/mattermost-context/'
    return {base + name: 'plugins/groot-mattermost-context/' + name
            for name in ('__init__.py', 'plugin.yaml', 'channel_sync.py')} | {
        base + 'startup/' + name: 'hooks/groot-mattermost-channel-sync/' + name
        for name in ('HOOK.yaml', 'handler.py')} | {
        'infra/hermes/query-completion/' + name: 'plugins/groot-query-completion/' + name
        for name in ('__init__.py', 'plugin.yaml')}
def query_completion_source_pins(raw=None):
    # Read literal pins from the shipped plugin without importing/executing it.
    if raw is None:
        raw = read(SOURCE/'infra/hermes/query-completion/__init__.py',512*1024)
    try:
        module = ast.parse(raw.decode('utf-8'))
        bindings = [node for node in module.body if isinstance(node,ast.Assign)
                    and any(isinstance(target,ast.Name) and target.id=='SOURCE_SHA256'
                            for target in node.targets)]
        need(len(bindings)==1 and isinstance(bindings[0].value,ast.Dict),
             'query_completion_source_pins_invalid')
        node = bindings[0].value
        pins = ast.literal_eval(node)
    except (AttributeError,UnicodeError,SyntaxError,ValueError,TypeError,RecursionError):
        raise Refused('query_completion_source_pins_invalid') from None
    expected = {'agent/turn_final_response.py','agent/conversation_loop.py',
                'agent/turn_context.py','agent/message_metadata.py',
                'agent/turn_api_request.py','agent/chat_completion_helpers.py'}
    need(len(node.keys)==len(expected) and set(pins)==expected and
         all(isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) for value in pins.values()),
         'query_completion_source_pins_invalid')
    return pins
def hermes_response_format(raw=None):
    if raw is None:
        raw = read(SOURCE/'infra/hermes/SOUL.groot.md',512*1024)
    try: text = raw.decode('utf-8')
    except (AttributeError,UnicodeError): raise Refused('SOC_response_format_encoding_invalid')
    start = '<!-- rule-change-policy:start -->\n### SOC 응답 서식\n'
    end = '\n## 보안 룰 변경 요청\n'
    need(text.count(start)==1 and text.count(end)==1, 'SOC_response_format_anchor_invalid')
    begin = text.index(start)+len(start); finish = text.index(end)
    need(begin < finish, 'SOC_response_format_order_invalid')
    body = text[begin:finish].strip()
    lines = body.splitlines()
    need(len(lines)==4 and all(line.startswith('- ') and len(line)>2 for line in lines)
         and len(body)<=16384, 'SOC_response_format_four_bullets_required')
    return '### SOC 응답 서식\n'+body+'\n'
def readonly_soul():
    # Copy only the shared presentation section, never live write-tool policies.
    return '''# SOC 읽기 보조자
설명은 한국어로 작성하고 IP, 경로, 규칙 ID, 해시 등 식별자는 원문을 보존한다.
현재 제공된 Wazuh 읽기 MCP와 security-events MCP에서 확인한 사실만 보고한다.
이 환경에는 쓰기 승인·차단·규칙 수정 도구가 배포되지 않았다. 수행했다고 주장하지 않는다.
본문/비밀을 요청하거나 노출하지 말고 필요한 경보 메타데이터만 요약한다.
시각은 명시된 offset을 기준으로 Asia/Seoul로 변환해 KST 또는 +09:00를 붙인다.
확인하지 못한 내용과 표본·지연의 한계를 명시한다.
\n'''+hermes_response_format()
def install_hermes_extensions(data, hu, creds, hc):
    for key in ('mattermost_admin_id','mattermost_team_id','mattermost_channel_id','mattermost_bot_id'):
        need(re.fullmatch(r'[a-z0-9]{26}',creds.get(key,'')), 'invalid_Mattermost_identity_' + key)
    files = hermes_extension_files()
    parents = {str(pathlib.PurePosixPath(relative).parent) for relative in files.values()}
    parents |= {'plugins', 'hooks'}
    for relative in sorted(parents, key=lambda value: (value.count('/'), value)):
        mkdir(data / relative,0o700,hu.pw_uid,hu.pw_gid)
    for source, relative in files.items():
        publish(data / relative,read(SOURCE/source,512*1024),0o600,hu.pw_uid,hu.pw_gid)
    hc['plugins'] = {'enabled':['groot-mattermost-context','groot-query-completion']}
    return {'MATTERMOST_URL':'http://'+IP+':8065','MATTERMOST_TOKEN':creds['mattermost_bot_token'],
            'MATTERMOST_ALLOWED_USERS':creds['mattermost_admin_id'],'MATTERMOST_ALLOWED_CHANNELS':'',
            'MATTERMOST_HOME_CHANNEL':creds['mattermost_channel_id'],'MATTERMOST_REQUIRE_MENTION':'true',
            'MATTERMOST_FREE_RESPONSE_CHANNELS':'','MATTERMOST_REPLY_MODE':'thread',
            'CAPSTONE_MM_TEAM_ID':creds['mattermost_team_id'],'CAPSTONE_MM_BOT_ID':creds['mattermost_bot_id']}
def profile(snap, images):
    return {'hosts':HOSTS,'ssh_port':int(SSH_PORT),'llm_base_url':LLM,'llm_model':MODEL,'images':images,
            'prerequisite_tree_sha256':digest(canonical(snap)),
            'prerequisite_credentials_sha256':digest(read(PRE/'siem.json',16384,True)),
            'source_sha256':{p:digest(read(SOURCE/p)) for p in (
                'infra/mcp/security-events-mcp.py','infra/hermes/korean_output_guard.py',
                'infra/hermes/SOUL.groot.md',
                'infra/groot-b/local_rules.xml','infra/groot-b/local_decoder.xml', *hermes_extension_files())}}
def fresh():
    forbidden = [DEST, ROOT/'exports/wazuh-enrollment-ca.pem', ROOT/'secrets/enrollment.pass',
                 pathlib.Path('/etc/ssh/sshd_config.d/65-capstone-mcp.conf'),
                 pathlib.Path('/etc/capstone-hermes-guard'), pathlib.Path('/var/lib/capstone-automation/hermes-guard'),
                 pathlib.Path('/var/lib/rule-change'), pathlib.Path('/opt/hermes-data')]
    need(not any(p.exists() or p.is_symlink() for p in forbidden), 'existing_siem_or_managed_state_refused')
    for user in (MCP_USER, HERMES_USER):
        try: pwd.getpwnam(user)
        except KeyError: pass
        else: raise Refused('service_account_already_exists_' + user)
    current = run(['docker', 'ps', '-a', '--format', '{{.Names}} {{.Image}}']).decode().splitlines()
    for line in current:
        name, _, img = line.partition(' ')
        need(not (name in set(NAMES.values()) | {'hermes', 'mm-app', 'mm-postgres'} or
                  'wazuh' in name or img.startswith(('wazuh/', 'mattermost/'))), 'existing_siem_container_refused')
    for kind in ('volume', 'network'):
        names = run(['docker', kind, 'ls', '--format', '{{.Name}}']).decode().splitlines()
        need(not any(n.startswith(PROJECT) for n in names), 'existing_compose_resource_refused')
    for port in (1514,1515,55000,9200,443,8065):
        need(not run(['ss','-H','-ltn','sport = :'+str(port)]).strip(),'required_TCP_port_already_used_'+str(port))
    need(not run(['ss','-H','-lun','sport = :514']).strip(),'required_UDP_port_already_used_514')
def preflight():
    global cfg
    need(os.geteuid() == 0, 'root_required')
    need(ROOT == pathlib.Path('/opt/capstone'), 'CAPSTONE_ROOT_must_be_opt_capstone')
    need(SOURCE.is_absolute() and SOURCE != pathlib.Path('/'), 'CAPSTONE_SOURCE_required')
    directory(SOURCE); directory(PRE)
    release = pathlib.Path('/etc/os-release').read_text()
    need('ID=ubuntu' in release and 'VERSION_ID="24.04"' in release, 'Ubuntu_24_04_required')
    need(os.uname().machine == 'x86_64', 'amd64_required')
    for host in HOSTS.values():
        a=ipaddress.IPv4Address(host)
        need(str(a)==host and not(a.is_loopback or a.is_multicast or a.is_unspecified),'three_canonical_unicast_IPv4_addresses_required')
    need(len(set(HOSTS.values())) == 3, 'three_distinct_hosts_required')
    need(re.fullmatch(r'[1-9][0-9]{0,4}',SSH_PORT) and 1<=int(SSH_PORT)<=65535,'invalid_SSH_PORT')
    u = urllib.parse.urlsplit(LLM)
    need(u.scheme in ('http', 'https') and u.hostname and not u.username and not u.password and
         u.path.rstrip('/') == '/v1' and not u.query and not u.fragment and '\n' not in LLM,
         'LLM_BASE_URL_must_be_http_or_https_v1')
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}', MODEL), 'invalid_LLM_MODEL')
    need(os.environ.get('TZ', 'Asia/Seoul') == 'Asia/Seoul', 'TZ_must_be_Asia_Seoul')
    for exe in ('docker', 'openssl', 'ssh-keygen', 'sshd', 'systemctl', 'useradd', 'getent', 'runuser', 'ip', 'ss'):
        need(shutil.which(exe) is not None, 'manual_package_missing_' + exe)
    run(['docker', 'compose', 'version'])
    need(int(pathlib.Path('/proc/sys/vm/max_map_count').read_text()) >= 262144, 'manual_vm_max_map_count_262144_required')
    address = parse(run(['ip', '-j', '-4', 'address', 'show']))
    need(any(v.get('local') == IP for row in address for v in row.get('addr_info', [])), 'SIEM_HOST_not_local')
    cfg = parse(read(PRE/'siem.json', 16384, True))
    need(set(cfg) == KEYS and cfg['schema_version'] == 1, 'siem_json_exact_schema_required')
    for k in KEYS - {'schema_version'}:
        need(isinstance(cfg[k], str) and 1 <= len(cfg[k]) <= 512 and not any(ord(c) < 32 for c in cfg[k]), 'invalid_prerequisite_field_' + k)
    for k in ('wazuh_api_password', 'indexer_password', 'postgres_password', 'mattermost_admin_password'):
        need(16 <= len(cfg[k].encode()) <= 72 and 'CHANGE_ME' not in cfg[k], 'strong_manual_password_required_' + k)
    need(cfg['indexer_username']=='admin','official_indexer_admin_username_required')
    need(re.fullmatch(r'[A-Za-z][A-Za-z0-9._-]{2,31}',cfg['wazuh_api_username']),'invalid_Wazuh_API_username')
    need(all(re.search(pattern,cfg['wazuh_api_password']) for pattern in ('[A-Z]','[a-z]','[0-9]',r'[^A-Za-z0-9]')),
         'Wazuh_API_password_requires_upper_lower_digit_special')
    need(re.fullmatch(r'[a-z][a-z0-9._-]{2,31}', cfg['mattermost_admin_username']), 'invalid_mattermost_admin_username')
    need(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', cfg['mattermost_admin_email']), 'invalid_mattermost_admin_email')
    need(re.fullmatch(r'(?:[A-Za-z0-9./:_-]+@)?sha256:[0-9a-f]{64}', cfg['hermes_image']), 'digest_pinned_prepared_Hermes_image_required')
    try: import bcrypt
    except ImportError: raise Refused('manual_package_missing_python3_bcrypt')
    snap = tree_snapshot(TREE)
    binary = read(PRE/'mcp/mcp-server-wazuh', 64*1024*1024)
    pin = read(PRE/'mcp/mcp-server-wazuh.sha256', 128).decode().strip()
    need(re.fullmatch(r'[0-9a-f]{64}', pin) and digest(binary) == pin and binary.startswith(b'\x7fELF'), 'reviewed_mcp_binary_SHA_required')
    for p in ('infra/mcp/security-events-mcp.py', 'infra/hermes/korean_output_guard.py',
              'infra/hermes/SOUL.groot.md',
              'infra/groot-b/local_rules.xml','infra/groot-b/local_decoder.xml', *hermes_extension_files()):
        read(SOURCE/p, 512*1024)
    hermes_response_format()
    query_completion_source_pins()
    images = {k: image_id(v) for k, v in IMAGES.items()}; images['hermes'] = image_id(cfg['hermes_image'])
    compose = parse(run(compose_args(TREE/'docker-compose.yml') + ['config', '--format', 'json'], 45))
    validate_wazuh(compose)
    dashboard_single_tenant(read(dashboard_configuration_mount(compose)))
    log_pipeline('check')
    need(tree_snapshot(TREE) == snap, 'prerequisite_tree_changed')
    sshcfg = run(['sshd', '-T', '-C', 'user='+MCP_USER+',host=localhost,addr='+IP+',laddr='+IP+',lport='+SSH_PORT]).decode()
    need('pubkeyauthentication yes\n' in sshcfg and 'usepam yes\n' in sshcfg, 'manual_sshd_pubkey_and_UsePAM_required')
    need(not re.search(r'^(allowusers|allowgroups|denyusers|denygroups) ', sshcfg, re.M), 'manual_sshd_allowlist_review_required')
    read('/etc/ssh/ssh_host_ed25519_key.pub', 4096)
    if not STATE.exists(): fresh()
    return compose, snap, images
def validate_wazuh(c):
    need(set(c.get('services', {})) == {'wazuh.manager', 'wazuh.indexer', 'wazuh.dashboard'}, 'official_single_node_three_services_required')
    for name, svc in c['services'].items():
        need(svc.get('image') == IMAGES[name], 'Wazuh_4_14_8_images_required')
        need(not any(k in svc for k in ('build', 'extends', 'include', 'develop', 'devices', 'pid', 'ipc', 'network_mode', 'secrets', 'configs')),
             'unsupported_official_compose_feature')
        need(not svc.get('privileged', False), 'privileged_container_refused')
        for vol in svc.get('volumes', []):
            need(vol['type'] in ('bind', 'volume'), 'unsupported_mount_type')
            if vol['type'] == 'bind':
                p = pathlib.Path(vol['source']); need(p.is_relative_to(TREE) and not p.is_symlink(), 'bind_outside_prerequisite_tree')
                need('docker.sock' not in vol['target'], 'docker_socket_refused')
    for group in ('networks', 'volumes'):
        need(not any(x.get('external') for x in c.get(group, {}).values()), 'external_compose_resource_refused')
def api(url, method='GET', body=None, headers=None, context=None, raw=False, statuses=(200,)):
    data = None if body is None else canonical(body)
    h = dict(headers or {})
    if data is not None: h['Content-Type'] = 'application/json'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try: response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as e: response = e
    with response:
        result = response.read(2*1024*1024+1)
        need(len(result) <= 2*1024*1024,'application_response_size_limit')
        if response.status not in statuses:
            if changed:
                publish(DEST/('api-failure-'+str(time.time_ns())+'.body'),result[:65536])
            raise Refused('application_http_status_'+str(response.status))
        return (result if raw else parse(result)), dict(response.headers)
def basic(user, password): return {'Authorization':'Basic '+base64.b64encode((user+':'+password).encode()).decode()}
def pending(label):
    # Mutations are issued once. A partial installation requires operator inspection.
    publish(DEST/'actions'/(label+'.intent.json'), canonical({'action':label,'at':int(time.time()),'automatic_retry':False}))
def wait(label, fn, seconds=240):
    until = time.monotonic()+seconds
    while time.monotonic() < until:
        try:
            value = fn()
            if value: return value
        except (Refused, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ssl.SSLError): pass
        time.sleep(3)
    raise Refused('health_timeout_'+label)
def auth_api():
    data, _ = api('https://'+IP+':55000/security/user/authenticate?raw=true', 'POST',
                  headers=basic(cfg['wazuh_api_username'], cfg['wazuh_api_password']), context=tls(), raw=True)
    token = data.decode().strip(); need(re.fullmatch(r'[A-Za-z0-9_.-]{20,8192}', token), 'API_authentication_failed')
    return {'Authorization':'Bearer '+token}
def tls(): return ssl.create_default_context(cafile=str(DEST/'tls/root-ca.pem'))
def current_containers(include_hermes=True):
    result = {}
    for service, name in NAMES.items():
        if service == 'hermes' and not include_hermes: continue
        d = docker_inspect(name)
        need(d['State']['Running'] and not d['State'].get('OOMKilled'), 'container_not_running_'+service)
        need(d['Config']['Labels'].get('com.docker.compose.project') == PROJECT, 'container_project_mismatch')
        need(d['State'].get('Health', {}).get('Status') not in ('unhealthy', 'starting'), 'container_not_healthy_'+service)
        result[service] = {'id':d['Id'], 'image':d['Image'], 'pid':d['State']['Pid']}
    return result
def core_health():
    current_containers(False)
    auth_api()
    j, _ = api('https://'+IP+':9200/_cluster/health', headers=basic(cfg['indexer_username'], cfg['indexer_password']), context=tls())
    need(j.get('status') in ('green', 'yellow') and not j.get('timed_out'), 'indexer_not_ready')
    ping, _ = api('http://'+IP+':8065/api/v4/system/ping')
    need(ping.get('status') == 'OK', 'Mattermost_not_ready')
    api('https://'+IP+'/',context=tls(),raw=True)
    return True
def create_certificates():
    target=DEST/'tls'; mkdir(target)
    ca=target/'root-ca.pem'; ca_key=target/'root-ca-key.pem'
    run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-keyout',str(ca_key),'-out',str(ca),
         '-sha256','-days','3650','-subj','/C=US/O=Capstone/CN=Capstone-Wazuh-Root-CA',
         '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],45)
    os.chmod(ca_key,0o600); os.chmod(ca,0o444)
    for name,cn in [('wazuh.manager','wazuh.manager'),('wazuh.indexer','wazuh.indexer'),
                    ('wazuh.dashboard','wazuh.dashboard'),('api-server','wazuh.manager'),('admin','admin')]:
        key=target/(name+'-key.pem'); cert=target/(name+'.pem'); csr=target/(name+'.csr'); ext=target/(name+'.ext')
        subject='/C=US/L=California/O=Wazuh/OU=Wazuh/CN='+cn
        run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-sha256','-keyout',str(key),'-out',str(csr),'-subj',subject],30)
        publish(ext,('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                     'extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:'+cn+',IP:'+IP+'\n').encode())
        run(['openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),
             '-set_serial',str(secrets.randbits(127)+1),'-out',str(cert),'-days','825','-sha256','-extfile',str(ext)],30)
        # The root0700 directory protects keys on the host. Native services read
        # only their individual RO bind mount; the CA signing key is never mounted.
        os.chmod(key,0o444); os.chmod(cert,0o444)
        cert_check(cert,key,ca)
    publish(target/'root-ca-manager.pem',read(ca),0o444)
    for path in target.iterdir():
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
def dashboard_configuration_mount(c):
    paths=[v for v in c['services']['wazuh.dashboard'].get('volumes',[])
           if v.get('type')=='bind' and v.get('target')=='/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml']
    need(len(paths)==1,'official_dashboard_configuration_mount_required')
    return pathlib.Path(paths[0]['source'])
def dashboard_single_tenant(raw):
    # Change one reviewed YAML scalar; never silently override ambiguous keys.
    key=rb'opensearch_security\.multitenancy\.enabled'
    lines=list(re.finditer(rb'^[ \t]*[\'"]?'+key+rb'[\'"]?\s*:.*$',raw,re.M))
    need(len(lines)<=1,'duplicate_dashboard_multitenancy_key')
    wanted=b'opensearch_security.multitenancy.enabled: false'
    if not lines: return raw.rstrip()+b'\n'+wanted+b'\n'
    item=lines[0]
    need(re.fullmatch(key+rb'\s*:\s*(true|false)\s*(?:#[^\r\n]*)?',item.group()),'unsupported_dashboard_multitenancy_value')
    return raw[:item.start()]+wanted+raw[item.end():]
def manager_auth_configuration(raw):
    # The official single-node file contains TWO ossec_config roots. Modify only
    # the unique auth element; retain all unrelated original bytes/comments.
    root=ET.fromstring(b'<capstone>'+raw+b'</capstone>')
    need(1<=len(root)<=4 and all(n.tag=='ossec_config' for n in root),'invalid_manager_configuration_roots')
    auths=[n for block in root for n in block.findall('auth')]
    need(len(auths)<=1,'duplicate_auth_configuration')
    auth=copy.deepcopy(auths[0]) if auths else ET.Element('auth')
    for k,v in {'disabled':'no','port':'1515','use_source_ip':'yes','use_password':'yes',
                'ssl_verify_host':'no','ssl_manager_cert':'etc/sslmanager.cert','ssl_manager_key':'etc/sslmanager.key'}.items():
        matches=auth.findall(k); need(len(matches)<=1,'duplicate_auth_option')
        node=matches[0] if matches else ET.SubElement(auth,k); node.text=v
    auth.tail=None; new=ET.tostring(auth,encoding='utf-8')
    spans=list(re.finditer(rb'<auth\s*>.*?</auth\s*>',raw,re.S))
    if auths:
        need(len(spans)==1,'auth_source_not_unique')
        a=spans[0]; need(ET.tostring(ET.fromstring(a.group()))==ET.tostring(ET.fromstring(ET.tostring(auths[0]))),
                        'auth_source_semantics_mismatch')
        output=raw[:a.start()]+new+raw[a.end():]
    else:
        need(not spans and raw.count(b'</ossec_config>')==len(root),'auth_insertion_boundary_ambiguous')
        pos=raw.index(b'</ossec_config>'); output=raw[:pos]+new+b'\n'+raw[pos:]
    check=ET.fromstring(b'<capstone>'+output+b'</capstone>')
    found=[n for block in check for n in block.findall('auth')]
    need(len(check)==len(root) and len(found)==1,'auth_postcheck_failed')
    return output
def write_compose(c, images):
    c = copy.deepcopy(c); c['name'] = PROJECT
    for name, svc in c['services'].items():
        svc['image'] = images[name]; svc['container_name'] = NAMES[name]; svc['pull_policy'] = 'never'
        for v in svc.get('volumes', []):
            if v['type'] == 'bind':
                rel=pathlib.Path(v['source']).relative_to(TREE)
                if rel.parent==pathlib.Path('config/wazuh_indexer_ssl_certs'):
                    need((DEST/'tls'/rel.name).is_file(),'unsupported_official_certificate_filename')
                    v['source']=str(DEST/'tls'/rel.name); v['read_only']=True
                else: v['source'] = str(DEST/'wazuh'/rel)
        for port in svc.get('ports', []): port['host_ip'] = IP
        if name in ('wazuh.manager','wazuh.dashboard'):
            svc.setdefault('environment',{}).update({'API_USERNAME':cfg['wazuh_api_username'],
                'API_PASSWORD':cfg['wazuh_api_password'],'INDEXER_USERNAME':cfg['indexer_username'],
                'INDEXER_PASSWORD':cfg['indexer_password'],'TZ':'Asia/Seoul'})
    c['services']['wazuh.dashboard']['environment']['DASHBOARD_PASSWORD']=dashboard_password
    for group in ('networks', 'volumes'):
        for name, spec in c.get(group, {}).items(): spec['name'] = PROJECT+'_'+name
    m = c['services']['wazuh.manager']
    need(any(v['target'] == '/wazuh-config-mount/etc/ossec.conf' for v in m.get('volumes', [])), 'official_manager_config_mount_required')
    for source, target in [('wazuh.manager.pem','etc/sslmanager.cert'),
                           ('wazuh.manager-key.pem','etc/sslmanager.key'),
                           ('api-server.pem','api/configuration/ssl/server.crt'),
                           ('api-server-key.pem','api/configuration/ssl/server.key')]:
        target='/wazuh-config-mount/'+target
        need(not any(v['target'] == target for v in m['volumes']), 'unexpected_existing_TLS_mount')
        m['volumes'].append({'type':'bind','source':str(DEST/'tls'/source),'target':target,'read_only':True})
    m['volumes'].append({'type':'bind','source':str(DEST/'wazuh/capstone-authd.pass'),'target':'/wazuh-config-mount/etc/authd.pass','read_only':True})
    for source,target in [('capstone-local-rules.xml','etc/rules/capstone_portable_rules.xml'),
                          ('capstone-local-decoder.xml','etc/decoders/capstone_portable_decoder.xml'),
                          ('capstone-internal-options.conf','etc/local_internal_options.conf')]:
        m['volumes'].append({'type':'bind','source':str(DEST/'wazuh'/source),
                            'target':'/wazuh-config-mount/'+target,'read_only':True})
    m.setdefault('environment', {})['TZ'] = 'Asia/Seoul'
    c.setdefault('volumes', {})['capstone_postgres'] = {'name':PROJECT+'_postgres'}
    c.setdefault('networks', {})['chat'] = {'name':PROJECT+'_chat'}
    c['services']['postgres'] = {'image':images['postgres'],'pull_policy':'never','container_name':NAMES['postgres'],
        'restart':'unless-stopped','environment':{'POSTGRES_USER':'mattermost','POSTGRES_DB':'mattermost',
        'POSTGRES_PASSWORD':cfg['postgres_password']},'volumes':[{'type':'volume','source':'capstone_postgres','target':'/var/lib/postgresql/data'}],
        'networks':['chat'],'healthcheck':{'test':['CMD-SHELL','pg_isready -U mattermost -d mattermost'],'interval':'5s','timeout':'3s','retries':40}}
    mm = {'MM_SQLSETTINGS_DRIVERNAME':'postgres','MM_SQLSETTINGS_DATASOURCE':
          'postgres://mattermost:'+urllib.parse.quote(cfg['postgres_password'],safe='')+'@postgres:5432/mattermost?sslmode=disable&connect_timeout=10',
          'MM_SERVICESETTINGS_SITEURL':'http://'+IP+':8065','MM_SERVICESETTINGS_ENABLEBOTACCOUNTCREATION':'true',
          'MM_SERVICESETTINGS_ENABLEUSERACCESSTOKENS':'true','MM_EMAILSETTINGS_REQUIREEMAILVERIFICATION':'false',
          'MM_LOGSETTINGS_CONSOLELEVEL':'WARN','TZ':'Asia/Seoul'}
    mmvol = []
    for name in ('config','data','logs','plugins','client/plugins'):
        target=DEST/'mattermost'/name; target.mkdir(parents=True,exist_ok=True); os.chown(target,2000,2000); os.chmod(target,0o750)
        mmvol.append({'type':'bind','source':str(target),'target':'/mattermost/'+name})
    c['services']['mattermost'] = {'image':images['mattermost'],'pull_policy':'never','container_name':NAMES['mattermost'],
        'restart':'unless-stopped','depends_on':{'postgres':{'condition':'service_healthy'}},'environment':mm,
        'networks':['chat'],'ports':[{'target':8065,'published':'8065','host_ip':IP,'protocol':'tcp'}],'volumes':mmvol}
    publish(DEST/'compose.core.json', canonical(c))
    return c
def prepare_files(c, snap, images):
    global changed, dashboard_password
    if not ROOT.exists(): mkdir(ROOT)
    directory(ROOT)
    mkdir(DEST); changed=True; mkdir(DEST/'actions')
    publish(DEST/'install-intent.json', canonical({'schema_version':1,'role':'siem','hosts':HOSTS,'started_at':int(time.time()),
             'source_tree_sha256':digest(canonical(snap)),'images':images,'automatic_retry':False}))
    shutil.copytree(TREE, DEST/'wazuh', copy_function=shutil.copy2)
    need(tree_snapshot(TREE) == snap and tree_snapshot(DEST/'wazuh') == snap, 'source_copy_hash_mismatch')
    os.chmod(DEST/'wazuh',0o700)
    create_certificates()
    import bcrypt
    dashboard_password='K!'+secrets.token_urlsafe(32)+'a9'
    users={'_meta':{'type':'internalusers','config_version':2},
           cfg['indexer_username']:{'hash':bcrypt.hashpw(cfg['indexer_password'].encode(),bcrypt.gensalt(12,prefix=b'2a')).decode(),
                 'reserved':True,'backend_roles':['admin'],'description':'Capstone administrator'},
           'kibanaserver':{'hash':bcrypt.hashpw(dashboard_password.encode(),bcrypt.gensalt(12,prefix=b'2a')).decode(),
                 'reserved':True,'backend_roles':[],'description':'Dashboard service'}}
    # JSON is YAML-compatible; only the private destination copy is replaced.
    internal=DEST/'wazuh/config/wazuh_indexer/internal_users.yml'
    need(internal.is_file() and not internal.is_symlink(),'official_internal_users_configuration_missing')
    internal.write_bytes(canonical(users)); os.chmod(internal,0o444)
    dashboard_config=DEST/'wazuh'/dashboard_configuration_mount(c).relative_to(TREE)
    dashboard_config.write_bytes(dashboard_single_tenant(read(dashboard_config)))
    os.chmod(dashboard_config,0o444)
    for name in ('secrets','exports'):
        if not (ROOT/name).exists(): mkdir(ROOT/name)
        directory(ROOT/name)
    password = secrets.token_urlsafe(36)
    publish(ROOT/'secrets/enrollment.pass', (password+'\n').encode())
    publish(DEST/'wazuh/capstone-authd.pass',(password+'\n').encode(),0o444)
    publish(ROOT/'exports/wazuh-enrollment-ca.pem', read(DEST/'tls/root-ca.pem'),0o644)
    manager = c['services']['wazuh.manager']
    mount = [v for v in manager['volumes'] if v['target']=='/wazuh-config-mount/etc/ossec.conf']
    need(len(mount)==1, 'manager_configuration_mount_not_unique')
    path = DEST/'wazuh'/pathlib.Path(mount[0]['source']).relative_to(TREE)
    path.write_bytes(manager_auth_configuration(path.read_bytes())); os.chmod(path,0o600)
    publish(DEST/'wazuh/capstone-local-rules.xml',read(SOURCE/'infra/groot-b/local_rules.xml'),0o444)
    publish(DEST/'wazuh/capstone-local-decoder.xml',read(SOURCE/'infra/groot-b/local_decoder.xml'),0o444)
    publish(DEST/'wazuh/capstone-internal-options.conf',b'analysisd.decoder_order_size=1024\n',0o444)
    return write_compose(c,images)
def app_bootstrap():
    mm='http://'+IP+':8065/api/v4'; admin={'username':cfg['mattermost_admin_username'],
         'email':cfg['mattermost_admin_email'],'password':cfg['mattermost_admin_password']}
    pending('mattermost-create-admin'); user,_=api(mm+'/users','POST',admin,statuses=(201,))
    need('system_admin' in user.get('roles','').split(),'first_Mattermost_user_not_admin')
    pending('mattermost-admin-login')
    login,headers=api(mm+'/users/login','POST',{'login_id':admin['username'],'password':admin['password']})
    token=next((v for k,v in headers.items() if k.lower()=='token'),None); need(token,'Mattermost_login_token_missing')
    hdr={'Authorization':'Bearer '+token}
    pending('mattermost-create-team'); team,_=api(mm+'/teams','POST',{'name':'capstone','display_name':'Capstone SOC','type':'I'},hdr,statuses=(201,))
    pending('mattermost-create-channel'); channel,_=api(mm+'/channels','POST',{'team_id':team['id'],'name':'soc','display_name':'SOC','type':'O'},hdr,statuses=(201,))
    pending('mattermost-create-bot'); bot,_=api(mm+'/bots','POST',{'username':'capstone-assistant','display_name':'Capstone Assistant','description':'Read-only SOC assistant'},hdr,statuses=(201,))
    bid=bot['user_id']
    pending('mattermost-add-bot-team'); api(mm+'/teams/'+team['id']+'/members','POST',{'team_id':team['id'],'user_id':bid},hdr,statuses=(201,))
    pending('mattermost-add-bot-channel'); api(mm+'/channels/'+channel['id']+'/members','POST',{'user_id':bid},hdr,statuses=(201,))
    pending('mattermost-create-bot-token'); bt,_=api(mm+'/users/'+bid+'/tokens','POST',{'description':'capstone-hermes'},hdr,statuses=(201,))
    need(re.fullmatch(r'[a-z0-9]{26}',bt.get('token','')),'unexpected_bot_token_format')
    creds={'schema_version':1,'mattermost_admin_id':user['id'],'mattermost_team_id':team['id'],
           'mattermost_channel_id':channel['id'],'mattermost_bot_id':bid,'mattermost_bot_token':bt['token'],
           'readonly_username':'capstone-ro','readonly_password':'C!'+secrets.token_urlsafe(32)+'a9'}
    publish(DEST/'app-credentials.json',canonical(creds))
    wa='https://'+IP+':55000'; wh=auth_api()
    roles,_=api(wa+'/security/roles',headers=wh,context=tls())
    r=[x for x in roles['data']['affected_items'] if x.get('name')=='readonly']; need(len(r)==1,'Wazuh_readonly_role_missing')
    pending('wazuh-create-readonly-user')
    created,_=api(wa+'/security/users','POST',{'username':creds['readonly_username'],'password':creds['readonly_password'],'allow_run_as':False},wh,tls())
    items=created['data']['affected_items']; need(len(items)==1,'Wazuh_readonly_user_creation_failed'); uid=items[0]['id']
    pending('wazuh-bind-readonly-role')
    api(wa+'/security/users/'+str(uid)+'/roles?role_ids='+str(r[0]['id']),'POST',headers=wh,context=tls())
    found,_=api(wa+'/security/users?user_ids='+str(uid),headers=wh,context=tls())
    need(found['data']['affected_items'][0]['roles']==[r[0]['id']], 'Wazuh_readonly_role_readback_failed')
    idx='https://'+IP+':9200/_plugins/_security/api'; ih=basic(cfg['indexer_username'],cfg['indexer_password'])
    role='capstone_mcp_readonly'
    pending('indexer-create-readonly-role')
    api(idx+'/roles/'+role,'PUT',{'cluster_permissions':['cluster_composite_ops_ro'],
        'index_permissions':[{'index_patterns':['wazuh-alerts-*','wazuh-monitoring-*','wazuh-states-*'],
                              'allowed_actions':['read']}],'tenant_permissions':[]},ih,tls(),statuses=(200,201))
    pending('indexer-create-readonly-user')
    api(idx+'/internalusers/'+creds['readonly_username'],'PUT',{'password':creds['readonly_password'],'backend_roles':[role]},ih,tls(),statuses=(200,201))
    pending('indexer-map-readonly-role')
    api(idx+'/rolesmapping/'+role,'PUT',{'backend_roles':[role],'hosts':[],'users':[]},ih,tls(),statuses=(200,201))
    check,_=api(idx+'/roles/'+role,headers=ih,context=tls())
    need(check[role]['index_permissions'][0]['allowed_actions']==['read'] and not check[role]['tenant_permissions'], 'indexer_readonly_role_readback_failed')
    readonly_credentials(creds)
    return creds
def readonly_credentials(creds):
    user=creds['readonly_username']; password=creds['readonly_password']
    token,_=api('https://'+IP+':55000/security/user/authenticate?raw=true','POST',
                headers=basic(user,password),context=tls(),raw=True)
    need(re.fullmatch(rb'[A-Za-z0-9_.-]{20,8192}',token.strip()),'readonly_API_auth_failed')
    agents,_=api('https://'+IP+':55000/agents?limit=1',headers={'Authorization':'Bearer '+token.decode().strip()},context=tls())
    need(agents.get('error')==0 and isinstance(agents.get('data',{}).get('affected_items'),list),'readonly_API_read_failed')
    result,_=api('https://'+IP+':9200/wazuh-alerts-*/_search?allow_no_indices=true&ignore_unavailable=true',
                 'POST',{'size':0,'query':{'match_none':{}}},basic(user,password),tls())
    need(isinstance(result.get('hits',{}),dict) and 'hits' in result,'readonly_Indexer_read_failed')
    api('https://'+IP+':9200/_plugins/_security/api/internalusers',headers=basic(user,password),context=tls(),raw=True,statuses=(403,))
def ssh_host_token(): return IP if SSH_PORT=='22' else '['+IP+']:'+SSH_PORT
def setup_mcp_and_hermes(c, images, creds):
    for account in (MCP_USER,HERMES_USER):
        pending('create-account-'+account)
        run(['useradd','--system','--user-group','--no-create-home','--home-dir',str(DEST/account),
             '--shell','/bin/dash' if account==MCP_USER else '/usr/sbin/nologin',account])
    mc=pwd.getpwnam(MCP_USER); hu=pwd.getpwnam(HERMES_USER)
    # Directory traversal to two intentionally readable subtrees only; secrets remain root0700.
    os.chmod(ROOT,0o711); os.chmod(DEST,0o711)
    mcp=DEST/MCP_USER; data=DEST/HERMES_USER
    mkdir(mcp,0o750,0,mc.pw_gid); mkdir(mcp/'.ssh',0o750,0,mc.pw_gid)
    mkdir(data,0o700,hu.pw_uid,hu.pw_gid); mkdir(data/'home',0o700,hu.pw_uid,hu.pw_gid)
    mkdir(data/'home/.ssh',0o700,hu.pw_uid,hu.pw_gid)
    publish(mcp/'mcp-server-wazuh',read(PRE/'mcp/mcp-server-wazuh',64*1024*1024),0o550,0,mc.pw_gid)
    publish(mcp/'security-events-mcp.py',read(SOURCE/'infra/mcp/security-events-mcp.py'),0o440,0,mc.pw_gid)
    publish(mcp/'root-ca.pem',read(DEST/'tls/root-ca.pem'),0o440,0,mc.pw_gid)
    env={'WAZUH_API_HOST':IP,'WAZUH_API_PORT':'55000','WAZUH_API_USERNAME':creds['readonly_username'],
         'WAZUH_API_PASSWORD':creds['readonly_password'],'WAZUH_INDEXER_HOST':IP,'WAZUH_INDEXER_PORT':'9200',
         'WAZUH_INDEXER_USERNAME':creds['readonly_username'],'WAZUH_INDEXER_PASSWORD':creds['readonly_password'],
         'WAZUH_VERIFY_SSL':'true','SSL_CERT_FILE':str(mcp/'root-ca.pem'),'RUST_LOG':'error'}
    publish(mcp/'credentials.json',canonical(env),0o440,0,mc.pw_gid)
    launcher='''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
root=Path(__file__).resolve().parent
command=os.environ.get('SSH_ORIGINAL_COMMAND','')
if command not in ('','security-events'): sys.exit(65)
env=json.loads((root/'credentials.json').read_bytes())
env.update(PATH='/usr/bin:/bin',LANG='C.UTF-8',PYTHONDONTWRITEBYTECODE='1')
args=['/usr/bin/python3','-B',str(root/'security-events-mcp.py')] if command else [str(root/'mcp-server-wazuh')]
os.execve(args[0],args,env)
'''
    publish(mcp/'run-mcp',launcher.encode(),0o550,0,mc.pw_gid)
    pending('hermes-SSH-key')
    run(['ssh-keygen','-q','-t','ed25519','-N','','-C','capstone-hermes-readonly','-f',str(data/'home/.ssh/id_ed25519')])
    for p in (data/'home/.ssh/id_ed25519',data/'home/.ssh/id_ed25519.pub'):
        os.chown(p,hu.pw_uid,hu.pw_gid); os.chmod(p,0o600)
    pub=(data/'home/.ssh/id_ed25519.pub').read_text().strip()
    publish(mcp/'.ssh/authorized_keys',('restrict,command="'+str(mcp/'run-mcp')+'" '+pub+'\n').encode(),0o440,0,mc.pw_gid)
    hk=read('/etc/ssh/ssh_host_ed25519_key.pub').decode().split()
    need(len(hk)>=2 and hk[0]=='ssh-ed25519','ed25519_host_key_required')
    publish(data/'home/.ssh/known_hosts',(ssh_host_token()+' '+hk[0]+' '+hk[1]+'\n').encode(),0o600,hu.pw_uid,hu.pw_gid)
    ssh='Host siem-readonly\n    HostName '+IP+'\n    Port '+SSH_PORT+'\n    User '+MCP_USER+'\n    IdentityFile /opt/data/home/.ssh/id_ed25519\n    IdentitiesOnly yes\n    BatchMode yes\n    StrictHostKeyChecking yes\n    UserKnownHostsFile /opt/data/home/.ssh/known_hosts\n    ConnectTimeout 10\n'
    publish(data/'home/.ssh/config',ssh.encode(),0o600,hu.pw_uid,hu.pw_gid)
    sshd='Match User '+MCP_USER+'\n    ForceCommand '+str(mcp/'run-mcp')+'\n    AuthenticationMethods publickey\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    DisableForwarding yes\n    PermitTTY no\n    X11Forwarding no\n    PermitUserEnvironment no\nMatch all\n'
    pending('sshd-readonly-MCP')
    publish('/etc/ssh/sshd_config.d/65-capstone-mcp.conf',sshd.encode(),0o644)
    run(['sshd','-t']); run(['systemctl','reload','ssh'],30)
    servers={}
    for name,extra in [('wazuh-ro',[]),('security-events',['security-events'])]:
        servers[name]={'command':'ssh','args':['-T','-F','/opt/data/home/.ssh/config','siem-readonly']+extra,
                      'connect_timeout':30,'timeout':120,'supports_parallel_tool_calls':False,
                      'tools':{'resources':False,'prompts':False},'trust':'full'}
    tools=['mcp-wazuh-ro','mcp-security-events']
    hc={'mcp_servers':servers,'security':{'allow_lazy_installs':False},'model':{'provider':'custom','base_url':LLM,'default':MODEL},
        'toolsets':tools,'platform_toolsets':{'mattermost':tools,'cli':tools},'tools':{'tool_search':{'enabled':False}},
        'agent':{'reasoning_overrides':{MODEL:'none'}},'display':{'platforms':{'mattermost':{
            'streaming':False,'interim_assistant_messages':False,'show_reasoning':False,'thinking_progress':False}}}}
    menv=install_hermes_extensions(data,hu,creds,hc)
    publish(data/'config.yaml',canonical(hc),0o600,hu.pw_uid,hu.pw_gid)
    # Only public-channel membership sync is started; no proactive chat/report.
    need(all('\n' not in v and '\r' not in v for v in menv.values()),'invalid_Mattermost_environment')
    publish(data/'.env',('\n'.join(k+'='+v for k,v in menv.items())+'\n').encode(),0o600,hu.pw_uid,hu.pw_gid)
    soul=readonly_soul()
    publish(data/'SOUL.md',soul.encode(),0o600,hu.pw_uid,hu.pw_gid)
    c=copy.deepcopy(c)
    c['services']['hermes']={'image':images['hermes'],'pull_policy':'never','container_name':NAMES['hermes'],
        'restart':'unless-stopped','environment':{'HERMES_UID':str(hu.pw_uid),'HERMES_GID':str(hu.pw_gid),
            'UV_OFFLINE':'1','PIP_NO_INDEX':'1','TZ':'Asia/Seoul'},'volumes':[{'type':'bind','source':str(data),'target':'/opt/data'}],
        'command':['gateway','run'],'networks':['chat']}
    publish(DEST/'compose.json',canonical(c))
    return hu
def image_probe(image):
    expected=digest(read(SOURCE/'infra/hermes/korean_output_guard.py'))
    pins=query_completion_source_pins()
    code="""import sys,hashlib,pathlib,inspect,json
sys.path.insert(0,'/opt/capstone-guard-runtime/regex-2026.9.29/lib/python3.13/site-packages')
import regex,mcp
assert regex.__version__=='2026.9.29'
p=pathlib.Path('/opt/hermes/capstone_korean_output_guard.py')
assert hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[1]
assert all('capstone_korean_output_guard' in pathlib.Path('/opt/hermes',q).read_text() for q in ['plugins/platforms/mattermost/adapter.py','gateway/run_turn.py'])
# The plugin enforces this same parsed pin set again at gateway startup.
source_pins=json.loads(sys.argv[2])
assert isinstance(source_pins,dict) and source_pins
assert all(hashlib.sha256(pathlib.Path('/opt/hermes',path).read_bytes()).hexdigest()==digest for path,digest in source_pins.items())
from hermes_cli.plugins import PluginContext, VALID_HOOKS
from gateway.hooks import HookRegistry
from gateway.platforms.event import MessageEvent
from gateway.run_inbound import GatewayInboundMixin
from gateway.authz_mixin import GatewayAuthorizationMixin
assert callable(GatewayAuthorizationMixin._intake_adapter_for)
assert 'pre_gateway_dispatch' in VALID_HOOKS
assert callable(PluginContext.register_hook)
assert callable(PluginContext.on_unload)
assert all(callable(getattr(HookRegistry,name,None)) for name in ('discover_and_load','emit','emit_collect'))
assert {'internal','reply_to_text','reply_to_message_id','channel_context'} <= set(MessageEvent.__dataclass_fields__)
assert callable(MessageEvent.is_command)
# Quoted history must be appended after native file-reference expansion.
inbound=inspect.getsource(GatewayInboundMixin._prepare_inbound_message_text)
assert 0 <= inbound.find('_expand_inbound_context_references') < inbound.find('_prepend_inbound_reply_context')
quote=inspect.getsource(GatewayInboundMixin._prepend_inbound_reply_context)
assert 'reply_to_text' in quote and 'reply_to_message_id' in quote
from hermes_cli.tools_config import _get_platform_tools
names=['mcp-wazuh-ro','mcp-security-events']
config={'platform_toolsets':{'mattermost':names},'mcp_servers':{k:{'command':'ssh'} for k in ['wazuh-ro','security-events']}}
assert set(_get_platform_tools(config,'mattermost'))==set(names)
"""
    # No host mounts/network and a unique name+label. If the CLI times out, only
    # this invocation's exact image/label container may be removed.
    nonce=secrets.token_hex(12); name='capstone-siem-image-probe-'+nonce
    try:
        run(['docker','run','--rm','--name',name,'--label','capstone.bootstrap.probe='+nonce,
             '--pull','never','--network','none','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
             '--entrypoint','/opt/hermes/.venv/bin/python','-e','PYTHONDONTWRITEBYTECODE=1',
             '-e','HERMES_HOME=/tmp/hermes',image,'-B','-c',code,expected,canonical(pins).decode()],45)
    finally:
        remaining=run(['docker','ps','-a','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}']).decode().splitlines()
        need(len(remaining)<=1,'private_probe_identity_ambiguous')
        if remaining:
            d=docker_inspect(remaining[0])
            need(d['Name']=='/'+name and d['Image']==image and
                 d['Config']['Labels'].get('capstone.bootstrap.probe')==nonce,'private_probe_identity_changed')
            run(['docker','rm','-f',d['Id']],20)
def mcp_probe():
    # Existing SDK/SSH; two lists and one bounded read of the fresh agent list.
    # No model, chat, response, approval or write tool is called.
    hu=pwd.getpwnam(HERMES_USER)
    code="""import asyncio,os
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
async def one(suffix):
 server=StdioServerParameters(command='/usr/bin/ssh',args=['-T','-F','/opt/data/home/.ssh/config','siem-readonly']+suffix,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
 with open(os.devnull,'w') as errlog:
  async with stdio_client(server,errlog=errlog) as (read,write):
   async with ClientSession(read,write) as session:
    initialized=await session.initialize(); assert initialized.server_info.name
    response=await session.list_tools(); assert response.next_cursor is None
    names={x.name for x in response.tools}; assert len(names)==len(response.tools)
    assert names=={'search_suricata_alerts','search_modsecurity_alerts'} if suffix else (len(names)==14 and 'get_wazuh_agents' in names)
    if not suffix:
     result=await session.call_tool('get_wazuh_agents',{'status':'active'})
     assert not result.isError and len(result.model_dump_json())<1048576
async def main():
 for suffix in ([],['security-events']): await asyncio.wait_for(one(suffix),timeout=40)
asyncio.run(main())
"""
    run(['docker','exec','-i','--user',str(hu.pw_uid)+':'+str(hu.pw_gid),NAMES['hermes'],
         '/opt/hermes/.venv/bin/python','-B','-'],100,code.encode())
def verify():
    saved=parse(read(STATE)); need(saved.get('status')=='applied','successful_apply_receipt_required')
    need(saved.get('profile')==profile(snap,images),'completed_deployment_profile_changed')
    now=current_containers(); need({k:v['id'] for k,v in now.items()}==saved['container_ids'],'container_replacement_requires_review')
    core_health(); mcp_probe()
    h=docker_inspect(NAMES['hermes']); need(h['State']['Running'],'Hermes_not_running')
    data=DEST/HERMES_USER
    log=(data/'logs/gateway.log')
    need(log.is_file() and not log.is_symlink(),'Hermes_gateway_log_missing')
    with open(log,'rb') as f:
        f.seek(max(0,os.fstat(f.fileno()).st_size-1024*1024)); tail=f.read(1024*1024)
    need(b'mattermost connected' in tail.lower() or b'websocket connected' in tail.lower(),'Hermes_Mattermost_connection_not_observed')
    state_path=data/'gateway_state.json'; hs=state_path.lstat()
    need(stat.S_ISREG(hs.st_mode) and hs.st_nlink==1 and hs.st_uid==pwd.getpwnam(HERMES_USER).pw_uid
         and hs.st_size<=65536,'unsafe_Hermes_heartbeat')
    heartbeat=parse(state_path.read_bytes()); stamp=heartbeat.get('updated_at')
    if isinstance(stamp,str):
        parsed=datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))
        need(parsed.tzinfo is not None,'Hermes_heartbeat_timezone_missing'); stamp=parsed.timestamp()
    need(isinstance(stamp,(int,float)) and not isinstance(stamp,bool) and -5<=time.time()-stamp<60 and
         heartbeat.get('gateway_state')=='running','Hermes_heartbeat_not_fresh')
    creds=parse(read(DEST/'app-credentials.json',16384,True))
    readonly_credentials(creds)
    bot,_=api('http://'+IP+':8065/api/v4/users/me',headers={'Authorization':'Bearer '+creds['mattermost_bot_token']})
    need(bot.get('id')==creds['mattermost_bot_id'] and bot.get('is_bot') is True,'Mattermost_bot_authentication_failed')
    return {'schema_version':1,'role':'siem','status':'verified','scope':'base_role','containers':6,'readonly_mcp_servers':2,
            'chat_messages_sent':0,'model_requests_sent':0,'extensions_verified_separately':True,'enrollment_password_configured':True}
try:
    c,snap,images=preflight()
    if STATE.exists():
        print(json.dumps(verify(),sort_keys=True)); sys.exit(0)
    need(MODE!='verify','completed_siem_deployment_required')
    if MODE=='check':
        print(json.dumps({'schema_version':1,'role':'siem','status':'prerequisites_checked','images':6,
              'package_installs':0,'application_health_checked':False,'Hermes_image_runtime_check_pending':True},sort_keys=True)); sys.exit(0)
    phase='prepared_image_validation'; image_probe(images['hermes'])
    # No root state is published until all static prerequisites and offline image imports pass.
    fresh(); phase='files_and_enrollment'; c=prepare_files(c,snap,images)
    phase='log_pipeline_prepare'
    log_pipeline('prepare')
    c=parse(read(DEST/'compose.core.json'))
    run(compose_args(DEST/'compose.core.json')+['config','--quiet'],45)
    phase='core_start'; pending('compose-core-up')
    run(compose_args(DEST/'compose.core.json')+['up','-d','--pull','never'],180)
    phase='core_health'; wait('core',core_health,300)
    manager_id=current_containers(False)['wazuh.manager']['id']
    run(['docker','exec',manager_id,'/var/ossec/bin/wazuh-analysisd','-t'],30)
    run(['docker','exec',manager_id,'/var/ossec/bin/wazuh-authd','-t'],30)
    log_pipeline('activate')
    phase='application_accounts'; creds=app_bootstrap()
    phase='readonly_MCP_and_Hermes'; setup_mcp_and_hermes(c,images,creds)
    run(compose_args(DEST/'compose.json')+['config','--quiet'],45)
    phase='Hermes_start'; pending('compose-Hermes-up')
    run(compose_args(DEST/'compose.json')+['up','-d','--no-deps','--pull','never','hermes'],120)
    wait('Hermes_running',lambda:current_containers(),120)
    phase='readonly_MCP_verification'; mcp_probe()
    snapshot=current_containers()
    publish(STATE,canonical({'schema_version':1,'role':'siem','status':'applied','hosts':HOSTS,
            'profile':profile(snap,images),
            'container_ids':{k:v['id'] for k,v in snapshot.items()},'images':images,
            'readonly_mcp_servers':2,'write_approval_configured':False,'chat_messages_sent':0,'model_requests_sent':0}))
    phase='final_health'; result=wait('Hermes_Mattermost',verify,120)
    publish(DEST/'verified.json',canonical(result)); print(json.dumps(result,sort_keys=True))
except Exception as error:
    code=str(error) if isinstance(error,Refused) else type(error).__name__
    # Errors expose fixed codes only. HTTP bodies, credentials and full commands stay private.
    result={'schema_version':1,'role':'siem','status':'failed','phase':phase,'reason':code,
            'partial_installation':changed,'automatic_retry':False,'rollback_automatic':False}
    if changed:
        try: publish(DEST/('failure-'+str(time.time_ns())+'.json'),canonical(result))
        except Exception: pass
    print(json.dumps(result,sort_keys=True),file=sys.stderr); sys.exit(78)
PY
