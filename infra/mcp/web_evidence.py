#!/usr/bin/env python3
"""Bounded, sanitized Apache evidence. No request-supplied file or command.

Root periodically publishes a fixed file; a dedicated restricted reader may
read that file using B's existing diagnostic public identity. No raw logs or
grant an actuator. File/index completeness is not logging continuity.
"""
from datetime import datetime, timedelta, timezone
import argparse
import grp
import gzip
import hashlib
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

KST = timezone(timedelta(hours=9))
STATE = Path('/var/lib/capstone-web-evidence')
SNAPSHOT = STATE / 'snapshot.json'
LOGS = Path('/var/log/apache2')
APACHE = Path('/etc/apache2')
WEBROOT = Path('/var/www/html')
CLIENT_KEYS = Path('/var/ossec/etc/client.keys')
TTL = 180
HISTORY = 14 * 86400
MAX_FILES = 15
MAX_INPUT = 8 * 1024 * 1024
MAX_SNAPSHOT = 4 * 1024 * 1024
MAX_ROWS = 10000
MAX_LINE = 16384
MAX_LIMIT = 50
TARGETS = {
    'c:dvwa': '/dvwa/',
    'c:lab-console': '/_offline-labs/',
    'c:lab-java': '/_offline-lab-java/',
    'c:lab-httpd49': '/_offline-lab-httpd49/',
    'c:lab-httpd50': '/_offline-lab-httpd50/',
}
FIELDS = {'timestamp_kst', 'source_ip', 'method', 'path', 'path_truncated', 'path_sha256',
          'entry_sha256', 'status', 'response_bytes', 'query_present', 'log_file'}
ACCESS = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]{1,20})\s+((?:\\.|[^"\s])+)\s+HTTP/[0-9.]+"\s+([0-9]{3})\s+([0-9]+|-)\s')
FILE = re.compile(r'access\.log(?:\.([1-9]|1[0-4])(\.gz)?)?\Z')


def need(value, code):
    if not value:
        raise ValueError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_key')
        result[key] = value
    return result


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))+'\n').encode()


def safe_directory(path, meta, log_path=False, registration=False):
    safe=not meta.st_mode & 0o022
    # Ubuntu's /var/log is root:syslog 0775. Only this exact ancestor
    # may be group-writable; every opened child/file remains root-owned,
    # non-writable and symlink-free. Traverse with dirfds to pin ancestry.
    if not safe and log_path and path==Path('/var/log') and stat.S_IMODE(meta.st_mode)==0o775:
        try:safe=meta.st_gid==grp.getgrnam('syslog').gr_gid
        except KeyError:safe=False
    owner=meta.st_uid==0
    if registration and path==CLIENT_KEYS.parent:
        user=pwd.getpwnam('wazuh');group=grp.getgrnam('wazuh')
        owner=meta.st_uid in (0,user.pw_uid) and meta.st_gid==group.gr_gid
        safe=not meta.st_mode&0o007 and stat.S_IMODE(meta.st_mode) in (0o750,0o770)
    need(stat.S_ISDIR(meta.st_mode) and owner and safe,'unsafe_parent')


def parents(path):
    log_path=Path(path).is_relative_to(LOGS)
    for item in (Path(path), *Path(path).parents):
        meta = item.lstat()
        safe_directory(item,meta,log_path)


def root_open(path, maximum):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts,'unsafe_path')
    log_path=path.is_relative_to(LOGS)
    registration=path==CLIENT_KEYS
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        safe_directory(Path('/'),os.fstat(parent),log_path,registration)
        current=Path('/')
        for part in path.parts[1:-1]:
            current/=part
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
            safe_directory(current,os.fstat(parent),log_path,registration)
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:os.close(parent)
    try:
        meta = os.fstat(fd)
        owner=meta.st_uid==0
        if registration:
            owner=meta.st_uid in (0,pwd.getpwnam('wazuh').pw_uid) and meta.st_gid==grp.getgrnam('wazuh').gr_gid
        need(stat.S_ISREG(meta.st_mode) and owner and meta.st_nlink == 1
             and not meta.st_mode & 0o022 and meta.st_size <= maximum, 'unsafe_file')
        return os.fdopen(fd, 'rb'), meta
    except Exception:
        os.close(fd)
        raise


def parse_access(raw, filename):
    """Return no query, credentials, headers, referrer or request body."""
    match = ACCESS.match(raw.decode('utf-8', 'replace'))
    if not match:
        return None
    ip, stamp, method, target, status_code, length = match.groups()
    try:
        address = str(ipaddress.ip_address(ip))
        instant = datetime.strptime(stamp, '%d/%b/%Y:%H:%M:%S %z').astimezone(KST)
        # Apache writes escapes verbatim. Do not decode attacker-controlled text.
        path = urlsplit(target).path
        need(path.startswith('/') and not re.search(r'[\x00-\x20\x7f]', path), 'invalid_path')
        code = int(status_code)
        need(100 <= code <= 599 and len(target) <= MAX_LINE, 'invalid_request')
        byte_count = None if length == '-' else int(length)
        need(byte_count is None or byte_count <= 2**63-1, 'invalid_size')
    except (ValueError, OverflowError):
        return None
    return {'timestamp_kst': instant.isoformat(), 'source_ip': address,
            'method': method if method in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE') else 'OTHER',
            'path': path[:240], 'path_truncated':len(path)>240, 'path_sha256': hashlib.sha256(path.encode()).hexdigest(),
            'entry_sha256': hashlib.sha256(raw).hexdigest(), 'status': code,
            'response_bytes': byte_count, 'query_present': '?' in target, 'log_file': filename}


def agent_identity():
    try:
        with root_open(CLIENT_KEYS, 65536)[0] as source:
            lines = source.read(65537).decode().splitlines()
        rows = [line.split() for line in lines if line.strip()]
        need(len(rows) == 1 and len(rows[0]) == 4 and re.fullmatch(r'[0-9]{3,8}', rows[0][0])
             and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', rows[0][1]), 'agent_identity_unavailable')
        return {'id': rows[0][0], 'name': rows[0][1]}
    except (OSError, ValueError, UnicodeError, KeyError):
        return {'id': None, 'name': None}


def configuration():
    records, directives = [], []
    for directory in ('sites-enabled', 'conf-enabled'):
        for candidate in sorted((APACHE / directory).glob('*.conf')):
            try:
                resolved = candidate.resolve(strict=True)
                need(resolved.is_relative_to(APACHE.resolve()), 'configuration_outside_apache')
                with root_open(resolved, 131072)[0] as source:
                    data = source.read(131073)
                records.append({'path': str(candidate), 'sha256': hashlib.sha256(data).hexdigest()})
                directives.extend(line.strip() for line in data.decode('utf-8', 'replace').splitlines()
                                  if re.match(r'^\s*(DocumentRoot|ProxyPass|CustomLog)\s', line))
            except (OSError, ValueError):
                records.append({'path': str(candidate), 'sha256': None})
    standard_log = any(re.search(r'^CustomLog\s+\"?\$\{APACHE_LOG_DIR\}/access\.log\"?\s+combined\s*$', line) for line in directives)
    docroot = any(re.fullmatch(r'DocumentRoot\s+\"?/var/www/html\"?\s*', line) for line in directives)
    targets = {}
    for target, prefix in TARGETS.items():
        configured = (docroot and (WEBROOT/'dvwa').is_dir()) if target == 'c:dvwa' else any(
            re.match(r'^ProxyPass\s+\"?'+re.escape(prefix)+r'\"?\s+', line) for line in directives)
        targets[target] = {'backend_role': 'c', 'request_path_prefix': prefix,
                           'configured_in_file_snapshot': bool(configured),
                           'diagnostic_target': 'c:apache', 'frontend_binding_verified': False,
                           'runtime_configuration_load_verified': False}
    return {'files': records, 'standard_access_log_configured': standard_log,
            'configuration_sha256': hashlib.sha256(encoded(records)).hexdigest(), 'targets': targets}


def collect(now=None):
    now = int(time.time()) if now is None else now
    need(os.geteuid() == 0, 'collector_root_required')
    parents(LOGS)
    candidates = sorted((p for p in LOGS.iterdir() if FILE.fullmatch(p.name)),
                        key=lambda p: int(FILE.fullmatch(p.name)[1] or 0))
    coverage = {'bytes_scanned': 0, 'malformed_lines': 0, 'files_unavailable': 0,
                'scan_limited': len(candidates) > MAX_FILES, 'rows_truncated': False,
                'logging_continuity_verified': False}
    rows, files = [], []
    for path in candidates[:MAX_FILES]:
        if coverage['bytes_scanned'] >= MAX_INPUT:
            coverage['scan_limited'] = True
            break
        try:
            source, before = root_open(path, MAX_INPUT)
            count = 0;file_rows=[];fingerprint=hashlib.sha256()
            with source:
                stream = gzip.GzipFile(fileobj=source) if path.suffix == '.gz' else source
                try:
                    while True:
                        remaining = MAX_INPUT-coverage['bytes_scanned']
                        if remaining <= 0:
                            coverage['scan_limited'] = True
                            break
                        line = stream.readline(min(MAX_LINE+1, remaining))
                        if not line:
                            break
                        count += len(line);coverage['bytes_scanned'] += len(line)
                        fingerprint.update(line)
                        if not line.endswith(b'\n') or len(line) > MAX_LINE:
                            coverage['scan_limited'] = True;coverage['malformed_lines'] += 1
                            continue
                        row = parse_access(line, path.name)
                        if row is None:
                            coverage['malformed_lines'] += 1
                        elif now-HISTORY <= datetime.fromisoformat(row['timestamp_kst']).timestamp() <= now:
                            file_rows.append(row)
                        if len(file_rows) >= MAX_ROWS*2:
                            coverage['rows_truncated'] = True
                            file_rows = sorted(file_rows, key=lambda r:r['timestamp_kst'], reverse=True)[:MAX_ROWS]
                finally:
                    if stream is not source:
                        stream.close()
                after = os.fstat(source.fileno())
            changed = (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns)
            files.append({'name': path.name, 'inode': before.st_ino, 'size_at_open': before.st_size,
                          'decompressed_bytes_scanned': count, 'decompressed_prefix_sha256':fingerprint.hexdigest(), 'changed_during_read': changed})
            coverage['scan_limited'] |= changed
            rows.extend(file_rows)
            if len(rows)>MAX_ROWS*2:
                coverage['rows_truncated']=True
                rows=sorted(rows,key=lambda r:r['timestamp_kst'],reverse=True)[:MAX_ROWS]
        except (OSError, ValueError, EOFError):
            coverage['files_unavailable'] += 1
    coverage['scan_limited'] |= coverage['files_unavailable'] > 0 or not files
    coverage['rows_truncated'] |= len(rows) > MAX_ROWS
    rows = sorted(rows, key=lambda r:(r['timestamp_kst'],r['entry_sha256']), reverse=True)[:MAX_ROWS]
    config = configuration()
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', 'apache2.service', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState'],
                                capture_output=True, text=True, timeout=3, env={'PATH':'/usr/bin:/bin','LANG':'C'})
        unit = dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line) if result.returncode == 0 else {}
        need(set(unit) == {'LoadState','ActiveState','SubState'} and all(re.fullmatch('[a-z-]{1,48}',v) for v in unit.values()), 'unit_unavailable')
    except (OSError, ValueError, subprocess.TimeoutExpired):
        unit = {'LoadState':None, 'ActiveState':None, 'SubState':None}
    value = {'schema':1, 'host':'c', 'checked_at':now, 'expires_at':now+TTL, 'retained_seconds':HISTORY,
            'agent':agent_identity(), 'configuration':config, 'apache_unit':unit,
            'coverage':coverage, 'files':files, 'records':rows}
    while len(encoded(value)) > MAX_SNAPSHOT and value['records']:
        value['coverage']['rows_truncated'] = True
        value['records'] = value['records'][:len(value['records'])//2]
    return value


def validate(value, now=None):
    now = int(time.time()) if now is None else now
    need(isinstance(value,dict) and set(value)=={'schema','host','checked_at','expires_at','retained_seconds','agent','configuration','apache_unit','coverage','files','records'}
         and value['schema']==1 and value['host']=='c' and type(value['checked_at']) is int
         and value['expires_at']==value['checked_at']+TTL and value['checked_at'] <= now+5 <= value['expires_at']+5
         and value['retained_seconds']==HISTORY, 'snapshot_invalid_or_stale')
    need(isinstance(value['configuration'],dict) and set(value['configuration']['targets'])==set(TARGETS), 'target_catalog_invalid')
    configuration=value['configuration']
    need(set(configuration)=={'files','standard_access_log_configured','configuration_sha256','targets'}
         and type(configuration['standard_access_log_configured']) is bool
         and re.fullmatch('[0-9a-f]{64}',str(configuration['configuration_sha256']))
         and isinstance(configuration['files'],list) and len(configuration['files'])<=64,'configuration_invalid')
    for target,row in configuration['targets'].items():
        need(isinstance(row,dict) and set(row)=={'backend_role','request_path_prefix','configured_in_file_snapshot','diagnostic_target','frontend_binding_verified','runtime_configuration_load_verified'}
             and row['backend_role']=='c' and row['request_path_prefix']==TARGETS[target]
             and row['diagnostic_target']=='c:apache' and type(row['configured_in_file_snapshot']) is bool
             and row['frontend_binding_verified'] is False and row['runtime_configuration_load_verified'] is False,'service_binding_invalid')
    for item in configuration['files']:
        need(isinstance(item,dict) and set(item)=={'path','sha256'} and isinstance(item['path'],str)
             and re.fullmatch(r'/etc/apache2/(?:sites|conf)-enabled/[A-Za-z0-9_.-]+\.conf',item['path'])
             and (item['sha256'] is None or re.fullmatch('[0-9a-f]{64}',str(item['sha256']))),'configuration_file_invalid')
    agent=value['agent']
    need(isinstance(agent,dict) and set(agent)=={'id','name'} and
         (agent=={'id':None,'name':None} or isinstance(agent['id'],str) and re.fullmatch('[0-9]{3,8}',agent['id'])
          and isinstance(agent['name'],str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}',agent['name'])),'agent_invalid')
    need(isinstance(value['apache_unit'],dict) and set(value['apache_unit'])=={'LoadState','ActiveState','SubState'}
         and all(v is None or isinstance(v,str) and re.fullmatch('[a-z-]{1,48}',v) for v in value['apache_unit'].values()),'unit_invalid')
    need(isinstance(value['coverage'],dict) and set(value['coverage'])=={'bytes_scanned','malformed_lines','files_unavailable','scan_limited','rows_truncated','logging_continuity_verified'}
         and value['coverage']['logging_continuity_verified'] is False, 'coverage_invalid')
    need(all(type(value['coverage'][k]) is int and 0<=value['coverage'][k]<=MAX_INPUT for k in ('bytes_scanned','malformed_lines','files_unavailable'))
         and all(type(value['coverage'][k]) is bool for k in ('scan_limited','rows_truncated'))
         and (not value['coverage']['files_unavailable'] or value['coverage']['scan_limited']),'coverage_counts_invalid')
    need(isinstance(value['records'],list) and len(value['records']) <= MAX_ROWS and isinstance(value['files'],list) and len(value['files']) <= MAX_FILES, 'row_bound')
    files=set()
    for item in value['files']:
        need(isinstance(item,dict) and set(item)=={'name','inode','size_at_open','decompressed_bytes_scanned','decompressed_prefix_sha256','changed_during_read'}
             and isinstance(item['name'],str) and FILE.fullmatch(item['name']) and item['name'] not in files
             and all(type(item[k]) is int and 0<=item[k]<=2**63-1 for k in ('inode','size_at_open','decompressed_bytes_scanned'))
             and re.fullmatch('[0-9a-f]{64}',str(item['decompressed_prefix_sha256']))
             and type(item['changed_during_read']) is bool,'source_file_invalid')
        files.add(item['name'])
    for row in value['records']:
        need(isinstance(row,dict) and set(row)==FIELDS and isinstance(row['path'],str) and len(row['path'])<=240
             and row['path'].startswith('/') and '?' not in row['path'] and '#' not in row['path']
             and re.fullmatch('[0-9a-f]{64}',row['path_sha256']) and re.fullmatch('[0-9a-f]{64}',row['entry_sha256'])
             and row['log_file'] in files and type(row['status']) is int and 100<=row['status']<=599
             and type(row['query_present']) is bool and type(row['path_truncated']) is bool and row['method'] in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','CONNECT','TRACE','OTHER')
             and (row['response_bytes'] is None or type(row['response_bytes']) is int and 0<=row['response_bytes']<=2**63-1), 'row_invalid')
        ipaddress.ip_address(row['source_ip'])
        stamp=datetime.fromisoformat(row['timestamp_kst'])
        need(stamp.utcoffset()==timedelta(hours=9) and value['checked_at']-HISTORY <= stamp.timestamp() <= value['checked_at'], 'row_time')
    need(len(encoded(value))<=MAX_SNAPSHOT,'snapshot_byte_bound')
    return value


def publish(value):
    need(os.geteuid()==0,'publisher_root_required');validate(value)
    gid=grp.getgrnam('capstone-diagnostics').gr_gid
    STATE.mkdir(mode=0o750,parents=True,exist_ok=True);parents(STATE)
    os.chown(STATE,0,gid);os.chmod(STATE,0o750)
    fd, temporary=tempfile.mkstemp(prefix='.snapshot-',dir=STATE)
    try:
        with os.fdopen(fd,'wb') as output:
            output.write(encoded(value));output.flush();os.fsync(output.fileno())
        os.chown(temporary,0,gid);os.chmod(temporary,0o640);os.replace(temporary,SNAPSHOT)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def read_snapshot(now=None):
    source,meta=root_open(SNAPSHOT,MAX_SNAPSHOT)
    need(meta.st_gid==grp.getgrnam('capstone-diagnostics').gr_gid and stat.S_IMODE(meta.st_mode)==0o640,'snapshot_access_invalid')
    with source:raw=source.read(MAX_SNAPSHOT+1)
    return validate(json.loads(raw,object_pairs_hook=unique),now)


def request(value, now=None):
    now = datetime.now(KST) if now is None else now
    need(isinstance(value,dict) and set(value) == {'operation','arguments'} and value['operation'] in ('get_web_service_target','search_web_access'),'operation_invalid')
    args=value['arguments'];need(isinstance(args,dict) and args.get('target') in TARGETS,'target_invalid')
    if value['operation']=='get_web_service_target':
        need(set(args)=={'target'},'arguments_invalid');return value
    need({'target'} <= set(args) <= {'target','since_kst','until_kst','lookback_minutes','source_ip','limit'},'arguments_invalid')
    args=dict(args)
    try:
        if 'since_kst' in args:
            need('until_kst' in args and 'lookback_minutes' not in args,'explicit_interval_required')
        else:
            minutes=args.pop('lookback_minutes',60)
            need(type(minutes) is int and 1<=minutes<=1440,'lookback_invalid')
            end=datetime.fromisoformat(args['until_kst']) if 'until_kst' in args else now
            need(end.utcoffset()==timedelta(hours=9),'until_timezone_invalid')
            args.update(since_kst=(end-timedelta(minutes=minutes)).isoformat(),until_kst=end.isoformat())
        start,end=(datetime.fromisoformat(args[k]) for k in ('since_kst','until_kst'))
        need(start.utcoffset()==end.utcoffset()==timedelta(hours=9)
             and start<end<=now and end-start<=timedelta(days=1) and start>=now-timedelta(seconds=HISTORY),'time_scope_invalid')
        if 'source_ip' in args:need(str(ipaddress.ip_address(args['source_ip']))==args['source_ip'],'source_ip_invalid')
        need(type(args.get('limit',10)) is int and 1<=args.get('limit',10)<=MAX_LIMIT,'limit_invalid')
    except (ValueError,TypeError,OverflowError):
        raise ValueError('query_scope_invalid') from None
    return {'operation':value['operation'],'arguments':args}


def answer(value, snapshot, now=None):
    now=datetime.now(KST) if now is None else now
    value=request(value,now);validate(snapshot,int(now.timestamp()));args=value['arguments'];target=args['target']
    result={'schema':1,'target':target,'source':'c_apache_access_snapshot','observed_at_kst':datetime.fromtimestamp(snapshot['checked_at'],KST).isoformat(),
            'queried_at_kst':now.isoformat(),'age_seconds':int(now.timestamp())-snapshot['checked_at'],
            'agent':snapshot['agent'],'agent_identity_source':'local_wazuh_registration_not_destination_attestation',
            'service':snapshot['configuration']['targets'][target],
            'apache_unit':snapshot['apache_unit'],'configuration_sha256':snapshot['configuration']['configuration_sha256'],
            'standard_access_log_configured':snapshot['configuration']['standard_access_log_configured'],
            'untrusted_evidence':True,'mutation_performed':False,'logging_continuity_verified':False,
            'identity_scope':'log_line_bytes_not_unique_http_transaction',
            'evidence_scope_ko':'C Apache 접근 로그를 제한하여 정제한 파일 표본입니다. 원본 질의 문자열·헤더·쿠키·본문은 반환하지 않습니다. 설정 파일/Apache 프로세스 관측은 앱 정상·침해 부재·프런트 경로 적재 증명이 아닙니다. 반환0건은 전체 요청 부재를 증명하지 않습니다. 행 SHA는 동일 바이트 식별이며 고유 HTTP 거래 ID가 아닙니다.'}
    if value['operation']=='get_web_service_target':return result
    prefix=TARGETS[target];start,end=(datetime.fromisoformat(args[k]) for k in ('since_kst','until_kst'))
    rows=[r for r in snapshot['records'] if (r['path'].startswith(prefix) or r['path']==prefix.rstrip('/'))
          and start<=datetime.fromisoformat(r['timestamp_kst'])<=end
          and ('source_ip' not in args or r['source_ip']==args['source_ip'])]
    limit=args.get('limit',10)
    result.update(requested_since_kst=start.isoformat(),requested_until_kst=end.isoformat(),returned_count=min(limit,len(rows)),
                  retained_index_match_count=len(rows),actual_request_total_count=None,returned_rows_truncated=len(rows)>limit,
                  coverage=snapshot['coverage'],source_files=snapshot['files'],records=rows[:limit])
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--collect',action='store_true',required=True);parser.parse_args()
    try:publish(collect())
    except (OSError,ValueError,KeyError,TypeError,UnicodeError):raise SystemExit('web_evidence_collection_unavailable') from None


if __name__=='__main__':main()
