#!/usr/bin/env python3
"""Import the shipped SOC saved objects without overwrites or external dependencies.

Only the default OpenSearch Dashboards 2.19.6 scope is supported. The caller must
configure multitenancy/workspaces off; no tenant, workspace or namespace is chosen
implicitly. API contract: OpenSearch-Dashboards/2.19.6, core saved_objects routes.
No event searches, browser rendering, or actual detection validation are performed.
"""
import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

PREFIX = 'groot-soc-20261019-'
PATTERN = 'wazuh-alerts-*'
DASHBOARD = PREFIX + 'dashboard'
VERSION = '2.19.6'
SOURCE = Path('infra/groot-b/soc-dashboard')
LIMIT = 4 * 1024 * 1024
COMMON = 'NOT rule.groups:(capstone_vector_evidence OR capstone_observation OR capstone_vector_canary OR capstone_validation OR package_shadow)'
JSON_ATTRIBUTES = {'visState', 'uiStateJSON', 'panelsJSON', 'optionsJSON', 'searchSourceJSON', 'fields'}
FIELD_TYPES = {
    'timestamp': ('date', 'date'), 'rule.level': ('number', 'long'),
    **{name: ('string', 'keyword') for name in (
        'rule.id', 'rule.description', 'rule.groups', 'agent.name', 'agent.id',
        'data.src_ip', 'data.dest_ip', 'data.dest_port', 'data.alert.signature',
        'data.alert.category', 'data.transaction.client_ip',
        'data.transaction.request.uri', 'data.transaction.response.http_code')},
}


class Refused(RuntimeError):
    """Fixed, non-sensitive diagnostic codes only."""


def need(condition, code):
    if not condition:
        raise Refused(code)


def unique(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def parse(data):
    try:
        return json.loads(data, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused('non_finite_json')))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise Refused('invalid_json') from None


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def semantic(value, key=None):
    if key in JSON_ATTRIBUTES and isinstance(value, str):
        return semantic(parse(value))
    if isinstance(value, dict):
        return {k: semantic(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [semantic(v) for v in value]
    return value


def normalized(obj):
    need(isinstance(obj, dict) and all(k in obj for k in ('type', 'id', 'attributes', 'references')),
         'invalid_saved_object')
    need(isinstance(obj['attributes'], dict) and isinstance(obj['references'], list), 'invalid_saved_object')
    result = {k: copy.deepcopy(obj[k]) for k in ('type', 'id', 'attributes', 'references')}
    # Reference list order is not meaningful; attribute array order is.
    for ref in result['references']:
        need(isinstance(ref, dict) and set(ref) == {'type', 'id', 'name'}
             and all(isinstance(v, str) and 0 < len(v) <= 512 for v in ref.values()),
             'invalid_saved_object_reference')
    result['references'].sort(key=lambda item: (item['name'], item['type'], item['id']))
    return semantic(result)


def load_bundle(source_root):
    """Read ordinary project files. The role pins the source archive separately."""
    root = Path(source_root) / SOURCE
    loaded = []
    for name in ('generated/soc-dashboard.ndjson', 'live-export-20261019.ndjson'):
        path = root / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= LIMIT,
             'unsafe_dashboard_source')
        lines = path.read_bytes().splitlines()
        need(15 <= len(lines) <= 16, 'dashboard_source_count')
        data = [parse(line) for line in lines]
        if len(data) == 16:
            footer = data.pop()
            need(footer == {'exportedCount': 15, 'missingRefCount': 0, 'missingReferences': []},
                 'dashboard_export_incomplete')
        loaded.append(data)
    generated, exported = loaded
    objects = {(obj.get('type'), obj.get('id')): obj for obj in generated if isinstance(obj, dict)}
    need(len(objects) == 15, 'dashboard_source_count')
    need({kind: sum(key[0] == kind for key in objects) for kind in ('visualization', 'search', 'dashboard')}
         == {'visualization': 13, 'search': 1, 'dashboard': 1}, 'dashboard_source_types')
    for obj in generated:
        need(set(obj) == {'type', 'id', 'attributes', 'references'} and
             isinstance(obj['id'], str) and re.fullmatch(PREFIX + r'[a-z0-9-]+', obj['id']),
             'foreign_dashboard_source')
        normalized(obj)
        source = parse(obj['attributes'].get('kibanaSavedObjectMeta', {}).get('searchSourceJSON', ''))
        need(isinstance(source, dict) and source.get('filter') == [] and
             isinstance(source.get('query'), dict) and source['query'].get('language') == 'lucene' and
             COMMON in source['query'].get('query', ''), 'dashboard_source_query')
        names = [ref['name'] for ref in obj['references']]
        need(len(names) == len(set(names)), 'duplicate_reference_name')
        for ref in obj['references']:
            need((ref['type'] == 'index-pattern' and ref['id'] == PATTERN) or
                 (ref['type'], ref['id']) in objects, 'dashboard_source_dangling_reference')
    need(('dashboard', DASHBOARD) in objects, 'dashboard_source_id')
    attrs = objects[('dashboard', DASHBOARD)]['attributes']
    need(attrs.get('timeRestore') is True and attrs.get('timeFrom') == 'now-7d' and attrs.get('timeTo') == 'now'
         and attrs.get('refreshInterval') == {'pause': False, 'value': 30000}
         and len(parse(attrs.get('panelsJSON', ''))) == 14, 'dashboard_source_defaults')
    need(sorted((normalized(obj) for obj in generated), key=lambda item: item['id']) ==
         sorted((normalized(obj) for obj in exported), key=lambda item: item['id']),
         'dashboard_export_generated_differ')
    # Publish dependency objects first, dashboard last. No source code is imported.
    return sorted(generated, key=lambda item: (item['type'] == 'dashboard', item['id']))


def safe_parents(path, allow_staging=False):
    for parent in (Path(path), *Path(path).parents):
        info = parent.lstat()
        staging = allow_staging and parent == Path('/var/tmp') and stat.S_IMODE(info.st_mode) == 0o1777
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and (staging or not info.st_mode & 0o022),
             'unsafe_dashboard_directory')


def safe_read(path, limit=LIMIT, private=False):
    path = Path(path)
    need(path.is_absolute(), 'absolute_dashboard_path_required')
    safe_parents(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
         and not before.st_mode & 0o022 and before.st_size <= limit, 'unsafe_dashboard_file')
    need(not private or stat.S_IMODE(before.st_mode) == 0o600, 'dashboard_secret_requires_root_0600')
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(fd)) == identity(before), 'dashboard_file_changed')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            result = stream.read(limit + 1)
        need(len(result) == before.st_size and identity(os.fstat(fd)) == identity(before)
             and identity(path.lstat()) == identity(before), 'dashboard_file_changed')
        return result
    finally:
        os.close(fd)


def credentials(path):
    data = parse(safe_read(path, 16384, private=True))
    need(isinstance(data, dict) and type(data.get('schema_version')) is int and data['schema_version'] == 1
         and data.get('indexer_username') == 'admin' and isinstance(data.get('indexer_password'), str),
         'dashboard_credentials_schema')
    password = data['indexer_password']
    need(8 <= len(password) <= 256 and len(password.encode()) <= 1024, 'dashboard_credentials_invalid')
    return 'admin', password


def endpoint(value):
    try:
        url = urllib.parse.urlsplit(value)
        need(url.scheme == 'https' and url.hostname and not url.username and not url.password
             and not url.query and not url.fragment and url.path in ('', '/'), 'dashboard_https_origin_required')
        need(url.port is None or 1 <= url.port <= 65535, 'dashboard_https_origin_required')
        # This role only uses an IP/DNS origin, never a tenant or workspace base path.
        try:
            ipaddress.ip_address(url.hostname)
        except ValueError:
            need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', url.hostname), 'dashboard_https_origin_required')
        need(not any(ord(ch) <= 32 or ord(ch) == 127 for ch in value), 'dashboard_https_origin_required')
    except (ValueError, AttributeError):
        raise Refused('dashboard_https_origin_required') from None
    return value.rstrip('/')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, url, username, password, ca_file):
        self.url = endpoint(url)
        ca = safe_read(ca_file, 128 * 1024)
        try:
            context = ssl.create_default_context(cadata=ca.decode('ascii'))
        except (UnicodeError, ssl.SSLError):
            raise Refused('dashboard_ca_invalid') from None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                                  urllib.request.HTTPSHandler(context=context))
        self.authorization = 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode()

    def request(self, method, path, body=None, statuses=(200,)):
        need(method in ('GET', 'POST') and path.startswith('/api/') and not path.startswith('//')
             and '\r' not in path and '\n' not in path, 'dashboard_api_request_invalid')
        headers = {'Authorization': self.authorization, 'osd-xsrf': 'capstone-soc-bootstrap',
                   'Accept': 'application/json'}
        data = None if body is None else encoded(body)
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Refused('dashboard_api_unavailable') from None
        try:
            with response:
                payload = response.read(LIMIT + 1)
                need(len(payload) <= LIMIT, 'dashboard_api_response_limit')
                need(response.status in statuses, 'dashboard_api_http_' + str(response.status))
                return response.status, parse(payload)
        except (TimeoutError, OSError):
            raise Refused('dashboard_api_unavailable') from None


def object_path(kind, object_id):
    need(kind in ('index-pattern', 'visualization', 'search', 'dashboard') and isinstance(object_id, str)
         and 0 < len(object_id) <= 512 and not any(ord(ch) < 32 for ch in object_id), 'saved_object_identity')
    return '/api/saved_objects/' + kind + '/' + urllib.parse.quote(object_id, safe='')


def get_object(client, kind, object_id):
    status, data = client.request('GET', object_path(kind, object_id), statuses=(200, 404))
    if status == 404:
        return None
    need(isinstance(data, dict) and 'error' not in data and data.get('id') == object_id
         and data.get('type') == kind, 'dashboard_api_identity_mismatch')
    normalized(data)
    # Other namespaces/workspaces are never adopted into the default scope.
    need(data.get('namespaces') in (None, [], ['default']) and data.get('workspaces') in (None, []),
         'dashboard_nondefault_scope_unsupported')
    return data


def validate_pattern(obj):
    attrs = obj.get('attributes', {})
    need(attrs.get('title') == PATTERN and attrs.get('timeFieldName') == 'timestamp',
         'dashboard_index_pattern_incompatible')
    need(not attrs.get('sourceFilters') or parse(attrs['sourceFilters']) == [],
         'dashboard_index_pattern_source_filters')
    if 'fields' in attrs:
        fields = parse(attrs['fields'])
        need(isinstance(fields, list) and all(isinstance(field, dict) and isinstance(field.get('name'), str)
                                             for field in fields), 'dashboard_index_pattern_fields')
        by_name = {field['name']: field for field in fields}
        need(len(by_name) == len(fields), 'dashboard_index_pattern_fields')
        for name, (kind, _) in FIELD_TYPES.items():
            field = by_name.get(name)
            # Existing incomplete/empty caches are not silently rewritten.
            need(field and field.get('type') == kind and field.get('searchable') is True
                 and field.get('aggregatable') is True and not field.get('scripted', False),
                 'dashboard_index_pattern_field_incompatible')
    else:
        raise Refused('dashboard_index_pattern_fields_missing')


def minimal_pattern(object_id):
    fields = [{'name': name, 'type': kind, 'esTypes': [native], 'count': 0, 'scripted': False,
               'searchable': True, 'aggregatable': True, 'readFromDocValues': True}
              for name, (kind, native) in sorted(FIELD_TYPES.items())]
    return {'type': 'index-pattern', 'id': object_id, 'references': [],
            'attributes': {'title': PATTERN, 'timeFieldName': 'timestamp', 'fields': encoded(fields).decode()}}


def find_pattern(client, explicit_id=None):
    if explicit_id is not None:
        found = get_object(client, 'index-pattern', explicit_id)
        if found:
            validate_pattern(found)
        return explicit_id, found
    # Enumerate metadata only, without a Lucene search containing wildcard syntax.
    candidates = []
    for page in range(1, 21):
        path = '/api/saved_objects/_find?' + urllib.parse.urlencode(
            {'type': 'index-pattern', 'page': page, 'per_page': 100})
        _, data = client.request('GET', path)
        need(isinstance(data, dict) and isinstance(data.get('saved_objects'), list)
             and type(data.get('total')) is int and 0 <= data['total'] <= 2000,
             'dashboard_index_pattern_listing')
        rows = data['saved_objects']
        need(len(rows) <= 100, 'dashboard_index_pattern_listing')
        for obj in rows:
            need(isinstance(obj, dict) and obj.get('type') == 'index-pattern'
                 and isinstance(obj.get('attributes'), dict), 'dashboard_index_pattern_listing')
            if obj['attributes'].get('title') == PATTERN:
                candidates.append(obj)
        if page * 100 >= data['total']:
            break
    need(len(candidates) <= 1, 'dashboard_index_pattern_ambiguous')
    if candidates:
        found = get_object(client, 'index-pattern', candidates[0].get('id'))
        need(found is not None, 'dashboard_index_pattern_changed')
        validate_pattern(found)
        return found['id'], found
    # A different pattern using our default ID is a conflict, never overwritten.
    found = get_object(client, 'index-pattern', PATTERN)
    if found:
        validate_pattern(found)
    return PATTERN, found


def create_missing(client, obj):
    body = {key: obj[key] for key in ('attributes', 'references')}
    status, _ = client.request('POST', object_path(obj['type'], obj['id']) + '?overwrite=false',
                               body, statuses=(200, 201, 409))
    # A concurrent exact creation is acceptable; no retry/overwrite is issued.
    actual = get_object(client, obj['type'], obj['id'])
    need(actual is not None and normalized(actual) == normalized(obj), 'dashboard_created_object_differs')
    return status != 409


def reconcile(client, objects, action='verify', index_pattern_id=None):
    """Create missing exact objects once; a partial failure is safely resumable."""
    need(action in ('apply', 'verify'), 'dashboard_action_invalid')
    _, status = client.request('GET', '/api/status')
    need(isinstance(status, dict) and status.get('version', {}).get('number') == VERSION,
         'dashboard_version_unsupported')
    need(status.get('status', {}).get('overall', {}).get('state') in ('green', 'available'),
         'dashboard_not_ready')
    pattern_id, pattern = find_pattern(client, index_pattern_id)
    wanted = copy.deepcopy(objects)
    for obj in wanted:
        for ref in obj['references']:
            if ref['type'] == 'index-pattern':
                ref['id'] = pattern_id
    missing = []
    # Detect every existing content conflict before the first write.
    for obj in wanted:
        actual = get_object(client, obj['type'], obj['id'])
        if actual is None:
            missing.append(obj)
        else:
            need(normalized(actual) == normalized(obj), 'dashboard_existing_object_differs')
    need(action == 'apply' or (pattern is not None and not missing), 'dashboard_objects_missing')
    created = 0
    if action == 'apply':
        if pattern is None:
            created += create_missing(client, minimal_pattern(pattern_id))
        for obj in missing:
            created += create_missing(client, obj)
    # Re-read the external reference and every panel after all writes; no API 200
    # or partial batch result is treated as successful deployment by itself.
    pattern = get_object(client, 'index-pattern', pattern_id)
    need(pattern is not None, 'dashboard_index_pattern_missing')
    validate_pattern(pattern)
    for obj in wanted:
        actual = get_object(client, obj['type'], obj['id'])
        need(actual is not None and normalized(actual) == normalized(obj), 'dashboard_final_verification_failed')
    return {'schema_version': 1, 'status': 'verified', 'dashboard_id': DASHBOARD,
            'dashboard_path': '/app/dashboards#/view/' + DASHBOARD,
            'scope': 'default', 'dashboard_version': VERSION, 'saved_objects': len(wanted),
            'panel_count': 14, 'index_pattern_id': pattern_id, 'index_pattern_title': PATTERN,
            'objects_sha256': digest([normalized(obj) for obj in wanted]), 'created_objects': created,
            'overwritten_objects': 0, 'event_queries': 0, 'live_data_mapping_verified': False,
            'browser_render_verified': False}


def receipt_identity(result):
    return {key: value for key, value in result.items() if key != 'created_objects'}


def trusted_source(source_root):
    need(source_root.is_absolute(), 'absolute_dashboard_path_required')
    for name in ('generated/soc-dashboard.ndjson', 'live-export-20261019.ndjson'):
        path = source_root / SOURCE / name
        safe_parents(path.parent, allow_staging=True)
        info = path.lstat()
        need(info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe_dashboard_source')


def write_receipt(path, result):
    path = Path(path)
    need(path.is_absolute(), 'absolute_dashboard_path_required')
    safe_parents(path.parent)
    if path.exists() or path.is_symlink():
        previous = parse(safe_read(path, 16384, private=True))
        need(receipt_identity(previous) == receipt_identity(result), 'dashboard_receipt_differs')
        return
    data = encoded(receipt_identity(result)) + b'\n'
    # Link a fully flushed new private file without replacing another writer's
    # receipt. This creates no persistent credential/hash material.
    fd, temporary = tempfile.mkstemp(prefix='.soc-dashboard-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            previous = parse(safe_read(path, 16384, private=True))
            need(receipt_identity(previous) == receipt_identity(result), 'dashboard_receipt_differs')
    finally:
        os.close(fd)
        os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'apply', 'verify'))
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--url')
    parser.add_argument('--ca-file')
    parser.add_argument('--credentials-file')
    parser.add_argument('--receipt')
    parser.add_argument('--index-pattern-id')
    args = parser.parse_args(argv)
    objects = load_bundle(args.source_root)
    if args.action == 'check':
        return {'schema_version': 1, 'status': 'prerequisites_checked', 'saved_objects': 15,
                'panel_count': 14, 'source_objects_sha256': digest([normalized(obj) for obj in objects]),
                'network_requests': 0, 'application_health_checked': False}
    need(os.geteuid() == 0, 'dashboard_root_required')
    need(all((args.url, args.ca_file, args.credentials_file, args.receipt)), 'dashboard_runtime_arguments_required')
    # Runtime sources must have the same root-owned, non-writable archive trust
    # boundary as the role. /var/tmp itself is permitted only for staged sources.
    source_root = Path(args.source_root)
    trusted_source(source_root)
    user, password = credentials(args.credentials_file)
    client = Client(args.url, user, password, args.ca_file)
    receipt = Path(args.receipt)
    previous = None
    if receipt.exists() or receipt.is_symlink():
        previous = parse(safe_read(receipt, 16384, private=True))
        need(isinstance(previous, dict) and previous.get('scope') == 'default'
             and previous.get('dashboard_id') == DASHBOARD
             and isinstance(previous.get('index_pattern_id'), str)
             and previous.get('dashboard_origin') == endpoint(args.url), 'dashboard_receipt_invalid')
        # Prevent later discovery from moving the dashboard to a new pattern.
        if args.index_pattern_id is not None:
            need(args.index_pattern_id == previous.get('index_pattern_id'), 'dashboard_receipt_differs')
        args.index_pattern_id = previous.get('index_pattern_id')
        expected = copy.deepcopy(objects)
        for obj in expected:
            for ref in obj['references']:
                if ref['type'] == 'index-pattern':
                    ref['id'] = args.index_pattern_id
        need(previous.get('objects_sha256') == digest([normalized(obj) for obj in expected]),
             'dashboard_receipt_source_changed')
    else:
        need(args.action == 'apply', 'dashboard_receipt_missing')
        safe_parents(receipt.parent)
    # A completed managed installation is verify-only, including repeated apply.
    # Resuming partial creation is allowed only before the first success receipt.
    result = reconcile(client, objects, 'verify' if previous is not None else args.action,
                       args.index_pattern_id)
    result['dashboard_origin'] = endpoint(args.url)
    if previous is not None:
        need(receipt_identity(previous) == receipt_identity(result), 'dashboard_receipt_differs')
    if args.action == 'apply':
        write_receipt(receipt, result)
    return result


def cli(argv=None):
    try:
        print(encoded(main(argv)).decode())
        return 0
    except Exception as error:
        # Never print urllib bodies, request headers, source values, or traceback.
        code = str(error) if isinstance(error, Refused) else 'dashboard_input_or_runtime_failure'
        print(encoded({'schema_version': 1, 'status': 'failed', 'reason': code,
                       'automatic_rollback': False, 'automatic_retry': False}).decode(), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(cli())
