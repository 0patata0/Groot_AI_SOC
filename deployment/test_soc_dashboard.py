"""Offline saved-object lifecycle/TLS/private input tests; no server connections."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.parse

import soc_dashboard as d


ROOT = Path(__file__).resolve().parents[1]


class FakeClient:
    def __init__(self, objects=()):
        self.objects = {(obj['type'], obj['id']): copy.deepcopy(obj) for obj in objects}
        self.calls = []
        self.fail_after = None
        self.creations = 0
        self.create_error = None
        self.version = d.VERSION
        self.health = 'green'
        self.race = None

    def request(self, method, path, body=None, statuses=(200,)):
        self.calls.append((method, path, copy.deepcopy(body)))
        url = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qs(url.query)
        if path == '/api/status':
            return 200, {'version': {'number': self.version}, 'status': {'overall': {'state': self.health}}}
        if url.path == '/api/saved_objects/_find':
            values = [copy.deepcopy(value) for key, value in sorted(self.objects.items()) if key[0] == 'index-pattern']
            page = int(query['page'][0]); size = int(query['per_page'][0])
            return 200, {'total': len(values), 'saved_objects': values[(page-1)*size:page*size]}
        kind, object_id = url.path.removeprefix('/api/saved_objects/').split('/', 1)
        object_id = urllib.parse.unquote(object_id)
        key = kind, object_id
        if method == 'GET':
            return (200, copy.deepcopy(self.objects[key])) if key in self.objects else (404, {'error': 'Not Found'})
        if method != 'POST' or query != {'overwrite': ['false']}:
            raise AssertionError('only non-overwrite creation is authorized')
        if self.fail_after is not None and self.creations == self.fail_after:
            raise d.Refused('dashboard_api_unavailable')
        if self.create_error:
            raise self.create_error
        obj = {'type': kind, 'id': object_id, **copy.deepcopy(body)}
        if self.race:
            self.objects[key] = self.race(obj)
            self.race = None
        if key in self.objects:
            return 409, {'error': {'statusCode': 409}}
        self.objects[key] = obj
        self.creations += 1
        return 200, copy.deepcopy(obj)

    def writes(self):
        return [call for call in self.calls if call[0] == 'POST']


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.objects = d.load_bundle(ROOT)

    def test_sources_equal_live_export_and_have_expected_graph(self):
        self.assertEqual(len(self.objects), 15)
        self.assertEqual(self.objects[-1]['type'], 'dashboard')
        self.assertEqual(len(d.parse(self.objects[-1]['attributes']['panelsJSON'])), 14)

    def test_check_needs_no_network_or_credentials_and_leaves_sources_unchanged(self):
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (ROOT/d.SOURCE/'generated').iterdir()}
        with patch.object(d, 'Client', side_effect=AssertionError('network forbidden')):
            answer = d.main(['check', '--source-root', str(ROOT)])
        self.assertEqual(answer['network_requests'], 0)
        self.assertFalse(answer['application_health_checked'])
        self.assertEqual(before, {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (ROOT/d.SOURCE/'generated').iterdir()})

    def test_fresh_import_creates_minimal_pattern_then_dashboard_last(self):
        client = FakeClient()
        result = d.reconcile(client, self.objects, 'apply')
        self.assertEqual(result['created_objects'], 16)
        self.assertEqual(result['saved_objects'], 15)
        self.assertEqual(result['overwritten_objects'], 0)
        self.assertFalse(result['browser_render_verified'])
        self.assertFalse(result['live_data_mapping_verified'])
        self.assertIn('/index-pattern/', client.writes()[0][1])
        self.assertIn('/dashboard/', client.writes()[-1][1])
        d.validate_pattern(client.objects['index-pattern', d.PATTERN])

    def test_repeat_apply_and_verify_do_not_write(self):
        client = FakeClient()
        first = d.reconcile(client, self.objects, 'apply')
        client.calls.clear()
        second = d.reconcile(client, self.objects, 'apply')
        third = d.reconcile(client, self.objects, 'verify')
        self.assertEqual(d.receipt_identity(first), d.receipt_identity(second))
        self.assertEqual(second, third)
        self.assertEqual(client.writes(), [])

    def test_existing_guid_index_is_reused_and_not_modified(self):
        pattern = d.minimal_pattern('a-new-environment-pattern-uuid')
        pattern['attributes']['extraUserSetting'] = 'keep'
        client = FakeClient([pattern]); before = copy.deepcopy(client.objects)
        result = d.reconcile(client, self.objects, 'apply')
        self.assertEqual(result['index_pattern_id'], pattern['id'])
        self.assertEqual(client.objects['index-pattern', pattern['id']], before['index-pattern', pattern['id']])
        self.assertEqual(result['created_objects'], 15)
        for key, obj in client.objects.items():
            if key[0] == 'index-pattern': continue
            for ref in obj['references']:
                if ref['type'] == 'index-pattern': self.assertEqual(ref['id'], pattern['id'])

    def test_ambiguous_patterns_refuse_before_write_and_explicit_id_resolves(self):
        client = FakeClient([d.minimal_pattern(d.PATTERN), d.minimal_pattern('another')])
        with self.assertRaisesRegex(d.Refused, 'ambiguous'):
            d.reconcile(client, self.objects, 'apply')
        self.assertEqual(client.writes(), [])
        result = d.reconcile(client, self.objects, 'apply', index_pattern_id='another')
        self.assertEqual(result['index_pattern_id'], 'another')

    def test_existing_different_object_refuses_entire_preflight(self):
        changed = copy.deepcopy(self.objects[-1]); changed['attributes']['title'] = 'operator changed title'
        client = FakeClient([changed])
        with self.assertRaisesRegex(d.Refused, 'existing_object_differs'):
            d.reconcile(client, self.objects, 'apply')
        self.assertEqual(client.writes(), [])
        self.assertEqual(len(client.objects), 1)

    def test_partial_create_retry_only_creates_missing_and_verify_never_repairs(self):
        client = FakeClient(); client.fail_after = 5
        with self.assertRaisesRegex(d.Refused, 'api_unavailable'):
            d.reconcile(client, self.objects, 'apply')
        existing = copy.deepcopy(client.objects)
        client.calls.clear()
        with self.assertRaisesRegex(d.Refused, 'objects_missing'):
            d.reconcile(client, self.objects, 'verify')
        self.assertEqual(client.writes(), [])
        client.fail_after = None
        result = d.reconcile(client, self.objects, 'apply')
        self.assertEqual(result['created_objects'], 11)
        for key, value in existing.items(): self.assertEqual(value, client.objects[key])

    def test_concurrent_identical_create_is_accepted_without_overwrite(self):
        client = FakeClient(); client.race = lambda obj: obj
        result = d.reconcile(client, self.objects, 'apply')
        self.assertEqual(result['created_objects'], 15)
        self.assertEqual(len(client.objects), 16)

    def test_concurrent_different_create_is_refused_without_cleanup(self):
        def changed(obj):
            obj['attributes']['timeFieldName'] = 'other'
            return obj
        client = FakeClient(); client.race = changed
        with self.assertRaisesRegex(d.Refused, 'created_object_differs'):
            d.reconcile(client, self.objects, 'apply')
        self.assertEqual(len(client.writes()), 1)
        self.assertEqual(client.objects['index-pattern', d.PATTERN]['attributes']['timeFieldName'], 'other')

    def test_pattern_title_time_field_type_script_and_filter_conflicts_fail(self):
        mutations = [lambda a: a.update(title='other-*'), lambda a: a.update(timeFieldName='other'),
                     lambda a: a.update(sourceFilters='[{"value":"rule.*"}]'),
                     lambda a: a.update(fields='[]'), lambda a: a.pop('fields')]
        for mutation in mutations:
            with self.subTest(case=mutations.index(mutation)):
                pattern = d.minimal_pattern(d.PATTERN); mutation(pattern['attributes'])
                client = FakeClient([pattern])
                with self.assertRaises(d.Refused): d.reconcile(client, self.objects, 'apply')
                self.assertEqual(client.writes(), [])
        for field_change in ({'type': 'number'}, {'scripted': True}, {'aggregatable': False}):
            pattern = d.minimal_pattern(d.PATTERN)
            fields = d.parse(pattern['attributes']['fields']); fields[0].update(field_change)
            pattern['attributes']['fields'] = json.dumps(fields)
            with self.assertRaises(d.Refused): d.validate_pattern(pattern)

    def test_wrong_server_version_or_unready_prevents_writes(self):
        for field, value in (('version', '3.0.0'), ('health', 'red')):
            client = FakeClient(); setattr(client, field, value)
            with self.assertRaises(d.Refused): d.reconcile(client, self.objects, 'apply')
            self.assertEqual(client.writes(), [])

    def test_foreign_scope_refused(self):
        for key, value in (('workspaces', ['foreign']), ('namespaces', ['private'])):
            pattern = d.minimal_pattern(d.PATTERN); pattern[key] = value
            client = FakeClient([pattern])
            with self.assertRaisesRegex(d.Refused, 'nondefault_scope'):
                d.reconcile(client, self.objects, 'apply')
            self.assertEqual(client.writes(), [])

    def test_structured_json_whitespace_and_reference_order_are_semantic(self):
        client = FakeClient(); d.reconcile(client, self.objects, 'apply')
        for obj in client.objects.values():
            obj['references'].reverse()
            for key, value in obj['attributes'].items():
                if key in d.JSON_ATTRIBUTES:
                    obj['attributes'][key] = json.dumps(json.loads(value), indent=2)
            obj['version'] = 'opaque-server-version'
        client.calls.clear()
        d.reconcile(client, self.objects, 'verify')
        self.assertEqual(client.writes(), [])

    def test_source_difference_and_incomplete_export_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/d.SOURCE
            shutil.copytree(ROOT/d.SOURCE, target)
            export = target/'live-export-20261019.ndjson'
            data = [json.loads(line) for line in export.read_text().splitlines()]
            original = export.read_bytes()
            data[-1]['missingRefCount'] = 1
            export.write_text('\n'.join(json.dumps(obj) for obj in data)+'\n')
            with self.assertRaisesRegex(d.Refused, 'export_incomplete'): d.load_bundle(temporary)
            export.write_bytes(original)
            data = [json.loads(line) for line in export.read_text().splitlines()]
            data[0]['attributes']['title'] = 'tampered'
            export.write_text('\n'.join(json.dumps(obj) for obj in data)+'\n')
            with self.assertRaisesRegex(d.Refused, 'export_generated_differ'): d.load_bundle(temporary)

    def test_duplicate_keys_and_nonfinite_json_rejected(self):
        for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}', 'not json'):
            with self.subTest(text=text), self.assertRaises(d.Refused): d.parse(text)

    def test_endpoint_requires_https_origin_and_forbids_userinfo_space_query(self):
        for text in ('https://10.0.0.2', 'https://dashboard.example:443/', 'https://[::1]'):
            self.assertEqual(d.endpoint(text), text.rstrip('/'))
        for text in ('http://host', 'https://user:private@host', 'https://host/s/private',
                     'https://host?securitytenant=global', 'https://host/#private',
                     'https://host\n', 'https://host:65536'):
            with self.subTest(text=text), self.assertRaises(d.Refused): d.endpoint(text)


class TransportAndReceiptTests(unittest.TestCase):
    def test_completed_receipt_reapply_is_verify_only_and_does_not_repair_deletion(self):
        client = FakeClient()
        result = d.reconcile(client, d.load_bundle(ROOT), 'apply')
        result['dashboard_origin'] = 'https://server.example'
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary)/'receipt.json'; receipt.write_bytes(d.encoded(d.receipt_identity(result)))
            arguments = ['apply', '--source-root', str(ROOT), '--url', 'https://server.example',
                         '--ca-file', '/fixed/ca', '--credentials-file', '/fixed/key', '--receipt', str(receipt)]
            with patch.object(d.os, 'geteuid', return_value=0), patch.object(d, 'trusted_source'), \
                 patch.object(d, 'credentials', return_value=('admin', 'synthetic-private-key')), \
                 patch.object(d, 'Client', return_value=client), patch.object(d, 'safe_parents'), \
                 patch.object(d, 'safe_read', side_effect=lambda *a, **k: receipt.read_bytes()), \
                 patch.object(d, 'write_receipt') as publish:
                client.calls.clear()
                answer = d.main(arguments)
                self.assertEqual(answer['created_objects'], 0)
                self.assertEqual(client.writes(), [])
                del client.objects['dashboard', d.DASHBOARD]
                client.calls.clear()
                with self.assertRaisesRegex(d.Refused, 'objects_missing'): d.main(arguments)
                self.assertEqual(client.writes(), [])
                publish.assert_called_once()

    def test_receipt_origin_or_source_change_fails_before_any_api_request(self):
        client = FakeClient()
        result = d.reconcile(client, d.load_bundle(ROOT), 'apply')
        result['dashboard_origin'] = 'https://server.example'
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary)/'receipt.json'
            arguments = ['apply', '--source-root', str(ROOT), '--url', 'https://server.example',
                         '--ca-file', '/fixed/ca', '--credentials-file', '/fixed/key', '--receipt', str(receipt)]
            for key, value in (('objects_sha256', '0'*64), ('dashboard_origin', 'https://other.example')):
                receipt.write_bytes(d.encoded({**d.receipt_identity(result), key: value}))
                client.calls.clear()
                with self.subTest(key=key), patch.object(d.os, 'geteuid', return_value=0), \
                     patch.object(d, 'trusted_source'), patch.object(d, 'credentials', return_value=('admin', 'synthetic')), \
                     patch.object(d, 'Client', return_value=client), patch.object(d, 'safe_parents'), \
                     patch.object(d, 'safe_read', side_effect=lambda *a, **k: receipt.read_bytes()), self.assertRaises(d.Refused):
                    d.main(arguments)
                self.assertEqual(client.calls, [])

    def test_transport_ca_verification_no_proxies_no_redirects_no_tenant_header(self):
        context = ssl.create_default_context()
        opener = Mock()
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"ok":true}'
        opener.open.return_value = response
        with patch.object(d, 'safe_read', return_value=b'public-CA-only'), \
             patch.object(d.ssl, 'create_default_context', return_value=context) as make_tls, \
             patch.object(d.urllib.request, 'build_opener', return_value=opener) as build:
            client = d.Client('https://server.example', 'admin', 'synthetic-private-value', '/trusted/ca.pem')
            self.assertEqual(client.request('GET', '/api/status'), (200, {'ok': True}))
        make_tls.assert_called_once_with(cadata='public-CA-only')
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], d.NoRedirect)
        self.assertIsNone(handlers[1].redirect_request(None, None, 302, None, {}, 'https://elsewhere'))
        request = opener.open.call_args.args[0]
        self.assertNotIn('Securitytenant', request.headers)
        self.assertIn('Osd-xsrf', request.headers)

    def test_response_limit_and_html_login_redirect_are_safe_errors(self):
        for status, body, message in ((302, b'private-login-body', 'http_302'),
                                      (200, b'x'*(d.LIMIT+1), 'response_limit'),
                                      (200, b'<html>private</html>', 'invalid_json')):
            client = object.__new__(d.Client); client.url = 'https://server'; client.authorization = 'Basic synthetic'
            response = Mock(status=status)
            response.__enter__ = Mock(return_value=response); response.__exit__ = Mock(return_value=False)
            response.read.return_value = body
            client.opener = Mock(); client.opener.open.return_value = response
            with self.subTest(status=status), self.assertRaisesRegex(d.Refused, message):
                client.request('GET', '/api/status')

    def test_cli_never_reflects_external_exception_secrets(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(d, 'main', side_effect=RuntimeError('Authorization: synthetic-private-value')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(d.cli(['verify']), 1)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn('synthetic-private-value', err.getvalue())
        self.assertEqual(json.loads(err.getvalue())['reason'], 'dashboard_input_or_runtime_failure')

    def test_private_credentials_are_read_in_memory_and_not_returned_in_reports(self):
        config = {'schema_version': 1, 'indexer_username': 'admin', 'indexer_password': '한글-Synthetic-key'}
        with patch.object(d, 'safe_read', return_value=json.dumps(config).encode()) as read:
            self.assertEqual(d.credentials('/fixed/siem.json'), ('admin', config['indexer_password']))
            read.assert_called_once_with('/fixed/siem.json', 16384, private=True)

    def test_receipt_is_atomic_private_root_owned_and_noop_for_same_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'receipt.json'
            result = {'schema_version': 1, 'status': 'verified', 'created_objects': 16}
            with patch.object(d, 'safe_parents'), patch.object(d.os, 'fchown') as chown:
                d.write_receipt(path, result)
                chown.assert_called_once_with(unittest.mock.ANY, 0, 0)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(list(Path(temporary).iterdir()), [path])
            before = path.stat().st_mtime_ns
            with patch.object(d, 'safe_parents'), patch.object(d, 'safe_read', return_value=path.read_bytes()):
                d.write_receipt(path, {**result, 'created_objects': 0})
                with self.assertRaisesRegex(d.Refused, 'receipt_differs'):
                    d.write_receipt(path, {**result, 'status': 'other'})
            self.assertEqual(path.stat().st_mtime_ns, before)

    def test_staging_sticky_directory_allowed_only_for_source(self):
        def info(path):
            mode = 0o1777 if str(path) == '/var/tmp' else 0o700
            return Mock(st_mode=stat.S_IFDIR | mode, st_uid=0)
        with patch.object(Path, 'lstat', autospec=True, side_effect=info):
            d.safe_parents(Path('/var/tmp/capstone-bootstrap-123/source'), allow_staging=True)
            with self.assertRaisesRegex(d.Refused, 'unsafe_dashboard_directory'):
                d.safe_parents(Path('/var/tmp/capstone-bootstrap-123/source'))

    def test_private_file_symlinks_hardlinks_nonroot_and_modes_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'private.json'; path.write_text('{}'); path.chmod(0o600)
            actual = path.lstat()
            for field, value in (('st_nlink', 2), ('st_uid', 1000),
                                 ('st_mode', stat.S_IFLNK | 0o600), ('st_mode', stat.S_IFREG | 0o644)):
                fake = Mock(**{name: getattr(actual, name) for name in dir(actual) if name.startswith('st_')})
                fake.st_uid = 0; setattr(fake, field, value)
                with self.subTest(field=field, value=value), patch.object(d, 'safe_parents'), \
                     patch.object(Path, 'lstat', return_value=fake), self.assertRaises(d.Refused):
                    d.safe_read(path, private=True)


if __name__ == '__main__':
    unittest.main()
