"""ASGI terminal boundary tests; run with the server's existing vendored FastAPI.

No live Unix daemon, Docker socket, package installation or browser is used.
"""
import asyncio
import base64
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HAS_FASTAPI = importlib.util.find_spec('fastapi') is not None
REDIS, SAMBA, SUDO = 'CVE-2022-0543', 'CVE-2017-7494', 'CVE-2021-3156'
SESSION = 'c' * 64
ORIGIN = b'http://127.0.0.1:18090'


@unittest.skipUnless(HAS_FASTAPI, 'Use existing server/vendor FastAPI; do not install packages on Mac')
class TerminalApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        manifest = base / 'catalog.json'
        manifest.write_text(json.dumps([
            {'type': 'managed-terminal', 'cve_id': REDIS, 'software': 'Redis', 'vulnerable_version': '5:5.0.7-2'},
            {'type': 'managed-terminal', 'cve_id': SAMBA, 'software': 'Samba', 'vulnerable_version': '4.6.3'},
            {'type': 'managed-terminal', 'cve_id': SUDO, 'software': 'sudo', 'vulnerable_version': '1.8.31-1ubuntu1'}]))
        key = base / 'key'
        key.write_text('test-only-terminal-fixture-key')
        self.environment = mock.patch.dict(os.environ, {'OFFLINE_LABS_MANIFEST': str(manifest),
            'OFFLINE_LABS_TOKEN_FILE': str(key), 'OFFLINE_LABS_ORIGINS': ORIGIN.decode()})
        self.environment.start()
        self.module = importlib.import_module('app')
        self.terminal = importlib.import_module('terminal_api')
        self.app = self.module.create_app()
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.rpc = mock.patch.object(self.terminal, 'terminal_rpc', return_value={'ok': True, 'session_id': SESSION, 'expires_in': 1800})
        self.call = self.rpc.start()

    async def asyncTearDown(self):
        self.rpc.stop()
        await self.lifespan.__aexit__(None, None, None)
        self.environment.stop()
        self.temp.cleanup()

    async def request(self, path, method='POST', payload=None, body=None, extra=(), origin=ORIGIN, query=b'', host=b'127.0.0.1:18090'):
        if body is None:
            body = json.dumps(payload).encode() if payload is not None else b''
        headers = [(b'host', host)]
        if not any(name == b'content-type' for name, _ in extra):
            headers.append((b'content-type', b'application/json'))
        if origin is not None:
            headers.append((b'origin', origin))
        headers.extend(extra)
        scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': method,
                 'scheme': 'http', 'path': path, 'raw_path': path.encode(), 'query_string': query,
                 'root_path': '', 'headers': headers, 'client': ('127.0.0.1', 1234), 'server': ('127.0.0.1', 18090)}
        sent, delivered = [], False
        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            await asyncio.sleep(20)
            return {'type': 'http.disconnect'}
        async def send(event):
            sent.append(event)
        await asyncio.wait_for(self.app(scope, receive, send), 8)
        start = next(item for item in sent if item['type'] == 'http.response.start')
        raw = b''.join(item.get('body', b'') for item in sent if item['type'] == 'http.response.body')
        return start['status'], raw, dict(start['headers'])

    async def open(self, **kwargs):
        return await self.request('/api/terminal/open', payload={'cve_id': REDIS, 'rows': 24, 'cols': 80}, **kwargs)

    async def test_open_has_only_fixed_lab_dimensions_and_host_ip_bound_owner(self):
        code, body, headers = await self.open()
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {'session_id': SESSION, 'expires_in': 1800})
        self.assertEqual(self.call.call_args.args[0], {'action': 'terminal_open', 'lab': 'redis', 'rows': 24, 'cols': 80,
            'owner': hashlib.sha256(b'127.0.0.1:18090\x00127.0.0.1').hexdigest()})
        self.assertEqual(headers[b'cache-control'], b'no-store')
        self.assertNotIn(b'set-cookie', headers)

    async def test_sudo_open_uses_fixed_rootless_lab_without_client_uid_or_container(self):
        code, body, _ = await self.request('/api/terminal/open', payload={'cve_id': SUDO, 'rows': 24, 'cols': 80})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {'session_id': SESSION, 'expires_in': 1800})
        self.assertEqual(self.call.call_args.args[0], {'action': 'terminal_open', 'lab': 'sudo', 'rows': 24, 'cols': 80,
            'owner': hashlib.sha256(b'127.0.0.1:18090\x00127.0.0.1').hexdigest()})

    async def test_terminal_requests_require_explicit_allowed_origin(self):
        for origin in (None, b'null', b'https://other.example'):
            code, _, _ = await self.open(origin=origin)
            self.assertEqual(code, 403)
        self.call.assert_not_called()

    async def test_cross_site_fetch_denied_even_with_allowed_origin(self):
        code, _, _ = await self.open(extra=[(b'sec-fetch-site', b'cross-site')])
        self.assertEqual(code, 403)
        self.call.assert_not_called()

    async def test_capability_or_data_querystring_is_never_accepted(self):
        code, body, _ = await self.open(query=('session_id=' + SESSION).encode())
        self.assertEqual(code, 403)
        self.assertNotIn(SESSION.encode(), body)
        self.call.assert_not_called()

    async def test_unknown_unregistered_and_nonterminal_targets_refused(self):
        for identifier in ('CVE-2021-44228', 'LAB-DVWA', 'CVE-2022-9999', 'redis;id'):
            code, body, _ = await self.request('/api/terminal/open', payload={'cve_id': identifier, 'rows': 24, 'cols': 80})
            self.assertEqual(code, 422)
            self.assertNotIn(identifier.encode(), body)
        self.app.state.lab_ids = frozenset({SAMBA})
        self.assertEqual((await self.open())[0], 422)
        self.call.assert_not_called()

    async def test_extra_fields_cannot_select_image_command_host_mount_or_owner(self):
        for identifier in (REDIS, SUDO):
            for key in ('command', 'image_id', 'host', 'mount', 'owner', 'container_id', 'user', 'exec_user', 'uid', 'socket'):
                code, _, _ = await self.request('/api/terminal/open', payload={'cve_id': identifier, 'rows': 24, 'cols': 80, key: 'untrusted'})
                self.assertEqual(code, 422)
        self.call.assert_not_called()

    async def test_invalid_dimensions_and_wrong_json_types_fail_without_rpc(self):
        for rows, cols in ((True, 80), (1, 80), (101, 80), (24, 301), (24, '80')):
            code, _, _ = await self.request('/api/terminal/open', payload={'cve_id': REDIS, 'rows': rows, 'cols': cols})
            self.assertEqual(code, 422)
        for payload in ([], None, 'request'):
            code, _, _ = await self.request('/api/terminal/open', body=json.dumps(payload).encode())
            self.assertEqual(code, 422)
        self.call.assert_not_called()

    async def test_duplicate_json_keys_and_oversized_body_are_not_reflected(self):
        duplicate = b'{"cve_id":"CVE-2022-0543","cve_id":"private-fixture","rows":24,"cols":80}'
        code, raw, _ = await self.request('/api/terminal/open', body=duplicate)
        self.assertEqual(code, 422)
        self.assertNotIn(b'private-fixture', raw)
        code, raw, _ = await self.request('/api/terminal/open', body=b'x' * 4097)
        self.assertEqual(code, 413)
        self.assertNotIn(b'x' * 32, raw)
        self.call.assert_not_called()

    async def test_session_id_is_strict_and_input_is_only_base64_json(self):
        for sid in ('short', SESSION + ';id', True, None):
            code, _, _ = await self.request('/api/terminal/input', payload={'session_id': sid, 'data': 'eA=='})
            self.assertEqual(code, 422)
        for data in ('%', 'a' * 2733, '', None):
            code, _, _ = await self.request('/api/terminal/input', payload={'session_id': SESSION, 'data': data})
            self.assertEqual(code, 422)
        self.call.assert_not_called()
        self.call.return_value = {'ok': True}
        encoded = base64.b64encode(b'echo harmless; $(whoami)\n').decode()
        code, _, _ = await self.request('/api/terminal/input', payload={'session_id': SESSION, 'data': encoded})
        self.assertEqual(code, 200)
        self.assertEqual(self.call.call_args.args[0]['data'], encoded)
        self.assertEqual(self.call.call_args.args[0]['action'], 'terminal_input')

    async def test_cursor_bool_negative_and_unbounded_values_are_refused(self):
        for cursor in (True, -1, 2**63, '0'):
            code, _, _ = await self.request('/api/terminal/poll', payload={'session_id': SESSION, 'cursor': cursor})
            self.assertEqual(code, 422)
        self.call.assert_not_called()

    async def test_owner_changes_with_trusted_proxy_client_address(self):
        await self.open(extra=[(b'x-lab-client-ip', b'192.168.15.10')])
        first = self.call.call_args.args[0]['owner']
        await self.open(extra=[(b'x-lab-client-ip', b'192.168.15.11')])
        second = self.call.call_args.args[0]['owner']
        self.assertNotEqual(first, second)

    async def test_terminal_html_only_for_registered_terminal_ids(self):
        for identifier in (REDIS, SAMBA, SUDO):
            code, body, headers = await self.request('/terminal/' + identifier + '/', method='GET', origin=None)
            self.assertEqual(code, 200)
            self.assertIn(b'terminal-screen', body)
            self.assertIn(b"script-src 'self'", headers[b'content-security-policy'])
        for identifier in ('CVE-2021-44228', 'LAB-DVWA', 'CVE-2022-9999'):
            code, _, _ = await self.request('/terminal/' + identifier + '/', method='GET', origin=None)
            self.assertEqual(code, 404)
        self.app.state.lab_ids = frozenset({SAMBA})
        self.assertEqual((await self.request('/terminal/' + REDIS + '/', method='GET', origin=None))[0], 404)
        self.call.assert_not_called()

    async def test_legacy_cli_catalog_cannot_open_sudo_page_or_terminal(self):
        legacy = Path(self.temp.name) / 'legacy-cli.json'
        legacy.write_text(json.dumps([{'type': 'local-cli', 'cve_id': SUDO, 'software': 'sudo',
                                      'vulnerable_version': 'legacy fixture'}]))
        with mock.patch.dict(os.environ, {'OFFLINE_LABS_MANIFEST': str(legacy)}):
            replacement = self.module.create_app()
            async with replacement.router.lifespan_context(replacement):
                original, self.app = self.app, replacement
                try:
                    self.assertEqual((await self.request('/terminal/' + SUDO + '/', method='GET', origin=None))[0], 404)
                    self.assertEqual((await self.request('/api/terminal/open', payload={'cve_id': SUDO, 'rows': 24, 'cols': 80}))[0], 422)
                finally:
                    self.app = original
        self.call.assert_not_called()

    async def test_content_type_and_host_guards_precede_terminal_rpc(self):
        self.assertEqual((await self.open(host=b'evil.example'))[0], 400)
        self.assertEqual((await self.open(extra=[(b'content-type', b'text/plain')]))[0], 415)
        self.call.assert_not_called()

    async def test_mode_key_and_cookie_do_not_replace_terminal_origin_boundary(self):
        code, _, _ = await self.open(origin=None, extra=[(b'authorization', b'Bearer test-only-terminal-fixture-key'),
                                                       (b'cookie', b'groot_lab_mode=invalid')])
        self.assertEqual(code, 403)
        self.call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
