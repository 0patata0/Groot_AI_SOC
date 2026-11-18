"""Response MCP must reject malformed call containers before all four tools.

The stdio fixture runs the original server loop with a recording dispatcher.
No firewall, approval, helper, network, credentials or service operations run.
"""
from pathlib import Path
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get('RESPONSE_RPC_TEST_SOURCE', str(Path(__file__).with_name('response-mcp.py'))))
NAMES = ('get_firewall_rules', 'list_blocks', 'block_ip', 'unblock_ip')
NONOBJECTS = (None, [], False, 0, '', [1], True, 1, 'not-an-object')
NONSTRING_NAMES = tuple(value for value in NONOBJECTS if not isinstance(value, str)) + ({},)
UNKNOWN_NAMES = ('', 'not-an-object', 'missing_tool')


def load_server(path=SOURCE):
    spec = importlib.util.spec_from_file_location('response_rpc_fixture', path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'notifier': None}):
        spec.loader.exec_module(module)
    return module


def stdio_child(source, audit_path):
    audit = {'dispatches': [], 'blocked_external_operations': 0,
             'backend_operations': 0, 'fixture': 'recording dispatcher; original main/handle'}

    def deny(event, args):
        if event in ('subprocess.Popen', 'socket.__new__', 'socket.connect', 'socket.bind'):
            audit['blocked_external_operations'] += 1
            raise PermissionError('external operation prohibited in stdio fixture')
    sys.addaudithook(deny)
    server = load_server(Path(source))

    def dispatch(name, args):
        audit['dispatches'].append({'name': name, 'arguments': args})
        if not isinstance(name, str) or name not in NAMES:
            return None
        return server.tool_text(json.dumps({'fixture_tool': name, 'arguments': args}))

    def backend_refused(*args, **kwargs):
        audit['backend_operations'] += 1
        raise AssertionError('fixture reached an operating backend')
    server.call_tool = dispatch
    for name in ('_fw_cache', '_fw_capture', 'request_approval', 'run_agent_block', '_broker'):
        setattr(server, name, backend_refused)
    try:
        server.main()
    finally:
        Path(audit_path).write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n')


def wire_cases():
    cases = []
    for name in NAMES:
        for value in NONOBJECTS:
            cases.append(({'name': name, 'arguments': copy.deepcopy(value)}, 'invalid'))
    for value in NONOBJECTS:
        cases.append((copy.deepcopy(value), 'invalid'))
    for value in NONSTRING_NAMES:
        cases.append(({'name': copy.deepcopy(value), 'arguments': {}}, 'invalid'))
    cases.append(({}, 'invalid'))
    for name in NAMES:
        for params in ({'name': name}, {'name': name, 'arguments': {}},
                       {'name': name, 'arguments': {'fixture_value': 'preserved'},
                        '_meta': {'progressToken': 'fixture'}}):
            cases.append((params, 'valid'))
    for name in UNKNOWN_NAMES:
        cases.append(({'name': name, 'arguments': {}}, 'unknown'))
    return cases


class ResponseRpcInput(unittest.TestCase):
    def setUp(self):
        self.server = load_server()

    def request(self, params):
        return {'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call', 'params': params}

    def assert_invalid(self, params):
        with patch.object(self.server, 'call_tool') as dispatch:
            reply = self.server.handle(self.request(params))
        self.assertEqual(reply.get('id'), 7)
        self.assertEqual(reply.get('error', {}).get('code'), -32602)
        self.assertNotIn('result', reply)
        dispatch.assert_not_called()

    def test_nonobject_arguments_never_reach_any_tool(self):
        for name in NAMES:
            for value in NONOBJECTS:
                with self.subTest(tool=name, value=value):
                    self.assert_invalid({'name': name, 'arguments': value})

    def test_nonobject_params_are_protocol_errors_without_dispatch(self):
        for value in NONOBJECTS:
            with self.subTest(value=value):
                self.assert_invalid(value)

    def test_missing_or_nonstring_name_is_rejected_before_dispatch(self):
        for value in NONSTRING_NAMES:
            with self.subTest(value=value):
                self.assert_invalid({'name': value, 'arguments': {}})
        self.assert_invalid({})
        with patch.object(self.server, 'call_tool') as dispatch:
            reply = self.server.handle({'jsonrpc': '2.0', 'id': 7, 'method': 'tools/call'})
        self.assertEqual(reply.get('error', {}).get('code'), -32602)
        dispatch.assert_not_called()

    def test_omitted_arguments_empty_objects_and_metadata_preserve_valid_calls(self):
        for name in NAMES:
            for params, expected in (({'name': name}, {}),
                                     ({'name': name, 'arguments': {}}, {}),
                                     ({'name': name, 'arguments': {'fixture': True},
                                       '_meta': {'progressToken': 'fixture'}}, {'fixture': True})):
                with self.subTest(name=name, params=params), patch.object(
                        self.server, 'call_tool', return_value=self.server.tool_text('fixture')) as dispatch:
                    reply = self.server.handle(self.request(params))
                    self.assertFalse(reply['result']['isError'])
                    dispatch.assert_called_once_with(name, expected)

    def test_unknown_string_tool_still_returns_the_existing_protocol_error(self):
        for name in UNKNOWN_NAMES:
            with self.subTest(name=name), patch.object(self.server, '_fw_capture') as capture, patch.object(
                    self.server, 'request_approval') as approval, patch.object(self.server, 'run_agent_block') as helper:
                reply = self.server.handle(self.request({'name': name, 'arguments': {}}))
            self.assertEqual(reply['error']['code'], -32602)
            capture.assert_not_called(); approval.assert_not_called(); helper.assert_not_called()

    def assert_stdio(self, source):
        cases = wire_cases()
        messages = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'response-input-fixture', 'version': '1'}}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}]
        messages += [{'jsonrpc': '2.0', 'id': i + 3, 'method': 'tools/call', 'params': params}
                     for i, (params, _) in enumerate(cases)]
        messages.append({'jsonrpc': '2.0', 'id': len(cases) + 3, 'method': 'ping'})
        with tempfile.TemporaryDirectory(prefix='response-rpc-') as directory:
            audit_path = Path(directory) / 'audit.json'
            env = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1',
                   'PYTHONNOUSERSITE': '1', 'TMPDIR': directory}
            result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                     '--stdio-child', str(source), str(audit_path)],
                                    input=''.join(json.dumps(m) + '\n' for m in messages),
                                    capture_output=True, text=True, timeout=10, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual([r['id'] for r in rows], list(range(1, len(cases) + 4)))
            self.assertEqual(rows[0]['result']['protocolVersion'], '2025-06-18')
            self.assertEqual([t['name'] for t in rows[1]['result']['tools']],
                             ['get_firewall_rules', 'block_ip', 'unblock_ip', 'list_blocks'])
            self.assertEqual(rows[-1]['result'], {})
            for reply, (params, expectation) in zip(rows[2:-1], cases):
                with self.subTest(source=source.name, params=params):
                    if expectation in ('invalid', 'unknown'):
                        self.assertEqual(reply.get('error', {}).get('code'), -32602)
                    else:
                        self.assertFalse(reply['result']['isError'])
                        observed = json.loads(reply['result']['content'][0]['text'])
                        self.assertEqual(observed['arguments'], params.get('arguments', {}))
            audit = json.loads(audit_path.read_text())
            expected = [{'name': p['name'], 'arguments': p.get('arguments', {})}
                        for p, expectation in cases if expectation in ('valid', 'unknown')]
            self.assertEqual(audit['dispatches'], expected)
            self.assertEqual(audit['blocked_external_operations'], 0)
            self.assertEqual(audit['backend_operations'], 0)
            self.assertNotIn('handler error', result.stderr)

    def test_real_stdio_loop_rejects_bad_calls_and_accepts_following_valid_calls(self):
        self.assert_stdio(SOURCE)

    def test_fresh_installer_render_preserves_the_same_rpc_boundary(self):
        # Reuse the installer's actual profile and pure render path.
        tests = ROOT / 'deployment/tests'
        sys.path.insert(0, str(tests))
        try:
            import test_soc_management as fixtures
            rendered = fixtures.runtime.render('response-mcp.py', SOURCE.read_bytes(), fixtures.profile('a'))
        finally:
            sys.path.remove(str(tests))
        with tempfile.TemporaryDirectory(prefix='response-rendered-') as directory:
            source = Path(directory) / 'response-mcp.py'
            source.write_bytes(rendered)
            self.assert_stdio(source)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--stdio-child':
        stdio_child(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
