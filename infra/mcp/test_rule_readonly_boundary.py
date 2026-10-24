"""Role separation must hold even when callers bypass tool discovery."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location('readonly_test_' + name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


transport = load('rule_change_mcp')
executor = load('rule_change_executor')


class ReadonlyBoundaryTests(unittest.TestCase):
    def test_each_operation_has_one_owner_and_only_local_targets(self):
        for host in ('a', 'b'):
            read, write = transport.tool_list('read', host), transport.tool_list('write', host)
            self.assertEqual({t['name'] for t in read}, transport.READ_TOOLS)
            self.assertEqual(len(write), 4 if host == 'a' else 3)
            self.assertFalse({t['name'] for t in read} & {t['name'] for t in write})
            for tool in read + write:
                targets = tool['inputSchema']['properties'].get('target', {}).get('enum', [])
                self.assertTrue(all(t.startswith(host + ':') for t in targets))
                self.assertEqual(tool['annotations']['readOnlyHint'], tool in read)

    def test_forged_cross_role_calls_never_reach_sudo(self):
        for access, other in (('read', 'write'), ('write', 'read')):
            for tool in transport.tool_list(other, 'a'):
                with self.subTest(access=access, name=tool['name']), patch.object(transport, '_call_helper') as helper:
                    result = transport.handle({'id': 1, 'method': 'tools/call', 'params': {
                        'name': tool['name'], 'arguments': {}}}, access, 'a')
                    self.assertIn('error', result)
                    helper.assert_not_called()

    def test_remote_host_target_is_refused_before_helper(self):
        for host, target in (('a', 'b:wazuh-local-rules'), ('b', 'a:suricata-local')):
            with patch.object(transport, '_call_helper') as helper:
                result = transport.handle({'id': 1, 'method': 'tools/call', 'params': {
                    'name': 'get_rule_change_target', 'arguments': {'target': target}}}, 'read', host)
                self.assertTrue(result['result']['isError'])
                helper.assert_not_called()

    def run_root(self, request, argv, caller):
        with patch.object(executor.os, 'geteuid', return_value=0), patch.dict(os.environ, {'SUDO_USER': caller}), \
             patch.object(executor.sys, 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))):
            executor.main(argv)

    def test_root_read_mode_rejects_every_mutating_operation_before_credentials(self):
        for operation in ('propose', 'propose-edit', 'service-propose', 'contain-ip', 'submit-incident', '--once', None):
            with self.subTest(operation=operation), patch.object(executor, '_secure_config') as config, \
                    patch.object(executor, 'Engine') as engine:
                with self.assertRaisesRegex(executor.RuleChangeError, 'not read-only'):
                    self.run_root({'operation': operation}, ['--read-only'], 'ruleview')
                config.assert_not_called()
                engine.assert_not_called()

    def test_readonly_account_cannot_select_worker_or_unrestricted_mode(self):
        for argv in ([], ['--once'], ['--check'], ['--broker-check']):
            with patch.object(executor, '_secure_config') as config:
                with self.assertRaisesRegex(executor.RuleChangeError, 'requires --read-only'):
                    self.run_root({}, argv, 'ruleview')
                config.assert_not_called()

    def test_write_account_cannot_reintroduce_duplicate_queries(self):
        for operation in ('get', 'status', 'service-get', 'operation-status'):
            with patch.object(executor, '_secure_config') as config:
                with self.assertRaisesRegex(executor.RuleChangeError, 'read-only MCP'):
                    self.run_root({'operation': operation}, [], 'rulechg')
                config.assert_not_called()

    def test_read_helper_selects_read_mode_with_fixed_argv(self):
        import subprocess
        with patch.object(transport.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'{}', b'')) as run:
            transport._call_helper({'operation': 'status', 'proposal_id': 'a' * 32}, readonly=True)
        self.assertEqual(run.call_args.args[0], ['/usr/bin/sudo', '-n', transport.HELPER, '--read-only'])

    def test_reader_does_not_create_state_or_lock(self):
        with tempfile.TemporaryDirectory(prefix='capstone-readonly-') as directory:
            state = Path(directory) / 'absent'
            engine = executor.Engine('a', None, state_dir=state, read_only=True)
            with engine.locked():
                self.assertFalse(state.exists())
            self.assertFalse(state.exists())


if __name__ == '__main__':
    unittest.main()
