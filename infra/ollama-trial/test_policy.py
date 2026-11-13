import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import hashlib
import contextlib
import io
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import policy
import runtime

spec = importlib.util.spec_from_file_location('trial_install', HERE.parents[1] / 'deployment/ollama_trial.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class ReadPolicy(unittest.TestCase):
    def test_mixed_catalog_only_exposes_reads_and_rejects_server_drift(self):
        tools = [SimpleNamespace(name=n) for n in ('list_blocks', 'get_firewall_rules', 'block_ip', 'unblock_ip')]
        self.assertEqual([t.name for t in policy.filter_catalog('resp', tools, 'read-only')], ['list_blocks', 'get_firewall_rules'])
        self.assertEqual(len(policy.filter_catalog('resp', tools, 'hermes-parity')), 4)
        for changed in (tools[:-1], tools + [SimpleNamespace(name='shell')]):
            with self.assertRaisesRegex(ValueError, 'server_tool_contract_changed'):
                policy.filter_catalog('resp', changed, 'read-only')
    def test_unique_names_and_exact_read_count(self):
        names = [policy.alias(s, t) for s, ts in policy.READ_TOOLS.items() for t in ts]
        self.assertEqual(len(names), 36)
        self.assertEqual(len(set(names)), 36)
        self.assertNotEqual(policy.alias('rule-a', 'get_service_action_target'),
                            policy.alias('rule-b', 'get_service_action_target'))

    def test_write_servers_and_methods_denied(self):
        for server, name in [('rule-write-a', 'propose_rule_change'),
                             ('rule-a', 'propose_service_action'), ('resp', 'block_ip'),
                             ('system-diagnostics', 'execute_shell')]:
            with self.subTest(server=server, name=name), self.assertRaises(ValueError):
                policy.validate_call(server, name, {})

    def test_cross_host_denied(self):
        with self.assertRaises(ValueError):
            policy.validate_call('rule-b', 'get_service_action_target', {'target': 'a:suricata'})
        policy.validate_call('rule-a', 'get_service_action_target', {'target': 'a:suricata'})

    def test_tool_budget_does_not_reset(self):
        budget = policy.Budget(2)
        budget.take(); budget.take()
        with self.assertRaises(ValueError):
            budget.take()
        self.assertEqual(budget.used, 2)

    def test_endpoint_disallows_embedded_credentials_and_compat_path(self):
        for value in ['http://user:pass@example.com', 'http://example.com/v1',
                      'file:///tmp/model', 'http://example.com?token=x']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.validate_endpoint(value)
        self.assertEqual(policy.validate_endpoint('http://192.0.2.40:11434/'), 'http://192.0.2.40:11434')

    def test_host_path_cannot_escape_home(self):
        home = Path('/opt/hermes-test')
        for path in ['/etc/shadow', '/opt/data/../../etc/shadow']:
            with self.assertRaises(ValueError):
                installer.hostpath(path, home)


class ArtifactBoundary(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='capstone-trial-test-')
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source, self.bundle = self.root / 'source', self.root / 'bundle'
        self.source.mkdir(); self.bundle.mkdir()
        self.doc = {'schema': 1, 'debs': [], 'wheels': []}
        for kind, names in [('debs', ['python3.12-venv', 'python3-pip-whl', 'python3-setuptools-whl']),
                            ('wheels', ['fixture'])]:
            (self.bundle / kind).mkdir()
            for name in names:
                filename = name + ('.deb' if kind == 'debs' else '.whl')
                data = name.encode(); (self.bundle / kind / filename).write_bytes(data)
                self.doc[kind].append({'package': name, 'version': '1', 'architecture': 'all',
                                      'filename': filename, 'size': len(data),
                                      'sha256': hashlib.sha256(data).hexdigest()})
        self.save()
        self.addCleanup(patch.stopall)
        patch.object(installer, 'safe', side_effect=lambda p, **kw: Path(p)).start()
        def metadata(args, **kw):
            name = Path(args[2]).stem
            class Result:
                stdout = ('Package: ' + name + '\nVersion: 1\nArchitecture: all\n').encode()
            return Result()
        patch.object(installer, 'run', side_effect=metadata).start()

    def save(self):
        for base in (self.source, self.bundle):
            (base / 'offline-manifest.json').write_text(json.dumps(self.doc))

    def test_hash_checked_before_install(self):
        installer.bundle_check(self.source, self.bundle)
        (self.bundle / 'wheels/fixture.whl').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact_hash'):
            installer.bundle_check(self.source, self.bundle)

    def test_extra_package_rejected(self):
        (self.bundle / 'wheels/unreviewed.whl').write_bytes(b'unreviewed')
        with self.assertRaisesRegex(ValueError, 'unexpected_artifact'):
            installer.bundle_check(self.source, self.bundle)

    def test_path_traversal_rejected(self):
        self.doc['wheels'][0]['filename'] = '../fixture.whl'; self.save()
        with self.assertRaisesRegex(ValueError, 'artifact_name'):
            installer.bundle_check(self.source, self.bundle)


class JsonProtocol(unittest.TestCase):
    def test_library_output_cannot_corrupt_result(self):
        async def fake_run(config, request):
            print('third-party initialization log')
            return {'status': 'completed', 'final_response': '확인 완료'}
        out, err = io.StringIO(), io.StringIO()
        with patch.object(runtime.os, 'geteuid', return_value=988), \
                patch.object(runtime, 'load_config', return_value={}), \
                patch.object(runtime, 'run', side_effect=fake_run), \
                patch.object(sys, 'argv', ['runtime.py']), \
                patch.object(sys, 'stdin', io.StringIO('{"question":"상태"}')), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(runtime.main(), 0)
        self.assertEqual(json.loads(out.getvalue())['final_response'], '확인 완료')
        self.assertIn('initialization log', err.getvalue())

    def test_root_invocation_rejected_before_mcp(self):
        with patch.object(runtime.os, 'geteuid', return_value=0), \
                patch.object(runtime, 'run') as run, \
                self.assertRaisesRegex(ValueError, 'unprivileged_user_required'):
            runtime.main()
        run.assert_not_called()


class CatalogContract(unittest.TestCase):
    """2026-11-13: B's rule servers gained the Harness² governance tools (11/13
    00:34) and every Ollama run that connected to rule-b stopped with
    server_tool_contract_changed (joint-channel peer reviews 17:23, 20:17,
    20:44, 21:27). The contract is checked against the MCP sources so a new
    server tool fails here first, not in a live chat."""

    @staticmethod
    def _load(name, path):
        spec = importlib.util.spec_from_file_location(name, HERE.parents[1] / path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def test_rule_server_catalogs_match_the_mcp_source(self):
        mcp = self._load('_catalog_rule_change_mcp', 'infra/mcp/rule_change_mcp.py')
        for server, access, host in (('rule-a', 'read', 'a'), ('rule-b', 'read', 'b'),
                                     ('rule-write-a', 'write', 'a'), ('rule-write-b', 'write', 'b')):
            with self.subTest(server=server):
                self.assertEqual({t['name'] for t in mcp.tool_list(access, host)}, policy.CATALOG_TOOLS[server])

    def test_security_events_catalog_matches_the_mcp_source(self):
        server = self._load('_catalog_security_events_mcp', 'infra/mcp/security-events-mcp.py')
        incident = self._load('_catalog_incident_evidence', 'infra/mcp/incident_evidence.py')
        # The advertised list is TOOLS plus the incident bundle tool; only the
        # root-owned path check of the fixed loader is replaced here.
        with patch.object(server, 'fixed_module', return_value=incident):
            listed = server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})['result']['tools']
        self.assertEqual({t['name'] for t in listed}, policy.CATALOG_TOOLS['security-events'])

    def test_live_b_catalogs_are_accepted_without_exposing_governance_tools(self):
        def tools(names): return [SimpleNamespace(name=n) for n in sorted(names)]
        read_b = tools(policy.RULE_READS | {'get_harness_check_status'})
        write_b = tools(policy.PROTECTED_TOOLS['rule-write-b'] | policy.HARNESS_GOVERNANCE_B['rule-write-b'])
        for mode in ('read-only', 'hermes-parity'):
            self.assertEqual({t.name for t in policy.filter_catalog('rule-b', read_b, mode)}, policy.RULE_READS)
        self.assertEqual({t.name for t in policy.filter_catalog('rule-write-b', write_b, 'hermes-parity')},
                         policy.PROTECTED_TOOLS['rule-write-b'])
        with self.assertRaisesRegex(ValueError, 'server_not_authorized'):
            policy.filter_catalog('rule-write-b', write_b, 'read-only')
        for name in ('get_harness_check_status', 'request_harness_check'):
            for server in ('rule-b', 'rule-write-b'):
                with self.assertRaisesRegex(ValueError, 'tool_not_allowed'):
                    policy.alias(server, name)

    def test_other_drift_still_fails_closed(self):
        base = policy.RULE_READS | {'get_harness_check_status'}
        for names in (policy.RULE_READS, base | {'shell'}, base - {'get_security_rules'}):
            with self.subTest(n=len(names)), self.assertRaisesRegex(ValueError, 'server_tool_contract_changed'):
                policy.filter_catalog('rule-b', [SimpleNamespace(name=n) for n in names], 'read-only')
        # Host scope: the B-only tools are drift on A.
        with self.assertRaisesRegex(ValueError, 'server_tool_contract_changed'):
            policy.filter_catalog('rule-a', [SimpleNamespace(name=n) for n in base], 'read-only')

    def test_capabilities_and_read_pool_are_unchanged(self):
        import read_pool
        self.assertEqual(policy.READ_TOOLS['rule-b'], policy.RULE_READS)
        self.assertEqual(policy.PARITY_TOOLS['rule-write-b'], {'propose_rule_edit', 'propose_rule_change', 'propose_service_action'})
        self.assertTrue(read_pool.eligible({'rule-b': {}}, [policy.alias('rule-b', 'get_security_rules')]))


if __name__ == '__main__':
    unittest.main()
