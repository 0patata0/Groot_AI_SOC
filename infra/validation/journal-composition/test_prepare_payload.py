"""The operating payload must retain the installer's inline execution binding."""
import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('payload_under_test', Path(__file__).with_name('prepare_payload.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class StaticPayload(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads, cls.manifest = m.build(lambda name: (m.ROOT / name).read_bytes(), 'a' * 40)

    def test_real_controller_launch_uses_the_exact_delivered_gate(self):
        gate = self.payloads['b'][m.GATE]
        bound = self.payloads['b'][m.CONTROLLER]
        self.assertNotEqual(bound, (m.ROOT / 'infra/hermes/soc_management_controller.py').read_bytes())
        namespace = {'__name__': 'bound_controller_under_test'}
        exec(compile(bound, 'bound_controller.py', 'exec'), namespace)
        with tempfile.TemporaryDirectory(prefix='payload-binding-') as directory:
            root = Path(directory)
            namespace['__file__'] = str(root / 'soc_management_controller.py')
            (root / 'soc_management_run.py').write_bytes(gate)
            case = {'mode': 'verify', 'session_id': None, 'operator_review': True}
            command = namespace['verified_management_command'](case)
            self.assertNotIn('/opt/data/management-code/run.py', command)
            self.assertEqual(command[command.index('-c') + 1], namespace['management_gate_argument'](gate))
            (root / 'soc_management_run.py').write_bytes(b'# stale gate\n')
            with self.assertRaisesRegex(Exception, 'embedded_gate_source_mismatch'):
                namespace['verified_management_command'](case)

    def test_all_other_source_bytes_and_provenance_are_preserved(self):
        self.assertEqual({role: len(values) for role, values in self.payloads.items()}, {'a': 6, 'b': 32, 'c': 6})
        transformed = []
        for role, rows in self.manifest['hosts'].items():
            for row in rows:
                raw = self.payloads[role][row['target']]
                self.assertEqual(m.sha(raw), row['after_sha256'])
                if row['transform'] == 'identity':
                    self.assertEqual(raw, (m.ROOT / row['source']).read_bytes())
                elif row['transform'] == 'installation_bound_inline_management_gate':
                    transformed.append((role, row['target']))
                    self.assertEqual(row['gate_sha256'], m.sha(self.payloads['b'][m.GATE]))
                else:
                    self.assertIn(row['target'], m.UNITS)
        self.assertEqual(transformed, [('b', m.CONTROLLER)])
        self.assertTrue(all(path not in self.payloads['b'] for path in m.RECEIPTS))

    def test_changed_controller_shape_is_refused_before_a_payload_is_returned(self):
        def read(name):
            raw = (m.ROOT / name).read_bytes()
            if name == 'infra/hermes/soc_management_controller.py':
                return raw.replace(b'/opt/data/management-code/run.py', b'/opt/data/unexpected.py')
            return raw
        with self.assertRaisesRegex(m.binding.Refused, 'management_command_source'):
            m.build(read, 'b' * 40)

    def test_generator_shape_and_git_source_scope_are_bounded(self):
        raw = (m.ROOT / m.GENERATOR).read_bytes()
        with self.assertRaisesRegex(m.contract.Refused, 'unit_generator_source_shape'):
            m.unit_generator(raw.replace(b'def unit_documents(', b'def renamed_unit_documents('))
        with self.assertRaisesRegex(m.contract.Refused, 'source_commit'):
            m.git_reader(m.ROOT, 'HEAD')
        read = m.git_reader(m.ROOT, 'c' * 40)
        with self.assertRaisesRegex(m.contract.Refused, 'source_not_in_catalog'):
            read('CREDENTIALS.local.md')
        self.assertTrue(all(ast.parse(raw) is not None for raw in (
            self.payloads['b'][m.CONTROLLER], self.payloads['b'][m.GATE])))

    def test_receipt_preserves_unrelated_provenance_and_reports_old_drift(self):
        target = '/etc/capstone-ollama-trial/receipt.json'
        source = '/opt/capstone-ollama-trial/runtime.py'
        original = {'schema': 3, 'sources': {'runtime.py': 'a' * 64, 'untouched.py': 'd' * 64},
                    'history': {'private_key_exported': False, 'marker': 'retain this provenance'}}
        raw, changes = m.prepare_receipt(json.dumps(original).encode(), target,
                                         {source: 'b' * 64}, {source: 'c' * 64})
        changed = json.loads(raw)
        self.assertEqual(changed['sources']['runtime.py'], 'c' * 64)
        changed['sources']['runtime.py'] = 'a' * 64
        self.assertEqual(changed, original)
        self.assertTrue(changes[0]['preexisting_receipt_drift'])
        self.assertEqual(changes[0]['observed_source_sha256'], 'b' * 64)

    def test_receipt_missing_entry_or_credential_material_is_not_exported(self):
        source = '/opt/capstone-review-chat/review_channel_worker.py'
        target = '/etc/capstone-review-chat/receipt.json'
        before = {source: 'a' * 64};after = {source: 'b' * 64}
        with self.assertRaisesRegex(m.contract.Refused, 'integrity_receipt_source_missing'):
            m.prepare_receipt(b'{"files": {}}', target, before, after)
        raw = json.dumps({'files': {source: 'a' * 64}, 'api_key': 'credential material forbidden'}).encode()
        with self.assertRaisesRegex(m.contract.Refused, 'credential_field_in_source_receipt'):
            m.prepare_receipt(raw, target, before, after)


if __name__ == '__main__':
    unittest.main()
