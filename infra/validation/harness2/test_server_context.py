import copy
import os
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('server_context', Path(__file__).with_name('server_context.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def discovered():
    return {'status': 'discovered', 'calls': [], 'model_calls': [], 'protected_calls': 0,
            'chat_posts': 0, 'model': 'model:trained', 'access_mode': 'hermes-parity',
            'catalog': [{'server': 'rule-b', 'name': 'get_rule_change_target',
                         'alias': 'mcp__rule_b__get_rule_change_target', 'schema_sha256': 'a' * 64}]}


class ContextCapture(unittest.TestCase):
    def test_source_reader_rejects_links_world_writes_and_nonfiles(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory); good = root / 'source.py'; good.write_text('original')
            allowed = {0, os.geteuid()}
            raw, meta = c.source_bytes(good, allowed)
            self.assertEqual(raw, b'original')
            self.assertEqual(meta['uid'], os.geteuid())
            linked = root / 'link.py'; linked.symlink_to(good)
            with self.assertRaises(OSError): c.source_bytes(linked, allowed)
            hard = root / 'hard.py'; os.link(good, hard)
            with self.assertRaises(ValueError): c.source_bytes(good, allowed)
            hard.unlink(); good.chmod(0o666)
            with self.assertRaises(ValueError): c.source_bytes(good, allowed)
            good.chmod(0o600)
            if os.geteuid():
                with self.assertRaises(ValueError): c.source_bytes(good, {0})
            with self.assertRaises(ValueError): c.source_bytes(root, allowed)

    def test_source_reader_does_not_follow_parent_symlink(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory); actual = root / 'actual'; actual.mkdir()
            (actual / 'source').write_text('unchanged')
            (root / 'alias').symlink_to(actual, target_is_directory=True)
            with self.assertRaises(OSError): c.source_bytes(root / 'alias/source', {0, os.geteuid()})

    def test_projection_excludes_unrequested_runtime_fields(self):
        value = discovered()
        value['secret_environment'] = 'must-never-be-published'
        result = c.discovery_projection(value)
        self.assertNotIn('must-never', json.dumps(result))
        self.assertEqual(result['catalog'], value['catalog'])
        self.assertIn('not tested', result['model_observation'])

    def test_non_discovery_unknown_calls_and_catalog_identity_are_refused(self):
        mutations = [lambda v: v.update(calls=[{}]), lambda v: v.update(model_calls=[{}]),
                     lambda v: v.update(protected_calls=True), lambda v: v.update(chat_posts=1),
                     lambda v: v.update(status='completed'), lambda v: v.update(model='bad\nmodel'),
                     lambda v: v['catalog'].append(v['catalog'][0]),
                     lambda v: v['catalog'][0].update(alias='mcp__rule_a__get_rule_change_target'),
                     lambda v: v['catalog'][0].update(input={'password': 'never'})]
        for mutation in mutations:
            value = discovered(); mutation(value)
            with self.assertRaises(ValueError): c.discovery_projection(value)

    def test_fixed_discovery_has_no_shell_or_model_request(self):
        seen = []
        def run(args, **kwargs):
            seen.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout=json.dumps(discovered()), stderr='private')
        with patch.object(c, 'read_fixed_hash', return_value='a' * 64):
            result = c.collect(run)
        self.assertEqual(result['status'], 'observed')
        args, kwargs = seen[0]
        self.assertEqual(args, [c.ENTRYPOINT])
        self.assertTrue(json.loads(kwargs['input'])['discover_only'])
        self.assertNotIn('shell', kwargs)
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual(result['model_calls'], 0)

    def test_failure_does_not_claim_verified_zero_activity_or_publish_stderr(self):
        for result in (SimpleNamespace(returncode=1, stdout='', stderr='secret'),
                       SimpleNamespace(returncode=0, stdout='not json', stderr='secret')):
            with patch.object(c, 'read_fixed_hash', return_value='a' * 64):
                value = c.collect(lambda *a, **k: result)
            self.assertEqual(value['status'], 'unavailable')
            self.assertIsNone(value['model_calls'])
            self.assertNotIn('secret', json.dumps(value))

    def test_timeout_is_an_unavailable_observation(self):
        def timeout(*args, **kwargs): raise subprocess.TimeoutExpired('fixed', 75)
        with patch.object(c, 'read_fixed_hash', return_value='a' * 64): value = c.collect(timeout)
        self.assertEqual(value['error_code'], 'discovery_timeout')

    def test_atomic_publishing_refuses_symlinks_and_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            path = root / 'context.json'
            c.publish({'status': 'unavailable'}, path)
            self.assertEqual(json.loads(path.read_text())['status'], 'unavailable')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            target = root / 'outside'; target.write_text('unchanged')
            path.unlink(); path.symlink_to(target)
            with self.assertRaises(ValueError): c.publish({}, path)
            self.assertEqual(target.read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main()
