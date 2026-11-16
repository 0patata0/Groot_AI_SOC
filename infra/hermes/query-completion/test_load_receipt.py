"""Gateway load observations; all writes stay in a temporary fake home."""
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_completion as fixtures

P = fixtures.PLUGIN


class LoadReceipt(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-load-receipt-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.home.chmod(0o700)
        self.plugin = self.home / 'plugins/groot-query-completion'; self.plugin.mkdir(parents=True)
        original = Path(P.__file__)
        files = {'__init__.py': original,
            'grounding.py': Path(P.EVIDENCE.__file__),
            'workflow_contract.py': original.parent.parent / 'workflow_contract.py',
            'skill-soc-investigate.md': original.parent.parent / 'skills/soc-investigate/SKILL.md',
            'chat_harness.py': original.parents[2] / 'ollama-trial/harness.py'}
        for name, source in files.items(): (self.plugin / name).write_bytes(source.read_bytes())
        env = patch.dict(P.os.environ, {'HERMES_HOME': str(self.home)}, clear=True)
        file = patch.object(P, '__file__', str(self.plugin / '__init__.py'))
        env.start(); file.start(); self.addCleanup(env.stop); self.addCleanup(file.stop)
        read_text = Path.read_text
        def proc(path, *args, **kwargs):
            if path == Path('/proc/self/stat'):
                return '111 (worker (test)) ' + ' '.join(['S'] + ['0'] * 18 + ['123456'])
            return read_text(path, *args, **kwargs)
        proc_patch = patch.object(Path, 'read_text', proc); proc_patch.start(); self.addCleanup(proc_patch.stop)
        self.receipt = self.home / 'health/query-completion.json'

    def test_fixed_receipt_binds_version_pid_start_and_loaded_evidence(self):
        self.assertTrue(P.publish_load_receipt(True)); v = json.loads(self.receipt.read_text())
        self.assertEqual(set(v), {'schema_version', 'adapter_version', 'pid', 'process_start_ticks',
            'observed_at_kst', 'aliases_installed', 'loaded_evidence_sha256', 'observed_sources_sha256'})
        self.assertEqual(v['adapter_version'], P.VERSION); self.assertEqual(v['pid'], os.getpid())
        self.assertEqual(v['process_start_ticks'], 123456); self.assertIs(v['aliases_installed'], True)
        self.assertEqual(v['loaded_evidence_sha256'], P.EVIDENCE_SOURCE_SHA256)
        self.assertEqual(datetime.fromisoformat(v['observed_at_kst']).utcoffset(), timedelta(hours=9))
        for name, sha in v['observed_sources_sha256'].items():
            self.assertEqual(sha, hashlib.sha256((self.plugin / name).read_bytes()).hexdigest())
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertFalse(list((self.home / 'health').glob('.query-load-*')))

    def test_unload_is_observed_as_not_installed(self):
        P.publish_load_receipt(True); P.publish_load_receipt(False)
        self.assertIs(json.loads(self.receipt.read_text())['aliases_installed'], False)

    def test_non_boolean_never_reports_success(self):
        P.publish_load_receipt(1)
        self.assertIs(json.loads(self.receipt.read_text())['aliases_installed'], False)

    def test_missing_environment_never_creates_a_home(self):
        with patch.dict(P.os.environ, {}, clear=True): self.assertFalse(P.publish_load_receipt(True))
        self.assertFalse(self.receipt.exists())

    def test_non_gateway_profile_and_other_source_location_do_not_write(self):
        for value in (str(self.home / 'management'), 'relative'):
            with patch.dict(P.os.environ, {'HERMES_HOME': value}, clear=True):
                self.assertFalse(P.publish_load_receipt(True))
        with patch.object(P, '__file__', '/opt/capstone-ollama-trial/query_grounding.py'):
            self.assertFalse(P.publish_load_receipt(True))
        self.assertFalse(self.receipt.exists())

    def test_unsafe_home_and_health_directory_are_rejected(self):
        self.home.chmod(0o777)
        with self.assertRaises(ValueError): P.publish_load_receipt(True)
        self.home.chmod(0o700); health = self.home / 'health'; health.mkdir(); health.chmod(0o777)
        with self.assertRaises(ValueError): P.publish_load_receipt(True)
        self.assertFalse(self.receipt.exists())

    def test_symlink_health_cannot_redirect_writes(self):
        outside = self.home / 'outside'; outside.mkdir(); (self.home / 'health').symlink_to(outside)
        with self.assertRaises(ValueError): P.publish_load_receipt(True)
        self.assertFalse(list(outside.iterdir()))

    def test_symlink_receipt_does_not_change_its_target(self):
        health = self.home / 'health'; health.mkdir(mode=0o700)
        outside = self.home / 'outside'; outside.write_text('keep'); self.receipt.symlink_to(outside)
        with self.assertRaises(ValueError): P.publish_load_receipt(True)
        self.assertEqual(outside.read_text(), 'keep')

    def test_symlink_source_is_rejected(self):
        target = self.plugin / 'grounding.py'; outside = self.home / 'source'
        outside.write_bytes(target.read_bytes()); target.unlink(); target.symlink_to(outside)
        with self.assertRaises(ValueError): P.publish_load_receipt(True)
        self.assertFalse(self.receipt.exists())

    def test_evidence_drift_cannot_produce_a_load_observation(self):
        (self.plugin / 'grounding.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'evidence_drift'): P.publish_load_receipt(True)
        self.assertFalse(self.receipt.exists())

    def test_atomic_write_failure_preserves_previous_receipt(self):
        P.publish_load_receipt(True); before = self.receipt.read_bytes()
        with patch.object(P.os, 'replace', side_effect=OSError('injected')):
            with self.assertRaises(OSError): P.publish_load_receipt(False)
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertFalse(list((self.home / 'health').glob('.query-load-*')))


if __name__ == '__main__':
    unittest.main()
