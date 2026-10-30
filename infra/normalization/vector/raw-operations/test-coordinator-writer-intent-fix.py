#!/usr/bin/env python3
"""Bounded operator test runner, private fixtures only; no packages or services."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE / 'coordinator-writer-intent-fix.sh'
BASE = HERE / 'coordinator-writer-reopen-fix.sh'
NATIVE = sys.platform == 'linux' and os.geteuid() == 0 and Path('/usr/bin/jq').is_file()


class SourcePolicy(unittest.TestCase):
    def test_previous_candidate_unchanged(self):
        self.assertEqual(hashlib.sha256(BASE.read_bytes()).hexdigest(),
                         '1400f4a255438f5b3f191ef36cfd345a5ab52b9efb71f63becd8a6a33df7a7a3')
        self.assertEqual(hashlib.sha256((HERE / 'state-lib.sh').read_bytes()).hexdigest(),
                         'd754d17726310a56c77e5d37c41f0ae3883881dfbc91bfa20b7ef916fe428f3a')

    def test_bash_syntax(self):
        for name in ('coordinator-writer-intent-fix.sh', 'test-writer-intent-native.sh'):
            self.assertEqual(subprocess.run(['/bin/bash', '-n', str(HERE / name)], capture_output=True, timeout=10).returncode, 0)


@unittest.skipUnless(NATIVE, 'installed Linux/root native tools required; no installation')
class Native(unittest.TestCase):
    def run_suite(self, test_name, expected_cases, fixture_root_override=False):
        names = ['state-lib.sh', 'state.jq', 'guard.sh', 'checkpoint-gates.sh',
                 'checkpoint-gates.jq', 'writer-gates.sh', test_name]
        hashes = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}
        with tempfile.TemporaryDirectory(prefix='capstone-signal-suite.', dir='/var/tmp') as directory:
            root = Path(directory)
            for name in names:
                shutil.copyfile(HERE / name, root / name)
            shutil.copyfile(CANDIDATE, root / 'coordinator.sh')
            shutil.copyfile(CANDIDATE, root / CANDIDATE.name)
            if fixture_root_override:
                # The original test remains untouched. New absent-marker probes
                # must read only this private root even in old mocked cases.
                test = root / test_name
                data = test.read_text()
                anchor = 'source "$here/coordinator.sh"\n'
                self.assertEqual(data.count(anchor), 1)
                additions = 'RO_ROOT=$here/synthetic-empty-state\n'
                if test_name == 'test-stop-intent-native.sh':
                    # This old suite intentionally mocks raw files and all EOF
                    # gates. Its private copy also mocks the newly introduced
                    # prefix gate; the new 28-case suite tests five prefix cases
                    # against actual private files. Never alter the original.
                    additions += 'ro_prefix_distinct() { [[ $# == 1 && $1 == 4 ]]; }\n'
                test.write_text(data.replace(anchor, anchor + additions))
            result = subprocess.run(['/bin/bash', str(root / test_name)], capture_output=True,
                                    text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stdout[:4096])
            report = json.loads(result.stdout.strip())
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(report['cases'], expected_cases)
            self.assertFalse(report['systemd_or_docker_called'])
            self.assertFalse(report['operational_files_touched'])
            self.assertTrue(report['fixture_removed'])
        self.assertFalse(root.exists())
        for name, digest in hashes.items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)

    def test_native_durable_intent_33(self):
        self.run_suite('test-writer-intent-native.sh', 33)

    def test_existing_dispatch_and_guard_30(self):
        self.run_suite('test-coordinator-native.sh', 30, True)

    def test_existing_stop_intent_24(self):
        self.run_suite('test-stop-intent-native.sh', 24, True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
