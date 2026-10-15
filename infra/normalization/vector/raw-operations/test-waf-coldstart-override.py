#!/usr/bin/env python3
"""Offline contract tests. Native rendering/copy is a separate A-only command."""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('coldstart_candidate', HERE / 'verify-waf-coldstart-override.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Exact public image script SHA747bb477; no production config or Env data.
SCRIPT = b'''#!/bin/sh
# vim:sw=2:ts=2:sts=2:et

set -eu

LC_ALL=C
ME=$( basename "$0" )
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

touch /etc/modsecurity.d/modsecurity-override.conf 2>/dev/null || { echo >&2 "$ME: error: can not modify /etc/modsecurity.d/modsecurity-override.conf (read-only file system?)"; exit 1; }

cp /etc/nginx/modsecurity.d/*.conf /etc/modsecurity.d 2>/dev/null || { echo >&2 "$ME: error: cannot copy config files to /etc/modsecurity.d"; exit 2; }

exit 0
'''


class Contract(unittest.TestCase):
    def test_exact_public_script_and_path_only_mapping(self):
        self.assertEqual(module.sha(SCRIPT), module.EXPECTED[module.SCRIPT90][0])
        temporary = '/tmp/capstone-waf-coldstart-' + 'a' * 32
        candidate = module.rendered_copy_script(SCRIPT, temporary)
        self.assertNotIn(b'/etc/modsecurity.d', candidate)
        self.assertNotIn(b'/etc/nginx/modsecurity.d', candidate)
        restored = candidate.replace((temporary + '/output/modsecurity.d').encode(), b'/etc/nginx/modsecurity.d')
        restored = restored.replace((temporary + '/destination').encode(), b'/etc/modsecurity.d')
        self.assertEqual(restored, SCRIPT)
        self.assertIn(b'/*.conf', candidate)

    def test_changed_native_source_refused(self):
        with self.assertRaisesRegex(module.Refusal, 'copy_script_pin_conflict'):
            module.rendered_copy_script(SCRIPT + b'# drift\n', '/tmp/capstone-waf-coldstart-' + 'a' * 32)

    def test_arbitrary_or_parent_private_path_refused(self):
        for value in ('/etc', '/tmp/capstone-waf-coldstart-' + 'a' * 32 + '/../etc',
                      '/tmp/capstone-waf-coldstart-' + 'g' * 32, '/tmp/capstone-waf-coldstart-'):
            with self.subTest(value=value), self.assertRaisesRegex(module.Refusal, 'invalid_private_copy_path'):
                module.rendered_copy_script(SCRIPT, value)

    def test_template_and_intermediate_are_only_planned_changes(self):
        self.assertEqual(module.EXPECTED[module.TEMPLATE], (module.OLD_SHA, 0, 0, 0o644))
        self.assertEqual(module.EXPECTED[module.INTERMEDIATE], (module.OLD_SHA, 101, 101, 0o644))
        self.assertEqual(module.EXPECTED[module.TARGET], (module.TARGET_SHA, 101, 101, 0o644))
        self.assertEqual(module.COPY_NAMES, ('modsecurity-override.conf', 'modsecurity.conf', 'setup.conf'))

    def test_nonfixed_host_rejected_before_any_evidence_creation(self):
        with mock.patch.object(module.os, 'geteuid', return_value=1000), \
             mock.patch.object(module.Path, 'mkdir') as mkdir:
            with self.assertRaisesRegex(module.Refusal, 'fixed_A_root_required'):
                module.run(Path('/var/tmp/capstone-resume-20261014/step3/waf-coldstart-fixture'))
            mkdir.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
