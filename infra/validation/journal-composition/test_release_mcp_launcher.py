"""Read-only account fence; no source credentials or operating marker access."""
import hashlib
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('release_mcp_gate_tested',Path(__file__).with_name('release_mcp_launcher.py'))
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
ORIGINAL=b'#!/bin/bash\nset -euo pipefail\n# original readonly routes\nexec /approved/reader\n'


class MCPFence(unittest.TestCase):
    def test_absence_admits_without_touching_stdin_or_sources(self):
        with patch.object(os,'lstat',side_effect=FileNotFoundError)as observed:
            exec(m.GATE_PY,{});observed.assert_called_once_with(m.MARKER)

    def test_existing_marker_including_symlink_or_directory_denies(self):
        for result in (object(),None):
            with patch.object(os,'lstat',return_value=result):
                with self.assertRaises(SystemExit)as err:exec(m.GATE_PY,{})
                self.assertEqual(err.exception.code,75)

    def test_permission_or_other_io_failure_is_not_absence(self):
        for error in (PermissionError,TimeoutError,OSError):
            with patch.object(os,'lstat',side_effect=error):
                with self.assertRaises(SystemExit)as err:exec(m.GATE_PY,{})
                self.assertEqual(err.exception.code,75)

    def test_original_routes_and_sanitization_are_exactly_preserved(self):
        source=m.build(ORIGINAL,hashlib.sha256(ORIGINAL).hexdigest());self.assertTrue(source.startswith(b'#!/bin/bash\nset -euo pipefail\n'))
        import shlex
        guard=('/usr/bin/python3 -I -B -c '+shlex.quote(m.GATE_PY)+'\n').encode()
        self.assertEqual(source.replace(guard,b'',1),ORIGINAL);self.assertEqual(source.count(guard),1)

    def test_unknown_sha_or_shell_shape_cannot_be_injected(self):
        for raw,digest in ((ORIGINAL,'a'*64),(b'#!/bin/sh\nset -eu\n',None),(ORIGINAL+ORIGINAL,None)):
            digest=digest or hashlib.sha256(raw).hexdigest()
            with self.assertRaises(ValueError):m.build(raw,digest)


if __name__=='__main__':unittest.main()
