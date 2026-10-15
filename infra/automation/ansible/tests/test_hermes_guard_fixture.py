"""Fail-closed boundaries of the native fixture harness, without Ansible installed."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import hermes_guard_fixture as fixture


class FixtureBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hermes-fixture-unit-')
        self.root = Path(self.temporary.name) / 'case'
        fixture.prepare(self.root, 'success')

    def tearDown(self):
        self.temporary.cleanup()

    def test_command_whitelist_rejects_new_real_executable(self):
        task = {'name': 'unexpected', 'ansible.builtin.command':
                {'argv': ['/bin/sh', '-c', 'exit 0']}}
        with self.assertRaisesRegex(ValueError, 'unexpected_executable'):
            fixture.rewrite_tasks([task], self.root)

    def test_native_copy_cannot_touch_outside_stage(self):
        for target in ('/etc/not-a-real-target', '{{ unrelated }}/file',
                       '{{ guard_stage.path }}/../../escape'):
            task = {'name': 'unexpected', 'ansible.builtin.copy':
                    {'content': 'synthetic', 'dest': target}}
            with self.assertRaisesRegex(ValueError, 'unsafe_native_file_target'):
                fixture.rewrite_tasks([task], self.root)

    def test_unexpected_docker_operation_never_becomes_native_call(self):
        task = {'name': 'unexpected', 'ansible.builtin.command':
                {'argv': ['/usr/local/bin/docker', 'run', 'unused']}}
        with self.assertRaisesRegex(ValueError, 'unexpected_docker_operation'):
            fixture.rewrite_tasks([task], self.root)

    def test_copy_cannot_escape_using_absolute_path_or_parent(self):
        state = json.loads((self.root / 'state.json').read_text())
        source = str(self.root / 'stage/original' / fixture.FILES[0])
        for target in ('/tmp/never-created-by-fixture',
                       str(self.root / 'stage/../../escape')):
            with self.assertRaisesRegex(ValueError, 'fixture_path_escape'):
                fixture.fixture_copy(self.root, copy.deepcopy(state), source, target)

    def test_nested_symlink_cannot_escape_fixture(self):
        outside = Path(self.temporary.name) / 'outside'
        outside.mkdir()
        (self.root / 'stage/link').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'fixture_path_escape'):
            fixture.confine(self.root / 'stage/link/file', self.root / 'stage')

    def test_only_named_container_files_and_identity_accepted(self):
        state = json.loads((self.root / 'state.json').read_text())
        target = str(self.root / 'stage/copied')
        with self.assertRaisesRegex(ValueError, 'unknown_container_file'):
            fixture.fixture_copy(self.root, state,
                                 fixture.IDENTITY + ':/opt/hermes/../data/config.yaml', target)
        with self.assertRaisesRegex(ValueError, 'unknown_start'):
            fixture.shim(self.root, ['docker', 'start', 'hermes'])

    def test_new_module_is_not_silently_executed(self):
        with self.assertRaisesRegex(ValueError, 'unexpected_module'):
            fixture.rewrite_tasks([{'name': 'unexpected',
                                    'ansible.builtin.service': {'name': 'unused'}}], self.root)


if __name__ == '__main__':
    unittest.main()
