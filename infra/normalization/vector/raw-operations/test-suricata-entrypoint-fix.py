#!/usr/bin/env python3
"""Finite private fixture for the installed Suricata entrypoint correction.

Only the pinned fix_perms function is executed, with all four absolute trees
rewritten below a private task directory. No entrypoint main, Suricata process,
container/service control, real config/log path or checkpoint is invoked.
Run inside the existing container as root with CAPSTONE_ENTRYPOINT_FIXTURE_ROOT.
"""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).absolute().parent
OLD_SHA = '49a6e84e7bd4aab2187483e7556e96e9e1dba641c3d6fda09c253a329279aef1'
NEW_SHA = 'eb6820266481f699306eb5730b9fd4b9276f37705450ff5cefe2eb9e3aaa9d47'
OLD_LINE = b'    chown -R suricata:suricata /var/log/suricata\n'
NEW_LINES = (b'    /usr/bin/find /var/log/suricata \\\n'
             b'        \\( -path /var/log/suricata/capstone-managed -o -path /var/log/suricata/eve.json \\) -prune -o \\\n'
             b'        -exec chown --no-dereference suricata:suricata -- {} +\n')
TREES = ('/etc/suricata', '/var/lib/suricata', '/var/log/suricata', '/var/run/suricata')


def source(candidate=True):
    path = HERE / ('suricata-entrypoint-managed.sh' if candidate else 'suricata-entrypoint-original.sh')
    assert not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (NEW_SHA if candidate else OLD_SHA)
    return raw


def isolated_function(root, candidate=True):
    raw = source(candidate).decode('ascii')
    assert raw.count('fix_perms() {') == 1
    function = 'fix_perms() {' + raw.split('fix_perms() {', 1)[1].split('\n}', 1)[0] + '\n}\n'
    # Only fixed prefixes are substituted; no operating directory is mounted
    # or read. PGID/PUID are empty, so groupmod/usermod branches do not run.
    for path in TREES:
        function = function.replace(path, str(root) + path)
    assert 'exec /usr/bin/suricata' not in function and 'check_for_cap' not in function
    assert function.count(str(root)) == (6 if candidate else 4)
    return 'set -e\n' + function + 'fix_perms\n'


class SourceContracts(unittest.TestCase):
    def test_exact_single_log_chown_replacement(self):
        old, new = source(False), source(True)
        self.assertEqual(old.count(OLD_LINE), 1)
        self.assertEqual(new, old.replace(OLD_LINE, NEW_LINES, 1))
        self.assertEqual(new.replace(NEW_LINES, OLD_LINE, 1), old)

    def test_bash_syntax_and_function_only_extraction(self):
        for candidate in (False, True):
            program = isolated_function(Path('/tmp/capstone-synthetic-only'), candidate)
            result = subprocess.run(['/bin/bash', '-n'], input=program.encode(), capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertNotIn('crond', program)
            self.assertNotIn('/etc/suricata.dist', program)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                     'native fixture requires existing Suricata container root')
class NativeContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_parent = Path(os.environ['CAPSTONE_ENTRYPOINT_FIXTURE_ROOT'])
        assert cls.fixture_parent.is_absolute() and '..' not in cls.fixture_parent.parts
        assert re.fullmatch(r'/(?:var/tmp|tmp)/capstone-[A-Za-z0-9._/-]+', str(cls.fixture_parent))
        for parent in (cls.fixture_parent, *cls.fixture_parent.parents):
            assert not parent.is_symlink() and parent.is_dir()
        info = cls.fixture_parent.stat()
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700)
        account = pwd.getpwnam('suricata')
        assert account.pw_uid == account.pw_gid == 998
        result = subprocess.run(['/usr/bin/find', '--version'], capture_output=True, timeout=5)
        assert result.returncode == 0 and result.stdout.splitlines()[0] == b'find (GNU findutils) 4.8.0'

    def setUp(self):
        self.area = tempfile.TemporaryDirectory(prefix='case-', dir=self.fixture_parent)
        self.root = Path(self.area.name)
        for path in TREES:
            directory = self.root / path.lstrip('/')
            directory.mkdir(parents=True)
            (directory / 'normal.log').write_bytes(b'fixture\n')
        self.logs = self.root / 'var/log/suricata'
        self.managed = self.logs / 'capstone-managed'
        self.managed.mkdir(mode=0o711)
        self.managed.chmod(0o711)
        managed_info = self.managed.stat()
        self.assertEqual((managed_info.st_uid, managed_info.st_gid, stat.S_IMODE(managed_info.st_mode)),
                         (0, 0, 0o711))
        self.closed = self.managed / 'generation-0000000000.jsonl'
        self.closed.write_bytes(b'{"synthetic":"closed"}\n')
        self.closed.chmod(0o400)
        os.link(self.closed, self.logs / 'eve.json')
        self.active = self.managed / 'generation-0000000001.jsonl'
        self.active.write_bytes(b'{"synthetic":"active"}\n')
        os.chown(self.active, 998, 998); self.active.chmod(0o644)
        os.link(self.active, self.managed / 'active.jsonl')
        self.outside = self.root / 'outside-sentinel'
        self.outside.write_bytes(b'private sentinel\n'); self.outside.chmod(0o400)
        (self.logs / 'outside-link').symlink_to(self.outside)
        (self.logs / 'closed-link').symlink_to(self.closed)
        (self.logs / 'normal with spaces.log').write_bytes(b'fixture\n')

    def tearDown(self):
        self.area.cleanup()

    def run_function(self, candidate=True, fail_log_chown=False):
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'PGID': '', 'PUID': ''}
        if fail_log_chown:
            directory = self.root / 'bin'; directory.mkdir()
            wrapper = directory / 'chown'
            # The wrapper still executes the installed chown for every other
            # tree. The fixed fixture log path alone simulates an actual error.
            wrapper.write_text('#!/bin/bash\nfor arg; do\n  case "$arg" in ' + str(self.logs) +
                               '|' + str(self.logs) + '/*) exit 41;; esac\ndone\nexec /usr/bin/chown "$@"\n')
            wrapper.chmod(0o500)
            env['PATH'] = str(directory) + ':' + env['PATH']
        return subprocess.run(['/bin/bash', '--noprofile', '--norc'],
                              input=isolated_function(self.root, candidate).encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=10)

    def test_original_reproduces_managed_and_sealed_ownership_damage(self):
        result = self.run_function(False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.managed.stat().st_uid, 998)
        self.assertEqual(self.closed.stat().st_uid, 998)
        self.assertEqual((self.logs / 'eve.json').stat().st_ino, self.closed.stat().st_ino)

    def test_candidate_preserves_root_seal_alias_and_active_writer(self):
        initial = {path: (path.stat(), path.read_bytes() if path.is_file() else None)
                   for path in (self.managed, self.closed, self.logs / 'eve.json', self.active,
                                self.managed / 'active.jsonl', self.outside)}
        result = self.run_function()
        self.assertEqual(result.returncode, 0)
        for path, (before, content) in initial.items():
            after = path.stat()
            self.assertEqual((after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_nlink),
                             (before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_nlink))
            if content is not None: self.assertEqual(path.read_bytes(), content)
        self.assertEqual((self.logs / 'closed-link').lstat().st_uid, 998)
        self.assertEqual((self.logs / 'outside-link').lstat().st_uid, 998)
        for path in TREES:
            self.assertEqual((self.root / path.lstrip('/') / 'normal.log').stat().st_uid, 998)
        self.assertEqual((self.logs / 'normal with spaces.log').stat().st_uid, 998)

    def test_repeat_keeps_exact_sealed_identity_and_content(self):
        self.assertEqual(self.run_function().returncode, 0)
        before = self.closed.stat(); content = self.closed.read_bytes()
        self.assertEqual(self.run_function().returncode, 0)
        after = self.closed.stat()
        self.assertEqual((after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_nlink),
                         (before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_nlink))
        self.assertEqual(self.closed.read_bytes(), content)

    def test_find_exec_chown_failure_propagates_and_stops_following_step(self):
        result = self.run_function(fail_log_chown=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'etc/suricata/normal.log').stat().st_uid, 998)
        self.assertEqual((self.root / 'var/lib/suricata/normal.log').stat().st_uid, 998)
        self.assertEqual((self.root / 'var/run/suricata/normal.log').stat().st_uid, 0)
        self.assertEqual(self.closed.stat().st_uid, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
