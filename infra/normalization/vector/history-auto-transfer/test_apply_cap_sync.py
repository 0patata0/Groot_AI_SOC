"""Pins of the 2026-11-13 transfer bound sync apply scripts (local, no host access).

OLD must be the committed bytes that A/B were observed to run; NEW must be the
reviewed candidate files of that change (commit CAPSYNC; applied 11-13 19:31).
Later changes to this folder have their own apply script and test. The apply
scripts never start a run.
"""
import hashlib
from pathlib import Path
import re
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
BASE = 'f83eedd'  # last commit before the bound change; A/B live SHAs matched it (11-13 17:38)
CAPSYNC = '3f30d52'  # the bound change itself; installed on A/B at 19:31


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def committed(name, commit=BASE):
    rel = HERE.relative_to(REPO) / name
    return subprocess.check_output(['git', '-C', str(REPO), 'show', '%s:%s' % (commit, rel)])


class Pins(unittest.TestCase):
    def test_a_script_pins_old_and_new_exporter(self):
        text = (HERE / 'apply-cap-sync-a.py').read_text()
        self.assertEqual(re.search(r"OLD = '([0-9a-f]{64})'", text)[1], sha(committed('export-a.sh')))
        self.assertEqual(re.search(r"NEW = '([0-9a-f]{64})'", text)[1], sha(committed('export-a.sh', CAPSYNC)))
        self.assertIn("visudo('/etc/sudoers')", text)
        self.assertNotIn('systemctl', text)

    def test_b_script_pins_three_runtime_files(self):
        text = (HERE / 'apply-cap-sync-b.py').read_text()
        for name in ('worker-b.sh', 'transfer-lib.sh', 'runtime.sha256'):
            old = re.search(r"'%s': '([0-9a-f]{64})'" % re.escape(name), text.split('NEW = ')[0])[1]
            new = re.search(r"'%s': '([0-9a-f]{64})'" % re.escape(name), text.split('NEW = ')[1])[1]
            self.assertEqual(old, sha(committed(name)), name)
            self.assertEqual(new, sha(committed(name, CAPSYNC)), name)
        self.assertIn('LOCK_EX', text)
        self.assertNotIn("'systemctl'", text)

    def test_runtime_manifest_and_source_pins_match_files(self):
        for line in (HERE / 'runtime.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, sha((HERE / name).read_bytes()), name)
        for line in (HERE / 'deploy/source-pins.sha256').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(digest, sha((HERE / name).read_bytes()), name)

    def test_only_bounds_changed_in_runtime_sources(self):
        for name, allowed in (('export-a.sh', {'4096', '4097', '256', '16384', '16385', '1024'}),
                              ('worker-b.sh', {'256', '1024'}),
                              ('transfer-lib.sh', {'8192', '8193', '2048', '2049', '16384', '16385', '4096', '4097'})):
            old = [l for l in committed(name).decode().splitlines() if not l.lstrip().startswith('#')]
            new = [l for l in committed(name, CAPSYNC).decode().splitlines() if not l.lstrip().startswith('#')]
            self.assertEqual(len(old), len(new), name)
            for a, b in zip(old, new):
                if a != b:
                    strip = lambda s: re.sub(r'\d+', 'N', re.sub(r'\s+#.*$', '', s))
                    self.assertEqual(strip(a), strip(b), (name, a, b))
                    changed = set(re.findall(r'\d+', a)) ^ set(re.findall(r'\d+', b))
                    self.assertTrue(changed and changed <= allowed, (name, a, b))


if __name__ == '__main__':
    unittest.main()
