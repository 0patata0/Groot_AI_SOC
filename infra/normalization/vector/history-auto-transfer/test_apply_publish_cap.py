"""Pins of the 2026-11-14 publish-bound apply script (local, no host access).

OLD must be the bytes B runs since the 11-13 19:31 bound sync (commit BASE);
NEW must be the reviewed candidate files in this folder. Only the publish
bound may change, and it must cover the worker batch bound times the receipt
bound. The apply script never starts a run.
"""
import difflib
import hashlib
from pathlib import Path
import re
import subprocess
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
BASE = '3f30d52'  # installed on B at 11-13 19:31 (apply-cap-sync-b.py NEW)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def committed(name):
    rel = HERE.relative_to(REPO) / name
    return subprocess.check_output(['git', '-C', str(REPO), 'show', '%s:%s' % (BASE, rel)])


def code(text):
    return [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith('#')]


class Pins(unittest.TestCase):
    def setUp(self):
        self.script = (HERE / 'apply-publish-cap-b.py').read_text()

    def pins(self, label):
        block = self.script.split(label + ' = {')[1].split('}')[0]
        return dict(re.findall(r"'([a-z.0-9-]+)': '([0-9a-f]{64})'", block))

    def test_old_new_and_worker_pins(self):
        old, new = self.pins('OLD'), self.pins('NEW')
        self.assertEqual(set(old), {'transfer-lib.sh', 'runtime.sha256'})
        self.assertEqual(set(new), set(old))
        for name in old:
            self.assertEqual(old[name], sha(committed(name)), name)
            self.assertEqual(new[name], sha((HERE / name).read_bytes()), name)
        worker = re.search(r"WORKER = '([0-9a-f]{64})'", self.script)[1]
        self.assertEqual(worker, sha(committed('worker-b.sh')))
        self.assertEqual(worker, sha((HERE / 'worker-b.sh').read_bytes()))
        self.assertIn('LOCK_EX', self.script)
        self.assertNotIn('systemctl', self.script)

    def test_runtime_manifest_and_source_pins_match_files(self):
        for manifest in ('runtime.sha256', 'deploy/source-pins.sha256'):
            for line in (HERE / manifest).read_text().splitlines():
                digest, name = line.split('  ')
                self.assertEqual(digest, sha((HERE / name).read_bytes()), (manifest, name))

    def test_only_publish_bound_changed(self):
        old = code(committed('transfer-lib.sh').decode())
        new = code((HERE / 'transfer-lib.sh').read_text())
        diff = [l for l in difflib.ndiff(old, new) if l[:2] in ('- ', '+ ')]
        removed = [l[2:] for l in diff if l.startswith('- ')]
        added = [l[2:] for l in diff if l.startswith('+ ')]
        self.assertEqual(removed, ['    if [[ -e $destination || -L $destination ]]; then hat_file "$destination" 600 262144 || return 65; fi'])
        self.assertEqual(added, [
            'HAT_PUBLISH_MAX=4194304',
            '    [[ -f $source && ! -L $source ]] && (( $(stat -c %s -- "$source") <= HAT_PUBLISH_MAX )) || return 65',
            '    if [[ -e $destination || -L $destination ]]; then hat_file "$destination" 600 "$HAT_PUBLISH_MAX" || return 65; fi'])

    def test_publish_bound_covers_batch_and_receipt_bounds(self):
        lib = (HERE / 'transfer-lib.sh').read_text()
        worker = (HERE / 'worker-b.sh').read_text()
        publish = int(re.search(r'^HAT_PUBLISH_MAX=(\d+)$', lib, re.M)[1])
        receipt = int(re.search(r'hat_receipt\(\) \{.*?hat_file "\$path" 600 (\d+)', lib, re.S)[1])
        batches = int(re.search(r'\(\( \$\{#batches\[@\]\} <= (\d+) \)\)', worker)[1])
        self.assertGreaterEqual(publish, batches * receipt)
        # The 11-13 23:36 catalog that stopped finalize fits with room to spare.
        self.assertGreater(publish, 262370)


if __name__ == '__main__':
    unittest.main()
