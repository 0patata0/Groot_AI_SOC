#!/usr/bin/env python3
"""Offline policy checks and Linux/root native fixture; no live Docker/systemd.

The real candidate functions are sourced. Absolute timeout is a Bash function
stub which accepts only the two exact Docker forms, never invokes Docker, and
stops before real generation sealing. Existing 30+24 fixtures are also rerun
unchanged against a private copy of the candidate under coordinator.sh.
"""
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
ORIGINAL = HERE / 'coordinator.sh'
CANDIDATE = HERE / 'coordinator-native-user-fix.sh'
ORIGINAL_SHA = '95f86e2db4115b929193fa9fac5c81fd4ad5cc98afc65ed3cad42dd7c950063e'
OLD = b'/usr/local/bin/docker exec --user 0 "$RO_CID" /usr/sbin/nginx -t'
NEW = OLD.replace(b'--user 0 ', b'--user 101:101 ')
NATIVE = sys.platform == 'linux' and os.geteuid() == 0 and Path('/usr/bin/jq').is_file()

# No original source/global initialization invokes a production command; the
# dispatcher is not called. The gate stub always prevents real seal/stat/write.
FIXTURE = r'''
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
source "$1"
case_dir=$2
mode=$3
RO_MANAGED=$case_dir/managed RO_NEXT=$case_dir/generation-0000000001.jsonl
RO_CURRENT=$case_dir/generation-0000000000.jsonl
RO_ENGINE=modsecurity RO_CID=synthetic-fixed-cid RO_CONTAINER=synthetic-fixed-name
RO_OLD_DEV=100 RO_OLD_INO=200
RO_WRITER='{"pid":1234,"start_ticks":5678}'
RO_STATE='{"pending":{"writer_config_sha256":"synthetic-sha"}}'
: > "$case_dir/calls"
: > "$case_dir/gates"
ro_validate() { [[ $mode != validation_failed ]]; }
ro_sha() { printf '%s\n' synthetic-sha; }
ro_devino() { printf '%s\n' 100:201; }
ro_replace_link() { return 99; }
writer_identity() {
  if [[ $mode == identity_changed ]]; then printf '{"identity":{"pid":4321,"start_ticks":8765}}\n'
  else printf '{"identity":%s}\n' "$RO_WRITER"; fi
}
writer_gate() { printf 'gate\n' >> "$case_dir/gates"; return 1; }
function /usr/bin/timeout {
  [[ $# -ge 5 && $1 == --signal=TERM && $2 == --kill-after=1s && $3 == 10s &&
     $4 == /usr/local/bin/docker ]] || return 98
  shift 4
  if [[ $# == 6 && $1 == exec && $2 == --user && $3 == 101:101 &&
        $4 == "$RO_CID" && $5 == /usr/sbin/nginx && $6 == -t ]]; then
    printf 'nginx:101:101\n' >> "$case_dir/calls"
    case $mode in native_failed) return 13 ;; native_timeout) return 124 ;; esac
    return 0
  elif [[ $# == 3 && $1 == kill && $2 == --signal=HUP && $3 == "$RO_CID" ]]; then
    printf 'hup\n' >> "$case_dir/calls"
    [[ $mode != hup_timeout ]] || return 124
    return 0
  elif [[ $# == 7 && $1 == exec && $2 == --user && $3 == 0 &&
          $4 == "$RO_CID" && $5 == /usr/bin/sha256sum && $6 == -- && $7 == /synthetic/config ]]; then
    printf 'hash:0\n' >> "$case_dir/calls"
    printf 'expected-sha  /synthetic/config\n'
    return 0
  fi
  printf 'unexpected_command\n' >> "$case_dir/calls"
  return 98
}
[[ $mode != suricata ]] || RO_ENGINE=suricata
rc=0
if [[ $mode == hash_check ]]; then ro_pin_container /synthetic/config expected-sha || rc=$?
else ro_switch_writer || rc=$?; fi
printf '{"rc":%s,"reason":"%s"}\n' "$rc" "$RO_REASON"
'''


class Policy(unittest.TestCase):
    def test_exact_original_and_one_uid_change(self):
        original, candidate = ORIGINAL.read_bytes(), CANDIDATE.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), ORIGINAL_SHA)
        self.assertEqual(original.count(OLD), 1)
        self.assertEqual(candidate, original.replace(OLD, NEW))

    def test_bash_syntax(self):
        result = subprocess.run(['/bin/bash', '-n', str(CANDIDATE)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)


@unittest.skipUnless(NATIVE, 'requires installed Linux/root coreutils and jq; no installation')
class NativeUID(unittest.TestCase):
    def check(self, mode, rc, reason, calls, gates=0):
        with tempfile.TemporaryDirectory(prefix='capstone-native-user-test.', dir='/var/tmp') as directory:
            root = Path(directory)
            result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', FIXTURE,
                                     'native-user-fixture', str(CANDIDATE), directory, mode],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, 'synthetic function fixture failed')
            self.assertEqual(json.loads(result.stdout), {'rc': rc, 'reason': reason})
            self.assertEqual((root / 'calls').read_text().splitlines(), calls)
            self.assertEqual(len((root / 'gates').read_text().splitlines()), gates)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['calls', 'gates'])
        self.assertFalse(root.exists())

    def test_waf_owner_check_precedes_one_hup(self):
        self.check('ok', 2, 'old_writer_reopen_pending', ['nginx:101:101', 'hup'], 1)

    def test_native_failure_does_not_signal(self):
        self.check('native_failed', 2, 'native_writer_config_test_failed', ['nginx:101:101'])

    def test_native_timeout_does_not_signal(self):
        self.check('native_timeout', 2, 'native_writer_config_test_failed', ['nginx:101:101'])

    def test_writer_identity_change_does_not_signal(self):
        self.check('identity_changed', 2, 'writer_changed_before_signal', ['nginx:101:101'])

    def test_uncertain_hup_is_not_retried(self):
        self.check('hup_timeout', 2, 'writer_reopen_uncertain', ['nginx:101:101', 'hup'])

    def test_suricata_path_never_runs_nginx(self):
        self.check('suricata', 2, 'old_writer_reopen_pending', ['hup'], 1)

    def test_validation_failure_does_not_execute_docker(self):
        self.check('validation_failed', 2, 'unspecified', [])

    def test_readonly_hash_check_keeps_root_uid(self):
        self.check('hash_check', 0, 'unspecified', ['hash:0'])


@unittest.skipUnless(NATIVE, 'requires installed Linux/root native fixture dependencies')
class ExistingRegressions(unittest.TestCase):
    def check_existing(self, name, expected_cases):
        names = ['state-lib.sh', 'state.jq', 'guard.sh', 'checkpoint-gates.sh',
                 'checkpoint-gates.jq', 'writer-gates.sh', name]
        original_hashes = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}
        with tempfile.TemporaryDirectory(prefix='capstone-native-user-test.', dir='/var/tmp') as directory:
            root = Path(directory)
            for name in names:
                shutil.copyfile(HERE / name, root / name)
            shutil.copyfile(CANDIDATE, root / 'coordinator.sh')
            result = subprocess.run(['/bin/bash', str(root / name)], capture_output=True,
                                    text=True, timeout=90)
            self.assertEqual(result.returncode, 0, 'existing synthetic native fixture failed')
            output = json.loads(result.stdout.strip())
            self.assertEqual(output['status'], 'passed')
            self.assertEqual(output['cases'], expected_cases)
            self.assertFalse(output['systemd_or_docker_called'])
            self.assertFalse(output['operational_files_touched'])
            self.assertTrue(output['fixture_removed'])
        self.assertFalse(root.exists())
        for name, digest in original_hashes.items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)

    def test_existing_dispatch_and_guard_30(self):
        self.check_existing('test-coordinator-native.sh', 30)

    def test_existing_stop_intent_24(self):
        self.check_existing('test-stop-intent-native.sh', 24)


if __name__ == '__main__':
    unittest.main(verbosity=2)
