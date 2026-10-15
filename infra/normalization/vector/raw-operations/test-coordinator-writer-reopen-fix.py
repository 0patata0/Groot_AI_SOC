#!/usr/bin/env python3
"""Private native files and exact command stubs; no operating Docker/systemd.

This tests observed-FD decisions, not power-loss or lost-HUP exactly-once.
An old-open/new-closed snapshot cannot identify a previous unacknowledged HUP.
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
BASE = HERE / 'coordinator-native-user-fix.sh'
CANDIDATE = HERE / 'coordinator-writer-reopen-fix.sh'
BASE_SHA = '2f8fdfc42c14ad7b7abd8643644a76005b415ce0f1f06cebbe6e2fc9233e3914'
NATIVE = sys.platform == 'linux' and os.geteuid() == 0 and Path('/usr/bin/jq').is_file()

FIXTURE = r'''
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
source "$1"
case_dir=$2 mode=$3
RO_ENGINE=modsecurity RO_CONTAINER=waf RO_CID=$(printf 'c%.0s' {1..64})
RO_MANAGED=$case_dir/managed
mkdir -m 700 "$RO_MANAGED"
RO_CURRENT=$RO_MANAGED/generation-0000000001.jsonl
RO_NEXT=$RO_MANAGED/generation-0000000002.jsonl
printf 'synthetic-old\n' > "$RO_CURRENT"
printf 'synthetic-new\n' > "$RO_NEXT"
chmod 644 "$RO_CURRENT" "$RO_NEXT"
RO_OLD_DEV=$(stat -c %d "$RO_CURRENT") RO_OLD_INO=$(stat -c %i "$RO_CURRENT")
RO_NEW_DEV=$(stat -c %d "$RO_NEXT") RO_NEW_INO=$(stat -c %i "$RO_NEXT")
if [[ $mode == suricata_already_reopened ]]; then
  RO_ENGINE=suricata RO_CONTAINER=suricata
  ln "$RO_NEXT" "$RO_MANAGED/active.jsonl"
fi
printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${RO_NEXT##*/}" > "$RO_MANAGED/audit-path.conf"
chmod 444 "$RO_MANAGED/audit-path.conf"
RO_WRITER=$(jq -nc --arg cid "$RO_CID" '{cid:$cid,pid:1234,start_ticks:"5678",mount_ns:"mnt:[11]",pid_ns:"pid:[12]",uid:101,gid:101}')
RO_STATE=$(jq -nc --arg hash "$(ro_sha "$RO_MANAGED/audit-path.conf")" --argjson dev "$RO_OLD_DEV" --argjson ino "$RO_OLD_INO" \
  '{revision:2,phase:"switch_pending",current:{device:$dev,inode:$ino},pending:{writer_config_sha256:$hash},proof:{}}')
: > "$case_dir/calls"
printf '0\n' > "$case_dir/old-count"
ro_validate() { return 0; }
ro_state_change() { /usr/bin/jq "$@" <<< "$RO_STATE" > "$case_dir/next-state"; }
writer_identity() {
  if [[ $mode == signal_identity_changed ]]; then jq -nc --argjson i "$RO_WRITER" '{identity:($i|.pid=4321)}'
  else jq -nc --argjson i "$RO_WRITER" '{identity:$i}'; fi
}
function /usr/bin/timeout {
  [[ $# -ge 5 && $1 == --signal=TERM && $2 == --kill-after=1s && $3 == 10s && $4 == /usr/local/bin/docker ]] || return 98
  shift 4
  if [[ $# == 6 && $1 == exec && $2 == --user && $3 == 101:101 && $4 == "$RO_CID" && $5 == /usr/sbin/nginx && $6 == -t ]]; then
    printf 'native\n' >> "$case_dir/calls"; return 0
  elif [[ $# == 3 && $1 == kill && $2 == --signal=HUP && $3 == "$RO_CID" ]]; then
    printf 'hup\n' >> "$case_dir/calls"
    : > "$case_dir/signalled"
    [[ $mode != hup_timeout ]] || return 124
    return 0
  fi
  printf 'unexpected\n' >> "$case_dir/calls"; return 98
}
writer_gate() {
  [[ $# == 4 && $1 == "$RO_CONTAINER" && $2 == "$RO_WRITER" && $3 == "$RO_OLD_DEV" ]] || return 75
  local side status=closed writable=0 rc=0 old_count identity=$RO_WRITER inode=$4 change='.'
  if [[ $4 == "$RO_OLD_INO" ]]; then
    side=old; old_count=$(cat "$case_dir/old-count"); old_count=$((old_count+1)); printf '%s\n' "$old_count" > "$case_dir/old-count"
  elif [[ $4 == "$RO_NEW_INO" ]]; then side=new
  else return 75; fi
  case $mode in
    both_open) status=open ;;
    both_closed) status=closed ;;
    initially_old|after_both_open|after_old_only|after_unavailable|hup_timeout|signal_identity_changed)
      if [[ -e $case_dir/signalled && $mode == initially_old ]]; then [[ $side != new ]] || status=open
      elif [[ -e $case_dir/signalled && $mode == after_both_open ]]; then status=open
      else [[ $side != old ]] || status=open; fi ;;
    reopen_before_seal)
      if [[ $side == new || $(cat "$case_dir/old-count") -gt 1 ]]; then status=open; fi ;;
    *) [[ $side != new ]] || status=open ;;
  esac
  [[ $status != open ]] || { writable=1; rc=10; }
  if [[ ( $mode == old_unavailable && $side == old ) || ( $mode == new_unavailable && $side == new ) ||
        ( $mode == after_unavailable && -e $case_dir/signalled ) ]]; then
    printf '{"status":"deferred"}\n'; return 75
  fi
  if [[ $mode == malformed && $side == old ]]; then printf '{'; return 0; fi
  [[ $mode != wrong_target || $side != old ]] || inode=99999999
  [[ $mode != wrong_identity || $side != old ]] || identity=$(jq -c '.pid=4321' <<< "$identity")
  [[ $mode != bad_count || $side != old ]] || change='.writable_fd_count=1'
  [[ $mode != changed_members || $side != new ]] || change='.processes[0].start_ticks="9999"'
  [[ $mode != extra_field || $side != old ]] || change='.untrusted=true'
  jq -nc --arg source "$1" --arg dev "$3" --arg ino "$inode" --arg status "$status" --argjson count "$writable" --argjson i "$identity" \
    '{schema_version:1,status:$status,reason:"stable_container_snapshot",source:$source,identity:$i,target:{device:$dev,inode:$ino},
      processes:[{pid:$i.pid,start_ticks:$i.start_ticks,uids:[101,101,101,101],gids:[101,101,101,101],mount_ns:$i.mount_ns,pid_ns:$i.pid_ns,
        net_ns:"net:[13]",exe:"/usr/sbin/nginx",scanned_fd_count:2,matching_fd_count:$count,writable_fd_count:$count}],
      process_count:1,scanned_fd_count:2,matching_fd_count:$count,writable_fd_count:$count,membership_stable:true,
      scope:"current_exact_container_process_snapshot",future_reopen_excluded:false,host_other_processes_checked:false,changes:false}' | jq -c "$change"
  [[ $mode != rc_mismatch || $side != old ]] || return 10
  return "$rc"
}
rc=0
ro_switch_writer || rc=$?
printf '{"rc":%s,"reason":"%s"}\n' "$rc" "$RO_REASON"
'''


class Policy(unittest.TestCase):
    def test_frozen_base_and_only_switch_scope_changed(self):
        base = BASE.read_bytes()
        candidate = CANDIDATE.read_bytes()
        self.assertEqual(hashlib.sha256(base).hexdigest(), BASE_SHA)
        self.assertEqual(base.split(b'ro_switch_writer() {')[0],
                         candidate.split(b'# Gate exit 10 is a stable OPEN observation')[0])
        self.assertEqual(base.split(b'\nro_vector_status() {', 1)[1],
                         candidate.split(b'\nro_vector_status() {', 1)[1])
        self.assertIn(b'--user 101:101 "$RO_CID" /usr/sbin/nginx -t', candidate)

    def test_bash_syntax(self):
        self.assertEqual(subprocess.run(['/bin/bash', '-n', str(CANDIDATE)], capture_output=True, timeout=10).returncode, 0)


@unittest.skipUnless(NATIVE, 'installed Linux/root coreutils and jq required; no installation')
class Native(unittest.TestCase):
    def check_case(self, mode, reason, hups, sealed=False):
        with tempfile.TemporaryDirectory(prefix='capstone-reopen-test.', dir='/var/tmp') as directory:
            root = Path(directory)
            result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', FIXTURE,
                                     'reopen-fixture', str(CANDIDATE), directory, mode],
                                    text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, 'synthetic function fixture failed')
            self.assertEqual(json.loads(result.stdout), {'rc': 0 if sealed else 2, 'reason': reason})
            expected_calls = ([] if mode == 'suricata_already_reopened' else ['native']) + ['hup'] * hups
            self.assertEqual((root / 'calls').read_text().splitlines(), expected_calls)
            old = root / 'managed/generation-0000000001.jsonl'
            self.assertEqual(old.read_bytes(), b'synthetic-old\n')
            self.assertEqual((root / 'managed/generation-0000000002.jsonl').read_bytes(), b'synthetic-new\n')
            self.assertEqual(old.stat().st_mode & 0o777, 0o400 if sealed else 0o644)
            self.assertEqual((root / 'next-state').exists(), sealed)
            if sealed:
                state = json.loads((root / 'next-state').read_text())
                self.assertEqual((state['phase'], state['revision']), ('old_closed', 3))
                proof = state['proof']['old_closed']
                self.assertTrue(proof['writer_fd_zero'])
                self.assertEqual(proof['bytes'], len(b'synthetic-old\n'))
                self.assertEqual(proof['sha256'], hashlib.sha256(b'synthetic-old\n').hexdigest())
        self.assertFalse(root.exists())


CASES = [
    ('already_reopened', 'unspecified', 0, True),
    ('suricata_already_reopened', 'unspecified', 0, True),
    ('both_open', 'writer_reopen_in_progress', 0, False),
    ('both_closed', 'writer_target_not_open', 0, False),
    ('initially_old', 'unspecified', 1, True),
    ('after_both_open', 'old_writer_reopen_pending', 1, False),
    ('after_old_only', 'old_writer_reopen_pending', 1, False),
    ('after_unavailable', 'old_writer_observation_invalid', 1, False),
    ('old_unavailable', 'old_writer_observation_invalid', 0, False),
    ('new_unavailable', 'new_writer_observation_invalid', 0, False),
    ('malformed', 'old_writer_observation_invalid', 0, False),
    ('wrong_target', 'old_writer_observation_invalid', 0, False),
    ('wrong_identity', 'old_writer_observation_invalid', 0, False),
    ('bad_count', 'old_writer_observation_invalid', 0, False),
    ('rc_mismatch', 'old_writer_observation_invalid', 0, False),
    ('extra_field', 'old_writer_observation_invalid', 0, False),
    ('changed_members', 'writer_membership_changed_between_targets', 0, False),
    ('reopen_before_seal', 'writer_reopen_changed_before_seal', 0, False),
    ('signal_identity_changed', 'writer_changed_before_signal', 0, False),
    ('hup_timeout', 'writer_reopen_uncertain', 1, False),
]
for mode, reason, hups, sealed in CASES:
    def test(self, mode=mode, reason=reason, hups=hups, sealed=sealed):
        self.check_case(mode, reason, hups, sealed)
    setattr(Native, 'test_' + mode, test)


@unittest.skipUnless(NATIVE, 'installed Linux/root native fixture dependencies required')
class ExistingRegressions(unittest.TestCase):
    def check_existing(self, test_name, expected_cases):
        names = ['state-lib.sh', 'state.jq', 'guard.sh', 'checkpoint-gates.sh',
                 'checkpoint-gates.jq', 'writer-gates.sh', test_name]
        hashes = {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in names}
        with tempfile.TemporaryDirectory(prefix='capstone-reopen-test.', dir='/var/tmp') as directory:
            root = Path(directory)
            for name in names:
                shutil.copyfile(HERE / name, root / name)
            shutil.copyfile(CANDIDATE, root / 'coordinator.sh')
            result = subprocess.run(['/bin/bash', str(root / test_name)], capture_output=True, text=True, timeout=90)
            self.assertEqual(result.returncode, 0, 'existing synthetic fixture failed')
            report = json.loads(result.stdout.strip())
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(report['cases'], expected_cases)
            self.assertFalse(report['systemd_or_docker_called'])
            self.assertFalse(report['operational_files_touched'])
            self.assertTrue(report['fixture_removed'])
        self.assertFalse(root.exists())
        for name, digest in hashes.items():
            self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)

    def test_dispatch_and_guard_30(self):
        self.check_existing('test-coordinator-native.sh', 30)

    def test_stop_intent_24(self):
        self.check_existing('test-stop-intent-native.sh', 24)


if __name__ == '__main__':
    unittest.main(verbosity=2)
