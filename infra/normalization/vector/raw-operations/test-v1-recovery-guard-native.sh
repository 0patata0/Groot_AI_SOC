#!/bin/bash
# Root Linux fixture only. No operating service, Docker, log or checkpoint access.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/v1-recovery-guard.sh"
stage=$(mktemp -d /var/tmp/capstone-v1-recovery-test.XXXXXXXX)
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-v1-recovery-test\.[A-Za-z0-9]{8}$ && -d $stage && ! -L $stage && $(stat -c %u:%g:%a "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
passed=0
setup() {
    VRG_ROOT=$stage/state VRG_AUTH=$stage/state/recovery-authority.json VRG_BACKUP=$stage/backup
    VRG_SELF=$stage/source.sh
    mkdir -m700 "$VRG_ROOT" "$VRG_BACKUP" "$VRG_BACKUP/source"
    cp "$here/v1-recovery-guard.sh" "$VRG_SELF"; chmod 500 "$VRG_SELF"
    printf '# fixture source: no operating functions\n' > "$VRG_BACKUP/source/checkpoint-gates.sh"
    vrg_host() { return 0; }
    vrg_boot() { printf '%032d\n' 1; }
    vrg_uptime() { printf '100\n'; }
    vrg_static() { return 0; }
    vrg_services() { return 0; }
    vrg_engines() { return 0; }
    vrg_raw() { VRG_RAW='[{"verdict":"pass"},{"verdict":"pass"},{"verdict":"pass"}]'; }
    vrg_outputs() { VRG_OUTPUTS='[{"empty_native_fd":true},{"empty_native_fd":true}]'; }
    jq -ncS --arg policy "$VRG_POLICY" --arg mid "$VRG_MID" --arg plan "$VRG_PLAN" --arg ledger "$VRG_LEDGER" \
      --arg cutover "$VRG_CUTOVER" --arg prepare "$VRG_PREPARE" --arg guard "$(vrg_hash "$VRG_SELF")" \
      '{schema_version:1,policy:$policy,machine_id:$mid,boot_id:("0"*31+"1"),plan_sha256:$plan,ledger_sha256:$ledger,
        cutover_sha256:$cutover,prepare_sha256:$prepare,guard_sha256:$guard,barrier_sha256:("a"*64),
        issued_uptime_seconds:90,expiry_uptime_seconds:200,wazuh_pid:123,wazuh_start_ticks:456}' > "$VRG_AUTH"
    chmod 600 "$VRG_AUTH"
}
run_case() {
    local name=$1 rc; shift
    set +e
    ( set -e; setup; "$@" ) > "$stage/stdout" 2> "$stage/stderr"
    rc=$?
    set -e
    if (( rc!=0 )); then printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1; fi
    passed=$((passed+1))
    rm -rf -- "$stage/state" "$stage/backup" "$stage/source.sh" "$stage/changed" "$stage/file" "$stage/link" "$stage/result"
}
mutate() { jq -cS "$1" "$VRG_AUTH" > "$stage/changed"; cat "$stage/changed" > "$VRG_AUTH"; }
reject_authority() { local rc; set +e; vrg_authority; rc=$?; set -e; [[ $rc == 75 ]]; }
reject_worker() { local rc; set +e; vrg_worker; rc=$?; set -e; [[ $rc == 75 ]]; }
good() { vrg_worker > "$stage/result"; jq -e '.status=="pass" and .read_only and (.checkpoints_rewritten|not) and (.delivery_acknowledged|not) and (.raw_current_proofs|length)==3 and (.output_eof_proofs|length)==2' "$stage/result" >/dev/null; }
mutated() { mutate "$1"; reject_authority; }
missing() { rm "$VRG_AUTH"; reject_authority; }
mode_bad() { chmod 644 "$VRG_AUTH"; reject_authority; }
link_bad() { ln "$VRG_AUTH" "$stage/link"; reject_authority; }
symlink_bad() { mv "$VRG_AUTH" "$stage/link"; ln -s "$stage/link" "$VRG_AUTH"; reject_authority; }
duplicate() { sed 's/"schema_version":1/"schema_version":1,"schema_version":1/' "$VRG_AUTH" > "$stage/changed"; cat "$stage/changed" > "$VRG_AUTH"; reject_authority; }
source_changed() { printf '\n# change\n' >> "$VRG_SELF"; reject_authority; }
config_failed() { vrg_static() { return 1; }; reject_worker; [[ $VRG_REASON == static_binding_changed ]]; }
service_failed() { vrg_services() { return 1; }; reject_worker; [[ $VRG_REASON == service_state_rejected ]]; }
engine_failed() { vrg_engines() { return 1; }; reject_worker; [[ $VRG_REASON == engine_binding_changed ]]; }
raw_failed() { vrg_raw() { return 1; }; reject_worker; [[ $VRG_REASON == raw_checkpoint_rejected ]]; }
output_failed() { vrg_outputs() { return 1; }; reject_worker; [[ $VRG_REASON == output_eof_rejected ]]; }
racing_auth() { vrg_outputs() { VRG_OUTPUTS='[]'; mutate '.expiry_uptime_seconds=199'; }; reject_worker; [[ $VRG_REASON == authority_changed ]]; }
final_failed() { calls=0; vrg_static() { calls=$((calls+1)); (( calls==1 )); }; reject_worker; [[ $VRG_REASON == final_binding_changed ]]; }
file_pin() { printf 'fixture\n' > "$stage/file"; chmod 600 "$stage/file"; vrg_file_pin "$stage/file" "$(vrg_hash "$stage/file")" 0:0:600:1; }
file_pin_bad() { file_pin; ! vrg_file_pin "$stage/file" "$(printf '%064d' 0)" 0:0:600:1; }
# Exercise the real empty/nonempty output-FD branch with a real private open FD.
# Only reader identity is stubbed; the PID is this fixture's own native shell.
output_fd_setup() {
    : > "$stage/file"; chmod 600 "$stage/file"
    exec {fixture_fd}< "$stage/file"
    VRG_READER=$BASHPID
    vrg_reader() { return 0; }
    fixture_inode=$(stat -c %i "$stage/file") fixture_device=$(stat -c %d "$stage/file")
}
output_empty_pass() { output_fd_setup; vrg_output "$stage/file" "$fixture_inode" "$fixture_device" > "$stage/result"; jq -e '.empty_native_fd and .fd_count==1 and .position==0' "$stage/result" >/dev/null; }
output_empty_no_fd() { output_fd_setup; exec {fixture_fd}<&-; ! vrg_output "$stage/file" "$fixture_inode" "$fixture_device"; }
output_empty_two_fd() { output_fd_setup; exec {second_fd}< "$stage/file"; ! vrg_output "$stage/file" "$fixture_inode" "$fixture_device"; }
output_nonempty_bad_position() { output_fd_setup; printf 'fixture\n' > "$stage/file"; ! vrg_output "$stage/file" "$fixture_inode" "$fixture_device"; }
output_nonempty_checkpoint_fail() {
    output_fd_setup; printf 'fixture\n' > "$stage/file"; IFS= read -r line <&"$fixture_fd"
    cg_wazuh_eof() { return 2; }
    ! vrg_output "$stage/file" "$fixture_inode" "$fixture_device"
}
output_nonempty_checkpoint_pass() {
    output_fd_setup; printf 'fixture\n' > "$stage/file"; IFS= read -r line <&"$fixture_fd"
    cg_wazuh_eof() { printf '{"verdict":"pass","source_stable":true}\n'; }
    vrg_output "$stage/file" "$fixture_inode" "$fixture_device" > "$stage/result"
    jq -e '(.empty_native_fd|not) and .bytes==8 and .position==8' "$stage/result" >/dev/null
}
run_case normal_metadata good
run_case authority_missing missing
run_case authority_mode mode_bad
run_case authority_hardlink link_bad
run_case authority_symlink symlink_bad
run_case duplicate_key duplicate
run_case unknown_key mutated '.extra=true'
run_case wrong_policy mutated '.policy="other"'
run_case wrong_machine mutated '.machine_id="other"'
run_case wrong_plan mutated '.plan_sha256=("a"*64)'
run_case wrong_ledger mutated '.ledger_sha256=("a"*64)'
run_case wrong_cutover mutated '.cutover_sha256=("a"*64)'
run_case wrong_prepare mutated '.prepare_sha256=("a"*64)'
run_case other_boot mutated '.boot_id=("a"*32)'
run_case expired mutated '.issued_uptime_seconds=1|.expiry_uptime_seconds=100'
run_case future_issued mutated '.issued_uptime_seconds=101'
run_case too_long_window mutated '.expiry_uptime_seconds=991'
run_case fractional_time mutated '.issued_uptime_seconds=90.5'
run_case wrong_guard_source source_changed
run_case config_binding config_failed
run_case disabled_timer_or_service service_failed
run_case engine_binding engine_failed
run_case native_raw_cp raw_failed
run_case output_readiness output_failed
run_case authority_race racing_auth
run_case final_static_race final_failed
run_case exact_file_pin file_pin
run_case bad_file_sha file_pin_bad
run_case empty_exact_fd output_empty_pass
run_case empty_missing_fd output_empty_no_fd
run_case empty_two_fds output_empty_two_fd
run_case nonempty_readahead_or_position output_nonempty_bad_position
run_case nonempty_native_cp_missing output_nonempty_checkpoint_fail
run_case nonempty_native_cp_pass output_nonempty_checkpoint_pass
cleanup
trap - EXIT
printf '{"status":"pass","cases":%s,"synthetic_only":true,"operating_services_called":false,"operating_files_accessed":false,"fixture_removed":true}\n' "$passed"
