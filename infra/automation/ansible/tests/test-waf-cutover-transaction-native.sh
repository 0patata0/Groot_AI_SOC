#!/bin/bash
# Synthetic root-private filesystem only. No Docker, systemctl, native readers,
# real raw files, checkpoint edits, network requests, or production source calls.
set -euo pipefail
umask 077
export LC_ALL=C
[[ $# == 2 && $EUID == 0 && $2 =~ ^[a-f0-9]{64}$ ]] || exit 64
SOURCE=$1
[[ -f $SOURCE && ! -L $SOURCE && $(sha256sum "$SOURCE" | cut -d' ' -f1) == "$2" ]] || exit 77
SOURCE_SHA=$2
TASK_ROOT=$(mktemp -d /var/tmp/capstone-waf-cutover-native.XXXXXXXX)
cleanup() { [[ $TASK_ROOT == /var/tmp/capstone-waf-cutover-native.* && -d $TASK_ROOT && ! -L $TASK_ROOT ]] && rm -rf -- "$TASK_ROOT"; }
trap cleanup EXIT
passed=0
run_case() {
    local name=$1 rc
    shift
    set +e
    (
      set -euo pipefail
      source "$SOURCE"
      T=$TASK_ROOT/$name
      mkdir -m 700 "$T" "$T/work" "$T/rebind" "$T/work/before"
      WRC_WORK=$T/work WRC_REBIND=$T/rebind WRC_STATE=$T/state
      WRC_BOOT=11111111111111111111111111111111
      WRC_NEW=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      mkdir -m 700 "$WRC_STATE"
      # The only filesystem policy adapter limits real native I/O to the private
      # test root; production checks above /var/tmp cannot apply to a fixture.
      wrc_dir() {
          local p=$1 mode
          [[ $p == "$T" || $p == "$T/"* ]] || return 1
          while :; do
              [[ -d $p && ! -L $p && $(stat -c %u:%g "$p") == 0:0 ]] || return 1
              mode=$(stat -c %a "$p") || return 1
              (( (8#$mode & 0022)==0 )) || return 1
              [[ $p != "$T" ]] || return 0
              p=${p%/*}
          done
      }
      wrc_load() { :; }
      wrc_blocked() { :; }
      wrc_old_stopped() { :; }
      wrc_original_sources() { :; }
      wrc_old_eof() { :; }
      # Fail closed if accidental live commands are introduced in tested paths.
      systemctl() { return 99; }
      docker() { return 99; }
      "$@"
    ) > "$TASK_ROOT/$name.out" 2>&1
    rc=$?
    set -e
    if (( rc != 0 )); then printf 'FAIL %s\n' "$name"; exit 1; fi
    passed=$((passed+1))
    printf 'PASS %s\n' "$name"
}
reject() { local rc=0; "$@" || rc=$?; (( rc != 0 )); }
new_ok() { printf 'original\n' | wrc_new "$T/x" 400; [[ $(cat "$T/x") == original && $(stat -c %u:%g:%a:%h "$T/x") == 0:0:400:1 ]]; }
new_existing() { new_ok; reject wrc_new "$T/x" 400 <<<changed; [[ $(cat "$T/x") == original ]]; }
new_symlink() { printf original > "$T/target"; ln -s target "$T/x"; reject wrc_new "$T/x" 400 <<<changed; [[ $(cat "$T/target") == original && -L $T/x ]]; }
new_sync_failure() { sync() { return 91; }; reject wrc_new "$T/x" 400 <<<changed; [[ ! -e $T/x ]]; }
new_rename_noop() { mv() { return 0; }; reject wrc_new "$T/x" 400 <<<changed; [[ ! -e $T/x ]]; }
new_parent_sync_failure() { sync() { [[ $# == 2 ]] && command sync "$@"; }; reject wrc_new "$T/x" 400 <<<changed; [[ $(cat "$T/x") == changed ]]; }
replace_ok() { new_ok; printf 'next\n' > "$T/candidate"; local sha; sha=$(wrc_sha "$T/x"); wrc_replace "$T/x" "$sha" "$T/candidate" 400; [[ $(cat "$T/x") == next ]]; }
replace_bad_sha() { new_ok; printf 'next\n' > "$T/candidate"; reject wrc_replace "$T/x" "$(printf wrong | sha256sum | cut -d' ' -f1)" "$T/candidate" 400; [[ $(cat "$T/x") == original ]]; }
replace_race() {
    new_ok; printf 'next\n' > "$T/candidate"; local sha; sha=$(wrc_sha "$T/x")
    sync() { if [[ $# == 2 && $2 == "$T/.next."* ]]; then printf concurrent > "$T/x"; fi; command sync "$@"; }
    reject wrc_replace "$T/x" "$sha" "$T/candidate" 400
    [[ $(cat "$T/x") == concurrent ]]
}
replace_hardlink() { new_ok; ln "$T/x" "$T/second"; printf next > "$T/candidate"; reject wrc_replace "$T/x" "$(wrc_sha "$T/x")" "$T/candidate" 400; [[ $(cat "$T/x") == original ]]; }
replace_postsync_failure() {
    new_ok; printf next > "$T/candidate"; local sha; sha=$(wrc_sha "$T/x")
    sync() { [[ $# == 2 ]] && command sync "$@"; }
    reject wrc_replace "$T/x" "$sha" "$T/candidate" 400
    [[ $(cat "$T/x") == next ]]
}
evidence_reuse() { printf 'same\n' | wrc_evidence "$T/evidence"; local ino; ino=$(stat -c %i "$T/evidence"); printf 'same\n' | wrc_evidence "$T/evidence"; [[ $(stat -c %i "$T/evidence") == "$ino" ]]; }
evidence_conflict() { evidence_reuse; reject wrc_evidence "$T/evidence" <<<changed; [[ $(cat "$T/evidence") == same ]]; }
phase_setup() {
    jq -ncS --arg boot "$WRC_BOOT" --arg new "$WRC_NEW" '{boot_id:$boot,new_cid:$new}' | wrc_new "$WRC_WORK/initialized.json" 400
    printf '{}\n' | wrc_new "$WRC_WORK/stop-old.json" 400
    printf '{}\n' | wrc_new "$WRC_WORK/before/modsecurity-state.json" 400
    BEFORE='{"ActiveState":"active","ExecMainStartTimestampMonotonic":"100","ExecMainStatus":"0","InvocationID":"22222222222222222222222222222222","MainPID":"1234","Result":"success","SubState":"running"}'
    AFTER='{"ActiveState":"inactive","ExecMainStartTimestampMonotonic":"100","ExecMainStatus":"0","InvocationID":"22222222222222222222222222222222","MainPID":"0","Result":"success","SubState":"dead"}'
    wrc_unit() { printf '%s\n' "$BEFORE"; }
    wrc_seal_old() { printf sealed > "$T/seal-observed"; }
    wrc_wait_old_eof() { [[ -e $T/eof-ready ]]; }
}
unit_canonical_dispatch() {
    eval "$(declare -f wrc_unit | sed '1s/wrc_unit/actual_native_unit/')"
    phase_setup
    systemctl() { jq -r 'to_entries|reverse|.[]|.key+"="+.value' <<< "$BEFORE"; }
    wrc_unit() { actual_native_unit "$@"; }
    : > "$T/eof-ready"
    wrc_pre drain-stop
    wrc_json "$WRC_WORK/vector-stop-before.json" 400
    cmp -s "$WRC_WORK/vector-stop-before.json" <(printf '%s\n' "$BEFORE")
    wrc_stop_dispatch_guard
}
drain_deferred() { phase_setup; reject wrc_pre drain-stop; [[ -f $T/seal-observed && ! -e $WRC_WORK/drain-stop.intent.json && ! -e $WRC_WORK/vector-stop-before.json ]]; }
drain_defer_retry() {
    drain_deferred
    : > "$T/eof-ready"
    wrc_pre drain-stop
    wrc_json "$WRC_WORK/drain-stop.intent.json" 400
    cmp -s "$WRC_WORK/vector-stop-before.json" <(printf '%s\n' "$BEFORE")
}
drain_no_resend() { drain_defer_retry; local sha; sha=$(wrc_sha "$WRC_WORK/drain-stop.intent.json"); reject wrc_pre drain-stop; [[ $(wrc_sha "$WRC_WORK/drain-stop.intent.json") == "$sha" ]]; }
dispatch_ok() { drain_defer_retry; wrc_stop_dispatch_guard; }
dispatch_new_invocation() { drain_defer_retry; BEFORE=${BEFORE/22222222222222222222222222222222/33333333333333333333333333333333}; reject wrc_stop_dispatch_guard; }
stop_receipt() {
    drain_defer_retry
    wrc_unit() { printf '%s\n' "$AFTER"; }
    wrc_post drain-stop
    jq -e 'keys|length==12' "$WRC_REBIND/stop-proof.json" >/dev/null
    jq -e '.stopped_clean and .stop_armed and .after_status.MainPID=="0"' "$WRC_REBIND/stop-proof.json" >/dev/null
    wrc_json "$WRC_WORK/drain-stop.json" 400
}
stop_unclean() { drain_defer_retry; AFTER=${AFTER/\"success\"/\"timeout\"}; wrc_unit() { printf '%s\n' "$AFTER"; }; reject wrc_post drain-stop; [[ ! -e $WRC_REBIND/stop-proof.json && ! -e $WRC_WORK/drain-stop.json ]]; }
stop_new_starttime() { drain_defer_retry; AFTER=${AFTER/\"100\"/\"200\"}; wrc_unit() { printf '%s\n' "$AFTER"; }; reject wrc_post drain-stop; [[ ! -e $WRC_REBIND/stop-proof.json ]]; }
post_receipt_recovery() {
    drain_defer_retry
    wrc_unit() { printf '%s\n' "$AFTER"; }
    eval "$(declare -f wrc_finish | sed '1s/wrc_finish/actual_finish/')"
    wrc_finish() { return 91; }
    reject wrc_post drain-stop
    [[ -f $WRC_REBIND/stop-proof.json && ! -e $WRC_WORK/drain-stop.json ]]
    wrc_finish() { actual_finish "$@"; }
    wrc_post drain-stop
    wrc_json "$WRC_WORK/drain-stop.json" 400
}
for spec in unit_canonical_dispatch new_ok new_existing new_symlink new_sync_failure new_rename_noop new_parent_sync_failure replace_ok replace_bad_sha replace_race replace_hardlink replace_postsync_failure evidence_reuse evidence_conflict drain_deferred drain_defer_retry drain_no_resend dispatch_ok dispatch_new_invocation stop_receipt stop_unclean stop_new_starttime post_receipt_recovery; do run_case "$spec" "$spec"; done
cleanup
trap - EXIT
[[ ! -e $TASK_ROOT ]]
printf '{"passed":%s,"source_sha256":"%s","native_private_filesystem":true,"phase_gates_mocked":true,"operating_paths_accessed":false,"systemd_or_docker_called":false,"fixture_removed":true}\n' "$passed" "$SOURCE_SHA"
