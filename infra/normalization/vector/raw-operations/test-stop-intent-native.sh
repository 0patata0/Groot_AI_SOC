#!/bin/bash
# Root/Linux metadata fixture. Actual durable intent/state helpers; systemd,
# writer and checkpoint queries are confined function stubs. No operating input.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/coordinator.sh"
source "$here/state-lib.sh"
stage=$(mktemp -d /var/tmp/capstone-raw-state-test.XXXXXXXX)
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-raw-state-test\.[A-Za-z0-9]{8}$ && -d $stage && ! -L $stage &&
       $(stat -c %u:%g:%a "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
passed=0
run_case() {
    local name=$1; shift
    if ( setup && "$@" ) > "$stage/stdout" 2> "$stage/stderr"; then passed=$((passed+1))
    else printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1; fi
    rm -rf -- "$stage/state" "$stage/unit.json" "$stage/calls"
}
setup() {
    RO_ROOT=$stage/state RO_ENGINE=suricata RO_MANAGED=$stage/managed RO_PHASE=active
    RO_ALIAS=$stage/alias RO_CP=$stage/vector-cp RO_WAZUH_CP=$stage/wazuh-cp
    RO_VECTOR_STOPPED=false
    mkdir -m 700 "$RO_ROOT" || return 1
    raw_state_prepare "$RO_ROOT" suricata >/dev/null || return 1
    local candidate=$RO_ROOT/suricata/staging/candidate-fixture.json
    jq -ncS '{schema_version:1,policy:"capstone-raw-operations-v1",engine:"suricata",
      machine_id:"096e90b6243e438aa8a7b392be754732",boot_id:("b"*32),revision:0,phase:"active",
      source_pins:{container_id:("c"*64),engine_config_sha256:("d"*64),producer_format_sha256:("e"*64),
        vector_config_sha256:("f"*64),vector_env_sha256:("a"*64),wazuh_config_sha256:("b"*64)},
      current:{number:0,basename:"generation-0000000000.jsonl",device:100,inode:200,writer_config_sha256:("a"*64)},
      pending:null,proof:{old_closed:null,readers_drained:null,publish_guard:null}}' > "$candidate" || return 1
    raw_state_init "$RO_ROOT" suricata "$candidate" >/dev/null || return 1
    rm "$candidate" || return 1
    ro_load || return 1
    ro_state_change '.revision+=1|.phase="switch_pending"|.pending=(.current|.number=1|.basename="generation-0000000001.jsonl"|.inode=201)' || return 1
    ro_state_change '.revision+=1|.phase="old_closed"|.proof.old_closed={boot_id:.boot_id,bytes:4,device:.current.device,inode:.current.inode,sha256:("a"*64),writer_fd_zero:true,writer_pid:1234,writer_start_ticks:4567}' || return 1
    status active || return 1
    : > "$stage/calls"
    ro_boot_id() { printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; }
    ro_vector_status() { cat "$stage/unit.json"; }
    ro_vector_stop_command() { printf 'stop\n' >> "$stage/calls"; status inactive; }
    ro_vector_start_command() { printf 'start\n' >> "$stage/calls"; status active cccccccccccccccccccccccccccccccc 200; }
    ro_guard_all() { return 0; }
    ro_engine() { RO_ENGINE=$1; }
    cg_sealed_lines() { return 0; }
    cg_wazuh_eof() { jq -nc '{checkpoint_sha256:("a"*64),offset:4,stored_sha1:("c"*40)}'; }
    cg_vector_eof() { jq -nc '{checkpoint_sha256:("b"*64),offset:4}'; }
}
status() {
    jq -ncS --arg state "$1" --arg invocation "${2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" --arg start "${3-100}" \
      '{ActiveState:$state,Result:"success",ExecMainStatus:"0",InvocationID:$invocation,ExecMainStartTimestampMonotonic:$start}' > "$stage/unit.json"
}
reject() { local rc=0; "$@" || rc=$?; [[ $rc != 0 ]]; }
create() { ro_intent_create "$(ro_vector_status)"; }
no_manual_start() {
    status inactive || return 1
    reject ro_stop_vector && reject ro_start_vector && [[ ! -s $stage/calls && ! -e $(ro_intent_path) ]]
}
run_case manual_inactive_never_started no_manual_start
stop_resume() {
    ro_stop_vector || return 1
    [[ $RO_VECTOR_STOPPED == true && $(cat "$stage/calls") == stop && -f $(ro_intent_path) ]] || return 1
    RO_VECTOR_STOPPED=false
    ro_reconcile_stop_intent && [[ $RO_VECTOR_STOPPED == true ]] || return 1
    ro_drain || return 1
    [[ $RO_PHASE == readers_drained && $(cat "$stage/calls") == stop ]] || return 1
    ro_intent_read || return 1
    ro_start_vector || return 1
    [[ $(cat "$stage/calls") == $'stop\nstart' && ! -e $(ro_intent_path) && $RO_VECTOR_STOPPED == false ]]
}
run_case stop_then_resume_eof_commit stop_resume
kill_gap() {
    local child rc=0
    ( ro_stop_vector || exit 97; kill -KILL "$BASHPID" ) & child=$!
    wait "$child" || rc=$?
    [[ $rc == 137 && $(cat "$stage/calls") == stop && $RO_PHASE == old_closed ]] || return 1
    RO_VECTOR_STOPPED=false
    ro_reconcile_stop_intent && ro_drain || return 1
    [[ $RO_PHASE == readers_drained && $(cat "$stage/calls") == stop ]]
}
run_case sigkill_after_stub_stop_before_state_commit kill_gap
intent_only() {
    create || return 1
    ro_stop_vector || return 1
    [[ $(cat "$stage/calls") == stop ]]
}
run_case intent_persisted_before_stop_retry intent_only
changed_before_stop() {
    eval "$(declare -f ro_intent_create | sed '1s/ro_intent_create/real_intent_create/')"
    ro_intent_create() { real_intent_create "$1" && status active cccccccccccccccccccccccccccccccc 200; }
    reject ro_stop_vector && [[ ! -s $stage/calls && -f $(ro_intent_path) ]]
}
run_case changed_invocation_after_intent_before_stop changed_before_stop
empty_invocation() {
    ro_stop_vector && status inactive '' || return 1
    ro_owned_pause "$(ro_vector_status)" && [[ $RO_VECTOR_STOPPED == true ]]
}
run_case inactive_invocation_cleared_start_time_retained empty_invocation
unit_changed() {
    local mode=$1
    ro_stop_vector || return 1
    case $mode in
      start) status inactive aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 101 ;;
      invocation) status inactive dddddddddddddddddddddddddddddddd ;;
      failure) jq -cS '.Result="signal"|.ExecMainStatus="9"' "$stage/unit.json" > "$stage/changed"; mv "$stage/changed" "$stage/unit.json" ;;
      boot) ro_boot_id() { printf '%s\n' dddddddddddddddddddddddddddddddd; } ;;
    esac
    reject ro_owned_pause "$(ro_vector_status)" && reject ro_start_vector && [[ $(cat "$stage/calls") == stop ]]
}
for mode in start invocation failure boot; do run_case "inactive_${mode}_changed_refused" unit_changed "$mode"; done
active_cleanup() {
    local mode=$1
    create || return 1
    if [[ $mode == new ]]; then status active cccccccccccccccccccccccccccccccc 200 || return 1; fi
    if [[ $mode == boot ]]; then ro_boot_id() { printf '%s\n' eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee; }; fi
    ro_reconcile_stop_intent || return 1
    [[ ! -e $(ro_intent_path) && ! -s $stage/calls ]]
}
for mode in same new boot; do run_case "active_stale_intent_${mode}_clear_only" active_cleanup "$mode"; done
bad_marker() {
    local mode=$1 path
    create || return 1
    path=$(ro_intent_path)
    case $mode in
      duplicate) sed 's/"schema_version":1/"schema_version":1,"schema_version":1/' "$path" > "$stage/changed"; cat "$stage/changed" > "$path" ;;
      mode) chmod 666 "$path" ;;
      link) ln "$path" "$RO_ROOT/extra" ;;
      engine) jq -cS '.engine="modsecurity"' "$path" > "$stage/changed"; cat "$stage/changed" > "$path" ;;
      state) jq -cS '.state_sha256=("f"*64)' "$path" > "$stage/changed"; cat "$stage/changed" > "$path" ;;
      symlink) mv "$path" "$RO_ROOT/saved"; ln -s saved "$path" ;;
    esac
    reject ro_intent_read && [[ ! -s $stage/calls ]]
}
for mode in duplicate mode link engine state symlink; do run_case "marker_${mode}_rejected" bad_marker "$mode"; done
history_progression() {
    create && ro_stop_vector && ro_drain || return 1
    ro_state_change '.revision+=1|.phase="publish_pending"|.proof.publish_guard={decision:"different_prefix",new_prefix_sha1:("d"*40),old_offset:4,old_sha1:("c"*40),source_bytes:4,wazuh_checkpoint_sha256:("e"*64)}' || return 1
    ro_intent_read && [[ $RO_PHASE == publish_pending ]]
}
run_case intent_binds_two_adjacent_history_transitions history_progression
active_marker_rejected() {
    history_progression || return 1
    ro_state_change '.revision+=1|.phase="active"|.current=.pending|.pending=null|.proof={old_closed:null,readers_drained:null,publish_guard:null}' || return 1
    reject ro_intent_read
}
run_case leftover_intent_after_active_rejected active_marker_rejected
eof_failure() {
    ro_stop_vector || return 1
    cg_vector_eof() { return 2; }
    reject ro_drain && [[ $RO_PHASE == old_closed && -f $(ro_intent_path) && $(cat "$stage/calls") == stop ]]
}
run_case eof_failure_keeps_pending_owned_pause eof_failure
guard_failure() {
    create || return 1
    ro_guard_all() { return 2; }
    reject ro_reconcile_stop_intent && [[ -f $(ro_intent_path) && ! -s $stage/calls ]]
}
run_case active_cleanup_requires_guard guard_failure
changed_before_start() {
    ro_stop_vector || return 1
    ro_guard_all() { status inactive cccccccccccccccccccccccccccccccc 200; }
    reject ro_start_vector && [[ $(cat "$stage/calls") == stop && -f $(ro_intent_path) ]]
}
run_case changed_invocation_during_guard_before_start changed_before_start
cleanup && [[ ! -e $stage ]]
trap - EXIT
printf '{"status":"passed","cases":%s,"synthetic_only":true,"native_state_fsync_and_sigkill":true,"systemd_or_docker_called":false,"operational_files_touched":false,"fixture_removed":true}\n' "$passed"
