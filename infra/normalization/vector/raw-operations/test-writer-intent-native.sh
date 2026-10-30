#!/bin/bash
# Actual private state/history/intent fsync and SIGKILL; Docker/systemd are mocks.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/coordinator-writer-intent-fix.sh"
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
    local name=$1 rc; shift
    : > "$stage/failure-line"
    set +e
    ( set -eE; trap 'printf "%s\n" "$LINENO" > "$stage/failure-line"' ERR; setup; "$@" ) > "$stage/stdout" 2> "$stage/stderr"
    rc=$?
    set -e
    if [[ $rc == 0 ]]; then passed=$((passed+1))
    else
        local line; line=$(tail -n 1 "$stage/failure-line")
        [[ $line =~ ^[0-9]+$ ]] || line=null
        jq -nc --arg name "$name" --argjson passed "$passed" --argjson rc "$rc" --argjson line "$line" \
          --argjson stderr_bytes "$(wc -c < "$stage/stderr")" \
          '{status:"failed",case:$name,passed:$passed,exit_code:$rc,failure_line:$line,stderr_bytes:$stderr_bytes,stderr_exported:false}'
        exit 1
    fi
    rm -rf -- "$stage/state" "$stage/managed" "$stage/calls" "$stage/old" "$stage/new"
}
setup() {
    RO_ROOT=$stage/state RO_ENGINE=modsecurity RO_CONTAINER=waf RO_MANAGED=$stage/managed
    RO_ALIAS=$stage/managed/alias RO_ALIAS_KIND=old RO_CP=$stage/private-cp RO_WAZUH_CP=$stage/private-wazuh
    mkdir -m 700 "$RO_ROOT" "$RO_MANAGED" || return 1
    raw_state_prepare "$RO_ROOT" "$RO_ENGINE" >/dev/null || return 1
    printf 'old\n' > "$RO_MANAGED/generation-0000000000.jsonl"
    printf 'new\n' > "$RO_MANAGED/generation-0000000001.jsonl"
    chmod 644 "$RO_MANAGED/generation-0000000000.jsonl" "$RO_MANAGED/generation-0000000001.jsonl"
    printf 'SecAuditLog /var/log/modsecurity/capstone-managed/generation-0000000001.jsonl\n' > "$RO_MANAGED/audit-path.conf"
    chmod 444 "$RO_MANAGED/audit-path.conf"
    local dev ino nextino hash seed=$RO_ROOT/$RO_ENGINE/staging/candidate-fixture.json
    dev=$(stat -c %d "$RO_MANAGED/generation-0000000000.jsonl")
    ino=$(stat -c %i "$RO_MANAGED/generation-0000000000.jsonl")
    nextino=$(stat -c %i "$RO_MANAGED/generation-0000000001.jsonl")
    hash=$(ro_sha "$RO_MANAGED/audit-path.conf")
    jq -ncS --arg boot "$(ro_boot_id)" --argjson dev "$dev" --argjson ino "$ino" '
      {schema_version:1,policy:"capstone-raw-operations-v1",engine:"modsecurity",machine_id:"096e90b6243e438aa8a7b392be754732",
       boot_id:$boot,revision:0,phase:"active",source_pins:{container_id:("c"*64),engine_config_sha256:("a"*64),
        producer_format_sha256:("b"*64),vector_config_sha256:("d"*64),vector_env_sha256:("e"*64),wazuh_config_sha256:("f"*64)},
       current:{number:0,basename:"generation-0000000000.jsonl",device:$dev,inode:$ino,writer_config_sha256:("a"*64)},pending:null,
       proof:{old_closed:null,readers_drained:null,publish_guard:null}}' > "$seed" || return 1
    raw_state_init "$RO_ROOT" "$RO_ENGINE" "$seed" >/dev/null || return 1
    rm "$seed" || return 1
    ro_load || return 1
    ro_state_change --argjson ino "$nextino" --arg hash "$hash" \
      '.revision+=1|.phase="switch_pending"|.pending=(.current|.number=1|.basename="generation-0000000001.jsonl"|.inode=$ino|.writer_config_sha256=$hash)' || return 1
    WG_ID=$(jq -nc --arg cid "$RO_CID" '{cid:$cid,pid:1234,start_ticks:"5678",mount_ns:"mnt:[11]",pid_ns:"pid:[12]",uid:101,gid:101}')
    RO_WRITER=$WG_ID RO_REASON=unspecified HUP_MODE=complete
    printf 'open\n' > "$stage/old"; printf 'closed\n' > "$stage/new"; : > "$stage/calls"
    ro_engine() { RO_ENGINE=$1; }
    ro_validate() {
        RO_WRITER=$WG_ID RO_ALIAS_KIND=old
        if [[ $RO_PHASE == old_closed ]]; then
            [[ $(stat -c %s "$RO_CURRENT") == "$(jq -r .proof.old_closed.bytes <<< "$RO_STATE")" &&
               $(ro_sha "$RO_CURRENT") == "$(jq -r .proof.old_closed.sha256 <<< "$RO_STATE")" ]] || return 2
        fi
    }
    writer_identity() { jq -nc --argjson i "$WG_ID" '{status:"observed",identity:$i}'; }
    writer_gate() {
        local state count=0 rc=0
        [[ $# == 4 && $1 == waf && $2 == "$WG_ID" && $3 == "$RO_OLD_DEV" ]] || return 75
        if [[ $4 == "$RO_OLD_INO" ]]; then state=$(cat "$stage/old")
        elif [[ $4 == "$RO_NEW_INO" ]]; then state=$(cat "$stage/new")
        else return 75; fi
        [[ $state != open ]] || { count=1; rc=10; }
        jq -nc --arg source "$1" --arg dev "$3" --arg ino "$4" --arg status "$state" --argjson n "$count" --argjson i "$WG_ID" '
          {schema_version:1,status:$status,reason:"stable_container_snapshot",source:$source,identity:$i,target:{device:$dev,inode:$ino},
           processes:[{pid:$i.pid,start_ticks:$i.start_ticks,uids:[101,101,101,101],gids:[101,101,101,101],mount_ns:$i.mount_ns,pid_ns:$i.pid_ns,
             net_ns:"net:[13]",exe:"/usr/sbin/nginx",scanned_fd_count:2,matching_fd_count:$n,writable_fd_count:$n}],process_count:1,
           scanned_fd_count:2,matching_fd_count:$n,writable_fd_count:$n,membership_stable:true,scope:"current_exact_container_process_snapshot",
           future_reopen_excluded:false,host_other_processes_checked:false,changes:false}'
        return "$rc"
    }
    function /usr/bin/timeout {
        [[ $# -ge 5 && $1 == --signal=TERM && $2 == --kill-after=1s && $3 == 10s && $4 == /usr/local/bin/docker ]] || return 98
        shift 4
        if [[ $# == 6 && $1 == exec && $2 == --user && $3 == 101:101 && $4 == "$RO_CID" && $5 == /usr/sbin/nginx && $6 == -t ]]; then
            return 0
        elif [[ $# == 3 && $1 == kill && $2 == --signal=HUP && $3 == "$RO_CID" ]]; then
            ro_writer_signal_read && ro_writer_signal_identity || return 98
            printf 'hup\n' >> "$stage/calls"
            case $HUP_MODE in
              complete) printf 'closed\n' > "$stage/old"; printf 'open\n' > "$stage/new" ;;
              both) printf 'open\n' > "$stage/new" ;;
              timeout) return 124 ;;
              lost_response) printf 'closed\n' > "$stage/old"; printf 'open\n' > "$stage/new"; return 124 ;;
              *) return 98 ;;
            esac
            return 0
        fi
        return 98
    }
}
refused() { local rc=0; "$@" || rc=$?; [[ $rc == 2 ]]; }
no_hup() { [[ ! -s $stage/calls ]]; }
one_hup() { [[ $(cat "$stage/calls") == hup ]]; }
complete_case() {
    ro_switch_writer && one_hup && [[ $RO_PHASE == old_closed && -f $(ro_writer_signal_path) ]] || return 1
    ro_reconcile_writer_signal && ro_writer_signal_absent && one_hup
}
preexisting_armed() {
    ro_writer_signal_create && refused ro_switch_writer && no_hup && [[ $RO_REASON == writer_signal_already_armed ]]
}
kill_before_signal() {
    (ro_writer_signal_create && kill -KILL "$BASHPID") & local child=$! rc=0
    wait "$child" || rc=$?
    [[ $rc == 137 ]] && ro_writer_signal_read && refused ro_switch_writer && no_hup
}
timeout_no_retry() {
    HUP_MODE=timeout
    refused ro_switch_writer && one_hup && [[ $RO_REASON == writer_reopen_uncertain ]] || return 1
    refused ro_switch_writer && one_hup && [[ $RO_REASON == writer_signal_already_armed ]]
}
lost_response() {
    HUP_MODE=lost_response
    refused ro_switch_writer && one_hup || return 1
    ro_switch_writer && one_hup && ro_reconcile_writer_signal && ro_writer_signal_absent
}
both_then_closed() {
    HUP_MODE=both
    refused ro_switch_writer && one_hup || return 1
    refused ro_switch_writer && one_hup && [[ $RO_REASON == writer_reopen_in_progress ]] || return 1
    printf 'closed\n' > "$stage/old"
    ro_switch_writer && one_hup && ro_reconcile_writer_signal && ro_writer_signal_absent
}
kill_after_cas() {
    (ro_switch_writer && kill -KILL "$BASHPID") & local child=$! rc=0
    wait "$child" || rc=$?
    [[ $rc == 137 ]] && one_hup && ro_load && [[ $RO_PHASE == old_closed ]] || return 1
    ro_reconcile_writer_signal && ro_writer_signal_absent && one_hup
}
fsync_before_publish() {
    : > "$stage/injected"
    function /bin/sync {
        if [[ $# == 2 && $1 == -- && $2 == */.writer-reopen.* ]]; then
            printf 'file_fsync\n' >> "$stage/injected"; return 1
        fi
        command /bin/sync "$@"
    }
    refused ro_switch_writer && no_hup && ro_writer_signal_absent && [[ $(cat "$stage/injected") == file_fsync ]]
}
fsync_after_publish() {
    : > "$stage/injected"
    function /bin/sync {
        if [[ $# == 2 && $1 == -- && $2 == "$RO_ROOT/$RO_ENGINE" ]]; then
            printf 'directory_fsync\n' >> "$stage/injected"; return 1
        fi
        command /bin/sync "$@"
    }
    refused ro_switch_writer && no_hup && [[ -f $(ro_writer_signal_path) && $(cat "$stage/injected") == directory_fsync ]] || return 1
    unset -f /bin/sync
    refused ro_switch_writer && no_hup && [[ $RO_REASON == writer_signal_already_armed ]]
}
cleanup_fsync_failure() {
    ro_switch_writer && one_hup || return 1
    function /bin/sync { return 1; }
    refused ro_reconcile_writer_signal && [[ -f $(ro_writer_signal_path) ]] || return 1
    unset -f /bin/sync
    ro_reconcile_writer_signal && ro_writer_signal_absent && one_hup
}
changed_boot() {
    ro_writer_signal_create || return 1
    ro_boot_id() { printf '00000000000000000000000000000000\n'; }
    refused ro_reconcile_writer_signal && no_hup
}
changed_identity() {
    ro_writer_signal_create || return 1
    WG_ID=$(jq -c '.pid=4321' <<< "$WG_ID")
    refused ro_reconcile_writer_signal && no_hup
}
changed_state() {
    ro_writer_signal_create || return 1
    local path=$RO_ROOT/$RO_ENGINE/state.json
    jq -cS '.source_pins.vector_env_sha256=("a"*64)' "$path" > "$stage/changed"
    cat "$stage/changed" > "$path"; rm "$stage/changed"
    ro_load && refused ro_reconcile_writer_signal && no_hup
}
bad_marker() {
    ro_writer_signal_create || return 1
    printf '{}\n' > "$(ro_writer_signal_path)"
    refused ro_reconcile_writer_signal && no_hup
}
metadata_changed() {
    ro_writer_signal_create && chmod 644 "$(ro_writer_signal_path)" || return 1
    refused ro_reconcile_writer_signal && no_hup
}
history_tamper() {
    ro_switch_writer || return 1
    local path=$RO_ROOT/$RO_ENGINE/history/$(jq -r .revision <<< "$RO_WRITER_SIGNAL")-$(jq -r .state_sha256 <<< "$RO_WRITER_SIGNAL").json
    printf ' ' >> "$path"
    refused ro_reconcile_writer_signal && [[ -f $(ro_writer_signal_path) ]] && one_hup
}
active_orphan_before_mutation() {
    ro_writer_signal_create || return 1
    local path=$RO_ROOT/$RO_ENGINE/state.json
    jq -cS '.phase="active"|.pending=null|.revision+=1' "$path" > "$stage/changed"
    cat "$stage/changed" > "$path"; rm "$stage/changed"
    ro_reconcile_link() { printf 'mutation\n' >> "$stage/calls"; return 0; }
    refused ro_operation run modsecurity && no_hup
}
guard_marker_present() { ro_writer_signal_create && refused ro_guard_one vector && no_hup; }
guard_marker_during_check() {
    cg_wazuh_cold() { return 0; }
    cg_vector_current() { ro_writer_signal_create; }
    refused ro_guard_one vector && [[ -f $(ro_writer_signal_path) ]] && no_hup
}
exclusive_create() {
    ro_writer_signal_create || return 1
    local before; before=$(ro_sha "$(ro_writer_signal_path)")
    refused ro_writer_signal_create && [[ $(ro_sha "$(ro_writer_signal_path)") == "$before" ]] && no_hup
}
cleanup_validate_identity_change() {
    ro_switch_writer || return 1
    ro_validate() { WG_ID=$(jq -c '.pid=4321' <<< "$WG_ID"); RO_WRITER=$WG_ID; }
    refused ro_reconcile_writer_signal && [[ -f $(ro_writer_signal_path) && $RO_REASON == writer_signal_identity_changed ]] && one_hup
}
cleanup_final_identity_change() {
    ro_switch_writer || return 1
    printf '0\n' > "$stage/identity-count"
    writer_identity() {
        local n identity=$WG_ID
        n=$(cat "$stage/identity-count"); n=$((n+1)); printf '%s\n' "$n" > "$stage/identity-count"
        [[ $n -lt 2 ]] || identity=$(jq -c '.pid=4321' <<< "$identity")
        jq -nc --argjson i "$identity" '{status:"observed",identity:$i}'
    }
    refused ro_reconcile_writer_signal && [[ -f $(ro_writer_signal_path) ]] && one_hup
}
drain_prefix_case() {
    local kind=$1 expected=$2
    ro_switch_writer && ro_reconcile_writer_signal || return 1
    case $kind in
      empty) : > "$RO_NEXT" ;;
      same) printf 'old\n' > "$RO_NEXT" ;;
      short_same) printf 'ol' > "$RO_NEXT" ;;
      distinct) printf 'different\n' > "$RO_NEXT" ;;
      old_zero) : > "$RO_CURRENT"; RO_STATE=$(jq -c '.proof.old_closed.bytes=0' <<< "$RO_STATE") ;;
    esac
    cg_sealed_lines() { return 0; }
    cg_wazuh_eof() { printf '{}\n'; }
    ro_stop_vector() { printf 'stop\n' >> "$stage/calls"; return 2; }
    refused ro_drain || return 1
    if [[ $expected == no_stop ]]; then one_hup
    else [[ $(cat "$stage/calls") == $'hup\nstop' ]]; fi
}
shared_lock_second_refused() {
    local rc=0
    exec 9>"$stage/synthetic.lock"
    /usr/bin/flock -n 9 || return 1
    (exec 9>&-; exec 8>"$stage/synthetic.lock"; /usr/bin/flock -n 8) || rc=$?
    exec 9>&-
    [[ $rc == 1 ]] && no_hup
}
peer_pause_existing_reopen() {
    local mode=$1 before marker
    ro_writer_signal_create || return 1
    before=$RO_STATE_SHA; marker=$(ro_writer_signal_path)
    case $mode in
      completed) printf 'closed\n' > "$stage/old"; printf 'open\n' > "$stage/new" ;;
      pending) ;;
      both_open) printf 'open\n' > "$stage/new" ;;
      changed_identity) WG_ID=$(jq -c '.pid=4321' <<< "$WG_ID") ;;
      absent) rm -- "$marker" ;;
    esac
    ro_reconcile_stop_intent() { printf 'pause-owner-check\n' >> "$stage/calls"; ro_refuse another_engine_owns_vector_pause; }
    refused ro_operation resume modsecurity || return 1
    case $mode in
      completed)
        [[ $RO_PHASE == old_closed && ! -e $marker && $RO_STATE_SHA != "$before" &&
           $RO_REASON == another_engine_owns_vector_pause && $(cat "$stage/calls") == pause-owner-check &&
           $(stat -c %u:%g:%a "$RO_CURRENT") == 0:0:400 ]] ;;
      absent)
        [[ $RO_PHASE == switch_pending && $RO_STATE_SHA == "$before" &&
           $(cat "$stage/calls") == pause-owner-check ]] ;;
      *) [[ $RO_PHASE == switch_pending && $RO_STATE_SHA == "$before" && -f $marker ]] && no_hup ;;
    esac
}
run_case one_signal_then_durable_cleanup complete_case
run_case existing_intent_no_signal preexisting_armed
run_case killed_after_intent_before_signal kill_before_signal
run_case timeout_never_resends timeout_no_retry
run_case lost_response_observation_recovers lost_response
run_case both_open_wait_then_no_signal_seal both_then_closed
run_case killed_after_state_cas_cleanup_only kill_after_cas
run_case intent_file_fsync_failure_no_signal fsync_before_publish
run_case intent_dir_fsync_uncertain_no_resend fsync_after_publish
run_case cleanup_fsync_failure_retains_marker cleanup_fsync_failure
run_case different_boot_refused changed_boot
run_case different_writer_refused changed_identity
run_case changed_state_refused changed_state
run_case malformed_marker_refused bad_marker
run_case marker_permissions_refused metadata_changed
run_case history_tamper_refused history_tamper
run_case active_orphan_before_mutation active_orphan_before_mutation
run_case guard_present_marker_refused guard_marker_present
run_case guard_midcheck_marker_refused guard_marker_during_check
run_case second_create_preserves_first exclusive_create
run_case cleanup_validate_identity_change_refused cleanup_validate_identity_change
run_case cleanup_final_identity_change_refused cleanup_final_identity_change
run_case empty_new_does_not_stop_vector drain_prefix_case empty no_stop
run_case same_new_does_not_stop_vector drain_prefix_case same no_stop
run_case shorter_same_new_does_not_stop_vector drain_prefix_case short_same no_stop
run_case distinct_new_reaches_stop drain_prefix_case distinct stop
run_case old_zero_reaches_stop drain_prefix_case old_zero stop
run_case shared_lock_second_worker_refused shared_lock_second_refused
run_case completed_reopen_finalizes_before_peer_pause_check peer_pause_existing_reopen completed
run_case pending_reopen_does_not_resignal_for_peer_pause peer_pause_existing_reopen pending
run_case both_open_cannot_bypass_peer_pause peer_pause_existing_reopen both_open
run_case changed_writer_cannot_finalize_for_peer_pause peer_pause_existing_reopen changed_identity
run_case no_intent_does_not_start_writer_under_peer_pause peer_pause_existing_reopen absent
cleanup && [[ ! -e $stage ]] || exit 1
trap - EXIT
printf '{"status":"passed","cases":%s,"native_state_and_fsync":true,"private_sigkill_reaped":true,"systemd_or_docker_called":false,"operational_files_touched":false,"fixture_removed":true}\n' "$passed"
