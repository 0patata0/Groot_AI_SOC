#!/bin/bash
# Existing GNU tools only; no operating files, services, Docker or journal.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul
umask 077
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
[[ $# == 0 || ( $# == 1 && $1 == --policy-only ) ]] || exit 64
ROOT=$(mktemp -d "${TMPDIR:-/var/tmp}/capstone-storage-relay.XXXXXXXX")
trap 'rm -rf -- "$ROOT"' EXIT
passed=0
event() {
    jq -ncS --arg observed "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{schema_version:1,policy:"capstone-storage-retention-v1",
      machine_id:"1e143067c98a44ffba6eaa925dc038d7",host:"b",observed_at_utc:$observed,
      status:"ok",reason:"healthy",scan_status:"complete",used_percent:40,available_bytes:10737418240,
      raw_bytes:0,backup_bytes:0,history_bytes:4096,raw_archive_review_due_count:0,backup_review_due_count:0,
      retention_days:90,automatic_deletion:false,checkpoint_changed:false}'
}
case_run() {
    local name=$1 rc; shift
    set +e
    (set -euo pipefail; "$@") > "$ROOT/case.stdout" 2> "$ROOT/case.stderr"
    rc=$?
    set -e
    if ((rc)); then printf 'FAIL %s rc=%d\n' "$name" "$rc"; cat "$ROOT/case.stderr"; exit 1; fi
    passed=$((passed+1)); printf 'PASS %s\n' "$name"
}
policy_ok() { event | jq -cSe -f "$HERE/status-b.jq" >/dev/null; }
policy_reject() {
    local rc
    event | jq -cS "$1" > "$ROOT/invalid.json"
    set +e; jq -cSe -f "$HERE/status-b.jq" "$ROOT/invalid.json" >/dev/null; rc=$?; set -e
    [[ $rc != 0 ]]
}
policy_critical_unknown() {
    event | jq -cS '.status="critical"|.reason="capacity_critical"|.scan_status="unavailable"|.used_percent=90|.raw_bytes=null' |
      jq -cSe -f "$HERE/status-b.jq" >/dev/null
}
case_run policy_valid policy_ok
case_run known_critical_unknown policy_critical_unknown
case_run wrong_host policy_reject '.host="a"'
case_run wrong_typed_flag policy_reject '.automatic_deletion="false"'
case_run severity_mismatch policy_reject '.used_percent=95'
case_run complete_null policy_reject '.raw_bytes=null'
case_run extra_key policy_reject '.extra=true'
if [[ ${1:-} == --policy-only ]]; then printf '{"passed":%d,"native_executed":false}\n' "$passed"; exit 0; fi
[[ $EUID == 0 && $OSTYPE == linux* ]] || exit 77
source "$HERE/relay-b.sh"
setup() {
    rm -rf -- "$ROOT/fixture"; mkdir -m700 "$ROOT/fixture"
    FIXTURE=$ROOT/fixture
    SR_LIB=$FIXTURE/lib; SR_STATE=$FIXTURE/state; SR_VOLUME=$FIXTURE/volume
    SR_LOG=$SR_VOLUME/capstone-storage-b.log
    mkdir -m700 "$SR_LIB" "$SR_STATE" "$SR_VOLUME"
    chown 999:999 "$SR_VOLUME"; chmod 770 "$SR_VOLUME"
    cp "$HERE/status-b.jq" "$SR_LIB/status-b.jq"; chmod 400 "$SR_LIB/status-b.jq"
    : > "$SR_STATE/.relay.lock"; : > "$SR_LOG"; chmod 600 "$SR_STATE/.relay.lock" "$SR_LOG"
    event > "$SR_STATE/status.json"; chmod 600 "$SR_STATE/status.json"
    # Same metadata policy, but the private fixture root is the trust boundary
    # instead of /var/tmp. Production sr_main/fixed MID are not invoked.
    sr_dir() {
        local p=$1 mode meta
        [[ $p == "$FIXTURE" || $p == "$FIXTURE/"* ]] || return 1
        while :; do
            [[ -d $p && ! -L $p ]] || return 1
            meta=$(stat -c %u:%g:%a "$p") || return 1
            if [[ $p == "$SR_VOLUME" ]]; then [[ $meta == 999:999:770 ]] || return 1
            else
                [[ $(stat -c %u:%g "$p") == 0:0 ]] || return 1
                mode=${meta##*:}; (( (8#$mode & 0022)==0 )) || return 1
            fi
            [[ $p != "$FIXTURE" ]] || break
            p=${p%/*}
        done
    }
}
invoke() {
    set +e
    (set -euo pipefail; sr_run) > "$FIXTURE/result.json" 2> "$FIXTURE/stderr"
    INVOKE_RC=$?
    set -e
    return 0
}
refused() {
    invoke
    [[ $INVOKE_RC != 0 && ! -e $SR_STATE/relay-last.sha256 ]]
}
success() {
    setup; invoke; [[ $INVOKE_RC == 0 ]]
    jq -e '.status=="relayed" and .appended==true' "$FIXTURE/result.json" >/dev/null
    [[ $(wc -l < "$SR_LOG") == 1 && $(stat -c %u:%g:%a:%h "$SR_LOG") == 0:0:600:1 ]]
    sed 's/^.* capstone-storage: //' "$SR_LOG" | jq -cSe -f "$HERE/status-b.jq" >/dev/null
    [[ $(find "$SR_STATE" -maxdepth 1 -name '.relay.*' -type d | wc -l) == 0 ]]
}
duplicate() {
    success; local before; before=$(sr_hash "$SR_LOG"); invoke; [[ $INVOKE_RC == 0 ]]
    jq -e '.status=="already_relayed" and .appended==false' "$FIXTURE/result.json" >/dev/null
    [[ $(sr_hash "$SR_LOG") == "$before" ]]
}
stale() { setup; jq -cS '.observed_at_utc="2000-01-01T00:00:00Z"' "$SR_STATE/status.json" > "$FIXTURE/x"; mv "$FIXTURE/x" "$SR_STATE/status.json"; refused; [[ ! -s $SR_LOG ]]; }
multi() { setup; cat "$SR_STATE/status.json" >> "$SR_STATE/status.json.copy"; cat "$SR_STATE/status.json.copy" >> "$SR_STATE/status.json"; refused; [[ ! -s $SR_LOG ]]; }
symlink() { setup; mv "$SR_LOG" "$FIXTURE/protected"; ln -s "$FIXTURE/protected" "$SR_LOG"; refused; [[ ! -s $FIXTURE/protected ]]; }
fifo() { setup; rm "$SR_LOG"; mkfifo "$SR_LOG"; refused; }
full() { setup; truncate -s 1048575 "$SR_LOG"; printf '\n' >> "$SR_LOG"; refused; [[ $(stat -c %s "$SR_LOG") == 1048576 ]]; }
partial() { setup; printf 'prior-partial' > "$SR_LOG"; refused; [[ $(cat "$SR_LOG") == prior-partial ]]; }
status_changed() {
    setup
    dd() { command dd "$@" || return; if [[ $1 == "if=$SR_STATE/status.json" ]]; then printf '\n' >> "$SR_STATE/status.json"; fi; }
    refused; [[ ! -s $SR_LOG ]]
}
log_replaced_after_open() {
    setup
    sr_hash() {
        local value; value=$(sha256sum -- "$1") || return 1
        if [[ $1 == /proc/self/fd/4 ]]; then mv "$SR_LOG" "$FIXTURE/opened-old"; : > "$SR_LOG"; chmod 600 "$SR_LOG"; fi
        printf '%s\n' "${value%% *}"
    }
    refused; [[ ! -s $SR_LOG && -s $FIXTURE/opened-old ]]
}
case_run append_metadata success
case_run duplicate_status_no_append duplicate
case_run stale_status_no_append stale
case_run multiple_json_refused multi
case_run symlink_target_preserved symlink
case_run fifo_refused fifo
case_run one_mib_bound_no_delete full
case_run prior_partial_line_refused partial
case_run status_change_refused status_changed
case_run name_replaced_only_pinned_fd_written log_replaced_after_open
printf '{"passed":%d,"native_executed":true,"operating_input":0,"service_calls":0,"fixture_cleanup_on_exit":true}\n' "$passed"
