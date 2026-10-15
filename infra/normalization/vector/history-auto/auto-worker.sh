#!/bin/bash
# Internal parameterized worker: public entrypoint supplies only fixed A paths.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
exec 2>/dev/null
AUTO_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$AUTO_DIR/auto-lib.sh"
[[ $# == 6 && $1 =~ ^(run|inspect)$ ]] || auto_refuse invalid_arguments
mode=$1 AUTO_ROOT=$2 AUTO_JOURNAL=$3 AUTO_BOOT_FILE=$4 history_dir=$5 AUTO_CUTOFF=$6
[[ $AUTO_CUTOFF =~ ^[1-9][0-9]{0,15}$ ]] || auto_refuse invalid_cutoff
[[ -x $AUTO_JOURNAL && -f $AUTO_BOOT_FILE ]] || auto_refuse missing_dependency
auto_ancestors "$AUTO_ROOT" || auto_refuse unsafe_state_ancestor
auto_safe_dir "$AUTO_ROOT" && auto_safe_dir "$AUTO_ROOT/jobs" && auto_safe_dir "$AUTO_ROOT/store" || auto_refuse unsafe_state_directory
auto_safe_file "$AUTO_ROOT/.lock" 600 || auto_refuse unsafe_state_lock
exec 8<>"$AUTO_ROOT/.lock"
flock -n 8 || { auto_report deferred concurrent_run; exit 75; }
# A hard stop can retain metadata-only .work/.job temporaries. Keep them bounded;
# never erase uncertain partial capture evidence as part of automatic recovery.
metadata_entries=$(find "$AUTO_ROOT" -path "$AUTO_ROOT/store" -prune -o -maxdepth 2 -printf '.\n' | head -n 257 | wc -l) || auto_refuse metadata_entry_limit
(( metadata_entries<257 )) || auto_refuse metadata_entry_limit
AUTO_CURRENT=$(auto_current) || auto_refuse invalid_current_boot
source "$history_dir/history-lib.sh"
source "$history_dir/continuation-lib.sh"
AUTO_WORK=$(mktemp -d "$AUTO_ROOT/.work.XXXXXX")
trap 'rm -rf -- "$AUTO_WORK"' EXIT
# No foreign state names, symlinks, or unbounded metadata are accepted.
shopt -s nullglob
jobs=("$AUTO_ROOT/jobs/"*)
(( ${#jobs[@]}<=AUTO_MAX_JOBS )) || auto_refuse job_count_limit
for job in "${jobs[@]}"; do
    name=${job##*/}; boot=${name%.json}
    [[ $name == "$boot.json" && $boot =~ ^[0-9a-f]{32}$ ]] || auto_refuse unexpected_job_entry
    auto_check_job "$job" "$boot"
done
if [[ $mode == inspect ]]; then
    jq -sc '{policy:"bounded-previous-kernel-auto-v1",jobs:length,
      ready:([.[]|select(.status=="ready")]|length),inflight:([.[]|select(.status=="inflight")]|length),
      complete:([.[]|select(.status=="complete")]|length),blocked:([.[]|select(.status=="blocked")]|length),
      records:([.[].records]|add//0),bytes:([.[].bytes]|add//0),raw_payload_exported:false,
      operational_checkpoint_changed:false,reinjected:false,remote_receipt:false}' "${jobs[@]}" </dev/null
    exit 0
fi
auto_discover
# Lexical ordering is deterministic. Each turn can capture/reconcile at most one batch.
jobs=("$AUTO_ROOT/jobs/"*.json)
for job in "${jobs[@]}"; do
    boot=$(jq -r .boot_id "$job") status=$(jq -r .status "$job")
    [[ $boot != "$AUTO_CURRENT" ]] || auto_refuse job_became_current_boot
    [[ $status == ready || $status == inflight ]] || continue
    until=$(jq -r .until_epoch_us "$job")
    (( 10#$until<=10#$AUTO_CUTOFF )) || auto_refuse cutoff_now_in_future
    if [[ $(jq -r .head "$job") != null ]]; then
        auto_validate_head "$job" >/dev/null 2>&1 || { auto_block "$job" saved_head_invalid; exit 2; }
    fi
    id=$(auto_next_id "$job")
    [[ $status != inflight || $(jq -r .pending_id "$job") == "$id" ]] || auto_refuse pending_id_mismatch
    if [[ -e $AUTO_ROOT/store/batch-$id || -L $AUTO_ROOT/store/batch-$id ]]; then
        auto_accept_batch "$job" "$id"
        exit 0
    fi
    partials=("$AUTO_ROOT/store/partial-$id."*)
    if (( ${#partials[@]}>0 )); then auto_block "$job" partial_requires_operator; exit 2; fi
    if ! grep -qx "$boot" "$AUTO_WORK/boots.ids"; then auto_block "$job" boot_no_longer_retained; exit 2; fi
    (( $(jq -r .attempts "$job")<3 )) || { auto_block "$job" attempt_limit; exit 2; }
    auto_store_capacity
    jq --arg id "$id" '.status="inflight"|.pending_id=$id|.attempts+=1|.last_reason="capture_started"' "$job" > "$AUTO_WORK/inflight.json"
    auto_atomic_job "$AUTO_WORK/inflight.json" "$boot"
    auto_boot_unchanged || auto_refuse current_boot_changed
    rc=0
    if [[ $(jq -r .head "$job") == null ]]; then
        /bin/bash "$history_dir/history-run.sh" "$AUTO_ROOT/store" "$AUTO_JOURNAL" "$boot" "$until" > "$AUTO_WORK/result.json" || rc=$?
    else
        /bin/bash "$history_dir/continue-run.sh" "$AUTO_ROOT/store" "$AUTO_JOURNAL" \
          "$(jq -r .head.batch_id "$job")" "$(jq -r .head.payload_sha256 "$job")" \
          "$(jq -r .head.manifest_sha256 "$job")" > "$AUTO_WORK/result.json" || rc=$?
    fi
    auto_boot_unchanged || auto_refuse current_boot_changed
    if (( rc==0 )); then auto_accept_batch "$job" "$id"; exit 0; fi
    # No arbitrary helper stderr/reason strings leave this process.
    if (( rc==75 )); then auto_report deferred store_locked "$boot"; exit 75; fi
    auto_block "$job" capture_failed_requires_operator
    exit 2
done
auto_boot_unchanged || auto_refuse current_boot_changed
auto_report idle no_ready_job
