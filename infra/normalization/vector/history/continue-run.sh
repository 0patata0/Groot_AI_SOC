#!/bin/bash
# Internal worker: root path/journal parameters are supplied only by the fixed wrapper or tests.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/history-lib.sh"
source "$directory/continuation-lib.sh"
[[ $# == 5 ]] || continuation_refuse invalid_internal_arguments
root=$1 journal=$2 CONTINUATION_PARENT=$3 CONTINUATION_PARENT_SHA=$4 CONTINUATION_PARENT_MANIFEST_SHA=$5
[[ $CONTINUATION_PARENT =~ ^[0-9a-f]{64}$ && $CONTINUATION_PARENT_SHA =~ ^[0-9a-f]{64}$ &&
   $CONTINUATION_PARENT_MANIFEST_SHA =~ ^[0-9a-f]{64}$ ]] || continuation_refuse invalid_parent_identity
history_safe_dir "$root" || continuation_refuse unsafe_store
history_safe_file "$root/.lock" || continuation_refuse unsafe_lock
[[ $(stat -c %a "$root/.lock") == 600 ]] || continuation_refuse unsafe_lock
[[ -x $journal ]] || continuation_refuse journal_unavailable
exec 9<>"$root/.lock"
flock -n 9 || exit 75
parent=$root/batch-$CONTINUATION_PARENT
continuation_safe_batch "$parent"
[[ $(sha256sum "$parent/manifest.json" | cut -d ' ' -f1) == "$CONTINUATION_PARENT_MANIFEST_SHA" ]] || continuation_refuse parent_manifest_mismatch
continuation_check_manifest "$parent" "$CONTINUATION_PARENT" "$CONTINUATION_PARENT_SHA"
HISTORY_BOOT=$(jq -r .boot_id "$parent/manifest.json")
HISTORY_UNTIL=$(jq -r .until_epoch_us "$parent/manifest.json")
HISTORY_POLICY=$CONTINUATION_POLICY
HISTORY_MAX_RECORDS=1000 HISTORY_MAX_BYTES=33554432 HISTORY_MAX_MS=15000
HISTORY_DEADLINE=$(( $(history_now_ms) + HISTORY_MAX_MS ))
HISTORY_CAPTURED=0 HISTORY_PRODUCER_RC=0 HISTORY_CONSUMER_RC=0 HISTORY_EXHAUSTED=null HISTORY_CAPTURE_ERROR=''
check=$(mktemp -d "$root/.parent-check.XXXXXX")
trap 'rm -rf -- "$check"' EXIT
history_validate "$parent/kernel.jsonl" 1000 "$check/parent-summary.json" || continuation_refuse parent_payload_invalid
jq -e --slurpfile actual "$check/parent-summary.json" '.record_metadata==$actual[0] and .records==$actual[0].count' \
  "$parent/manifest.json" >/dev/null || continuation_refuse parent_record_metadata_mismatch
HISTORY_BATCH=$(continuation_id "$CONTINUATION_PARENT" "$CONTINUATION_PARENT_SHA" "$CONTINUATION_PARENT_MANIFEST_SHA" "$HISTORY_BOOT" "$HISTORY_UNTIL")
final=$root/batch-$HISTORY_BATCH
if [[ -e $final || -L $final ]]; then
    continuation_safe_batch "$final"
    child_sha=$(jq -er '.sha256|select(type=="string" and test("^[0-9a-f]{64}$"))' "$final/manifest.json")
    continuation_check_manifest "$final" "$HISTORY_BATCH" "$child_sha"
    history_validate "$final/kernel.jsonl" 1000 "$check/child-summary.json" || continuation_refuse existing_child_invalid
    jq -e --slurpfile actual "$check/child-summary.json" --arg parent "$CONTINUATION_PARENT" \
      --arg payload_sha "$CONTINUATION_PARENT_SHA" --arg manifest_sha "$CONTINUATION_PARENT_MANIFEST_SHA" \
      --arg boot "$HISTORY_BOOT" --arg until "$HISTORY_UNTIL" \
      '.record_metadata==$actual[0] and .records==$actual[0].count and .parent.batch_id==$parent and
       .parent.payload_sha256==$payload_sha and .parent.manifest_sha256==$manifest_sha and
       .boot_id==$boot and .until_epoch_us==$until and .continuation_boundary_verified==true' \
      "$final/manifest.json" >/dev/null || continuation_refuse existing_child_binding_mismatch
    sync -- "$final/kernel.jsonl" "$final/manifest.json" "$final" "$root"
    history_report "$final"
    exit 0
fi
jq -e '.source_range_exhausted==false' "$parent/manifest.json" >/dev/null || continuation_refuse parent_already_exhausted
available=$(df --output=avail -B1 "$root" | tail -n1 | tr -d ' ')
[[ $available =~ ^[0-9]+$ ]] && (( available >= 41943040 )) || continuation_refuse insufficient_free_space
HISTORY_ATTEMPT=$(mktemp -d "$root/partial-$HISTORY_BATCH.XXXXXX")
: > "$HISTORY_ATTEMPT/kernel.jsonl"
CONTINUATION_PHASE=parent_boundary_before CONTINUATION_VERIFIED=false
parent_last=$(jq -r .last_cursor "$check/parent-summary.json")
parent_monotonic=$(jq -r .last_monotonic "$check/parent-summary.json")
seconds=$((10#$HISTORY_UNTIL / 1000000)); fraction=$((10#$HISTORY_UNTIL % 1000000))
printf -v cutoff '@%d.%06d' "$seconds" "$fraction"
common=(--boot="$HISTORY_BOOT" --until="$cutoff" --no-pager --quiet --all --output=json \
  --output-fields=__CURSOR,__REALTIME_TIMESTAMP,__MONOTONIC_TIMESTAMP,_BOOT_ID,_TRANSPORT,MESSAGE _TRANSPORT=kernel)
reason='' summary=$HISTORY_ATTEMPT/summary.json
if ! history_capture "$HISTORY_ATTEMPT/boundary-before.jsonl" "$journal" "${common[@]}" --cursor="$parent_last" --lines=+2; then reason=$HISTORY_CAPTURE_ERROR
elif ! history_validate "$HISTORY_ATTEMPT/boundary-before.jsonl" 2 "$HISTORY_ATTEMPT/boundary-before-summary.json"; then reason=$HISTORY_CAPTURE_ERROR
elif [[ $(jq -r .first_cursor "$HISTORY_ATTEMPT/boundary-before-summary.json") != "$parent_last" ]]; then reason=parent_cursor_unavailable
elif [[ $(jq -r .count "$HISTORY_ATTEMPT/boundary-before-summary.json") != 2 ]]; then reason=next_record_unavailable
fi
if [[ -z $reason ]]; then
    CONTINUATION_PHASE=child_capture
    expected_first=$(jq -r .last_cursor "$HISTORY_ATTEMPT/boundary-before-summary.json")
    if ! history_capture "$HISTORY_ATTEMPT/kernel.jsonl" "$journal" "${common[@]}" --after-cursor="$parent_last" --lines=+1000; then reason=$HISTORY_CAPTURE_ERROR
    elif ! history_validate "$HISTORY_ATTEMPT/kernel.jsonl" 1000 "$summary"; then reason=$HISTORY_CAPTURE_ERROR
    elif ! jq -e --arg next "$expected_first" --arg parent "$parent_last" --arg mono "$parent_monotonic" \
      '.first_cursor==$next and .first_cursor!=$parent and (.first_monotonic|tonumber)>=($mono|tonumber)' "$summary" >/dev/null; then reason=child_start_boundary_mismatch
    fi
fi
if [[ -z $reason ]]; then
    CONTINUATION_PHASE=child_boundary_after
    child_last=$(jq -r .last_cursor "$summary")
    if ! history_capture "$HISTORY_ATTEMPT/tail.jsonl" "$journal" "${common[@]}" --cursor="$child_last" --lines=+2; then reason=$HISTORY_CAPTURE_ERROR
    elif ! history_validate "$HISTORY_ATTEMPT/tail.jsonl" 2 "$HISTORY_ATTEMPT/tail-summary.json"; then reason=$HISTORY_CAPTURE_ERROR
    elif [[ $(jq -r .first_cursor "$HISTORY_ATTEMPT/tail-summary.json") != "$child_last" ]]; then reason=child_cursor_unavailable
    else HISTORY_EXHAUSTED=$(jq '.count==1' "$HISTORY_ATTEMPT/tail-summary.json")
    fi
fi
if [[ -z $reason ]]; then
    CONTINUATION_PHASE=parent_boundary_after
    if ! history_capture "$HISTORY_ATTEMPT/boundary-after.jsonl" "$journal" "${common[@]}" --cursor="$parent_last" --lines=+1; then reason=$HISTORY_CAPTURE_ERROR
    elif ! history_validate "$HISTORY_ATTEMPT/boundary-after.jsonl" 1 "$HISTORY_ATTEMPT/boundary-after-summary.json"; then reason=$HISTORY_CAPTURE_ERROR
    elif [[ $(jq -r .first_cursor "$HISTORY_ATTEMPT/boundary-after-summary.json") != "$parent_last" ]]; then reason=parent_cursor_disappeared
    elif [[ $(sha256sum "$parent/kernel.jsonl" | cut -d ' ' -f1) != "$CONTINUATION_PARENT_SHA" ||
            $(sha256sum "$parent/manifest.json" | cut -d ' ' -f1) != "$CONTINUATION_PARENT_MANIFEST_SHA" ]]; then reason=parent_changed_during_capture
    else CONTINUATION_VERIFIED=true; CONTINUATION_PHASE=verified
    fi
fi
if [[ -n $reason ]]; then
    HISTORY_EXHAUSTED=null
    if ! jq -e 'type=="object" and (.count|type)=="number"' "$summary" >/dev/null 2>&1; then summary=/dev/null; fi
    continuation_manifest partial "$reason" "$summary"
    sync -- "$HISTORY_ATTEMPT/kernel.jsonl" "$HISTORY_ATTEMPT/manifest.json" "$HISTORY_ATTEMPT" "$root"
    history_report "$HISTORY_ATTEMPT"
    exit 2
fi
continuation_manifest complete_batch verified "$summary"
chmod 400 "$HISTORY_ATTEMPT/kernel.jsonl" "$HISTORY_ATTEMPT/manifest.json"
sync -- "$HISTORY_ATTEMPT/kernel.jsonl" "$HISTORY_ATTEMPT/manifest.json" "$HISTORY_ATTEMPT"
mv -T -n -- "$HISTORY_ATTEMPT" "$final"
[[ ! -e $HISTORY_ATTEMPT ]]
sync -- "$root"
history_report "$final"
