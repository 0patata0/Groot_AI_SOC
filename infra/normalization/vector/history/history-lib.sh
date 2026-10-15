#!/bin/bash
# Sourced by the fixed operator wrapper and synthetic tests, never a daemon.
HISTORY_POLICY=previous-kernel-batch-v1
HISTORY_LIB_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

history_now_ms() { awk '{printf "%.0f\n", $1 * 1000}' /proc/uptime; }
history_safe_dir() {
    [[ -d $1 && ! -L $1 && $(stat -c %u "$1") == "$(id -u)" && $(stat -c %a "$1") == 700 ]]
}
history_safe_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u "$1") == "$(id -u)" && $(stat -c %h "$1") == 1 ]]
}
history_capture() {
    local dest=$1; shift
    local remaining=$(( HISTORY_DEADLINE - $(history_now_ms) - 200 ))
    local allowance=$(( HISTORY_MAX_BYTES - HISTORY_CAPTURED ))
    HISTORY_PRODUCER_RC=0 HISTORY_CONSUMER_RC=0 HISTORY_CAPTURE_ERROR=''
    if (( remaining <= 0 )); then HISTORY_CAPTURE_ERROR=deadline; return 1; fi
    if (( allowance <= 0 )); then HISTORY_CAPTURE_ERROR=byte_budget; return 1; fi
    local seconds pipe_rc bytes extra
    printf -v seconds '%d.%03d' "$((remaining / 1000))" "$((remaining % 1000))"
    # Preserve the two statuses separately; SIGPIPE is not success even under pipefail.
    # The extra byte is counted, never written to disk or returned as payload.
    set +e
    timeout --kill-after=0.2s "${seconds}s" "$@" 2>/dev/null |
      { head -c "$allowance" > "$dest" && head -c 1 | wc -c > "$dest.overflow-count"; }
    pipe_rc=("${PIPESTATUS[@]}")
    set -e
    HISTORY_PRODUCER_RC=${pipe_rc[0]} HISTORY_CONSUMER_RC=${pipe_rc[1]}
    bytes=$(stat -c %s "$dest")
    HISTORY_CAPTURED=$((HISTORY_CAPTURED + bytes))
    extra=$(cat "$dest.overflow-count" 2>/dev/null || printf '0')
    if [[ $extra != 0 ]]; then HISTORY_CAPTURE_ERROR=byte_budget
    elif (( HISTORY_CONSUMER_RC != 0 )); then HISTORY_CAPTURE_ERROR=capture_io
    elif (( HISTORY_PRODUCER_RC == 124 )); then HISTORY_CAPTURE_ERROR=timeout
    elif (( HISTORY_PRODUCER_RC == 137 )); then HISTORY_CAPTURE_ERROR=killed_or_timeout
    elif (( HISTORY_PRODUCER_RC == 141 )); then HISTORY_CAPTURE_ERROR=producer_sigpipe
    elif (( HISTORY_PRODUCER_RC != 0 )); then HISTORY_CAPTURE_ERROR=producer_failed
    fi
    [[ -z $HISTORY_CAPTURE_ERROR ]]
}
history_validate() {
    local file=$1 max=$2 out=$3 remaining seconds
    [[ -s $file ]] || { HISTORY_CAPTURE_ERROR=empty_range_unproven; return 1; }
    [[ $(tail -c 1 "$file" | od -An -tu1 | tr -d ' \n') == 10 ]] || {
        HISTORY_CAPTURE_ERROR=missing_final_lf; return 1;
    }
    remaining=$(( HISTORY_DEADLINE - $(history_now_ms) - 200 ))
    if (( remaining <= 0 )); then HISTORY_CAPTURE_ERROR=deadline; return 1; fi
    printf -v seconds '%d.%03d' "$((remaining / 1000))" "$((remaining % 1000))"
    if ! (ulimit -v 262144; timeout --kill-after=0.2s "${seconds}s" jq -Rn \
      --arg boot "$HISTORY_BOOT" --arg until "$HISTORY_UNTIL" --argjson max_records "$max" \
      -f "$HISTORY_LIB_DIR/validate-records.jq" "$file" > "$out" 2>/dev/null); then
        HISTORY_CAPTURE_ERROR=invalid_json_or_metadata; return 1
    fi
}
history_manifest() {
    local status=$1 reason=$2 summary=${3:-/dev/null}
    local bytes=0 sha count=null summary_json=null physical_lines
    [[ ! -f $HISTORY_ATTEMPT/kernel.jsonl ]] || bytes=$(stat -c %s "$HISTORY_ATTEMPT/kernel.jsonl")
    sha=$(sha256sum "$HISTORY_ATTEMPT/kernel.jsonl" | cut -d ' ' -f1)
    physical_lines=$(wc -l < "$HISTORY_ATTEMPT/kernel.jsonl" | tr -d ' ')
    if [[ -s $summary ]]; then summary_json=$(cat "$summary"); count=$(jq -r '.count' "$summary"); fi
    jq -n --arg policy "$HISTORY_POLICY" --arg batch_id "$HISTORY_BATCH" --arg status "$status" \
      --arg reason "$reason" --arg boot "$HISTORY_BOOT" --arg until "$HISTORY_UNTIL" \
      --arg sha "$sha" --argjson bytes "$bytes" --argjson count "$count" \
      --argjson physical_lines "$physical_lines" \
      --argjson max_bytes "$HISTORY_MAX_BYTES" --argjson max_records "$HISTORY_MAX_RECORDS" \
      --argjson max_ms "$HISTORY_MAX_MS" --argjson producer_exit "$HISTORY_PRODUCER_RC" \
      --argjson consumer_exit "$HISTORY_CONSUMER_RC" --argjson captured_bytes "$HISTORY_CAPTURED" \
      --argjson source_range_exhausted "$HISTORY_EXHAUSTED" --argjson record_metadata "$summary_json" \
      '{policy:$policy,batch_id:$batch_id,status:$status,reason:$reason,boot_id:$boot,until_epoch_us:$until,
        selection:{transport:"kernel",order:"oldest",max_records:$max_records,max_bytes:$max_bytes,
          capture_validation_budget_ms:$max_ms,finalization_in_budget:false},
        bytes:$bytes,sha256:$sha,records:$count,physical_newlines:$physical_lines,
        records_verified:($count != null),record_metadata:$record_metadata,
        source_range_exhausted:$source_range_exhausted,captured_bytes_including_verification:$captured_bytes,
        producer_exit:$producer_exit,consumer_exit:$consumer_exit,original_ack_boundary_known:false,
        operational_checkpoint_changed:false,reinjected:false,remote_receipt:false}' \
        > "$HISTORY_ATTEMPT/manifest.json.tmp"
    mv -T -- "$HISTORY_ATTEMPT/manifest.json.tmp" "$HISTORY_ATTEMPT/manifest.json"
}
history_report() {
    jq -c '{policy,batch_id,status,reason,records,bytes,sha256,source_range_exhausted,
      original_ack_boundary_known,operational_checkpoint_changed,reinjected,remote_receipt}' "$1/manifest.json"
}
history_export() {
    # A fresh shell keeps errexit effective even when an operator/test captures our status with ||.
    /bin/bash "$HISTORY_LIB_DIR/history-run.sh" "$@"
}
history_export_inner() (
    set -euo pipefail
    umask 077
    export LC_ALL=C
    local root=$1 journal=$2
    HISTORY_BOOT=$3 HISTORY_UNTIL=$4
    HISTORY_MAX_RECORDS=${5:-1000} HISTORY_MAX_BYTES=${6:-33554432} HISTORY_MAX_MS=${7:-15000}
    [[ $HISTORY_BOOT =~ ^[a-f0-9]{32}$ && $HISTORY_UNTIL =~ ^[1-9][0-9]{0,15}$ ]]
    [[ $HISTORY_MAX_RECORDS =~ ^[1-9][0-9]*$ && $HISTORY_MAX_BYTES =~ ^[1-9][0-9]*$ && $HISTORY_MAX_MS =~ ^[1-9][0-9]*$ ]]
    (( HISTORY_MAX_RECORDS <= 1000 && HISTORY_MAX_BYTES <= 33554432 && HISTORY_MAX_MS <= 15000 ))
    [[ -x $journal && ! -L $root ]]
    if [[ ! -e $root ]]; then mkdir -m 700 -- "$root"; fi
    history_safe_dir "$root"
    if [[ ! -e $root/.lock ]]; then (set -C; : > "$root/.lock"); fi
    history_safe_file "$root/.lock"
    [[ $(stat -c %a "$root/.lock") == 600 ]]
    exec 9<>"$root/.lock"
    flock -n 9 || return 75
    HISTORY_BATCH=$(printf '%s\n' "$HISTORY_POLICY" "$HISTORY_BOOT" "$HISTORY_UNTIL" "$HISTORY_MAX_RECORDS" "$HISTORY_MAX_BYTES" | sha256sum | cut -d ' ' -f1)
    local final=$root/batch-$HISTORY_BATCH
    if [[ -e $final || -L $final ]]; then
        history_safe_dir "$final" && history_safe_file "$final/manifest.json" && history_safe_file "$final/kernel.jsonl"
        [[ $(stat -c %a "$final/manifest.json") == 400 && $(stat -c %a "$final/kernel.jsonl") == 400 ]]
        jq -e --arg id "$HISTORY_BATCH" --arg boot "$HISTORY_BOOT" --arg until "$HISTORY_UNTIL" \
          '.batch_id==$id and .boot_id==$boot and .until_epoch_us==$until and .status=="complete_batch"' "$final/manifest.json" >/dev/null
        [[ $(sha256sum "$final/kernel.jsonl" | cut -d ' ' -f1) == "$(jq -r .sha256 "$final/manifest.json")" ]]
        [[ $(stat -c %s "$final/kernel.jsonl") == "$(jq -r .bytes "$final/manifest.json")" ]]
        sync -- "$final/kernel.jsonl"
        sync -- "$final/manifest.json"
        sync -- "$root"
        history_report "$final"
        return 0
    fi
    local available
    available=$(df --output=avail -B1 "$root" | tail -n 1 | tr -d ' ')
    [[ $available =~ ^[0-9]+$ ]]
    (( available >= HISTORY_MAX_BYTES + 8388608 ))
    HISTORY_ATTEMPT=$(mktemp -d "$root/partial-$HISTORY_BATCH.XXXXXX")
    : > "$HISTORY_ATTEMPT/kernel.jsonl"
    # /proc/uptime is monotonic across wall-clock adjustments; fixed --until is realtime.
    HISTORY_DEADLINE=$(( $(history_now_ms) + HISTORY_MAX_MS ))
    HISTORY_CAPTURED=0 HISTORY_PRODUCER_RC=0 HISTORY_CONSUMER_RC=0 HISTORY_EXHAUSTED=null HISTORY_CAPTURE_ERROR=''
    local cutoff seconds fraction summary=$HISTORY_ATTEMPT/summary.json reason=''
    seconds=$((10#$HISTORY_UNTIL / 1000000)); fraction=$((10#$HISTORY_UNTIL % 1000000))
    printf -v cutoff '@%d.%06d' "$seconds" "$fraction"
    local common=(--boot="$HISTORY_BOOT" --until="$cutoff" --no-pager --quiet --all --output=json \
      --output-fields=__CURSOR,__REALTIME_TIMESTAMP,__MONOTONIC_TIMESTAMP,_BOOT_ID,_TRANSPORT,MESSAGE _TRANSPORT=kernel)
    if ! history_capture "$HISTORY_ATTEMPT/kernel.jsonl" "$journal" "${common[@]}" --lines="+$HISTORY_MAX_RECORDS"; then reason=$HISTORY_CAPTURE_ERROR
    elif ! history_validate "$HISTORY_ATTEMPT/kernel.jsonl" "$HISTORY_MAX_RECORDS" "$summary"; then reason=$HISTORY_CAPTURE_ERROR
    else
        local first last
        first=$(jq -r .first_cursor "$summary"); last=$(jq -r .last_cursor "$summary")
        if ! history_capture "$HISTORY_ATTEMPT/first.jsonl" "$journal" "${common[@]}" --cursor="$first" --lines=+1; then reason=$HISTORY_CAPTURE_ERROR
        elif ! history_validate "$HISTORY_ATTEMPT/first.jsonl" 1 "$HISTORY_ATTEMPT/first-summary.json"; then reason=$HISTORY_CAPTURE_ERROR
        elif [[ $(jq -r .first_cursor "$HISTORY_ATTEMPT/first-summary.json") != "$first" ]]; then reason=first_cursor_unavailable
        elif ! history_capture "$HISTORY_ATTEMPT/tail.jsonl" "$journal" "${common[@]}" --cursor="$last" --lines=+2; then reason=$HISTORY_CAPTURE_ERROR
        elif ! history_validate "$HISTORY_ATTEMPT/tail.jsonl" 2 "$HISTORY_ATTEMPT/tail-summary.json"; then reason=$HISTORY_CAPTURE_ERROR
        elif [[ $(jq -r .first_cursor "$HISTORY_ATTEMPT/tail-summary.json") != "$last" ]]; then reason=last_cursor_unavailable
        else
            HISTORY_EXHAUSTED=$(jq '.count == 1' "$HISTORY_ATTEMPT/tail-summary.json")
        fi
    fi
    if [[ -n $reason ]]; then
        # A failed validator may leave a partial summary; never parse it as a completed result.
        if ! jq -e 'type=="object" and (.count|type)=="number"' "$summary" >/dev/null 2>&1; then summary=/dev/null; fi
        history_manifest partial "$reason" "$summary"
        sync -- "$HISTORY_ATTEMPT/kernel.jsonl"
        sync -- "$HISTORY_ATTEMPT/manifest.json"
        sync -- "$root"
        history_report "$HISTORY_ATTEMPT"
        return 2
    fi
    history_manifest complete_batch verified "$summary"
    chmod 400 "$HISTORY_ATTEMPT/kernel.jsonl" "$HISTORY_ATTEMPT/manifest.json"
    sync -- "$HISTORY_ATTEMPT/kernel.jsonl"
    sync -- "$HISTORY_ATTEMPT/manifest.json"
    sync -- "$HISTORY_ATTEMPT"
    mv -T -n -- "$HISTORY_ATTEMPT" "$final"
    [[ ! -e $HISTORY_ATTEMPT ]]
    sync -- "$root"
    history_report "$final"
)
