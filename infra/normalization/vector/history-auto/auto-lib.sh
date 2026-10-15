#!/bin/bash
# Sourced only by the fixed root worker or the private native fixture.
AUTO_POLICY=bounded-previous-kernel-auto-v1
AUTO_MAX_JOBS=64 AUTO_MAX_BYTES=1073741824 AUTO_RESERVE_BYTES=41943040
AUTO_MAX_BATCH_DIRS=256 AUTO_MAX_STORE_ENTRIES=4096
auto_report() {
    jq -nc --arg outcome "$1" --arg reason "$2" --arg boot "${3:-}" \
      '{policy:"bounded-previous-kernel-auto-v1",outcome:$outcome,reason:$reason,
        boot_id:(if $boot=="" then null else $boot end),raw_payload_exported:false,
        operational_checkpoint_changed:false,reinjected:false,remote_receipt:false}'
}
auto_refuse() { auto_report deferred "$1"; exit "${2:-65}"; }
auto_safe_dir() {
    [[ -d $1 && ! -L $1 && $(stat -c %u:%g:%a "$1") == "$(id -u):$(id -g):700" ]]
}
auto_safe_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u:%g:%a:%h "$1") == "$(id -u):$(id -g):$2:1" ]]
}
auto_ancestors() {
    local p=$1
    [[ $p == /* && $p != *$'\n'* && $p != *'/../'* && $p != *'/./'* ]] || return 1
    while [[ $p != / ]]; do
        [[ ! -L $p ]] || return 1
        p=$(dirname -- "$p")
    done
}
auto_current() {
    local value
    value=$(tr -d '\n-' < "$AUTO_BOOT_FILE")
    [[ $value =~ ^[0-9a-f]{32}$ ]] || return 1
    printf '%s' "$value"
}
auto_boot_unchanged() { [[ $(auto_current) == "$AUTO_CURRENT" ]]; }
auto_atomic_job() {
    local src=$1 boot=$2 temp
    jq -e -f "$AUTO_DIR/state.jq" "$src" >/dev/null || auto_refuse invalid_job_candidate
    [[ $(jq -r .boot_id "$src") == "$boot" ]] || auto_refuse invalid_job_binding
    auto_boot_unchanged || auto_refuse current_boot_changed
    temp=$(mktemp "$AUTO_ROOT/jobs/.job-$boot.XXXXXX")
    cat -- "$src" > "$temp"
    chmod 600 "$temp"
    sync -- "$temp"
    # Check immediately before rename as well; no boot-switch result is committed.
    auto_boot_unchanged || auto_refuse current_boot_changed
    mv -T -- "$temp" "$AUTO_ROOT/jobs/$boot.json"
    sync -- "$AUTO_ROOT/jobs"
}
auto_check_job() {
    local file=$1 boot=$2
    auto_safe_file "$file" 600 && (( $(stat -c %s "$file") <= 16384 )) || auto_refuse unsafe_job
    jq -se --arg boot "$boot" 'length==1 and .[0].boot_id==$boot' "$file" >/dev/null || auto_refuse invalid_job
    jq -e -f "$AUTO_DIR/state.jq" "$file" >/dev/null || auto_refuse invalid_job
}
auto_next_id() {
    local job=$1
    if [[ $(jq -r .head "$job") == null ]]; then
        printf '%s\n' previous-kernel-batch-v1 "$(jq -r .boot_id "$job")" \
          "$(jq -r .until_epoch_us "$job")" 1000 33554432 | sha256sum | cut -d ' ' -f1
    else
        continuation_id "$(jq -r .head.batch_id "$job")" "$(jq -r .head.payload_sha256 "$job")" \
          "$(jq -r .head.manifest_sha256 "$job")" "$(jq -r .boot_id "$job")" "$(jq -r .until_epoch_us "$job")"
    fi
}
auto_validate_batch() (
    # A subprocess contains continuation_refuse's exit and never prints raw/cursors.
    set -euo pipefail
    local job=$1 id=$2 path=$AUTO_ROOT/store/batch-$2 sha
    continuation_safe_batch "$path" >/dev/null || return 1
    sha=$(jq -er '.sha256|select(type=="string" and test("^[0-9a-f]{64}$"))' "$path/manifest.json") || return 1
    continuation_check_manifest "$path" "$id" "$sha" >/dev/null || return 1
    HISTORY_BOOT=$(jq -r .boot_id "$job") || return 1
    HISTORY_UNTIL=$(jq -r .until_epoch_us "$job") || return 1
    HISTORY_DEADLINE=$(( $(history_now_ms) + 15000 ))
    history_validate "$path/kernel.jsonl" 1000 "$AUTO_WORK/record-summary.json" || return 1
    jq -e --slurpfile actual "$AUTO_WORK/record-summary.json" --slurpfile job "$job" '
      .boot_id==$job[0].boot_id and .until_epoch_us==$job[0].until_epoch_us and
      .record_metadata==$actual[0] and .records==$actual[0].count and
      (if $job[0].head==null then .policy=="previous-kernel-batch-v1" else
        .policy=="previous-kernel-continuation-v1" and .parent==$job[0].head end)' "$path/manifest.json" >/dev/null || return 1
)
auto_validate_head() (
    set -euo pipefail
    local job=$1 id path sha
    id=$(jq -r .head.batch_id "$job") || return 1
    path=$AUTO_ROOT/store/batch-$id
    sha=$(jq -r .head.payload_sha256 "$job") || return 1
    continuation_safe_batch "$path" >/dev/null || return 1
    [[ $(sha256sum "$path/manifest.json" | cut -d ' ' -f1) == "$(jq -r .head.manifest_sha256 "$job")" ]] || return 1
    continuation_check_manifest "$path" "$id" "$sha" >/dev/null || return 1
    HISTORY_BOOT=$(jq -r .boot_id "$job") || return 1
    HISTORY_UNTIL=$(jq -r .until_epoch_us "$job") || return 1
    HISTORY_DEADLINE=$(( $(history_now_ms) + 15000 ))
    history_validate "$path/kernel.jsonl" 1000 "$AUTO_WORK/head-summary.json" || return 1
    jq -e --slurpfile actual "$AUTO_WORK/head-summary.json" --slurpfile job "$job" '
      .boot_id==$job[0].boot_id and .until_epoch_us==$job[0].until_epoch_us and
      .record_metadata==$actual[0] and .records==$actual[0].count and
      (.source_range_exhausted==($job[0].status=="complete"))' "$path/manifest.json" >/dev/null || return 1
)
auto_accept_batch() {
    local job=$1 id=$2 path=$AUTO_ROOT/store/batch-$2 msha
    auto_validate_batch "$job" "$id" >/dev/null 2>&1 || auto_refuse completed_batch_invalid
    # Recovered rename is not enough: make the completed source durable again
    # before publishing its identity in the persistent job (also on replay).
    sync -- "$path/kernel.jsonl" "$path/manifest.json" "$path" "$AUTO_ROOT/store" || auto_refuse completed_batch_sync_failed
    msha=$(sha256sum "$path/manifest.json" | cut -d ' ' -f1)
    jq --arg id "$id" --arg manifest_sha "$msha" --slurpfile result "$path/manifest.json" '
      .head={batch_id:$id,payload_sha256:$result[0].sha256,manifest_sha256:$manifest_sha} |
      .batches+=1 | .records+=$result[0].records | .bytes+=$result[0].bytes |
      .status=(if $result[0].source_range_exhausted then "complete" else "ready" end) |
      .pending_id=null | .attempts=0 | .last_reason="batch_preserved"
    ' "$job" > "$AUTO_WORK/next.json"
    auto_atomic_job "$AUTO_WORK/next.json" "$(jq -r .boot_id "$job")"
    jq -c '{policy,outcome:"batch_preserved",boot_id,status,batches,records,bytes,
       source_range_exhausted:(.status=="complete"),raw_payload_exported:false,
       operational_checkpoint_changed:false,reinjected:false,remote_receipt:false}' "$AUTO_WORK/next.json"
}
auto_block() {
    local job=$1 reason=$2
    jq --arg reason "$reason" '.status="blocked"|.pending_id=null|.last_reason=$reason' "$job" > "$AUTO_WORK/blocked.json"
    auto_atomic_job "$AUTO_WORK/blocked.json" "$(jq -r .boot_id "$job")"
    auto_report blocked "$reason" "$(jq -r .boot_id "$job")"
}
auto_store_capacity() {
    local rc entries bytes dirs
    set +e
    find "$AUTO_ROOT/store" -xdev -printf '%y %s\n' 2>/dev/null | head -n 4097 > "$AUTO_WORK/store-size.txt"
    rc=("${PIPESTATUS[@]}")
    set -e
    entries=$(wc -l < "$AUTO_WORK/store-size.txt")
    (( entries < 4097 )) || auto_refuse store_entry_limit
    (( rc[0]==0 && rc[1]==0 )) || auto_refuse store_measurement_failed
    awk 'NF!=2 || $1!~/^[df]$/ || $2!~/^[0-9]+$/ {exit 1}' "$AUTO_WORK/store-size.txt" || auto_refuse unsafe_store_entry
    bytes=$(awk '{n+=$2} END{printf "%.0f",n}' "$AUTO_WORK/store-size.txt")
    dirs=$(find "$AUTO_ROOT/store" -mindepth 1 -maxdepth 1 -type d \( -name 'batch-*' -o -name 'partial-*' \) -printf '.\n' | wc -l)
    (( bytes <= AUTO_MAX_BYTES - AUTO_RESERVE_BYTES )) || auto_refuse store_byte_limit
    (( dirs < AUTO_MAX_BATCH_DIRS )) || auto_refuse store_batch_partial_limit
}
auto_discover() {
    local rc bytes count boot current_seen=0
    set +e
    timeout --kill-after=1s 5s "$AUTO_JOURNAL" --list-boots --no-pager --quiet 2>/dev/null |
      head -c 65537 > "$AUTO_WORK/boots.txt"
    rc=("${PIPESTATUS[@]}")
    set -e
    bytes=$(stat -c %s "$AUTO_WORK/boots.txt")
    (( bytes<=65536 )) || auto_refuse boot_list_byte_limit
    (( rc[0]==0 && rc[1]==0 )) || auto_refuse boot_list_unavailable
    awk 'NF<2 || $1!~/^-?[0-9]+$/ || length($2)!=32 || $2!~/^[0-9a-f]+$/ {exit 1}
      {print $2}' "$AUTO_WORK/boots.txt" > "$AUTO_WORK/boots.ids" || auto_refuse boot_list_invalid
    count=$(wc -l < "$AUTO_WORK/boots.ids")
    (( count>=1 && count<=AUTO_MAX_JOBS )) || auto_refuse boot_list_count_limit
    [[ $(sort -u "$AUTO_WORK/boots.ids" | wc -l) == "$count" ]] || auto_refuse boot_list_duplicate
    grep -qx "$AUTO_CURRENT" "$AUTO_WORK/boots.ids" || auto_refuse current_boot_not_listed
    # All metadata is parsed before any new job is committed: no hidden truncation.
    count=$(find "$AUTO_ROOT/jobs" -mindepth 1 -maxdepth 1 -name '*.json' -printf '.\n' | wc -l)
    while IFS= read -r boot; do
        [[ $boot != "$AUTO_CURRENT" || -e $AUTO_ROOT/jobs/$boot.json ]] || continue
        [[ ! -e $AUTO_ROOT/jobs/$boot.json ]] || continue
        count=$((count+1))
    done < "$AUTO_WORK/boots.ids"
    (( count<=AUTO_MAX_JOBS )) || auto_refuse job_count_limit
    while IFS= read -r boot; do
        [[ $boot != "$AUTO_CURRENT" ]] || continue
        [[ ! -e $AUTO_ROOT/jobs/$boot.json ]] || continue
        jq -n --arg boot "$boot" --arg current "$AUTO_CURRENT" --arg until "$AUTO_CUTOFF" '
          {schema_version:1,policy:"bounded-previous-kernel-auto-v1",boot_id:$boot,until_epoch_us:$until,
           current_boot_at_discovery:$current,status:"ready",head:null,batches:0,records:0,bytes:0,
           pending_id:null,attempts:0,last_reason:"discovered"}' > "$AUTO_WORK/new.json"
        auto_atomic_job "$AUTO_WORK/new.json" "$boot"
    done < "$AUTO_WORK/boots.ids"
}
