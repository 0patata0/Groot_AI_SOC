#!/bin/bash
# Bounded read-only inventory of previous-boot journal; never reinjects events.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH
[[ $(uname -s) == Linux && $# == 0 ]] || exit 64
stage=$(mktemp -d /var/tmp/capstone-vector-journal-history.XXXXXX)
step=list_boots
cleanup() {
    status=$?
    if [[ $status != 0 ]]; then
        jq -nc --arg step "$step" --argjson status "$status" '{test:"journal_history",step:$step,exit_code:$status,operational_reinjection:false}'
    fi
    rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM
timeout 15s journalctl --list-boots --no-pager > "$stage/boots" 2> "$stage/error"
boot_count=$(awk '$1 ~ /^-?[0-9]+$/ {n++} END {print n+0}' "$stage/boots")
has_previous=$(awk '$1 == "-1" {found=1} END {print found+0}' "$stage/boots")
if [[ $has_previous == 0 ]]; then
    jq -nc --argjson boots "$boot_count" '{previous_boot_available:false,retained_boots:$boots,operational_reinjection:false,raw_payload_exported:false}'
    exit 0
fi
previous_id=$(awk '$1 == "-1" {print $2}' "$stage/boots")
[[ $previous_id =~ ^[a-f0-9]{32}$ ]]
step=extract_previous_boot
(
    ulimit -f 32768
    timeout 15s nice -n 10 journalctl --boot="$previous_id" --no-pager --all --output=json --lines=1000 \
        --output-fields=__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_TRANSPORT,MESSAGE _TRANSPORT=kernel \
        > "$stage/kernel.jsonl" 2> "$stage/error"
)
bytes=$(stat -c %s "$stage/kernel.jsonl")
[[ $bytes -le 33554432 ]]
step=summarize_metadata
jq -sc --argjson boots "$boot_count" --argjson bytes "$bytes" --arg boot "$previous_id" '
{previous_boot_available:true,retained_boots:$boots,examined_previous_kernel_records:length,sample_bytes:$bytes,
 nft_prefix_records:([.[] | select((.MESSAGE|type)=="string") | select(.MESSAGE|test("^(AGENT_BLOCK|FW_DROP_IN|FW_DROP_OUT|FW_DROP_FWD|FW_SHADOW_OUT|FW_SSH_RATE|SPOOF)\\s"))]|length),
 records_with_cursor_timestamp_transport:([.[] | select((.__CURSOR|type)=="string" and (.__REALTIME_TIMESTAMP|type)=="string" and ._TRANSPORT=="kernel")]|length),
 selected_boot_binding_verified:all(.[]; ._BOOT_ID==$boot),
 bounded_sample_only:true,operational_reinjection:false,raw_payload_exported:false}' "$stage/kernel.jsonl"
