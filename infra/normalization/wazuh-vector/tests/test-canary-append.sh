#!/bin/bash
# Linux native fixture only; no operational paths or services are accessed.
set -euo pipefail
umask 077
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/canary-append-lib.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/capstone-canary-append.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
for n in {1..13}; do printf '{"synthetic_delivery_seq":%s}\n' "$n"; done > "$work/payload"
passed=0
for mode in paced burst; do
    printf 'previous fixture row\n' > "$work/$mode"
    prefix=$(stat -c %s "$work/$mode")
    identity=$(stat -c '%d:%i' "$work/$mode")
    exec 9>> "$work/$mode"
    flock -n 9
    capstone_canary_append "$work/$mode" "$work/payload" "$mode" "$identity" > "$work/$mode-result.json"
    exec 9>&-
    jq -e --arg mode "$mode" --argjson prefix "$prefix" \
      '.delivery_mode==$mode and .synthetic_rows_appended==13 and .append_start_bytes==$prefix and
       .append_end_bytes==(.append_start_bytes+.bytes) and .append_readback_sha_and_rows_verified and
       .source_sync_is_not_analysis_ack and .cross_pair_pause_seconds==(if $mode=="paced" then 3 else 0 end)' \
      "$work/$mode-result.json" >/dev/null
    tail -n 13 "$work/$mode" > "$work/readback"
    cmp -s "$work/payload" "$work/readback"
    passed=$((passed+1))
done
: > "$work/refused"
identity=$(stat -c '%d:%i' "$work/refused")
exec 9>> "$work/refused"
flock -n 9
if capstone_canary_append "$work/refused" "$work/payload" invalid "$identity" >/dev/null 2>&1; then exit 1; fi
[[ $(stat -c %s "$work/refused") == 0 ]]
passed=$((passed+1))
head -n 12 "$work/payload" > "$work/short"
if capstone_canary_append "$work/refused" "$work/short" burst "$identity" >/dev/null 2>&1; then exit 1; fi
[[ $(stat -c %s "$work/refused") == 0 ]]
passed=$((passed+1))
if capstone_canary_append "$work/refused" "$work/payload" burst '0:0' >/dev/null 2>&1; then exit 1; fi
[[ $(stat -c %s "$work/refused") == 0 ]]
passed=$((passed+1))
exec 9>&-
jq -cn --argjson passed "$passed" '{kind:"synthetic_canary_append_regression",passed:$passed,
 operational_input_write:false,server_connection:false,packet_generation:false}'
