#!/bin/bash
# Fixed A operator entry point; private functions can be sourced by synthetic tests.
# The receipt hash proves content identity. An authenticated B response remains a caller precondition.
ack_sync() { /usr/bin/sync -- "$@"; }
ack_sha() { /usr/bin/sha256sum -- "$1" | cut -d ' ' -f1; }
ack_dir() { [[ -d $1 && ! -L $1 && $(stat -c '%u:%a' "$1") == "$(id -u):700" ]]; }
ack_file() {
    [[ -f $1 && ! -L $1 && $(stat -c '%u:%a:%h' "$1") == "$(id -u):$2:1" ]]
}
ack_identity() { stat -c '%d:%i:%s:%y:%z:%u:%g:%a:%h' -- "$1"; }
ack_make_dir() {
    if [[ ! -e $1 && ! -L $1 ]]; then mkdir -m 700 -- "$1"; ack_sync "$1" "$(dirname -- "$1")"; fi
    ack_dir "$1"
}
ack_source() {
    local root=$1 id=$2 payload_sha=$3 manifest_sha=$4 path before_payload before_manifest
    path=$root/batch-$id
    ack_dir "$root"; ack_dir "$path"
    ack_file "$path/kernel.jsonl" 400; ack_file "$path/manifest.json" 400
    (( $(stat -c %s "$path/kernel.jsonl") > 0 && $(stat -c %s "$path/kernel.jsonl") <= 33554432 ))
    (( $(stat -c %s "$path/manifest.json") > 0 && $(stat -c %s "$path/manifest.json") <= 65536 ))
    before_payload=$(ack_identity "$path/kernel.jsonl"); before_manifest=$(ack_identity "$path/manifest.json")
    [[ $(dd if="$path/kernel.jsonl" iflag=nofollow,nonblock,count_bytes count=33554432 status=none | sha256sum | cut -d ' ' -f1) == "$payload_sha" ]]
    [[ $(dd if="$path/manifest.json" iflag=nofollow,nonblock,count_bytes count=65536 status=none | sha256sum | cut -d ' ' -f1) == "$manifest_sha" ]]
    [[ $(ack_identity "$path/kernel.jsonl") == "$before_payload" && $(ack_identity "$path/manifest.json") == "$before_manifest" ]]
    jq -e --arg id "$id" --arg payload "$payload_sha" --argjson size "$(stat -c %s "$path/kernel.jsonl")" '
      .batch_id==$id and .sha256==$payload and .bytes==$size and .status=="complete_batch" and
      (.records|type=="number" and floor==. and .>=1 and .<=1000) and
      (.policy=="previous-kernel-batch-v1" or .policy=="previous-kernel-continuation-v1")
    ' "$path/manifest.json" >/dev/null
}
ack_report() {
    jq -nc --arg id "$1" --arg sha "$2" --argjson reused "$3" '
      {stage:"receipt_recorded_on_source",batch_id:$id,receipt_sha256:$sha,reused:$reused,
       remote_stage:"remote_file_preserved",wazuh_analysis_receipt:false,indexer_receipt:false}'
}
acknowledge_core() (
    set -euo pipefail
    umask 077
    export LC_ALL=C TZ=Asia/Seoul
    [[ $# == 4 ]]
    root=$1 id=$2 payload_sha=$3 manifest_sha=$4
    for value in "$id" "$payload_sha" "$manifest_sha"; do [[ $value =~ ^[0-9a-f]{64}$ ]]; done
    ack_source "$root" "$id" "$payload_sha" "$manifest_sha"
    receipts=$root/receipts
    ack_make_dir "$receipts"
    if [[ ! -e $receipts/.lock && ! -L $receipts/.lock ]]; then (set -C; : > "$receipts/.lock"); fi
    ack_file "$receipts/.lock" 600
    exec 9<>"$receipts/.lock"
    flock -n 9
    attempt=$(mktemp -d "$receipts/.pending-$id.XXXXXX")
    trap '[[ ! -e $attempt ]] || rm -rf -- "$attempt"' EXIT
    # At most 64 KiB is stored; the next byte is counted only. Slow input is bounded too.
    timeout --kill-after=0.2s 5s /bin/bash -c \
      'set -euo pipefail; head -c 65536 > "$1/response.json"; head -c 1 | wc -c > "$1/overflow-count"' _ "$attempt"
    [[ $(cat "$attempt/overflow-count") == 0 && -s $attempt/response.json ]]
    # Flat scalar fields only: this also refuses duplicate keys hidden behind nested values.
    (ulimit -v 131072; timeout --kill-after=0.2s 5s jq --stream -ne '
      [inputs | select(length==2)] as $items |
      all($items[]; (.[0]|length)==1 and (.[1]|type)!="array" and (.[1]|type)!="object") and
      ($items|map(.[0]|tojson)|length)==($items|map(.[0]|tojson)|unique|length)
    ' "$attempt/response.json" >/dev/null 2>&1)
    (ulimit -v 131072; timeout --kill-after=0.2s 5s jq -se --arg id "$id" --arg payload "$payload_sha" --arg manifest "$manifest_sha" '
      length==1 and (.[0] | type=="object" and
      keys==["batch_id","bytes","manifest_sha256","payload_sha256","receipt_sha256","received_at_kst","receiver_machine_id","records","reused","schema_version","source_machine_id","source_policy","stage","store_id"] and
      .schema_version=="1" and .stage=="remote_file_preserved" and .batch_id==$id and
      .receiver_machine_id=="1e143067c98a44ffba6eaa925dc038d7" and
      .source_machine_id=="096e90b6243e438aa8a7b392be754732" and .store_id=="capstone-history-receipts-v1" and
      .payload_sha256==$payload and .manifest_sha256==$manifest and
      (.receipt_sha256|type=="string" and test("^[0-9a-f]{64}$")) and (.reused|type)=="boolean" and
      (.bytes|type=="number" and floor==. and .>0 and .<=33554432) and
      (.records|type=="number" and floor==. and .>=1 and .<=1000) and
      (.source_policy=="previous-kernel-batch-v1" or .source_policy=="previous-kernel-continuation-v1") and
      (.received_at_kst|type=="string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\+09:00$")))
    ' "$attempt/response.json" >/dev/null 2>&1)
    received_at=$(jq -r .received_at_kst "$attempt/response.json")
    [[ $(date -d "$received_at" '+%Y-%m-%dT%H:%M:%S%:z') == "$received_at" ]]
    jq -cS 'del(.reused,.receipt_sha256)' "$attempt/response.json" > "$attempt/receipt.json"
    receipt_sha=$(jq -r .receipt_sha256 "$attempt/response.json")
    [[ $(ack_sha "$attempt/receipt.json") == "$receipt_sha" ]]
    jq -e --slurpfile source "$root/batch-$id/manifest.json" \
      '.bytes==$source[0].bytes and .records==$source[0].records and .source_policy==$source[0].policy' \
      "$attempt/receipt.json" >/dev/null
    printf '%s\n' "$receipt_sha" > "$attempt/receipt.sha256"
    # Recheck the A originals before publishing any claim about this exact source batch.
    ack_source "$root" "$id" "$payload_sha" "$manifest_sha"
    final=$receipts/$id
    if [[ -e $final || -L $final ]]; then
        ack_dir "$final"
        ack_file "$final/receipt.json" 400; ack_file "$final/receipt.sha256" 400
        shopt -s nullglob dotglob
        files=("$final"/*); [[ ${#files[@]} == 2 ]]
        [[ $(stat -c %s "$final/receipt.json") -le 65536 && $(stat -c %s "$final/receipt.sha256") == 65 ]]
        [[ $(ack_sha "$final/receipt.json") == "$receipt_sha" && $(cat "$final/receipt.sha256") == "$receipt_sha" ]]
        cmp -s "$attempt/receipt.json" "$final/receipt.json"
        ack_sync "$final/receipt.json" "$final/receipt.sha256" "$final" "$receipts" "$root"
        ack_report "$id" "$receipt_sha" true
        exit 0
    fi
    rm -- "$attempt/response.json" "$attempt/overflow-count"
    chmod 400 "$attempt/receipt.json" "$attempt/receipt.sha256"
    ack_sync "$attempt/receipt.json" "$attempt/receipt.sha256" "$attempt"
    before_inode=$(stat -c '%d:%i' "$attempt")
    [[ $(stat -c %d "$attempt") == "$(stat -c %d "$receipts")" ]]
    mv -T -n -- "$attempt" "$final"
    [[ ! -e $attempt && ! -L $attempt && $(stat -c '%d:%i' "$final") == "$before_inode" ]]
    ack_sync "$final/receipt.json" "$final/receipt.sha256" "$final" "$receipts" "$root"
    ack_report "$id" "$receipt_sha" false
)
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    umask 077
    PATH=/usr/bin:/bin
    export PATH LC_ALL=C
    [[ $(uname -s) == Linux && $EUID == 0 && $# == 3 ]] || exit 64
    [[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 65
    for value in "$@"; do [[ $value =~ ^[0-9a-f]{64}$ ]] || exit 64; done
    directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
    source_file=$directory/acknowledge-receipt.sh
    [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]]
    (( (8#$(stat -c %a "$directory") & 0022) == 0 ))
    [[ -f $source_file && ! -L $source_file && $(stat -c %u "$source_file") == 0 && $(stat -c %h "$source_file") == 1 ]]
    (( (8#$(stat -c %a "$source_file") & 0022) == 0 ))
    # Source the core in a fresh shell: no inherited functions or test hooks, and errexit stays active.
    exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul /bin/bash -c \
      'set -euo pipefail; source "$1"; shift; acknowledge_core /var/lib/capstone-vector-history "$@"' \
      ack-worker "$source_file" "$@"
fi
