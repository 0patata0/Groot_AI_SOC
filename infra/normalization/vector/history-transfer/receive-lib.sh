#!/bin/bash
# Native operator transaction. Synthetic tests override only these private hooks.
HT_LIB_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
HT_MACHINE_ID=1e143067c98a44ffba6eaa925dc038d7
HT_SOURCE_MACHINE_ID=096e90b6243e438aa8a7b392be754732
HT_STORE_ID=capstone-history-receipts-v1
ht_sync() { /usr/bin/sync -- "$@"; }
ht_rename() { /usr/bin/mv -T -n -- "$1" "$2"; }
ht_sha() { /usr/bin/sha256sum -- "$1" | cut -d ' ' -f1; }
ht_dir() {
    [[ -d $1 && ! -L $1 && $(stat -c %u "$1") == "$(id -u)" && $(stat -c %a "$1") == 700 ]]
}
ht_make_dir() {
    if [[ ! -e $1 && ! -L $1 ]]; then
        mkdir -m 700 -- "$1"
        ht_sync "$1"
        ht_sync "$(dirname -- "$1")"
    fi
    ht_dir "$1"
}
ht_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u "$1") == "$(id -u)" && $(stat -c %h "$1") == 1 ]]
    local mode; mode=$(stat -c %a "$1")
    [[ $mode == 600 || $mode == 400 ]]
}
ht_identity() { stat -c '%d:%i:%s:%y:%z:%u:%g:%a:%h' -- "$1"; }
ht_exact_files() (
    shopt -s nullglob dotglob
    local directory=$1 expected=$2; shift 2
    local files=("$directory"/*)
    [[ ${#files[@]} == "$expected" ]]
    local file
    for file in "$@"; do ht_file "$directory/$file"; done
)
ht_snapshot() {
    local source=$1 target=$2 maximum=$3 expected=$4 before size after
    ht_file "$source"
    before=$(ht_identity "$source"); size=$(stat -c %s "$source")
    (( size > 0 && size <= maximum ))
    # Both the copied body and the post-copy digest read are bounded.
    dd if="$source" of="$target" iflag=nofollow,nonblock,count_bytes count="$maximum" status=none
    [[ $(stat -c %s "$target") == "$size" && $(ht_sha "$target") == "$expected" ]]
    after=$(ht_identity "$source"); [[ $before == "$after" ]]
    [[ $(dd if="$source" iflag=nofollow,nonblock,count_bytes count="$size" status=none | sha256sum | cut -d ' ' -f1) == "$expected" ]]
    [[ $(ht_identity "$source") == "$before" ]]
}
ht_batch_id() {
    local manifest=$1 policy boot until max_records max_bytes
    policy=$(jq -r .policy "$manifest"); boot=$(jq -r .boot_id "$manifest")
    until=$(jq -r .until_epoch_us "$manifest")
    max_records=$(jq -r .selection.max_records "$manifest"); max_bytes=$(jq -r .selection.max_bytes "$manifest")
    case "$policy" in
      previous-kernel-batch-v1)
        printf '%s\n' "$policy" "$boot" "$until" "$max_records" "$max_bytes" ;;
      previous-kernel-continuation-v1)
        printf '%s\n' "$policy" "$(jq -r .parent.batch_id "$manifest")" \
          "$(jq -r .parent.payload_sha256 "$manifest")" "$(jq -r .parent.manifest_sha256 "$manifest")" \
          "$boot" "$until" "$max_records" "$max_bytes" ;;
      *) return 65 ;;
    esac | sha256sum | cut -d ' ' -f1
}
ht_validate() {
    local directory=$1 id=$2 payload_sha=$3 manifest_sha=$4
    local payload=$directory/kernel.jsonl manifest=$directory/manifest.json
    ht_file "$payload"; ht_file "$manifest"
    (( $(stat -c %s "$payload") > 0 && $(stat -c %s "$payload") <= 33554432 ))
    (( $(stat -c %s "$manifest") > 0 && $(stat -c %s "$manifest") <= 65536 ))
    [[ $(ht_sha "$payload") == "$payload_sha" && $(ht_sha "$manifest") == "$manifest_sha" ]]
    # Fixed manifest scalars must not be silently replaced by duplicate paths.
    timeout --kill-after=0.2s 15s jq --stream -ne \
      '[inputs | select(length == 2) | .[0] | tojson] | length == (unique | length)' "$manifest" >/dev/null
    timeout --kill-after=0.2s 15s jq -e --arg id "$id" --arg payload_sha "$payload_sha" \
      -f "$HT_LIB_DIR/validate-manifest.jq" "$manifest" >/dev/null
    [[ $(ht_batch_id "$manifest") == "$id" ]]
    [[ $(stat -c %s "$payload") == "$(jq -r .bytes "$manifest")" ]]
    [[ $(tail -c 1 "$payload" | od -An -tu1 | tr -d ' \n') == 10 ]]
    [[ $(wc -l < "$payload" | tr -d ' ') == "$(jq -r .records "$manifest")" ]]
    # The existing producer metadata validator is pinned by the public wrapper.
    (ulimit -v 262144; timeout --kill-after=0.2s 15s jq -Rn \
      --arg boot "$(jq -r .boot_id "$manifest")" --arg until "$(jq -r .until_epoch_us "$manifest")" \
      --argjson max_records "$(jq -r .selection.max_records "$manifest")" \
      -f "$HT_LIB_DIR/../history/validate-records.jq" "$payload" 2>/dev/null) |
      jq -e --slurpfile manifest "$manifest" '. == $manifest[0].record_metadata' >/dev/null
}
ht_receipt() {
    local directory=$1 id=$2 payload_sha=$3 manifest_sha=$4
    jq -cnS --arg machine "$HT_MACHINE_ID" --arg source_machine "$HT_SOURCE_MACHINE_ID" --arg store "$HT_STORE_ID" --arg id "$id" \
      --arg payload_sha "$payload_sha" --arg manifest_sha "$manifest_sha" \
      --arg at "$(date '+%Y-%m-%dT%H:%M:%S%:z')" --slurpfile manifest "$directory/manifest.json" \
      '{schema_version:"1",stage:"remote_file_preserved",receiver_machine_id:$machine,source_machine_id:$source_machine,store_id:$store,
        batch_id:$id,payload_sha256:$payload_sha,manifest_sha256:$manifest_sha,
        bytes:$manifest[0].bytes,records:$manifest[0].records,source_policy:$manifest[0].policy,
        received_at_kst:$at}' > "$directory/receipt.json"
    ht_sha "$directory/receipt.json" > "$directory/receipt.sha256"
}
ht_validate_receipt() {
    local directory=$1 id=$2 payload_sha=$3 manifest_sha=$4 receipt_sha
    ht_exact_files "$directory" 4 kernel.jsonl manifest.json receipt.json receipt.sha256
    local file
    for file in kernel.jsonl manifest.json receipt.json receipt.sha256; do [[ $(stat -c %a "$directory/$file") == 400 ]]; done
    (( $(stat -c %s "$directory/receipt.json") <= 2048 ))
    [[ $(stat -c %s "$directory/receipt.sha256") == 65 ]]
    receipt_sha=$(cat "$directory/receipt.sha256"); [[ $receipt_sha =~ ^[a-f0-9]{64}$ ]]
    [[ $(ht_sha "$directory/receipt.json") == "$receipt_sha" ]]
    jq -e --arg id "$id" --arg payload "$payload_sha" --arg manifest "$manifest_sha" \
      --arg machine "$HT_MACHINE_ID" --arg source_machine "$HT_SOURCE_MACHINE_ID" --arg store "$HT_STORE_ID" --slurpfile source "$directory/manifest.json" \
      'keys==["batch_id","bytes","manifest_sha256","payload_sha256","received_at_kst","receiver_machine_id","records","schema_version","source_machine_id","source_policy","stage","store_id"] and
       .schema_version=="1" and .stage=="remote_file_preserved" and .batch_id==$id and
       .receiver_machine_id==$machine and .source_machine_id==$source_machine and .store_id==$store and .payload_sha256==$payload and
       .manifest_sha256==$manifest and .bytes==$source[0].bytes and .records==$source[0].records and
       .source_policy==$source[0].policy and
       (.received_at_kst | type=="string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\+09:00$"))' \
      "$directory/receipt.json" >/dev/null
}
ht_sync_final() {
    local directory=$1
    ht_sync "$directory/kernel.jsonl"
    ht_sync "$directory/manifest.json"
    ht_sync "$directory/receipt.json"
    ht_sync "$directory/receipt.sha256"
    ht_sync "$directory"
    ht_sync "$(dirname -- "$directory")"
}
ht_report() {
    jq -cS --arg receipt_sha "$(cat "$1/receipt.sha256")" --argjson reused "$2" \
      '{schema_version,stage,receiver_machine_id,source_machine_id,store_id,batch_id,
        payload_sha256,manifest_sha256,bytes,records,source_policy,received_at_kst} +
       {receipt_sha256:$receipt_sha,reused:$reused}' "$1/receipt.json"
}
ht_receive() {
    local root=$1 id=$2 payload_sha=$3 manifest_sha=$4
    [[ $# == 4 && $id =~ ^[a-f0-9]{64}$ && $payload_sha =~ ^[a-f0-9]{64}$ && $manifest_sha =~ ^[a-f0-9]{64}$ ]]
    ht_make_dir "$root"; ht_make_dir "$root/incoming"; ht_make_dir "$root/batches"; ht_make_dir "$root/partial"
    if [[ ! -e $root/.lock && ! -L $root/.lock ]]; then (set -C; : > "$root/.lock"); fi
    ht_file "$root/.lock"; [[ $(stat -c %a "$root/.lock") == 600 ]]
    exec 9<>"$root/.lock"; flock -n 9
    local final=$root/batches/$id
    local incoming=$root/incoming/$id/$payload_sha-$manifest_sha
    if [[ -e $final || -L $final ]]; then
        ht_dir "$final"
        ht_validate "$final" "$id" "$payload_sha" "$manifest_sha"
        ht_validate_receipt "$final" "$id" "$payload_sha" "$manifest_sha"
        ht_sync_final "$final"
        ht_report "$final" true
        return 0
    fi
    ht_dir "$root/incoming/$id"; ht_dir "$incoming"
    ht_exact_files "$incoming" 2 kernel.jsonl manifest.json
    local available; available=$(df --output=avail -B1 "$root" | tail -n 1 | tr -d ' ')
    [[ $available =~ ^[0-9]+$ ]]; (( available >= 33554432 + 8388608 ))
    local attempt before_inode
    attempt=$(mktemp -d "$root/partial/$id.XXXXXX")
    ht_snapshot "$incoming/kernel.jsonl" "$attempt/kernel.jsonl" 33554432 "$payload_sha"
    ht_snapshot "$incoming/manifest.json" "$attempt/manifest.json" 65536 "$manifest_sha"
    ht_validate "$attempt" "$id" "$payload_sha" "$manifest_sha"
    ht_receipt "$attempt" "$id" "$payload_sha" "$manifest_sha"
    chmod 400 "$attempt/kernel.jsonl" "$attempt/manifest.json" "$attempt/receipt.json" "$attempt/receipt.sha256"
    ht_validate_receipt "$attempt" "$id" "$payload_sha" "$manifest_sha"
    ht_sync_final "$attempt"
    before_inode=$(stat -c '%d:%i' "$attempt")
    [[ $(stat -c %d "$attempt") == "$(stat -c %d "$root/batches")" ]]
    ht_rename "$attempt" "$final"
    [[ ! -e $attempt && ! -L $attempt && $(stat -c '%d:%i' "$final") == "$before_inode" ]]
    ht_sync "$root/partial"
    ht_sync_final "$final"
    ht_report "$final" false
}
