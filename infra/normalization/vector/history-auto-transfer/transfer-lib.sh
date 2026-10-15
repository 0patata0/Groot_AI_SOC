#!/bin/bash
# Internal helpers. Public wrappers fix every path; fixtures source this library.
HAT_LIB=/usr/local/lib/capstone-history-auto-transfer
HAT_ROOT=/var/lib/capstone-history-auto-transfer
HAT_RECEIPTS=/var/lib/capstone-history-receipts
HAT_RECEIVER=/opt/capstone-automation/project/infra/normalization/vector/history-transfer
HAT_CONFIG=/etc/capstone-history-transfer
HAT_QUOTA=1073741824
hat_sha() { sha256sum -- "$1" | cut -d ' ' -f1; }
hat_dir() {
    [[ -d $1 && ! -L $1 && $(stat -c '%u:%g:%a' -- "$1") == 0:0:700 ]]
}
hat_file() {
    local path=$1 mode=$2 limit=$3
    [[ -f $path && ! -L $path && $(stat -c '%u:%g:%a:%h' -- "$path") == "0:0:$mode:1" ]] || return 65
    (( $(stat -c %s -- "$path") <= limit ))
}
hat_parents() {
    local path=$1
    while :; do
        [[ -d $path && ! -L $path && $(stat -c %u -- "$path") == 0 ]] || return 65
        (( (8#$(stat -c %a -- "$path") & 0022) == 0 )) || return 65
        [[ $path != / ]] || break
        path=$(dirname -- "$path")
    done
}
hat_dependencies() {
    local file digest mode
    hat_parents "$HAT_RECEIVER" || return 65
    hat_parents "$HAT_RECEIVER/../history" || return 65
    while read -r digest mode file; do
        hat_file "$HAT_RECEIVER/$file" "$mode" 131072 || return 65
        [[ $(hat_sha "$HAT_RECEIVER/$file") == "$digest" ]] || return 65
    done <<'PINS'
e024ec0d28490f6eba57a83809eafc97c08437883ef54cd9701381471dd40152 644 receive-batch.sh
28ab8e9f50fe478b11b6b69b16a100d1538d9d3cab1bdf059b5fd7a3aaa072e3 644 receive-run.sh
d6056aa404508352abda247f09e3242615fe8cfcdb16a9333c1863c8d4dd884e 644 receive-lib.sh
84583156c2389c1fbc213b614c05e2f51e5d8979c6488b5691be68d2685c2ae3 644 validate-manifest.jq
2470fab15dfde40540d60a3e47f4de8a6f5520f46acb231d1067895c770ffaa9 600 ../history/validate-records.jq
PINS
    [[ $(hat_sha /usr/bin/rsync) == 6b4fb867cb49d0332b72b234656311c807ab68b0537905fda7a3e7481a139f16 ]] || return 65
    hat_parents "$HAT_CONFIG" || return 65
    hat_dir "$HAT_CONFIG" || return 65
    hat_file "$HAT_CONFIG/id_ed25519" 600 8192 || return 65
    hat_file "$HAT_CONFIG/known_hosts" 600 1024 || return 65
    [[ $(wc -l < "$HAT_CONFIG/known_hosts") == 1 ]] || return 65
    grep -Eq '^capstone-history-source-a ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' "$HAT_CONFIG/known_hosts" || return 65
}
hat_capacity() {
    local reserve=$1 listing entries bytes available
    [[ $reserve =~ ^[0-9]+$ ]] || return 65
    listing=$(find "$HAT_ROOT" "$HAT_RECEIPTS" -xdev -printf '%y %s %U\n' | head -n 8193) || return 65
    entries=$(printf '%s\n' "$listing" | wc -l)
    (( entries <= 8192 )) || return 65
    printf '%s\n' "$listing" | awk 'NF!=3 || $1!~/^[df]$/ || $2!~/^[0-9]+$/ || $3!=0 {exit 1}' || return 65
    bytes=$(printf '%s\n' "$listing" | awk '{n+=$2} END{printf "%.0f",n}')
    (( bytes + reserve <= HAT_QUOTA )) || return 65
    available=$(df --output=avail -B1 "$HAT_RECEIPTS" | tail -n 1 | tr -d ' ')
    [[ $available =~ ^[0-9]+$ ]] || return 65
    (( available >= reserve + 41943040 ))
}
hat_manifest() {
    local path=$1 id=$2 payload
    [[ $id =~ ^[a-f0-9]{64}$ ]] || return 65
    hat_file "$path" 600 65536 || return 65
    (( $(stat -c %s "$path") > 0 )) || return 65
    jq -se 'length==1 and (.[0]|type=="object")' "$path" >/dev/null 2>&1 || return 65
    jq --stream -ne '[inputs|select(length==2)|.[0]|tojson]|length==(unique|length)' "$path" >/dev/null 2>&1 || return 65
    payload=$(jq -er '.sha256|select(type=="string" and test("^[a-f0-9]{64}$"))' "$path" 2>/dev/null) || return 65
    jq -e --arg id "$id" --arg payload_sha "$payload" -f "$HAT_RECEIVER/validate-manifest.jq" "$path" >/dev/null 2>&1 || return 65
    # Same pinned producer ID derivation as the receiver; no cursor is exported.
    local derived
    derived=$(/bin/bash -c 'set -euo pipefail; source "$1/receive-lib.sh"; ht_batch_id "$2"' history-id "$HAT_RECEIVER" "$path" 2>/dev/null) || return 65
    [[ $derived == "$id" ]] || return 65
}
hat_rsync() {
    /usr/bin/timeout --signal=TERM --kill-after=2s 65s /usr/bin/rsync \
      --recursive --perms --chmod=D700,F600 --no-owner --no-group \
      --no-links --safe-links --no-devices --no-specials --fsync \
      --timeout=30 --bwlimit=8192 --quiet \
      -e "/bin/bash $HAT_LIB/ssh-b.sh" "$@" >/dev/null 2>&1
}
hat_fetch_manifests() {
    hat_rsync --max-size=65536 --include='/batch-*/' --include='/batch-*/manifest.json' \
      --exclude='*' 10.200.10.1:./ "$1/"
}
hat_fetch_batch() {
    local id=$1 destination=$2 maximum=$3
    [[ $id =~ ^[a-f0-9]{64}$ && $maximum =~ ^[0-9]+$ ]] || return 65
    (( maximum >= 65536 && maximum <= 33554432 )) || return 65
    hat_rsync --max-size="$maximum" --include='/kernel.jsonl' --include='/manifest.json' \
      --exclude='*' "10.200.10.1:./batch-$id/" "$destination/"
}
hat_promote() {
    # Called only by a fresh set-e worker. Same receiver .lock and same filesystem.
    local source=$1 id=$2 payload_sha=$3 manifest_sha=$4
    source "$HAT_RECEIVER/receive-lib.sh"
    ht_make_dir "$HAT_RECEIPTS/incoming"
    ht_make_dir "$HAT_RECEIPTS/partial"
    ht_file "$HAT_RECEIPTS/.lock"
    [[ $(stat -c %a "$HAT_RECEIPTS/.lock") == 600 ]]
    exec 9<>"$HAT_RECEIPTS/.lock"; flock -n 9
    ht_dir "$source"; ht_exact_files "$source" 2 kernel.jsonl manifest.json
    ht_make_dir "$HAT_RECEIPTS/incoming/$id"
    local target=$HAT_RECEIPTS/incoming/$id/$payload_sha-$manifest_sha partial inode
    if [[ -e $target || -L $target ]]; then
        ht_dir "$target"; ht_exact_files "$target" 2 kernel.jsonl manifest.json
        ht_validate "$target" "$id" "$payload_sha" "$manifest_sha"
        printf 'existing\n'; return 0
    fi
    partial=$(mktemp -d "$HAT_RECEIPTS/incoming/$id/.pull-XXXXXXXX")
    ht_snapshot "$source/kernel.jsonl" "$partial/kernel.jsonl" 33554432 "$payload_sha"
    ht_snapshot "$source/manifest.json" "$partial/manifest.json" 65536 "$manifest_sha"
    ht_validate "$partial" "$id" "$payload_sha" "$manifest_sha"
    chmod 400 "$partial/kernel.jsonl" "$partial/manifest.json"
    ht_sync "$partial/kernel.jsonl" "$partial/manifest.json" "$partial" "$(dirname "$partial")"
    inode=$(stat -c '%d:%i' "$partial")
    mv -T -n -- "$partial" "$target"
    [[ ! -e $partial && ! -L $partial && $(stat -c '%d:%i' "$target") == "$inode" ]]
    ht_sync "$(dirname "$target")"
    printf 'created\n'
}
hat_receipt() {
    local path=$1 id=$2 payload=$3 manifest=$4
    hat_file "$path" 600 4096 || return 65
    jq -se --arg id "$id" --arg payload "$payload" --arg manifest "$manifest" '
      length==1 and (.[0] |
      keys==["batch_id","bytes","manifest_sha256","payload_sha256","receipt_sha256","received_at_kst","receiver_machine_id","records","reused","schema_version","source_machine_id","source_policy","stage","store_id"] and
      .schema_version=="1" and .stage=="remote_file_preserved" and
      .receiver_machine_id=="1e143067c98a44ffba6eaa925dc038d7" and
      .source_machine_id=="096e90b6243e438aa8a7b392be754732" and .store_id=="capstone-history-receipts-v1" and
      .batch_id==$id and .payload_sha256==$payload and .manifest_sha256==$manifest and
      (.receipt_sha256|type=="string" and test("^[a-f0-9]{64}$")) and (.reused|type=="boolean"))' "$path" >/dev/null 2>&1 || return 65
    local fixed=$HAT_RECEIPTS/batches/$id/receipt.json
    [[ $(hat_sha "$fixed") == "$(jq -r .receipt_sha256 "$path")" ]] || return 65
    jq -e --slurpfile fixed "$fixed" 'del(.receipt_sha256,.reused)==$fixed[0]' "$path" >/dev/null 2>&1
}
hat_publish() {
    local source=$1 destination=$2
    if [[ -e $destination || -L $destination ]]; then hat_file "$destination" 600 262144 || return 65; fi
    [[ $(stat -c %d "$source") == "$(stat -c %d "$HAT_ROOT")" ]] || return 65
    chmod 600 "$source" || return 65
    sync -- "$source" || return 65
    mv -T -- "$source" "$destination" || return 65
    sync -- "$HAT_ROOT"
}
hat_cleanup_work() {
    local path=$1 inventory
    [[ $path == "$HAT_ROOT"/work/run-* ]] || return 65
    hat_dir "$path" || return 65
    inventory=$(find "$path" -xdev -printf '%y %U %G %m %n\n' | head -n 2049) || return 65
    (( $(printf '%s\n' "$inventory" | wc -l) <= 2048 )) || return 65
    printf '%s\n' "$inventory" | awk '
      NF!=5 || $2!=0 || $3!=0 {exit 1}
      $1=="d" {if($4!=700)exit 1;next}
      $1=="f" {if($4!=600||$5!=1)exit 1;next} {exit 1}' || return 65
    # This is our root-only attempt tree, never an A source or B receipt tree.
    rm -rf --one-file-system -- "$path" || return 65
    sync -- "$HAT_ROOT/work"
}
