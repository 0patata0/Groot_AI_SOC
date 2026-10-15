#!/bin/bash
# Candidate Linux/root library: copy/restore only. The installing caller owns
# fixed paths, shared vector.lock, live writer-gate proof and receipt commits.
# No SSH, timer, source deletion or checkpoint access. No public mutation CLI.
lc_sha() { local v; v=$(sha256sum -- "$1") || return 1; printf '%s\n' "${v%% *}"; }
lc_identity() { stat -Lc '%d:%i:%s:%u:%g:%a:%h:%y:%z' -- "$1"; }
lc_ancestors() {
    local p=$1
    [[ $p == /* && $p != *'/../'* && $p != *'/./'* && $p != */.. && $p != */. && $p != *$'\n'* ]] || return 1
    while [[ $p != / ]]; do [[ -d $p && ! -L $p ]] || return 1; p=${p%/*}; [[ -n $p ]] || p=/; done
}
lc_private_dir() {
    local p=$1 mode
    [[ $p == /var/backups/capstone-raw-retention || $p == /var/backups/capstone-raw-retention/* ||
       $p =~ ^/var/tmp/capstone-lifecycle-native\.[A-Za-z0-9]{8}(/.*)?$ ]] || return 1
    lc_ancestors "$p" || return 1
    [[ $(stat -c '%u:%g:%a' -- "$p") == 0:0:700 ]] || return 1
    while [[ $p != / ]]; do
        [[ $(stat -c %u -- "$p") == 0 ]] || return 1
        mode=$(stat -c %a -- "$p") || return 1
        if [[ $p != /var/tmp ]]; then (( (8#$mode & 0022)==0 )) || return 1; fi
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
lc_file() {
    [[ -f $1 && ! -L $1 && $(stat -c '%u:%g:%a:%h' -- "$1") == "0:0:$2:1" && $(stat -c %s -- "$1") -le $3 ]]
}
lc_json() {
    lc_file "$1" 400 16384 && jq -se 'length==1 and (.[0]|type=="object")' "$1" >/dev/null &&
      cmp -s -- "$1" <(jq -cS . "$1")
}
lc_source_meta() {
    jq -e '
      def n: type=="number" and floor==. and .>=0 and .<=9007199254740991;
      keys==["basename","bytes","device","gid","inode","links","mode","sha1","sha256","stable","uid"] and
      (.basename|test("^generation-[0-9]{10}\\.jsonl$")) and all([.bytes,.device,.inode,.links][];n) and
      .bytes<=2147483648 and .inode>0 and .uid==0 and .gid==0 and .mode=="0400" and
      .links==1 and .stable==true and
      (.sha256|test("^[a-f0-9]{64}$")) and (.sha1|test("^[a-f0-9]{40}$"))' "$1" >/dev/null
}
lc_manifest() {
    lc_json "$1" || return 1
    jq -e '
      def n: type=="number" and floor==. and .>=0 and .<=9007199254740991;
      def h: type=="string" and test("^[a-f0-9]{64}$");
      keys==["compression","created_at_epoch","gzip_bytes","gzip_sha256","policy","schema_version","source"] and
      .schema_version==1 and .policy=="capstone-sealed-raw-bundle-v1" and .compression=="gzip" and
      (.created_at_epoch|n) and .created_at_epoch>0 and (.gzip_sha256|h) and
      (.gzip_bytes|n) and .gzip_bytes>0 and .gzip_bytes<=2155872256 and
      (.source|keys==["basename","bytes","device","inode","sha256"] and
       (.basename|type=="string" and test("^generation-[0-9]{10}\\.jsonl$")) and
       all([.bytes,.device,.inode][];n) and .bytes<=2147483648 and .inode>0 and (.sha256|h))' "$1" >/dev/null
}
lc_verify_bundle() (
    set -euo pipefail
    [[ $# == 2 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
    local bundle=$1 work_parent=$2 work='' manifest_before payload_before bytes digest compressed size limit
    lc_private_dir "$bundle" && lc_private_dir "$work_parent" || exit 65
    # Exact two-file bundle; no nested trees, symlinks or hidden additions.
    [[ $(find "$bundle" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort) == $'manifest.json\npayload.jsonl.gz' ]] || exit 65
    lc_manifest "$bundle/manifest.json" && lc_file "$bundle/payload.jsonl.gz" 400 2155872256 || exit 65
    manifest_before=$(lc_identity "$bundle/manifest.json") || exit 65; payload_before=$(lc_identity "$bundle/payload.jsonl.gz") || exit 65
    digest=$(jq -r .source.sha256 "$bundle/manifest.json") || exit 65; bytes=$(jq -r .source.bytes "$bundle/manifest.json") || exit 65
    compressed=$(lc_sha "$bundle/payload.jsonl.gz") || exit 65; size=$(stat -c %s "$bundle/payload.jsonl.gz") || exit 65
    [[ $compressed == "$(jq -r .gzip_sha256 "$bundle/manifest.json")" && $size == "$(jq -r .gzip_bytes "$bundle/manifest.json")" ]] || exit 65
    work=$(mktemp -d "$work_parent/restore.XXXXXXXX") || exit 65
    trap '[[ -z $work ]] || { rm -f -- "$work/payload.jsonl"; rmdir -- "$work"; }' EXIT
    chmod 700 "$work" || exit 65
    # A gzip member has no extraction pathname. Bound decompression to the
    # declared size (+ one block), wall time and CPU before verifying bytes/SHA.
    limit=$(( (bytes+1023)/1024+1 ))
    (ulimit -f "$limit" || exit 65; ulimit -t 120 || exit 65; timeout --signal=TERM --kill-after=2s 120s gzip -dc -- "$bundle/payload.jsonl.gz" > "$work/payload.jsonl") || exit 65
    [[ $(stat -c %s "$work/payload.jsonl") == "$bytes" && $(lc_sha "$work/payload.jsonl") == "$digest" ]] || exit 65
    [[ $(lc_identity "$bundle/manifest.json") == "$manifest_before" && $(lc_identity "$bundle/payload.jsonl.gz") == "$payload_before" ]] || exit 65
    lc_manifest "$bundle/manifest.json" && lc_file "$bundle/payload.jsonl.gz" 400 2155872256 || exit 65
    sync -- "$bundle/manifest.json" "$bundle/payload.jsonl.gz" "$bundle" || exit 65
    jq -ncS --slurpfile m "$bundle/manifest.json" --arg sha "$(lc_sha "$bundle/manifest.json")" '
      $m[0] as $m|{schema_version:1,policy:"capstone-sealed-raw-archive-v1",source:$m.source,
       gzip_sha256:$m.gzip_sha256,gzip_bytes:$m.gzip_bytes,manifest_sha256:$sha,
       local_restore_sha256:$m.source.sha256,local_restore_bytes:$m.source.bytes}'
)
lc_pack() (
    set -euo pipefail
    [[ $# == 4 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
    local source=$1 metadata=$2 bundle=$3 work_parent=$4 expected before after fd compressed size meta_before meta_sha metadata_json
    lc_json "$metadata" && lc_source_meta "$metadata" || exit 65
    meta_before=$(lc_identity "$metadata") || exit 65
    meta_sha=$(lc_sha "$metadata") || exit 65
    metadata_json=$(cat -- "$metadata") || exit 65
    [[ $(printf '%s\n' "$metadata_json" | sha256sum | cut -d ' ' -f1) == "$meta_sha" ]] || exit 65
    lc_private_dir "${bundle%/*}" && lc_private_dir "$work_parent" || exit 65
    [[ ${bundle##*/} =~ ^[a-z0-9][a-z0-9-]{1,120}$ && ! -e $bundle && ! -L $bundle ]] || exit 65
    [[ $source == /home/groot_a/capstone/secstack/logs/suricata/capstone-managed/generation-??????????.jsonl ||
       $source == /home/groot_a/capstone/secstack/logs/modsec/capstone-managed/generation-??????????.jsonl ||
       $source =~ ^/var/tmp/capstone-lifecycle-native\.[A-Za-z0-9]{8}/raw/generation-[0-9]{10}\.jsonl$ ]] || exit 65
    lc_ancestors "${source%/*}" || exit 65
    [[ -f $source && ! -L $source && ${source##*/} == "$(jq -r .basename <<< "$metadata_json")" ]] || exit 65
    expected=$(jq -r '[.device,.inode,.bytes,.uid,.gid,"400",.links]|map(tostring)|join(":")' <<< "$metadata_json") || exit 65
    [[ $(stat -c '%d:%i:%s:%u:%g:%a:%h' "$source") == "$expected" ]] || exit 65
    before=$(lc_identity "$source") || exit 65
    exec {fd}<"$source" || exit 65
    [[ $(lc_identity "/proc/self/fd/$fd") == "$before" && ! -L $source ]] || exit 65
    [[ $(lc_sha "/proc/self/fd/$fd") == "$(jq -r .sha256 <<< "$metadata_json")" ]] || exit 65
    [[ $(sha1sum "/proc/self/fd/$fd" | cut -d ' ' -f1) == "$(jq -r .sha1 <<< "$metadata_json")" ]] || exit 65
    umask 077
    mkdir -m 700 -- "$bundle" || exit 65 # exclusive; a partial attempt is not reused
    (ulimit -f 2105344 || exit 65; ulimit -t 120 || exit 65; timeout --signal=TERM --kill-after=2s 120s gzip -n -c <&$fd > "$bundle/payload.jsonl.gz") || exit 65
    after=$(lc_identity "$source") || exit 65
    [[ ! -L $source && $before == "$after" && $(lc_identity "/proc/self/fd/$fd") == "$before" ]] || exit 65
    lc_json "$metadata" && [[ $(lc_identity "$metadata") == "$meta_before" && $(lc_sha "$metadata") == "$meta_sha" ]] || exit 65
    exec {fd}<&- || exit 65
    chmod 400 "$bundle/payload.jsonl.gz" || exit 65
    compressed=$(lc_sha "$bundle/payload.jsonl.gz") || exit 65; size=$(stat -c %s "$bundle/payload.jsonl.gz") || exit 65
    jq -ncS --argjson s "$metadata_json" --arg sha "$compressed" --argjson bytes "$size" --argjson now "$(date +%s)" '
      {schema_version:1,policy:"capstone-sealed-raw-bundle-v1",compression:"gzip",created_at_epoch:$now,
       source:($s|{basename,bytes,device,inode,sha256}),gzip_sha256:$sha,gzip_bytes:$bytes}' > "$bundle/manifest.json" || exit 65
    chmod 400 "$bundle/manifest.json" || exit 65
    sync -- "$bundle/payload.jsonl.gz" "$bundle/manifest.json" "$bundle" "${bundle%/*}" || exit 65
    lc_verify_bundle "$bundle" "$work_parent" || exit 65
)
lc_b_receipt() (
    set -euo pipefail
    [[ $# == 2 && $EUID == 0 && $OSTYPE == linux* && $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 64
    local result begin end
    begin=$(date +%s) || exit 65
    result=$(lc_verify_bundle "$1" "$2") || exit 65
    end=$(date +%s) || exit 65
    (( end>=begin )) || exit 65
    jq -ncS --argjson result "$result" --argjson begin "$begin" --argjson end "$end" '
      {schema_version:1,policy:"capstone-sealed-raw-receipt-v1",receiver_machine_id:"1e143067c98a44ffba6eaa925dc038d7",
       stage:"remote_preserved_and_restore_verified",manifest_sha256:$result.manifest_sha256,gzip_sha256:$result.gzip_sha256,
       gzip_bytes:$result.gzip_bytes,restored_sha256:$result.local_restore_sha256,restored_bytes:$result.local_restore_bytes,
       received_at_epoch:$begin,restore_verified_at_epoch:$end}'
)
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    printf '{"status":"refused","reason":"library_only_not_installed","delete_authorized":false}\n'
    exit 78
fi
