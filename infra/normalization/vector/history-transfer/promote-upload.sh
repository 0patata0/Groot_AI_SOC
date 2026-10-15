#!/bin/bash
# Operator-only upload promotion. This is neither a daemon nor an SSH/MCP endpoint.
# Tests source these functions and use private synthetic paths; the executable
# entry point accepts only three hashes and always uses the fixed B paths.

promote_user_dir() {
    [[ -d $1 && ! -L $1 && $(stat -c '%u:%a' -- "$1") == 1000:700 ]]
}
promote_user_file() {
    [[ -f $1 && ! -L $1 && $(stat -c '%u:%h' -- "$1") == 1000:1 ]]
    local mode; mode=$(stat -c %a -- "$1")
    [[ $mode == 600 || $mode == 400 ]]
}
promote_user_files() (
    shopt -s nullglob dotglob
    local files=(./*)
    [[ ${#files[@]} == 2 ]]
    promote_user_file ./kernel.jsonl
    promote_user_file ./manifest.json
)
promote_copy() {
    # Test-only fault substitution is possible after sourcing, never in the
    # clean-environment public entry. No unbounded cp from a user-owned file.
    /usr/bin/dd if="$1" of="$2" iflag=nofollow,nonblock,count_bytes count="$3" status=none
}
promote_snapshot() {
    local source=$1 target=$2 maximum=$3 expected=$4 before size
    promote_user_file "$source"
    before=$(ht_identity "$source"); size=$(stat -c %s -- "$source")
    (( size > 0 && size <= maximum ))
    promote_copy "$source" "$target" "$maximum"
    [[ $(stat -c %s -- "$target") == "$size" && $(ht_sha "$target") == "$expected" ]]
    promote_user_file "$source"
    [[ $(ht_identity "$source") == "$before" ]]
}
promote_snapshot_pair() (
    local source=$1 target=$2 payload_sha=$3 manifest_sha=$4 identity
    promote_user_dir "$source"
    identity=$(ht_identity "$source")
    # Pin the actual directory as cwd before opening fixed basenames. Swapping
    # an intermediate upload pathname cannot redirect a later file open.
    cd -P -- "$source"
    [[ $(ht_identity .) == "$identity" ]]
    promote_user_files
    promote_snapshot ./kernel.jsonl "$target/kernel.jsonl" 33554432 "$payload_sha"
    promote_snapshot ./manifest.json "$target/manifest.json" 65536 "$manifest_sha"
    promote_user_files
    [[ $(ht_identity .) == "$identity" && $(ht_identity "$source") == "$identity" ]]
)
promote_validate_incoming() {
    local destination=$1 id=$2 payload_sha=$3 manifest_sha=$4
    ht_dir "$destination"
    ht_exact_files "$destination" 2 kernel.jsonl manifest.json
    [[ $(stat -c %a -- "$destination/kernel.jsonl") == 400 &&
       $(stat -c %a -- "$destination/manifest.json") == 400 ]]
    ht_validate "$destination" "$id" "$payload_sha" "$manifest_sha"
}
promote_sync_incoming() {
    ht_sync "$1/kernel.jsonl"
    ht_sync "$1/manifest.json"
    ht_sync "$1"
    ht_sync "$(dirname -- "$1")"
}
promote_report() {
    jq -cnS --arg id "$1" --arg payload "$2" --arg manifest "$3" --argjson reused "$4" \
      '{status:"promoted_input",batch_id:$id,payload_sha256:$payload,
        manifest_sha256:$manifest,reused:$reused,remote_receipt:false}'
}
promote_transaction() (
    set -euo pipefail
    umask 077
    export LC_ALL=C TZ=Asia/Seoul
    [[ $EUID == 0 && $# == 5 ]]
    local root=$1 upload_root=$2 id=$3 payload_sha=$4 manifest_sha=$5
    [[ $root == /* && $upload_root == /* && $id =~ ^[a-f0-9]{64}$ &&
       $payload_sha =~ ^[a-f0-9]{64}$ && $manifest_sha =~ ^[a-f0-9]{64}$ ]]
    local attempt='' attempt_inode='' destination source available before_inode
    # Never remove user uploads or an existing incoming/final directory.
    cleanup() {
        local status=$?
        trap - EXIT
        if [[ -n $attempt && -e $attempt ]]; then
            if [[ -d $attempt && ! -L $attempt &&
                  $(stat -c '%u:%a' -- "$attempt") == 0:700 &&
                  $(stat -c '%d:%i' -- "$attempt") == "$attempt_inode" ]]; then
                rm -f -- "$attempt/kernel.jsonl" "$attempt/manifest.json" || status=73
                rmdir -- "$attempt" || status=73
                ht_sync "$root/partial" || status=73
            else
                status=73
            fi
        fi
        exit "$status"
    }
    trap cleanup EXIT
    ht_make_dir "$root"
    ht_make_dir "$root/incoming"
    ht_make_dir "$root/partial"
    if [[ ! -e $root/.lock && ! -L $root/.lock ]]; then (set -C; : > "$root/.lock"); fi
    ht_file "$root/.lock"; [[ $(stat -c %a -- "$root/.lock") == 600 ]]
    exec 9<>"$root/.lock"
    flock -n 9
    ht_make_dir "$root/incoming/$id"
    destination=$root/incoming/$id/$payload_sha-$manifest_sha
    if [[ -e $destination || -L $destination ]]; then
        promote_validate_incoming "$destination" "$id" "$payload_sha" "$manifest_sha"
        promote_sync_incoming "$destination"
        promote_report "$id" "$payload_sha" "$manifest_sha" true
        exit 0
    fi
    promote_user_dir "$upload_root"
    promote_user_dir "$upload_root/$id"
    source=$upload_root/$id/$payload_sha-$manifest_sha
    promote_user_dir "$source"
    available=$(df --output=avail -B1 "$root" | tail -n 1 | tr -d ' ')
    [[ $available =~ ^[0-9]+$ ]]; (( available >= 33554432 + 65536 + 8388608 ))
    attempt=$(mktemp -d "$root/partial/promote-$id.XXXXXX")
    attempt_inode=$(stat -c '%d:%i' -- "$attempt")
    promote_snapshot_pair "$source" "$attempt" "$payload_sha" "$manifest_sha"
    ht_exact_files "$attempt" 2 kernel.jsonl manifest.json
    ht_validate "$attempt" "$id" "$payload_sha" "$manifest_sha"
    chmod 400 -- "$attempt/kernel.jsonl" "$attempt/manifest.json"
    promote_validate_incoming "$attempt" "$id" "$payload_sha" "$manifest_sha"
    promote_sync_incoming "$attempt"
    before_inode=$(stat -c '%d:%i' -- "$attempt")
    [[ $(stat -c %d -- "$attempt") == "$(stat -c %d -- "$root/incoming/$id")" ]]
    ht_rename "$attempt" "$destination"
    [[ ! -e $attempt && ! -L $attempt && $(stat -c '%d:%i' -- "$destination") == "$before_inode" ]]
    ht_sync "$root/partial"
    promote_sync_incoming "$destination"
    promote_report "$id" "$payload_sha" "$manifest_sha" false
)

promote_main() {
    set -euo pipefail
    umask 077
    PATH=/usr/bin:/bin
    export PATH LC_ALL=C TZ=Asia/Seoul
    [[ $(uname -s) == Linux && $EUID == 0 && $# == 3 ]] || exit 64
    [[ $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 65
    [[ $(id -u groot_b) == 1000 ]] || exit 65
    local value directory parent source status=0
    for value in "$@"; do [[ $value =~ ^[a-f0-9]{64}$ ]] || exit 64; done
    directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
    for parent in "$directory" "$directory/../history"; do
        [[ -d $parent && ! -L $parent && $(stat -c %u -- "$parent") == 0 ]] || exit 65
        (( (8#$(stat -c %a -- "$parent") & 0022) == 0 )) || exit 65
    done
    for source in "$directory/promote-upload.sh" "$directory/receive-lib.sh" \
      "$directory/validate-manifest.jq" "$directory/../history/validate-records.jq"; do
        [[ -f $source && ! -L $source && $(stat -c '%u:%h' -- "$source") == 0:1 ]] || exit 65
        (( (8#$(stat -c %a -- "$source") & 0022) == 0 )) || exit 65
    done
    [[ $(sha256sum "$directory/../history/validate-records.jq" | cut -d ' ' -f1) == 2470fab15dfde40540d60a3e47f4de8a6f5520f46acb231d1067895c770ffaa9 ]] || exit 65
    # Fresh process: inherited functions/environment cannot become test hooks,
    # and all parser diagnostics are replaced with one content-free rejection.
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul /bin/bash -c \
      'set -euo pipefail; source "$1"; source "$2"; shift 2; promote_transaction "$@"' \
      history-promoter "$directory/receive-lib.sh" "$directory/promote-upload.sh" \
      /var/lib/capstone-history-receipts /var/tmp/capstone-history-upload-20261014 "$@" \
      2>/dev/null || status=$?
    if (( status != 0 )); then
        printf '{"status":"rejected","stage":"not_promoted"}\n' >&2
        exit "$status"
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then promote_main "$@"; fi
