#!/bin/bash
# Internal fixed-schema state helpers. The coordinator MUST hold its shared
# operation lock for prepare/init/CAS. read_twice is intentionally lock-free.
# No raw source, writer, reader checkpoint, service or container is modified.
RAW_STATE_LIBRARY_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
RAW_STATE_MAX_BYTES=16384 RAW_STATE_MAX_HISTORY=1024 RAW_STATE_MAX_STAGING=32

_rs_fail() { printf '{"status":"refused","reason":"%s"}\n' "$1"; return 65; }
_rs_engine() { [[ $1 == suricata || $1 == modsecurity ]]; }
_rs_dir() { [[ -d $1 && ! -L $1 && $(stat -c %u:%g:%a "$1") == 0:0:700 ]]; }
_rs_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u:%g:%a:%h "$1") == "0:0:$2:1" ]] &&
      (( $(stat -c %s "$1") <= RAW_STATE_MAX_BYTES ))
}
_rs_root() {
    local p=$1 mode
    [[ $(id -u) == 0 && $(uname -s) == Linux ]] || return 1
    if [[ $p == /var/lib/capstone-raw-operations ]]; then
        [[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || return 1
    else
        # Confined root-owned native fixture only, never exposed by a sudo/MCP
        # wrapper. Production callers use the single literal path above.
        [[ $p =~ ^/var/tmp/capstone-raw-state-test\.[A-Za-z0-9_-]{6,20}/state$ ]] || return 1
    fi
    _rs_dir "$p" || return 1
    while [[ $p != / ]]; do
        [[ -d $p && ! -L $p && $(stat -c %u "$p") == 0 ]] || return 1
        mode=$(stat -c %a "$p") || return 1
        if [[ $p != /var/tmp ]]; then (( (8#$mode & 0022)==0 )) || return 1; fi
        p=$(dirname -- "$p") || return 1
    done
}
_rs_layout() {
    _rs_engine "$2" && _rs_root "$1" && _rs_dir "$1/$2" &&
      _rs_dir "$1/$2/history" && _rs_dir "$1/$2/staging"
}
_rs_validate() {
    local file=$1 engine=$2 mode=$3
    _rs_file "$file" "$mode" || return 1
    jq -se --arg engine "$engine" 'length==1 and .[0].engine==$engine' "$file" >/dev/null 2>&1 || return 1
    jq -e -f "$RAW_STATE_LIBRARY_DIR/state.jq" "$file" >/dev/null 2>&1 || return 1
    # Canonical compact JSON plus exactly one LF excludes duplicate keys,
    # concatenated objects, noncanonical numbers and invisible extra content.
    cmp -s -- "$file" <(jq -cS . "$file" 2>/dev/null)
}
_rs_sha() { sha256sum -- "$1" | cut -d ' ' -f1; }
_rs_identity() { stat -c %d:%i:%s:%Y:%Z -- "$1"; }
_rs_capacity() {
    local count
    count=$(find "$1/history" -mindepth 1 -maxdepth 1 -printf '.\n' | head -n 1025 | wc -l) || return 1
    (( count < RAW_STATE_MAX_HISTORY )) || return 1
    count=$(find "$1/staging" -mindepth 1 -maxdepth 1 -printf '.\n' | head -n 33 | wc -l) || return 1
    (( count <= RAW_STATE_MAX_STAGING )) || return 1
}

raw_state_prepare() (
    [[ $# == 2 ]] || { _rs_fail invalid_arguments; return 65; }
    local root=$1 engine=$2 dir
    _rs_engine "$engine" && _rs_root "$root" || { _rs_fail unsafe_state_root; return 65; }
    umask 077
    for dir in "$root/$engine" "$root/$engine/history" "$root/$engine/staging"; do
        if [[ ! -e $dir && ! -L $dir ]]; then
            mkdir -m 700 -- "$dir" && sync -- "${dir%/*}" || { _rs_fail state_directory_create_failed; return 65; }
        fi
        _rs_dir "$dir" || { _rs_fail unsafe_state_directory; return 65; }
    done
)

raw_state_read_twice() (
    [[ $# == 2 ]] || { _rs_fail invalid_arguments; return 65; }
    local root=$1 engine=$2 path first second before after digest
    _rs_layout "$root" "$engine" || { _rs_fail unsafe_state_layout; return 65; }
    path=$root/$engine/state.json
    _rs_validate "$path" "$engine" 600 || { _rs_fail invalid_current_state; return 65; }
    before=$(_rs_identity "$path") || return 65
    first=$(cat -- "$path") || return 65
    second=$(cat -- "$path") || return 65
    after=$(_rs_identity "$path") || return 65
    [[ $first == "$second" && $before == "$after" ]] || { _rs_fail state_changed_during_read; return 65; }
    _rs_validate "$path" "$engine" 600 || { _rs_fail invalid_current_state; return 65; }
    # Validate the captured value too: it is what the caller receives.
    printf '%s\n' "$first" | jq -e -f "$RAW_STATE_LIBRARY_DIR/state.jq" >/dev/null 2>&1 || return 65
    [[ $(printf '%s\n' "$first" | jq -cS .) == "$first" ]] || return 65
    digest=$(printf '%s\n' "$first" | sha256sum | cut -d ' ' -f1) || return 65
    [[ $(_rs_sha "$path") == "$digest" && $(_rs_identity "$path") == "$before" ]] || { _rs_fail state_changed_during_read; return 65; }
    jq -nc --argjson state "$first" --arg sha "$digest" --arg identity "$before" \
      '{state:$state,sha256:$sha,file_identity:$identity,start_authorized:false}'
)

_rs_transition() {
    jq -e --slurpfile previous "$1" '
      $previous[0] as $a | . as $b |
      $b.revision==($a.revision+1) and $b.source_pins==$a.source_pins and
      ([$a.phase,$b.phase] as $transition | any([
        ["active","switch_pending"],["switch_pending","old_closed"],
        ["old_closed","readers_drained"],["readers_drained","publish_pending"],["publish_pending","active"]][]; .==$transition)) and
      (if $a.phase=="publish_pending" then $b.current==$a.pending and $b.pending==null else
         $b.current==$a.current and
         (if $a.phase=="active" then true else $b.pending==$a.pending end) and
         (if $a.proof.old_closed==null then true else $b.proof.old_closed==$a.proof.old_closed end) and
         (if $a.proof.readers_drained==null then true else $b.proof.readers_drained==$a.proof.readers_drained end)
       end)
    ' "$2" >/dev/null 2>&1
}

_rs_candidate() {
    local root=$1 engine=$2 candidate=$3 name
    [[ ${candidate%/*} == "$root/$engine/staging" ]] || return 1
    name=${candidate##*/}
    [[ $name =~ ^candidate-[A-Za-z0-9_-]{6,40}\.json$ ]] || return 1
    _rs_validate "$candidate" "$engine" 600
}

raw_state_init() (
    [[ $# == 3 ]] || { _rs_fail invalid_arguments; return 65; }
    local root=$1 engine=$2 candidate=$3 path temp='' expected
    _rs_layout "$root" "$engine" && _rs_candidate "$root" "$engine" "$candidate" || { _rs_fail invalid_initial_candidate; return 65; }
    path=$root/$engine/state.json
    [[ ! -e $path && ! -L $path ]] || { _rs_fail state_already_exists; return 65; }
    jq -e '.phase=="active" and .revision==0 and .current.number==0' "$candidate" >/dev/null || { _rs_fail invalid_initial_phase; return 65; }
    _rs_capacity "$root/$engine" || { _rs_fail metadata_capacity_limit; return 65; }
    expected=$(_rs_sha "$candidate") || return 65
    umask 077
    temp=$(mktemp "$root/$engine/.next.XXXXXXXX") || return 65
    trap '[[ -z $temp ]] || rm -f -- "$temp"' EXIT
    cat -- "$candidate" > "$temp" && chmod 600 "$temp" &&
      _rs_validate "$temp" "$engine" 600 && [[ $(_rs_sha "$temp") == "$expected" ]] &&
      sync -- "$temp" || { _rs_fail initial_state_write_failed; return 65; }
    mv -T -n -- "$temp" "$path" || { _rs_fail initial_state_publish_failed; return 65; }
    [[ ! -e $temp ]] || { _rs_fail initial_state_raced; return 65; }
    temp=''
    sync -- "$root/$engine" || { _rs_fail initial_state_directory_sync_failed; return 65; }
    [[ $(_rs_sha "$path") == "$expected" ]] || { _rs_fail initial_readback_mismatch; return 65; }
    printf '{"status":"initialized","sha256":"%s","revision":0}\n' "$expected"
)

raw_state_cas() (
    [[ $# == 4 ]] || { _rs_fail invalid_arguments; return 65; }
    local root=$1 engine=$2 expected=$3 candidate=$4 path identity digest revision archive temp='' oldtemp=''
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || { _rs_fail invalid_expected_sha; return 65; }
    _rs_layout "$root" "$engine" && _rs_candidate "$root" "$engine" "$candidate" || { _rs_fail invalid_candidate; return 65; }
    path=$root/$engine/state.json
    _rs_validate "$path" "$engine" 600 || { _rs_fail invalid_current_state; return 65; }
    identity=$(_rs_identity "$path") || return 65
    [[ $(_rs_sha "$path") == "$expected" ]] || { _rs_fail state_compare_conflict; return 65; }
    _rs_transition "$path" "$candidate" || { _rs_fail state_transition_rejected; return 65; }
    _rs_capacity "$root/$engine" || { _rs_fail metadata_capacity_limit; return 65; }
    digest=$(_rs_sha "$candidate") || return 65
    revision=$(jq -r .revision "$path") || return 65
    archive=$root/$engine/history/$revision-$expected.json
    umask 077
    trap '[[ -z $temp ]] || rm -f -- "$temp"; [[ -z $oldtemp ]] || rm -f -- "$oldtemp"' EXIT
    if [[ -e $archive || -L $archive ]]; then
        _rs_validate "$archive" "$engine" 400 && [[ $(_rs_sha "$archive") == "$expected" ]] || { _rs_fail history_conflict; return 65; }
    else
        oldtemp=$(mktemp "$root/$engine/history/.prior.XXXXXXXX") || return 65
        cat -- "$path" > "$oldtemp" && chmod 400 "$oldtemp" &&
          [[ $(_rs_sha "$oldtemp") == "$expected" ]] && _rs_validate "$oldtemp" "$engine" 400 &&
          sync -- "$oldtemp" || { _rs_fail history_write_failed; return 65; }
        mv -T -n -- "$oldtemp" "$archive" || { _rs_fail history_publish_failed; return 65; }
        [[ ! -e $oldtemp ]] || { _rs_fail history_publish_raced; return 65; }
        oldtemp=''
    fi
    # Re-sync even a previously published history file. This covers a process
    # stop after its rename but before parent-dir durability was established.
    sync -- "$archive" "$root/$engine/history" || { _rs_fail history_sync_failed; return 65; }
    temp=$(mktemp "$root/$engine/.next.XXXXXXXX") || return 65
    cat -- "$candidate" > "$temp" && chmod 600 "$temp" &&
      _rs_validate "$temp" "$engine" 600 && [[ $(_rs_sha "$temp") == "$digest" ]] &&
      sync -- "$temp" || { _rs_fail candidate_write_failed; return 65; }
    # Compare again immediately before atomic replacement. This is CAS under
    # the coordinator's external lock, not an adversarial-root kernel CAS.
    _rs_validate "$path" "$engine" 600 && [[ $(_rs_identity "$path") == "$identity" && $(_rs_sha "$path") == "$expected" ]] || { _rs_fail state_compare_conflict; return 65; }
    mv -T -- "$temp" "$path" || { _rs_fail state_publish_failed; return 65; }
    temp=''
    sync -- "$root/$engine" || { _rs_fail state_directory_sync_failed; return 65; }
    _rs_validate "$path" "$engine" 600 && [[ $(_rs_sha "$path") == "$digest" ]] || { _rs_fail state_readback_mismatch; return 65; }
    printf '{"status":"updated","sha256":"%s","revision":%s}\n' "$digest" "$((revision+1))"
)
