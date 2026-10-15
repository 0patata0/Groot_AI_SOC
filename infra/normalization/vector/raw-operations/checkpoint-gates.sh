#!/bin/bash
# Read-only native checkpoint gates; source this file from the root coordinator.
# All public calls: exit 0 = pass, 2 = defer; stdout is one metadata-only JSON.
# These gates do NOT prove Wazuh queue delivery, manager receipt or indexing.
# Coordinator owns fixed path/UID/config pins, closed-writer proof and locking.
# Source/CP owners are returned/observed, not inferred to be trusted here.
# Reading may update atime. No checkpoint is changed, repaired or initialized.
#
# Wazuh 4.14.8 hashes ALL saved offset bytes, not a 4096-byte prefix:
# https://github.com/wazuh/wazuh/blob/v4.14.8/src/os_crypto/sha1/sha1_op.c#L124-L205
# https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L2602-L2613
# Vector 0.59.0 version="1", pending file preference:
# https://github.com/vectordotdev/vector/blob/v0.59.0/lib/file-source-common/src/checkpointer.rs
_CG_SELF=${BASH_SOURCE[0]}

cg_path_shape() {
    [[ ${#1} -le 512 && $1 =~ ^/[A-Za-z0-9_./-]+$ && $1 != *//* &&
       $1 != */./* && $1 != */../* && $1 != */. && $1 != */.. && $1 != */ ]]
}
cg_uint() { [[ $1 =~ ^(0|[1-9][0-9]{0,15})$ ]] && (( $1 <= 9007199254740991 )); }
cg_directories() {
    local path=$1 current=/ component i
    local -a parts
    cg_path_shape "$path" || return 1
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- / || return 1
    IFS=/ read -r -a parts <<< "${path#/}"
    for ((i=0; i<${#parts[@]}-1; i++)); do
        component=${parts[i]}; current=${current%/}/$component
        [[ -d $current && ! -L $current ]] || return 1
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$current" || return 1
    done
    [[ ! -L $path ]]
}
cg_stat() { /usr/bin/stat -c '%d|%i|%s|%u|%g|%a|%h|%f|%y|%z' -- "$1"; }
cg_fdstat() { /usr/bin/stat -Lc '%d|%i|%s|%u|%g|%a|%h|%f|%y|%z' -- "/proc/$_cg_owner/fd/$1"; }
cg_regular() {
    local dev ino bytes uid gid mode links bits mtime ctime source_links=${2:-false}
    IFS='|' read -r dev ino bytes uid gid mode links bits mtime ctime <<< "$1"
    cg_uint "$dev" && cg_uint "$ino" && cg_uint "$bytes" && (( ino>0 )) &&
      [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $mode =~ ^[0-7]{3,4}$ &&
         $links =~ ^[1-9][0-9]{0,9}$ && $bits =~ ^[a-f0-9]{4,8}$ ]] &&
      [[ $links == 1 || $source_links == true ]] && (( (16#$bits & 0170000)==0100000 ))
}
cg_emit() {
    /usr/bin/jq -nc --arg gate "${_cg_gate:-unknown}" --arg verdict "$1" --arg reason "$2" \
      --argjson source "${_cg_identity:-null}" --argjson stable "${_cg_stable:-false}" \
      --arg cp_sha "${_cg_cp_sha:-}" --arg cp_kind "${_cg_cp_kind:-}" \
      --argjson offset "${_cg_offset:-null}" --arg stored "${_cg_stored:-}" \
      --arg prefix "${_cg_prefix:-}" --argjson seek "${_cg_seek:-null}" \
      --argjson backlog "${_cg_backlog:-null}" --argjson scanned "${_cg_scanned:-null}" \
      --argjson longest "${_cg_longest:-null}" --argjson lf "${_cg_lf:-null}" \
      --argjson limit "${_cg_limit:-null}" \
      '{schema_version:1,gate:$gate,verdict:$verdict,reason:$reason,
        source_identity:$source,source_stable:$stable,
        checkpoint_sha256:(if $cp_sha=="" then null else $cp_sha end),
        checkpoint_kind:(if $cp_kind=="" then null else $cp_kind end),
        offset:$offset,stored_sha1:(if $stored=="" then null else $stored end),
        prefix_sha1:(if $prefix=="" then null else $prefix end),expected_seek:$seek,
        backlog_bytes:$backlog,scanned_bytes:$scanned,max_line_bytes:$longest,
        eof_lf:$lf,line_limit_bytes:$limit,timeout_seconds:30,
        delivery_acknowledged:false}'
}
cg_stop() { cg_emit defer "$1"; exit 2; }
cg_source_open() {
    _cg_source=$1
    _cg_dirs=$(cg_directories "$_cg_source") || cg_stop source_path_rejected
    [[ -f $_cg_source && ! -L $_cg_source ]] || cg_stop source_not_regular
    _cg_before=$(cg_stat "$_cg_source") || cg_stop source_stat_failed
    cg_regular "$_cg_before" true || cg_stop source_metadata_invalid
    IFS='|' read -r _cg_dev _cg_ino _cg_size _cg_uid _cg_gid _cg_mode _cg_links _ _ _ <<< "$_cg_before"
    _cg_identity=$(/usr/bin/jq -nc --argjson d "$_cg_dev" --argjson i "$_cg_ino" \
      --argjson s "$_cg_size" --argjson u "$_cg_uid" --argjson g "$_cg_gid" --arg m "$_cg_mode" --argjson links "$_cg_links" \
      '{device:$d,inode:$i,bytes:$s,uid:$u,gid:$g,mode:$m,links:$links}') || cg_stop metadata_encoding_failed
    # The entire worker, including a possible FIFO race at this open, is timed.
    { exec 7< "$_cg_source"; } 2>/dev/null || cg_stop source_open_failed
    [[ $(cg_fdstat 7) == "$_cg_before" && $(cg_stat "$_cg_source") == "$_cg_before" && ! -L $_cg_source ]] ||
      cg_stop source_open_identity_changed
}
cg_source_stable() {
    local fd_after path_after dirs_after
    fd_after=$(cg_fdstat 7) && path_after=$(cg_stat "$_cg_source") &&
      dirs_after=$(cg_directories "$_cg_source") &&
      [[ $fd_after == "$_cg_before" && $path_after == "$_cg_before" && $dirs_after == "$_cg_dirs" ]] || return 1
    _cg_stable=true
}
cg_checkpoint_open() {
    local maximum=$2 bytes actual non_ascii syntax_rc
    _cg_cp=$1
    _cg_cp_dirs=$(cg_directories "$_cg_cp") || cg_stop checkpoint_path_rejected
    [[ -f $_cg_cp && ! -L $_cg_cp ]] || cg_stop checkpoint_missing_or_not_regular
    _cg_cp_before=$(cg_stat "$_cg_cp") || cg_stop checkpoint_stat_failed
    cg_regular "$_cg_cp_before" || cg_stop checkpoint_metadata_invalid
    IFS='|' read -r _ _ bytes _ _ _ _ _ _ _ <<< "$_cg_cp_before"
    (( bytes>0 && bytes<=maximum )) || cg_stop checkpoint_size_rejected
    { exec 8< "$_cg_cp"; } 2>/dev/null || cg_stop checkpoint_open_failed
    [[ $(cg_fdstat 8) == "$_cg_cp_before" && $(cg_stat "$_cg_cp") == "$_cg_cp_before" && ! -L $_cg_cp ]] ||
      cg_stop checkpoint_open_identity_changed
    /usr/bin/dd bs=65536 count="$bytes" iflag=count_bytes status=none <&8 > "$_cg_tmp/checkpoint.json" ||
      cg_stop checkpoint_read_failed
    actual=$(/usr/bin/stat -c %s -- "$_cg_tmp/checkpoint.json") || cg_stop checkpoint_read_failed
    [[ $actual == "$bytes" ]] || cg_stop checkpoint_short_read
    cg_checkpoint_stable || cg_stop checkpoint_changed
    _cg_cp_sha=$(/usr/bin/sha256sum -- "$_cg_tmp/checkpoint.json") || cg_stop checkpoint_hash_failed
    _cg_cp_sha=${_cg_cp_sha%% *}
    # Native managed paths/cursors are ASCII; reject BOM, NUL and unsupported
    # encodings rather than relying on jq's replacement of malformed UTF-8.
    non_ascii=$(/usr/bin/tr -d '\11\12\15\40-\176' < "$_cg_tmp/checkpoint.json" | /usr/bin/wc -c) ||
      cg_stop checkpoint_read_failed
    [[ $non_ascii =~ ^[[:space:]]*0[[:space:]]*$ ]] || cg_stop checkpoint_json_invalid
    # serde u64 rejects 1.0/1e0/-0, whereas jq can normalize them to integers.
    # Remove JSON string tokens before checking only outside-string numerals.
    /usr/bin/sed -E 's/"([^"\\]|\\.)*"//g' "$_cg_tmp/checkpoint.json" > "$_cg_tmp/structure" ||
      cg_stop checkpoint_json_invalid
    if /usr/bin/grep -E '[0-9][.eE]|-[0-9]' "$_cg_tmp/structure" >/dev/null; then
        cg_stop checkpoint_json_invalid
    else syntax_rc=$?; [[ $syntax_rc == 1 ]] || cg_stop checkpoint_json_invalid; fi
    # Duplicate keys must be rejected before jq collapses them. Wazuh cJSON
    # resolves duplicates differently. All stdout from parsing remains private.
    /usr/bin/jq -nce --stream --arg mode stream_guard --arg logical '' --argjson device 0 --argjson inode 0 \
      -f "$_cg_filter" "$_cg_tmp/checkpoint.json" >/dev/null || cg_stop checkpoint_json_invalid
}
cg_checkpoint_stable() {
    local fd_after path_after dirs_after
    fd_after=$(cg_fdstat 8) && path_after=$(cg_stat "$_cg_cp") &&
      dirs_after=$(cg_directories "$_cg_cp") &&
      [[ $fd_after == "$_cg_cp_before" && $path_after == "$_cg_cp_before" && $dirs_after == "$_cg_cp_dirs" ]] || return 1
    if [[ $_cg_gate == vector_* && $_cg_cp_kind == stable ]]; then
        [[ ! -e $_cg_pending && ! -L $_cg_pending ]] || return 1
    fi
}
cg_read_wazuh() {
    local parsed
    _cg_cp_kind=wazuh
    # Native 4.14.8 w_load_file_status reads OS_MAXSTR-1, i.e. 65,535 bytes.
    cg_checkpoint_open "$1" 65535
    parsed=$(/usr/bin/jq -sce --arg mode wazuh --arg logical "$2" --argjson device 0 --argjson inode 0 \
      -f "$_cg_filter" "$_cg_tmp/checkpoint.json") || cg_stop wazuh_checkpoint_invalid
    _cg_offset=$(/usr/bin/jq -r .offset <<< "$parsed") || cg_stop wazuh_checkpoint_invalid
    _cg_stored=$(/usr/bin/jq -r .sha1 <<< "$parsed") || cg_stop wazuh_checkpoint_invalid
    (( _cg_offset<=536870912 )) || cg_stop prefix_budget_exceeded
    if (( _cg_offset>_cg_size )); then
        [[ ${3:-false} == true ]] || cg_stop saved_offset_beyond_source
        _cg_backlog=0
    else _cg_backlog=$((_cg_size-_cg_offset)); fi
    _cg_hash_bytes=$((_cg_offset<_cg_size ? _cg_offset : _cg_size))
    (( _cg_backlog<=2147483648 )) || cg_stop backlog_exceeds_2gib
}
cg_hash_prefix() {
    local counter_pid measured hash_output pipeline_rc=0 counter_rc=0 extra
    # Only a pipe contains source bytes. Count and SHA1 see the exact same
    # bounded stream; a short read cannot masquerade as a matching empty hash.
    /usr/bin/mkfifo -m 600 -- "$_cg_tmp/count.fifo" || cg_stop prefix_pipe_failed
    /usr/bin/wc -c < "$_cg_tmp/count.fifo" > "$_cg_tmp/count.txt" & counter_pid=$!
    if hash_output=$(/usr/bin/dd bs=65536 count="$_cg_hash_bytes" iflag=count_bytes status=none <&7 |
        /usr/bin/tee -- "$_cg_tmp/count.fifo" | /usr/bin/sha1sum); then :; else pipeline_rc=$?; fi
    if wait "$counter_pid"; then :; else counter_rc=$?; fi
    read -r measured extra < "$_cg_tmp/count.txt" || cg_stop prefix_read_failed
    [[ $measured =~ ^(0|[1-9][0-9]{0,9})$ && -z ${extra:-} ]] || cg_stop prefix_read_failed
    _cg_scanned=$measured
    _cg_prefix=${hash_output%% *}
    (( pipeline_rc==0 && counter_rc==0 && measured==_cg_hash_bytes )) &&
      [[ $_cg_prefix =~ ^[0-9a-f]{40}$ ]] || cg_stop prefix_read_failed
}
cg_finish() {
    cg_source_stable || cg_stop source_changed
    if [[ $_cg_gate != sealed_lines ]]; then cg_checkpoint_stable || cg_stop checkpoint_changed; fi
    cg_emit pass "$1"
}
cg_worker() {
    _cg_gate=$1; shift
    _cg_owner=$BASHPID
    _cg_filter=${_CG_SELF%/*}/checkpoint-gates.jq
    [[ -f $_cg_filter && ! -L $_cg_filter ]] || cg_stop filter_unavailable
    _cg_tmp=$(/usr/bin/mktemp -d /var/tmp/capstone-checkpoint-gates.XXXXXX) || cg_stop scratch_unavailable
    trap '/bin/rm -rf -- "$_cg_tmp"' EXIT
    trap 'exit 143' TERM HUP INT
    /bin/chmod 700 -- "$_cg_tmp" || cg_stop scratch_unavailable
    local expected_dev expected_ino expected_size cp_dir selected parsed reason last measure extra
    case $_cg_gate in
      vector_eof|vector_current)
        if [[ $_cg_gate == vector_eof ]]; then
            [[ $# == 5 ]] && cg_uint "$5" || cg_stop arguments_invalid
            expected_size=$5
        else [[ $# == 4 ]] || cg_stop arguments_invalid; fi
        cp_dir=$1; expected_dev=$3; expected_ino=$4
        cg_path_shape "$cp_dir" && cg_uint "$expected_dev" && cg_uint "$expected_ino" || cg_stop arguments_invalid
        cg_source_open "$2"
        [[ $_cg_dev == "$expected_dev" && $_cg_ino == "$expected_ino" ]] ||
          cg_stop sealed_identity_mismatch
        if [[ $_cg_gate == vector_eof ]]; then
            [[ $_cg_size == "$expected_size" ]] || cg_stop sealed_identity_mismatch
            (( expected_size<=536870912 )) || cg_stop sealed_budget_exceeded
        fi
        _cg_pending=$cp_dir/checkpoints.new.json
        if [[ -e $_cg_pending || -L $_cg_pending ]]; then selected=$_cg_pending; _cg_cp_kind=pending
        else selected=$cp_dir/checkpoints.json; _cg_cp_kind=stable; fi
        cg_checkpoint_open "$selected" 1048576
        parsed=$(/usr/bin/jq -sce --arg mode vector --arg logical '' --argjson device "$_cg_dev" --argjson inode "$_cg_ino" \
          -f "$_cg_filter" "$_cg_tmp/checkpoint.json") || cg_stop vector_checkpoint_invalid
        if /usr/bin/jq -e '.match_count==0' <<< "$parsed" >/dev/null; then
            # Only an otherwise valid, unchanged native CP with exactly zero
            # matches is distinguishable from corruption for first-start use.
            cg_source_stable || cg_stop source_changed
            cg_checkpoint_stable || cg_stop checkpoint_changed
            cg_stop vector_checkpoint_match_missing
        fi
        _cg_offset=$(/usr/bin/jq -r .offset <<< "$parsed") || cg_stop vector_checkpoint_invalid
        (( _cg_offset<=_cg_size )) || cg_stop saved_offset_beyond_source
        _cg_seek=$_cg_offset; _cg_backlog=$((_cg_size-_cg_offset))
        (( _cg_backlog<=2147483648 )) || cg_stop backlog_exceeds_2gib
        if [[ $_cg_gate == vector_eof ]]; then
            [[ $_cg_offset == "$_cg_size" ]] || cg_stop checkpoint_not_at_sealed_eof
            cg_finish sealed_eof
        else cg_finish current_offset_valid; fi
        ;;
      wazuh_eof)
        [[ $# == 6 ]] || cg_stop arguments_invalid
        cg_path_shape "$2" && cg_uint "$4" && cg_uint "$5" && cg_uint "$6" || cg_stop arguments_invalid
        cg_source_open "$3"
        [[ $_cg_dev == "$4" && $_cg_ino == "$5" && $_cg_size == "$6" ]] || cg_stop sealed_identity_mismatch
        (( _cg_size<=536870912 )) || cg_stop sealed_budget_exceeded
        cg_read_wazuh "$1" "$2"
        [[ $_cg_offset == "$_cg_size" ]] || cg_stop checkpoint_not_at_sealed_eof
        cg_hash_prefix
        [[ $_cg_prefix == "$_cg_stored" ]] || cg_stop checkpoint_prefix_mismatch
        _cg_seek=$_cg_offset
        cg_finish sealed_eof
        ;;
      wazuh_cold)
        [[ $# == 5 ]] || cg_stop arguments_invalid
        cg_path_shape "$2" && cg_uint "$4" && cg_uint "$5" || cg_stop arguments_invalid
        cg_source_open "$3"
        cg_read_wazuh "$1" "$2" true
        if [[ $_cg_dev == "$4" && $_cg_ino == "$5" ]] && (( _cg_offset>_cg_size )); then
            cg_stop saved_offset_beyond_source
        fi
        cg_hash_prefix
        cg_source_stable || cg_stop source_changed
        cg_checkpoint_stable || cg_stop checkpoint_changed
        if (( _cg_offset==0 )); then
            [[ $_cg_stored == da39a3ee5e6b4b0d3255bfef95601890afd80709 ]] || cg_stop zero_offset_hash_invalid
            _cg_seek=0; reason=saved_zero
        elif [[ $_cg_dev == "$4" && $_cg_ino == "$5" ]]; then
            [[ $_cg_prefix == "$_cg_stored" ]] || cg_stop same_inode_prefix_changed
            _cg_seek=$_cg_offset; reason=existing_inode_resume
        elif [[ $_cg_prefix == "$_cg_stored" ]]; then
            cg_stop cold_prefix_ambiguous
        else
            _cg_seek=0; reason=different_prefix
        fi
        _cg_backlog=$((_cg_size-_cg_seek))
        (( _cg_backlog<=2147483648 )) || cg_stop backlog_exceeds_2gib
        cg_finish "$reason"
        ;;
      sealed_lines)
        [[ $# == 5 && $5 == 1048576 ]] || cg_stop arguments_invalid
        cg_uint "$2" && cg_uint "$3" && cg_uint "$4" || cg_stop arguments_invalid
        _cg_limit=$5
        cg_source_open "$1"
        [[ $_cg_dev == "$2" && $_cg_ino == "$3" && $_cg_size == "$4" ]] || cg_stop sealed_identity_mismatch
        (( _cg_size<=536870912 )) || cg_stop sealed_budget_exceeded
        measure=$(/usr/bin/dd bs=65536 count="$_cg_size" iflag=count_bytes status=none <&7 |
          /usr/bin/tr -c '\n' '.' | /usr/bin/wc -c -L) || cg_stop sealed_scan_failed
        read -r _cg_scanned _cg_longest extra <<< "$measure"
        cg_uint "$_cg_scanned" && cg_uint "$_cg_longest" && [[ -z ${extra:-} ]] &&
          (( _cg_scanned==_cg_size && _cg_longest<=_cg_scanned )) || cg_stop sealed_scan_short_or_invalid
        if (( _cg_size==0 )); then _cg_lf=true
        else
            # Reopen the already checked descriptor through procfs, obtaining
            # an independent file offset after the preceding full-file scan.
            last=$(/usr/bin/dd if="/proc/$_cg_owner/fd/7" bs=1 skip="$((_cg_size-1))" count=1 status=none |
              /usr/bin/od -An -tu1) ||
              cg_stop sealed_eof_read_failed
            if [[ $last =~ ^[[:space:]]*10[[:space:]]*$ ]]; then _cg_lf=true; else _cg_lf=false; fi
        fi
        cg_source_stable || cg_stop source_changed
        (( _cg_longest<=_cg_limit )) || cg_stop sealed_line_oversize
        [[ $_cg_lf == true ]] || cg_stop sealed_partial_final_line
        cg_finish complete_lines_within_limit
        ;;
      *) cg_stop gate_unknown ;;
    esac
}
cg_dispatch() {
    local gate=$1 result rc=0; shift
    # Fresh child globals avoid leaking a prior successful proof on an error.
    if [[ $EUID != 0 || $OSTYPE != linux* || $_CG_SELF != /* || ! -f $_CG_SELF || -L $_CG_SELF ]]; then
        ( _cg_gate=$gate; cg_emit defer runtime_precondition_failed ); return 2
    fi
    if result=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=UTC \
      /usr/bin/timeout --signal=TERM --kill-after=2s 30s \
      /bin/bash --noprofile --norc "$_CG_SELF" --worker "$gate" "$@" 2>/dev/null); then :; else rc=$?; fi
    if (( rc==0 || rc==2 )) && /usr/bin/jq -se \
      'length==1 and (.[0]|type=="object" and .schema_version==1 and (.verdict=="pass" or .verdict=="defer"))' \
      <<< "$result" >/dev/null 2>&1; then
        printf '%s\n' "$result"
        return "$rc"
    fi
    if (( rc==124 || rc==137 )); then
        ( _cg_gate=$gate; cg_emit defer gate_timeout )
    else
        ( _cg_gate=$gate; cg_emit defer gate_execution_failed )
    fi
    return 2
}
cg_vector_eof() { cg_dispatch vector_eof "$@"; }
cg_vector_current() { cg_dispatch vector_current "$@"; }
cg_wazuh_eof() { cg_dispatch wazuh_eof "$@"; }
cg_wazuh_cold() { cg_dispatch wazuh_cold "$@"; }
cg_sealed_lines() { cg_dispatch sealed_lines "$@"; }

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    PATH=/usr/bin:/bin; export PATH LC_ALL=C TZ=UTC
    umask 077
    [[ $EUID == 0 && $OSTYPE == linux* && $# -ge 2 && $1 == --worker ]] || exit 77
    shift
    cg_worker "$@"
fi
