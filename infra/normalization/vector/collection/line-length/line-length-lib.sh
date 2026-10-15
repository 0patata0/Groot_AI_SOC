#!/bin/bash
# Bounded GNU byte-length observation. No raw bytes or input path are emitted.
# Public callers choose the fixed source; this library also supports private fixtures.
_LL_SELF=${BASH_SOURCE[0]}

ll_emit() {
    /usr/bin/jq -nc \
      --arg verdict "$1" --arg reason "$2" --argjson positive "$3" \
      --argjson stable "$4" --argjson complete "$5" --argjson full "$6" \
      --argjson start "$7" --argjson end "$8" --argjson size "$9" \
      --argjson scanned "${10}" --argjson longest "${11}" \
      --argjson limit "${12}" --argjson budget "${13}" --argjson seconds "${14}" \
      '{verdict:$verdict,reason:$reason,observed_positive:$positive,file_stable:$stable,
        complete_snapshot_range:$complete,full_file_scan:$full,
        range_start:$start,range_end:$end,snapshot_bytes:$size,
        scanned_bytes:$scanned,max_line_bytes:$longest,line_limit_bytes:$limit,
        scan_budget_bytes:$budget,timeout_seconds:$seconds,
        leading_fragment_possible:(if $start==null then null else $start>0 end)}'
}

ll_path_shape() {
    [[ ${#1} -le 512 && $1 =~ ^/[A-Za-z0-9_./-]+$ && $1 != *//* &&
       $1 != */./* && $1 != */../* && $1 != */. && $1 != */.. && $1 != */ ]]
}

ll_directory_snapshot() {
    local input=$1 current=/ component i
    local -a components
    ll_path_shape "$input" || return 1
    IFS=/ read -r -a components <<< "${input#/}"
    /usr/bin/stat -c '%d:%i:%u:%g:%a' -- / || return 1
    for ((i=0; i<${#components[@]}-1; i++)); do
        component=${components[i]}
        current=${current%/}/$component
        [[ -d $current && ! -L $current ]] || return 1
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$current" || return 1
    done
    [[ ! -L $input ]]
}

ll_file_stat() {
    /usr/bin/stat -c '%d|%i|%s|%u|%g|%a|%h|%f|%y|%z' -- "$1"
}

ll_worker() {
    local input=$1 wanted_uid=$2 wanted_gid=$3 wanted_mode=$4 limit=$5 budget=$6 seconds=$7
    local dirs_before dirs_after before fd_before after fd_after dev ino size uid gid mode links bits mtime ctime
    local start count measure scanned longest extra scan_rc=0 positive=false stable=false full=false
    local owner_pid=$BASHPID
    if ! dirs_before=$(ll_directory_snapshot "$input") || [[ ! -f $input || -L $input ]] ||
       ! before=$(ll_file_stat "$input"); then
        ll_emit inconclusive source_unavailable false false false false null null null null null "$limit" "$budget" "$seconds"
        return
    fi
    IFS='|' read -r dev ino size uid gid mode links bits mtime ctime <<< "$before"
    if [[ ! $size =~ ^(0|[1-9][0-9]{0,14})$ || $uid != "$wanted_uid" || $gid != "$wanted_gid" ||
          $mode != "$wanted_mode" || $links != 1 || ! $bits =~ ^[a-f0-9]{4,8}$ ]] ||
       (( (16#$bits & 0170000) != 0100000 )); then
        ll_emit inconclusive metadata_mismatch false false false false null null null null null "$limit" "$budget" "$seconds"
        return
    fi
    # The whole worker is inside GNU timeout, including this open. A path that
    # races to a FIFO cannot leave an indefinitely blocked opener.
    if ! { exec 7< "$input"; } 2>/dev/null ||
       ! fd_before=$(/usr/bin/stat -Lc '%d|%i|%s|%u|%g|%a|%h|%f|%y|%z' -- "/proc/$owner_pid/fd/7") ||
       [[ $fd_before != "$before" ]] || [[ -L $input ]] || [[ $(ll_file_stat "$input") != "$before" ]]; then
        ll_emit inconclusive open_identity_changed false false false false null null null null null "$limit" "$budget" "$seconds"
        return
    fi
    start=$(( size > budget ? size-budget : 0 )); count=$((size-start))
    # Fixed byte range, including the observed EOF. dd seeks on the already
    # checked regular FD, reads at most count bytes, and never follows appends.
    # Non-LF bytes (including NUL, UTF-8, tab and CR) all become one ASCII dot.
    if measure=$(/usr/bin/dd bs=65536 skip="$start" count="$count" iflag=skip_bytes,count_bytes status=none <&7 |
                 /usr/bin/tr -c '\n' '.' | /usr/bin/wc -c -L); then
        scan_rc=0
    else
        scan_rc=$?
    fi
    IFS=' ' read -r scanned longest extra <<< "$measure"
    if [[ ! $scanned =~ ^(0|[1-9][0-9]{0,8})$ || ! $longest =~ ^(0|[1-9][0-9]{0,8})$ || -n ${extra:-} ]] ||
       (( scanned > count || longest > scanned )); then
        ll_emit inconclusive scanner_output_invalid false false false false "$start" "$size" "$size" null null "$limit" "$budget" "$seconds"
        return
    fi
    if (( longest > limit )); then positive=true; fi
    if fd_after=$(/usr/bin/stat -Lc '%d|%i|%s|%u|%g|%a|%h|%f|%y|%z' -- "/proc/$owner_pid/fd/7") &&
       after=$(ll_file_stat "$input") && dirs_after=$(ll_directory_snapshot "$input") &&
       [[ ! -L $input && $before == "$fd_after" && $before == "$after" && $dirs_before == "$dirs_after" ]]; then
        stable=true
    fi
    exec 7<&-
    if [[ $stable != true ]]; then
        ll_emit inconclusive file_changed "$positive" false false false "$start" "$size" "$size" "$scanned" "$longest" "$limit" "$budget" "$seconds"
    elif (( scan_rc != 0 || scanned != count )); then
        ll_emit inconclusive scan_error "$positive" true false false "$start" "$size" "$size" "$scanned" "$longest" "$limit" "$budget" "$seconds"
    else
        if (( start == 0 )); then full=true; fi
        if [[ $positive == true ]]; then
            ll_emit oversize limit_exceeded true true true "$full" "$start" "$size" "$size" "$scanned" "$longest" "$limit" "$budget" "$seconds"
        else
            ll_emit within_scanned_range range_within_limit false true true "$full" "$start" "$size" "$size" "$scanned" "$longest" "$limit" "$budget" "$seconds"
        fi
    fi
}

ll_scan() {
    # API: path uid gid mode limit_bytes budget_bytes timeout_seconds.
    local input=${1:-} uid=${2:-} gid=${3:-} mode=${4:-} limit=${5:-} budget=${6:-} seconds=${7:-}
    local result code
    [[ $# == 7 && $EUID == 0 && $OSTYPE == linux* && $_LL_SELF == /* && -f $_LL_SELF && ! -L $_LL_SELF ]] || return 77
    [[ $uid =~ ^(0|[1-9][0-9]{0,9})$ && $gid =~ ^(0|[1-9][0-9]{0,9})$ && $mode =~ ^[0-7]{3,4}$ &&
       $limit =~ ^[1-9][0-9]{0,6}$ && $budget =~ ^[1-9][0-9]{0,7}$ && $seconds =~ ^[1-9]$ ]] || return 64
    (( limit <= 1048576 && budget <= 33554432 && budget > limit && seconds <= 5 )) || return 64
    if ! ll_path_shape "$input"; then
        ll_emit inconclusive path_rejected false false false false null null null null null "$limit" "$budget" "$seconds"
        return
    fi
    # Clean child environment prevents inherited Bash/locale/startup injection.
    # timeout owns its child process group and bounds open/stat/read as well as the pipe.
    if result=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
        /usr/bin/timeout --signal=TERM --kill-after=1s "${seconds}s" \
        /bin/bash --noprofile --norc "$_LL_SELF" --worker "$input" "$uid" "$gid" "$mode" "$limit" "$budget" "$seconds" 2>/dev/null); then
        if /usr/bin/jq -e 'type=="object" and (.verdict=="oversize" or .verdict=="within_scanned_range" or .verdict=="inconclusive")' <<< "$result" >/dev/null 2>&1; then
            printf '%s\n' "$result"
            return
        fi
        code=70
    else
        code=$?
    fi
    if (( code == 124 || code == 137 )); then
        ll_emit inconclusive scan_timeout false false false false null null null null null "$limit" "$budget" "$seconds"
    else
        ll_emit inconclusive scanner_failed false false false false null null null null null "$limit" "$budget" "$seconds"
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    PATH=/usr/bin:/bin; export PATH LC_ALL=C TZ=Asia/Seoul
    umask 077
    [[ $EUID == 0 && $OSTYPE == linux* && $# == 8 && $1 == --worker ]] || exit 77
    shift
    [[ $2 =~ ^(0|[1-9][0-9]{0,9})$ && $3 =~ ^(0|[1-9][0-9]{0,9})$ && $4 =~ ^[0-7]{3,4}$ &&
       $5 =~ ^[1-9][0-9]{0,6}$ && $6 =~ ^[1-9][0-9]{0,7}$ && $7 =~ ^[1-9]$ ]] || exit 64
    (( $5 <= 1048576 && $6 <= 33554432 && $6 > $5 && $7 <= 5 )) || exit 64
    ll_worker "$@"
fi
