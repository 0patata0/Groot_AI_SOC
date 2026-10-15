#!/bin/bash
# Read-only source library. The coordinator owns trusted state, paths and signals.
# Public API: writer_identity SOURCE; writer_gate SOURCE EXPECTED_INIT_JSON DEV INO
# DEV/INO/start_ticks are decimal strings. Only status=closed and exit=0 is a gate.
WG_LIBRARY=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/writer-gates.sh

_wg_report() {
    /usr/bin/jq -nc --arg status "$1" --arg reason "$2" \
        '{schema_version:1,status:$status,reason:$reason,writable_fd_count:null,
          scope:"current_exact_container_process_snapshot",future_reopen_excluded:false,
          host_other_processes_checked:false,changes:false}'
}

_wg_docker() {
    local output
    # Overall public worker timeout also covers this command. Limit metadata bytes.
    output=$(/usr/local/bin/docker "$@" 2>/dev/null | /usr/bin/head -c 65537) || return 1
    (( ${#output}<=65536 )) || return 1
    printf '%s\n' "$output"
}

_wg_container() {
    local output
    output=$(_wg_docker inspect --format '{"cid":{{json .Id}},"pid":{{json .State.Pid}},"running":{{json .State.Running}},"started_at":{{json .State.StartedAt}},"restart_count":{{json .RestartCount}},"image":{{json .Image}}}' "$1") || return 1
    printf '%s\n' "$output" | /usr/bin/jq -sce '
      select(length==1)|.[0]|
      select(keys==["cid","image","pid","restart_count","running","started_at"] and
        (.cid|type=="string" and test("^[0-9a-f]{64}$")) and
        (.pid|type=="number" and floor==. and .>1 and .<2147483648) and .running==true and
        (.started_at|type=="string" and length<100) and
        (.restart_count|type=="number" and floor==. and .>=0) and
        (.image|type=="string" and test("^sha256:[0-9a-f]{64}$")))' 2>/dev/null
}

_wg_members() {
    local output pids
    output=$(_wg_docker top "$1" -eo pid) || return 1
    pids=$(printf '%s\n' "$output" | /usr/bin/awk '
      NR==1 {if ($0 !~ /^[[:space:]]*PID[[:space:]]*$/) exit 1; next}
      NF!=1 || $1!~/^[0-9]+$/ || $1<=1 || $1>=2147483648 {exit 1}
      {print $1}') || return 1
    printf '%s\n' "$pids" | /usr/bin/jq -Rsce '
      split("\n")|map(select(length>0)|tonumber)|sort|
      select(length>0 and length<=64 and (unique|length)==length)' 2>/dev/null
}

_wg_proc_identity() {
    local pid=$1 record parsed status uid gid mountns pidns netns exe
    [[ $pid =~ ^[1-9][0-9]{0,9}$ && $pid -gt 1 ]] || return 1
    record=$(/usr/bin/head -c 4097 "/proc/$pid/stat" 2>/dev/null) || return 1
    (( ${#record}<=4096 )) || return 1
    parsed=$(printf '%s\n' "$record" | /usr/bin/awk '
      {sub(/^.*\) /, ""); if(NF<20 || $1~/^[ZX]$/ || $20!~/^[0-9]+$/)exit 1;print $20}') || return 1
    [[ $parsed =~ ^[1-9][0-9]{0,19}$ ]] || return 1
    status=$(/usr/bin/head -c 16385 "/proc/$pid/status" 2>/dev/null) || return 1
    (( ${#status}<=16384 )) || return 1
    uid=$(printf '%s\n' "$status" | /usr/bin/awk '/^Uid:/ {if(NF!=5)exit 1;print $2,$3,$4,$5;n++}END{if(n!=1)exit 1}') || return 1
    gid=$(printf '%s\n' "$status" | /usr/bin/awk '/^Gid:/ {if(NF!=5)exit 1;print $2,$3,$4,$5;n++}END{if(n!=1)exit 1}') || return 1
    [[ $uid =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ && $gid =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]] || return 1
    mountns=$(/usr/bin/readlink "/proc/$pid/ns/mnt" 2>/dev/null) || return 1
    pidns=$(/usr/bin/readlink "/proc/$pid/ns/pid" 2>/dev/null) || return 1
    netns=$(/usr/bin/readlink "/proc/$pid/ns/net" 2>/dev/null) || return 1
    exe=$(/usr/bin/readlink "/proc/$pid/exe" 2>/dev/null) || return 1
    [[ $mountns =~ ^mnt:\[[0-9]+\]$ && $pidns =~ ^pid:\[[0-9]+\]$ && $netns =~ ^net:\[[0-9]+\]$ &&
       $exe == /* && $exe != *$'\n'* && ${#exe} -le 512 ]] || return 1
    /usr/bin/jq -nc --argjson pid "$pid" --arg ticks "$parsed" --arg uids "$uid" --arg gids "$gid" \
      --arg mount "$mountns" --arg pidns "$pidns" --arg netns "$netns" --arg exe "$exe" '
      {pid:$pid,start_ticks:$ticks,uids:($uids|split(" ")|map(tonumber)),gids:($gids|split(" ")|map(tonumber)),
       mount_ns:$mount,pid_ns:$pidns,net_ns:$netns,exe:$exe}'
}

_wg_init_identity() {
    local source=$1 container=$2 proc cid pid expected_exe
    pid=$(printf '%s\n' "$container" | /usr/bin/jq -er .pid) || return 1
    cid=$(printf '%s\n' "$container" | /usr/bin/jq -er .cid) || return 1
    [[ $source == suricata ]] && expected_exe=/usr/bin/suricata || expected_exe=/usr/sbin/nginx
    proc=$(_wg_proc_identity "$pid") || return 1
    printf '%s\n' "$proc" | /usr/bin/jq -ce --arg cid "$cid" --arg exe "$expected_exe" '
      select(.exe==$exe)|{cid:$cid,pid,start_ticks,mount_ns,pid_ns,uid:.uids[1],gid:.gids[1]}' 2>/dev/null
}

_wg_fd_numbers() {
    local output
    output=$(/usr/bin/find "/proc/$1/fd" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | /usr/bin/head -c 65537) || return 1
    (( ${#output}<=65536 )) || return 1
    printf '%s\n' "$output" | /usr/bin/jq -Rsce '
      split("\n")|map(select(length>0))|
      select(length<=4096 and all(.[];test("^[0-9]{1,10}$")))|
      map(tonumber)|sort|select((unique|length)==length)' 2>/dev/null
}

_wg_fd_meta() {
    local pid=$1 fd=$2 identity flags after
    identity=$(/usr/bin/stat -Lc '%d:%i' "/proc/$pid/fd/$fd" 2>/dev/null) || return 1
    flags=$(/usr/bin/awk '/^flags:/ {if(NF!=2 || $2!~/^[0-7]{1,12}$/)exit 1;print $2;n++}END{if(n!=1)exit 1}' "/proc/$pid/fdinfo/$fd" 2>/dev/null) || return 1
    after=$(/usr/bin/stat -Lc '%d:%i' "/proc/$pid/fd/$fd" 2>/dev/null) || return 1
    [[ $identity == "$after" && $identity =~ ^[0-9]+:[0-9]+$ && $flags =~ ^[0-7]{1,12}$ ]] || return 1
    printf '%s:%s\n' "$identity" "$flags"
}

_wg_scan_process() {
    local pid=$1 dev=$2 ino=$3 before after fd fd_lines meta meta_after fddev fdino flags writable=0 observed=0 count=0
    before=$(_wg_fd_numbers "$pid") || return 1
    fd_lines=$(printf '%s\n' "$before" | /usr/bin/jq -r '.[]') || return 1
    while read -r fd; do
        [[ -n $fd ]] || continue
        meta=$(_wg_fd_meta "$pid" "$fd") || return 1
        IFS=: read -r fddev fdino flags <<< "$meta"
        if [[ $fddev == "$dev" && $fdino == "$ino" ]]; then
            observed=$((observed+1))
            case $((8#$flags & 3)) in
              1|2) writable=$((writable+1)) ;;
              0) ;;
              *) return 1 ;;
            esac
        fi
        meta_after=$(_wg_fd_meta "$pid" "$fd") || return 1
        [[ $meta == "$meta_after" ]] || return 1
        count=$((count+1))
    done <<< "$fd_lines"
    after=$(_wg_fd_numbers "$pid") || return 1
    [[ $before == "$after" ]] || return 1
    /usr/bin/jq -nc --argjson scanned "$count" --argjson writable "$writable" --argjson matching "$observed" \
      '{scanned_fd_count:$scanned,writable_fd_count:$writable,matching_fd_count:$matching}'
}

_wg_observe_identity() {
    local source=$1 before after identity repeated
    [[ $source == suricata || $source == waf ]] || return 1
    before=$(_wg_container "$source") || return 1
    identity=$(_wg_init_identity "$source" "$before") || return 1
    after=$(_wg_container "$source") || return 1
    repeated=$(_wg_init_identity "$source" "$after") || return 1
    [[ $before == "$after" && $identity == "$repeated" ]] || return 1
    /usr/bin/jq -nc --arg source "$source" --argjson identity "$identity" '
      {schema_version:1,status:"observed",source:$source,identity:$identity,
       authorization_or_state_rebinding:false,changes:false}'
}

_wg_gate() {
    local source=$1 expected=$2 dev=$3 ino=$4 before after init repeated members members_after pid proc proc_after member_lines row_lines
    local rows='[]' scan count total=0 matching=0 scanned=0
    [[ $source == suricata || $source == waf ]] || return 1
    [[ $dev =~ ^(0|[1-9][0-9]{0,19})$ && $ino =~ ^[1-9][0-9]{0,19}$ && ${#expected} -le 2048 ]] || return 1
    expected=$(printf '%s\n' "$expected" | /usr/bin/jq -sce '
      select(length==1)|.[0]|select(keys==["cid","gid","mount_ns","pid","pid_ns","start_ticks","uid"] and
        (.cid|type=="string" and test("^[0-9a-f]{64}$")) and
        (.pid|type=="number" and floor==. and .>1 and .<2147483648) and
        (.start_ticks|type=="string" and test("^[1-9][0-9]{0,19}$")) and
        (.mount_ns|type=="string" and test("^mnt:\\[[0-9]+\\]$")) and
        (.pid_ns|type=="string" and test("^pid:\\[[0-9]+\\]$")) and
        (.uid|type=="number" and floor==. and .>=0 and .<=4294967295) and
        (.gid|type=="number" and floor==. and .>=0 and .<=4294967295))') || return 1
    before=$(_wg_container "$source") || return 1
    init=$(_wg_init_identity "$source" "$before") || return 1
    /usr/bin/jq -ne --argjson expected "$expected" --argjson actual "$init" '$expected==$actual' >/dev/null || return 1
    members=$(_wg_members "$(printf '%s\n' "$init" | /usr/bin/jq -r .cid)") || return 1
    printf '%s\n' "$members" | /usr/bin/jq -e --argjson init "$init" 'index($init.pid)!=null' >/dev/null || return 1
    member_lines=$(printf '%s\n' "$members" | /usr/bin/jq -r '.[]') || return 1
    while read -r pid; do
        proc=$(_wg_proc_identity "$pid") || return 1
        /usr/bin/jq -ne --argjson init "$init" --argjson p "$proc" \
          '$p.mount_ns==$init.mount_ns and $p.pid_ns==$init.pid_ns' >/dev/null || return 1
        scan=$(_wg_scan_process "$pid" "$dev" "$ino") || return 1
        proc_after=$(_wg_proc_identity "$pid") || return 1
        [[ $proc == "$proc_after" ]] || return 1
        rows=$(/usr/bin/jq -nc --argjson rows "$rows" --argjson p "$proc" --argjson fd "$scan" '$rows+[$p+$fd]') || return 1
    done <<< "$member_lines"
    /usr/bin/jq -ne --argjson rows "$rows" --argjson members "$members" \
        '([$rows[].pid]|sort)==$members' >/dev/null || return 1
    # A process may exit/exec or be replaced while another process is scanned.
    row_lines=$(printf '%s\n' "$rows" | /usr/bin/jq -c '.[]') || return 1
    while read -r proc; do
        pid=$(printf '%s\n' "$proc" | /usr/bin/jq -r .pid) || return 1
        proc_after=$(_wg_proc_identity "$pid") || return 1
        /usr/bin/jq -ne --argjson row "$proc" --argjson p "$proc_after" \
          '($row|del(.scanned_fd_count,.writable_fd_count,.matching_fd_count))==$p' >/dev/null || return 1
    done <<< "$row_lines"
    members_after=$(_wg_members "$(printf '%s\n' "$init" | /usr/bin/jq -r .cid)") || return 1
    after=$(_wg_container "$source") || return 1
    repeated=$(_wg_init_identity "$source" "$after") || return 1
    [[ $before == "$after" && $members == "$members_after" && $init == "$repeated" ]] || return 1
    total=$(printf '%s\n' "$rows" | /usr/bin/jq '[.[].writable_fd_count]|add//0') || return 1
    /usr/bin/jq -nc --arg source "$source" --arg dev "$dev" --arg ino "$ino" \
      --argjson init "$init" --argjson rows "$rows" --argjson total "$total" '
      {schema_version:1,status:(if $total==0 then "closed" else "open" end),reason:"stable_container_snapshot",
       source:$source,identity:$init,target:{device:$dev,inode:$ino},processes:$rows,
       process_count:($rows|length),scanned_fd_count:([$rows[].scanned_fd_count]|add//0),
       matching_fd_count:([$rows[].matching_fd_count]|add//0),writable_fd_count:$total,
       membership_stable:true,scope:"current_exact_container_process_snapshot",future_reopen_excluded:false,
       host_other_processes_checked:false,changes:false}' || return 1
    [[ $total == 0 ]] && return 0
    return 10
}

_wg_public() {
    local kind=$1 output rc=0; shift
    [[ $EUID == 0 && $(/usr/bin/uname -s) == Linux &&
       $(/usr/bin/cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || {
        _wg_report deferred fixed_A_root_required; return 75;
    }
    [[ ( $kind == identity && $# == 1 ) || ( $kind == gate && $# == 4 ) ]] || {
        _wg_report deferred invalid_arguments; return 75;
    }
    # Fresh worker keeps all metadata buffered until complete; no partial success
    # is emitted on timeout. No source, logger, state file or process is changed.
    output=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout --signal=TERM --kill-after=1s 14s \
      /bin/bash --noprofile --norc -c 'set -uo pipefail; source "$1"; shift; kind=$1; shift;
        if [[ $kind == identity ]]; then _wg_observe_identity "$@"; else _wg_gate "$@"; fi' \
      writer-gate "$WG_LIBRARY" "$kind" "$@" 2>/dev/null) || rc=$?
    if [[ $rc == 0 || $rc == 10 ]]; then
        (( ${#output}<=65536 )) || { _wg_report deferred metadata_limit; return 75; }
        printf '%s\n' "$output"
        return "$rc"
    fi
    if [[ $rc == 124 || $rc == 137 ]]; then _wg_report deferred timeout
    else _wg_report deferred identity_membership_or_fd_unavailable; fi
    return 75
}

writer_identity() { _wg_public identity "$@"; }
writer_gate() { _wg_public gate "$@"; }
