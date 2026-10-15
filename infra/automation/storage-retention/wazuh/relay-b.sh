#!/bin/bash
# Fixed B status metadata -> existing manager logs volume. No Docker/service
# commands, raw/CP reads, truncation, deletion, network or package operations.
SR_LIB=/usr/local/lib/capstone-storage-monitor
SR_STATE=/var/lib/capstone-storage-monitor
SR_VOLUME=/var/lib/docker/volumes/single-node_wazuh_logs/_data
SR_LOG=$SR_VOLUME/capstone-storage-b.log
SR_VALIDATOR_SHA=668bf6f0992526984c0af3b48ad4b3f9e799905e706861c381f2cf062daa819b
SR_PHASE=entry

sr_dir() {
    local p=$1 mode meta
    while [[ $p != / ]]; do
        [[ -d $p && ! -L $p ]] || return 1
        meta=$(stat -c %u:%g:%a -- "$p") || return 1
        if [[ $p == "$SR_VOLUME" ]]; then [[ $meta == 999:999:770 ]] || return 1
        else
            [[ $(stat -c %u:%g -- "$p") == 0:0 ]] || return 1
            mode=${meta##*:}; (( (8#$mode & 0022)==0 )) || return 1
        fi
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
sr_file() {
    local p=$1 mode=$2 maximum=$3
    sr_dir "${p%/*}" || return 1
    [[ -f $p && ! -L $p && $(stat -c %u:%g:%a:%h -- "$p") == "0:0:$mode:1" &&
       $(stat -c %s -- "$p") -le $maximum ]]
}
sr_hash() { local value; value=$(sha256sum -- "$1") || return 1; printf '%s\n' "${value%% *}"; }
sr_meta() { stat -c %d:%i:%s:%u:%g:%a:%h:%y:%z -- "$1"; }
sr_run() {
    set -euo pipefail
    umask 077
    local lockmeta work status_before status_hash prior= observed current age
    local parent before bytes linebytes after prefix
    SR_WORK=
    trap 'rc=$?; [[ -z ${SR_WORK:-} ]] || rm -rf -- "$SR_WORK"; if ((rc)); then printf "{\"schema_version\":1,\"status\":\"relay_unavailable\",\"phase\":\"%s\"}\n" "$SR_PHASE" >&2; fi' EXIT
    SR_PHASE=metadata
    sr_dir "$SR_STATE"; [[ $(stat -c %a "$SR_STATE") == 700 ]]
    sr_file "$SR_LIB/status-b.jq" 400 8192
    [[ $(sr_hash "$SR_LIB/status-b.jq") == "$SR_VALIDATOR_SHA" ]]
    # Installer creates these fixed files; this worker never creates a log or
    # lock through a manager-writable pathname.
    sr_file "$SR_STATE/.relay.lock" 600 0
    exec 8<>"$SR_STATE/.relay.lock"
    lockmeta=$(stat -c %d:%i "$SR_STATE/.relay.lock")
    [[ $(stat -Lc %d:%i /proc/self/fd/8) == "$lockmeta" ]]
    flock -n 8
    work=$(mktemp -d "$SR_STATE/.relay.XXXXXXXX")
    SR_WORK=$work
    SR_PHASE=status
    sr_file "$SR_STATE/status.json" 600 4096
    status_before=$(sr_meta "$SR_STATE/status.json")
    dd if="$SR_STATE/status.json" of="$work/status.json" iflag=nofollow,nonblock,count_bytes count=4097 status=none
    [[ $(sr_meta "$SR_STATE/status.json") == "$status_before" ]]
    jq -sce 'select(length==1)|.[0]' "$work/status.json" > "$work/one.json"
    jq -cSe -f "$SR_LIB/status-b.jq" "$work/one.json" > "$work/canonical.json"
    cmp -s -- "$work/status.json" "$work/canonical.json"
    status_hash=$(sr_hash "$work/status.json")
    observed=$(jq -er .observed_at_utc "$work/status.json")
    observed=$(date -u -d "$observed" +%s)
    current=$(date -u +%s); age=$(( current-observed ))
    (( age>=0 && age<=120 ))
    if [[ -e $SR_STATE/relay-last.sha256 || -L $SR_STATE/relay-last.sha256 ]]; then
        sr_file "$SR_STATE/relay-last.sha256" 600 65
        [[ $(stat -c %s "$SR_STATE/relay-last.sha256") == 65 ]]
        read -r prior < "$SR_STATE/relay-last.sha256"
        [[ $prior =~ ^[0-9a-f]{64}$ ]]
    fi
    if [[ $prior == "$status_hash" ]]; then
        printf '%s\n' '{"schema_version":1,"status":"already_relayed","appended":false}'
        return 0
    fi
    SR_PHASE=log_descriptor
    sr_file "$SR_LOG" 600 1048576
    parent=$(stat -c %d:%i:%u:%g:%a "$SR_VOLUME")
    before=$(sr_meta "$SR_LOG"); bytes=$(stat -c %s "$SR_LOG")
    # Read-only open cannot truncate/create. Check named inode and FD before
    # any write. Only the verified FD magic-link is later reopened for append;
    # a substituted pathname is never used as the write destination.
    exec 9<"$SR_VOLUME"
    exec 4<"$SR_LOG"
    [[ $(stat -Lc %d:%i:%u:%g:%a /proc/self/fd/9) == "$parent" ]]
    [[ -f /proc/self/fd/4 && $(stat -Lc %d:%i /proc/self/fd/4) == "$(stat -c %d:%i "$SR_LOG")" ]]
    sr_file "$SR_LOG" 600 1048576
    [[ $(sr_meta "$SR_LOG") == "$before" ]]
    [[ $bytes == 0 || $(tail -c 1 /proc/self/fd/4 | od -An -t x1 | tr -d '[:space:]') == 0a ]]
    prefix=$(sr_hash /proc/self/fd/4)
    printf '%s groot-b capstone-storage: %s\n' "$(date '+%b %e %H:%M:%S')" "$(cat "$work/status.json")" > "$work/line"
    linebytes=$(stat -c %s "$work/line")
    (( linebytes>0 && linebytes<=4352 && bytes+linebytes<=1048576 ))
    SR_PHASE=append
    dd if="$work/line" of=/proc/self/fd/4 oflag=append conv=notrunc status=none
    sync -- /proc/self/fd/4
    # A manager-writable volume can rename a child; failure remains visible,
    # and does not authorize a fresh append/retry or a different destination.
    sr_file "$SR_LOG" 600 1048576
    [[ $(stat -c %d:%i:%u:%g:%a "$SR_VOLUME") == "$parent" &&
       $(stat -Lc %d:%i:%u:%g:%a /proc/self/fd/9) == "$parent" &&
       $(stat -Lc %d:%i /proc/self/fd/4) == "$(stat -c %d:%i "$SR_LOG")" &&
       $(stat -c %s "$SR_LOG") == "$((bytes+linebytes))" ]]
    after=$(dd if=/proc/self/fd/4 iflag=count_bytes count="$bytes" status=none | sha256sum)
    [[ ${after%% *} == "$prefix" ]]
    SR_PHASE=receipt
    printf '%s\n' "$status_hash" > "$work/relay-last.sha256"
    chmod 600 "$work/relay-last.sha256"; sync -- "$work/relay-last.sha256"
    if [[ -n $prior ]]; then
        sr_file "$SR_STATE/relay-last.sha256" 600 65
        [[ $(cat "$SR_STATE/relay-last.sha256") == "$prior" ]]
    else [[ ! -e $SR_STATE/relay-last.sha256 && ! -L $SR_STATE/relay-last.sha256 ]]; fi
    mv -T -- "$work/relay-last.sha256" "$SR_STATE/relay-last.sha256"
    sync -- "$SR_STATE/relay-last.sha256" "$SR_STATE"
    printf '{"schema_version":1,"status":"relayed","appended":true,"bytes_appended":%d,"status_sha256":"%s"}\n' "$linebytes" "$status_hash"
}
sr_main() {
    [[ $# == 0 && $EUID == 0 && $OSTYPE == linux* &&
       $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || return 77
    sr_file "$SR_LIB/relay-b.sh" 500 16384 || return 77
    exec /usr/bin/timeout --signal=TERM --kill-after=2s 10s /usr/bin/env -i \
      PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
      /bin/bash --noprofile --norc -c '
        source /usr/local/lib/capstone-storage-monitor/relay-b.sh
        sr_run
      ' </dev/null
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then sr_main "$@"; fi
