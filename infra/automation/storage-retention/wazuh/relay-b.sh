#!/bin/bash
# Fixed B status metadata -> existing manager logs volume. No Docker/service
# commands, raw/CP reads, truncation, deletion, network or package operations.
SR_LIB=/usr/local/lib/capstone-storage-monitor
SR_STATE=/var/lib/capstone-storage-monitor
SR_VOLUME=/var/lib/docker/volumes/single-node_wazuh_logs/_data
SR_LOG=$SR_VOLUME/capstone-storage-b.log
SR_CHECKPOINT=/var/lib/docker/volumes/single-node_wazuh_queue/_data/logcollector/file_status.json
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
sr_rotate() {
    # The relay lock is held by sr_run. Preserve every byte before replacing
    # the old name; never truncate or discard an unconsumed file.
    local work=$1 before=$2 bytes=$3 parent=$4 fingerprint=$5 identity checkpoint directory
    SR_PHASE=rotation_checkpoint
    [[ -f $SR_CHECKPOINT && ! -L $SR_CHECKPOINT &&
       $(stat -c %s "$SR_CHECKPOINT") -le 65536 ]] || return 1
    checkpoint=$(sr_meta "$SR_CHECKPOINT")
    dd if="$SR_CHECKPOINT" of="$work/checkpoint.json" iflag=nofollow,nonblock,count_bytes count=65537 status=none
    [[ $(sr_meta "$SR_CHECKPOINT") == "$checkpoint" ]]
    # The installed Wazuh checkpoint at EOF hashes the whole consumed file.
    # Require both EOF and the full digest; a prefix match is insufficient.
    local prefix_sha1
    prefix_sha1=$(sha1sum /proc/self/fd/4)
    prefix_sha1=${prefix_sha1%% *}
    jq -e --arg bytes "$bytes" --arg hash "$prefix_sha1" '
      [.files[] | select(.path=="/var/ossec/logs/capstone-storage-b.log")]
      | length==1 and .[0].offset==$bytes and .[0].hash==$hash' "$work/checkpoint.json" >/dev/null
    [[ $(sr_meta "$SR_LOG") == "$before" &&
       $(stat -c %d:%i:%u:%g:%a "$SR_VOLUME") == "$parent" &&
       $(sr_hash /proc/self/fd/4) == "$fingerprint" ]]
    identity=$(stat -Lc %d:%i:%s:%u:%g:%a:%h /proc/self/fd/4)
    # A finite root-only archive is retained for review; no age-based deletion.
    local -a archives=("$SR_STATE"/relay-archive-*)
    [[ ! -e ${archives[0]} ]] || (( ${#archives[@]}<1024 ))
    directory=$(mktemp -d "$SR_STATE/relay-archive-XXXXXXXX")
    jq -ncS --arg sha256 "$fingerprint" --argjson bytes "$bytes" \
      '{schema:1,phase:"prepared",bytes:$bytes,sha256:$sha256,old_log_content_deleted:false}' > "$directory/receipt.json"
    cp -- "$work/checkpoint.json" "$directory/collector-checkpoint.json"
    sync -- "$directory/receipt.json" "$directory/collector-checkpoint.json" "$directory" "$SR_STATE"
    SR_PHASE=rotation_preserve
    sr_file "$SR_LOG" 600 1048576
    [[ $(sr_meta "$SR_LOG") == "$before" ]]
    # ProtectSystem/ReadWritePaths can put state and volume on separate bind
    # mounts, even with the same st_dev. Do not rely on rename across them.
    cp -- /proc/self/fd/4 "$directory/closed.log"
    [[ -f $directory/closed.log && ! -L $directory/closed.log &&
       $(stat -c %s:%u:%g:%a:%h "$directory/closed.log") == "$bytes:0:0:600:1" &&
       $(sr_hash "$directory/closed.log") == "$fingerprint" ]]
    sync -- "$directory/closed.log" "$directory"
    [[ $(sr_meta "$SR_LOG") == "$before" &&
       $(stat -Lc %d:%i:%s:%u:%g:%a:%h /proc/self/fd/4) == "$identity" &&
       $(stat -c %d:%i:%u:%g:%a "$SR_VOLUME") == "$parent" ]]
    # Only the fixed volume entry is unlinked after durable full-SHA backup.
    # No pathname is followed or used as a write destination here.
    /usr/bin/python3 -B -c '
import os, stat
old = os.fstat(4)
named = os.stat("capstone-storage-b.log", dir_fd=9, follow_symlinks=False)
assert stat.S_ISREG(named.st_mode) and named.st_uid == named.st_gid == 0
assert stat.S_IMODE(named.st_mode) == 0o600 and named.st_nlink == 1
assert (old.st_dev, old.st_ino, old.st_size) == (named.st_dev, named.st_ino, named.st_size)
os.unlink("capstone-storage-b.log", dir_fd=9)
os.fsync(9)
'
    SR_PHASE=rotation_new_log
    # noclobber uses exclusive creation. A manager-created name is never
    # overwritten, and subsequent writes still go through the verified FD.
    (set -o noclobber; : > "$SR_LOG")
    sr_file "$SR_LOG" 600 0
    [[ $(stat -c %d:%i:%u:%g:%a "$SR_VOLUME") == "$parent" ]]
    sync -- "$SR_LOG" "$SR_VOLUME"
    jq -ncS --arg sha256 "$fingerprint" --argjson bytes "$bytes" \
      '{schema:1,phase:"preserved_new_log_ready",bytes:$bytes,sha256:$sha256,old_log_content_deleted:false,old_name_unlinked:true}' > "$directory/receipt.json"
    sync -- "$directory/receipt.json" "$directory"
}
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
    (( linebytes>0 && linebytes<=4352 ))
    if (( bytes+linebytes>1048576 )); then
        sr_rotate "$work" "$before" "$bytes" "$parent" "$prefix"
        exec 4<&-
        exec 4<"$SR_LOG"
        sr_file "$SR_LOG" 600 0
        [[ $(stat -Lc %d:%i /proc/self/fd/4) == "$(stat -c %d:%i "$SR_LOG")" ]]
        before=$(sr_meta "$SR_LOG"); bytes=0; prefix=$(sr_hash /proc/self/fd/4)
    fi
    (( bytes+linebytes<=1048576 ))
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
