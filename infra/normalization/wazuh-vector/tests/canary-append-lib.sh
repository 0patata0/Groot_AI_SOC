# Internal helper: caller validates the fixed operational path and holds flock
# on its append-only descriptor 9. This file grants no privilege and is not a
# standalone command. Synthetic fixtures exercise it on their own private file.
capstone_canary_append() {
    local path=$1 payload=$2 mode=$3 identity=$4 bytes rows start end hash copied_hash copied_rows pause
    [[ $mode == paced || $mode == burst ]] || return 64
    [[ -f $payload && ! -L $payload ]] || return 65
    bytes=$(wc -c < "$payload") || return 1
    rows=$(wc -l < "$payload") || return 1
    [[ $rows == 13 && $bytes -gt 0 && $bytes -le 32768 ]] || return 65
    [[ $(stat -c '%d:%i' "$path") == "$identity" &&
       $(stat -Lc '%d:%i' /proc/$$/fd/9) == "$identity" ]] || return 65
    start=$(stat -c %s "$path") || return 1
    [[ $start -le 10485760 ]] || return 65
    hash=$(sha256sum "$payload") || return 1
    hash=${hash%% *}
    pause=0
    if [[ $mode == paced ]]; then
        head -n 6 "$payload" >&9 || return 1
        sync -f "$path" || return 1
        sleep 3 || return 1
        [[ $(stat -c '%d:%i' "$path") == "$identity" ]] || return 65
        tail -n 7 "$payload" >&9 || return 1
        pause=3
    else
        cat "$payload" >&9 || return 1
    fi
    sync -f "$path" || return 1
    [[ $(stat -c '%d:%i' "$path") == "$identity" &&
       $(stat -Lc '%d:%i' /proc/$$/fd/9) == "$identity" ]] || return 65
    end=$(stat -c %s "$path") || return 1
    [[ $end -eq $((start+bytes)) ]] || return 65
    copied_hash=$(dd if="$path" iflag=skip_bytes,count_bytes skip="$start" count="$bytes" status=none | sha256sum) || return 1
    copied_hash=${copied_hash%% *}
    copied_rows=$(dd if="$path" iflag=skip_bytes,count_bytes skip="$start" count="$bytes" status=none | wc -l) || return 1
    [[ $copied_hash == "$hash" && $copied_rows == 13 ]] || return 65
    jq -cn --arg mode "$mode" --arg hash "$hash" --arg identity "$identity" \
      --argjson bytes "$bytes" --argjson start "$start" --argjson end "$end" --argjson pause "$pause" \
      '{delivery_mode:$mode,synthetic_rows_appended:13,bytes:$bytes,payload_sha256:$hash,
        append_start_bytes:$start,append_end_bytes:$end,file_device_inode:$identity,
        append_readback_sha_and_rows_verified:true,cross_pair_pause_seconds:$pause,
        source_file_sync_completed:true,source_sync_is_not_analysis_ack:true}'
}
