#!/bin/bash
# Fixed-path worker or sourced private native fixture. Metadata reads only.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul
st_uint() { [[ $1 =~ ^(0|[1-9][0-9]{0,15})$ ]] && (( 10#$1<=9007199254740991 )); }
st_ancestors() {
    local p=$1
    [[ $p == /* && $p != *'/../'* && $p != *$'\n'* ]] || return 1
    while [[ $p != / ]]; do [[ -d $p && ! -L $p ]] || return 1; p=${p%/*}; [[ -n $p ]] || p=/; done
}
st_tree() {
    # No symlink following, no payload read. An unreadable/incomplete inventory
    # is unknown, never a zero-size successful scan. Scope is one filesystem.
    local work=$1 path=$2 count value before after
    st_ancestors "$path" || return 1
    before=$(stat -c %d:%i:%u:%g:%a:%y:%z -- "$path") || return 1
    if ! find "$path" -xdev -printf '%y\n' | head -n 100001 > "$work/types"; then return 1; fi
    count=$(wc -l < "$work/types") || return 1
    (( count<100001 )) || return 1
    if grep -qvE '^[df]$' "$work/types"; then return 1; fi
    value=$(du -xsb -- "$path") || return 1
    value=${value%%$'\t'*}
    st_uint "$value" || return 1
    st_ancestors "$path" || return 1
    after=$(stat -c %d:%i:%u:%g:%a:%y:%z -- "$path") || return 1
    [[ $before == "$after" ]] || return 1
    printf '%s\n' "$value"
}
st_disk() {
    local text value percent rest available=9007199254740991 used=0 count=0
    text=$(df -B1 --output=avail,pcent -- "$@") || return 1
    while read -r value percent rest; do
        [[ $value == Avail ]] && continue
        [[ -z ${rest:-} && $percent =~ ^(0|[1-9][0-9]*)%$ ]] || return 1
        st_uint "$value" || return 1; percent=${percent%%%}
        (( percent<=100 )) || return 1
        if (( value<available )); then available=$value; fi
        if (( percent>used )); then used=$percent; fi
        count=$((count+1))
    done <<< "$text"
    (( count>0 )) || return 1
    printf '%s %s\n' "$available" "$used"
}
st_backup_list() {
    local base=$1 p name
    st_ancestors "$base" || return 1
    shopt -s nullglob
    local paths=("$base"/capstone-*)
    (( ${#paths[@]}<=64 )) || return 1
    for p in "${paths[@]}"; do
        name=${p##*/}
        [[ $name =~ ^capstone-[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ && -d $p && ! -L $p && $(stat -c %u "$p") == 0 ]] || return 1
        printf '%s\n' "$p"
    done
}
st_state() {
    local file=$1 engine=$2 raw canonical
    st_ancestors "${file%/*}" || return 1
    [[ -f $file && ! -L $file && $(stat -c %u:%g:%a:%h "$file") == 0:0:600:1 && $(stat -c %s "$file") -le 16384 ]] || return 1
    raw=$(cat -- "$file") || return 1
    jq -se 'length==1 and (.[0]|type=="object")' <<< "$raw" >/dev/null || return 1
    canonical=$(jq -cS . <<< "$raw") || return 1
    [[ $raw == "$canonical" ]] || return 1
    cmp -s <(printf '%s\n' "$canonical") "$file" || return 1
    jq -ce --arg engine "$engine" '
      select(type=="object" and .schema_version==1 and .policy=="capstone-raw-operations-v1" and
        .engine==$engine and .machine_id=="096e90b6243e438aa8a7b392be754732" and
        (.phase|IN("active","switch_pending","old_closed","readers_drained","publish_pending")) and
        (.current.number|type=="number" and floor==. and .>=0 and .<=4294967295) and
        (.pending==null or (.pending.number|type=="number" and floor==. and .>=0 and .<=4294967295)))
      | {current:.current.number,pending:(.pending.number//null),phase,revision}' <<< "$raw"
}
st_raw_review() {
    local dir=$1 state=$2 engine=$3 cutoff=$4 inventory=$5 before after file name number metadata uid gid mode links size mtime count=0
    before=$(st_state "$state" "$engine") || return 1
    : > "$inventory" || return 1
    shopt -s nullglob
    local paths=("$dir"/generation-*.jsonl)
    (( ${#paths[@]}<=1024 )) || return 1
    for file in "${paths[@]}"; do
        name=${file##*/}
        [[ $name =~ ^generation-([0-9]{10})\.jsonl$ && -f $file && ! -L $file ]] || return 1
        number=$((10#${BASH_REMATCH[1]}))
        metadata=$(stat -c '%u %g %a %h %s %Y' -- "$file") || return 1
        read -r uid gid mode links size mtime <<< "$metadata"
        st_uint "$size" && st_uint "$mtime" || return 1
        # This is a review queue, NOT proof of drain, FD closure or remote ACK.
        if [[ $uid:$gid:$mode:$links == 0:0:400:1 ]] && (( mtime<=cutoff )) &&
           jq -e --argjson n "$number" '.current!=$n and .pending!=$n' <<< "$before" >/dev/null; then
            count=$((count+1))
            jq -nc --arg engine "$engine" --argjson number "$number" --argjson bytes "$size" \
                --argjson mtime "$mtime" '{engine:$engine,generation:$number,bytes:$bytes,mtime_epoch:$mtime,
                sealed_metadata:true,archive_authorized:false,delete_authorized:false}' >> "$inventory" || return 1
        fi
    done
    after=$(st_state "$state" "$engine") || return 1
    [[ $before == "$after" ]] || return 1
    printf '%s\n' "$count"
}
st_worker() {
    local host=$1 work=$2 machine observed now cutoff errors=0 raw=0 backups=0 history=0 due=0 review=0 disk available=null used=null value path lists rawreview=null
    local -a raws=() histories=() disks=(/var/backups) backup_paths=()
    case "$host" in
      a) machine=096e90b6243e438aa8a7b392be754732
         raws=(/home/groot_a/capstone/secstack/logs/suricata/capstone-managed /home/groot_a/capstone/secstack/logs/modsec/capstone-managed)
         histories=(/var/lib/capstone-vector-history-auto/store /var/lib/capstone-vector-history)
         # A shared lock gives a stable generation selection; a busy coordinator
         # causes an unavailable observation, never any stop/start operation.
         [[ -f /var/lib/capstone-automation/ansible/vector.lock && ! -L /var/lib/capstone-automation/ansible/vector.lock &&
            $(stat -c %u:%g:%a:%h /var/lib/capstone-automation/ansible/vector.lock) == 0:0:600:1 ]] || return 1
         exec 9</var/lib/capstone-automation/ansible/vector.lock
         flock -sn 9 || return 1
         ;;
      b) machine=1e143067c98a44ffba6eaa925dc038d7; histories=(/var/lib/capstone-history-receipts); rawreview=0 ;;
      *) return 1 ;;
    esac
    now=$(date +%s) || return 1
    observed=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
    if [[ $host == a ]]; then cutoff=$((now-30*86400)); else cutoff=$((now-90*86400)); fi
    for path in "${raws[@]}"; do
        disks+=("$path")
        if value=$(st_tree "$work" "$path"); then if (( raw>=0 )); then raw=$((raw+value)); fi; else raw=-1; errors=$((errors+1)); fi
    done
    for path in "${histories[@]}"; do
        disks+=("$path")
        if value=$(st_tree "$work" "$path"); then if (( history>=0 )); then history=$((history+value)); fi; else history=-1; errors=$((errors+1)); fi
    done
    if lists=$(st_backup_list /var/backups); then
        while IFS= read -r path; do [[ -n $path ]] && backup_paths+=("$path"); done <<< "$lists"
        for path in "${backup_paths[@]}"; do
            disks+=("$path")
            if value=$(st_tree "$work" "$path"); then if (( backups>=0 )); then backups=$((backups+value)); fi; else backups=-1; errors=$((errors+1)); fi
            if value=$(stat -c %Y -- "$path") && st_uint "$value"; then
                if (( due>=0 && value<=cutoff )); then due=$((due+1)); fi
            else due=-1; errors=$((errors+1)); fi
        done
    else backups=-1; due=-1; errors=$((errors+1)); fi
    if disk=$(st_disk "${disks[@]}"); then read -r available used <<< "$disk"; else errors=$((errors+1)); fi
    : > "$work/raw-review.jsonl"
    if [[ $host == a ]]; then
        if value=$(st_raw_review "${raws[0]}" /var/lib/capstone-raw-operations/suricata/state.json suricata "$cutoff" "$work/suri-review.jsonl") &&
           rawreview=$value && value=$(st_raw_review "${raws[1]}" /var/lib/capstone-raw-operations/modsecurity/state.json modsecurity "$cutoff" "$work/waf-review.jsonl"); then
            rawreview=$((rawreview+value))
            cat "$work/suri-review.jsonl" "$work/waf-review.jsonl" > "$work/raw-review.jsonl" || return 1
        else rawreview=null; errors=$((errors+1)); fi
    fi
    if (( raw<0 )); then raw=null; fi
    if (( backups<0 )); then backups=null; fi
    if (( history<0 )); then history=null; fi
    if (( due<0 )); then due=null; fi
    local scan=complete; if (( errors>0 )); then scan=unavailable; fi
    jq -nc --arg scan "$scan" --argjson used "$used" --argjson available "$available" \
      --argjson raw "$raw" --argjson backups "$backups" --argjson history "$history" \
      --argjson review "$rawreview" --argjson due "$due" '{used_percent:$used,available_bytes:$available,
       raw_bytes:$raw,backup_bytes:$backups,history_bytes:$history,raw_archive_review_due_count:$review,
       backup_review_due_count:$due,scan_status:$scan}' > "$work/measurements.json" || return 1
    # Keep the inventory small even after many years; counts remain complete.
    head -n 32 "$work/raw-review.jsonl" | jq -sc --arg host "$host" --argjson total "${rawreview:-null}" \
      '{schema_version:1,host:$host,raw_review_rows:.,raw_review_total:$total,
        all_capstone_backups_protected:true,referenced_backups_always_protected:true,
        archive_authorized:false,automatic_deletion:false,checkpoint_changed:false}' > "$work/inventory.json"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    [[ $# == 2 ]] || exit 64
    st_worker "$1" "$2"
fi
