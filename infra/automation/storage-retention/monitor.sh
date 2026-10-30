#!/bin/bash
# Fixed A/B metadata observation. No raw/backup deletion, CP access, or service calls.
SM_ROOT=/usr/local/lib/capstone-storage-monitor
SM_SELF=$SM_ROOT/monitor.sh
SM_STATE=/var/lib/capstone-storage-monitor
SM_TIMEOUT=30s
SM_LIB_SHA=f18839b72581599cc2418889450b966e36671e31358812babe4f0ca508b923cc
SM_POLICY_SHA=0c6f43d05eca8b0355b833dbbc54a1c3ccefff6fda49995c64105308c30bd37d
sm_dir() {
    local p=$1 mode
    while [[ $p != / ]]; do
        [[ -d $p && ! -L $p && $(stat -c %u:%g -- "$p") == 0:0 ]] || return 1
        mode=$(stat -c %a -- "$p") || return 1
        (( (8#$mode & 0022)==0 )) || return 1
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
sm_file() {
    local path=$1 mode=$2 maximum=$3
    sm_dir "${path%/*}" || return 1
    [[ -f $path && ! -L $path && $(stat -c %u:%g:%a:%h -- "$path") == "0:0:$mode:1" &&
       $(stat -c %s -- "$path") -gt 0 && $(stat -c %s -- "$path") -le $maximum ]] || return 1
}
sm_hash() { local value; value=$(sha256sum -- "$1") || return 1; printf '%s\n' "${value%% *}"; }
sm_unknown() {
    printf '%s\n' '{"available_bytes":null,"backup_bytes":null,"backup_review_due_count":null,"history_bytes":null,"raw_archive_review_due_count":null,"raw_bytes":null,"scan_status":"unavailable","used_percent":null}' > "$1/measurements.json" || return 1
    printf '%s\n' '{"archive_authorized":false,"automatic_deletion":false,"checkpoint_changed":false,"inventory_status":"unavailable","referenced_backups_always_protected":true,"schema_version":1}' > "$1/inventory.json"
}
sm_collect() {
    local host=$1 machine=$2 work=$3 observed rc=0
    # A process-group timeout also bounds find/du/df descendants. A 1MiB file
    # ceiling prevents unbounded metadata output; all diagnostics stay private.
    /usr/bin/timeout --signal=TERM --kill-after=2s "$SM_TIMEOUT" /usr/bin/env -i \
      PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
      /bin/bash --noprofile --norc "$SM_ROOT/monitor-lib.sh" "$host" "$work" \
      </dev/null > "$work/worker.stdout" 2> "$work/worker.stderr" || rc=$?
    if (( rc!=0 )) || [[ ! -f $work/measurements.json || ! -f $work/inventory.json ]] ||
       [[ $(stat -c %s "$work/measurements.json") -gt 4096 || $(stat -c %s "$work/inventory.json") -gt 16384 ]]; then
        sm_unknown "$work" || return 1
    fi
    if ! jq -se 'length==1 and (.[0]|type=="object")' "$work/measurements.json" >/dev/null 2>&1 ||
       ! jq -se 'length==1 and (.[0]|type=="object" and .schema_version==1 and .automatic_deletion==false and .checkpoint_changed==false and .archive_authorized==false and .referenced_backups_always_protected==true)' "$work/inventory.json" >/dev/null 2>&1; then
        sm_unknown "$work" || return 1
    fi
    observed=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
    if ! jq -cSe --arg machine "$machine" --arg host "$host" --arg observed "$observed" \
        -f "$SM_ROOT/policy.jq" "$work/measurements.json" > "$work/result.json"; then
        sm_unknown "$work" || return 1
        jq -cSe --arg machine "$machine" --arg host "$host" --arg observed "$observed" \
          -f "$SM_ROOT/policy.jq" "$work/measurements.json" > "$work/result.json" || return 1
    fi
    # Inventory is supplementary and cannot supply an eligibility/deletion claim.
    jq -cSe 'select(type=="object" and .schema_version==1 and
      .automatic_deletion==false and .checkpoint_changed==false and
      .archive_authorized==false and .referenced_backups_always_protected==true)' \
      "$work/inventory.json" > "$work/inventory.canonical.json" || return 1
    [[ $(wc -l < "$work/result.json") == 1 && $(stat -c %s "$work/result.json") -le 4096 &&
       $(wc -l < "$work/inventory.canonical.json") == 1 ]] || return 1
}
sm_publish() {
    local source=$1 name=$2 dest="$SM_STATE/$2" before=absent after
    [[ $name == status.json || $name == inventory.json ]] || return 1
    if [[ -e $dest || -L $dest ]]; then
        sm_file "$dest" 600 16384 || return 1
        before=$(stat -c %d:%i:%s:%y:%z -- "$dest") || return 1
    fi
    chmod 600 -- "$source" || return 1
    sync -- "$source" || return 1
    if [[ $before == absent ]]; then [[ ! -e $dest && ! -L $dest ]] || return 1
    else
        sm_file "$dest" 600 16384 || return 1
        after=$(stat -c %d:%i:%s:%y:%z -- "$dest") || return 1
        [[ $before == "$after" ]] || return 1
    fi
    mv -T -- "$source" "$dest" || return 1
    sync -- "$dest" "$SM_STATE" || return 1
}
sm_entry() {
    set -euo pipefail
    umask 077
    ulimit -f 1024
    local operation=$1 host=$2 machine=$3 work output lockmeta
    sm_dir "$SM_STATE" || return 77
    [[ $(stat -c %a "$SM_STATE") == 700 ]] || return 77
    if [[ -e $SM_STATE/.lock || -L $SM_STATE/.lock ]]; then
        [[ -f $SM_STATE/.lock && ! -L $SM_STATE/.lock && $(stat -c %u:%g:%a:%h "$SM_STATE/.lock") == 0:0:600:1 ]] || return 77
    fi
    exec 8<>"$SM_STATE/.lock"
    flock -n 8 || return 75
    lockmeta=$(stat -c %d:%i "$SM_STATE/.lock")
    [[ $(stat -Lc %d:%i /proc/self/fd/8) == "$lockmeta" ]] || return 77
    work=$(mktemp -d "$SM_STATE/.scan.XXXXXXXX")
    SM_WORK=$work
    # Only this call's mkdtemp scratch is removed; retention paths are never targets.
    trap '[[ -z ${SM_WORK:-} ]] || rm -rf -- "$SM_WORK"' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    sm_collect "$host" "$machine" "$work"
    if [[ $operation == run ]]; then
        sm_publish "$work/inventory.canonical.json" inventory.json
        sm_publish "$work/result.json" status.json
        output=$(cat "$SM_STATE/status.json")
        logger --tag capstone-storage --priority daemon.notice -- "$output"
    else output=$(cat "$work/result.json"); fi
    printf '%s\n' "$output"
    # Warning/critical are successful observations. Unknown remains visible in
    # the unit result as well as the JSON even when known critical takes priority.
    jq -e '.scan_status=="complete"' <<< "$output" >/dev/null || return 2
}
sm_main() {
    [[ $# == 1 && ($1 == run || $1 == check) && $EUID == 0 && $(uname -s) == Linux ]] || return 77
    local machine host
    machine=$(cat /etc/machine-id) || return 77
    case "$machine" in
      096e90b6243e438aa8a7b392be754732) host=a ;;
      1e143067c98a44ffba6eaa925dc038d7) host=b ;;
      *) return 77 ;;
    esac
    [[ ${BASH_SOURCE[0]} == "$SM_SELF" ]] || return 77
    sm_file "$SM_SELF" 500 32768 && sm_file "$SM_ROOT/monitor-lib.sh" 400 32768 &&
      sm_file "$SM_ROOT/policy.jq" 400 8192 || return 77
    [[ $(sm_hash "$SM_ROOT/monitor-lib.sh") == "$SM_LIB_SHA" &&
       $(sm_hash "$SM_ROOT/policy.jq") == "$SM_POLICY_SHA" ]] || return 77
    exec /usr/bin/timeout --signal=TERM --kill-after=2s 40s /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=Asia/Seoul \
      /bin/bash --noprofile --norc -c 'source /usr/local/lib/capstone-storage-monitor/monitor.sh; sm_entry "$@"' monitor "$1" "$host" "$machine"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then set -euo pipefail; sm_main "$@"; fi
