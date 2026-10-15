#!/bin/bash
# Root-only glue around systemd/logrotate. No raw events are printed or deleted here.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
state=/var/lib/capstone-vector-maintenance
ready=/var/log/capstone-vector/ready/normalized.jsonl
evidence=/var/log/capstone-vector/evidence/normalized.jsonl
quarantine=/var/log/capstone-vector/quarantine/quarantine.jsonl
telemetry=/var/log/capstone-vector/telemetry/health.jsonl
raw_line_state=$state/raw-lines.json
pending=$state/resume.pending
service=capstone-vector.service
operation=${1:-run}
[[ $# -le 1 && $(id -u) == 0 ]] || exit 77
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
case "$operation" in run|check|prepare|finish|force) ;; *) exit 64 ;; esac
for directory in "$state" /var/log/capstone-vector /var/log/capstone-vector/ready /var/log/capstone-vector/evidence /var/log/capstone-vector/quarantine /var/log/capstone-vector/telemetry; do
    [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || exit 77
    mode=$(stat -c %a "$directory")
    (( (8#$mode & 0022) == 0 )) || exit 77
done
for file in "$ready" "$evidence" "$quarantine" "$telemetry" "$pending" "$raw_line_state"; do
    if [[ -e $file || -L $file ]]; then
        [[ -f $file && ! -L $file && $(stat -c %u "$file") == 0 && $(stat -c %h "$file") == 1 ]] || exit 77
    fi
done

report() { logger -t capstone-vector-storage -p "daemon.$1" -- "status=$2"; }

# Periodic observation of a fixed, bounded raw tail. This does not advance a
# source checkpoint, measure delivered/lost events, or scan every historical byte.
raw_line_unavailable() {
    jq -nc --arg reason "$1" --arg at "$(TZ=Asia/Seoul date --iso-8601=seconds)" \
        '{schema_version:1,scope:"periodic_snapshot_tail",observed_at_kst:$at,
          binding_verified:false,failure_code:$reason,sources:[],
          statuses:["collection_raw_line_scan_unavailable"]}'
}

raw_line_runtime_hashes() {
    local directory file mode hash
    for directory in /etc /etc/capstone-vector /usr/local /usr/local/sbin; do
        [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || return 1
        mode=$(stat -c %a "$directory") || return 1
        (( (8#$mode & 0022) == 0 )) || return 1
    done
    for file in /etc/capstone-vector/vector.toml /etc/capstone-vector/vector.env /etc/capstone-vector/raw-line-binding.json; do
        [[ -f $file && ! -L $file && $(stat -c '%u:%h:%a' "$file") == 0:1:600 ]] || return 1
        [[ $(stat -c %s "$file") -le 1048576 ]] || return 1
        hash=$(sha256sum -- "$file") || return 1
        printf '%s\n' "${hash%% *}"
    done
    for file in /etc/capstone-vector/line-length-lib.sh /etc/capstone-vector/raw-line-status.jq /usr/local/sbin/capstone-vector-raw-lines; do
        [[ -f $file && ! -L $file && $(stat -c '%u:%h' "$file") == 0:1 ]] || return 1
        mode=$(stat -c %a "$file") || return 1
        (( (8#$mode & 0022) == 0 )) || return 1
    done
}

raw_line_snapshot() {
    local before after binding config_sha env_sha binding_sha result statuses projected
    local LC_ALL=C
    if ! before=$(raw_line_runtime_hashes 2>/dev/null); then
        raw_line_unavailable runtime_binding_unavailable; return
    fi
    if ! binding=$(jq -sce 'select(length==1) | .[0] | select(type=="object" and
          keys==["policy","schema_version","vector_config_sha256","vector_env_sha256"] and
          .schema_version==1 and .policy=="periodic-snapshot-tail-v1" and
          (.vector_config_sha256|type=="string" and test("^[a-f0-9]{64}$")) and
          (.vector_env_sha256|type=="string" and test("^[a-f0-9]{64}$")))' \
          /etc/capstone-vector/raw-line-binding.json 2>/dev/null); then
        raw_line_unavailable runtime_binding_invalid; return
    fi
    { read -r config_sha; read -r env_sha; read -r binding_sha; } <<< "$before"
    if ! jq -e --arg config "$config_sha" --arg environment "$env_sha" \
        '.vector_config_sha256==$config and .vector_env_sha256==$environment' <<< "$binding" >/dev/null 2>&1; then
        raw_line_unavailable runtime_binding_mismatch; return
    fi
    # Source workers are each bounded; the outer deadline also covers the wrapper.
    # Only a bounded metadata response is captured. Scanner stderr is never logged.
    if ! result=$(/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
          /usr/bin/timeout --signal=TERM --kill-after=2s 30s \
          /usr/local/sbin/capstone-vector-raw-lines check 2>/dev/null | head -c 16385) ||
       (( ${#result} > 16384 )); then
        raw_line_unavailable scanner_failed_or_response_limit; return
    fi
    if ! result=$(jq -sce 'select(length==1) | .[0]' <<< "$result" 2>/dev/null); then
        raw_line_unavailable scanner_metadata_invalid; return
    fi
    if ! statuses=$(jq -ce -f /etc/capstone-vector/raw-line-status.jq <<< "$result" 2>/dev/null) ||
       ! jq -e 'type=="array" and length<=2 and (unique|length)==length and
          all(.[];.=="collection_raw_line_oversize_seen" or .=="collection_raw_line_scan_unavailable")' \
          <<< "$statuses" >/dev/null 2>&1; then
        raw_line_unavailable scanner_metadata_invalid; return
    fi
    # Explicit field projection prevents arbitrary scanner text from becoming
    # a check result or durable health record, even on a malformed response.
    if ! projected=$(jq -ce --argjson statuses "$statuses" \
          'select(.schema_version==1 and .scope=="periodic_snapshot_tail" and
             (.observed_at_kst|type=="string" and test("^[0-9T:+.-]+\\+09:00$")) and
             (.sources|type=="array" and length==3) and
             ([.sources[].source]|sort)==["suricata","waf_access","waf_audit"] and
             all(.sources[];
               (.verdict|IN("oversize","within_scanned_range","inconclusive")) and
               (.reason|IN("source_unavailable","metadata_mismatch","open_identity_changed",
                 "scanner_output_invalid","file_changed","scan_error","limit_exceeded",
                 "range_within_limit","path_rejected","scan_timeout","scanner_failed")) and
               all([.observed_positive,.file_stable,.complete_snapshot_range,.full_file_scan][];type=="boolean") and
               (.leading_fragment_possible==null or (.leading_fragment_possible|type=="boolean")) and
               all([.range_start,.range_end,.snapshot_bytes,.scanned_bytes,.max_line_bytes,
                    .line_limit_bytes,.scan_budget_bytes,.timeout_seconds][];
                   .==null or (type=="number" and floor==. and .>=0)))) |
           {schema_version,scope,observed_at_kst,binding_verified:true,statuses:$statuses,
            sources:[.sources[]|{source,verdict,reason,observed_positive,file_stable,
              complete_snapshot_range,full_file_scan,leading_fragment_possible,
              range_start,range_end,snapshot_bytes,scanned_bytes,max_line_bytes,
              line_limit_bytes,scan_budget_bytes,timeout_seconds}]}' <<< "$result" 2>/dev/null); then
        raw_line_unavailable scanner_metadata_invalid; return
    fi
    if ! after=$(raw_line_runtime_hashes 2>/dev/null) || [[ $after != "$before" ]]; then
        jq -c '.binding_verified=false | .failure_code="runtime_binding_changed" |
           .statuses=(.statuses+["collection_raw_line_scan_unavailable"]|unique)' <<< "$projected"
        return
    fi
    printf '%s\n' "$projected"
}

save_raw_line_snapshot() {
    local result=$1 temporary
    if [[ -e $raw_line_state || -L $raw_line_state ]]; then
        [[ -f $raw_line_state && ! -L $raw_line_state && $(stat -c '%u:%h:%a' "$raw_line_state") == 0:1:600 ]] || return 1
    fi
    temporary=$(mktemp "$state/.raw-lines.XXXXXX") || return 1
    if ! printf '%s\n' "$result" > "$temporary" || ! sync -f "$temporary" ||
       ! mv -T -- "$temporary" "$raw_line_state"; then
        rm -f -- "$temporary"; return 1
    fi
    sync -f "$state"
}

# This is current-invocation health, not a loss ledger or an ACK receipt.
# No counter delta state is stored. Wazuh bounds repeated low-level notices.
collection_statuses() {
    local now pid invocation started_text started result
    if ! systemctl is-active --quiet "$service"; then printf '[]\n'; return; fi
    now=$(date +%s)
    pid=$(systemctl show "$service" -p MainPID --value)
    invocation=$(systemctl show "$service" -p InvocationID --value)
    started_text=$(LC_ALL=C systemctl show "$service" -p ExecMainStartTimestamp --value --timestamp=unix)
    if [[ ! $pid =~ ^[1-9][0-9]*$ || ! $invocation =~ ^[a-f0-9]{32}$ ]] ||
       ! started=$(date -d "$started_text" +%s 2>/dev/null); then
        printf '["collection_telemetry_invalid"]\n'; return
    fi
    if [[ ! -s $telemetry ]]; then
        if (( now-started < 180 )); then printf '[]\n'; else printf '["collection_telemetry_missing"]\n'; fi
        return
    fi
    # jq sees only metadata, and at most 1MiB. Its edge-fragment rule also
    # tolerates a concurrent unfinished final JSONL write without parsing it.
    if ! result=$(tail -c 1048576 "$telemetry" | jq -Rsc \
        --arg pid "$pid" --arg invocation "$invocation" \
        --argjson now "$now" --argjson started "$started" \
        -f /etc/capstone-vector/collection-health.jq 2>/dev/null); then
        printf '["collection_telemetry_invalid"]\n'; return
    fi
    printf '%s\n' "$result"
}

# Kernel FD position alone includes libc read-ahead. Require the native saved
# logical offset AND prefix SHA1 for nonempty files before rotating. This still
# does not acknowledge delivery to the manager/indexer or zero internal drops.
reader_at_eof() {
    local input_file=$1
    [[ -f $input_file ]] || return 0
    local identity size pid fd fd_identity pos entry logical_offset logical_hash actual_hash count=0
    identity=$(stat -c '%d:%i' "$input_file")
    size=$(stat -c '%s' "$input_file")
    while read -r pid; do
        [[ $pid =~ ^[0-9]+$ ]] || continue
        for fd in /proc/"$pid"/fd/[0-9]*; do
            [[ -e $fd ]] || continue
            fd_identity=$(stat -Lc '%d:%i' "$fd" 2>/dev/null) || continue
            [[ $fd_identity == "$identity" ]] || continue
            pos=$(awk '$1=="pos:" {print $2}' /proc/"$pid"/fdinfo/"${fd##*/}")
            [[ $pos =~ ^[0-9]+$ && $pos == "$size" ]] || return 1
            count=$((count+1))
        done
    done < <(pgrep -x wazuh-logcollec || true)
    [[ $count == 1 ]] || return 1
    [[ $size != 0 ]] || return 0
    entry=$(jq -er --arg path "$input_file" '[.files[] | select(.path==$path)] | if length==1 then .[0] | [.offset,.hash] | @tsv else error("ambiguous file state") end' /var/ossec/queue/logcollector/file_status.json 2>/dev/null) || return 1
    IFS=$'\t' read -r logical_offset logical_hash <<< "$entry"
    [[ $logical_offset == "$size" && $logical_hash =~ ^[a-f0-9]{40}$ ]] || return 1
    actual_hash=$(sha1sum "$input_file")
    [[ ${actual_hash%% *} == "$logical_hash" ]]
}

readers_at_eof() {
    reader_at_eof "$ready" && reader_at_eof "$evidence"
}

wait_reader() {
    local attempt
    # A currently persists native offsets every 64 seconds. Keep the bound
    # explicit and retry partial JSON reads; do not rewrite Wazuh's own state.
    for attempt in {1..90}; do
        if readers_at_eof; then return 0; fi
        sleep 1
    done
    report err reader_not_at_current_eof
    return 1
}

case "$operation" in
    prepare)
        [[ ${CAPSTONE_VECTOR_MAINTENANCE:-} == active ]] || exit 77
        systemctl is-active --quiet "$service"
        systemctl is-active --quiet wazuh-agent.service
        printf 'pending\n' > "$pending"
        systemctl stop "$service"
        [[ $(systemctl show "$service" -p MainPID --value) == 0 ]]
        for file in "$ready" "$evidence" "$quarantine" "$telemetry"; do [[ ! -f $file ]] || sync -f "$file"; done
        wait_reader
        if [[ -f $ready ]]; then
            stat -c '%d:%i %s' "$ready" > "$state/ready-before.stat"
            sha256sum "$ready" > "$state/ready-before.sha256"
        fi
        if [[ -f $evidence ]]; then
            stat -c '%d:%i %s' "$evidence" > "$state/evidence-before.stat"
            sha256sum "$evidence" > "$state/evidence-before.sha256"
        fi
        report notice writer_paused_reader_drained
        exit 0
        ;;
    finish)
        [[ ${CAPSTONE_VECTOR_MAINTENANCE:-} == active && -f $pending ]] || exit 77
        wait_reader
        report notice rotated_current_reader_ready
        exit 0
        ;;
esac

if [[ $operation == check ]]; then
    available=$(df -PB1 /var/log/capstone-vector | awk 'NR==2 {print $4}')
    percent=$(df -P /var/log/capstone-vector | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
    active=$(systemctl is-active "$service" || true)
    recovery=no
    [[ ! -f $pending ]] || recovery=pending
    collection=$(collection_statuses)
    raw_lines=$(raw_line_snapshot)
    printf 'storage_check=ok available_bytes=%s used_percent=%s vector=%s recovery=%s collection=%s raw_lines=%s\n' "$available" "$percent" "$active" "$recovery" "$collection" "$raw_lines"
    exit 0
fi

exec 9> /var/lib/capstone-automation/ansible/vector.lock
flock -n 9 || exit 75
exec 8> "$state/maintenance.lock"
flock -n 8 || exit 75

# A failed/interrupted rotation keeps this marker. Resume only after checking the
# current file, so the next timer recovers without truncating or discarding data.
if [[ -f $pending ]]; then
    if ! systemctl is-active --quiet "$service"; then
        wait_reader
        systemctl start "$service"
    fi
    systemctl is-active --quiet "$service"
    rm -- "$pending"
    report notice recovered_pending_rotation
fi

available=$(df -PB1 /var/log/capstone-vector | awk 'NR==2 {print $4}')
percent=$(df -P /var/log/capstone-vector | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
if ! systemctl is-active --quiet "$service"; then report err vector_not_active; fi
if (( available < 2147483648 || percent >= 90 )); then
    report err disk_space_critical
elif (( available < 5368709120 || percent >= 80 )); then
    report warning disk_space_low
fi
collection=$(collection_statuses)
while IFS= read -r status; do
    case "$status" in
        collection_telemetry_missing|collection_telemetry_stale|collection_telemetry_invalid|collection_error_seen|collection_loss_signal_seen|collection_buffer_pressure)
            report warning "$status" ;;
    esac
done < <(printf '%s' "$collection" | jq -r '.[]')
raw_lines=$(raw_line_snapshot)
if ! save_raw_line_snapshot "$raw_lines"; then
    report warning collection_raw_line_scan_unavailable
fi
while IFS= read -r status; do
    case "$status" in
        collection_raw_line_oversize_seen|collection_raw_line_scan_unavailable)
            report warning "$status" ;;
    esac
done < <(printf '%s' "$raw_lines" | jq -r '.statuses[]')
export CAPSTONE_VECTOR_MAINTENANCE=active
extra=()
[[ $operation != force ]] || extra=(--force)
if ! logrotate --state "$state/logrotate.status" "${extra[@]}" /etc/capstone-vector/logrotate.conf; then
    report err rotation_failed_pending_recovery
    exit 1
fi
if [[ -f $pending ]]; then
    wait_reader
    systemctl start "$service"
    systemctl is-active --quiet "$service"
    rm -- "$pending"
    report notice rotation_completed
fi
