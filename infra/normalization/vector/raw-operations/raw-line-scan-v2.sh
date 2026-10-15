#!/bin/bash
# Read-only, fixed-A health snapshot. This is not a rotation/closure gate.
# At most two generation scans run concurrently; each GNU timeout owns its
# bounded worker. No raw bytes, filenames, container calls or state writes.
RLS_LIBRARY=/usr/local/lib/capstone-raw-operations
RLS_STATE=/var/lib/capstone-raw-operations
RLS_PREDICATE=/etc/capstone-vector/raw-line-status.jq

rls_sha() { local value; value=$(/usr/bin/sha256sum -- "$1") || return 1; printf '%s\n' "${value%% *}"; }
rls_regular() { [[ -f $1 && ! -L $1 ]]; }
rls_identity() { /usr/bin/stat -c '%d:%i:%u:%g:%a:%h' -- "$1"; }
rls_devino() { /usr/bin/stat -c '%d:%i' -- "$1"; }
rls_unavailable() { ll_emit inconclusive "${1:-metadata_mismatch}" false false false false null null null null null 1048576 33554432 5; }
rls_parents() {
    local path=$1
    while [[ $path != / ]]; do
        [[ -d $path && ! -L $path ]] || return 1
        /usr/bin/stat -c '%d:%i:%u:%g:%a' -- "$path" || return 1
        path=${path%/*}; [[ -n $path ]] || path=/
    done
}
rls_pin() {
    local path=$1 expected=$2 before after digest
    rls_regular "$path" && [[ $(/usr/bin/stat -c %u:%h "$path") == 0:1 ]] &&
      (( $(/usr/bin/stat -c %s "$path") <= 1048576 )) || return 1
    before=$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' -- "$path") || return 1
    digest=$(rls_sha "$path") || return 1
    after=$(/usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' -- "$path") || return 1
    [[ $before == "$after" && $digest == "$expected" && ! -L $path ]] || return 1
    printf '%s:%s\n' "$before" "$digest"
}

rls_snapshot() (
    # Internal fixture-callable API. Public CLI supplies only fixed paths.
    [[ $# == 6 ]] || return 1
    local root=$1 engine=$2 base=$3 cfg=$4 env=$5 wazuh=$6 envelope state phase managed alias uid
    local current pending='' current_id pending_id='' alias_id pointer writer reader dirs pins='' pin key path
    local old_hash next_hash='' expected actual pointer_proof lanes='[]' gen kind id mode links expected_links metadata
    case $engine in
      suricata) alias=$base/eve.json; uid=998 ;;
      modsecurity) alias=$base/audit.log; uid=101 ;;
      *) return 1 ;;
    esac
    managed=$base/capstone-managed
    dirs=$(rls_parents "$managed") || return 1
    [[ $(/usr/bin/stat -c %u:%g:%a "$managed") == 0:0:711 &&
       ! -e $managed/.publish-link && ! -L $managed/.publish-link &&
       ! -e $managed/.audit-path.next && ! -L $managed/.audit-path.next ]] || return 1
    envelope=$(raw_state_read_twice "$root" "$engine" 2>/dev/null) || return 1
    state=$(/usr/bin/jq -c .state <<< "$envelope") || return 1
    phase=$(/usr/bin/jq -r .phase <<< "$state") || return 1
    current=$managed/$(/usr/bin/jq -r .current.basename <<< "$state")
    current_id=$(/usr/bin/jq -r '.current|"\(.device):\(.inode)"' <<< "$state")
    if [[ $phase != active ]]; then
        pending=$managed/$(/usr/bin/jq -r .pending.basename <<< "$state")
        pending_id=$(/usr/bin/jq -r '.pending|"\(.device):\(.inode)"' <<< "$state")
    fi
    rls_regular "$alias" || return 1
    alias_id=$(rls_devino "$alias") || return 1
    reader=current
    if [[ $alias_id != "$current_id" ]]; then
        [[ $phase == publish_pending && $alias_id == "$pending_id" ]] || return 1
        reader=pending
    fi
    for key in vector_config_sha256 vector_env_sha256 wazuh_config_sha256; do
        case $key in vector_config_sha256) path=$cfg;; vector_env_sha256) path=$env;; *) path=$wazuh;; esac
        pin=$(rls_pin "$path" "$(/usr/bin/jq -r --arg key "$key" '.source_pins[$key]' <<< "$state")") || return 1
        pins+="$pin"$'\n'
    done
    writer=current
    if [[ $engine == suricata ]]; then
        pointer=$managed/active.jsonl
        rls_regular "$pointer" || return 1
        actual=$(rls_devino "$pointer") || return 1
        if [[ $actual != "$current_id" ]]; then
            [[ $phase != active && $actual == "$pending_id" ]] || return 1
            writer=pending
        fi
        expected=$(/usr/bin/jq -r .source_pins.engine_config_sha256 <<< "$state")
        [[ $(/usr/bin/jq -r .current.writer_config_sha256 <<< "$state") == "$expected" ]] || return 1
        [[ $phase == active || $(/usr/bin/jq -r .pending.writer_config_sha256 <<< "$state") == "$expected" ]] || return 1
        pointer_proof=$(rls_identity "$pointer") || return 1
    else
        pointer=$managed/audit-path.conf
        rls_regular "$pointer" && [[ $(/usr/bin/stat -c %u:%g:%a:%h "$pointer") == 0:0:444:1 ]] &&
          (( $(/usr/bin/stat -c %s "$pointer") <= 256 )) || return 1
        old_hash=$(/usr/bin/jq -r .current.writer_config_sha256 <<< "$state")
        expected=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${current##*/}" | /usr/bin/sha256sum)
        [[ $old_hash == "${expected%% *}" ]] || return 1
        if [[ $phase != active ]]; then
            next_hash=$(/usr/bin/jq -r .pending.writer_config_sha256 <<< "$state")
            expected=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${pending##*/}" | /usr/bin/sha256sum)
            [[ $next_hash == "${expected%% *}" ]] || return 1
        fi
        actual=$(rls_sha "$pointer") || return 1
        if [[ $actual != "$old_hash" ]]; then
            [[ $phase != active && $actual == "$next_hash" ]] || return 1
            writer=pending
        fi
        pointer_proof="$(rls_identity "$pointer"):$actual" || return 1
    fi
    [[ $phase == active || $phase == switch_pending || $writer == pending ]] || return 1
    for kind in current pending; do
        [[ $kind != pending || -n $pending ]] || continue
        if [[ $kind == current ]]; then path=$current; id=$current_id; else path=$pending; id=$pending_id; fi
        rls_regular "$path" && [[ $(rls_devino "$path") == "$id" ]] || return 1
        metadata=$(rls_identity "$path") || return 1
        mode=$(/usr/bin/stat -c %u:%g:%a "$path") || return 1
        if [[ $kind == "$writer" || $kind == pending || ( $kind == current && $phase == switch_pending ) ]]; then
            if [[ $mode != "$uid:$uid:644" ]]; then
                [[ $kind == current && $phase == switch_pending && $writer == pending && $mode == 0:0:400 ]] || return 1
            fi
        else
            [[ $mode == 0:0:400 ]] || return 1
        fi
        expected_links=1
        [[ $alias_id != "$id" ]] || expected_links=$((expected_links+1))
        if [[ $engine == suricata && $(rls_devino "$pointer") == "$id" ]]; then expected_links=$((expected_links+1)); fi
        links=$(/usr/bin/stat -c %h "$path") || return 1
        [[ $links == "$expected_links" && $links =~ ^[1-3]$ ]] || return 1
        if [[ $kind == current && $phase != active && $phase != switch_pending ]]; then
            [[ $(/usr/bin/stat -c %s "$path") == "$(/usr/bin/jq -r .proof.old_closed.bytes <<< "$state")" ]] || return 1
        fi
        gen=$(/usr/bin/jq -c --arg kind "$kind" '.[$kind]' <<< "$state") || return 1
        lanes=$(/usr/bin/jq -c --argjson gen "$gen" --arg kind "$kind" --arg path "$path" \
          --arg mode "$mode" --argjson links "$links" --arg metadata "$metadata" \
          '.+[{generation:$gen.number,kind:$kind,path:$path,permissions:$mode,links:$links,identity:$metadata}]' <<< "$lanes") || return 1
    done
    /usr/bin/jq -nc --argjson envelope "$envelope" --arg phase "$phase" --arg writer "$writer" --arg reader "$reader" \
      --arg dirs "$dirs" --arg pins "$pins" --arg pointer "$pointer_proof" --argjson lanes "$lanes" \
      '{state_sha256:$envelope.sha256,state_identity:$envelope.file_identity,phase:$phase,
        writer_kind:$writer,reader_kind:$reader,directories:$dirs,pins:$pins,pointer:$pointer,lanes:$lanes}'
)

rls_scan_lanes() (
    # Each process substitution execs a direct GNU timeout, not another shell
    # that could outlive it. No temp files. On TERM/EXIT wait for the at-most-two
    # workers (each <=5s+1s) instead of signalling a possibly reaped/reused PID.
    local plan=$1 lane path uid gid mode links fd pid output code row rows='[]' index=0
    local -a pids=() fds=() generations=()
    rls_join() { local p; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || :; done; }
    trap 'rls_join' EXIT
    trap 'rls_join; exit 143' TERM INT HUP
    [[ $(/usr/bin/jq '.lanes|length' <<< "$plan") =~ ^[12]$ ]] || return 1
    while IFS= read -r lane; do
        path=$(/usr/bin/jq -r .path <<< "$lane")
        IFS=: read -r uid gid mode <<< "$(/usr/bin/jq -r .permissions <<< "$lane")"
        links=$(/usr/bin/jq -r .links <<< "$lane")
        exec {fd}< <(exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
          /usr/bin/timeout --signal=TERM --kill-after=1s 5s /bin/bash --noprofile --norc \
          "$_LL_SELF" --worker "$path" "$uid" "$gid" "$mode" 1048576 33554432 5 "$links" 2>/dev/null)
        pid=$!; pids+=("$pid"); fds+=("$fd"); generations+=("$(/usr/bin/jq -r .generation <<< "$lane")")
    done < <(/usr/bin/jq -c '.lanes[]' <<< "$plan")
    for fd in "${fds[@]}"; do
        output=$(/usr/bin/head -c 4097 <&"$fd") || output=''
        exec {fd}<&-
        code=0; wait "${pids[$index]}" || code=$?
        if (( code == 0 && ${#output} > 0 && ${#output} <= 4096 )) &&
           /usr/bin/jq -se 'length==1 and (.[0]|type=="object")' <<< "$output" >/dev/null 2>&1; then
            row=$output
        elif (( code == 124 || code == 137 )); then row=$(rls_unavailable scan_timeout)
        else row=$(rls_unavailable scanner_failed); fi
        rows=$(/usr/bin/jq -c --argjson gen "${generations[$index]}" --argjson row "$row" \
          '.+[{generation:$gen,row:$row}]' <<< "$rows") || return 1
        index=$((index+1))
    done
    printf '%s\n' "$rows"
)

rls_select() {
    # Keep ONE selected byte-range. A positive plus an uncertain companion is
    # represented as positive+inconclusive, preserving both stage2 health codes.
    /usr/bin/jq -nc --arg source "$1" --argjson plan "$2" --argjson rows "$3" --argjson metadata_ok "$4" '
      ($plan.lanes|map(select(.kind==$plan.writer_kind))[0].generation) as $writer |
      ($plan.lanes|map(select(.kind==$plan.reader_kind))[0].generation) as $reader |
      (any($rows[];.row.verdict=="inconclusive") or ($metadata_ok|not)) as $uncertain |
      ($rows|sort_by([if .row.observed_positive then 0 elif .row.verdict=="inconclusive" then 1 else 2 end,
                     if .generation==$writer then 0 else 1 end,.generation])|.[0]) as $chosen |
      {row:($chosen.row + {source:$source} |
         if $uncertain then .verdict="inconclusive" | .complete_snapshot_range=false | .full_file_scan=false |
           if $metadata_ok|not then .reason="metadata_mismatch"
           elif .observed_positive then .reason="scanner_failed" else . end
         else . end),
       selection:{source:$source,phase:$plan.phase,writer_generation:$writer,reader_generation:$reader,
         scanned_generations:[$rows[].generation],selected_generation:$chosen.generation,
         metadata_verified:$metadata_ok,
         reason:(if $metadata_ok|not then "metadata_changed"
                 elif $chosen.row.observed_positive and $uncertain then "positive_with_inconclusive"
                 elif $chosen.row.observed_positive then "positive_priority"
                 elif $uncertain then "inconclusive_priority" else "writer_snapshot" end)}}'
}
rls_engine() {
    local root=$1 engine=$2 base=$3 cfg=$4 env=$5 wazuh=$6 source before after rows valid=true
    if [[ $engine == suricata ]]; then source=suricata; else source=waf_audit; fi
    if ! before=$(rls_snapshot "$root" "$engine" "$base" "$cfg" "$env" "$wazuh" 2>/dev/null); then
        /usr/bin/jq -nc --arg source "$source" --argjson row "$(rls_unavailable)" \
          '{row:($row+{source:$source}),selection:{source:$source,metadata_verified:false,scanned_generations:[],reason:"metadata_unavailable"}}'
        return
    fi
    rows=$(rls_scan_lanes "$before") || return 1
    if ! after=$(rls_snapshot "$root" "$engine" "$base" "$cfg" "$env" "$wazuh" 2>/dev/null) || [[ $before != "$after" ]]; then valid=false; fi
    rls_select "$source" "$before" "$rows" "$valid"
}

rls_envelope() {
    local result statuses
    result=$(/usr/bin/jq -nc --arg now "$(/usr/bin/date --iso-8601=seconds)" --argjson suri "$1" --argjson waf "$2" --argjson access "$3" \
      '{schema_version:1,scope:"periodic_snapshot_tail",observed_at_kst:$now,
        sources:[$suri.row,$waf.row,($access+{source:"waf_access"})],selection:[$suri.selection,$waf.selection] }') || return 70
    statuses=$(/usr/bin/jq -c -f "$RLS_PREDICATE" <<< "$result") || return 70
    /usr/bin/jq -c --argjson statuses "$statuses" '.+{statuses:$statuses}' <<< "$result"
}

rls_main() {
    [[ $EUID == 0 && $OSTYPE == linux* && $# == 1 && $1 == check &&
       $(/usr/bin/cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || return 77
    local file parent mode suri waf access
    for file in "$RLS_LIBRARY/state-lib.sh" "$RLS_LIBRARY/state.jq" "$RLS_LIBRARY/line-length-lib-v2.sh" "$RLS_PREDICATE"; do
        rls_regular "$file" && [[ $(/usr/bin/stat -c %u:%h "$file") == 0:1 ]] &&
          (( (8#$(/usr/bin/stat -c %a "$file") & 0022)==0 )) || return 77
        parent=${file%/*}
        while [[ $parent != / ]]; do
            [[ -d $parent && ! -L $parent && $(/usr/bin/stat -c %u "$parent") == 0 ]] || return 77
            mode=$(/usr/bin/stat -c %a "$parent"); (( (8#$mode & 0022)==0 )) || return 77
            parent=${parent%/*}; [[ -n $parent ]] || parent=/
        done
    done
    source "$RLS_LIBRARY/state-lib.sh"
    source "$RLS_LIBRARY/line-length-lib-v2.sh"
    suri=$(rls_engine "$RLS_STATE" suricata /home/groot_a/capstone/secstack/logs/suricata \
      /etc/capstone-vector/vector.toml /etc/capstone-vector/vector.env /var/ossec/etc/ossec.conf) || return 70
    waf=$(rls_engine "$RLS_STATE" modsecurity /home/groot_a/capstone/secstack/logs/modsec \
      /etc/capstone-vector/vector.toml /etc/capstone-vector/vector.env /var/ossec/etc/ossec.conf) || return 70
    access=$(ll_scan /home/groot_a/capstone/secstack/logs/modsec/capstone-access.log 101 101 640 1048576 33554432 5 1) || return 70
    rls_envelope "$suri" "$waf" "$access"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    export PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul
    umask 077
    rls_main "$@"
fi
