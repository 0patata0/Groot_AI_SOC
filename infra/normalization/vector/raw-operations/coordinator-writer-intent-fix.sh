#!/bin/bash
# Finite, administrator-only native raw rotation. No raw deletion or checkpoint
# rewrite. A successful local checkpoint is NOT a manager/indexer receipt.
# Deployment must initialize BOTH engines and install the reader start guard
# before enabling this script. Initial writer migration belongs to deployment.
RO_LIBRARY=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
RO_ROOT=/var/lib/capstone-raw-operations
RO_LOCK=/var/lib/capstone-automation/ansible/vector.lock
RO_WAZUH_CP=/var/ossec/queue/logcollector/file_status.json
RO_VECTOR_UNIT=capstone-vector.service
RO_WAZUH_UNIT=wazuh-agent.service
RO_VECTOR_STOPPED=false
RO_REASON=unspecified

ro_refuse() { RO_REASON=$1; return 2; }
ro_sha() { local s; s=$(/usr/bin/sha256sum -- "$1") || return 1; printf '%s\n' "${s%% *}"; }
ro_json() { /usr/bin/jq -nc --arg status "$1" --arg reason "$2" --arg engine "${RO_ENGINE:-all}" \
    '{schema_version:1,status:$status,reason:$reason,engine:$engine,raw_deleted:false,checkpoint_rewritten:false,delivery_acknowledged:false}'; }
ro_regular() { [[ -f $1 && ! -L $1 ]]; }
ro_devino() { /usr/bin/stat -c '%d:%i' -- "$1"; }
ro_match() { [[ $(ro_devino "$1") == "$2:$3" ]]; }
ro_engine() {
    case $1 in
      suricata)
        RO_ENGINE=suricata RO_CONTAINER=suricata RO_UID=998
        RO_BASE=/home/groot_a/capstone/secstack/logs/suricata
        RO_ALIAS=$RO_BASE/eve.json RO_CP=/var/lib/capstone-vector/suricata_eve
        RO_ENGINE_CONFIG=/etc/suricata/suricata.yaml
        RO_FORMAT_CONFIG=$RO_ENGINE_CONFIG ;;
      modsecurity)
        RO_ENGINE=modsecurity RO_CONTAINER=waf RO_UID=101
        RO_BASE=/home/groot_a/capstone/secstack/logs/modsec
        RO_ALIAS=$RO_BASE/audit.log RO_CP=/var/lib/capstone-vector/waf_audit
        RO_ENGINE_CONFIG=/etc/modsecurity.d/modsecurity-override.conf
        RO_FORMAT_CONFIG=/etc/nginx/conf.d/zz-capstone-evidence.conf ;;
      *) ro_refuse invalid_engine; return 2 ;;
    esac
    RO_MANAGED=$RO_BASE/capstone-managed
}
ro_runtime() {
    [[ $EUID == 0 && $OSTYPE == linux* && $(/usr/bin/cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] ||
        { ro_refuse fixed_A_root_required; return 2; }
    local path
    for path in "$RO_LIBRARY" "$RO_ROOT"; do
        [[ $path == /* && -d $path && ! -L $path && $(/usr/bin/stat -c %u "$path") == 0 ]] &&
          (( (8#$(/usr/bin/stat -c %a "$path") & 0022)==0 )) ||
            { ro_refuse unsafe_runtime_directory; return 2; }
    done
    for path in state-lib.sh state.jq checkpoint-gates.sh checkpoint-gates.jq writer-gates.sh coordinator.sh guard.sh; do
        ro_regular "$RO_LIBRARY/$path" && [[ $(/usr/bin/stat -c %u:%h "$RO_LIBRARY/$path") == 0:1 ]] &&
          (( (8#$(/usr/bin/stat -c %a "$RO_LIBRARY/$path") & 0022)==0 )) ||
            { ro_refuse unsafe_runtime_source; return 2; }
    done
    source "$RO_LIBRARY/state-lib.sh" || return 2
    source "$RO_LIBRARY/checkpoint-gates.sh" || return 2
    source "$RO_LIBRARY/writer-gates.sh" || return 2
}
ro_load() {
    RO_ENVELOPE=$(raw_state_read_twice "$RO_ROOT" "$RO_ENGINE") || { ro_refuse state_unavailable; return 2; }
    RO_STATE=$(/usr/bin/jq -cS .state <<< "$RO_ENVELOPE") || return 2
    RO_STATE_SHA=$(/usr/bin/jq -r .sha256 <<< "$RO_ENVELOPE") || return 2
    RO_PHASE=$(/usr/bin/jq -r .phase <<< "$RO_STATE") || return 2
    RO_CID=$(/usr/bin/jq -r .source_pins.container_id <<< "$RO_STATE") || return 2
    RO_CURRENT=$RO_MANAGED/$(/usr/bin/jq -r .current.basename <<< "$RO_STATE")
    RO_OLD_DEV=$(/usr/bin/jq -r .current.device <<< "$RO_STATE")
    RO_OLD_INO=$(/usr/bin/jq -r .current.inode <<< "$RO_STATE")
    RO_NEXT=''
    if [[ $RO_PHASE != active ]]; then
        RO_NEXT=$RO_MANAGED/$(/usr/bin/jq -r .pending.basename <<< "$RO_STATE")
        RO_NEW_DEV=$(/usr/bin/jq -r .pending.device <<< "$RO_STATE")
        RO_NEW_INO=$(/usr/bin/jq -r .pending.inode <<< "$RO_STATE")
    fi
}
ro_generation() {
    local file=$1 dev=$2 ino=$3 uid gid mode links
    ro_regular "$file" && ro_match "$file" "$dev" "$ino" || { ro_refuse generation_identity_changed; return 2; }
    IFS=: read -r uid gid mode links < <(/usr/bin/stat -c %u:%g:%a:%h -- "$file")
    [[ ( $uid == "$RO_UID" && $gid == "$RO_UID" && $mode == 644 ) ||
       ( $uid == 0 && $gid == 0 && $mode == 400 ) ]] || { ro_refuse generation_permissions_changed; return 2; }
    # Exact link accounting, not a global relaxation: generation + optional
    # fixed reader alias + optional Suricata fixed writer path.
    local expected=1
    if ro_regular "$RO_ALIAS" && ro_match "$RO_ALIAS" "$dev" "$ino"; then expected=$((expected+1)); fi
    if [[ $RO_ENGINE == suricata ]] && ro_regular "$RO_MANAGED/active.jsonl" &&
       ro_match "$RO_MANAGED/active.jsonl" "$dev" "$ino"; then expected=$((expected+1)); fi
    [[ $links == "$expected" ]] || { ro_refuse unexpected_raw_hardlink; return 2; }
}
ro_writer_mode() {
    [[ $(/usr/bin/stat -c %u:%g:%a "$1") == "$RO_UID:$RO_UID:644" ]] ||
        { ro_refuse writer_file_permissions_changed; return 2; }
}
ro_pin_host() {
    local path=$1 expected=$2
    ro_regular "$path" && [[ $(/usr/bin/stat -c %u:%h -- "$path") == 0:1 && $(ro_sha "$path") == "$expected" ]] ||
        { ro_refuse host_source_pin_changed; return 2; }
}
ro_pin_container() {
    local path=$1 expected=$2 actual
    actual=$(/usr/bin/timeout --signal=TERM --kill-after=1s 10s /usr/local/bin/docker exec --user 0 "$RO_CID" /usr/bin/sha256sum -- "$path" 2>/dev/null) ||
        { ro_refuse container_source_unavailable; return 2; }
    [[ $actual == "$expected  $path" ]] || { ro_refuse container_source_pin_changed; return 2; }
}
ro_validate() {
    local identity actual expected pointer old_hash next_hash file mode parent
    # Refuse symlinks in every fixed source ancestor. The pre-existing lab log
    # parents may be operator-owned; managed itself is root:root 0711.
    parent=$RO_MANAGED
    while [[ $parent != / ]]; do
        [[ -d $parent && ! -L $parent ]] || { ro_refuse raw_parent_changed; return 2; }
        parent=${parent%/*}; [[ -n $parent ]] || parent=/
    done
    [[ $(/usr/bin/stat -c %u:%g:%a "$RO_MANAGED") == 0:0:711 ]] ||
        { ro_refuse managed_directory_permissions; return 2; }
    ro_generation "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" || return 2
    if [[ $RO_PHASE != active ]]; then ro_generation "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO" || return 2; fi
    ro_regular "$RO_ALIAS" || { ro_refuse alias_not_regular; return 2; }
    actual=$(ro_devino "$RO_ALIAS") || return 2
    RO_ALIAS_KIND=old
    if [[ $actual != "$RO_OLD_DEV:$RO_OLD_INO" ]]; then
        [[ $RO_PHASE == publish_pending && $actual == "$RO_NEW_DEV:$RO_NEW_INO" ]] ||
            { ro_refuse alias_generation_conflict; return 2; }
        RO_ALIAS_KIND=new
    fi
    ro_pin_host /etc/capstone-vector/vector.toml "$(/usr/bin/jq -r .source_pins.vector_config_sha256 <<< "$RO_STATE")" || return 2
    ro_pin_host /etc/capstone-vector/vector.env "$(/usr/bin/jq -r .source_pins.vector_env_sha256 <<< "$RO_STATE")" || return 2
    ro_pin_host /var/ossec/etc/ossec.conf "$(/usr/bin/jq -r .source_pins.wazuh_config_sha256 <<< "$RO_STATE")" || return 2
    identity=$(writer_identity "$RO_CONTAINER") || { ro_refuse writer_identity_unavailable; return 2; }
    RO_WRITER=$(/usr/bin/jq -ce --arg cid "$RO_CID" 'select(.status=="observed" and .identity.cid==$cid)|.identity' <<< "$identity") ||
        { ro_refuse writer_container_changed; return 2; }
    ro_pin_container "$RO_ENGINE_CONFIG" "$(/usr/bin/jq -r .source_pins.engine_config_sha256 <<< "$RO_STATE")" || return 2
    ro_pin_container "$RO_FORMAT_CONFIG" "$(/usr/bin/jq -r .source_pins.producer_format_sha256 <<< "$RO_STATE")" || return 2
    if [[ $RO_ENGINE == suricata ]]; then
        ro_regular "$RO_MANAGED/active.jsonl" || { ro_refuse writer_alias_invalid; return 2; }
        actual=$(ro_devino "$RO_MANAGED/active.jsonl") || return 2
        [[ $actual == "$RO_OLD_DEV:$RO_OLD_INO" || ( $RO_PHASE != active && $actual == "$RO_NEW_DEV:$RO_NEW_INO" ) ]] ||
            { ro_refuse writer_alias_conflict; return 2; }
        [[ $RO_PHASE == active || $RO_PHASE == switch_pending || $actual == "$RO_NEW_DEV:$RO_NEW_INO" ]] ||
            { ro_refuse writer_not_on_pending_generation; return 2; }
        ro_writer_mode "$RO_MANAGED/active.jsonl" || return 2
        [[ $(/usr/bin/jq -r .current.writer_config_sha256 <<< "$RO_STATE") == "$(/usr/bin/jq -r .source_pins.engine_config_sha256 <<< "$RO_STATE")" ]] || return 2
        if [[ $RO_PHASE != active ]]; then
            [[ $(/usr/bin/jq -r .pending.writer_config_sha256 <<< "$RO_STATE") == "$(/usr/bin/jq -r .source_pins.engine_config_sha256 <<< "$RO_STATE")" ]] || return 2
        fi
    else
        pointer=$RO_MANAGED/audit-path.conf
        ro_regular "$pointer" && [[ $(/usr/bin/stat -c %u:%g:%a:%h "$pointer") == 0:0:444:1 ]] ||
            { ro_refuse writer_path_config_invalid; return 2; }
        actual=$(ro_sha "$pointer") || return 2
        old_hash=$(/usr/bin/jq -r .current.writer_config_sha256 <<< "$RO_STATE")
        next_hash=$(/usr/bin/jq -r '.pending.writer_config_sha256//""' <<< "$RO_STATE")
        expected=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${RO_CURRENT##*/}" | /usr/bin/sha256sum)
        [[ $old_hash == "${expected%% *}" ]] || { ro_refuse current_writer_path_binding_invalid; return 2; }
        if [[ $RO_PHASE != active ]]; then
            expected=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${RO_NEXT##*/}" | /usr/bin/sha256sum)
            [[ $next_hash == "${expected%% *}" ]] || { ro_refuse pending_writer_path_binding_invalid; return 2; }
        fi
        [[ $actual == "$old_hash" || ( $RO_PHASE != active && $actual == "$next_hash" ) ]] ||
            { ro_refuse writer_path_config_changed; return 2; }
        [[ $RO_PHASE == active || $RO_PHASE == switch_pending || $actual == "$next_hash" ]] ||
            { ro_refuse writer_path_not_pending; return 2; }
        if [[ $actual == "$old_hash" ]]; then ro_writer_mode "$RO_CURRENT" || return 2
        else ro_writer_mode "$RO_NEXT" || return 2; fi
    fi
    if [[ $RO_PHASE == old_closed || $RO_PHASE == readers_drained || $RO_PHASE == publish_pending ]]; then
        [[ $(/usr/bin/stat -c %s "$RO_CURRENT") == "$(/usr/bin/jq -r .proof.old_closed.bytes <<< "$RO_STATE")" &&
           $(ro_sha "$RO_CURRENT") == "$(/usr/bin/jq -r .proof.old_closed.sha256 <<< "$RO_STATE")" ]] ||
            { ro_refuse sealed_generation_changed; return 2; }
        writer_gate "$RO_CONTAINER" "$RO_WRITER" "$RO_OLD_DEV" "$RO_OLD_INO" >/dev/null ||
            { ro_refuse old_writer_not_closed; return 2; }
    fi
}
ro_guard_one() {
    local target=$1 state_sha result entry offset hash final
    ro_load && ro_writer_signal_absent && ro_validate || return 2
    state_sha=$RO_STATE_SHA
    if [[ $RO_ALIAS_KIND == old ]]; then
        cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" >/dev/null ||
            { ro_refuse existing_native_cursor_unsafe; return 2; }
        cg_vector_current "$RO_CP" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" >/dev/null ||
            { ro_refuse vector_current_cursor_unavailable; return 2; }
    else
        # Before Vector starts, its new inode CP cannot yet exist. The old EOF
        # checkpoint plus pinned read_from=beginning configuration permits that
        # one adjacent generation. Active promotion checks the new CP later.
        if result=$(cg_vector_current "$RO_CP" "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO"); then :
        else
            [[ $(/usr/bin/jq -r '.reason//""' <<< "$result") == vector_checkpoint_match_missing ]] ||
                { ro_refuse new_vector_checkpoint_invalid; return 2; }
            cg_vector_eof "$RO_CP" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" \
              "$(/usr/bin/jq -r .proof.old_closed.bytes <<< "$RO_STATE")" >/dev/null ||
                { ro_refuse old_vector_eof_unavailable; return 2; }
        fi
        result=$(cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_NEXT" "$RO_OLD_DEV" "$RO_OLD_INO") || {
            # A saved checkpoint already advanced to this new generation can
            # match its prefix. Distinguish it from the frozen OLD entry.
            offset=$(/usr/bin/jq -r '.offset//-1' <<< "$result") || return 2
            hash=$(/usr/bin/jq -r '.stored_sha1//""' <<< "$result") || return 2
            [[ $offset != "$(/usr/bin/jq -r .proof.readers_drained.wazuh_offset <<< "$RO_STATE")" ||
               $hash != "$(/usr/bin/jq -r .proof.readers_drained.wazuh_sha1 <<< "$RO_STATE")" ]] ||
                { ro_refuse new_generation_prefix_ambiguous; return 2; }
            cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO" >/dev/null ||
                { ro_refuse new_generation_cursor_unsafe; return 2; }
        }
        # A shorter new file must differ over actual COMMON bytes, not merely
        # have a different hash because the old saved offset was longer.
        offset=$(/usr/bin/jq -r '.offset//-1' <<< "$result")
        hash=$(/usr/bin/jq -r '.stored_sha1//""' <<< "$result")
        if [[ $offset == "$(/usr/bin/jq -r .proof.readers_drained.wazuh_offset <<< "$RO_STATE")" &&
              $hash == "$(/usr/bin/jq -r .proof.readers_drained.wazuh_sha1 <<< "$RO_STATE")" ]]; then
            ro_prefix_distinct || return 2
        fi
    fi
    final=$(raw_state_read_twice "$RO_ROOT" "$RO_ENGINE") || { ro_refuse state_changed_during_guard; return 2; }
    [[ $(/usr/bin/jq -r .sha256 <<< "$final") == "$state_sha" ]] || { ro_refuse state_changed_during_guard; return 2; }
    # Recheck aliases, config and writer membership after the checkpoint reads.
    ro_validate && ro_writer_signal_absent || return 2
}
ro_guard_all() {
    local target=$1 engine
    [[ $target == vector || $target == wazuh ]] || { ro_refuse invalid_reader; return 2; }
    for engine in suricata modsecurity; do ro_engine "$engine" && ro_guard_one "$target" || return 2; done
    # An intent does not change state SHA. Recheck both engines at the end too.
    for engine in suricata modsecurity; do ro_engine "$engine" && ro_writer_signal_absent || return 2; done
}
ro_state_change() {
    local candidate result
    candidate=$(/usr/bin/mktemp --suffix=.json "$RO_ROOT/$RO_ENGINE/staging/candidate-XXXXXXXX") || return 2
    /bin/chmod 600 "$candidate" || { /bin/rm -f "$candidate"; return 2; }
    if ! /usr/bin/jq -cS "$@" <<< "$RO_STATE" > "$candidate"; then /bin/rm -f "$candidate"; return 2; fi
    if result=$(raw_state_cas "$RO_ROOT" "$RO_ENGINE" "$RO_STATE_SHA" "$candidate"); then
        /bin/rm -f -- "$candidate" || return 2
        ro_load
    else
        /bin/rm -f -- "$candidate" || true
        ro_refuse state_commit_uncertain_inspect_required
    fi
}
ro_space() {
    local bytes avail history
    bytes=$(/usr/bin/du -sb -- "$RO_MANAGED" | /usr/bin/cut -f1) || return 2
    avail=$(/usr/bin/df --output=avail -B1 -- "$RO_MANAGED" | /usr/bin/tail -1 | /usr/bin/tr -d ' ') || return 2
    history=$(/usr/bin/find "$RO_ROOT/$RO_ENGINE/history" -mindepth 1 -maxdepth 1 -printf '.\n' | /usr/bin/wc -l) || return 2
    [[ $bytes =~ ^[0-9]+$ && $avail =~ ^[0-9]+$ && $history =~ ^[[:space:]]*[0-9]+[[:space:]]*$ ]] || return 2
    (( bytes<=5368709120 && avail>=2147483648 && history<=1018 )) || { ro_refuse capacity_hold; return 2; }
}
ro_new_generation() {
    local number basename path dev ino hash epoch size born now
    ro_space || return 2
    size=$(/usr/bin/stat -c %s "$RO_CURRENT") || return 2
    born=$(/usr/bin/stat -c %W "$RO_CURRENT") || return 2
    now=$(/usr/bin/date +%s) || return 2
    if [[ $RO_FORCE != true ]] && (( size<67108864 )); then
        (( born>0 && now>=born && now-born>=86400 )) || return 10
    fi
    number=$(( $(/usr/bin/jq -r .current.number <<< "$RO_STATE")+1 ))
    (( number<=4294967295 )) || { ro_refuse generation_counter_limit; return 2; }
    printf -v basename 'generation-%010d.jsonl' "$number"
    path=$RO_MANAGED/$basename
    # Reconcile only the next empty, unlinked allocation in the dedicated
    # root-owned directory. Nonempty or unknown metadata is preserved/refused.
    # Neither fixed writer path can refer to it while the state is active.
    if [[ -e $path || -L $path ]]; then
        local allocated_meta
        allocated_meta=$(/usr/bin/stat -c %u:%g:%a:%h:%s "$path") || return 2
        ro_regular "$path" && [[ ( $allocated_meta == "$RO_UID:$RO_UID:644:1:0" ||
          $allocated_meta == "$RO_UID:$RO_UID:600:1:0" || $allocated_meta == 0:0:600:1:0 ) &&
          $(/usr/bin/stat -c %d "$path") == "$RO_OLD_DEV" ]] ||
            { ro_refuse uncommitted_generation_exists; return 2; }
    else
        ( set -o noclobber; umask 077; : > "$path" ) || return 2
    fi
    /bin/chown "$RO_UID:$RO_UID" "$path" && /bin/chmod 644 "$path" || return 2
    /bin/sync -- "$path" "$RO_MANAGED" || { ro_refuse generation_allocation_uncertain; return 2; }
    dev=$(/usr/bin/stat -c %d "$path") ino=$(/usr/bin/stat -c %i "$path")
    if [[ $RO_ENGINE == suricata ]]; then hash=$(/usr/bin/jq -r .source_pins.engine_config_sha256 <<< "$RO_STATE")
    else hash=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "$basename" | /usr/bin/sha256sum); hash=${hash%% *}; fi
    ro_state_change --arg name "$basename" --argjson n "$number" --argjson dev "$dev" --argjson ino "$ino" --arg hash "$hash" \
      '.revision+=1|.phase="switch_pending"|.pending={number:$n,basename:$name,device:$dev,inode:$ino,writer_config_sha256:$hash}'
}
ro_replace_link() {
    local destination=$1 expected=$2 source=$3 tmp=$RO_MANAGED/.publish-link
    [[ ! -e $tmp && ! -L $tmp && $(ro_devino "$destination") == "$expected" ]] ||
        { ro_refuse link_publication_conflict; return 2; }
    /bin/ln -- "$source" "$tmp" || return 2
    /bin/sync -- "$source" "$RO_MANAGED" || { /bin/rm -f -- "$tmp"; return 2; }
    if [[ $(ro_devino "$destination") != "$expected" ]]; then /bin/rm -f -- "$tmp"; ro_refuse link_publication_conflict; return 2; fi
    /bin/mv -T -- "$tmp" "$destination" && /bin/sync -- "${destination%/*}" "$RO_MANAGED" ||
        { ro_refuse link_publication_uncertain; return 2; }
}
# Gate exit 10 is a stable OPEN observation, not a closed gate or an error.
# Do not infer successful reopen from an error, an empty result, or new path size.
ro_writer_target() {
    local dev=$1 ino=$2 output rc=0
    output=$(writer_gate "$RO_CONTAINER" "$RO_WRITER" "$dev" "$ino") || rc=$?
    [[ ( $rc == 0 || $rc == 10 ) && ${#output} -le 65536 ]] || return 2
    /usr/bin/jq -sce --arg source "$RO_CONTAINER" --arg cid "$RO_CID" --arg dev "$dev" --arg ino "$ino" \
      --argjson identity "$RO_WRITER" --argjson rc "$rc" '
      def count: type=="number" and floor==. and .>=0 and .<=262144;
      select(length==1)|.[0]|
      select(keys==["changes","future_reopen_excluded","host_other_processes_checked","identity",
        "matching_fd_count","membership_stable","process_count","processes","reason","scanned_fd_count",
        "schema_version","scope","source","status","target","writable_fd_count"])|
      select(.schema_version==1 and .source==$source and .identity==$identity and .identity.cid==$cid and
        .target=={device:$dev,inode:$ino} and .reason=="stable_container_snapshot" and
        .membership_stable==true and .scope=="current_exact_container_process_snapshot" and
        .future_reopen_excluded==false and .host_other_processes_checked==false and .changes==false)|
      select((.processes|type)=="array" and (.processes|length)>=1 and (.processes|length)<=64 and
        (.process_count|count) and .process_count==(.processes|length) and
        ([.processes[].pid]|unique|length)==.process_count and
        ([.processes[]|select(.pid==$identity.pid)]|length)==1)|
      select(all(.processes[];
        keys==["exe","gids","matching_fd_count","mount_ns","net_ns","pid","pid_ns","scanned_fd_count","start_ticks","uids","writable_fd_count"] and
        (.pid|type=="number" and floor==. and .>1 and .<2147483648) and
        (.start_ticks|type=="string" and test("^[1-9][0-9]{0,19}$")) and
        .mount_ns==$identity.mount_ns and .pid_ns==$identity.pid_ns and
        (.net_ns|type=="string" and startswith("net:[") and endswith("]")) and
        (.exe|type=="string" and startswith("/") and length<=512) and
        (.uids|type=="array" and length==4 and all(.[];type=="number" and floor==. and .>=0 and .<=4294967295)) and
        (.gids|type=="array" and length==4 and all(.[];type=="number" and floor==. and .>=0 and .<=4294967295)) and
        (.scanned_fd_count|count) and .scanned_fd_count<=4096 and (.matching_fd_count|count) and
        (.writable_fd_count|count) and .writable_fd_count<=.matching_fd_count and .matching_fd_count<=.scanned_fd_count))|
      select((.scanned_fd_count|count) and (.matching_fd_count|count) and (.writable_fd_count|count) and
        .scanned_fd_count==([.processes[].scanned_fd_count]|add) and
        .matching_fd_count==([.processes[].matching_fd_count]|add) and
        .writable_fd_count==([.processes[].writable_fd_count]|add))|
      select(($rc==0 and .status=="closed" and .writable_fd_count==0) or
             ($rc==10 and .status=="open" and .writable_fd_count>0))' <<< "$output" 2>/dev/null
}
ro_writer_pair() {
    local old new
    old=$(ro_writer_target "$RO_OLD_DEV" "$RO_OLD_INO") || { ro_refuse old_writer_observation_invalid; return 2; }
    new=$(ro_writer_target "$RO_NEW_DEV" "$RO_NEW_INO") || { ro_refuse new_writer_observation_invalid; return 2; }
    # Each gate already verifies a stable process snapshot. Require the same
    # process identities across old/new observations as well; FD counts may differ.
    /usr/bin/jq -ne --argjson old "$old" --argjson new "$new" '
      def members: .processes|map(del(.scanned_fd_count,.matching_fd_count,.writable_fd_count))|sort_by(.pid);
      ($old|members)==($new|members)' >/dev/null || { ro_refuse writer_membership_changed_between_targets; return 2; }
    RO_OLD_WRITER_STATUS=$(/usr/bin/jq -r .status <<< "$old") || return 2
    RO_NEW_WRITER_STATUS=$(/usr/bin/jq -r .status <<< "$new") || return 2
}
ro_writer_signal_path() { printf '%s/%s/writer-reopen-intent.json\n' "$RO_ROOT" "$RO_ENGINE"; }
ro_writer_signal_absent() {
    local path
    path=$(ro_writer_signal_path)
    [[ ! -e $path && ! -L $path ]] || { ro_refuse writer_signal_intent_present; return 2; }
}
ro_writer_signal_read() {
    local path before after raw canonical revision expected origin history phase
    path=$(ro_writer_signal_path)
    _rs_layout "$RO_ROOT" "$RO_ENGINE" && _rs_file "$path" 600 &&
      (( $(/usr/bin/stat -c %s "$path")<=8192 )) || { ro_refuse writer_signal_metadata_invalid; return 2; }
    before=$(/usr/bin/stat -c '%d:%i:%s:%y:%z' "$path") || return 2
    raw=$(/usr/bin/cat "$path") || return 2
    /usr/bin/jq -se '
      def hex($n): type=="string" and test("^[a-f0-9]{"+($n|tostring)+"}$");
      length==1 and (.[0]|
      keys==["boot_id","current","engine","machine_id","pending","phase","policy","revision","schema_version","source_pins","state_sha256","writer_identity"] and
      .schema_version==1 and .policy=="capstone-writer-reopen-intent-v1" and
      .machine_id=="096e90b6243e438aa8a7b392be754732" and
      (.engine=="suricata" or .engine=="modsecurity") and .phase=="switch_pending" and
      (.boot_id|hex(32)) and (.state_sha256|hex(64)) and
      (.revision|type=="number" and floor==. and .>=0 and .<=2147483646) and
      (.writer_identity|keys==["cid","gid","mount_ns","pid","pid_ns","start_ticks","uid"] and
       (.cid|hex(64)) and (.pid|type=="number" and floor==. and .>1 and .<2147483648) and
       (.start_ticks|type=="string" and test("^[1-9][0-9]{0,19}$")) and
       (.mount_ns|type=="string" and startswith("mnt:[") and endswith("]")) and
       (.pid_ns|type=="string" and startswith("pid:[") and endswith("]")) and
       (.uid|type=="number" and floor==. and .>=0 and .<=4294967295) and
       (.gid|type=="number" and floor==. and .>=0 and .<=4294967295)))
      ' <<< "$raw" >/dev/null || { ro_refuse writer_signal_invalid; return 2; }
    canonical=$(/usr/bin/jq -cS . <<< "$raw") || return 2
    [[ $canonical == "$raw" ]] && /usr/bin/cmp -s "$path" <(printf '%s\n' "$canonical") ||
      { ro_refuse writer_signal_not_canonical; return 2; }
    [[ $(/usr/bin/jq -r .engine <<< "$raw") == "$RO_ENGINE" &&
       $(/usr/bin/jq -r .boot_id <<< "$raw") == "$(ro_boot_id)" ]] ||
      { ro_refuse writer_signal_engine_or_boot_changed; return 2; }
    revision=$(/usr/bin/jq -r .revision <<< "$raw") expected=$(/usr/bin/jq -r .state_sha256 <<< "$raw")
    phase=$(/usr/bin/jq -r .phase <<< "$RO_STATE")
    if [[ $phase == switch_pending ]]; then
        [[ $expected == "$RO_STATE_SHA" ]] || { ro_refuse writer_signal_state_conflict; return 2; }
        origin=$RO_STATE
    elif [[ $phase == old_closed ]]; then
        history=$RO_ROOT/$RO_ENGINE/history/$revision-$expected.json
        _rs_validate "$history" "$RO_ENGINE" 400 && [[ $(ro_sha "$history") == "$expected" ]] ||
          { ro_refuse writer_signal_history_invalid; return 2; }
        origin=$(/usr/bin/cat "$history") || return 2
    else ro_refuse writer_signal_phase_conflict; return 2; fi
    /usr/bin/jq -e --argjson signal "$raw" --argjson origin "$origin" '
      $origin.phase=="switch_pending" and $origin.revision==$signal.revision and $origin.engine==$signal.engine and
      $origin.current==$signal.current and $origin.pending==$signal.pending and $origin.source_pins==$signal.source_pins and
      .engine==$origin.engine and .current==$origin.current and .pending==$origin.pending and .source_pins==$origin.source_pins and
      $signal.writer_identity.cid==.source_pins.container_id and
      (if .phase=="switch_pending" then .==$origin else
        .phase=="old_closed" and .revision==($origin.revision+1) and
        .proof.readers_drained==null and .proof.publish_guard==null and
        .proof.old_closed.boot_id==$signal.boot_id and .proof.old_closed.device==.current.device and
        .proof.old_closed.inode==.current.inode and .proof.old_closed.writer_fd_zero==true and
        .proof.old_closed.writer_pid==$signal.writer_identity.pid and
        (.proof.old_closed.writer_start_ticks|tostring)==$signal.writer_identity.start_ticks end)
      ' <<< "$RO_STATE" >/dev/null || { ro_refuse writer_signal_state_binding_invalid; return 2; }
    after=$(/usr/bin/stat -c '%d:%i:%s:%y:%z' "$path") || return 2
    [[ $before == "$after" && $(ro_sha "$path") == "$(printf '%s\n' "$raw" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)" ]] ||
      { ro_refuse writer_signal_changed; return 2; }
    RO_WRITER_SIGNAL=$raw
}
ro_writer_signal_identity() {
    local observed
    observed=$(writer_identity "$RO_CONTAINER") || { ro_refuse writer_signal_identity_unavailable; return 2; }
    /usr/bin/jq -ne --argjson signal "$RO_WRITER_SIGNAL" --argjson observed "$observed" '
      $observed.status=="observed" and $observed.identity==$signal.writer_identity' >/dev/null ||
      { ro_refuse writer_signal_identity_changed; return 2; }
}
ro_writer_signal_create() {
    local path temp count
    path=$(ro_writer_signal_path)
    ro_writer_signal_absent && _rs_layout "$RO_ROOT" "$RO_ENGINE" && [[ $RO_PHASE == switch_pending ]] || return 2
    [[ $(ro_sha "$RO_ROOT/$RO_ENGINE/state.json") == "$RO_STATE_SHA" ]] ||
      { ro_refuse writer_signal_state_conflict; return 2; }
    count=$(/usr/bin/find "$RO_ROOT/$RO_ENGINE" -mindepth 1 -maxdepth 1 -name '.writer-reopen.*' -printf '.\n' | /usr/bin/wc -l) || return 2
    (( count<8 )) || { ro_refuse writer_signal_staging_limit; return 2; }
    temp=$(/usr/bin/mktemp "$RO_ROOT/$RO_ENGINE/.writer-reopen.XXXXXXXX") || return 2
    if ! /usr/bin/jq -cS --arg boot "$(ro_boot_id)" --arg sha "$RO_STATE_SHA" --argjson writer "$RO_WRITER" '
      {schema_version:1,policy:"capstone-writer-reopen-intent-v1",machine_id:"096e90b6243e438aa8a7b392be754732",
       engine,boot_id:$boot,state_sha256:$sha,revision,phase,current,pending,source_pins,writer_identity:$writer}' <<< "$RO_STATE" > "$temp"; then
        /bin/rm -f -- "$temp"; return 2
    fi
    /bin/chmod 600 "$temp" && /bin/sync -- "$temp" ||
      { /bin/rm -f -- "$temp"; ro_refuse writer_signal_sync_failed; return 2; }
    [[ $(ro_sha "$RO_ROOT/$RO_ENGINE/state.json") == "$RO_STATE_SHA" ]] ||
      { /bin/rm -f -- "$temp"; ro_refuse writer_signal_state_conflict; return 2; }
    /bin/mv -T -n -- "$temp" "$path" && [[ ! -e $temp ]] ||
      { /bin/rm -f -- "$temp"; ro_refuse writer_signal_publish_conflict; return 2; }
    /bin/sync -- "$RO_ROOT/$RO_ENGINE" && ro_writer_signal_read && ro_writer_signal_identity ||
      { ro_refuse writer_signal_publish_uncertain; return 2; }
}
ro_reconcile_writer_signal() {
    local path expected history signal_sha
    path=$(ro_writer_signal_path)
    [[ -e $path || -L $path ]] || return 0
    ro_writer_signal_read && ro_writer_signal_identity || return 2
    [[ $RO_PHASE == old_closed ]] || return 0
    signal_sha=$(ro_sha "$path") || return 2
    ro_validate || return 2
    /usr/bin/jq -ne --argjson signal "$RO_WRITER_SIGNAL" --argjson writer "$RO_WRITER" \
      '$signal.writer_identity==$writer' >/dev/null || { ro_refuse writer_signal_identity_changed; return 2; }
    ro_writer_pair || return 2
    [[ $RO_OLD_WRITER_STATUS == closed && $RO_NEW_WRITER_STATUS == open &&
       $(/usr/bin/stat -c %u:%g:%a "$RO_CURRENT") == 0:0:400 ]] ||
      { ro_refuse writer_signal_cleanup_not_ready; return 2; }
    history=$RO_ROOT/$RO_ENGINE/history/$(/usr/bin/jq -r '.revision|tostring' <<< "$RO_WRITER_SIGNAL")-$(/usr/bin/jq -r .state_sha256 <<< "$RO_WRITER_SIGNAL").json
    /bin/sync -- "$RO_CURRENT" "$RO_MANAGED" "$history" "$RO_ROOT/$RO_ENGINE/history" \
      "$RO_ROOT/$RO_ENGINE/state.json" "$RO_ROOT/$RO_ENGINE" "$path" ||
      { ro_refuse writer_signal_cleanup_sync_failed; return 2; }
    ro_writer_signal_read && ro_writer_signal_identity && [[ $(ro_sha "$path") == "$signal_sha" &&
      $(ro_sha "$RO_ROOT/$RO_ENGINE/state.json") == "$RO_STATE_SHA" ]] ||
      { ro_refuse writer_signal_changed_before_cleanup; return 2; }
    /bin/rm -- "$path" && /bin/sync -- "$RO_ROOT/$RO_ENGINE" && [[ ! -e $path && ! -L $path ]] ||
      { ro_refuse writer_signal_cleanup_uncertain; return 2; }
}
ro_switch_writer() {
    local actual temporary expected observed signal_path
    ro_validate || return 2
    if [[ $RO_ENGINE == suricata ]]; then
        actual=$(ro_devino "$RO_MANAGED/active.jsonl") || return 2
        if [[ $actual == "$RO_OLD_DEV:$RO_OLD_INO" ]]; then
            ro_replace_link "$RO_MANAGED/active.jsonl" "$actual" "$RO_NEXT" || return 2
        fi
    else
        expected=$(/usr/bin/jq -r .pending.writer_config_sha256 <<< "$RO_STATE")
        actual=$(ro_sha "$RO_MANAGED/audit-path.conf") || return 2
        if [[ $actual != "$expected" ]]; then
            temporary=$RO_MANAGED/.audit-path.next
            if [[ -e $temporary || -L $temporary ]]; then
                ro_regular "$temporary" && [[ ( $(/usr/bin/stat -c %u:%g:%a:%h "$temporary") == 0:0:444:1 ||
                  $(/usr/bin/stat -c %u:%g:%a:%h "$temporary") == 0:0:600:1 ) &&
                  $(ro_sha "$temporary") == "$expected" ]] || { ro_refuse uncommitted_path_configuration; return 2; }
            else
                ( set -o noclobber; printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${RO_NEXT##*/}" > "$temporary" ) || return 2
                /bin/chown 0:0 "$temporary" && /bin/chmod 444 "$temporary" || return 2
            fi
            /bin/chmod 444 "$temporary" && /bin/sync -- "$temporary" || return 2
            [[ $(ro_sha "$temporary") == "$expected" && $(ro_sha "$RO_MANAGED/audit-path.conf") == "$actual" ]] || return 2
            /bin/mv -T "$temporary" "$RO_MANAGED/audit-path.conf" && /bin/sync -- "$RO_MANAGED" || return 2
        fi
        /usr/bin/timeout --signal=TERM --kill-after=1s 10s /usr/local/bin/docker exec --user 101:101 "$RO_CID" /usr/sbin/nginx -t >/dev/null 2>&1 ||
            { ro_refuse native_writer_config_test_failed; return 2; }
    fi
    signal_path=$(ro_writer_signal_path)
    if [[ -e $signal_path || -L $signal_path ]]; then
        ro_writer_signal_read && ro_writer_signal_identity || return 2
    fi
    ro_writer_pair || return 2
    case "$RO_OLD_WRITER_STATUS:$RO_NEW_WRITER_STATUS" in
      closed:open) ;; # Reopen already happened; never send another HUP to seal.
      open:open) ro_refuse writer_reopen_in_progress; return 2 ;;
      closed:closed) ro_refuse writer_target_not_open; return 2 ;;
      open:closed)
        ro_writer_signal_absent || { ro_refuse writer_signal_already_armed; return 2; }
        observed=$(writer_identity "$RO_CONTAINER") || return 2
        [[ $(/usr/bin/jq -cS .identity <<< "$observed") == "$(/usr/bin/jq -cS . <<< "$RO_WRITER")" ]] ||
            { ro_refuse writer_changed_before_signal; return 2; }
        ro_writer_signal_create || return 2
        # This call alone created the durable intent. A later call never
        # re-sends, even if this process died before invoking Docker.
        ro_writer_signal_read && ro_writer_signal_identity && ro_writer_pair || return 2
        case "$RO_OLD_WRITER_STATUS:$RO_NEW_WRITER_STATUS" in
          closed:open) ;;
          open:closed)
            /usr/bin/timeout --signal=TERM --kill-after=1s 10s /usr/local/bin/docker kill --signal=HUP "$RO_CID" >/dev/null 2>&1 ||
                { ro_refuse writer_reopen_uncertain; return 2; } ;;
          *) ro_refuse writer_signal_armed_observation_pending; return 2 ;;
        esac
        ro_writer_pair || return 2
        [[ $RO_OLD_WRITER_STATUS == closed && $RO_NEW_WRITER_STATUS == open ]] ||
            { ro_refuse old_writer_reopen_pending; return 2; } ;;
      *) ro_refuse writer_observation_ambiguous; return 2 ;;
    esac
    local size sha before after boot pid ticks
    before=$(/usr/bin/stat -c '%d:%i:%s:%y:%z' "$RO_CURRENT") || return 2
    size=$(/usr/bin/stat -c %s "$RO_CURRENT") || return 2
    (( size<=536870912 )) || { ro_refuse sealed_size_budget; return 2; }
    sha=$(ro_sha "$RO_CURRENT") || return 2
    after=$(/usr/bin/stat -c '%d:%i:%s:%y:%z' "$RO_CURRENT") || return 2
    [[ $before == "$after" ]] || { ro_refuse old_generation_still_changing; return 2; }
    ro_writer_pair || return 2
    [[ $RO_OLD_WRITER_STATUS == closed && $RO_NEW_WRITER_STATUS == open ]] ||
        { ro_refuse writer_reopen_changed_before_seal; return 2; }
    ro_match "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" && ro_match "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO" ||
        { ro_refuse generation_identity_changed_before_seal; return 2; }
    /bin/chown 0:0 "$RO_CURRENT" && /bin/chmod 400 "$RO_CURRENT" && /bin/sync -- "$RO_CURRENT" "$RO_MANAGED" || return 2
    boot=$(/usr/bin/tr -d '-' < /proc/sys/kernel/random/boot_id)
    pid=$(/usr/bin/jq -r .pid <<< "$RO_WRITER") ticks=$(/usr/bin/jq -r .start_ticks <<< "$RO_WRITER")
    ro_state_change --arg boot "$boot" --argjson size "$size" --arg sha "$sha" --argjson pid "$pid" --argjson ticks "$ticks" \
      '.revision+=1|.phase="old_closed"|.proof.old_closed={boot_id:$boot,bytes:$size,device:.current.device,inode:.current.inode,sha256:$sha,writer_fd_zero:true,writer_pid:$pid,writer_start_ticks:$ticks}'
}
ro_vector_status() {
    local fields
    fields=$(/usr/bin/systemctl show "$RO_VECTOR_UNIT" -p ActiveState -p Result -p ExecMainStatus \
      -p InvocationID -p ExecMainStartTimestampMonotonic) || return 2
    /usr/bin/jq -nce --arg fields "$fields" '
      ($fields|split("\n")|map(select(length>0)|split("=")|select(length==2))) as $rows |
      select(($rows|length)==5 and ($rows|map(.[0])|unique|length)==5) |
      ($rows|map({key:.[0],value:.[1]})|from_entries) |
      select((keys==["ActiveState","ExecMainStartTimestampMonotonic","ExecMainStatus","InvocationID","Result"]) and
        (.ActiveState|test("^[a-z-]+$")) and (.Result|test("^[a-z-]+$")) and
        (.ExecMainStatus|test("^[0-9]+$")) and (.InvocationID|test("^([a-f0-9]{32})?$")) and
        (.ExecMainStartTimestampMonotonic|test("^[1-9][0-9]{0,17}$")))'
}
ro_boot_id() { /usr/bin/tr -d '-' < /proc/sys/kernel/random/boot_id; }
ro_intent_path() { printf '%s/vector-stop-intent.json\n' "$RO_ROOT"; }
ro_intent_read() {
    local path before after raw canonical revision origin expected current_phase
    path=$(ro_intent_path)
    _rs_layout "$RO_ROOT" "$RO_ENGINE" && _rs_file "$path" 600 &&
      (( $(/usr/bin/stat -c %s "$path")<=4096 )) || { ro_refuse stop_intent_metadata_invalid; return 2; }
    before=$(/usr/bin/stat -c '%d:%i:%s:%y:%z' "$path") || return 2
    raw=$(/usr/bin/cat "$path") || return 2
    /usr/bin/jq -e '
      def hex($n): type=="string" and test("^[a-f0-9]{"+($n|tostring)+"}$");
      keys==["boot_id","current","engine","invocation_id","pending","phase","revision","schema_version","source_pins","start_usec","state_sha256"] and
      .schema_version==1 and (.engine=="suricata" or .engine=="modsecurity") and
      (.boot_id|hex(32)) and (.invocation_id|hex(32)) and (.state_sha256|hex(64)) and
      (.start_usec|type=="string" and test("^[1-9][0-9]{0,17}$")) and
      (.revision|type=="number" and floor==. and .>=0 and .<=2147483647) and
      (.phase=="old_closed" or .phase=="readers_drained" or .phase=="publish_pending")
      ' <<< "$raw" >/dev/null || { ro_refuse stop_intent_invalid; return 2; }
    canonical=$(/usr/bin/jq -cS . <<< "$raw") || return 2
    [[ $canonical == "$raw" ]] && /usr/bin/cmp -s "$path" <(printf '%s\n' "$canonical") ||
      { ro_refuse stop_intent_not_canonical; return 2; }
    [[ $(/usr/bin/jq -r .engine <<< "$raw") == "$RO_ENGINE" ]] ||
      { ro_refuse another_engine_owns_vector_pause; return 2; }
    revision=$(/usr/bin/jq -r .revision <<< "$raw")
    expected=$(/usr/bin/jq -r .state_sha256 <<< "$raw")
    if [[ $revision == "$(/usr/bin/jq -r .revision <<< "$RO_STATE")" ]]; then
        [[ $expected == "$RO_STATE_SHA" ]] || { ro_refuse stop_intent_state_conflict; return 2; }
        origin=$RO_STATE
    else
        local history=$RO_ROOT/$RO_ENGINE/history/$revision-$expected.json
        _rs_validate "$history" "$RO_ENGINE" 400 && [[ $(ro_sha "$history") == "$expected" ]] ||
          { ro_refuse stop_intent_history_invalid; return 2; }
        origin=$(/usr/bin/cat "$history") || return 2
    fi
    /usr/bin/jq -e --argjson intent "$raw" --argjson origin "$origin" '
      def rank: if .=="old_closed" then 0 elif .=="readers_drained" then 1 elif .=="publish_pending" then 2 else -100 end;
      ((.phase|rank)-($origin.phase|rank)) as $delta |
      $origin.engine==$intent.engine and $origin.phase==$intent.phase and $origin.revision==$intent.revision and
      $origin.current==$intent.current and $origin.pending==$intent.pending and $origin.source_pins==$intent.source_pins and
      .engine==$origin.engine and .current==$origin.current and .pending==$origin.pending and .source_pins==$origin.source_pins and
      .proof.old_closed==$origin.proof.old_closed and
      ($origin.proof.readers_drained==null or .proof.readers_drained==$origin.proof.readers_drained) and
      $delta>=0 and $delta<=2 and .revision==($origin.revision+$delta)
      ' <<< "$RO_STATE" >/dev/null || { ro_refuse stop_intent_phase_conflict; return 2; }
    after=$(/usr/bin/stat -c '%d:%i:%s:%y:%z' "$path") || return 2
    [[ $before == "$after" && $(ro_sha "$path") == "$(printf '%s\n' "$raw" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)" ]] ||
      { ro_refuse stop_intent_changed; return 2; }
    RO_STOP_INTENT=$raw
}
ro_intent_create() {
    local status=$1 path temp count
    path=$(ro_intent_path)
    [[ ! -e $path && ! -L $path ]] && _rs_layout "$RO_ROOT" "$RO_ENGINE" || return 2
    [[ $RO_PHASE == old_closed || $RO_PHASE == readers_drained || $RO_PHASE == publish_pending ]] || return 2
    /usr/bin/jq -e '.ActiveState=="active" and (.InvocationID|test("^[a-f0-9]{32}$"))' <<< "$status" >/dev/null || return 2
    count=$(/usr/bin/find "$RO_ROOT" -mindepth 1 -maxdepth 1 -name '.stop-intent.*' -printf '.\n' | /usr/bin/wc -l) || return 2
    (( count<8 )) || { ro_refuse stop_intent_staging_limit; return 2; }
    temp=$(/usr/bin/mktemp "$RO_ROOT/.stop-intent.XXXXXXXX") || return 2
    if ! /usr/bin/jq -cS --arg boot "$(ro_boot_id)" --arg sha "$RO_STATE_SHA" --argjson unit "$status" '
      {schema_version:1,engine,boot_id:$boot,state_sha256:$sha,revision,phase,current,pending,source_pins,
       invocation_id:$unit.InvocationID,start_usec:$unit.ExecMainStartTimestampMonotonic}' <<< "$RO_STATE" > "$temp"; then
        /bin/rm -f "$temp"; return 2
    fi
    /bin/chmod 600 "$temp" && /bin/sync -- "$temp" || { /bin/rm -f "$temp"; ro_refuse stop_intent_sync_failed; return 2; }
    /bin/mv -T -n -- "$temp" "$path" && [[ ! -e $temp ]] ||
      { /bin/rm -f "$temp"; ro_refuse stop_intent_publish_conflict; return 2; }
    /bin/sync -- "$RO_ROOT" && ro_intent_read || { ro_refuse stop_intent_publish_uncertain; return 2; }
}
ro_intent_clear() {
    local path
    path=$(ro_intent_path)
    ro_intent_read || return 2
    /bin/rm -- "$path" && /bin/sync -- "$RO_ROOT" && [[ ! -e $path && ! -L $path ]] ||
      { ro_refuse stop_intent_clear_uncertain; return 2; }
}
ro_owned_pause() {
    local status=$1
    ro_intent_read || return 2
    [[ $(/usr/bin/jq -r .boot_id <<< "$RO_STOP_INTENT") == "$(ro_boot_id)" ]] ||
      { ro_refuse stop_intent_previous_boot; return 2; }
    /usr/bin/jq -e --argjson intent "$RO_STOP_INTENT" '
      .ActiveState=="inactive" and .Result=="success" and .ExecMainStatus=="0" and
      .ExecMainStartTimestampMonotonic==$intent.start_usec and
      (.InvocationID=="" or .InvocationID==$intent.invocation_id)' <<< "$status" >/dev/null ||
      { ro_refuse vector_pause_not_owned_or_clean; return 2; }
    RO_VECTOR_STOPPED=true
}
ro_reconcile_stop_intent() {
    local path status saved_engine=$RO_ENGINE
    path=$(ro_intent_path)
    [[ -e $path || -L $path ]] || return 0
    ro_intent_read || return 2
    status=$(ro_vector_status) || return 2
    if [[ $(/usr/bin/jq -r .ActiveState <<< "$status") == active ]]; then
        # Clearing an obsolete intent never starts/stops a service. This also
        # handles boot/retry startup and a lost response after successful start.
        ro_guard_all vector || return 2
        ro_engine "$saved_engine" && ro_load || return 2
        ro_intent_clear || return 2
    else
        ro_owned_pause "$status" || return 2
    fi
}
ro_vector_stop_command() {
    /usr/bin/timeout --signal=TERM --kill-after=1s 45s /usr/bin/systemctl stop "$RO_VECTOR_UNIT"
}
ro_stop_vector() {
    local status path
    status=$(ro_vector_status) || return 2
    path=$(ro_intent_path)
    if [[ $(/usr/bin/jq -r .ActiveState <<< "$status") == inactive ]]; then
        ro_owned_pause "$status" || return 2
        return 0
    fi
    [[ $(/usr/bin/jq -r .ActiveState <<< "$status") == active ]] || { ro_refuse vector_not_active; return 2; }
    if [[ -e $path || -L $path ]]; then
        ro_intent_read || return 2
        /usr/bin/jq -e --argjson status "$status" --arg boot "$(ro_boot_id)" '
          .boot_id==$boot and .invocation_id==$status.InvocationID and .start_usec==$status.ExecMainStartTimestampMonotonic
          ' <<< "$RO_STOP_INTENT" >/dev/null || { ro_refuse vector_invocation_changed_before_stop; return 2; }
    else ro_intent_create "$status" || return 2; fi
    # A service may have restarted while the intent was made durable. Recheck
    # the exact invocation immediately before requesting its stop.
    status=$(ro_vector_status) || return 2
    /usr/bin/jq -e --argjson status "$status" --arg boot "$(ro_boot_id)" '
      .boot_id==$boot and $status.ActiveState=="active" and .invocation_id==$status.InvocationID and
      .start_usec==$status.ExecMainStartTimestampMonotonic
      ' <<< "$RO_STOP_INTENT" >/dev/null || { ro_refuse vector_invocation_changed_before_stop; return 2; }
    RO_VECTOR_STOPPED=true
    ro_vector_stop_command || { ro_refuse vector_stop_failed; return 2; }
    status=$(ro_vector_status) && ro_owned_pause "$status" || { ro_refuse vector_stop_not_clean; return 2; }
}
ro_drain() {
    local size w v
    size=$(/usr/bin/jq -r .proof.old_closed.bytes <<< "$RO_STATE")
    cg_sealed_lines "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" "$size" 1048576 >/dev/null ||
        { ro_refuse sealed_line_guard_failed; return 2; }
    # Quiet/new-empty generations must not stop/restart Vector every timer run.
    # Publication still repeats the check with the frozen reader offset later.
    ro_prefix_distinct "$size" || return 2
    w=$(cg_wazuh_eof "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" "$size") ||
        { ro_refuse wazuh_old_eof_pending; return 2; }
    ro_stop_vector || return 2
    v=$(cg_vector_eof "$RO_CP" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" "$size") ||
        { ro_refuse vector_old_eof_pending; return 2; }
    ro_state_change --argjson w "$w" --argjson v "$v" \
      '.revision+=1|.phase="readers_drained"|.proof.readers_drained={vector_checkpoint_sha256:$v.checkpoint_sha256,wazuh_checkpoint_sha256:$w.checkpoint_sha256,vector_offset:$v.offset,wazuh_offset:$w.offset,wazuh_sha1:$w.stored_sha1,vector_stopped:true}'
}
ro_prepare_publication() {
    local cold size
    # A preceding attempt may have safely restored Vector. Stop it cleanly
    # again before publication; a stored proof never implies current inactivity.
    ro_stop_vector || return 2
    size=$(/usr/bin/jq -r .proof.old_closed.bytes <<< "$RO_STATE")
    cg_vector_eof "$RO_CP" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" "$size" >/dev/null || return 2
    cg_wazuh_eof "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" "$size" >/dev/null || return 2
    ro_prefix_distinct || return 2
    cold=$(cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_NEXT" "$RO_OLD_DEV" "$RO_OLD_INO") ||
        { ro_refuse next_generation_cold_prefix_unsafe; return 2; }
    /usr/bin/jq -e '.reason=="saved_zero" or .reason=="different_prefix"' <<< "$cold" >/dev/null || return 2
    ro_state_change --argjson cold "$cold" \
      '.revision+=1|.phase="publish_pending"|.proof.publish_guard={decision:$cold.reason,new_prefix_sha1:$cold.prefix_sha1,old_offset:$cold.offset,old_sha1:$cold.stored_sha1,source_bytes:$cold.source_identity.bytes,wazuh_checkpoint_sha256:$cold.checkpoint_sha256}'
}
ro_prefix_distinct() {
    local offset size common rc=0
    if [[ $# == 0 ]]; then offset=$(/usr/bin/jq -r .proof.readers_drained.wazuh_offset <<< "$RO_STATE") || return 2
    elif [[ $# == 1 ]]; then offset=$1
    else return 2; fi
    [[ $offset =~ ^(0|[1-9][0-9]{0,8})$ ]] && (( offset<=536870912 )) || return 2
    (( offset==0 )) && return 0
    ro_regular "$RO_CURRENT" && ro_regular "$RO_NEXT" &&
      ro_match "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" && ro_match "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO" || return 2
    size=$(/usr/bin/stat -c %s "$RO_NEXT") || return 2
    [[ $size =~ ^[0-9]+$ && $offset =~ ^[0-9]+$ ]] && (( offset<=536870912 && size<=2147483648 )) || return 2
    common=$offset; (( size>=common )) || common=$size
    (( common>0 )) || { ro_refuse next_prefix_not_yet_distinguishable; return 2; }
    /usr/bin/cmp -s -n "$common" -- "$RO_CURRENT" "$RO_NEXT" || rc=$?
    [[ $rc == 1 ]] || { ro_refuse next_prefix_not_distinguishable; return 2; }
    ro_match "$RO_CURRENT" "$RO_OLD_DEV" "$RO_OLD_INO" && ro_match "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO" || return 2
    (( $(/usr/bin/stat -c %s "$RO_NEXT")>=common ))
}
ro_start_vector() {
    local saved_engine=$RO_ENGINE rc=0 reason status was_inactive=false path
    status=$(ro_vector_status) || return 2
    if [[ $(/usr/bin/jq -r .ActiveState <<< "$status") == inactive ]]; then
        ro_owned_pause "$status" || return 2
        was_inactive=true
    else
        [[ $(/usr/bin/jq -r .ActiveState <<< "$status") == active ]] || return 2
    fi
    ro_guard_all vector || rc=$?
    reason=$RO_REASON
    ro_engine "$saved_engine" && ro_load || return 2
    RO_REASON=$reason
    (( rc==0 )) || return 2
    if [[ $was_inactive == true ]]; then
        status=$(ro_vector_status) && ro_owned_pause "$status" || return 2
        ro_vector_start_command || return 2
    fi
    status=$(ro_vector_status) || return 2
    [[ $(/usr/bin/jq -r .ActiveState <<< "$status") == active ]] || return 2
    path=$(ro_intent_path)
    if [[ -e $path || -L $path ]]; then ro_intent_clear || return 2; fi
    RO_VECTOR_STOPPED=false
}
ro_vector_start_command() {
    /usr/bin/timeout --signal=TERM --kill-after=1s 125s /usr/bin/systemctl start "$RO_VECTOR_UNIT"
}
ro_wazuh_fd() {
    local file pid ticks before after matches=0 fd count=0 selected=''
    for file in /var/ossec/var/run/wazuh-logcollector-*.pid; do
        [[ -f $file ]] || continue
        pid=${file##*/wazuh-logcollector-}; pid=${pid%.pid}
        [[ $pid =~ ^[1-9][0-9]{0,9}$ && $pid -gt 1 ]] || return 2
        [[ $(/usr/bin/readlink "/proc/$pid/exe") == /var/ossec/bin/wazuh-logcollector ]] || continue
        count=$((count+1)); selected=$pid
    done
    (( count==1 )) || return 2
    before=$(/usr/bin/awk '{sub(/^.*\) /, ""); print $1 ":" $20}' "/proc/$selected/stat") || return 2
    [[ $before != Z:* && $before != X:* ]] || return 2
    for fd in /proc/"$selected"/fd/*; do
        if [[ $(/usr/bin/stat -Lc %d:%i "$fd" 2>/dev/null) == "$RO_NEW_DEV:$RO_NEW_INO" ]]; then matches=$((matches+1)); fi
    done
    after=$(/usr/bin/awk '{sub(/^.*\) /, ""); print $20}' "/proc/$selected/stat") || return 2
    [[ $after == "${before#*:}" && $matches -ge 1 ]]
}
ro_publish() {
    ro_validate || return 2
    if [[ $RO_ALIAS_KIND == old ]]; then
        ro_stop_vector || return 2
        ro_guard_one vector || return 2
        # The pending generation is still being appended. Revalidate the
        # distinguishable prefix immediately before publishing the alias.
        ro_prefix_distinct || return 2
        ro_replace_link "$RO_ALIAS" "$RO_OLD_DEV:$RO_OLD_INO" "$RO_NEXT" || return 2
    fi
    ro_start_vector || { ro_refuse reader_restart_guard_failed; return 2; }
    # A successful native start is insufficient: both native readers must
    # expose current-inode state before the durable phase becomes active.
    local current_wazuh
    cg_vector_current "$RO_CP" "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO" >/dev/null &&
      current_wazuh=$(cg_wazuh_cold "$RO_WAZUH_CP" "$RO_ALIAS" "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO") &&
      ro_wazuh_fd || { ro_refuse new_reader_checkpoint_pending; return 2; }
    if [[ $(/usr/bin/jq -r .proof.readers_drained.wazuh_offset <<< "$RO_STATE") != 0 &&
          $(/usr/bin/jq -r .offset <<< "$current_wazuh") == "$(/usr/bin/jq -r .proof.readers_drained.wazuh_offset <<< "$RO_STATE")" &&
          $(/usr/bin/jq -r .stored_sha1 <<< "$current_wazuh") == "$(/usr/bin/jq -r .proof.readers_drained.wazuh_sha1 <<< "$RO_STATE")" ]]; then
        ro_refuse old_checkpoint_entry_not_advanced; return 2
    fi
    ro_validate || return 2
    ro_state_change '.revision+=1|.phase="active"|.current=.pending|.pending=null|.proof={old_closed:null,readers_drained:null,publish_guard:null}'
}
ro_operation() {
    local action=$1 engine=$2 rc=0
    ro_engine "$engine" && ro_load || return 2
    # Reject stale/orphan markers before link reconciliation or new allocation.
    ro_reconcile_writer_signal || return 2
    ro_reconcile_link || return 2
    ro_validate || return 2
    ro_reconcile_stop_intent || return 2
    if [[ $RO_PHASE == active ]]; then
        [[ $action != resume ]] || return 0
        local unit_status
        unit_status=$(ro_vector_status) || return 2
        [[ $(/usr/bin/jq -r .ActiveState <<< "$unit_status") == active ]] ||
          { ro_refuse vector_not_active; return 2; }
        if ro_new_generation; then :; else rc=$?; [[ $rc == 10 ]] && return 0; return 2; fi
    fi
    [[ $RO_PHASE != switch_pending ]] || { ro_switch_writer || return 2; }
    ro_reconcile_writer_signal || return 2
    [[ $RO_PHASE != old_closed ]] || { ro_drain || return 2; }
    [[ $RO_PHASE != readers_drained ]] || { ro_prepare_publication || return 2; }
    [[ $RO_PHASE != publish_pending ]] || { ro_publish || return 2; }
}
ro_reconcile_link() {
    local temp=$RO_MANAGED/.publish-link parent=$RO_MANAGED
    [[ -e $temp || -L $temp ]] || return 0
    while [[ $parent != / ]]; do
        [[ -d $parent && ! -L $parent ]] || { ro_refuse interrupted_link_parent_changed; return 2; }
        parent=${parent%/*}; [[ -n $parent ]] || parent=/
    done
    [[ $RO_PHASE != active ]] && ro_regular "$temp" && ro_regular "$RO_NEXT" &&
      ro_match "$temp" "$RO_NEW_DEV" "$RO_NEW_INO" && ro_match "$RO_NEXT" "$RO_NEW_DEV" "$RO_NEW_INO" &&
      [[ $(/usr/bin/stat -c %u:%g:%a "$RO_MANAGED") == 0:0:711 ]] ||
        { ro_refuse unrecognized_interrupted_link; return 2; }
    # This removes only the extra staging hardlink. The immutable named
    # generation remains; no source contents or generation file is deleted.
    /bin/rm -- "$temp" && /bin/sync -- "$RO_MANAGED" || { ro_refuse interrupted_link_cleanup_uncertain; return 2; }
}
ro_worker() {
    local action=$1 engine=$2 lock_meta rc=0
    ro_runtime || { ro_json deferred "$RO_REASON"; return 2; }
    ro_regular "$RO_LOCK" && [[ $(/usr/bin/stat -c %u:%g:%a:%h "$RO_LOCK") == 0:0:600:1 ]] ||
        { ro_json deferred shared_lock_invalid; return 2; }
    exec 9<>"$RO_LOCK" || return 2
    /usr/bin/flock -n 9 || { ro_json deferred coordinator_busy; return 2; }
    [[ ! -e /var/lib/capstone-vector-maintenance/resume.pending && ! -L /var/lib/capstone-vector-maintenance/resume.pending ]] ||
        { ro_json deferred output_rotation_pending; return 2; }
    trap 'if [[ $RO_VECTOR_STOPPED == true ]]; then ro_start_vector >/dev/null 2>&1 || true; fi' EXIT
    trap 'RO_REASON=operation_interrupted; exit 2' TERM INT HUP
    if ro_operation "$action" "$engine"; then ro_json completed local_rotation_or_not_due
    else rc=$?; ro_json deferred "$RO_REASON"; return "$rc"; fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -uo pipefail
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
    umask 077
    [[ $# == 2 && $1 =~ ^(check|run|resume|force)$ && $2 =~ ^(suricata|modsecurity)$ ]] || exit 64
    action=$1 engine=$2
    if [[ $action == check ]]; then
        if ro_runtime && ro_engine "$engine" && ro_guard_one vector; then ro_json ready read_only_guard
        else ro_json deferred "$RO_REASON"; exit 2; fi
    else
        RO_FORCE=false; [[ $action != force ]] || RO_FORCE=true
        export RO_FORCE
        # Outer timeout bounds Docker/systemd/checkpoint children as a group.
        # Durable state remains authoritative after an interrupted mutation.
        /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC RO_FORCE="$RO_FORCE" \
          /usr/bin/timeout --signal=TERM --kill-after=5s 240s /bin/bash --noprofile --norc -c \
          'set -uo pipefail; source "$1"; ro_worker "$2" "$3"' raw-coordinator "$RO_LIBRARY/coordinator.sh" "$action" "$engine" 2>/dev/null
    fi
fi
