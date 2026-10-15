#!/bin/bash
# Temporary initial-migration startup barrier. Read-only; never arms/releases
# itself, changes a checkpoint, starts a service or acknowledges delivery.
# Released means delegation to the pinned normal guard, not unconditional allow.
MSG_ROOT=/var/lib/capstone-raw-migration
MSG_FILE=$MSG_ROOT/start-barrier.json
MSG_GUARD=/usr/local/lib/capstone-raw-operations/guard.sh
MSG_MID=096e90b6243e438aa8a7b392be754732
MSG_REASON=unavailable

msg_fail() { MSG_REASON=$1; return 75; }
msg_report() {
    /usr/bin/jq -nc --arg status "$1" --arg reason "$2" \
      '{schema_version:1,status:$status,reason:$reason,read_only:true,migration_barrier:true}'
}
msg_host() {
    [[ $EUID == 0 && $OSTYPE == linux* && $(/usr/bin/cat /etc/machine-id) == "$MSG_MID" ]]
}
msg_parents() {
    local path=$1 mode
    while [[ $path != / ]]; do
        [[ -d $path && ! -L $path && $(/usr/bin/stat -c %u:%g "$path") == 0:0 ]] || return 1
        mode=$(/usr/bin/stat -c %a "$path") || return 1
        # The root-owned sticky ancestor is used only by confined native tests.
        # Public entrypoints supply the fixed /var/lib and /usr/local paths.
        if [[ $path == /var/tmp ]]; then [[ $mode == 1777 ]] || return 1
        else (( (8#$mode & 0022)==0 )) || return 1; fi
        path=${path%/*}; [[ -n $path ]] || path=/
    done
}
msg_identity() { /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' -- "$1"; }
msg_hash() {
    local result
    result=$(/usr/bin/sha256sum -- "$1") || return 1
    printf '%s\n' "${result%% *}"
}
msg_schema() {
    /usr/bin/jq -se --arg machine "$MSG_MID" '
      def hex($n): type=="string" and test("^[a-f0-9]{"+($n|tostring)+"}$");
      length==1 and (.[0] |
      type=="object" and
      keys==["armed_boot_id","armed_ledger_sha256","machine_id","phase","plan_sha256","policy","release","schema_version"] and
      .schema_version==1 and .policy=="capstone-raw-migration-start-v1" and .machine_id==$machine and
      (.plan_sha256|hex(64)) and (.armed_boot_id|hex(32)) and (.armed_ledger_sha256|hex(64)) and
      (if .phase=="blocked" then .release==null elif .phase=="released" then
        (.release|type=="object" and
          keys==["boot_id","ledger_sha256","modsecurity_state_sha256","readers_verified","runtime_guard_sha256","suricata_state_sha256"] and
          (.boot_id|hex(32)) and (.ledger_sha256|hex(64)) and (.runtime_guard_sha256|hex(64)) and
          (.suricata_state_sha256|hex(64)) and (.modsecurity_state_sha256|hex(64)) and
          .readers_verified==["vector","wazuh"])
       else false end))' >/dev/null 2>&1
}
msg_load() {
    local before after raw captured
    msg_parents "$MSG_ROOT" && [[ $(/usr/bin/stat -c %u:%g:%a "$MSG_ROOT") == 0:0:700 ]] ||
      { msg_fail barrier_directory_untrusted; return 75; }
    [[ $MSG_FILE == "$MSG_ROOT/start-barrier.json" && -f $MSG_FILE && ! -L $MSG_FILE &&
       $(/usr/bin/stat -c %u:%g:%a:%h "$MSG_FILE") == 0:0:600:1 ]] &&
      (( $(/usr/bin/stat -c %s "$MSG_FILE")<=4096 )) ||
      { msg_fail barrier_missing_or_untrusted; return 75; }
    before=$(msg_identity "$MSG_FILE") || return 75
    raw=$(/usr/bin/head -c 4097 -- "$MSG_FILE") || return 75
    msg_schema <<< "$raw" || { msg_fail barrier_schema_invalid; return 75; }
    # Byte comparison includes exactly one LF; duplicate keys, concatenated
    # objects and noncanonical JSON cannot masquerade as the reviewed record.
    /usr/bin/cmp -s -- "$MSG_FILE" <(/usr/bin/jq -cS . <<< "$raw") ||
      { msg_fail barrier_not_canonical; return 75; }
    captured=$(printf '%s\n' "$raw" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1) || return 75
    [[ $(msg_hash "$MSG_FILE") == "$captured" ]] || { msg_fail barrier_changed; return 75; }
    after=$(msg_identity "$MSG_FILE") || return 75
    [[ $before == "$after" && ! -L $MSG_FILE ]] || { msg_fail barrier_changed; return 75; }
    MSG_RECORD=$raw MSG_RECORD_SHA=$captured MSG_RECORD_IDENTITY=$after
}
msg_runtime_guard() {
    local before after expected
    msg_parents "${MSG_GUARD%/*}" && [[ -f $MSG_GUARD && ! -L $MSG_GUARD &&
      $(/usr/bin/stat -c %u:%g:%h "$MSG_GUARD") == 0:0:1 ]] &&
      (( (8#$(/usr/bin/stat -c %a "$MSG_GUARD") & 0022)==0 && $(/usr/bin/stat -c %s "$MSG_GUARD")<=65536 )) ||
      { msg_fail runtime_guard_untrusted; return 75; }
    before=$(msg_identity "$MSG_GUARD") || return 75
    expected=$(/usr/bin/jq -r .release.runtime_guard_sha256 <<< "$MSG_RECORD") || return 75
    [[ $(msg_hash "$MSG_GUARD") == "$expected" ]] || { msg_fail runtime_guard_sha_changed; return 75; }
    after=$(msg_identity "$MSG_GUARD") || return 75
    [[ $before == "$after" && ! -L $MSG_GUARD ]] || { msg_fail runtime_guard_changed; return 75; }
}
msg_delegate() {
    exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC \
      /bin/bash --noprofile --norc "$MSG_GUARD" "$1"
}
msg_entry() {
    [[ $# == 1 && ( $1 == vector || $1 == wazuh || $1 == inspect ) ]] || return 64
    msg_host || { msg_report refused fixed_A_root_required; return 75; }
    msg_load || { msg_report refused "$MSG_REASON"; return 75; }
    local mode=$1 phase record_sha=$MSG_RECORD_SHA record_identity=$MSG_RECORD_IDENTITY
    phase=$(/usr/bin/jq -r .phase <<< "$MSG_RECORD") || return 75
    if [[ $mode == inspect ]]; then
        /usr/bin/jq -nc --arg phase "$phase" --arg sha "$record_sha" \
          '{schema_version:1,status:"observed",phase:$phase,barrier_sha256:$sha,read_only:true,reader_start_authorized:false}'
        return 0
    fi
    [[ $phase == released ]] || { msg_report refused initial_migration_blocked; return 75; }
    msg_runtime_guard || { msg_report refused "$MSG_REASON"; return 75; }
    # Re-read after the guard-file validation. Startup is never authorized by
    # a stale release record while the installer is publishing a different one.
    msg_load || { msg_report refused "$MSG_REASON"; return 75; }
    [[ $MSG_RECORD_SHA == "$record_sha" && $MSG_RECORD_IDENTITY == "$record_identity" ]] ||
      { msg_report refused barrier_changed; return 75; }
    msg_delegate "$mode"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -uo pipefail
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
    umask 077
    msg_entry "$@"
fi
