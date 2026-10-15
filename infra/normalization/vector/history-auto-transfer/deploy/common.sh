#!/bin/bash
# Operator-only installer primitives, not a sudo/SSH endpoint.
hd_sha() { sha256sum -- "$1" | cut -d ' ' -f1; }
hd_parents() {
    local p=$1 mode
    while :; do
        [[ -d $p && ! -L $p && $(stat -c '%u:%g' "$p") == 0:0 ]] || return 65
        mode=$(stat -c %a "$p") || return 65
        if [[ $p == /tmp || $p == /var/tmp ]]; then [[ $mode == 1777 ]] || return 65
        else (( (8#$mode & 0022) == 0 )) || return 65; fi
        [[ $p != / ]] || break
        p=$(dirname "$p")
    done
}
hd_file() {
    local p=$1 mode=$2 limit=$3
    hd_parents "$(dirname "$p")" || return 65
    [[ -f $p && ! -L $p && $(stat -c '%u:%g:%a:%h' "$p") == "0:0:$mode:1" ]] || return 65
    (( $(stat -c %s "$p") <= limit ))
}
hd_absent() { [[ ! -e $1 && ! -L $1 ]]; }
hd_newdir() {
    hd_absent "$1" || return 65
    hd_parents "$(dirname "$1")" || return 65
    mkdir -m "$2" -- "$1" || return 65
    sync -- "$1" "$(dirname "$1")"
}
hd_dir() {
    if hd_absent "$1"; then hd_newdir "$1" "$2" || return 65; fi
    hd_parents "$1" || return 65
    [[ $(stat -c %a "$1") == "$2" ]]
}
hd_publish() {
    local source=$1 destination=$2 mode=$3 temp inode digest
    hd_absent "$destination" || return 65
    hd_parents "$(dirname "$destination")" || return 65
    digest=$(hd_sha "$source") || return 65
    temp=$(mktemp "$(dirname "$destination")/.history-install-XXXXXXXX") || return 65
    cp -- "$source" "$temp" || return 65
    chmod "$mode" "$temp" || return 65
    [[ $(hd_sha "$temp") == "$digest" ]] || return 65
    sync -- "$temp" || return 65
    inode=$(stat -c '%d:%i' "$temp") || return 65
    # Atomic no-replace publication; unlike mv -n, EEXIST cannot look successful.
    ln -- "$temp" "$destination" || return 65
    [[ $(stat -c '%d:%i' "$destination") == "$inode" ]] || return 65
    rm -- "$temp" || return 65
    hd_file "$destination" "$mode" 131072 || return 65
    [[ $(hd_sha "$destination") == "$digest" ]] || return 65
    sync -- "$destination" "$(dirname "$destination")"
}
hd_record() {
    local name=$1
    [[ $name =~ ^[a-z0-9-]+\.json$ ]] || return 65
    (set -C; cat > "$HD_BACKUP/$name") || return 65
    chmod 400 "$HD_BACKUP/$name" || return 65
    sync -- "$HD_BACKUP/$name" "$HD_BACKUP"
}
hd_public() {
    local path=$1 expected=$2 before key
    [[ $path == /* && $expected =~ ^[a-f0-9]{64}$ ]] || return 65
    hd_file "$path" 400 1024 || return 65
    before=$(stat -c '%d:%i:%s:%y:%z' "$path") || return 65
    [[ $(hd_sha "$path") == "$expected" && $(wc -l < "$path") == 1 ]] || return 65
    key=$(awk 'NR==1 && NF>=2 && NF<=3 && $1=="ssh-ed25519" && $2~/^[A-Za-z0-9+\/=]+$/ {print $1 " " $2; next} {exit 1} END {if(NR!=1) exit 1}' "$path") || return 65
    [[ -n $key ]] || return 65
    /usr/bin/ssh-keygen -l -E sha256 -f "$path" >/dev/null 2>&1 || return 65
    [[ $(stat -c '%d:%i:%s:%y:%z' "$path") == "$before" && $(hd_sha "$path") == "$expected" ]] || return 65
    printf '%s\n' "$key"
}
hd_sources() {
    local names expected name
    hd_parents "$HD_SOURCE" || return 65
    hd_file "$HD_SOURCE/deploy/source-pins.sha256" 400 2048 || return 65
    expected=$(printf '%s\n' capstone-history-auto-transfer.service capstone-history-auto-transfer.timer export-a.sh run-b.sh runtime.sha256 ssh-b.sh ssh-gate-a.sh test-native.sh transfer-lib.sh worker-b.sh)
    names=$(awk 'NF!=2 || length($1)!=64 || $1!~/^[a-f0-9]+$/ {exit 1} {print $2}' "$HD_SOURCE/deploy/source-pins.sha256") || return 65
    [[ $names == "$expected" ]] || return 65
    while IFS= read -r name; do hd_file "$HD_SOURCE/$name" 400 32768 || return 65; done <<< "$expected"
    (cd "$HD_SOURCE" && sha256sum --status -c deploy/source-pins.sha256)
}
hd_backup() {
    local role=$1 name
    [[ $role == a-install || $role == b-key || $role == b-install ]] || return 65
    hd_dir /var/backups/capstone-history-transfer-20261015 700 || return 65
    HD_BACKUP=/var/backups/capstone-history-transfer-20261015/$role
    hd_newdir "$HD_BACKUP" 700 || { HD_BACKUP=; return 65; }
    cp -- "$HD_SOURCE/deploy/source-pins.sha256" "$HD_BACKUP/source-pins.sha256" || return 65
    chmod 400 "$HD_BACKUP/source-pins.sha256" || return 65
    sync -- "$HD_BACKUP/source-pins.sha256" "$HD_BACKUP" || return 65
    hd_newdir "$HD_BACKUP/source" 700 || return 65
    for name in capstone-history-auto-transfer.service capstone-history-auto-transfer.timer export-a.sh run-b.sh runtime.sha256 ssh-b.sh ssh-gate-a.sh test-native.sh transfer-lib.sh worker-b.sh; do
        hd_publish "$HD_SOURCE/$name" "$HD_BACKUP/source/$name" 400 || return 65
    done
    for name in common.sh deploy-a.sh deploy-b.sh; do
        hd_file "$HD_SOURCE/deploy/$name" 400 32768 || return 65
        hd_publish "$HD_SOURCE/deploy/$name" "$HD_BACKUP/source/$name" 400 || return 65
    done
    jq -cnS --arg role "$role" --arg at "$(date --iso-8601=seconds)" \
      '{schema_version:1,role:$role,at_kst:$at,automatic_retry:false}' | hd_record intent.json
}
hd_command() { /usr/bin/timeout --signal=TERM --kill-after=2s 30s "$@"; }
hd_finish() {
    local rc=$?
    trap - EXIT
    if ((rc)); then
        local status
        status=$(jq -cnS --arg phase "$HD_PHASE" --argjson rc "$rc" \
          '{schema_version:1,status:"inspect_required",phase:$phase,exit_code:$rc,automatic_retry:false}')
        if [[ -n ${HD_BACKUP:-} && -d $HD_BACKUP && ! -L $HD_BACKUP ]]; then
            printf '%s\n' "$status" | hd_record failure.json || :
        fi
        printf '%s\n' "$status"
    fi
    exit "$rc"
}
