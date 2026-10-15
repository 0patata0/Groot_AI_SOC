#!/bin/bash
# Finite administrator-only A/WAF handoff. Sourced by the pinned native play.
# Uncertain mutations are retained; this driver never repeats a pending action.
WRC_SOURCE=${BASH_SOURCE[0]}
WRC_BASE=/var/backups/capstone-waf-recreation-20261015
WRC_WORK=$WRC_BASE/cutover
WRC_REBIND=$WRC_BASE/rebind
WRC_LIB=/usr/local/lib/capstone-raw-operations
WRC_STATE=/var/lib/capstone-raw-operations
WRC_RAW=/home/groot_a/capstone/secstack/logs/modsec
WRC_OLD=02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e
WRC_IMAGE=sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650
WRC_NETWORK=aaadd71ccea72ed484e217ace846752bcaf465412116f3806de5b14834138654
WRC_BARRIER=$'[Service]\nExecStartPre=/usr/bin/false\n'
WRC_TIMERS=(capstone-raw-operations@suricata.timer capstone-raw-operations@modsecurity.timer capstone-vector-maintenance.timer)
WRC_READERS=(capstone-vector.service wazuh-agent.service)
WRC_NAMES=(vector.env raw-line-binding.json waf-binding.json suricata-state.json modsecurity-state.json)
WRC_TARGETS=(/etc/capstone-vector/vector.env /etc/capstone-vector/raw-line-binding.json /etc/capstone-vector/waf-binding.json /var/lib/capstone-raw-operations/suricata/state.json /var/lib/capstone-raw-operations/modsecurity/state.json)
wrc_die() { printf '%s\n' "WAF cutover refused: $1" >&2; return 75; }
wrc_sha() { local x; x=$(sha256sum -- "$1") || return 1; printf '%s\n' "${x%% *}"; }
wrc_dir() {
    local p=$1 mode
    while [[ $p != / ]]; do
        [[ -d $p && ! -L $p && $(stat -c %u:%g "$p") == 0:0 ]] || return 1
        mode=$(stat -c %a "$p") || return 1
        (( (8#$mode & 0022)==0 )) || return 1
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
wrc_file() {
    [[ -f $1 && ! -L $1 && $(stat -c %u:%g:%a:%h "$1") == "0:0:$2:1" &&
       $(stat -c %s "$1") -le ${3:-65536} ]] && wrc_dir "${1%/*}"
}
wrc_json() { wrc_file "$1" "$2" && jq -se 'length==1' "$1" >/dev/null && cmp -s "$1" <(jq -cS . "$1"); }
wrc_target() {
    local path=$1 mode=$2 parent
    if [[ $path == /home/groot_a/capstone/secstack/logs/modsec/capstone-managed/audit-path.conf ]]; then
        [[ $mode == 444 && -f $path && ! -L $path && $(stat -c %u:%g:%a:%h "$path") == 0:0:444:1 && $(stat -c %s "$path") == 78 ]] || return 1
        parent=${path%/*}
        [[ $(stat -c %u:%g:%a "$parent") == 0:0:711 ]] || return 1
        while [[ $parent != / ]]; do
            [[ -d $parent && ! -L $parent ]] || return 1
            parent=${parent%/*}; [[ -n $parent ]] || parent=/
        done
    else wrc_file "$path" "$mode"; fi
}
wrc_new() {
    local dest=$1 mode=$2 temp
    [[ ! -e $dest && ! -L $dest ]] && wrc_dir "${dest%/*}" || return 1
    temp=$(mktemp "${dest%/*}/.new.XXXXXXXX") || return 1
    cat > "$temp" && chmod "$mode" "$temp" && sync -- "$temp" || return 1
    mv -T -n -- "$temp" "$dest" && [[ ! -e $temp ]] && sync -- "$dest" "${dest%/*}"
}
wrc_replace() {
    local dest=$1 old=$2 source=$3 mode=$4 temp
    wrc_target "$dest" "$mode" && [[ $(wrc_sha "$dest") == "$old" ]] || return 1
    temp=$(mktemp "${dest%/*}/.next.XXXXXXXX") || return 1
    cat -- "$source" > "$temp" && chmod "$mode" "$temp" && sync -- "$temp" || return 1
    [[ $(wrc_sha "$temp") == "$(wrc_sha "$source")" ]] && wrc_target "$dest" "$mode" &&
      [[ $(wrc_sha "$dest") == "$old" ]] || return 1
    mv -T -- "$temp" "$dest" && sync -- "$dest" "${dest%/*}"
}
wrc_evidence() {
    # A post-action verification may finish after its first response was lost.
    # Reuse only exactly the same already durable evidence; never overwrite it.
    local dest=$1 temp
    temp=$(mktemp "$WRC_WORK/.evidence.XXXXXXXX") || return 1
    if ! cat > "$temp"; then rm -- "$temp"; return 1; fi
    if [[ -e $dest || -L $dest ]]; then
        if ! { wrc_file "$dest" 400 && cmp -s "$dest" "$temp" && sync -- "$dest" "${dest%/*}"; }; then
            rm -- "$temp"; return 1
        fi
    else
        if ! wrc_new "$dest" 400 < "$temp"; then rm -- "$temp"; return 1; fi
    fi
    rm -- "$temp"
}
wrc_docker_contract() {
    [[ $(/usr/bin/timeout --signal=TERM --kill-after=1s 15s /usr/local/bin/docker info --format '{{json .OomKillDisable}}:{{json .CgroupVersion}}') == 'false:"2"' &&
       $(/usr/bin/timeout --signal=TERM --kill-after=1s 15s /usr/local/bin/docker version --format '{{.Server.Version}}:{{.Server.APIVersion}}') == 29.8.1:1.56 ]]
}
wrc_unit() {
    systemctl show "$1" -p ActiveState,SubState,InvocationID,MainPID,Result,ExecMainStatus,ExecMainStartTimestampMonotonic |
      jq -RcsSe 'split("\n")|map(select(length>0)|split("="))|
        select(length==7 and all(.[];length==2) and (map(.[0])|unique|length)==7)|
        map({key:.[0],value:.[1]})|from_entries|
        select(keys==["ActiveState","ExecMainStartTimestampMonotonic","ExecMainStatus","InvocationID","MainPID","Result","SubState"])'
}
wrc_inspect() {
    /usr/bin/timeout --signal=TERM --kill-after=1s 15s /usr/local/bin/docker inspect \
      --format '{"cid":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"state":{{json .State}},"restart":{{json .HostConfig.RestartPolicy}},"networks":{{json .NetworkSettings.Networks}}}' "$1" |
      jq -cS '{cid,image,name,restart,networks,state:(.state|{Status,Running,Restarting,Pid,OOMKilled,ExitCode,StartedAt,FinishedAt,Health:{Status:(.Health.Status//null)}})}'
}
wrc_pin_runtime() {
    local item name sha
    for item in \
      coordinator.sh:4b741931945035d1a99d953998cf2543c35d406a647ccaffcb6deb8158ee39c0 \
      guard.sh:7f78865f4be32dbd647b46f15c4d5118471ef5eca607e6f966aa4579b9b3037e \
      state-lib.sh:d754d17726310a56c77e5d37c41f0ae3883881dfbc91bfa20b7ef916fe428f3a \
      state.jq:3db6baef5c679521bdc257cbe1aca66fd6884714f734a1778ca27b249e40a775 \
      checkpoint-gates.sh:92acb7ce322d109bc7e70c32bb42a17cf5cddd1b7f5b6d7f23871e89cbaa4af6 \
      checkpoint-gates.jq:ebc3022b44dae2a79845e35b5b26439d369162715644a720ce35257a1e22d8e6 \
      writer-gates.sh:c8a4f766c8cff125115f4d6413b746309004d608fdc1db370ec4dfe456cb1667; do
        name=${item%%:*}; sha=${item#*:}
        wrc_dir "$WRC_LIB" && [[ -f $WRC_LIB/$name && ! -L $WRC_LIB/$name &&
          $(stat -c %u:%g:%h "$WRC_LIB/$name") == 0:0:1 && $(wrc_sha "$WRC_LIB/$name") == "$sha" ]] || return 1
        (( (8#$(stat -c %a "$WRC_LIB/$name") & 0022)==0 )) || return 1
    done
    source "$WRC_LIB/coordinator.sh" && ro_runtime
}
wrc_fixed_files() {
    local path
    path=/var/ossec/etc/ossec.conf
    [[ -f $path && ! -L $path && $(stat -c %u:%g:%a:%h "$path") == 0:110:660:1 &&
       $(wrc_sha "$path") == b27ec250b19ef0fe9cc1f999467dc24176b82035e763080b33f037a063d4ce0a ]] || return 1
    path=/etc/capstone-vector/vector.toml
    wrc_file "$path" 600 && [[ $(wrc_sha "$path") == 6602dcefef13b0b9f31310b8f3afe77b66b20795517135911ee38056968e93d8 ]] || return 1
    path=/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf
    wrc_file "$path" 444 && [[ $(wrc_sha "$path") == d95e75f39d082053543b04de10d538154da4ce8b25e9333014b3b2d858b65f8d ]] || return 1
    path=/etc/capstone-waf/modsecurity-override-v2.conf.template
    wrc_file "$path" 444 && [[ $(wrc_sha "$path") == 814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb ]] || return 1
    path=/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf
    [[ -f $path && ! -L $path && $(stat -c %u:%g:%a:%h "$path") == 1000:1000:644:1 &&
       $(wrc_sha "$path") == 62c855cf8e927ff57beb11d92daaa7936bbbdc2b035c029535d0da59cce2eebf ]] || return 1
}
wrc_load() {
    [[ $EUID == 0 && $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || return 1
    wrc_pin_runtime && wrc_fixed_files && wrc_dir "$WRC_BASE" || return 1
    wrc_json "$WRC_BASE/candidate-create/result.json" 400 &&
      wrc_file "$WRC_BASE/candidate-create/candidate-inspect.json" 400 &&
      [[ $(wrc_sha "$WRC_BASE/candidate-create/candidate-inspect.json") == b96c80a08b97830e929af3c9d710aff94f12d914d136c78d37876634989c242f ]] || return 1
    WRC_NEW=$(jq -er --arg old "$WRC_OLD" 'select(.schema_version==1 and .status=="stopped_candidate_profile_verified" and .original_cid==$old and .create_calls==1 and .start_calls==0 and .stop_calls==0 and .new_ipam_config=="172.18.0.2")|.candidate_cid|select(test("^[a-f0-9]{64}$"))' "$WRC_BASE/candidate-create/result.json") || return 1
    [[ $WRC_NEW == 6c72d5a5b8229fc3b6e010c9d046d97ac5c13437cae045c72a330fe0d6d82f81 && $WRC_NEW != "$WRC_OLD" ]] || return 1
    WRC_BOOT=$(tr -d '-' < /proc/sys/kernel/random/boot_id) || return 1
    if [[ -e $WRC_WORK/initialized.json || -L $WRC_WORK/initialized.json ]]; then
        wrc_json "$WRC_WORK/initialized.json" 400 && jq -e --arg boot "$WRC_BOOT" --arg old "$WRC_OLD" --arg new "$WRC_NEW" \
          '.boot_id==$boot and .old_cid==$old and .new_cid==$new' "$WRC_WORK/initialized.json" >/dev/null || return 1
    fi
}
wrc_blocked() {
    local unit path value
    for unit in "${WRC_READERS[@]}"; do
        path=/etc/systemd/system/$unit.d/99-capstone-waf-rebind-block.conf
        wrc_file "$path" 644 && cmp -s "$path" <(printf '%s' "$WRC_BARRIER") || return 1
        [[ $(systemctl show "$unit" -p NeedDaemonReload --value) == no ]] || return 1
        value=$(systemctl show "$unit" -p ExecStartPre --value) || return 1
        [[ $(grep -o 'path=/usr/bin/false' <<< "$value" | wc -l) == 1 && $value == *'/usr/local/lib/capstone-raw-operations/guard.sh'* ]] || return 1
    done
    for unit in "${WRC_TIMERS[@]}"; do
        [[ $(systemctl show "$unit" -p UnitFileState --value) == disabled && $(systemctl show "$unit" -p ActiveState --value) == inactive ]] || return 1
        [[ $(systemctl show "${unit%.timer}.service" -p ActiveState --value) == inactive ]] || return 1
    done
}
wrc_save_old_processes() {
    local members repeated rows='[]' lines pid proc
    members=$(_wg_members "$WRC_OLD") || return 1
    lines=$(jq -r '.[]' <<< "$members") || return 1
    while IFS= read -r pid; do
        proc=$(_wg_proc_identity "$pid") || return 1
        jq -e '.exe=="/usr/sbin/nginx" and all(.uids[];.==101) and all(.gids[];.==101)' <<< "$proc" >/dev/null || return 1
        rows=$(jq -ncS --argjson rows "$rows" --argjson p "$proc" '$rows+[$p|{pid,start_ticks}]') || return 1
    done <<< "$lines"
    repeated=$(_wg_members "$WRC_OLD") || return 1
    [[ $members == "$repeated" ]] && jq -e 'any(.[];.pid==2377669 and .start_ticks=="142492178")' <<< "$rows" >/dev/null || return 1
    printf '%s\n' "$rows" | wrc_evidence "$WRC_WORK/old-processes.json"
}
wrc_old_stopped() {
    local x rows pid ticks observed; x=$(wrc_inspect "$WRC_OLD") || return 1
    jq -e --arg cid "$WRC_OLD" --arg image "$WRC_IMAGE" '.cid==$cid and .image==$image and .state.Running==false and .state.Restarting==false and .state.Pid==0 and .state.OOMKilled==false and .state.ExitCode==0' <<< "$x" >/dev/null || return 1
    wrc_json "$WRC_WORK/old-processes.json" 400 || return 1
    rows=$(jq -er 'select(length>0 and length<=64 and any(.[];.pid==2377669 and .start_ticks=="142492178"))|.[]|[.pid,.start_ticks]|@tsv' "$WRC_WORK/old-processes.json") || return 1
    while IFS=$'\t' read -r pid ticks; do
        [[ $pid =~ ^[1-9][0-9]+$ && $ticks =~ ^[1-9][0-9]+$ ]] || return 1
        if [[ -e /proc/$pid/stat ]]; then
            observed=$(awk '{sub(/^.*\) /, "");print $20}' "/proc/$pid/stat") || return 1
            [[ $observed =~ ^[1-9][0-9]+$ && $observed != "$ticks" ]] || return 1
        fi
    done <<< "$rows"
}
wrc_original_sources() {
    local i
    for i in 0 1 2 3 4; do
        wrc_file "$WRC_WORK/before/${WRC_NAMES[$i]}" 400 && wrc_file "${WRC_TARGETS[$i]}" 600 &&
          cmp -s "$WRC_WORK/before/${WRC_NAMES[$i]}" "${WRC_TARGETS[$i]}" || return 1
    done
    [[ ! -e $WRC_STATE/vector-stop-intent.json && ! -L $WRC_STATE/vector-stop-intent.json &&
       ! -e /var/lib/capstone-vector-maintenance/resume.pending && ! -L /var/lib/capstone-vector-maintenance/resume.pending ]]
}
wrc_old_eof() {
    local dev ino bytes file=$WRC_RAW/capstone-managed/generation-0000000003.jsonl
    dev=$(jq -r .current.device "$WRC_WORK/before/modsecurity-state.json") && ino=$(jq -r .current.inode "$WRC_WORK/before/modsecurity-state.json") || return 1
    [[ ! -L $file && $(stat -c %d:%i:%u:%g:%a:%h "$file") == "$dev:$ino:0:0:400:2" &&
       $(stat -c %d:%i "$WRC_RAW/audit.log") == "$dev:$ino" ]] || return 1
    bytes=$(stat -c %s "$file") || return 1
    cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576 > /dev/null &&
      cg_wazuh_eof /var/ossec/queue/logcollector/file_status.json "$WRC_RAW/audit.log" "$file" "$dev" "$ino" "$bytes" >/dev/null &&
      cg_vector_eof /var/lib/capstone-vector/waf_audit "$file" "$dev" "$ino" "$bytes" >/dev/null
}
wrc_wait_old_eof() {
    # Read-only native CP refresh retries have a hard outer deadline. A deferred
    # read never arms the irreversible stop command or edits native checkpoints.
    /usr/bin/timeout --signal=TERM --kill-after=2s 125s /bin/bash -c '
        set -euo pipefail
        source "$1"
        wrc_pin_runtime
        until wrc_old_eof; do sleep 2; done
    ' wrc-eof "$WRC_SOURCE"
}
wrc_seal_old() {
    local file=$WRC_RAW/capstone-managed/generation-0000000003.jsonl dev ino meta
    dev=$(jq -r .current.device "$WRC_WORK/before/modsecurity-state.json") &&
      ino=$(jq -r .current.inode "$WRC_WORK/before/modsecurity-state.json") || return 1
    [[ -f $file && ! -L $file && ! -L $WRC_RAW/audit.log &&
       $(stat -c %d:%i:%h "$file") == "$dev:$ino:2" &&
       $(stat -c %d:%i "$WRC_RAW/audit.log") == "$dev:$ino" ]] || return 1
    meta=$(stat -c %u:%g:%a "$file") || return 1
    # Only the original metadata, the chown intermediate, or our sealed result.
    [[ $meta == 101:101:644 || $meta == 0:0:644 || $meta == 0:0:400 ]] || return 1
    chown 0:0 "$file" && chmod 400 "$file" && sync -- "$file" "${file%/*}" || return 1
    [[ $(stat -c %d:%i:%u:%g:%a:%h "$file") == "$dev:$ino:0:0:400:2" ]]
}
wrc_arm() {
    local phase=$1 previous=$2
    wrc_load && wrc_dir "$WRC_WORK" && wrc_json "$WRC_WORK/initialized.json" 400 || return 1
    jq -e --arg boot "$WRC_BOOT" --arg cid "$WRC_NEW" '.boot_id==$boot and .new_cid==$cid' "$WRC_WORK/initialized.json" >/dev/null || return 1
    [[ -z $previous ]] || wrc_json "$WRC_WORK/$previous.json" 400 || return 1
    [[ ! -e $WRC_WORK/$phase.intent.json && ! -L $WRC_WORK/$phase.intent.json && ! -e $WRC_WORK/$phase.json && ! -L $WRC_WORK/$phase.json ]] || return 1
    jq -ncS --arg phase "$phase" --arg boot "$WRC_BOOT" --arg old "$WRC_OLD" --arg new "$WRC_NEW" \
      '{schema_version:1,phase:$phase,boot_id:$boot,old_cid:$old,new_cid:$new,armed:true,completion_unknown:true,automatic_retry:false}' |
      wrc_new "$WRC_WORK/$phase.intent.json" 400
}
wrc_finish() {
    local phase=$1
    wrc_json "$WRC_WORK/$phase.intent.json" 400 || return 1
    jq -ncS --arg phase "$phase" --arg sha "$(wrc_sha "$WRC_WORK/$phase.intent.json")" \
      '{schema_version:1,phase:$phase,status:"verified",intent_sha256:$sha,checkpoint_rewritten:false,raw_deleted:false}' |
      wrc_new "$WRC_WORK/$phase.json" 400
}
wrc_initialize() {
    local i unit
    wrc_load || return 1
    [[ ! -e $WRC_WORK && ! -L $WRC_WORK && ! -e $WRC_REBIND && ! -L $WRC_REBIND ]] || return 1
    /bin/bash "$WRC_LIB/guard.sh" vector >/dev/null && /bin/bash "$WRC_LIB/guard.sh" wazuh >/dev/null || return 1
    jq -e '.phase=="active" and .revision==5 and .current.number==1' "$WRC_STATE/suricata/state.json" >/dev/null &&
      jq -e --arg cid "$WRC_OLD" '.phase=="active" and .revision==11 and .current.number==3 and .source_pins.container_id==$cid' "$WRC_STATE/modsecurity/state.json" >/dev/null || return 1
    for unit in "${WRC_TIMERS[@]}"; do
        [[ $(systemctl show "$unit" -p UnitFileState --value) == enabled && $(systemctl show "$unit" -p ActiveState --value) == active ]] || return 1
    done
    mkdir -m 700 "$WRC_WORK" "$WRC_REBIND" "$WRC_WORK/before" || return 1
    sync -- "$WRC_WORK" "$WRC_REBIND" "$WRC_BASE" || return 1
    for i in 0 1 2 3 4; do
        wrc_file "${WRC_TARGETS[$i]}" 600 && cat "${WRC_TARGETS[$i]}" | wrc_new "$WRC_WORK/before/${WRC_NAMES[$i]}" 400 || return 1
    done
    jq -ncS --arg boot "$WRC_BOOT" --arg old "$WRC_OLD" --arg new "$WRC_NEW" \
      '{schema_version:1,boot_id:$boot,old_cid:$old,new_cid:$new,previous_timers:"enabled",raw_generations:{suricata:1,modsecurity:3}}' |
      wrc_new "$WRC_WORK/initialized.json" 400
}
wrc_preflight() {
    local x unit path
    wrc_load || return 1
    [[ ! -e $WRC_WORK && ! -L $WRC_WORK && ! -e $WRC_REBIND && ! -L $WRC_REBIND ]] || return 1
    x=$(wrc_inspect "$WRC_OLD") || return 1
    jq -e --arg image "$WRC_IMAGE" '.name=="/waf" and .image==$image and .state.Running and (.state.Restarting|not) and .state.Pid==2377669 and .state.Health.Status=="healthy" and .networks["secstack_waf-net"].IPAddress=="172.18.0.2"' <<< "$x" >/dev/null || return 1
    x=$(wrc_inspect "$WRC_NEW") || return 1
    jq -e --arg image "$WRC_IMAGE" '.name=="/waf-prestart-20261015" and .image==$image and .state.Status=="created" and (.state.Running|not) and .state.Pid==0 and .restart.Name=="no" and .networks["secstack_waf-net"].IPAMConfig.IPv4Address=="172.18.0.2"' <<< "$x" >/dev/null || return 1
    wrc_docker_contract || return 1
    /usr/bin/timeout --signal=TERM --kill-after=1s 15s /usr/local/bin/docker inspect "$WRC_NEW" |
      jq -e --slurpfile expected "$WRC_BASE/candidate-create/candidate-inspect.json" 'def normalized: map(.Mounts |= sort_by(.Destination)); normalized==($expected[0]|normalized)' >/dev/null || return 1
    wrc_target "$WRC_RAW/capstone-managed/audit-path.conf" 444 || return 1
    wrc_file "$WRC_LIB/waf-rebind-metadata.sh" 400 &&
      [[ $(wrc_sha "$WRC_LIB/waf-rebind-metadata.sh") == 884dbf89cf1a031ae3193100a13832cb76437cf466e02857221c014bb7e550ca ]] || return 1
    wrc_file /usr/local/sbin/capstone-raw-operations 500 &&
      [[ $(wrc_sha /usr/local/sbin/capstone-raw-operations) == 1f5c13ed2ea2b2a0553ff8102c0517a3640da586ee2b50f2e393cc34c2952537 ]] || return 1
    wrc_file /usr/local/sbin/capstone-vector-maintenance 700 &&
      [[ $(wrc_sha /usr/local/sbin/capstone-vector-maintenance) == 2334ba3697cd98a445a5ab83dfa4ba044775868e9ed7a2be9e8ed0cceef0a921 ]] || return 1
    wrc_file /etc/capstone-waf/zz-capstone-evidence-v2.conf 444 &&
      [[ $(wrc_sha /etc/capstone-waf/zz-capstone-evidence-v2.conf) == 1e4c37a9bcedd730e693029fa4b40a6fd5e68a93b206ea161f458e11d7e6e212 ]] || return 1
    [[ ! -e $WRC_RAW/capstone-managed/generation-0000000004.jsonl && ! -L $WRC_RAW/capstone-managed/generation-0000000004.jsonl ]] || return 1
    for path in "${WRC_TARGETS[@]}"; do wrc_file "$path" 600 || return 1; done
    jq -e '.phase=="active" and .revision==5 and .current.number==1' "$WRC_STATE/suricata/state.json" >/dev/null &&
      jq -e '.phase=="active" and .revision==11 and .current.number==3' "$WRC_STATE/modsecurity/state.json" >/dev/null || return 1
    [[ ! -e $WRC_STATE/vector-stop-intent.json && ! -L $WRC_STATE/vector-stop-intent.json &&
       ! -e /var/lib/capstone-vector-maintenance/resume.pending && ! -L /var/lib/capstone-vector-maintenance/resume.pending ]] || return 1
    for unit in "${WRC_TIMERS[@]}"; do
        [[ $(systemctl show "$unit" -p UnitFileState --value) == enabled && $(systemctl show "$unit" -p ActiveState --value) == active ]] || return 1
    done
    for unit in "${WRC_READERS[@]}"; do
        path=/etc/systemd/system/$unit.d/99-capstone-waf-rebind-block.conf
        wrc_dir "${path%/*}" && [[ ! -e $path && ! -L $path ]] || return 1
    done
    /bin/bash "$WRC_LIB/guard.sh" vector >/dev/null && /bin/bash "$WRC_LIB/guard.sh" wazuh >/dev/null || return 1
    jq -ncS --arg cid "$WRC_NEW" '{status:"preflight_ready",candidate_cid:$cid,read_only:true,signals_sent:0,checkpoint_rewritten:false,raw_written:false}'
}

wrc_pre() {
    local phase=$1 x unit path before dev ino file
    wrc_load || return 1
    case $phase in
      barrier)
        wrc_arm barrier '' && wrc_original_sources || return 1
        for unit in "${WRC_READERS[@]}"; do
            path=/etc/systemd/system/$unit.d/99-capstone-waf-rebind-block.conf
            wrc_dir "${path%/*}" && [[ ! -e $path && ! -L $path ]] || return 1
        done ;;
      stop-old)
        wrc_blocked && wrc_original_sources || return 1
        x=$(wrc_inspect "$WRC_OLD") || return 1
        jq -e --arg image "$WRC_IMAGE" '.name=="/waf" and .image==$image and .state.Running and (.state.Restarting|not) and .state.Pid==2377669 and .state.Health.Status=="healthy"' <<< "$x" >/dev/null || return 1
        [[ $(awk '{sub(/^.*\) /," ");print $20}' /proc/2377669/stat) == 142492178 ]] || return 1
        x=$(wrc_inspect "$WRC_NEW") || return 1
        jq -e --arg image "$WRC_IMAGE" '.name=="/waf-prestart-20261015" and .image==$image and .state.Status=="created" and (.state.Running|not) and .state.Pid==0 and .restart.Name=="no"' <<< "$x" >/dev/null || return 1
        wrc_save_old_processes && wrc_arm stop-old barrier ;;
      drain-stop)
        wrc_blocked && wrc_old_stopped && wrc_original_sources && wrc_json "$WRC_WORK/stop-old.json" 400 || return 1
        [[ ! -e $WRC_WORK/drain-stop.intent.json && ! -L $WRC_WORK/drain-stop.intent.json &&
           ! -e $WRC_WORK/drain-stop.json && ! -L $WRC_WORK/drain-stop.json ]] || return 1
        wrc_seal_old && wrc_wait_old_eof || return 1
        before=$(wrc_unit capstone-vector.service) || return 1
        jq -e '.ActiveState=="active" and .SubState=="running" and .Result=="success" and .ExecMainStatus=="0" and (.MainPID|test("^[1-9][0-9]+$")) and (.InvocationID|test("^[a-f0-9]{32}$")) and (.ExecMainStartTimestampMonotonic|test("^[1-9][0-9]+$"))' <<< "$before" >/dev/null || return 1
        printf '%s\n' "$before" | wrc_evidence "$WRC_WORK/vector-stop-before.json" || return 1
        [[ $(wrc_unit capstone-vector.service) == "$before" ]] && wrc_arm drain-stop stop-old || return 1 ;;
      retain-old)
        wrc_blocked && wrc_old_stopped && wrc_original_sources && wrc_arm retain-old prepare-new || return 1
        [[ $(wrc_inspect "$WRC_OLD" | jq -r .name) == /waf && $(wrc_inspect "$WRC_NEW" | jq -r .name) == /waf-prestart-20261015 ]] || return 1 ;;
      name-new)
        wrc_blocked && wrc_old_stopped && wrc_original_sources && wrc_arm name-new retain-old || return 1
        [[ $(wrc_inspect "$WRC_OLD" | jq -r .name) == /waf-before-20261015 && $(wrc_inspect "$WRC_NEW" | jq -r .name) == /waf-prestart-20261015 ]] || return 1 ;;
      start-new)
        wrc_blocked && wrc_old_stopped && wrc_original_sources && wrc_docker_contract || return 1
        x=$(wrc_inspect "$WRC_NEW") || return 1
        jq -e '.name=="/waf" and .state.Status=="created" and .state.Pid==0 and (.state.Running|not) and .restart.Name=="no" and .networks["secstack_waf-net"].IPAMConfig.IPv4Address=="172.18.0.2"' <<< "$x" >/dev/null || return 1
        /usr/local/bin/docker network inspect --format '{{json .Containers}}' "$WRC_NETWORK" |
          jq -e 'all(.[];(.IPv4Address|split("/")[0])!="172.18.0.2")' >/dev/null || return 1
        [[ $(wrc_sha /etc/capstone-waf/zz-capstone-evidence-v2.conf) == "$(jq -r .producer_sha256 "$WRC_WORK/prepare-new-details.json")" ]] && wrc_arm start-new name-new || return 1 ;;
      *) return 64 ;;
    esac
}
wrc_stop_dispatch_guard() {
    local before
    wrc_load && wrc_blocked && wrc_old_stopped && wrc_original_sources &&
      wrc_json "$WRC_WORK/drain-stop.intent.json" 400 && wrc_json "$WRC_WORK/vector-stop-before.json" 400 || return 1
    jq -e --arg boot "$WRC_BOOT" --arg new "$WRC_NEW" --arg old "$WRC_OLD"       '.phase=="drain-stop" and .boot_id==$boot and .old_cid==$old and .new_cid==$new and .armed==true and .completion_unknown==true and .automatic_retry==false' "$WRC_WORK/drain-stop.intent.json" >/dev/null || return 1
    before=$(cat "$WRC_WORK/vector-stop-before.json") || return 1
    [[ $(wrc_unit capstone-vector.service) == "$before" ]]
}
wrc_post() {
    local phase=$1 x before after status ticks
    wrc_load || return 1
    case $phase in
      barrier) wrc_blocked && wrc_original_sources || return 1 ;;
      stop-old) wrc_old_stopped && wrc_blocked || return 1 ;;
      drain-stop)
        wrc_old_stopped && wrc_old_eof && wrc_blocked && wrc_original_sources || return 1
        before=$(cat "$WRC_WORK/vector-stop-before.json") && after=$(wrc_unit capstone-vector.service) || return 1
        jq -ne --argjson b "$before" --argjson a "$after" '$a.ActiveState=="inactive" and $a.SubState=="dead" and $a.MainPID=="0" and $a.Result=="success" and $a.ExecMainStatus=="0" and $a.ExecMainStartTimestampMonotonic==$b.ExecMainStartTimestampMonotonic and ($a.InvocationID=="" or $a.InvocationID==$b.InvocationID)' >/dev/null || return 1
        jq -ncS --arg boot "$WRC_BOOT" --arg old "$WRC_OLD" --arg new "$WRC_NEW" --arg sha "$(wrc_sha "$WRC_WORK/before/modsecurity-state.json")" --argjson before "$before" --argjson after "$after" \
          '{schema_version:1,policy:"capstone-waf-rebind-vector-stop-v1",boot_id:$boot,old_cid:$old,new_cid:$new,invocation_id:$before.InvocationID,start_usec:$before.ExecMainStartTimestampMonotonic,stop_armed:true,stopped_clean:true,old_state_sha256:$sha,before_status:$before,after_status:$after}' |
          wrc_evidence "$WRC_REBIND/stop-proof.json" || return 1 ;;
      retain-old)
        wrc_old_stopped && [[ $(wrc_inspect "$WRC_OLD" | jq -r .name) == /waf-before-20261015 ]] || return 1 ;;
      name-new)
        wrc_old_stopped && [[ $(wrc_inspect "$WRC_NEW" | jq -r .name) == /waf && $(wrc_inspect "$WRC_NEW" | jq -r .state.Status) == created ]] || return 1 ;;
      start-new)
        wrc_old_stopped && wrc_blocked || return 1
        x=$(wrc_inspect "$WRC_NEW") || return 1
        jq -e --arg cid "$WRC_NEW" --arg image "$WRC_IMAGE" --arg network "$WRC_NETWORK" '.cid==$cid and .image==$image and .name=="/waf" and .state.Running and (.state.Restarting|not) and .state.Pid>1 and .state.Health.Status=="healthy" and .restart.Name=="no" and .networks["secstack_waf-net"].IPAddress=="172.18.0.2" and .networks["secstack_waf-net"].NetworkID==$network' <<< "$x" >/dev/null || return 1
        wrc_new_writer || return 1
        printf '%s\n' "$x" | wrc_evidence "$WRC_WORK/new-running.json" || return 1 ;;
      *) return 64 ;;
    esac
    wrc_finish "$phase"
}
wrc_prepare_new() {
    local binding oldbinding original next pointer oldsha
    wrc_load && wrc_blocked && wrc_old_stopped && wrc_original_sources && wrc_old_eof || return 1
    wrc_arm prepare-new drain-stop || return 1
    next=$WRC_RAW/capstone-managed/generation-0000000004.jsonl
    pointer=$WRC_RAW/capstone-managed/audit-path.conf
    [[ ! -e $next && ! -L $next && $(stat -c %u:%g:%a "${next%/*}") == 0:0:711 ]] || return 1
    wrc_target "$pointer" 444 || return 1
    wrc_file /etc/capstone-waf/zz-capstone-evidence-v2.conf 444 &&
      [[ $(wrc_sha /etc/capstone-waf/zz-capstone-evidence-v2.conf) == 1e4c37a9bcedd730e693029fa4b40a6fd5e68a93b206ea161f458e11d7e6e212 ]] || return 1
    oldbinding=$(jq -er .deployment_binding "$WRC_WORK/before/waf-binding.json") || return 1
    binding=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n') || return 1
    [[ $binding =~ ^[a-f0-9]{64}$ && $oldbinding =~ ^[a-f0-9]{64}$ && $binding != "$oldbinding" ]] || return 1
    jq -ne --rawfile producer /etc/capstone-waf/zz-capstone-evidence-v2.conf --arg old "$oldbinding" '$producer|split($old)|length==3' >/dev/null || return 1
    jq -nrj --rawfile producer /etc/capstone-waf/zz-capstone-evidence-v2.conf --arg old "$oldbinding" --arg new "$binding" '$producer|split($old)|join($new)' |
      wrc_new "$WRC_REBIND/new-producer.conf" 400 || return 1
    printf 'SecAuditLog /var/log/modsecurity/capstone-managed/generation-0000000004.jsonl\n' | wrc_new "$WRC_WORK/new-audit-path.conf" 400 || return 1
    oldsha=$(jq -r .current.writer_config_sha256 "$WRC_WORK/before/modsecurity-state.json") || return 1
    # New writer output is created exclusively; the existing alias is untouched.
    (set -o noclobber; : > "$next") && chown 101:101 "$next" && chmod 644 "$next" && sync -- "$next" "${next%/*}" || return 1
    wrc_replace "$pointer" "$oldsha" "$WRC_WORK/new-audit-path.conf" 444 || return 1
    wrc_replace /etc/capstone-waf/zz-capstone-evidence-v2.conf 1e4c37a9bcedd730e693029fa4b40a6fd5e68a93b206ea161f458e11d7e6e212 "$WRC_REBIND/new-producer.conf" 444 || return 1
    jq -ncS --arg binding "$binding" --arg producer "$(wrc_sha "$WRC_REBIND/new-producer.conf")" --arg pointer "$(wrc_sha "$pointer")" \
      --argjson dev "$(stat -c %d "$next")" --argjson ino "$(stat -c %i "$next")" \
      '{schema_version:1,new_binding:$binding,producer_sha256:$producer,writer_config_sha256:$pointer,pending:{number:4,device:$dev,inode:$ino,basename:"generation-0000000004.jsonl",writer_config_sha256:$pointer}}' |
      wrc_new "$WRC_WORK/prepare-new-details.json" 400 || return 1
    wrc_finish prepare-new
}
wrc_new_writer() {
    local observed identity dev ino olddev oldino proof rc=0 expected x
    observed=$(writer_identity waf) || return 1
    identity=$(jq -ce --arg cid "$WRC_NEW" 'select(.status=="observed" and .identity.cid==$cid and .identity.uid==101 and .identity.gid==101)|.identity' <<< "$observed") || return 1
    olddev=$(jq -r .current.device "$WRC_WORK/before/modsecurity-state.json") && oldino=$(jq -r .current.inode "$WRC_WORK/before/modsecurity-state.json") || return 1
    dev=$(jq -r .pending.device "$WRC_WORK/prepare-new-details.json") && ino=$(jq -r .pending.inode "$WRC_WORK/prepare-new-details.json") || return 1
    writer_gate waf "$identity" "$olddev" "$oldino" >/dev/null || return 1
    proof=$(writer_gate waf "$identity" "$dev" "$ino") || rc=$?
    [[ $rc == 10 ]] && jq -e '.status=="open"' <<< "$proof" >/dev/null || return 1
    # Actual first-start native output must match both immutable host bindings.
    for x in /etc/modsecurity.d/modsecurity-override.conf /etc/nginx/modsecurity.d/modsecurity-override.conf /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template; do
        expected=$(/usr/local/bin/docker exec --user 0 "$WRC_NEW" sha256sum "$x") || return 1
        [[ $expected == "814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb  $x" ]] || return 1
    done
    expected=$(/usr/local/bin/docker exec --user 0 "$WRC_NEW" sha256sum /etc/nginx/conf.d/zz-capstone-evidence.conf) || return 1
    [[ $expected == "$(jq -r .producer_sha256 "$WRC_WORK/prepare-new-details.json")  /etc/nginx/conf.d/zz-capstone-evidence.conf" ]] || return 1
    wrc_docker_contract || return 1
    /usr/local/bin/docker inspect "$WRC_NEW" | jq -e --slurpfile expected "$WRC_BASE/candidate-create/candidate-inspect.json" \
      'def empty_keys: ["BlkioDeviceReadBps","BlkioDeviceReadIOps","BlkioDeviceWriteBps","BlkioDeviceWriteIOps","BlkioWeightDevice","Devices","DnsOptions","DnsSearch"];
       def empty_only: . as $h|all(empty_keys[]; $h[.]==null or $h[.]==[]);
       def host_config: reduce empty_keys[] as $key (del(.OomKillDisable); .[$key]=null);
       length==1 and .[0].Config==$expected[0][0].Config and
       (.[0].HostConfig|keys)==($expected[0][0].HostConfig|keys) and
       (.[0].HostConfig|has("OomKillDisable")) and ($expected[0][0].HostConfig|has("OomKillDisable")) and
       (.[0].HostConfig|empty_only) and ($expected[0][0].HostConfig|empty_only) and
       (.[0].HostConfig|host_config)==($expected[0][0].HostConfig|host_config) and
       ($expected[0][0].HostConfig.OomKillDisable==false and (.[0].HostConfig.OomKillDisable==false or .[0].HostConfig.OomKillDisable==null)) and
       (.[0].Mounts|sort_by(.Destination))==($expected[0][0].Mounts|sort_by(.Destination)) and (.[0].Mounts|length)==5 and .[0].RestartCount==0' >/dev/null || return 1
}
wrc_descriptor() {
    local old new oldbytes newbytes common cold identity running runtime='{}' hashes='{}' name unit vpre wpre
    wrc_load && wrc_blocked && wrc_old_stopped && wrc_original_sources && wrc_old_eof && wrc_new_writer || return 1
    wrc_json "$WRC_WORK/start-new.json" 400 || return 1
    [[ ! -e $WRC_REBIND/descriptor.json && ! -L $WRC_REBIND/descriptor.json ]] || return 1
    old=$WRC_RAW/capstone-managed/generation-0000000003.jsonl
    new=$WRC_RAW/capstone-managed/generation-0000000004.jsonl
    oldbytes=$(stat -c %s "$old") && newbytes=$(stat -c %s "$new") || return 1
    if (( oldbytes>0 )); then
        (( newbytes>0 )) || return 1
        common=$oldbytes; (( newbytes>=common )) || common=$newbytes
        local rc=0; cmp -s -n "$common" "$old" "$new" || rc=$?
        [[ $rc == 1 ]] || return 1
    fi
    cg_wazuh_cold /var/ossec/queue/logcollector/file_status.json "$WRC_RAW/audit.log" "$new" "$(stat -c %d "$old")" "$(stat -c %i "$old")" >/dev/null || return 1
    identity=$(writer_identity waf | jq -ce .identity) && running=$(wrc_inspect "$WRC_NEW") || return 1
    for name in coordinator.sh guard.sh state-lib.sh state.jq checkpoint-gates.sh checkpoint-gates.jq writer-gates.sh; do
        runtime=$(jq -ncS --argjson old "$runtime" --arg key "$name" --arg sha "$(wrc_sha "$WRC_LIB/$name")" '$old+{($key):$sha}') || return 1
    done
    for name in "${WRC_NAMES[@]}"; do
        hashes=$(jq -ncS --argjson old "$hashes" --arg key "$name" --arg sha "$(wrc_sha "$WRC_WORK/before/$name")" '$old+{($key):$sha}') || return 1
    done
    vpre=$(systemctl show capstone-vector.service -p ExecStartPre --value | sha256sum | cut -d' ' -f1) &&
      wpre=$(systemctl show wazuh-agent.service -p ExecStartPre --value | sha256sum | cut -d' ' -f1) || return 1
    [[ $(readlink /proc/1909632/exe) == /var/ossec/bin/wazuh-logcollector && $(awk '{sub(/^.*\) /, "");print $20}' /proc/1909632/stat) == 141224139 ]] || return 1
    jq -ncS --arg boot "$WRC_BOOT" --arg old "$WRC_OLD" --arg image "$WRC_IMAGE" --argjson identity "$identity" \
      --arg started "$(jq -r .state.StartedAt <<< "$running")" --argjson runtime "$runtime" --argjson hashes "$hashes" \
      --arg barrier "$(printf '%s' "$WRC_BARRIER" | sha256sum | cut -d' ' -f1)" --arg vpre "$vpre" --arg wpre "$wpre" \
      --arg stop "$(wrc_sha "$WRC_REBIND/stop-proof.json")" --arg winv "$(systemctl show wazuh-agent.service -p InvocationID --value)" \
      --slurpfile details "$WRC_WORK/prepare-new-details.json" \
      '{schema_version:1,policy:"capstone-waf-rebind-metadata-v1",machine_id:"096e90b6243e438aa8a7b392be754732",boot_id:$boot,expected_before_sha256:$hashes,
        authority:{barrier_sha256:$barrier,unit_execstartpre_sha256:{vector:$vpre,wazuh:$wpre},runtime_sha256:$runtime,stop_proof_sha256:$stop,
          old_container:{cid:$old,image:$image,pid:2377669,start_ticks:"142492178"},new_container:{identity:$identity,image:$image,started_at:$started},
          wazuh:{pid:1909632,start_ticks:"141224139",invocation_id:$winv},new_binding:$details[0].new_binding,new_producer_sha256:$details[0].producer_sha256}}' |
      wrc_new "$WRC_REBIND/descriptor.json" 400
}
wrc_publish() {
    local proof status target marker new old alias kind plan_sha i
    wrc_load && wrc_blocked && wrc_old_stopped && wrc_new_writer || return 1
    wrc_json "$WRC_REBIND/result.json" 400 && wrc_json "$WRC_REBIND/stop-proof.json" 400 &&
      wrc_json "$WRC_REBIND/plan.json" 400 && wrc_json "$WRC_REBIND/intent.json" 600 || return 1
    plan_sha=$(wrc_sha "$WRC_REBIND/plan.json") || return 1
    jq -e --arg sha "$plan_sha" '.=={schema_version:1,policy:"capstone-waf-rebind-metadata-v1",status:"metadata_applied",plan_sha256:$sha,files:5,alias_published:false,reader_start_authorized:false,signals_sent:0,raw_written:false,checkpoint_written:false}' "$WRC_REBIND/result.json" >/dev/null &&
      jq -e --arg sha "$plan_sha" '.=={schema_version:1,policy:"capstone-waf-rebind-metadata-v1",plan_sha256:$sha,prefix:5,attempted:null,complete:true}' "$WRC_REBIND/intent.json" >/dev/null || return 1
    for i in 0 1 2 3 4; do
        wrc_file "${WRC_TARGETS[$i]}" 600 && wrc_file "$WRC_REBIND/after/${WRC_NAMES[$i]}" 400 &&
          [[ $(wrc_sha "${WRC_TARGETS[$i]}") == "$(jq -r --argjson i "$i" '.files[$i].after_sha256' "$WRC_REBIND/plan.json")" ]] &&
          cmp -s "${WRC_TARGETS[$i]}" "$WRC_REBIND/after/${WRC_NAMES[$i]}" || return 1
    done
    [[ ! -e $WRC_STATE/vector-stop-intent.json && ! -L $WRC_STATE/vector-stop-intent.json ]] || return 1
    wrc_arm publish start-new || return 1
    ro_engine modsecurity && ro_load && ro_validate || return 1
    [[ $RO_PHASE == publish_pending && $RO_STATE_SHA == "$(wrc_sha "$WRC_REBIND/after/modsecurity-state.json")" ]] || return 1
    cmp -s "$WRC_STATE/suricata/state.json" "$WRC_REBIND/after/suricata-state.json" || return 1
    wrc_old_eof && ro_prefix_distinct || return 1
    status=$(ro_vector_status) && proof=$(cat "$WRC_REBIND/stop-proof.json") || return 1
    jq -ne --argjson s "$status" --argjson p "$proof" '$s.ActiveState=="inactive" and $s.Result=="success" and $s.ExecMainStatus=="0" and $s.ExecMainStartTimestampMonotonic==$p.start_usec and ($s.InvocationID=="" or $s.InvocationID==$p.invocation_id)' >/dev/null || return 1
    # This is an ownership handoff from a real, durably recorded stop. It is not
    # a checkpoint and never invents a service stop or rewinds native positions.
    marker=$(jq -ncS --argjson s "$RO_STATE" --argjson p "$proof" --arg sha "$RO_STATE_SHA" \
      '$s|{schema_version:1,engine,boot_id:$p.boot_id,state_sha256:$sha,revision,phase,current,pending,source_pins,invocation_id:$p.invocation_id,start_usec:$p.start_usec}') || return 1
    printf '%s\n' "$marker" | wrc_new "$WRC_WORK/runtime-stop-intent.json" 400 || return 1
    printf '%s\n' "$marker" | wrc_new "$WRC_STATE/vector-stop-intent.json" 600 || return 1
    ro_owned_pause "$status" && ro_guard_one vector && ro_prefix_distinct || return 1
    ro_replace_link "$RO_ALIAS" "$RO_OLD_DEV:$RO_OLD_INO" "$RO_NEXT" || return 1
    ro_validate && ro_guard_all vector && ro_guard_all wazuh || return 1
    wrc_finish publish
}
wrc_unblock_pre() {
    wrc_load && wrc_blocked && wrc_json "$WRC_WORK/publish.json" 400 || return 1
    /bin/bash "$WRC_LIB/guard.sh" vector >/dev/null && /bin/bash "$WRC_LIB/guard.sh" wazuh >/dev/null || return 1
    wrc_arm unblock publish
}
wrc_verify_publish() {
    wrc_load && wrc_blocked && wrc_old_stopped && wrc_new_writer &&
      wrc_json "$WRC_WORK/publish.intent.json" 400 || return 1
    ro_engine modsecurity && ro_load && ro_validate || return 1
    [[ $RO_PHASE == publish_pending && $RO_ALIAS_KIND == new &&
       $RO_STATE_SHA == "$(wrc_sha "$WRC_REBIND/after/modsecurity-state.json")" ]] || return 1
    ro_owned_pause "$(ro_vector_status)" && ro_guard_all vector && ro_guard_all wazuh && wrc_finish publish
}
wrc_unblock_post() {
    local unit value
    wrc_load || return 1
    for unit in "${WRC_READERS[@]}"; do
        [[ ! -e /etc/systemd/system/$unit.d/99-capstone-waf-rebind-block.conf && ! -L /etc/systemd/system/$unit.d/99-capstone-waf-rebind-block.conf ]] || return 1
        value=$(systemctl show "$unit" -p ExecStartPre --value) || return 1
        [[ $value != *'path=/usr/bin/false'* && $value == *'/usr/local/lib/capstone-raw-operations/guard.sh'* && $(systemctl show "$unit" -p NeedDaemonReload --value) == no ]] || return 1
    done
    /bin/bash "$WRC_LIB/guard.sh" vector >/dev/null && /bin/bash "$WRC_LIB/guard.sh" wazuh >/dev/null && wrc_finish unblock
}
wrc_complete_pre() {
    local x unit
    wrc_load && wrc_old_stopped && wrc_json "$WRC_WORK/resume.json" 400 || return 1
    /bin/bash "$WRC_LIB/guard.sh" vector >/dev/null && /bin/bash "$WRC_LIB/guard.sh" wazuh >/dev/null || return 1
    jq -e --arg cid "$WRC_NEW" '.phase=="active" and .revision==13 and .current.number==4 and .source_pins.container_id==$cid' "$WRC_STATE/modsecurity/state.json" >/dev/null &&
      jq -e '.phase=="active" and .revision==6 and .current.number==1' "$WRC_STATE/suricata/state.json" >/dev/null || return 1
    [[ ! -e $WRC_STATE/vector-stop-intent.json && ! -L $WRC_STATE/vector-stop-intent.json && ! -e /var/lib/capstone-vector-maintenance/resume.pending && ! -L /var/lib/capstone-vector-maintenance/resume.pending ]] || return 1
    x=$(wrc_unit capstone-vector.service) || return 1
    jq -e '.ActiveState=="active" and .SubState=="running" and .Result=="success" and (.MainPID|test("^[1-9][0-9]+$"))' <<< "$x" >/dev/null || return 1
    [[ $(readlink /proc/1909632/exe) == /var/ossec/bin/wazuh-logcollector && $(awk '{sub(/^.*\) /," ");print $20}' /proc/1909632/stat) == 141224139 ]] || return 1
    for unit in "${WRC_TIMERS[@]}"; do
        [[ $(systemctl show "$unit" -p UnitFileState --value) == disabled && $(systemctl show "$unit" -p ActiveState --value) == inactive ]] || return 1
    done
    wrc_new_writer && wrc_arm complete resume
}
wrc_complete_post() {
    local x
    wrc_load && wrc_old_stopped || return 1
    x=$(wrc_inspect "$WRC_NEW") || return 1
    jq -e --arg cid "$WRC_NEW" --arg image "$WRC_IMAGE" '.cid==$cid and .image==$image and .name=="/waf" and .state.Running and (.state.Restarting|not) and .state.Health.Status=="healthy" and .restart=={Name:"unless-stopped",MaximumRetryCount:0} and .networks["secstack_waf-net"].IPAddress=="172.18.0.2"' <<< "$x" >/dev/null || return 1
    /bin/bash "$WRC_LIB/guard.sh" vector >/dev/null && /bin/bash "$WRC_LIB/guard.sh" wazuh >/dev/null &&
      /usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance check >/dev/null || return 1
    wrc_finish complete || return 1
    jq -ncS --arg cid "$WRC_NEW" --arg sha "$(wrc_sha "$WRC_WORK/complete.json")" \
      '{schema_version:1,status:"native_handoff_complete_timers_paused",candidate_cid:$cid,receipt_sha256:$sha,timer_activation_required:true,old_container_retained:true,raw_deleted:false,checkpoint_rewritten:false,security_delivery_acknowledged:false}' |
      wrc_new "$WRC_WORK/result.json" 400
}

# Fixed native-validated release. Every mutation still requires its explicit phase,
# exact source pins and independent current preconditions; no generic retry mode.
wrc_main() {
    [[ $# == 1 && $1 =~ ^(syntax|inspect|preflight|initialize|barrier|stop-old|drain-stop|prepare-new|retain-old|name-new|start-new|prepare-metadata|apply-metadata|publish|unblock|resume|complete|verify-stop-old|verify-drain-stop|verify-retain-old|verify-name-new|verify-start-new|verify-publish|verify-unblock|verify-complete)$ ]] || return 64
    local phase=$1 project
    project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || return 1
    [[ $EUID == 0 && $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || return 77
    wrc_dir "$project" && wrc_file "$project/waf-recreate-cutover-a.yml" 400 131072 &&
      [[ -f $project/waf-recreate-cutover-local-a.sh && ! -L $project/waf-recreate-cutover-local-a.sh &&
         $(stat -c %u:%g:%h "$project/waf-recreate-cutover-local-a.sh") == 0:0:1 ]] || return 77
    (( (8#$(stat -c %a "$project/waf-recreate-cutover-local-a.sh") & 0022)==0 )) || return 77
    [[ $(wrc_sha "$project/waf-recreate-cutover-a.yml") == 433925fb6fdf069bb9387bd98f53eb11ec0b3d389b5231984cb32a809861cd55 ]] || return 77
    [[ $(wrc_sha "$project/ansible.cfg") == 89a4bde4e9ed9d17bb621097a24214ade588b23cee1c779f7544f1455cc1746a ]] || return 77
    [[ $(wrc_sha "$project/inventory/local-a.ini") == 592adf39e7e0a8b729f66c16a0ca005917d30c6c2ed4bf73df813fb9b1d3acd5 ]] || return 77
    wrc_file /var/lib/rule-change/.lock 600 && wrc_file /var/lib/capstone-automation/ansible/vector.lock 600 || return 77
    exec 8<>/var/lib/rule-change/.lock; flock -n 8 || return 75
    exec 9<>/var/lib/capstone-automation/ansible/vector.lock; flock -n 9 || return 75
    export ANSIBLE_CONFIG=$project/ansible.cfg ANSIBLE_NOCOLOR=1 PYTHONDONTWRITEBYTECODE=1
    export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/ansible/tmp ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/ansible/remote-tmp
    wrc_dir "$ANSIBLE_LOCAL_TEMP" && wrc_dir "$ANSIBLE_REMOTE_TEMP" || return 77
    cd -- "$project" || return 1
    if [[ $phase == verify-* ]]; then
        # Explicit operator postcheck only: never repeats the Docker/systemd
        # action. It still requires its immutable pending intent and all gates.
        case $phase in
          verify-publish) wrc_verify_publish ;;
          verify-unblock) wrc_unblock_post ;;
          verify-complete) wrc_complete_post ;;
          *) wrc_post "${phase#verify-}" ;;
        esac
        return
    elif [[ $phase == prepare-metadata || $phase == apply-metadata ]]; then
        wrc_file "$WRC_LIB/waf-rebind-metadata.sh" 400 &&
          [[ $(wrc_sha "$WRC_LIB/waf-rebind-metadata.sh") == 884dbf89cf1a031ae3193100a13832cb76437cf466e02857221c014bb7e550ca ]] || return 77
        if [[ $phase == prepare-metadata ]]; then
            wrc_descriptor && /bin/bash "$WRC_LIB/waf-rebind-metadata.sh" prepare
        else /bin/bash "$WRC_LIB/waf-rebind-metadata.sh" apply; fi
        return
    elif [[ $phase == resume ]]; then
        wrc_load && wrc_json "$WRC_WORK/unblock.json" 400 || return 1
        [[ ! -e $WRC_WORK/resume.json && ! -L $WRC_WORK/resume.json ]] || return 1
        if [[ -e $WRC_WORK/resume.intent.json || -L $WRC_WORK/resume.intent.json ]]; then
            # Unlike Docker lifecycle calls, the installed coordinator owns a
            # durable, explicitly resumable state machine. Only this fixed
            # pending/new-generation phase may be observed and invoked again.
            wrc_json "$WRC_WORK/resume.intent.json" 400 && jq -e --arg boot "$WRC_BOOT" --arg new "$WRC_NEW" --arg old "$WRC_OLD" \
              '.phase=="resume" and .boot_id==$boot and .new_cid==$new and .old_cid==$old' "$WRC_WORK/resume.intent.json" >/dev/null || return 1
        else wrc_arm resume unblock || return 1; fi
        jq -e --arg cid "$WRC_NEW" '.source_pins.container_id==$cid and ((.phase=="publish_pending" and .revision==12 and .pending.number==4) or (.phase=="active" and .revision==13 and .current.number==4))' "$WRC_STATE/modsecurity/state.json" >/dev/null || return 1
        local attempts count
        count=$(find "$WRC_WORK" -maxdepth 1 -name 'resume-attempt-*.json' -printf '.\n' | wc -l) || return 1
        (( count<8 )) || return 75
        attempts=$((count+1))
        jq -ncS --argjson number "$attempts" --arg sha "$(wrc_sha "$WRC_STATE/modsecurity/state.json")" \
          '{attempt:$number,state_sha256:$sha,operation:"native_resume_only",docker_lifecycle_calls:0}' | wrc_new "$WRC_WORK/resume-attempt-$attempts.json" 400 || return 1
        # Public coordinator takes this same lock itself. Keep rule-change lock
        # and paused timers, but release vector.lock before the fixed invocation.
        flock -u 9 || return 1
        local rc=0
        /usr/local/sbin/capstone-raw-operations resume modsecurity || rc=$?
        flock -n 9 || return 75
        [[ $rc == 0 ]] || return "$rc"
        /bin/bash "$WRC_LIB/guard.sh" vector >/dev/null && /bin/bash "$WRC_LIB/guard.sh" wazuh >/dev/null || return 1
        wrc_finish resume
        return
    fi
    local args=(--extra-vars "capstone_waf_operator_lock=true waf_cutover_phase=$phase")
    [[ $phase != syntax ]] || args+=(--syntax-check)
    /opt/capstone-automation/venv/bin/ansible-playbook -i inventory/local-a.ini waf-recreate-cutover-a.yml "${args[@]}"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    umask 077
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C.UTF-8 TZ=Asia/Seoul
    wrc_main "$@"
fi
