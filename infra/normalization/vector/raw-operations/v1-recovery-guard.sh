#!/bin/bash
# Temporary, read-only authorization for ONE administrator-owned v1 recovery.
# It does not consume authority or enforce one-shot semantics: the controller
# owns the single start, immediately restores the blocked drop-in and archives
# the proof. An unexpired authority alone never bypasses the checks below.
VRG_ROOT=/var/lib/capstone-raw-migration
VRG_AUTH=$VRG_ROOT/recovery-authority.json
VRG_BARRIER=$VRG_ROOT/start-barrier.json
VRG_BACKUP=/var/backups/capstone-raw-operations-initial-20261014
VRG_STATE=/var/lib/capstone-raw-operations
VRG_PENDING=/var/lib/capstone-vector-maintenance/resume.pending
VRG_MID=096e90b6243e438aa8a7b392be754732
VRG_PLAN=39ec7c6829888a3394217b98b5fbea05c89c0fc94e480ccd309fe72af7c9f40f
VRG_LEDGER=78f9261b6347ef43622428ad041e9bffb841c4c6d99804406052c8831b873343
VRG_CUTOVER=9a17d6fac16240dbd98039253b806b5e115e2569e7f8ea0e38c472b61c956b83
VRG_PREPARE=6dcf1556f89c8882a422cf92a3c8caa90bbdcdf71b809d0224587fe45b17db15
VRG_POLICY=capstone-v1-vector-recovery-20261015
VRG_SELF=${BASH_SOURCE[0]}
VRG_REASON=unavailable
vrg_fail() { VRG_REASON=$1; return 75; }
vrg_hash() { local h; h=$(sha256sum -- "$1") || return 1; printf '%s\n' "${h%% *}"; }
vrg_stat() { stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' -- "$1"; }
vrg_boot() { tr -d '\n-' < /proc/sys/kernel/random/boot_id; }
vrg_uptime() { local n rest; read -r n rest < /proc/uptime; printf '%s\n' "${n%%.*}"; }
vrg_host() { [[ $EUID == 0 && $OSTYPE == linux* && $(cat /etc/machine-id) == "$VRG_MID" ]]; }
vrg_no_symlinks() {
    local p=$1
    while [[ $p != / ]]; do [[ ! -L $p && -e $p ]] || return 1; p=${p%/*}; [[ -n $p ]] || p=/; done
}
vrg_private() {
    local p=$1 cap=$2 meta mode u g links bytes
    vrg_no_symlinks "$p" && [[ -f $p ]] || return 1
    meta=$(stat -c '%u:%g:%a:%h:%s' "$p") || return 1
    IFS=: read -r u g mode links bytes <<< "$meta"
    [[ $u == 0 && $g == 0 && ( $mode == 400 || $mode == 600 || $mode == 500 ) && $links == 1 ]] && (( bytes<=cap ))
}
vrg_schema() {
    jq -se --arg policy "$VRG_POLICY" --arg mid "$VRG_MID" --arg plan "$VRG_PLAN" --arg ledger "$VRG_LEDGER" \
      --arg cutover "$VRG_CUTOVER" --arg prepare "$VRG_PREPARE" '
      def hex($n): type=="string" and test("^[a-f0-9]{"+($n|tostring)+"}$");
      def uint: type=="number" and floor==. and .>=0 and .<=9007199254740991;
      length==1 and (.[0] | keys==["barrier_sha256","boot_id","cutover_sha256","expiry_uptime_seconds","guard_sha256","issued_uptime_seconds","ledger_sha256","machine_id","plan_sha256","policy","prepare_sha256","schema_version","wazuh_pid","wazuh_start_ticks"] and
        .schema_version==1 and .policy==$policy and .machine_id==$mid and .plan_sha256==$plan and .ledger_sha256==$ledger and
        .cutover_sha256==$cutover and .prepare_sha256==$prepare and
        (.barrier_sha256|hex(64)) and (.guard_sha256|hex(64)) and (.boot_id|hex(32)) and
        (.issued_uptime_seconds|uint) and (.expiry_uptime_seconds|uint) and
        .expiry_uptime_seconds>.issued_uptime_seconds and .expiry_uptime_seconds<=.issued_uptime_seconds+900 and
        (.wazuh_pid|uint) and .wazuh_pid>1 and (.wazuh_start_ticks|uint) and .wazuh_start_ticks>0)' >/dev/null 2>&1
}
vrg_authority() {
    local first raw now
    vrg_no_symlinks "$VRG_ROOT" && [[ $(stat -c '%u:%g:%a' "$VRG_ROOT") == 0:0:700 ]] &&
      vrg_private "$VRG_AUTH" 4096 && [[ $(stat -c %a "$VRG_AUTH") == 600 ]] || { vrg_fail authority_untrusted; return 75; }
    first=$(vrg_stat "$VRG_AUTH") || return 75
    raw=$(head -c 4097 "$VRG_AUTH") || return 75
    vrg_schema <<< "$raw" && cmp -s "$VRG_AUTH" <(jq -cS . <<< "$raw") || { vrg_fail authority_invalid; return 75; }
    [[ $(vrg_stat "$VRG_AUTH") == "$first" ]] || { vrg_fail authority_changed; return 75; }
    now=$(vrg_uptime) || return 75
    jq -e --arg boot "$(vrg_boot)" --argjson now "$now" '.boot_id==$boot and .issued_uptime_seconds<=$now and $now<.expiry_uptime_seconds' <<< "$raw" >/dev/null ||
      { vrg_fail authority_expired_or_other_boot; return 75; }
    VRG_RECORD=$raw VRG_AUTH_SHA=$(vrg_hash "$VRG_AUTH") VRG_AUTH_ID=$first || return 75
    vrg_private "$VRG_SELF" 65536 && [[ $(vrg_hash "$VRG_SELF") == $(jq -r .guard_sha256 <<< "$raw") ]] ||
      { vrg_fail guard_source_changed; return 75; }
}
vrg_file_pin() {
    local path=$1 digest=$2 expected=$3 first
    vrg_no_symlinks "$path" && [[ -f $path && $(stat -c '%u:%g:%a:%h' "$path") == "$expected" ]] &&
      (( $(stat -c %s "$path")<=2097152 )) || return 1
    first=$(vrg_stat "$path") || return 1
    [[ $(vrg_hash "$path") == "$digest" && $(vrg_stat "$path") == "$first" ]]
}
vrg_static() {
    local key path expected digest raw u g mode links
    [[ ! -e $VRG_STATE && ! -L $VRG_STATE ]] || return 1
    vrg_private "$VRG_BACKUP/plan.json" 262144 && [[ $(vrg_hash "$VRG_BACKUP/plan.json") == "$VRG_PLAN" ]] || return 1
    vrg_private "$VRG_BACKUP/migration.json" 262144 && [[ $(vrg_hash "$VRG_BACKUP/migration.json") == "$VRG_LEDGER" ]] || return 1
    vrg_private "$VRG_BACKUP/before.json" 262144 && [[ $(vrg_hash "$VRG_BACKUP/before.json") == $(jq -r .before_sha256 "$VRG_BACKUP/plan.json") ]] || return 1
    jq -e --arg boot "$(vrg_boot)" '.sequence==6 and .boot_id==$boot' "$VRG_BACKUP/migration.json" >/dev/null || return 1
    vrg_private "$VRG_BARRIER" 4096 && [[ $(vrg_hash "$VRG_BARRIER") == $(jq -r .barrier_sha256 <<< "$VRG_RECORD") ]] || return 1
    jq -e --arg plan "$VRG_PLAN" '.phase=="blocked" and .release==null and .plan_sha256==$plan' "$VRG_BARRIER" >/dev/null || return 1
    vrg_private "$VRG_PENDING" 8 && cmp -s "$VRG_PENDING" <(printf 'pending\n') || return 1
    for key in vector environment waf_binding line_binding wazuh compose logrotate; do
        case $key in
          vector) path=/etc/capstone-vector/vector.toml; expected=0:0:600:1;;
          environment) path=/etc/capstone-vector/vector.env; expected=0:0:600:1;;
          waf_binding) path=/etc/capstone-vector/waf-binding.json; expected=0:0:600:1;;
          line_binding) path=/etc/capstone-vector/raw-line-binding.json; expected=0:0:600:1;;
          wazuh) path=/var/ossec/etc/ossec.conf; expected=0:110:660:1;;
          compose) path=/home/groot_a/capstone/secstack/docker-compose.yml; expected=1000:1000:644:1;;
          logrotate) path=/etc/logrotate.d/capstone-secstack; expected=0:0:644:1;;
        esac
        if [[ $key == logrotate ]]; then digest=$(jq -r '.candidate_sha256.logrotate' "$VRG_BACKUP/plan.json")
        else digest=$(jq -r --arg k "$key" '.files[$k].sha256' "$VRG_BACKUP/before.json"); fi
        vrg_file_pin "$path" "$digest" "$expected" || return 1
    done
    for key in waf_access_part.vrl waf_audit_part.vrl correlation.vrl nftables.vrl waf_json_guard.vrl suricata.vrl waf_pair_normalize.vrl; do
        digest=$(jq -r --arg k "vrl:$key" '.files[$k].sha256' "$VRG_BACKUP/before.json") || return 1
        # Original installed VRLs are root0444; mode is taken from pinned before metadata.
        expected=$(jq -r --arg k "vrl:$key" '.files[$k]|[.uid,.gid,.mode,.links]|@tsv' "$VRG_BACKUP/before.json") || return 1
        read -r u g mode links <<< "$expected"; printf -v expected '%s:%s:%o:%s' "$u" "$g" "$mode" "$links"
        vrg_file_pin "/etc/capstone-vector/transforms/$key" "$digest" "$expected" || return 1
    done
    for key in checkpoint-gates.sh checkpoint-gates.jq; do
        vrg_private "$VRG_BACKUP/source/$key" 65536 &&
          [[ $(vrg_hash "$VRG_BACKUP/source/$key") == $(jq -r --arg k "$key" '.source_sha256[$k]' "$VRG_BACKUP/plan.json") ]] || return 1
    done
}
vrg_docker() { timeout -k 1 5 /usr/local/bin/docker "$@"; }
vrg_engines() {
    local name cid image info again pid key path digest expected
    for name in suricata waf; do
        cid=$(jq -r --arg n "$name" '.containers[$n].cid' "$VRG_BACKUP/before.json") || return 1
        image=$(jq -r --arg n "$name" '.containers[$n].image' "$VRG_BACKUP/before.json") || return 1
        [[ $cid =~ ^[a-f0-9]{64}$ && $image =~ ^sha256:[a-f0-9]{64}$ ]] || return 1
        info=$(vrg_docker inspect --format '{{json .}}' "$cid" | jq -c '{Id,Image,pid:.State.Pid,running:.State.Running}') || return 1
        jq -e --arg cid "$cid" --arg image "$image" '.Id==$cid and .Image==$image and .running==true and (.pid|type=="number" and .>1)' <<< "$info" >/dev/null || return 1
        pid=$(jq -r .pid <<< "$info") || return 1
        if [[ $name == suricata ]]; then
            key=suricata_yaml; path=/etc/suricata/suricata.yaml; expected=998:998:600:1
            digest=$(jq -r '.candidate_sha256.suricata_yaml' "$VRG_BACKUP/plan.json") || return 1
            # /proc/PID/root itself is an intentional kernel link; container file
            # components below it are checked independently for symlinks.
            vrg_engine_file "$pid" "$path" "$digest" "$expected" || return 1
        else
            for key in waf_override waf_producer; do
                if [[ $key == waf_override ]]; then path=/etc/modsecurity.d/modsecurity-override.conf; expected=101:101:644:1
                else path=/etc/nginx/conf.d/zz-capstone-evidence.conf; expected=0:0:644:1; fi
                digest=$(jq -r --arg k "$key" '.files[$k].sha256' "$VRG_BACKUP/before.json") || return 1
                vrg_engine_file "$pid" "$path" "$digest" "$expected" || return 1
            done
        fi
        again=$(vrg_docker inspect --format '{{json .}}' "$cid" | jq -c '{Id,Image,pid:.State.Pid,running:.State.Running}') || return 1
        [[ $info == "$again" ]] || return 1
    done
}
vrg_engine_file() {
    local pid=$1 path=$2 digest=$3 metadata=$4 current= part first full=/proc/$1/root$2
    local -a parts
    IFS=/ read -r -a parts <<< "${path#/}"
    for part in "${parts[@]}"; do current=$current/$part; [[ ! -L /proc/$pid/root$current ]] || return 1; done
    [[ -f $full && $(stat -c '%u:%g:%a:%h' "$full") == "$metadata" ]] && (( $(stat -c %s "$full")<=2097152 )) || return 1
    first=$(vrg_stat "$full") || return 1
    [[ $(vrg_hash "$full") == "$digest" && $(vrg_stat "$full") == "$first" ]]
}
vrg_systemctl() { timeout -k 1 5 /usr/bin/systemctl "$@"; }
vrg_services() {
    local timer vector
    timer=$(vrg_systemctl show capstone-vector-maintenance.timer -p ActiveState -p UnitFileState --value) || return 1
    [[ $timer == $'inactive\ndisabled' || $timer == $'disabled\ninactive' ]] || return 1
    vector=$(vrg_systemctl show capstone-vector.service -p ActiveState -p SubState -p MainPID) || return 1
    [[ $(sed -n 's/^MainPID=//p' <<< "$vector") == 0 ]] || return 1
    case $(sed -n 's/^ActiveState=//p' <<< "$vector"):$(sed -n 's/^SubState=//p' <<< "$vector") in
        inactive:dead|activating:start-pre) ;; *) return 1;; esac
    [[ $(vrg_systemctl show wazuh-agent.service -p ActiveState --value) == active ]]
}
vrg_raw() {
    local name path cp ino uid mode links proof all='[]'
    for name in suricata_eve waf_audit waf_access; do
        case $name in
          suricata_eve) path=/home/groot_a/capstone/secstack/logs/suricata/eve.json; ino=1441879; uid=998; mode=644; links=3;;
          waf_audit) path=/home/groot_a/capstone/secstack/logs/modsec/audit.log; ino=1441881; uid=101; mode=644; links=1;;
          waf_access) path=/home/groot_a/capstone/secstack/logs/modsec/capstone-access.log; ino=1441928; uid=101; mode=640; links=1;;
        esac
        vrg_no_symlinks "$path" && [[ -f $path && $(stat -c '%d:%i:%u:%g:%a:%h' "$path") == "64512:$ino:$uid:$uid:$mode:$links" ]] || return 1
        proof=$(cg_vector_current "/var/lib/capstone-vector/$name" "$path" 64512 "$ino") || return 1
        jq -e --argjson ino "$ino" --argjson links "$links" '.verdict=="pass" and .reason=="current_offset_valid" and .source_stable==true and .source_identity.device==64512 and .source_identity.inode==$ino and .source_identity.links==$links and .offset<=.source_identity.bytes' <<< "$proof" >/dev/null || return 1
        all=$(jq -c --argjson p "$proof" '.+[$p]' <<< "$all") || return 1
    done
    VRG_RAW=$all
}
vrg_ticks() { local s rest; s=$(cat /proc/"$1"/stat) || return 1; rest=${s##*) }; read -r -a fields <<< "$rest"; printf '%s\n' "${fields[19]}"; }
vrg_reader() {
    local pid ticks matches
    pid=$(jq -r .wazuh_pid <<< "$VRG_RECORD") ticks=$(jq -r .wazuh_start_ticks <<< "$VRG_RECORD") || return 1
    matches=$(pgrep -x wazuh-logcollec) || return 1
    [[ $matches == "$pid" && $(readlink /proc/"$pid"/exe) == /var/ossec/bin/wazuh-logcollector && $(vrg_ticks "$pid") == "$ticks" ]] || return 1
    VRG_READER=$pid
}
vrg_output() {
    local path=$1 inode=$2 device=${3:-64512} first size fd target count=0 pos proof fdlist flags
    vrg_no_symlinks "$path" && [[ -f $path && $(stat -c '%d:%i:%u:%g:%a:%h' "$path") == "$device:$inode:0:0:600:1" ]] || return 1
    first=$(vrg_stat "$path") size=$(stat -c %s "$path") || return 1
    fdlist=$(printf '%s\n' /proc/"$VRG_READER"/fd/[0-9]*) || return 1
    for fd in /proc/"$VRG_READER"/fd/[0-9]*; do
        target=$(stat -Lc '%d:%i' "$fd" 2>/dev/null) || return 1
        [[ $target == "$device:$inode" ]] || continue
        pos=$(awk '$1=="pos:" {print $2}' /proc/"$VRG_READER"/fdinfo/"${fd##*/}") || return 1
        flags=$(awk '$1=="flags:" {print $2}' /proc/"$VRG_READER"/fdinfo/"${fd##*/}") || return 1
        [[ $pos == "$size" && $flags =~ ^[0-7]+$ ]] && (( (8#$flags & 3)==0 )) || return 1
        count=$((count+1))
    done
    (( count==1 )) || return 1
    if (( size>0 )); then
        proof=$(cg_wazuh_eof /var/ossec/queue/logcollector/file_status.json "$path" "$path" "$device" "$inode" "$size") || return 1
        jq -e '.verdict=="pass" and .source_stable==true' <<< "$proof" >/dev/null || return 1
    fi
    [[ $(vrg_stat "$path") == "$first" && $(printf '%s\n' /proc/"$VRG_READER"/fd/[0-9]*) == "$fdlist" ]] && vrg_reader || return 1
    jq -nc --arg path "$path" --argjson inode "$inode" --argjson size "$size" --argjson device "$device" \
      '{path:$path,device:$device,inode:$inode,bytes:$size,fd_count:1,position:$size,empty_native_fd:($size==0)}'
}
vrg_outputs() {
    local a b
    vrg_reader || return 1
    a=$(vrg_output /var/log/capstone-vector/ready/normalized.jsonl 416855) || return 1
    b=$(vrg_output /var/log/capstone-vector/evidence/normalized.jsonl 418116) || return 1
    VRG_OUTPUTS=$(jq -nc --argjson a "$a" --argjson b "$b" '[$a,$b]')
}
vrg_worker() {
    local auth identity
    vrg_host || { vrg_fail fixed_A_root_required; return 75; }
    vrg_authority || return 75
    auth=$VRG_AUTH_SHA identity=$VRG_AUTH_ID
    vrg_static || { vrg_fail static_binding_changed; return 75; }
    vrg_services || { vrg_fail service_state_rejected; return 75; }
    vrg_engines || { vrg_fail engine_binding_changed; return 75; }
    source "$VRG_BACKUP/source/checkpoint-gates.sh" || return 75
    vrg_raw || { vrg_fail raw_checkpoint_rejected; return 75; }
    vrg_outputs || { vrg_fail output_eof_rejected; return 75; }
    vrg_static && vrg_services && vrg_engines || { vrg_fail final_binding_changed; return 75; }
    vrg_authority || return 75
    [[ $auth == "$VRG_AUTH_SHA" && $identity == "$VRG_AUTH_ID" ]] || { vrg_fail authority_changed; return 75; }
    jq -ncS --arg policy "$VRG_POLICY" --arg mid "$VRG_MID" --arg boot "$(vrg_boot)" \
      --arg auth "$auth" --arg guard "$(jq -r .guard_sha256 <<< "$VRG_RECORD")" --arg plan "$VRG_PLAN" --arg ledger "$VRG_LEDGER" \
      --arg barrier "$(jq -r .barrier_sha256 <<< "$VRG_RECORD")" --argjson raw "$VRG_RAW" --argjson outputs "$VRG_OUTPUTS" \
      '{schema_version:1,policy:$policy,status:"pass",reason:"verified_v1_start_only",machine_id:$mid,boot_id:$boot,authority_sha256:$auth,
        guard_sha256:$guard,plan_sha256:$plan,ledger_sha256:$ledger,barrier_sha256:$barrier,checkpoints_rewritten:false,
        delivery_acknowledged:false,read_only:true,raw_current_proofs:$raw,output_eof_proofs:$outputs}'
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -uo pipefail
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
    umask 077
    [[ $# == 1 && $1 == vector ]] || exit 64
    if [[ ${VRG_WORKER:-} != 1 ]]; then
        exec /usr/bin/timeout -k 2 115 /usr/bin/env -i PATH="$PATH" LC_ALL=C TZ=UTC VRG_WORKER=1 \
          /bin/bash --noprofile --norc "$0" vector
    fi
    vrg_worker 2>/dev/null || { jq -ncS --arg reason "$VRG_REASON" '{schema_version:1,status:"refused",reason:$reason,read_only:true}'; exit 75; }
fi
