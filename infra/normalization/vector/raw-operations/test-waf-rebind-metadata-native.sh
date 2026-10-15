#!/bin/bash
# Linux/root private metadata fixture. No live journal/Docker/systemd/CP/raw.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $EUID == 0 && $OSTYPE == linux* && $0 == /* ]] || exit 77
[[ $# -le 1 && ( ${1:-all} == all || ${1:-all} == prepare || ${1:-all} == env ) ]] || exit 64
selection=${1:-all}
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
root=$(/usr/bin/mktemp -d /var/tmp/capstone-waf-rebind-test.XXXXXXXX)
/bin/chmod 700 "$root"
trap '/bin/rm -rf -- "$root"' EXIT
source "$directory/waf-rebind-metadata.sh"
original_sha=$(wr_sha "$directory/waf-rebind-metadata.sh")
# Only private metadata CAS/validators are tested. The real runtime precondition
# functions are not invoked; this explicit stub can inject a refused boundary.
wr_preconditions() {
    printf '%s\n' "$1" >> "$root/checks"
    [[ ! -e $root/deny ]]
}
# Allow only our native fixture's sticky /var/tmp ancestor. Other root ownership,
# mode and symlink rules remain identical; public wr_context is never called.
wr_parents() {
    local p=$1 mode
    [[ $p == "$root" || $p == "$root/"* ]] || return 1
    while [[ $p != "$root" ]]; do
        [[ -d $p && ! -L $p && $(stat -c %u:%g "$p") == 0:0 ]] || return 1
        mode=$(stat -c %a "$p"); (( (8#$mode & 0022)==0 )) || return 1
        p=${p%/*}
    done
    [[ ! -L $root && $(stat -c %u:%g:%a "$root") == 0:0:700 ]]
}
put() { /usr/bin/jq -cS . > "$1"; /bin/chmod "${2:-400}" "$1"; }
hex() { printf '%064d' "$1"; }
setup() {
    /bin/rm -rf -- "$root/case" "$root/deny" "$root/checks" "$root/injected" "$root/add.json"
    WR_BASE=$root/case/rebind WR_STATE=$root/case/state WR_LIBRARY=$root/case/lib
    /bin/mkdir -m 700 -p "$WR_BASE/before" "$WR_BASE/after" "$WR_BASE/receipts" "$WR_LIBRARY" "$root/case/etc"
    /bin/cp "$directory/state.jq" "$WR_LIBRARY/state.jq"; /bin/chmod 400 "$WR_LIBRARY/state.jq"
    WR_TARGETS=("$root/case/etc/vector.env" "$root/case/etc/raw-line-binding.json" "$root/case/etc/waf-binding.json" "$WR_STATE/suricata/state.json" "$WR_STATE/modsecurity/state.json")
    local b=$WR_BASE/before a=$WR_BASE/after oldcid newcid bind newbind producer newproducer vc wc engine pointer envold envnew e n i files authority
    oldcid=$(hex 1); newcid=$(hex 2); bind=$(hex 3); newbind=$(hex 4); producer=$(hex 5); newproducer=$(hex 6)
    vc=$(hex 7); wc=$(hex 8); engine=$(hex 9); pointer=$(hex 10)
    printf 'first:%s\nsecond:%s\n' "$bind" "$bind" > "$root/old-producer.conf"
    printf 'first:%s\nsecond:%s\n' "$newbind" "$newbind" > "$WR_BASE/new-producer.conf"
    /bin/chmod 400 "$WR_BASE/new-producer.conf"
    producer=$(wr_sha "$root/old-producer.conf"); newproducer=$(wr_sha "$WR_BASE/new-producer.conf")
    printf 'SENSOR_ID=groot-a\nWAF_INSTANCE_ID=%s\nWAF_CONFIG_SHA256=%s\nWAF_DEPLOYMENT_BINDING=%s\nWAF_AUDIT_PATH=/home/groot_a/capstone/secstack/logs/modsec/audit.log\nWAF_ACCESS_PATH=/home/groot_a/capstone/secstack/logs/modsec/capstone-access.log\n' "$oldcid" "$producer" "$bind" > "$b/vector.env"
    printf 'SENSOR_ID=groot-a\nWAF_INSTANCE_ID=%s\nWAF_CONFIG_SHA256=%s\nWAF_DEPLOYMENT_BINDING=%s\nWAF_AUDIT_PATH=/home/groot_a/capstone/secstack/logs/modsec/audit.log\nWAF_ACCESS_PATH=/home/groot_a/capstone/secstack/logs/modsec/capstone-access.log\n' "$newcid" "$newproducer" "$newbind" > "$a/vector.env"
    /bin/chmod 400 "$b/vector.env" "$a/vector.env"
    envold=$(wr_sha "$b/vector.env"); envnew=$(wr_sha "$a/vector.env")
    /usr/bin/jq -n --arg env "$envold" --arg vc "$vc" '{schema_version:1,policy:"periodic-snapshot-tail-v1",vector_config_sha256:$vc,vector_env_sha256:$env}' | put "$b/raw-line-binding.json"
    /usr/bin/jq --arg env "$envnew" '.vector_env_sha256=$env' "$b/raw-line-binding.json" | put "$a/raw-line-binding.json"
    /usr/bin/jq -n --arg cid "$oldcid" --arg producer "$producer" --arg bind "$bind" '{schema:"waf-producer-deployment-2",schema_version:2,machine_id:"096e90b6243e438aa8a7b392be754732",container_name:"waf",instance_id:$cid,configuration_sha256:$producer,deployment_binding:$bind,audit_path:"/home/groot_a/capstone/secstack/logs/modsec/audit.log",access_path:"/home/groot_a/capstone/secstack/logs/modsec/capstone-access.log",time_policy:"context-created-fixed-offset-v2"}' | put "$b/waf-binding.json"
    /usr/bin/jq --arg cid "$newcid" --arg p "$newproducer" --arg b "$newbind" '.instance_id=$cid|.configuration_sha256=$p|.deployment_binding=$b' "$b/waf-binding.json" | put "$a/waf-binding.json"
    for e in suricata modsecurity; do
        /bin/mkdir -m 700 -p "$WR_STATE/$e/history" "$WR_STATE/$e/staging"
        /usr/bin/jq -n --arg e "$e" --arg cid "$oldcid" --arg p "$producer" --arg vc "$vc" --arg wc "$wc" --arg env "$envold" --arg engine "$engine" --arg pointer "$pointer" '
          (if $e=="suricata" then 1 else 3 end) as $gen|
          {schema_version:1,policy:"capstone-raw-operations-v1",machine_id:"096e90b6243e438aa8a7b392be754732",boot_id:"11111111111111111111111111111111",engine:$e,revision:(if $e=="suricata" then 5 else 11 end),phase:"active",
           current:{basename:("generation-000000000"+($gen|tostring)+".jsonl"),number:$gen,device:100,inode:200,writer_config_sha256:$pointer},pending:null,
           source_pins:{container_id:$cid,engine_config_sha256:$engine,producer_format_sha256:$p,vector_config_sha256:$vc,vector_env_sha256:$env,wazuh_config_sha256:$wc},proof:{old_closed:null,readers_drained:null,publish_guard:null}}' | put "$b/$e-state.json"
    done
    /usr/bin/jq --arg env "$envnew" '.revision=6|.source_pins.vector_env_sha256=$env' "$b/suricata-state.json" | put "$a/suricata-state.json"
    /usr/bin/jq --arg env "$envnew" --arg cid "$newcid" --arg p "$newproducer" --arg sha "$(hex 11)" '
      .revision=12|.phase="publish_pending"|.source_pins.container_id=$cid|.source_pins.producer_format_sha256=$p|.source_pins.vector_env_sha256=$env|
      .pending={basename:"generation-0000000004.jsonl",number:4,device:100,inode:201,writer_config_sha256:$sha}|
      .proof.old_closed={boot_id:.boot_id,bytes:7,device:100,inode:200,sha256:$sha,writer_fd_zero:true,writer_pid:123,writer_start_ticks:456}|
      .proof.readers_drained={vector_checkpoint_sha256:$sha,wazuh_checkpoint_sha256:$sha,vector_offset:7,wazuh_offset:7,wazuh_sha1:"1111111111111111111111111111111111111111",vector_stopped:true}|
      .proof.publish_guard={decision:"different_prefix",new_prefix_sha1:"2222222222222222222222222222222222222222",old_sha1:"1111111111111111111111111111111111111111",old_offset:7,source_bytes:6,wazuh_checkpoint_sha256:$sha}' "$b/modsecurity-state.json" | put "$a/modsecurity-state.json"
    /usr/bin/jq -n --arg old "$oldcid" --arg new "$newcid" --arg sha "$(wr_sha "$b/modsecurity-state.json")" '
      {schema_version:1,policy:"capstone-waf-rebind-vector-stop-v1",boot_id:"11111111111111111111111111111111",old_cid:$old,new_cid:$new,old_state_sha256:$sha,invocation_id:"22222222222222222222222222222222",start_usec:"123456",stop_armed:true,stopped_clean:true,
       before_status:{ActiveState:"active",SubState:"running",MainPID:"999",Result:"success",ExecMainStatus:"0",InvocationID:"22222222222222222222222222222222",ExecMainStartTimestampMonotonic:"123456"},
       after_status:{ActiveState:"inactive",SubState:"dead",MainPID:"0",Result:"success",ExecMainStatus:"0",InvocationID:"",ExecMainStartTimestampMonotonic:"123456"}}' | put "$WR_BASE/stop-proof.json"
    files='[]'
    for i in 0 1 2 3 4; do n=${WR_NAMES[$i]}; /bin/cp "$b/$n" "${WR_TARGETS[$i]}"; /bin/chmod 600 "${WR_TARGETS[$i]}"
        files=$(/usr/bin/jq -nc --argjson files "$files" --arg n "$n" --arg b "$(wr_sha "$b/$n")" --arg a "$(wr_sha "$a/$n")" '$files+[{name:$n,before_sha256:$b,after_sha256:$a}]')
    done
    /usr/bin/jq -n --argjson files "$files" --arg old "$oldcid" --arg new "$newcid" --arg bind "$newbind" --arg producer "$newproducer" --arg sha "$(hex 12)" --arg proof "$(wr_sha "$WR_BASE/stop-proof.json")" '
      {schema_version:1,policy:"capstone-waf-rebind-metadata-v1",machine_id:"096e90b6243e438aa8a7b392be754732",boot_id:"11111111111111111111111111111111",files:$files,
       authority:{barrier_sha256:$sha,new_binding:$bind,new_producer_sha256:$producer,stop_proof_sha256:$proof,
         unit_execstartpre_sha256:{vector:$sha,wazuh:$sha},runtime_sha256:{"coordinator.sh":$sha,"guard.sh":$sha,"state-lib.sh":$sha,"state.jq":$sha,"checkpoint-gates.sh":$sha,"checkpoint-gates.jq":$sha,"writer-gates.sh":$sha},
         old_container:{cid:$old,image:("sha256:"+$sha),pid:123,start_ticks:"456"},
         new_container:{image:("sha256:"+$sha),started_at:"2026-10-15T00:00:00Z",identity:{cid:$new,pid:321,start_ticks:"654",mount_ns:"mnt:[123]",pid_ns:"pid:[124]",uid:101,gid:101}},
         wazuh:{invocation_id:"33333333333333333333333333333333",pid:444,start_ticks:"777"}}}' | put "$WR_BASE/plan.json"
    WR_REASON=unspecified
}
expect_refused() { local rc=0; "$@" > "$root/out" 2> "$root/err" || rc=$?; [[ $rc != 0 ]]; }
mutate() { local file=$1 filter=$2; /usr/bin/jq "$filter" "$file" | put "$root/replacement.json"; /bin/cp "$root/replacement.json" "$file"; }
rehash_plan() {
    local i=$1 side=$2 sha
    sha=$(wr_sha "$WR_BASE/$side/${WR_NAMES[$i]}")
    /usr/bin/jq --argjson i "$i" --arg key "${side}_sha256" --arg sha "$sha" '.files[$i][$key]=$sha' "$WR_BASE/plan.json" | put "$root/plan-next.json"
    /bin/cp "$root/plan-next.json" "$WR_BASE/plan.json"
}
success() { wr_apply > "$root/out"; [[ $WR_PREFIX == 5 ]]; /usr/bin/jq -e '.complete and .prefix==5' "$WR_BASE/intent.json" >/dev/null; }
repeat_no_rewrite() { success; local a b; a=$(wr_meta "${WR_TARGETS[4]}"); success; b=$(wr_meta "${WR_TARGETS[4]}"); [[ $a == "$b" ]]; }
precondition_fail() { /usr/bin/touch "$root/deny"; expect_refused wr_apply; [[ ! -e $WR_BASE/intent.json ]]; wr_prefix; [[ $WR_PREFIX == 0 ]]; }
target_mismatch() { printf 'wrong\n' >> "${WR_TARGETS[0]}"; expect_refused wr_apply; [[ ! -e $WR_BASE/intent.json ]]; }
nonprefix() { /bin/cp "$WR_BASE/after/waf-binding.json" "${WR_TARGETS[2]}"; /bin/chmod 600 "${WR_TARGETS[2]}"; expect_refused wr_apply; }
unowned_partial() { /bin/cp "$WR_BASE/after/vector.env" "${WR_TARGETS[0]}"; /bin/chmod 600 "${WR_TARGETS[0]}"; expect_refused wr_apply; }
resume_after_rename() { wr_plan; wr_intent_set 0 vector.env false absent; wr_atomic "${WR_TARGETS[0]}" "$WR_BASE/after/vector.env" 600 "$(wr_sha "$WR_BASE/before/vector.env")"; success; }
resume_after_intent() { wr_plan; wr_intent_set 0 vector.env false absent; success; }
resume_after_state() {
    wr_plan; local i
    for i in 0 1 2 3; do
        wr_intent_set "$i" "${WR_NAMES[$i]}" false "${WR_INTENT_SHA:-absent}"; wr_history "$i"
        wr_atomic "${WR_TARGETS[$i]}" "$WR_BASE/after/${WR_NAMES[$i]}" 600 "$(wr_sha "$WR_BASE/before/${WR_NAMES[$i]}")"
        if (( i<3 )); then wr_receipt "$i"; wr_intent_set "$((i+1))" '' false; fi
    done
    success
}
wrong_intent() { wr_plan; wr_intent_set 0 '' false absent; mutate "$WR_BASE/intent.json" '.plan_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"'; /bin/chmod 600 "$WR_BASE/intent.json"; expect_refused wr_apply; }
history_conflict() { wr_plan; local sha; sha=$(wr_sha "$WR_BASE/before/suricata-state.json"); printf 'bad\n' > "$WR_STATE/suricata/history/5-$sha.json"; /bin/chmod 400 "$WR_STATE/suricata/history/5-$sha.json"; expect_refused wr_apply; wr_prefix; [[ $WR_PREFIX == 3 ]]; }
changed_candidate() { mutate "$WR_BASE/after/suricata-state.json" '.current.inode=999'; rehash_plan 3 after; expect_refused wr_apply; }
changed_old_waf() { mutate "$WR_BASE/after/modsecurity-state.json" '.current.inode=999|.proof.old_closed.inode=999'; rehash_plan 4 after; expect_refused wr_apply; }
extra_pin() { mutate "$WR_BASE/after/modsecurity-state.json" '.source_pins.engine_config_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"'; rehash_plan 4 after; expect_refused wr_apply; }
wrong_generation() { mutate "$WR_BASE/after/modsecurity-state.json" '.pending.number=5|.pending.basename="generation-0000000005.jsonl"'; rehash_plan 4 after; expect_refused wr_apply; }
unrelated_env() { printf 'UNRELATED=1\n' >> "$WR_BASE/after/vector.env"; rehash_plan 0 after; expect_refused wr_apply; }
duplicate_env() { printf 'WAF_INSTANCE_ID=%s\n' "$(hex 2)" >> "$WR_BASE/after/vector.env"; rehash_plan 0 after; expect_refused wr_apply; }
bad_stop() { mutate "$WR_BASE/stop-proof.json" '.after_status.MainPID="7"'; local sha; sha=$(wr_sha "$WR_BASE/stop-proof.json"); mutate "$WR_BASE/plan.json" ".authority.stop_proof_sha256=\"$sha\""; expect_refused wr_apply; }
noncanonical() { printf ' ' >> "$WR_BASE/plan.json"; expect_refused wr_apply; }
multiple_json() { /bin/cat "$WR_BASE/plan.json" >> "$root/add.json"; /bin/cat "$root/add.json" >> "$WR_BASE/plan.json"; expect_refused wr_apply; }
target_symlink() { /bin/mv "${WR_TARGETS[0]}" "$root/elsewhere"; /bin/ln -s "$root/elsewhere" "${WR_TARGETS[0]}"; expect_refused wr_apply; }
target_hardlink() { /bin/ln "${WR_TARGETS[0]}" "$root/extra-link"; expect_refused wr_apply; /bin/rm "$root/extra-link"; }
wrong_mode() { /bin/chmod 644 "${WR_TARGETS[0]}"; expect_refused wr_apply; }
artifact_link() { /bin/ln "$WR_BASE/after/vector.env" "$root/artifact-link"; expect_refused wr_apply; /bin/rm "$root/artifact-link"; }
cas_failure() {
    eval "$(declare -f wr_atomic | /bin/sed '1s/wr_atomic/wr_real_atomic/')"
    wr_atomic() { if [[ $1 == "${WR_TARGETS[1]}" ]]; then printf 'injected\n' > "$root/injected"; return 1; else wr_real_atomic "$@"; fi; }
    expect_refused wr_apply; [[ -e $root/injected ]]; wr_prefix; [[ $WR_PREFIX == 1 ]];
    /usr/bin/jq -e '.attempted=="raw-line-binding.json" and .prefix==1' "$WR_BASE/intent.json" >/dev/null
}
postrename_failure_resume() {
    eval "$(declare -f wr_atomic | /bin/sed '1s/wr_atomic/wr_real_atomic/')"
    wr_atomic() { wr_real_atomic "$@" || return; if [[ $1 == "${WR_TARGETS[0]}" ]]; then printf 'injected\n' > "$root/injected"; return 1; fi; }
    expect_refused wr_apply; [[ -e $root/injected ]]; wr_prefix; [[ $WR_PREFIX == 1 ]];
    wr_atomic() { wr_real_atomic "$@"; }; success
}
history_sync_failure() {
    wr_history() { if [[ $1 == 3 ]]; then printf 'injected\n' > "$root/injected"; return 1; fi; }
    expect_refused wr_apply; [[ -e $root/injected ]]; wr_prefix; [[ $WR_PREFIX == 3 ]];
    [[ $(wr_sha "${WR_TARGETS[3]}") == "$(wr_sha "$WR_BASE/before/suricata-state.json")" ]]
}
prepare_setup() {
    WR_MANAGED=$root/case/raw/managed WR_ALIAS=$root/case/raw/audit.log
    /bin/mkdir -m 700 -p "$WR_MANAGED"
    printf 'OLDrow\n' > "$WR_MANAGED/generation-0000000003.jsonl"
    printf 'NEWxx\n' > "$WR_MANAGED/generation-0000000004.jsonl"
    /bin/ln "$WR_MANAGED/generation-0000000003.jsonl" "$WR_ALIAS"
    local dev ino sha files i n
    dev=$(/usr/bin/stat -c %d "$WR_ALIAS"); ino=$(/usr/bin/stat -c %i "$WR_ALIAS")
    /usr/bin/jq --argjson dev "$dev" --argjson ino "$ino" '.current.device=$dev|.current.inode=$ino' "${WR_TARGETS[4]}" | put "$root/state-next.json" 600
    /bin/cp "$root/state-next.json" "${WR_TARGETS[4]}"
    sha=$(wr_sha "${WR_TARGETS[4]}")
    mutate "$WR_BASE/stop-proof.json" ".old_state_sha256=\"$sha\""
    sha=$(wr_sha "$WR_BASE/stop-proof.json")
    mutate "$WR_BASE/plan.json" ".authority.stop_proof_sha256=\"$sha\""
    files='{}'
    for i in 0 1 2 3 4; do n=${WR_NAMES[$i]}; files=$(/usr/bin/jq -nc --argjson f "$files" --arg n "$n" --arg sha "$(wr_sha "${WR_TARGETS[$i]}")" '$f+{($n):$sha}'); done
    /usr/bin/jq --argjson files "$files" 'del(.files)|.expected_before_sha256=$files' "$WR_BASE/plan.json" | put "$WR_BASE/descriptor.json"
    /bin/rm -rf "$WR_BASE/before" "$WR_BASE/after" "$WR_BASE/receipts" "$WR_BASE/plan.json"
    # Only known synthetic EOF proof objects. No native CP or source is read.
    cg_sealed_lines() { [[ $1 == "$WR_MANAGED/generation-0000000003.jsonl" && $4 == 7 ]]; }
    cg_vector_eof() { /usr/bin/jq -nc --arg sha "$(hex 11)" '{checkpoint_sha256:$sha,offset:7}'; }
    cg_wazuh_eof() { /usr/bin/jq -nc --arg sha "$(hex 11)" '{checkpoint_sha256:$sha,offset:7,stored_sha1:"1111111111111111111111111111111111111111"}'; }
    cg_wazuh_cold() { /usr/bin/jq -nc --arg sha "$(hex 11)" '{reason:"different_prefix",checkpoint_sha256:$sha,offset:7,stored_sha1:"1111111111111111111111111111111111111111",prefix_sha1:"2222222222222222222222222222222222222222",source_identity:{bytes:6}}'; }
}
prepare_success() { prepare_setup; wr_prepare > "$root/out"; wr_plan; wr_prefix; [[ $WR_PREFIX == 0 && ! -e $WR_BASE/intent.json ]]; /usr/bin/jq -e '.status=="prepared" and .operating_files_changed==0' "$root/out" >/dev/null; }
prepare_refuses_existing() { prepare_setup; /bin/mkdir -m 700 "$WR_BASE/after"; expect_refused wr_prepare; [[ ! -e $WR_BASE/before ]]; }
prepare_eof_refusal() { prepare_setup; cg_vector_eof() { return 2; }; expect_refused wr_prepare; [[ ! -e $WR_BASE/plan.json && ! -e $WR_BASE/intent.json ]]; }
prepare_expected_hash_conflict() { prepare_setup; printf 'changed\n' >> "${WR_TARGETS[0]}"; expect_refused wr_prepare; [[ ! -e $WR_BASE/intent.json ]]; }
producer_extra_change() { printf 'extra\n' >> "$WR_BASE/new-producer.conf"; expect_refused wr_apply; }
env_blank_comment_final_lf() {
    /bin/cp "$WR_BASE/before/vector.env" "$root/env-before"
    /bin/cp "$WR_BASE/after/vector.env" "$root/env-after"
    local side input
    for side in before after; do
        input=$root/env-$side
        { printf '\n# literal $NOT_EVALUATED $(false) = comment\n\n'; /bin/cat "$input"; printf '\n# final comment\n\n'; } > "$WR_BASE/$side/vector.env"
    done
    /bin/cp "$WR_BASE/plan.json" "$WR_BASE/descriptor.json"
    wr_prepare_env > "$root/env-observed"
    /usr/bin/cmp -s "$root/env-observed" "$WR_BASE/after/vector.env"
}
env_final_lf_exact() {
    /bin/cp "$WR_BASE/plan.json" "$WR_BASE/descriptor.json"
    wr_prepare_env > "$root/env-observed"
    /usr/bin/cmp -s "$root/env-observed" "$WR_BASE/after/vector.env"
    [[ $(/usr/bin/tail -c 1 "$root/env-observed" | /usr/bin/od -An -tu1 | /usr/bin/tr -d ' \n') == 10 ]]
}
passed=0 failed=0
run() {
    local name=$1 rc=0
    # Execute outside an if/&& condition so assertions keep errexit semantics.
    set +e
    ( set -euo pipefail; setup; "$name" ) > "$root/test.stdout" 2> "$root/test.stderr"
    rc=$?
    set -e
    if (( rc==0 )); then passed=$((passed+1)); printf 'PASS %s\n' "$name"
    else failed=$((failed+1)); printf 'FAIL %s rc=%s\n' "$name" "$rc"; /usr/bin/tail -n 8 "$root/test.stderr"; fi
}
case $selection in
 all) cases=(success repeat_no_rewrite precondition_fail target_mismatch nonprefix unowned_partial resume_after_rename resume_after_intent resume_after_state wrong_intent history_conflict changed_candidate changed_old_waf extra_pin wrong_generation unrelated_env duplicate_env bad_stop noncanonical multiple_json target_symlink target_hardlink wrong_mode artifact_link cas_failure postrename_failure_resume history_sync_failure prepare_success prepare_refuses_existing prepare_eof_refusal prepare_expected_hash_conflict producer_extra_change env_blank_comment_final_lf env_final_lf_exact) ;;
 prepare) cases=(prepare_success prepare_refuses_existing prepare_eof_refusal prepare_expected_hash_conflict env_blank_comment_final_lf env_final_lf_exact) ;;
 env) cases=(env_blank_comment_final_lf env_final_lf_exact) ;;
esac
for name in "${cases[@]}"; do run "$name"; done
[[ $(wr_sha "$directory/waf-rebind-metadata.sh") == "$original_sha" ]]
/usr/bin/jq -nc --arg selection "$selection" --argjson passed "$passed" --argjson failed "$failed" '{suite:"waf_rebind_metadata_private",selection:$selection,passed:$passed,failed:$failed,live_preconditions_executed:false,production_access:false}'
(( failed==0 ))
