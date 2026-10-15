#!/bin/bash
# Local synthetic metadata only. Uses the actual evaluator and pinned state
# schema. No operational files, Docker/systemd, SSH or deletion are called.
set -euo pipefail
export LC_ALL=C
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/capstone-lifecycle-test.XXXXXXXX")
trap 'rm -f -- "$work/seed" "$work/base" "$work/input" "$work/result" "$work/err" "$work/rows" "$work/value" "$work/hashed" "$work/first"; rmdir -- "$work"' EXIT
sha() { local v; v=$(sha256sum -- "$1"); printf '%s\n' "${v%% *}"; }
a=$(printf 'a%.0s' {1..64}); b=$(printf 'b%.0s' {1..64}); c=$(printf 'c%.0s' {1..64})
s=$(printf 'd%.0s' {1..40})
jq -ncS --arg a "$a" --arg b "$b" --arg c "$c" --arg s "$s" '
 def gen($n;$i): {basename:("generation-"+(("0000000000"+($n|tostring))[-10:])+".jsonl"),number:$n,device:42,inode:$i,writer_config_sha256:$a};
 def state($engine;$gen;$rev): {schema_version:1,policy:"capstone-raw-operations-v1",machine_id:"096e90b6243e438aa8a7b392be754732",
  boot_id:("f"*32),engine:$engine,phase:"active",revision:$rev,current:$gen,pending:null,
  source_pins:{container_id:$a,engine_config_sha256:$a,producer_format_sha256:$a,vector_config_sha256:$a,vector_env_sha256:$a,wazuh_config_sha256:$a},
  proof:{old_closed:null,readers_drained:null,publish_guard:null}};
 (state("suricata";gen(1;101);2)|.phase="old_closed"|.pending=gen(2;102)|
   .proof.old_closed={boot_id:("f"*32),bytes:25,device:42,inode:101,sha256:$a,writer_fd_zero:true,writer_pid:123,writer_start_ticks:999}) as $closed |
 ($closed|.revision=3|.phase="readers_drained"|.proof.readers_drained={vector_checkpoint_sha256:$b,vector_offset:25,vector_stopped:true,
    wazuh_checkpoint_sha256:$b,wazuh_offset:25,wazuh_sha1:$s}) as $drained |
 ($drained|.revision=4|.phase="publish_pending"|.proof.publish_guard={decision:"different_prefix",new_prefix_sha1:("e"*40),old_offset:25,
    old_sha1:$s,source_bytes:20,wazuh_checkpoint_sha256:$c}) as $pub |
 (state("suricata";gen(2;102);5)) as $active |
 (state("modsecurity";gen(4;204);13)) as $waf |
 {schema_version:1,policy:"capstone-sealed-raw-snapshot-v1",machine_id:"096e90b6243e438aa8a7b392be754732",engine:"suricata",observed_at_epoch:1800000000,
  capture:{complete:true,stable:true,shared_lock_held:true,host_pins_match:true,raw_guards_passed:true,intents_absent:true,writer_fd_zero:true,references_clear:true},
  source:{basename:"generation-0000000001.jsonl",device:42,inode:101,bytes:25,sha256:$a,sha1:$s,uid:0,gid:0,mode:"0400",links:1,stable:true},
  current:{suricata:{sha256:$a,state:$active},modsecurity:{sha256:$a,state:$waf}},
  chain:[$closed,$drained,$pub,$active]|map({sha256:$a,state:.}),
  aliases:[{engine:"suricata",device:42,inode:102,writer_device:42,writer_inode:102},{engine:"modsecurity",device:42,inode:204,writer_device:42,writer_inode:204}],
  first_verified:null,archive:null,remote:null}' > "$work/seed"
rehash() {
    jq -c '.chain[],.current.suricata,.current.modsecurity' "$work/input" > "$work/rows"
    : > "$work/hashed"
    while IFS= read -r row; do
        jq -cS .state <<< "$row" > "$work/value"
        jq -c --arg sha "$(sha "$work/value")" '.sha256=$sha' <<< "$row" >> "$work/hashed"
    done < "$work/rows"
    jq -cS --slurpfile rows "$work/hashed" '.chain=$rows[:-2]|.current.suricata=$rows[-2]|.current.modsecurity=$rows[-1]' "$work/input" > "$work/value"
    cp "$work/value" "$work/input"
    if jq -e '.first_verified!=null' "$work/input" >/dev/null; then
        jq -cS .first_verified.record "$work/input" > "$work/first"
        jq -cS --arg sha "$(sha "$work/first")" '.first_verified.sha256=$sha' "$work/input" > "$work/value"
        cp "$work/value" "$work/input"
    fi
}
cp "$work/seed" "$work/input"; rehash; cp "$work/input" "$work/base"
passed=0
run() {
    local name=$1 filter=$2 assertion=$3 rc
    jq -cS "$filter" "$work/base" > "$work/input"
    rehash
    set +e
    /bin/bash "$here/evaluate.sh" "$work/input" > "$work/result" 2> "$work/err"
    rc=$?
    set -e
    if (( rc!=0 )) || ! jq -e "$assertion and .delete_authorized==false and .automatic_deletion==false and .observation_authenticated==false" "$work/result" >/dev/null; then
       printf '{"status":"failed","case":"%s","passed":%s,"exit":%s}\n' "$name" "$passed" "$rc"; cat "$work/result"; cat "$work/err"; exit 1
    fi
    passed=$((passed+1))
}
run initial_qualified '.' '.archive_copy_eligible and .first_receipt_action=="create_exclusive" and (.retention_elapsed|not) and (.deletion_review_ready|not)'
/bin/bash "$here/evaluate.sh" "$work/base" | jq -cS .first_verified_receipt > "$work/first"
jq -cS --slurpfile first "$work/first" --arg sha "$(sha "$work/first")" '.first_verified={sha256:$sha,record:$first[0]}' "$work/base" > "$work/value"
cp "$work/value" "$work/base"
run preserve_first_next_day '.observed_at_epoch+=86400' '.first_receipt_action=="preserve_exact" and .first_verified_receipt.first_verified_at_epoch==1800000000 and .age_seconds==86400'
run before_30_day_boundary '.observed_at_epoch+=2591999' '(.retention_elapsed|not)'
run exact_30_day_boundary '.observed_at_epoch+=2592000' '.retention_elapsed and (.deletion_review_ready|not)'
run backward_clock '.observed_at_epoch-=1' '(.reasons|index("clock_before_first_verified"))!=null'
run first_binding_conflict '.first_verified.record.source.inode=999' '.first_verified_receipt==null'
for field in complete stable shared_lock_held host_pins_match raw_guards_passed intents_absent writer_fd_zero references_clear; do
    run "capture_$field" ".capture.$field=false" '.deletion_review_ready==false and .first_verified_receipt==null'
done
for change in '.source.links=2' '.source.mode="0644"' '.source.uid=998' '.source.gid=998' '.source.stable=false' '.source.bytes=26' '.source.inode=99' '.source.sha256=("0"*64)' '.source.sha1=("0"*40)'; do
    run "source_$passed" "$change" '.deletion_review_ready==false and .first_verified_receipt==null'
done
run alias_not_current '.aliases[0].inode=199' '.deletion_review_ready==false and .first_verified_receipt==null'
run writer_not_current '.aliases[0].writer_inode=199' '.deletion_review_ready==false and .first_verified_receipt==null'
run candidate_alias_reference '.aliases[0].inode=101' '.deletion_review_ready==false and .first_verified_receipt==null'
run candidate_writer_reference '.aliases[0].writer_inode=101' '.deletion_review_ready==false and .first_verified_receipt==null'
run copy_without_consumption_proof '.chain=[]|.first_verified=null' '.archive_copy_eligible and .status=="archive_copy_only" and .first_verified_receipt==null'
run linked_source_copy_refused '.source.links=2' '.archive_copy_eligible==false and .first_verified_receipt==null'
run reference_without_link_copy '.capture.references_clear=false' '.archive_copy_eligible and .first_verified_receipt==null'
run missing_transition '.chain[1]=.chain[0]' '.deletion_review_ready==false and .first_verified_receipt==null'
run pin_rebind '.chain[3].state.source_pins.vector_env_sha256=("0"*64)|.current.suricata=.chain[3]' '.deletion_review_ready==false and .first_verified_receipt==null'
run current_detached '.current.suricata.state.revision+=1' '.deletion_review_ready==false and .first_verified_receipt==null'
run boot_change '.chain[3].state.boot_id=("0"*32)|.current.suricata=.chain[3]' '.deletion_review_ready==false and .first_verified_receipt==null'
# Complete archive/B restore receipts are metadata fixtures, not a network test.
jq -cS --arg c "$c" '.observed_at_epoch+=2592000|
 .archive={schema_version:1,policy:"capstone-sealed-raw-archive-v1",source:(.first_verified.record.source),gzip_sha256:$c,gzip_bytes:45,manifest_sha256:$c,local_restore_sha256:.source.sha256,local_restore_bytes:.source.bytes}|
 .remote={schema_version:1,policy:"capstone-sealed-raw-receipt-v1",receiver_machine_id:"1e143067c98a44ffba6eaa925dc038d7",
 stage:"remote_preserved_and_restore_verified",manifest_sha256:$c,gzip_sha256:$c,gzip_bytes:45,restored_sha256:.source.sha256,
 restored_bytes:.source.bytes,received_at_epoch:1800000001,restore_verified_at_epoch:1800000002}' "$work/base" > "$work/value"
cp "$work/value" "$work/base"
run bounded_review_ready '.' '.deletion_review_ready and .remote_archive_restore_verified'
run wrong_archive_source '.archive.source.inode=999' '.deletion_review_ready==false'
run bad_local_restore '.archive.local_restore_sha256=("0"*64)' '.deletion_review_ready==false'
run bad_remote_payload '.remote.restored_sha256=("0"*64)' '.deletion_review_ready==false'
run bad_remote_size '.remote.restored_bytes+=1' '.deletion_review_ready==false'
run bad_remote_manifest '.remote.manifest_sha256=("0"*64)' '.deletion_review_ready==false'
run bad_remote_gzip '.remote.gzip_sha256=("0"*64)' '.deletion_review_ready==false'
run future_remote '.remote.restore_verified_at_epoch=.observed_at_epoch+1' '.deletion_review_ready==false'
run old_remote '.remote.received_at_epoch=1799999999' '.deletion_review_ready'
reject() {
    local name=$1 expected=$2 rc
    set +e
    /bin/bash "$here/evaluate.sh" "$work/input" > "$work/result" 2> "$work/err"
    rc=$?
    set -e
    if (( rc!=65 )) || ! jq -e --arg expected "$expected" '.reason==$expected and .delete_authorized==false' "$work/result" >/dev/null; then
       printf '{"status":"failed","case":"%s","passed":%s,"exit":%s}\n' "$name" "$passed" "$rc"; cat "$work/result"; exit 1
    fi
    passed=$((passed+1))
}
jq -cS '.chain[0].sha256=("0"*64)' "$work/base" > "$work/input"; reject bad_state_digest state_digest_mismatch
jq -cS '.first_verified.sha256=("0"*64)' "$work/base" > "$work/input"; reject bad_receipt_digest first_receipt_digest_mismatch
jq -cS '.chain[2].state.proof.readers_drained.wazuh_offset=24' "$work/base" > "$work/input"; reject incomplete_eof invalid_snapshot_schema
jq -cS '.remote.receiver_machine_id=("0"*32)' "$work/base" > "$work/input"; reject wrong_receiver invalid_snapshot_schema
jq -cS '.extra=true' "$work/base" > "$work/input"; reject extra_field invalid_snapshot_schema
jq . "$work/base" > "$work/input"; reject noncanonical noncanonical_json
{ cat "$work/base"; cat "$work/base"; } > "$work/input"; reject multiple multiple_documents
sed 's/"schema_version":1/"schema_version":1,"schema_version":1/' "$work/base" > "$work/input"; reject duplicate noncanonical_json
printf '{"status":"passed","cases":%s,"live_observations":false,"service_or_ssh_calls":false,"deletion_executed":false}\n' "$passed"
