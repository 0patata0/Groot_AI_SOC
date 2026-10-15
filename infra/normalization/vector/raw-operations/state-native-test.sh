#!/bin/bash
# Synthetic metadata only. No operating reader/writer/configuration is touched.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $(id -u) == 0 && $(uname -s) == Linux ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/state-lib.sh"
fixture=$(mktemp -d /var/tmp/capstone-raw-state-test.XXXXXXXX)
chmod 700 "$fixture"
cleanup() {
    [[ $fixture =~ ^/var/tmp/capstone-raw-state-test\.[A-Za-z0-9_-]{6,20}$ &&
       -d $fixture && ! -L $fixture && $(stat -c %u:%g:%a "$fixture") == 0:0:700 ]] && rm -rf -- "$fixture"
}
trap cleanup EXIT
root=$fixture/state
mkdir -m 700 "$root"
: > "$root/.fixture.lock"
exec 9<>"$root/.fixture.lock"
flock -n 9
passed=0
ok() { passed=$((passed+1)); }
accept() {
    local name=$1; shift
    if "$@" > "$fixture/result.json" 2> "$fixture/error"; then ok; else
        printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1
    fi
}
reject() {
    local name=$1; shift
    if "$@" > "$fixture/result.json" 2> "$fixture/error"; then
        printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1
    fi
    ok
}
same() { [[ $(_rs_sha "$root/suricata/state.json") == "$1" ]] || exit 1; }
base() {
    jq -ncS --arg engine "$1" '{schema_version:1,policy:"capstone-raw-operations-v1",engine:$engine,
      machine_id:"096e90b6243e438aa8a7b392be754732",boot_id:("b"*32),revision:0,phase:"active",
      source_pins:{container_id:("c"*64),engine_config_sha256:("d"*64),producer_format_sha256:("e"*64),
        vector_config_sha256:("f"*64),vector_env_sha256:("a"*64),wazuh_config_sha256:("b"*64)},
      current:{number:0,basename:"generation-0000000000.jsonl",device:100,inode:200,writer_config_sha256:("a"*64)},
      pending:null,proof:{old_closed:null,readers_drained:null,publish_guard:null}}'
}
candidate=$root/suricata/staging/candidate-fixture.json
new_candidate() { jq -cS "$1" "$root/suricata/state.json" > "$candidate"; chmod 600 "$candidate"; }
accept prepare_suricata raw_state_prepare "$root" suricata
base suricata > "$candidate"
accept initialize raw_state_init "$root" suricata "$candidate"
accept lockfree_read raw_state_read_twice "$root" suricata
jq -e '.start_authorized==false and .state.phase=="active"' "$fixture/result.json" >/dev/null
reject duplicate_initialization raw_state_init "$root" suricata "$candidate"
original=$(_rs_sha "$root/suricata/state.json")

new_candidate '.revision+=1'
reject same_phase_not_transition raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
new_candidate '.revision+=1|.phase="switch_pending"|.pending=(.current|.number=1|.basename="generation-0000000001.jsonl"|.inode=201)'
correct_candidate=$(cat "$candidate")
reject stale_expected_hash raw_state_cas "$root" suricata "$(printf '%064d' 0)" "$candidate"; same "$original"
jq -cS '.revision=3' <<< "$correct_candidate" > "$candidate"
reject revision_skip raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
jq -cS '.source_pins.vector_env_sha256=("0"*64)' <<< "$correct_candidate" > "$candidate"
reject changed_source_pin raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
jq -cS '.pending.number=2|.pending.basename="generation-0000000002.jsonl"' <<< "$correct_candidate" > "$candidate"
reject skipped_generation raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
jq -cS '.pending.basename="../escape.jsonl"' <<< "$correct_candidate" > "$candidate"
reject arbitrary_generation_path raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
jq -cS '.pending.inode=.current.inode' <<< "$correct_candidate" > "$candidate"
reject reused_inode raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
printf '%s\n' "$correct_candidate" | sed 's/"revision":1/"revision":0,"revision":1/' > "$candidate"
reject duplicate_key raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
printf '%s\n%s\n' "$correct_candidate" "$correct_candidate" > "$candidate"
reject multiple_objects raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
printf '%s\n' "$correct_candidate" > "$candidate"; chmod 666 "$candidate"
reject writable_candidate raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
chmod 600 "$candidate"
ln "$candidate" "$root/suricata/staging/extra-link"
reject hardlinked_candidate raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
rm "$root/suricata/staging/extra-link"
mv "$candidate" "$root/suricata/staging/saved-candidate"
ln -s saved-candidate "$candidate"
reject symlink_candidate raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
rm "$candidate"; mv "$root/suricata/staging/saved-candidate" "$candidate"

# Failure before the current state mutation must not advance revision. The
# newly published history snapshot may remain and must be re-fsynced on retry.
sync() { [[ $* != *'/history'* ]] || return 1; command sync "$@"; }
reject history_fsync_failure raw_state_cas "$root" suricata "$original" "$candidate"; same "$original"
unset -f sync
accept history_fsync_retry raw_state_cas "$root" suricata "$original" "$candidate"
reject lost_reply_does_not_repeat_transition raw_state_cas "$root" suricata "$original" "$candidate"

new_candidate '.revision+=1|.phase="old_closed"|
 .proof.old_closed={boot_id:.boot_id,bytes:123,device:.current.device,inode:.current.inode,
 sha256:("a"*64),writer_fd_zero:true,writer_pid:1234,writer_start_ticks:4567}'
previous=$(_rs_sha "$root/suricata/state.json")
accept close_proof raw_state_cas "$root" suricata "$previous" "$candidate"
new_candidate '.revision+=1|.phase="readers_drained"|
 .proof.readers_drained={vector_checkpoint_sha256:("a"*64),wazuh_checkpoint_sha256:("b"*64),
 vector_offset:122,wazuh_offset:123,wazuh_sha1:("c"*40),vector_stopped:true}'
previous=$(_rs_sha "$root/suricata/state.json")
reject mismatched_reader_eof raw_state_cas "$root" suricata "$previous" "$candidate"; same "$previous"
jq -cS '.proof.readers_drained.vector_offset=123' "$candidate" > "$fixture/correct.json"
cat "$fixture/correct.json" > "$candidate"
accept drained_proof raw_state_cas "$root" suricata "$previous" "$candidate"

new_candidate '.revision+=1|.phase="publish_pending"|
 .proof.publish_guard={decision:"different_prefix",new_prefix_sha1:("c"*40),old_offset:123,
 old_sha1:("c"*40),source_bytes:456,wazuh_checkpoint_sha256:("b"*64)}'
previous=$(_rs_sha "$root/suricata/state.json")
reject equal_prefix_not_publishable raw_state_cas "$root" suricata "$previous" "$candidate"; same "$previous"
jq -cS '.proof.publish_guard.new_prefix_sha1=("d"*40)' "$candidate" > "$fixture/correct.json"
cat "$fixture/correct.json" > "$candidate"
# Another Wazuh source may change the full checkpoint file after EOF. Preserve
# both observation hashes; only this source's saved offset/SHA1 must agree.
jq -cS '.proof.publish_guard.wazuh_checkpoint_sha256=("f"*64)' "$candidate" > "$fixture/correct.json"
cat "$fixture/correct.json" > "$candidate"
accept publication_proof raw_state_cas "$root" suricata "$previous" "$candidate"
jq -e '.proof.publish_guard.wazuh_checkpoint_sha256!=.proof.readers_drained.wazuh_checkpoint_sha256' "$root/suricata/state.json" >/dev/null
ok
new_candidate '.revision+=1|.phase="active"|.current=.pending|.pending=null|
 .proof={old_closed:null,publish_guard:null,readers_drained:null}'
previous=$(_rs_sha "$root/suricata/state.json")
accepted=$(_rs_sha "$candidate")
# A failure after atomic rename is not acknowledged as success. The caller must
# inspect the actual state; it must not blindly issue the same old CAS again.
sync() {
    [[ ${1:-} != -- ]] || shift
    [[ $# != 1 || $1 != "$root/suricata" ]] || return 1
    command sync -- "$@"
}
# Verify the injected failure itself; GNU coreutils '--' is a real argument.
if sync -- "$root/suricata"; then exit 1; fi
ok
reject postrename_directory_fsync_failure raw_state_cas "$root" suricata "$previous" "$candidate"
unset -f sync
same "$accepted"
command sync -- "$root/suricata/state.json" "$root/suricata"
accept inspect_after_uncertain_ack raw_state_read_twice "$root" suricata
jq -e '.state.revision==5 and .state.current.number==1 and .state.phase=="active"' "$fixture/result.json" >/dev/null
[[ $(find "$root/suricata/history" -type f | wc -l) == 5 ]]
ok
chmod 640 "$root/suricata/state.json"
reject state_mode_change raw_state_read_twice "$root" suricata
chmod 600 "$root/suricata/state.json"

accept prepare_modsecurity raw_state_prepare "$root" modsecurity
base modsecurity > "$root/modsecurity/staging/candidate-fixture.json"
accept initialize_modsecurity raw_state_init "$root" modsecurity "$root/modsecurity/staging/candidate-fixture.json"
accept read_modsecurity raw_state_read_twice "$root" modsecurity

# Bound crossing is tested with metadata only, without allocating raw files.
new_candidate '.revision+=1|.phase="switch_pending"|.pending=(.current|.number=2|.basename="generation-0000000002.jsonl"|.inode=202)'
for number in $(seq 1 1019); do : > "$root/suricata/history/capacity-$number"; done
previous=$(_rs_sha "$root/suricata/state.json")
reject history_capacity_bound raw_state_cas "$root" suricata "$previous" "$candidate"; same "$previous"
cleanup
[[ ! -e $fixture ]]
trap - EXIT
printf '{"status":"passed","cases":%s,"synthetic_only":true,"operating_mutations":0,"fixture_removed":true,"native_reader_tested":false}\n' "$passed"
