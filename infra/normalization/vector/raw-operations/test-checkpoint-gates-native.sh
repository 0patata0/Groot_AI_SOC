#!/bin/bash
# Synthetic only. No installed checkpoint, journal, Docker or service access.
# Usage: /bin/bash this-file /absolute/private-root-owned-task-directory
set -euo pipefail
PATH=/usr/bin:/bin; export PATH LC_ALL=C TZ=UTC
umask 077
[[ $EUID == 0 && $OSTYPE == linux* && $# == 1 && $1 == /* && -d $1 && ! -L $1 ]] || exit 77
[[ $(/usr/bin/stat -c '%u:%a' -- "$1") == 0:700 ]] || exit 77
here=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd -P)
root=$(/usr/bin/mktemp -d "$1/checkpoint-fixture.XXXXXX")
trap '/bin/rm -rf -- "$root"' EXIT
trap 'exit 143' TERM HUP INT
source "$here/checkpoint-gates.sh"
original=$(/usr/bin/sha256sum -- "$here/checkpoint-gates.sh" "$here/checkpoint-gates.jq")
mkdir -m 700 -- "$root/cp"
file=$root/source.jsonl; cp_file=$root/wazuh.json; logical=/var/log/capstone-raw/suricata/reader.jsonl
passed=0; result=''; result_rc=0
base() {
    /bin/rm -f -- "$root/cp/checkpoints.json" "$root/cp/checkpoints.new.json" "$cp_file" "$file" "$root/new.jsonl"
    printf 'alpha\nbeta\n' > "$file"
    read -r dev ino bytes < <(/usr/bin/stat -c '%d %i %s' -- "$file")
    sha=$(/usr/bin/sha1sum -- "$file"); sha=${sha%% *}
}
vector_cp() {
    /usr/bin/jq -nc --argjson d "$dev" --argjson i "$ino" --argjson n "$1" \
      '{version:"1",checkpoints:[{fingerprint:{dev_inode:[$d,$i]},position:$n,modified:"2026-10-14T00:00:00Z"}]}' > "$root/cp/checkpoints.json"
}
wazuh_cp() {
    /usr/bin/jq -nc --arg p "$logical" --arg o "$1" --arg h "$2" \
      '{files:[{path:$p,offset:$o,hash:$h}]}' > "$cp_file"
}
expect() {
    local label=$1 expected=$2 reason=$3; shift 3
    result_rc=0
    if result=$("$@"); then :; else result_rc=$?; fi
    if [[ $result_rc != "$expected" ]] || ! /usr/bin/jq -se --arg reason "$reason" \
      'length==1 and (.[0]|.reason==$reason and .delivery_acknowledged==false and
       (.verdict=="pass" or .verdict=="defer"))' <<< "$result" >/dev/null; then
        printf '{"suite":"native_checkpoint_gates_synthetic","failed_case":"%s","exit":%s}\n' "$label" "$result_rc"
        exit 1
    fi
    passed=$((passed+1))
}
require_result() { /usr/bin/jq -e "$1" <<< "$result" >/dev/null || exit 1; }

base; vector_cp "$bytes"
expect vector_eof 0 sealed_eof cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
require_result '.source_stable and .source_identity.bytes==11 and .checkpoint_kind=="stable" and .offset==11'
vector_cp 3
expect vector_not_eof 2 checkpoint_not_at_sealed_eof cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
expect vector_current 0 current_offset_valid cg_vector_current "$root/cp" "$file" "$dev" "$ino"
require_result '.offset==3 and .backlog_bytes==8'
vector_cp 12
expect vector_future_offset 2 saved_offset_beyond_source cg_vector_current "$root/cp" "$file" "$dev" "$ino"
vector_cp "$bytes"
printf '{broken' > "$root/cp/checkpoints.new.json"
expect bad_pending_no_fallback 2 checkpoint_json_invalid cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
/bin/cp -- "$root/cp/checkpoints.json" "$root/cp/checkpoints.new.json"
vector_cp 0
expect valid_pending_first 0 sealed_eof cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
require_result '.checkpoint_kind=="pending"'
rm -- "$root/cp/checkpoints.new.json"
vector_cp "$bytes"
/usr/bin/jq '.checkpoints += .checkpoints' "$root/cp/checkpoints.json" > "$root/cp/change"
mv -- "$root/cp/change" "$root/cp/checkpoints.json"
expect duplicate_vector_identity 2 vector_checkpoint_invalid cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
printf '{"version":"1","checkpoints":[]}\n' > "$root/cp/checkpoints.json"
expect valid_checkpoint_missing_only_match 2 vector_checkpoint_match_missing cg_vector_current "$root/cp" "$file" "$dev" "$ino"
require_result '.source_stable and .checkpoint_sha256!=null'
vector_cp "$bytes"
/usr/bin/jq '.version=1' "$root/cp/checkpoints.json" > "$root/cp/change"; mv -- "$root/cp/change" "$root/cp/checkpoints.json"
expect numeric_version_rejected 2 vector_checkpoint_invalid cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
vector_cp "$bytes"
/usr/bin/sed 's/"position":11/"position":11e0/' "$root/cp/checkpoints.json" > "$root/cp/change"; mv -- "$root/cp/change" "$root/cp/checkpoints.json"
expect exponent_offset_rejected 2 checkpoint_json_invalid cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
vector_cp "$bytes"
/usr/bin/jq '.checkpoints[0].modified="2026-02-29T00:00:00Z"' "$root/cp/checkpoints.json" > "$root/cp/change"; mv -- "$root/cp/change" "$root/cp/checkpoints.json"
expect invalid_calendar_date 2 vector_checkpoint_invalid cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
vector_cp "$bytes"
/usr/bin/jq '.checkpoints[0].modified="invalid"' "$root/cp/checkpoints.json" > "$root/cp/change"; mv -- "$root/cp/change" "$root/cp/checkpoints.json"
expect timestamp_without_match 2 vector_checkpoint_invalid cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
vector_cp "$bytes"
ln -s -- "$root/cp/checkpoints.json" "$root/cp/checkpoints.new.json"
expect pending_symlink_rejected 2 checkpoint_path_rejected cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
base; vector_cp "$bytes"
expect mismatched_inode 2 sealed_identity_mismatch cg_vector_eof "$root/cp" "$file" "$dev" "$((ino+1))" "$bytes"
ln -s -- "$file" "$root/link.jsonl"
expect source_symlink 2 source_path_rejected cg_vector_eof "$root/cp" "$root/link.jsonl" "$dev" "$ino" "$bytes"
ln -s -- "$root/cp" "$root/linked-cp"
expect parent_symlink 2 checkpoint_path_rejected cg_vector_eof "$root/linked-cp" "$file" "$dev" "$ino" "$bytes"
rm -- "$file"; /usr/bin/mkfifo -- "$file"
expect fifo_rejected 2 source_not_regular cg_vector_current "$root/cp" "$file" "$dev" "$ino"
base; vector_cp "$bytes"; ln -- "$file" "$root/hard.jsonl"
expect source_hardlink_metadata 0 current_offset_valid cg_vector_current "$root/cp" "$file" "$dev" "$ino"
require_result '.source_identity.links==2'
rm -- "$root/hard.jsonl"

base; wazuh_cp "$bytes" "$sha"
expect wazuh_eof 0 sealed_eof cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
require_result '.prefix_sha1==.stored_sha1 and .scanned_bytes==11'
# Real native hashing reads beyond 4096. Change byte 7000 while retaining size.
/usr/bin/head -c 8192 /dev/zero | /usr/bin/tr '\000' A > "$file"
printf '\n' >> "$file"
read -r dev ino bytes < <(/usr/bin/stat -c '%d %i %s' -- "$file")
sha=$(/usr/bin/sha1sum -- "$file"); sha=${sha%% *}; wazuh_cp "$bytes" "$sha"
expect full_prefix_over_4096 0 sealed_eof cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
printf Z | /usr/bin/dd of="$file" bs=1 seek=7000 conv=notrunc status=none
expect changed_after_4096 2 checkpoint_prefix_mismatch cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
base; wazuh_cp "$bytes" "$sha"
/usr/bin/jq '.files[0].offset|=tonumber' "$cp_file" > "$root/change"; mv -- "$root/change" "$cp_file"
expect native_string_offset_only 2 wazuh_checkpoint_invalid cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
wazuh_cp "$bytes" "$sha"
/usr/bin/jq '.files += .files' "$cp_file" > "$root/change"; mv -- "$root/change" "$cp_file"
expect duplicate_wazuh_path 2 wazuh_checkpoint_invalid cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
wazuh_cp "$bytes" "$sha"
expect missing_logical_path 2 wazuh_checkpoint_invalid cg_wazuh_eof "$cp_file" /unmatched.jsonl "$file" "$dev" "$ino" "$bytes"
printf '{"files":[],"files":[{"path":"%s","hash":"%s","offset":"%s"}]}\n' "$logical" "$sha" "$bytes" > "$cp_file"
expect duplicate_empty_container 2 checkpoint_json_invalid cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
printf '{"FILES":[],"files":[{"path":"%s","hash":"%s","offset":"%s"}]}\n' "$logical" "$sha" "$bytes" > "$cp_file"
expect cjson_case_insensitive_key_ambiguity 2 wazuh_checkpoint_invalid cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
printf '{"files\\u0000suffix":[],"files":[{"path":"%s","hash":"%s","offset":"%s"}]}\n' "$logical" "$sha" "$bytes" > "$cp_file"
expect cjson_null_key_ambiguity 2 checkpoint_json_invalid cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
printf '{"files":[{"path":"%s","hash":"%s","offset":"0","offset":"%s"}]}\n' "$logical" "$sha" "$bytes" > "$cp_file"
expect duplicate_scalar_key 2 checkpoint_json_invalid cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
wazuh_cp "$bytes" "$sha"; printf '{}\n' >> "$cp_file"
expect multiple_documents 2 checkpoint_json_invalid cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
wazuh_cp "$bytes" "$sha"; /usr/bin/truncate -s 65536 -- "$cp_file"
expect native_checkpoint_read_cap 2 checkpoint_size_rejected cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
rm -- "$cp_file"
expect missing_checkpoint 2 checkpoint_missing_or_not_regular cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"

base
prefix=$(printf alp | /usr/bin/sha1sum); prefix=${prefix%% *}; wazuh_cp 3 "$prefix"
expect existing_inode_resume 0 existing_inode_resume cg_wazuh_cold "$cp_file" "$logical" "$file" "$dev" "$ino"
require_result '.expected_seek==3 and .backlog_bytes==8'
printf 'different\n' > "$root/new.jsonl"
expect new_inode_different_prefix 0 different_prefix cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"
require_result '.expected_seek==0'
cp -- "$file" "$root/new.jsonl"
expect identical_new_inode_ambiguous 2 cold_prefix_ambiguous cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"
require_result '.source_stable and .prefix_sha1==.stored_sha1'
printf 'changed\n' > "$file"
expect same_inode_changed_prefix 2 same_inode_prefix_changed cg_wazuh_cold "$cp_file" "$logical" "$file" "$dev" "$ino"
wazuh_cp 0 da39a3ee5e6b4b0d3255bfef95601890afd80709
expect zero_offset_valid 0 saved_zero cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"
wazuh_cp 0 0000000000000000000000000000000000000000
expect zero_offset_invalid_hash 2 zero_offset_hash_invalid cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"
wazuh_cp 999 "$prefix"
expect new_shorter_prefix 0 different_prefix cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"
require_result '.scanned_bytes==11 and .expected_seek==0 and .offset==999'
expect old_inode_truncated 2 saved_offset_beyond_source cg_wazuh_cold "$cp_file" "$logical" "$file" "$dev" "$ino"
: > "$root/new.jsonl"
expect new_empty_generation 0 different_prefix cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"
require_result '.scanned_bytes==0 and .expected_seek==0 and .source_identity.bytes==0'
wazuh_cp 0 da39a3ee5e6b4b0d3255bfef95601890afd80709
/usr/bin/truncate -s 2147483648 -- "$root/new.jsonl"
expect backlog_exact_2gib 0 saved_zero cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"
/usr/bin/truncate -s 2147483649 -- "$root/new.jsonl"
expect backlog_over_2gib 2 backlog_exceeds_2gib cg_wazuh_cold "$cp_file" "$logical" "$root/new.jsonl" "$dev" "$ino"

base
expect full_lines 0 complete_lines_within_limit cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576
printf '\000\t\303\251\r\n' > "$file"; bytes=6
expect binary_byte_count 0 complete_lines_within_limit cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576
require_result '.scanned_bytes==6 and .max_line_bytes==5 and .eof_lf'
printf no_lf > "$file"; bytes=5
expect partial_eof 2 sealed_partial_final_line cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576
/usr/bin/head -c 1048576 /dev/zero > "$file"; printf '\n' >> "$file"; bytes=1048577
expect line_exact_limit 0 complete_lines_within_limit cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576
/usr/bin/head -c 1048577 /dev/zero > "$file"; printf '\n' >> "$file"; bytes=1048578
expect line_over_limit 2 sealed_line_oversize cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576
require_result '.source_stable and .max_line_bytes==1048577'
: > "$file"; bytes=0
expect empty_sealed 0 complete_lines_within_limit cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576
/usr/bin/truncate -s 536870913 -- "$file"; bytes=536870913
expect sealed_budget_cap 2 sealed_budget_exceeded cg_sealed_lines "$file" "$dev" "$ino" "$bytes" 1048576

# Deterministic fault clones touch private fixtures only. Production source is
# unchanged; no test hook or override is added to the runtime gate.
mkdir -m 700 -- "$root/clone"
cp -- "$here/checkpoint-gates.jq" "$root/clone/checkpoint-gates.jq"
clone=$root/clone/checkpoint-gates.sh
base; vector_cp "$bytes"
/usr/bin/sed '/^cg_finish() {/a\    /usr/bin/printf "\\n" >> "$_cg_cp"' "$here/checkpoint-gates.sh" > "$clone"
_CG_SELF=$clone
expect checkpoint_mutation 2 checkpoint_changed cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
_CG_SELF=$here/checkpoint-gates.sh
base; vector_cp "$bytes"
/usr/bin/sed '/^cg_finish() {/a\    /bin/cp -- "$_cg_source" "$_cg_tmp/replacement"; /bin/mv -- "$_cg_tmp/replacement" "$_cg_source"' \
  "$here/checkpoint-gates.sh" > "$clone"
_CG_SELF=$clone
expect rename_source_replacement 2 source_changed cg_vector_eof "$root/cp" "$file" "$dev" "$ino" "$bytes"
_CG_SELF=$here/checkpoint-gates.sh
base; wazuh_cp "$bytes" "$sha"
/usr/bin/sed 's@| /usr/bin/sha1sum@| /usr/bin/false@' "$here/checkpoint-gates.sh" > "$clone"
_CG_SELF=$clone
expect hash_pipeline_failure 2 prefix_read_failed cg_wazuh_eof "$cp_file" "$logical" "$file" "$dev" "$ino" "$bytes"
_CG_SELF=$here/checkpoint-gates.sh
base; vector_cp "$bytes"
/usr/bin/sed -e '/^    # The entire worker/a\    /bin/rm -- "$_cg_source"; /usr/bin/mkfifo -- "$_cg_source"' \
  -e 's/--kill-after=2s 30s/--kill-after=1s 2s/' "$here/checkpoint-gates.sh" > "$clone"
_CG_SELF=$clone
expect open_fifo_race_timed 2 gate_timeout cg_vector_current "$root/cp" "$file" "$dev" "$ino"
_CG_SELF=$here/checkpoint-gates.sh
[[ $original == "$(/usr/bin/sha256sum -- "$here/checkpoint-gates.sh" "$here/checkpoint-gates.jq")" ]] || exit 1
/usr/bin/jq -nc --argjson passed "$passed" \
  '{suite:"native_checkpoint_gates_synthetic",passed:$passed,failed:0,
    actual_native_checkpoint_read:false,production_source_read:false,
    checkpoint_modified:false,synthetic_fixture_mutations:true,source_unchanged:true}'
