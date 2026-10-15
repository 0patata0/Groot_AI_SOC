#!/bin/bash
# Isolated Linux fixture: real temporary FDs/SHA1, synthetic Wazuh checkpoint.
# Only pgrep and the fixed checkpoint pathname are redirected. No production
# security source, Wazuh state, systemd service, or logger is touched.
set -euo pipefail
[[ $# == 1 && -f $1 && -d /proc/$$/fd ]] || exit 64
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
awk '/^reader_at_eof\(\) \{/ {capture=1} capture {print} capture && /^\}/ {capture=0}' "$1" > "$stage/functions.sh"
awk '/^readers_at_eof\(\) \{/ {capture=1} capture {print} capture && /^\}/ {capture=0}' "$1" >> "$stage/functions.sh"
. "$stage/functions.sh"
ready=$stage/ready.jsonl
evidence=$stage/evidence.jsonl
checkpoint=$stage/file_status.json
printf '{"fixture":"ready"}\n' > "$ready"
printf '{"fixture":"evidence"}\n' > "$evidence"
ready_size=$(stat -c %s "$ready"); evidence_size=$(stat -c %s "$evidence")
ready_hash=$(sha1sum "$ready"); ready_hash=${ready_hash%% *}
evidence_hash=$(sha1sum "$evidence"); evidence_hash=${evidence_hash%% *}
command jq -nc --arg r "$ready" --arg e "$evidence" --arg rh "$ready_hash" --arg eh "$evidence_hash" --argjson rs "$ready_size" --argjson es "$evidence_size" '{files:[{path:$r,offset:$rs,hash:$rh},{path:$e,offset:$es,hash:$eh}]}' > "$stage/good.json"
cp "$stage/good.json" "$checkpoint"
pgrep() { [[ $1 == -x && $2 == wazuh-logcollec ]] || return 1; printf '%s\n' "$$"; }
jq() {
    local args=("$@") last=$(($#-1))
    [[ ${args[$last]} != /var/ossec/queue/logcollector/file_status.json ]] || args[$last]=$checkpoint
    command jq "${args[@]}"
}
exec 9< "$ready" 8< "$evidence"
cat <&9 >/dev/null; cat <&8 >/dev/null
passed=0
check() {
    local name=$1 expected=$2 got=1
    if readers_at_eof; then got=0; fi
    [[ $got == "$expected" ]] || { printf 'reader_fixture_failed=%s\n' "$name"; exit 1; }
    passed=$((passed+1))
}
check both_proven 0
command jq '.files[0].offset=0' "$stage/good.json" > "$checkpoint"; check ready_logical_behind 1
command jq '.files[1].offset=0' "$stage/good.json" > "$checkpoint"; check evidence_logical_behind 1
command jq '.files[1].hash="0000000000000000000000000000000000000000"' "$stage/good.json" > "$checkpoint"; check evidence_hash_mismatch 1
command jq '.files += [.files[1]]' "$stage/good.json" > "$checkpoint"; check evidence_ambiguous_checkpoint 1
cp "$stage/good.json" "$checkpoint"
exec 8<&-; exec 8< "$evidence"; check evidence_kernel_offset_behind 1
cat <&8 >/dev/null
exec 10< "$evidence"; cat <&10 >/dev/null; check evidence_multiple_reader_fds 1
exec 10<&- 8<&-; check evidence_missing_reader_fd 1
exec 8< "$evidence"; cat <&8 >/dev/null
check both_recovered 0
command jq -nc --argjson passed "$passed" '{reader_rotation_tests_passed:$passed,failed:0,production_paths_opened:false,operational_state_changed:false}'
