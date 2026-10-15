#!/bin/bash
# Synthetic fixtures in isolated Wazuh logtest sessions, never operational input.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
[[ $EUID == 0 && $# == 0 && $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
fixtures=$directory/../fixtures/correlation
stage=$(mktemp -d /var/tmp/capstone-canary-native.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
run_id=5f54ed9eb8c9fdd4586cfb97fd4f6cdd
stamp=$(date '+%Y-%m-%dT%H:%M:%S.000000+09:00')
for scenario in canary-repeat canary-cross canary-repeat-duplicate canary-historical; do
 key=$(printf '%s:%s' "$run_id" "$scenario" | sha256sum | cut -d ' ' -f1)
 jq -c --arg rid "$run_id" --arg stamp "$stamp" --arg key "$key" --arg scenario "$scenario" '
   .capstone_validation.run_id=$rid | .capstone_validation.scenario=$scenario |
   .capstone_norm.correlation_key=$key | .capstone_norm.observed_at_kst=$stamp |
   if .capstone_norm.correlation_time_class=="fresh" then .capstone_norm.event_time_kst=$stamp else . end
 ' "$fixtures/$scenario.jsonl" > "$stage/$scenario.jsonl"
done
cat "$stage/canary-repeat.jsonl" "$stage/canary-cross.jsonl" "$stage/canary-repeat-duplicate.jsonl" "$stage/canary-historical.jsonl" > "$stage/combined.jsonl"
cat "$stage/canary-cross.jsonl" "$stage/canary-repeat.jsonl" "$stage/canary-repeat-duplicate.jsonl" "$stage/canary-historical.jsonl" > "$stage/cross_first.jsonl"
cat "$stage/canary-repeat-duplicate.jsonl" "$stage/canary-repeat.jsonl" "$stage/canary-cross.jsonl" "$stage/canary-historical.jsonl" > "$stage/duplicate_first.jsonl"
tac "$stage/canary-cross.jsonl" > "$stage/reversed_cross.jsonl"
manager=$(/usr/local/bin/docker inspect --format '{{.Id}}' single-node-wazuh.manager-1)
rules=/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules
before=$(sha256sum "$rules/local_rules.xml" "$rules/capstone_vector_rules.xml")
: > "$stage/results.jsonl"
for profile in combined canary-repeat canary-cross canary-repeat-duplicate canary-historical reversed_cross cross_first duplicate_first; do
 timeout --kill-after=2s 20s /usr/local/bin/docker exec -i "$manager" /var/ossec/bin/wazuh-logtest \
  -l '(groot-sec) any->/var/log/capstone-vector/canary/normalized.jsonl' \
  < "$stage/$profile.jsonl" > "$stage/logtest" 2>&1
 ! grep -Eq '(ERROR|CRITICAL):' "$stage/logtest"
 sed -n "s/^[[:space:]]*id: '\([0-9][0-9]*\)'.*/\1/p" "$stage/logtest" > "$stage/ids"
 rows=$(wc -l < "$stage/$profile.jsonl")
 predecode=$(grep -c 'Phase 1: Completed pre-decoding' "$stage/logtest")
 [[ $rows == "$predecode" ]]
 jq -Rn --arg profile "$profile" --argjson rows "$rows" \
 '{profile:$profile,input_rows:$rows,phase1_rows:$rows,rule_ids:[inputs|tonumber]}' "$stage/ids" >> "$stage/results.jsonl"
done
[[ $(sha256sum "$rules/local_rules.xml" "$rules/capstone_vector_rules.xml") == "$before" ]]
[[ $(/usr/local/bin/docker inspect --format '{{.Id}}' single-node-wazuh.manager-1) == "$manager" ]]
jq -sc --arg at "$(date '+%Y-%m-%dT%H:%M:%S%:z')" \
 '{checked_at_kst:$at,kind:"synthetic_canary_native_sequence_audit",profiles:.,
 manager_container_unchanged:true,rule_files_unchanged:true,operational_input_written:false,
 indexer_write:false,raw_or_cursor_exported:false}' "$stage/results.jsonl"
