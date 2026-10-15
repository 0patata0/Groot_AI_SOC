#!/bin/bash
# Read-only verification of one already-recorded synthetic run. Never writes input.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
[[ $EUID == 0 && $# -le 1 && $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 64
docker=/usr/local/bin/docker
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
[[ -f $directory/canary-validation.jq && ! -L $directory/canary-validation.jq ]] || exit 77
run_id=${1:-1507d4e26aa74ca590aae9ea9c4f187d}
[[ $run_id =~ ^[a-f0-9]{32}$ ]] || exit 64
repeat_key=$(printf '%s:canary-repeat' "$run_id" | sha256sum | cut -d ' ' -f1)
cross_key=$(printf '%s:canary-cross' "$run_id" | sha256sum | cut -d ' ' -f1)
stage=$(mktemp -d /var/tmp/capstone-history-retained-canary.XXXXXX)
step=preflight
cleanup() {
    status=$?
    trap - EXIT
    if (( status != 0 )); then jq -cn --arg phase "$step" '{status:"not_verified",phase:$phase,operational_input_written:false,indexer_write:false}'; fi
    rm -rf -- "$stage"
    exit "$status"
}
trap cleanup EXIT
manager=$($docker inspect --format '{{.Id}}' single-node-wazuh.manager-1)
indexer=$($docker inspect --format '{{.Id}}' single-node-wazuh.indexer-1)
[[ $manager =~ ^[a-f0-9]{64}$ && $indexer =~ ^[a-f0-9]{64}$ ]]
[[ $($docker inspect --format '{{.State.Running}}' "$manager") == true && $($docker inspect --format '{{.State.Running}}' "$indexer") == true ]]
rules=/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules
before=$(sha256sum "$rules/local_rules.xml" "$rules/capstone_vector_rules.xml")
$docker exec "$manager" /var/ossec/bin/wazuh-logtest -h > "$stage/help" 2>&1 || true
grep -q -- '-l' "$stage/help"
grep -q -- '-U' "$stage/help"
step=indexer_search
jq -cn --arg rid "$run_id" '{size:20,timeout:"10s",track_total_hits:true,
 _source:["timestamp","rule.id","rule.level","agent.id","location","data.capstone_validation","data.capstone_norm.event_id","data.capstone_norm.correlation_dedupe_key",
          "data.capstone_norm.correlation_key","data.capstone_norm.source","data.capstone_norm.sensor",
          "data.capstone_norm.schema_version","data.capstone_norm.pipeline"],
 query:{bool:{filter:[{term:{"data.capstone_validation.run_id":$rid}}]}}}' > "$stage/query.json"
# Existing mounted CA/admin client identity. Hostname verification stays enabled.
timeout --kill-after=2s 20s "$docker" exec -i "$indexer" curl --disable --silent --show-error --fail \
 --max-time 15 --max-filesize 1048576 \
 --cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
 --cert /usr/share/wazuh-indexer/config/certs/admin.pem \
 --key /usr/share/wazuh-indexer/config/certs/admin-key.pem \
 -H 'Content-Type: application/json' -X POST --data-binary @- \
 'https://wazuh.indexer:9200/wazuh-alerts-*/_search?allow_partial_search_results=false' \
 < "$stage/query.json" > "$stage/indexer.json" 2> "$stage/error"
jq -e -L "$directory" --arg rid "$run_id" --arg repeat_key "$repeat_key" --arg cross_key "$cross_key" '
 include "canary-validation"; canary_indexer($rid; $repeat_key; $cross_key)
' "$stage/indexer.json" > "$stage/indexer-tuples.json" 2> "$stage/error"
step=manager_retained_tail
# Bounded current-file tail can prove matching evidence remains, not lifetime absence.
# Whole output stays on B and is projected before any stdout is emitted.
(timeout --kill-after=2s 15s "$docker" exec "$manager" tail -n 10000 /var/ossec/logs/alerts/alerts.json \
 | head -c 16777217 > "$stage/manager-tail.jsonl") 2> "$stage/error"
(( $(stat -c %s "$stage/manager-tail.jsonl") <= 16777216 ))
jq -sc -L "$directory" --arg rid "$run_id" --arg repeat_key "$repeat_key" --arg cross_key "$cross_key" '
 include "canary-validation"; canary_manager($rid; $repeat_key; $cross_key)
' "$stage/manager-tail.jsonl" > "$stage/manager.json" 2> "$stage/error"
step=manager_indexer_tuple_match
jq -en -L "$directory" --slurpfile m "$stage/manager.json" --slurpfile i "$stage/indexer-tuples.json" '
 include "canary-validation"; canary_pair($m[0]; $i[0])
' >/dev/null 2> "$stage/error"
step=postcheck
[[ $($docker inspect --format '{{.Id}}' single-node-wazuh.manager-1) == "$manager" &&
   $($docker inspect --format '{{.Id}}' single-node-wazuh.indexer-1) == "$indexer" ]]
[[ $(sha256sum "$rules/local_rules.xml" "$rules/capstone_vector_rules.xml") == "$before" ]]
jq -cn --arg at "$(date '+%Y-%m-%dT%H:%M:%S%:z')" --arg rid "$run_id" \
 --slurpfile m "$stage/manager.json" --slurpfile i "$stage/indexer.json" '
 {checked_at_kst:$at,kind:"selected_canary_evidence_readonly",run_id:$rid,
 expected_synthetic_rows_from_writer_contract:13,manager_retained_tail_matches:($m[0]|length),
 manager_search_scope:"current alerts.json last 10000 rows bounded 16MiB",
 indexer_documents:$i[0].hits.total.value,indexer_shards:$i[0]._shards,
 exact_total_relation:$i[0].hits.total.relation,indexer_timed_out:$i[0].timed_out,
 exact_event_ids_match:true,exact_canonical_tuples_match:true,
 event_identity_contract:"rule-scenario-input-membership-v2",
 observed_event_ids:[$m[0][]|{rule_id,event_id,scenario,source}],expected_rule_ids:["100293","100294"],levels:[3],
 strict_ca_and_hostname_validation:true,mounted_existing_client_identity:true,
 manager_and_indexer_container_ids_unchanged:true,rule_files_unchanged:true,
 logtest_location_and_single_rule_assertion_supported:true,
 operational_input_written_by_verifier:false,indexer_write:false,new_probe_generated_by_verifier:false,
 new_delivery_requires_separate_writer_evidence:true,raw_or_cursor_exported:false}'
