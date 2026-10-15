#!/bin/bash
# Fixed, root-only, read-preserved-data experiment. stdout contains aggregate metadata only.
set -euo pipefail
umask 077
PATH=/usr/local/bin:/usr/bin:/bin
export PATH LC_ALL=C
[[ $# == 0 && $(id -u) == 0 && $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 64
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
[[ $(stat -c '%u:%a' "$source_dir") == 0:700 && ! -L $source_dir ]]
[[ $(sha256sum "$source_dir/validate-records.jq" | cut -d' ' -f1) == 2470fab15dfde40540d60a3e47f4de8a6f5520f46acb231d1067895c770ffaa9 ]]
base=/var/lib/capstone-vector-history
first=67f858b9c78551e3ca95cd3bc9948cf9ded19834d1e0d9d9f78b4bb4c95fd33a
child=bf58e25ad123f6d84c54b66ced22e186750c2328f67d59439b1bccb4c47fae68
boot=b807aba1a92547ffb0c429771628b521
until=1791926099107280
first_payload=4f3fd39e4bd0e63eca07e00e5dac4515f59b473a401c97e84ed206d568f1128d
child_payload=5e96e0e71bb8c67bf5e751c5d71fca467d26058440229503fe45c8036e70fe58
first_manifest=067728c72a202e44c7244a29b3c403a6ca7533587d4ad18d1d11984f8d531ec3
child_manifest=18c79f4f8473da11bd7edf5e6f472e22aeb4d43c5fb2dcc5e08117ea87f4e697
check_sources() {
  local id file expected
  [[ -d $base && ! -L $base && $(stat -c '%u:%a' "$base") == 0:700 ]]
  for id in "$first" "$child"; do
    [[ -d $base/batch-$id && ! -L $base/batch-$id && $(stat -c '%u:%a' "$base/batch-$id") == 0:700 ]]
    for file in kernel.jsonl manifest.json; do
      [[ -f $base/batch-$id/$file && ! -L $base/batch-$id/$file && $(stat -c '%u:%a:%h' "$base/batch-$id/$file") == 0:400:1 ]]
    done
  done
  [[ $(sha256sum "$base/batch-$first/kernel.jsonl" | cut -d' ' -f1) == "$first_payload" ]]
  [[ $(sha256sum "$base/batch-$child/kernel.jsonl" | cut -d' ' -f1) == "$child_payload" ]]
  [[ $(sha256sum "$base/batch-$first/manifest.json" | cut -d' ' -f1) == "$first_manifest" ]]
  [[ $(sha256sum "$base/batch-$child/manifest.json" | cut -d' ' -f1) == "$child_manifest" ]]
}
check_sources
[[ $(/usr/local/bin/vector --version) == "vector 0.59.0 "* ]]
[[ $(sha256sum /etc/capstone-vector/transforms/nftables.vrl | cut -d' ' -f1) == 8450cefe8d884522b6e817acd7fb963efccfb8a0c93a023a854befdc75c715e5 ]]
[[ $(sha256sum /etc/capstone-vector/transforms/correlation.vrl | cut -d' ' -f1) == e8da4312819ca8442fb6183d40e7e1d14d8256bbcf2d6136c73e3aa69e92434d ]]
# Require the live selector to be the exact expression used by the isolated graph.
selector=$(sed -n '/^\[transforms.nft_select\]/,/^\[/p' /etc/capstone-vector/vector.toml | sed -n '/^condition = /p')
[[ $selector == "$(sed -n '/^\[transforms.nft_select\]/,/^\[/p' "$source_dir/replay.toml" | sed -n '/^condition = /p')" ]]
sensor=$(sed -n 's/^CAPSTONE_SENSOR=//p' /etc/capstone-vector/vector.env)
[[ $sensor =~ ^[A-Za-z0-9_.:-]{1,80}$ ]]
work=$(mktemp -d /var/tmp/capstone-replay-20261014/history-replay-XXXXXX)
# Retain private results for operator review; the parent removes the task staging afterwards.
trap 'rc=$?; if (( rc != 0 )); then printf "history_replay_failed exit=%s private_stage=%s\n" "$rc" "$work" >&2; fi' EXIT
for case in actual synthetic; do mkdir -m 700 "$work/$case"; done
started=$(date --iso-8601=seconds)
systemctl show capstone-vector.service wazuh-agent.service --property=Id,ActiveState,MainPID,InvocationID,NRestarts > "$work/services.before"
[[ $(grep -c '^ActiveState=active$' "$work/services.before") == 2 ]]
[[ $(systemctl show capstone-vector.service --property=MainPID --value) =~ ^[1-9][0-9]*$ ]]
collector_pid=$(pgrep -f '^/var/ossec/bin/wazuh-logcollector$')
[[ $collector_pid =~ ^[1-9][0-9]*$ && $(readlink /proc/"$collector_pid"/exe) == /var/ossec/bin/wazuh-logcollector ]]
awk '{print $1,$22}' /proc/"$collector_pid"/stat > "$work/logcollector.before"
for id in "$first" "$child"; do
  jq -Rn --arg boot "$boot" --arg until "$until" --argjson max_records 1000 -f "$source_dir/validate-records.jq" "$base/batch-$id/kernel.jsonl" > "$work/$id.summary"
  jq -e --slurpfile actual "$work/$id.summary" '.record_metadata==$actual[0] and .records==$actual[0].count' "$base/batch-$id/manifest.json" >/dev/null
done
jq -e --arg first "$first" --arg payload "$first_payload" --arg manifest "$first_manifest" '.parent=={batch_id:$first,payload_sha256:$payload,manifest_sha256:$manifest} and .source_range_exhausted==true and .continuation_boundary_verified==true and .continuation_phase=="verified"' "$base/batch-$child/manifest.json" >/dev/null
cat "$base/batch-$first/kernel.jsonl" "$base/batch-$child/kernel.jsonl" > "$work/actual/input.jsonl"
jq -e -s 'length==1481 and (map(.__CURSOR)|unique|length)==1481 and all(.[]; .MESSAGE|type=="string")' "$work/actual/input.jsonl" >/dev/null
jq -cn -f "$source_dir/synthetic.jq" > "$work/synthetic/input.jsonl"
for case in actual synthetic; do
  cp /etc/capstone-vector/transforms/nftables.vrl /etc/capstone-vector/transforms/correlation.vrl "$work/$case/"
  /bin/bash "$source_dir/run-isolated.sh" "$work/$case/input.jsonl" "$work/$case" "$sensor"
done
jq -e -s '
 ([.[]|select(.replay_stage=="selector")]|length)==1481 and
 all(.[]; .replay_stage=="selector" and .selected==false) and
 (map(.event_id)|unique|length)==1481 and (map(.record_id)|unique|length)==1481
' "$work/actual/result.jsonl" >/dev/null
# Independent shell SHA computation verifies both boundary IDs of both batches.
for id in "$first" "$child"; do
  for field in first_cursor last_cursor; do
    event=$(jq -cj --arg sensor "$sensor" --arg field "$field" '[$sensor,"nftables",.[$field]]' "$work/$id.summary" | sha256sum | cut -d' ' -f1)
    record=$(jq -cj --arg sensor "$sensor" --arg field "$field" '[$sensor,.[$field]]' "$work/$id.summary" | sha256sum | cut -d' ' -f1)
    jq -e -s --arg event "$event" --arg record "$record" 'any(.[]; .event_id==$event and .record_id==$record)' "$work/actual/result.jsonl" >/dev/null
  done
done
jq -e -s '
 ([.[]|select(.replay_stage=="selector")]|length)==14 and
 ([.[]|select(.replay_stage=="selector" and .selected)]|length)==12 and
 ([.[]|select(.replay_stage=="normalization_failed")]|length)==3 and
 ([.[]|select(.replay_stage=="normalized")]|length)==9 and
 ([.[]|select(.replay_stage=="mapping_failed" or .replay_stage=="correlation_failed")]|length)==0 and
 all(.[]|select(.replay_stage=="normalized"); .capstone_norm.replay==true and .capstone_norm.replay_lane=="previous-boot-analysis-v1" and .capstone_norm.correlation_eligible==false and .capstone_norm.correlation_time_class=="historical" and (.capstone_norm|has("evidence_lane")|not)) and
 ([.[]|select(.replay_stage=="normalized" and .capstone_norm.protected_asset==true)]|length)==1 and
 ([.[]|select(.replay_stage=="normalized" and .capstone_norm.quality_flags!=[])]|length)==1 and
 ([.[]|select(.replay_stage=="normalized" and .capstone_norm.action=="observed")]|length)==2 and
 ([.[]|select(.replay_stage=="normalized" and .capstone_norm.action=="would_drop")]|length)==1 and
 ([.[]|select(.replay_stage=="normalized" and .capstone_norm.action=="logged_drop")]|length)==6
' "$work/synthetic/result.jsonl" >/dev/null
check_sources
systemctl show capstone-vector.service wazuh-agent.service --property=Id,ActiveState,MainPID,InvocationID,NRestarts > "$work/services.after"
cmp -s "$work/services.before" "$work/services.after"
[[ $(grep -c '^ActiveState=active$' "$work/services.before") == 2 ]]
[[ $(pgrep -f '^/var/ossec/bin/wazuh-logcollector$') == "$collector_pid" ]]
awk '{print $1,$22}' /proc/"$collector_pid"/stat > "$work/logcollector.after"
cmp -s "$work/logcollector.before" "$work/logcollector.after"
finished=$(date --iso-8601=seconds)
input_sha=$(sha256sum "$work/actual/input.jsonl" | cut -d' ' -f1)
ids_sha=$(jq -r '.event_id' "$work/actual/result.jsonl" | sort | sha256sum | cut -d' ' -f1)
config_sha=$(sha256sum "$source_dir/replay.toml" | cut -d' ' -f1)
jq -n --arg started "$started" --arg finished "$finished" --arg work "$work" \
 --arg input_sha "$input_sha" --arg ids_sha "$ids_sha" --arg config_sha "$config_sha" \
 --arg first "$first" --arg child "$child" --arg first_payload "$first_payload" --arg child_payload "$child_payload" \
 --arg first_manifest "$first_manifest" --arg child_manifest "$child_manifest" \
 '{operation:"isolated_previous_boot_vector_classification",started_at:$started,finished_at:$finished,private_stage:$work,
 vector_version:"0.59.0",input_records:1481,input_bytes:621820,string_message_records:1481,nft_prefix_candidates:0,
 non_target_kernel_records:1481,normalization_attempts:0,normalization_failures:0,normalized_security_records:0,
 production_indexer_candidate_records:0,input_sha256:$input_sha,sorted_event_id_ledger_sha256:$ids_sha,probe_config_sha256:$config_sha,
 batches:[{batch_id:$first,payload_sha256:$first_payload,manifest_sha256:$first_manifest,records:1000},{batch_id:$child,payload_sha256:$child_payload,manifest_sha256:$child_manifest,records:481}],
 batch_record_metadata_matches_manifest:true,cursor_uniqueness_across_batches:true,child_parent_binding_matches:true,
 four_boundary_event_and_record_id_hashes_independently_verified:true,
 synthetic:{records:14,selector_candidates:12,non_target:2,normalized:9,normalization_failed:3,quality_flagged:1,protected_asset:1,historical:9,production_correlation_eligible:0},
 source_payload_and_manifest_sha_unchanged:true,live_transform_hashes_matched:true,live_selector_exactly_matched:true,
 vector_and_wazuh_service_pid_invocation_state_unchanged:true,operational_checkpoint_write:false,
 operational_input_write:false,network_sink:false,wazuh_reinjection:false,indexer_write:false,raw_or_cursor_returned_to_mac:false,
 limitations:["Actual preserved records contain no known nft alert prefix; this does not prove their raw content is universally benign.","Synthetic pipeline controls are separate from actual records and do not prove historical Wazuh/Indexer ingestion.","The string-only journal adapter is deliberately limited to the verified input field types; binary-array fields are refused.","No completeness claim about journal entries removed before the original preservation.","Operational sources continue naturally; no claim that live checkpoints remain byte-identical over time."]}' > "$work/result.json"
cat "$work/result.json"
