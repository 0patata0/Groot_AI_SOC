#!/bin/bash
# Native helpers for an explicit child batch. Existing v1 sources/data are unchanged.
CONTINUATION_POLICY=previous-kernel-continuation-v1
continuation_refuse() {
    jq -nc --arg reason "$1" '{status:"refused",reason:$reason,raw_payload_exported:false}'
    exit 65
}
continuation_id() {
    printf '%s\n' "$CONTINUATION_POLICY" "$1" "$2" "$3" "$4" "$5" 1000 33554432 |
      sha256sum | cut -d ' ' -f1
}
continuation_safe_batch() {
    local path=$1
    history_safe_dir "$path" || continuation_refuse unsafe_batch_directory
    for file in "$path/kernel.jsonl" "$path/manifest.json"; do
        history_safe_file "$file" || continuation_refuse unsafe_batch_file
        [[ $(stat -c %a "$file") == 400 ]] || continuation_refuse unsafe_batch_mode
    done
    (( $(stat -c %s "$path/manifest.json") <= 65536 )) || continuation_refuse manifest_too_large
    (( $(stat -c %s "$path/kernel.jsonl") <= 33554432 )) || continuation_refuse payload_too_large
}
continuation_check_manifest() {
    local path=$1 id=$2 expected_sha=$3 manifest=$1/manifest.json actual_id policy
    continuation_safe_batch "$path"
    jq -e --arg id "$id" --arg sha "$expected_sha" '
      type=="object" and .status=="complete_batch" and .reason=="verified" and
      .batch_id==$id and .sha256==$sha and (.sha256|test("^[0-9a-f]{64}$")) and
      (.boot_id|type=="string" and test("^[0-9a-f]{32}$")) and
      (.until_epoch_us|type=="string" and test("^[1-9][0-9]{0,15}$")) and
      .selection.transport=="kernel" and .selection.max_records==1000 and
      .selection.max_bytes==33554432 and .selection.capture_validation_budget_ms==15000 and
      .selection.finalization_in_budget==false and
      (.records|type=="number" and floor==. and .>=1 and .<=1000) and
      (.bytes|type=="number" and floor==. and .>=1 and .<=33554432) and
      .records_verified==true and .physical_newlines==.records and
      (.source_range_exhausted|type)=="boolean" and
      .original_ack_boundary_known==false and .operational_checkpoint_changed==false and
      .reinjected==false and .remote_receipt==false and .producer_exit==0 and .consumer_exit==0 and
      (.captured_bytes_including_verification|type=="number" and .>=1 and .<=33554432) and
      .captured_bytes_including_verification>=.bytes
    ' "$manifest" >/dev/null 2>&1 || continuation_refuse parent_manifest_invalid
    policy=$(jq -r .policy "$manifest")
    if [[ $policy == previous-kernel-batch-v1 ]]; then
        jq -e '.selection.order=="oldest" and (has("parent")|not)' "$manifest" >/dev/null || continuation_refuse parent_policy_invalid
        actual_id=$(printf '%s\n' "$policy" "$(jq -r .boot_id "$manifest")" "$(jq -r .until_epoch_us "$manifest")" 1000 33554432 | sha256sum | cut -d ' ' -f1)
    elif [[ $policy == "$CONTINUATION_POLICY" ]]; then
        jq -e '.selection.order=="after_verified_parent_cursor" and
          (.parent|type)=="object" and (.parent|keys)==["batch_id","manifest_sha256","payload_sha256"] and
          all(.parent[]; type=="string" and test("^[0-9a-f]{64}$")) and
          .continuation_boundary_verified==true and .continuation_phase=="verified"' "$manifest" >/dev/null || continuation_refuse parent_chain_invalid
        actual_id=$(continuation_id "$(jq -r .parent.batch_id "$manifest")" "$(jq -r .parent.payload_sha256 "$manifest")" \
          "$(jq -r .parent.manifest_sha256 "$manifest")" "$(jq -r .boot_id "$manifest")" "$(jq -r .until_epoch_us "$manifest")")
    else
        continuation_refuse unknown_parent_policy
    fi
    [[ $actual_id == "$id" ]] || continuation_refuse parent_id_mismatch
    [[ $(sha256sum "$path/kernel.jsonl" | cut -d ' ' -f1) == "$expected_sha" ]] || continuation_refuse parent_payload_mismatch
    [[ $(stat -c %s "$path/kernel.jsonl") == "$(jq -r .bytes "$manifest")" ]] || continuation_refuse parent_size_mismatch
}
continuation_manifest() {
    local status=$1 reason=$2 summary=${3:-/dev/null}
    history_manifest "$status" "$reason" "$summary"
    jq --arg parent "$CONTINUATION_PARENT" --arg payload_sha "$CONTINUATION_PARENT_SHA" \
      --arg manifest_sha "$CONTINUATION_PARENT_MANIFEST_SHA" --arg phase "$CONTINUATION_PHASE" \
      --argjson verified "$CONTINUATION_VERIFIED" '
      .selection.order="after_verified_parent_cursor" |
      .parent={batch_id:$parent,payload_sha256:$payload_sha,manifest_sha256:$manifest_sha} |
      .continuation_boundary_verified=$verified | .continuation_phase=$phase
    ' "$HISTORY_ATTEMPT/manifest.json" > "$HISTORY_ATTEMPT/manifest.child.tmp"
    mv -T -- "$HISTORY_ATTEMPT/manifest.child.tmp" "$HISTORY_ATTEMPT/manifest.json"
}
