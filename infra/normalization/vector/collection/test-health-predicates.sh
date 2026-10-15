#!/bin/bash
# Pure jq fixtures: no logger, systemctl, security inputs, or persistent state.
set -euo pipefail
[[ $# == 1 && -f $1 ]] || exit 64
predicate=$1
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
epoch=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
base=$(jq -nc --arg epoch "$epoch" '{capstone_collection_health:{schema_version:"1",metric:"uptime_seconds",component:"vector",value:500,vector_pid:"123",invocation_id:$epoch,labels:{},observed_unix:1000,observed_at_kst:"2026-10-14T04:00:00+09:00"}}')
passed=0
check() {
    local name=$1 expected=$2 started=${3:-500} result
    result=$(jq -Rsc --arg pid 123 --arg invocation "$epoch" --argjson now 1000 --argjson started "$started" -f "$predicate" "$stage/input")
    [[ $result == "$expected" ]] || { printf 'fixture_failed=%s\n' "$name"; exit 1; }
    passed=$((passed+1))
}
printf '\n%s\n' "$base" > "$stage/input"; check healthy '[]'
printf '\n' > "$stage/input"; check missing '["collection_telemetry_missing"]'
check startup_grace '[]' 900
printf '\n%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health.observed_unix=800')" > "$stage/input"; check stale '["collection_telemetry_stale"]'
printf '\n%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health.invocation_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"')" > "$stage/input"; check wrong_epoch '["collection_telemetry_missing"]'
printf '\n%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health.vector_pid="124"')" > "$stage/input"; check wrong_pid '["collection_telemetry_missing"]'
printf '\n%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health.observed_unix=1010')" > "$stage/input"; check future '["collection_telemetry_invalid"]'
printf '\n%s\nnot-json\n' "$base" > "$stage/input"; check malformed '["collection_telemetry_invalid"]'
printf '\n%s\n' "$base" > "$stage/input"
printf '%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="component_errors_total" | .component="waf_audit" | .value=1)')" >> "$stage/input"; check errors '["collection_error_seen"]'
printf '\n%s\n' "$base" > "$stage/input"
printf '%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="files_unwatched_with_unknown_bytes_total" | .component="suricata_eve" | .value=1)')" >> "$stage/input"; check loss_signal '["collection_loss_signal_seen"]'
printf '\n%s\n' "$base" > "$stage/input"
printf '%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="buffer_size_bytes" | .component="normalized" | .value=201326616)')" >> "$stage/input"; check buffer_threshold '["collection_buffer_pressure"]'
printf '\n%s\n' "$base" > "$stage/input"
printf '%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="component_errors_total" | .component="waf_audit" | .value=1 | .invocation_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")')" >> "$stage/input"; check ignore_old_epoch_error '[]'
printf 'truncated-prefix\n%s\n{"partial":' "$base" > "$stage/input"; check edge_fragments '[]'
unread_false=$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="files_unwatched_bytes_unread_total" | .component="suricata_eve" | .value=42 | .labels={reached_eof:"false"})')
unread_true=$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="files_unwatched_bytes_unread_total" | .component="suricata_eve" | .value=0 | .labels={reached_eof:"true"})')
printf '\n%s\n%s\n%s\n' "$base" "$unread_false" "$unread_true" > "$stage/input"; check eof_series_false_first '["collection_loss_signal_seen"]'
printf '\n%s\n%s\n%s\n' "$base" "$unread_true" "$unread_false" > "$stage/input"; check eof_series_true_first '["collection_loss_signal_seen"]'
printf '\n%s\n%s\n' "$base" "$(printf '%s' "$unread_false" | jq -c '.capstone_collection_health.labels.reached_eof="not-bool"')" > "$stage/input"; check invalid_eof_label '["collection_telemetry_invalid"]'
printf '\n%s\n' "$base" > "$stage/input"
printf '%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="buffer_size_bytes" | .component="evidence" | .value=201326616)')" >> "$stage/input"; check evidence_buffer_threshold '["collection_buffer_pressure"]'
printf '\n%s\n' "$base" > "$stage/input"
printf '%s\n' "$(printf '%s' "$base" | jq -c '.capstone_collection_health |= (.metric="component_errors_total" | .component="evidence" | .value=1)')" >> "$stage/input"; check evidence_sink_error '["collection_error_seen"]'
jq -nc --argjson passed "$passed" '{health_predicate_tests_passed:$passed,failed:0,operational_state_changed:false}'
