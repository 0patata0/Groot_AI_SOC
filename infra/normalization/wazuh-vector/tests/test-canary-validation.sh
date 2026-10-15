#!/bin/bash
# Synthetic JSON only; never connects to Wazuh or writes an operational input.
set -euo pipefail
umask 077
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
lib=$project/history-replay-b
work=$(mktemp -d "${TMPDIR:-/tmp}/capstone-canary-validation.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
rid=0123456789abcdef0123456789abcdef
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
repeat_key=$(printf '%s:canary-repeat' "$rid" | sha | cut -d ' ' -f1)
cross_key=$(printf '%s:canary-cross' "$rid" | sha | cut -d ' ' -f1)
passed=0
jq -n --arg rid "$rid" --arg rk "$repeat_key" --arg ck "$cross_key" \
 --slurpfile r "$project/fixtures/correlation/canary-repeat.jsonl" \
 --slurpfile c "$project/fixtures/correlation/canary-cross.jsonl" '
 def record($row; $rule; $scenario; $key):
   $row | .capstone_validation.run_id=$rid | .capstone_validation.scenario=$scenario |
   .capstone_norm.correlation_key=$key |
   {rule:{id:$rule,level:3},agent:{id:"001"},
    location:"/var/log/capstone-vector/canary/normalized.jsonl",data:.};
 [record($r[4];"100293";"canary-repeat";$rk),
  record($c[1];"100294";"canary-cross";$ck)]' > "$work/manager.json"
jq '{timed_out:false,_shards:{total:57,successful:57,skipped:0,failed:0},
 hits:{total:{value:2,relation:"eq"},hits:map({_source:.})}}' \
 "$work/manager.json" > "$work/indexer.json"
validate() {
    jq -e -L "$lib" --arg rid "$rid" --arg rk "$repeat_key" --arg ck "$cross_key" \
      'include "canary-validation"; canary_indexer($rid;$rk;$ck)' "$1" > "$work/tuples.json" 2> "$work/error"
}
ok() { if ! validate "$1"; then printf 'FAIL %s\n' "$2" >&2; exit 1; fi; passed=$((passed+1)); }
bad() { if validate "$1"; then printf 'FAIL %s\n' "$2" >&2; exit 1; fi; passed=$((passed+1)); }
reject_expr() { jq "$2" "$work/indexer.json" > "$work/candidate.json"; bad "$work/candidate.json" "$1"; }
for n in 1 2 3 4 5; do
    jq --arg id "$(printf '%063d%s' 0 "$n")" \
      '.hits.hits[0]._source.data.capstone_norm |= (.event_id=$id | .correlation_dedupe_key=$id)' \
      "$work/indexer.json" > "$work/candidate.json"
    ok "$work/candidate.json" "repeat input ID $n is accepted"
done
jq '.hits.hits |= reverse' "$work/indexer.json" > "$work/candidate.json"
ok "$work/candidate.json" 'response order does not matter'
reject_expr missing_cross '.hits.total.value=1 | .hits.hits=[.hits.hits[0]]'
reject_expr duplicate_extra '.hits.total.value=3 | .hits.hits += [.hits.hits[0]]'
reject_expr wrong_rule '.hits.hits[1]._source.rule.id="100293"'
reject_expr repeat_foreign_id '.hits.hits[0]._source.data.capstone_norm |= (.event_id=("0"*63+"6") | .correlation_dedupe_key=.event_id)'
reject_expr cross_wrong_id '.hits.hits[1]._source.data.capstone_norm |= (.event_id=("0"*63+"5") | .correlation_dedupe_key=.event_id)'
reject_expr swapped_scenarios '.hits.hits[0]._source.data.capstone_validation.scenario="canary-cross" | .hits.hits[1]._source.data.capstone_validation.scenario="canary-repeat"'
reject_expr swapped_sources '.hits.hits[0]._source.data.capstone_norm.source="nftables" | .hits.hits[1]._source.data.capstone_norm.source="suricata"'
reject_expr wrong_key '.hits.hits[0]._source.data.capstone_norm.correlation_key=("f"*64)'
reject_expr wrong_dedupe '.hits.hits[0]._source.data.capstone_norm.correlation_dedupe_key=("f"*64)'
reject_expr wrong_run '.hits.hits[0]._source.data.capstone_validation.run_id=("f"*32)'
reject_expr missing_scenario 'del(.hits.hits[0]._source.data.capstone_validation.scenario)'
reject_expr wrong_agent '.hits.hits[0]._source.agent.id="000"'
reject_expr wrong_location '.hits.hits[0]._source.location="/var/log/capstone-vector/ready/normalized.jsonl"'
reject_expr wrong_kind '.hits.hits[0]._source.data.capstone_validation.kind="other"'
reject_expr wrong_level '.hits.hits[0]._source.rule.level=5'
reject_expr wrong_sensor '.hits.hits[0]._source.data.capstone_norm.sensor="groot-sec"'
reject_expr wrong_schema '.hits.hits[0]._source.data.capstone_norm.schema_version="other"'
reject_expr wrong_pipeline '.hits.hits[0]._source.data.capstone_norm.pipeline="other"'
reject_expr bad_event_type '.hits.hits[0]._source.data.capstone_norm.event_id=[]'
reject_expr no_norm 'del(.hits.hits[0]._source.data.capstone_norm)'
reject_expr timeout '.timed_out=true'
reject_expr early_termination '.terminated_early=true'
reject_expr partial_shards '._shards.successful=56 | ._shards.failed=1'
reject_expr missing_shard '._shards.successful=56'
reject_expr zero_shards '._shards.total=0 | ._shards.successful=0'
reject_expr invalid_shard_type '._shards.total="57"'
reject_expr lower_bound_total '.hits.total.relation="gte"'
reject_expr truncated_hits '.hits.hits=[.hits.hits[0]]'
reject_expr total_mismatch '.hits.total.value=3'
reject_expr numeric_rule_id '.hits.hits[0]._source.rule.id=100293'

jq -e -L "$lib" --arg rid "$rid" --arg rk "$repeat_key" --arg ck "$cross_key" \
 'include "canary-validation"; canary_manager($rid;$rk;$ck)' "$work/manager.json" > "$work/manager-tuples.json"
passed=$((passed+1))
ok "$work/indexer.json" 'baseline indexer tuples'
jq -en -L "$lib" --slurpfile m "$work/manager-tuples.json" --slurpfile i "$work/tuples.json" \
 'include "canary-validation"; canary_pair($m[0];$i[0])' >/dev/null
passed=$((passed+1))
jq '.[0].data.capstone_norm |= (.event_id=("0"*63+"1") | .correlation_dedupe_key=.event_id)' \
 "$work/manager.json" > "$work/manager-alternate.json"
jq -e -L "$lib" --arg rid "$rid" --arg rk "$repeat_key" --arg ck "$cross_key" \
 'include "canary-validation"; canary_manager($rid;$rk;$ck)' "$work/manager-alternate.json" > "$work/alternate-tuples.json"
if jq -en -L "$lib" --slurpfile m "$work/alternate-tuples.json" --slurpfile i "$work/tuples.json" \
 'include "canary-validation"; canary_pair($m[0];$i[0])' >/dev/null 2> "$work/error"; then
    printf 'FAIL independently valid but different manager/indexer tuples\n' >&2; exit 1
fi
passed=$((passed+1))
jq '. + [.[0] | .data.capstone_validation.run_id=("f"*32)]' "$work/manager.json" > "$work/manager-other-run.json"
jq -e -L "$lib" --arg rid "$rid" --arg rk "$repeat_key" --arg ck "$cross_key" \
 'include "canary-validation"; canary_manager($rid;$rk;$ck)' "$work/manager-other-run.json" > "$work/other-tuples.json"
cmp -s "$work/other-tuples.json" "$work/manager-tuples.json"
passed=$((passed+1))
jq '. + [.[0]]' "$work/manager.json" > "$work/manager-duplicate.json"
if jq -e -L "$lib" --arg rid "$rid" --arg rk "$repeat_key" --arg ck "$cross_key" \
 'include "canary-validation"; canary_manager($rid;$rk;$ck)' "$work/manager-duplicate.json" >/dev/null 2> "$work/error"; then
    printf 'FAIL duplicate manager row\n' >&2; exit 1
fi
passed=$((passed+1))
jq -cn --arg version "$(jq --version)" --argjson passed "$passed" \
 '{kind:"synthetic_canary_verifier_regression",passed:$passed,jq_version:$version,
   server_connection:false,operational_input_write:false,indexer_write:false}'
