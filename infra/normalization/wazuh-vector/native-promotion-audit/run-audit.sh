#!/bin/bash
# Existing Vector only; synthetic stdin, private temp, no live configuration/logs.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
project=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project"
[[ $(/usr/local/bin/vector --version) == vector\ 0.59.0* ]]
command -v jq >/dev/null
scratch=$(mktemp -d /var/tmp/capstone-correlation-audit.XXXXXX)
trap 'rm -rf -- "$scratch"' EXIT HUP INT TERM
export CAPSTONE_AUDIT_DATA="$scratch/data"
mkdir "$CAPSTONE_AUDIT_DATA"
/usr/local/bin/vector validate --no-environment vector.toml > "$scratch/validate.log" 2>&1 || { cat "$scratch/validate.log" >&2; exit 1; }
/usr/local/bin/vector validate --no-environment reduce.toml > "$scratch/reduce-validate.log" 2>&1 || { cat "$scratch/reduce-validate.log" >&2; exit 1; }
/usr/local/bin/vector test vector.toml tests.toml > "$scratch/unit.log" 2>&1 || { cat "$scratch/unit.log" >&2; exit 1; }
emit() {
 jq -cn --arg key "$1" --arg stamp "${2:-$(date -u '+%Y-%m-%dT%H:%M:%SZ')}" --arg src "${3:-suricata}" \
 '{capstone_norm:{schema_version:"vector-1",pipeline:"vector",sensor:"groot-sec",source:$src,correlation_dedupe_key:(("0"*63)+$key),correlation_eligible:true,correlation_time_class:"fresh",protected_asset:false,quality_flags:[],event_time_kst:$stamp}}'
}
run_vector() {
 timeout --signal=TERM 15 /usr/local/bin/vector --config vector.toml > "$scratch/$1.jsonl" 2> "$scratch/$1.log"
}
{ emit 1; emit 1; emit 1; emit 1; emit 2; } | run_vector repeated
jq -se '[.[].capstone_norm.correlation_dedupe_key[-1:]] == ["1","2"]' "$scratch/repeated.jsonl" >/dev/null
{ emit 1; emit 2; emit 3; emit 1; } | run_vector evicted
jq -se '[.[].capstone_norm.correlation_dedupe_key[-1:]] == ["1","2","3","1"]' "$scratch/evicted.jsonl" >/dev/null
emit 1 | run_vector restart_first
emit 1 | run_vector restart_second
[[ $(wc -l < "$scratch/restart_first.jsonl") == 1 && $(wc -l < "$scratch/restart_second.jsonl") == 1 ]]
emit 1 '2000-01-01T00:00:00+09:00' | run_vector delayed
[[ ! -s "$scratch/delayed.jsonl" ]]
{ emit 1; emit 1 '' nftables; } | run_vector distinct_source
[[ $(wc -l < "$scratch/distinct_source.jsonl") == 2 ]]
run_reduce() {
 timeout --signal=TERM 15 /usr/local/bin/vector --config reduce.toml > "$scratch/$1.jsonl" 2> "$scratch/$1.log"
}
{ emit 1; emit 1; emit 1; emit 1; emit 2; } | run_reduce batch_repeated
jq -se 'length==1 and .[0].unique_count==2 and .[0].input_count==5' "$scratch/batch_repeated.jsonl" >/dev/null
{ emit 1; emit 2; emit 3; emit 1; } | run_reduce batch_evicted_order
jq -se 'length==1 and .[0].unique_count==3 and .[0].input_count==4' "$scratch/batch_evicted_order.jsonl" >/dev/null
{ for pass in 1 2; do for key in 1 2 3 4 5; do emit "$key"; done; done; } | run_reduce batch_boundary
jq -se 'length==2 and all(.[]; .unique_count==5 and .input_count==5) and (.[0].unique_ids|sort)==(.[1].unique_ids|sort)' "$scratch/batch_boundary.jsonl" >/dev/null
jq -cn '{vector:"0.59.0",unit_cases:8,stream_cases:8,reduce_repeated_unique:2,reduce_a_b_c_a_unique:3,reduce_same_five_ids_twice_summaries:2,repeated_aaaa_b_outputs:2,lru_a_b_c_a_outputs:4,restart_first_outputs:1,restart_second_outputs:1,old_fresh_label_outputs:0,same_key_different_sources_outputs:2,full_unique_window_proven:false,post_gate_transport_age_rechecked:false,operating_files_changed:false,operational_promotion_authorized:false}'
