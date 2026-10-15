#!/bin/bash
# Isolated synthetic real-metric smoke test; candidate vector.toml is read only.
set -euo pipefail
umask 077
[[ $(uname -s) == Linux && $# == 1 && -f $1 ]] || exit 64
candidate=$1
stage=$(mktemp -d /var/tmp/capstone-vector-telemetry.XXXXXX)
pid=
cleanup() {
    if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
    rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM
mkdir "$stage/data"
printf 'CAPSTONE_SYNTHETIC_RAW_PAYLOAD_%.0s' {1..12} > "$stage/input.log"
printf '\nnormal\n' >> "$stage/input.log"
python3 -B - "$candidate" "$stage" <<'PY'
import json, sys, tomllib
from pathlib import Path
config=tomllib.loads(Path(sys.argv[1]).read_text())
stage=Path(sys.argv[2])
metrics=config['sources']['collection_metrics'].copy()
metrics['scrape_interval_secs']=1
health=config['sinks']['collection_health_file'].copy()
health['path']=str(stage/'health.jsonl')
selected={key:value for key,value in config['transforms'].items() if key.startswith('collection_')}
selected['test_lengths']={'type':'remap','inputs':['suricata_eve'],'source':'. = {"length": length(string!(.message))}'}
test={
 'data_dir':str(stage/'data'), 'timezone':'Asia/Seoul',
 'sources':{
  'collection_metrics':metrics,
  'suricata_eve':{'type':'file','include':[str(stage/'input.log')],'read_from':'beginning','max_line_bytes':128,'fingerprint':{'strategy':'device_and_inode'}}},
 'transforms':selected,
 'sinks':{'collection_health_file':health,'normalized':{'type':'file','inputs':['test_lengths'],'path':str(stage/'lengths.jsonl'),'encoding':{'codec':'json'},'buffer':{'type':'memory','max_events':64}}}}
(stage/'probe.json').write_text(json.dumps(test))
PY
export INVOCATION_ID=dddddddddddddddddddddddddddddddd
export VECTOR_LOG=info,vector::internal_events::file::source=off
/usr/local/bin/vector validate --no-environment "$stage/probe.json" > "$stage/validate.out" 2>&1
timeout --signal=TERM --kill-after=5s 40s nice -n 10 /usr/local/bin/vector --config "$stage/probe.json" --log-format json > "$stage/stdout.log" 2> "$stage/stderr.log" &
pid=$!
for _ in {1..60}; do
    if [[ -s $stage/health.jsonl ]] && jq -es 'any(.[]; .capstone_collection_health.metric=="uptime_seconds") and any(.[]; .capstone_collection_health.metric=="component_errors_total")' "$stage/health.jsonl" >/dev/null 2>&1; then break; fi
    kill -0 "$pid" 2>/dev/null || exit 1
    sleep 0.2
done
sleep 1
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=
marker_present=false
if grep -q CAPSTONE_SYNTHETIC_RAW_PAYLOAD_ "$stage/stdout.log" "$stage/stderr.log"; then marker_present=true; fi
summary=$(jq -sc --arg invocation "$INVOCATION_ID" --argjson raw "$marker_present" '
map(.capstone_collection_health) as $r |
{test:"real_internal_metrics",metadata_records:($r|length),heartbeat_records:([$r[]|select(.metric=="uptime_seconds")]|length),source_error_max:([$r[]|select(.metric=="component_errors_total")|.value]|max // 0),buffer_gauge_records:([$r[]|select(.metric=="buffer_size_bytes" or .metric=="buffer_size_events")]|length),invocation_binding:all($r[];.invocation_id==$invocation),numeric_epoch:all($r[];(.observed_unix|type)=="number"),kst:all($r[];.observed_at_kst|endswith("+09:00")),private_field_absent:all($r[];has("raw")|not),raw_payload_marker_in_stdout_stderr:$raw,operational_configuration_changed:false}' "$stage/health.jsonl")
printf '%s\n' "$summary"
printf '%s' "$summary" | jq -e '.heartbeat_records>0 and .source_error_max==1 and .buffer_gauge_records>0 and .invocation_binding and .numeric_epoch and .kst and .private_field_absent and (.raw_payload_marker_in_stdout_stderr|not)' >/dev/null
