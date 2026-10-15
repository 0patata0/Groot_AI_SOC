#!/bin/bash
# One isolated Vector process, synthetic input only; never touches operational paths.
set -euo pipefail
umask 077
PATH=/usr/local/bin:/usr/bin:/bin
export PATH
[[ $(uname -s) == Linux && $# -le 1 ]] || exit 64
VECTOR_LOG=info
if [[ ${1:-} == --source-log-filter ]]; then
    VECTOR_LOG=info,vector::internal_events::file::source=off
elif [[ $# != 0 ]]; then
    exit 64
fi
export VECTOR_LOG
for tool in vector jq timeout nice head tr stat sha256sum awk; do command -v "$tool" >/dev/null; done
stage=$(mktemp -d /var/tmp/capstone-vector-file-boundary.XXXXXX)
pid=
cleanup() {
    if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM
mkdir "$stage/data"
input=$stage/input.log
emit_line() { head -c "$1" /dev/zero | tr '\000' "$2"; printf '\n'; }
emit_line 1048575 A > "$input"
emit_line 1048576 B >> "$input"
emit_line 1048577 C >> "$input"
printf 'D-following-normal\n' >> "$input"
cat > "$stage/probe.toml" <<EOF
data_dir = "$stage/data"
[acknowledgements]
enabled = true
[sources.boundary_file]
type = "file"
include = ["$input"]
read_from = "beginning"
max_line_bytes = 1048576
max_read_bytes = 262144
fingerprint.strategy = "device_and_inode"
[sources.probe_metrics]
type = "internal_metrics"
scrape_interval_secs = 1
[transforms.length_only]
type = "remap"
inputs = ["boundary_file"]
source = '. = {"length": length(string!(.message)), "marker": slice!(string!(.message), 0, 1)}'
[transforms.metrics_as_logs]
type = "metric_to_log"
inputs = ["probe_metrics"]
[sinks.lengths]
type = "file"
inputs = ["length_only"]
path = "$stage/lengths.jsonl"
encoding.codec = "json"
[sinks.metrics]
type = "file"
inputs = ["metrics_as_logs"]
path = "$stage/metrics.jsonl"
encoding.codec = "json"
EOF
vector validate --no-environment "$stage/probe.toml" > "$stage/validate.out" 2>&1
timeout --signal=TERM --kill-after=5s 80s nice -n 10 vector --config "$stage/probe.toml" --log-format json > "$stage/stdout.log" 2> "$stage/stderr.log" &
pid=$!
wait_records() {
    local target=$1 count=0
    for _ in {1..100}; do
        [[ ! -f $stage/lengths.jsonl ]] || count=$(wc -l < "$stage/lengths.jsonl")
        (( count >= target )) && return 0
        kill -0 "$pid" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}
error_count() {
    [[ -f $stage/metrics.jsonl ]] || { printf '0\n'; return; }
    jq -s '[.[] | select(.name=="component_errors_total" and .tags.component_id=="boundary_file" and .tags.error_code=="reading_line_from_file") | .counter.value] | max // 0' "$stage/metrics.jsonl"
}
wait_records 3
sleep 2
first_error_count=$(error_count)
emit_line 1048577 E >> "$input"
sleep 3
eof_error_count=$(error_count)
printf 'F-after-oversize-at-eof\n' >> "$input"
wait_records 4
sleep 2
final_error_count=$(error_count)
vector_child=$(pgrep -P "$pid" 2>/dev/null | head -n 1 || true)
peak_kib=0
if [[ -n $vector_child && -r /proc/$vector_child/status ]]; then
    peak_kib=$(awk '$1=="VmHWM:" {print $2}' /proc/"$vector_child"/status)
fi
input_bytes=$(stat -c %s "$input")
[[ $input_bytes -le 33554432 ]]
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=
raw_in_error=false
if raw_field_found=$(awk '/truncated_bytes/ {found=1} END {print found+0}' "$stage/stdout.log" "$stage/stderr.log"); [[ $raw_field_found == 1 ]]; then raw_in_error=true; fi
error_targets=$(jq -sc '[.[] | select(tostring|contains("truncated_bytes")) | .target | select(type=="string") | select(test("^[A-Za-z0-9_:]+$"))] | unique' "$stage/stdout.log")
jq -nc --slurpfile lengths "$stage/lengths.jsonl" \
    --argjson first "$first_error_count" --argjson eof "$eof_error_count" --argjson final "$final_error_count" \
    --argjson bytes "$input_bytes" --argjson peak "${peak_kib:-0}" --argjson raw "$raw_in_error" \
    --arg filter "$VECTOR_LOG" --argjson targets "$error_targets" \
    '{test:"vector_file_boundary",vector_version:"0.59.0",synthetic_only:true,input_bytes:$bytes,emitted_lengths:$lengths,error_count_after_oversize_followed_by_normal:$first,error_count_after_oversize_at_eof:$eof,error_count_after_later_normal:$final,error_log_contains_truncated_bytes:$raw,error_trace_targets:$targets,vector_log_filter:$filter,observed_peak_rss_kib:$peak,operational_paths_changed:false}'
