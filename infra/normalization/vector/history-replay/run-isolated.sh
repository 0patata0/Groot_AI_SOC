#!/bin/bash
# Internal fixed probe: input/work directories are supplied by the root-owned A verifier.
# No journald/file source, network sink, current checkpoint, service action or reinjection.
set -euo pipefail
umask 077
PATH=/usr/local/bin:/usr/bin:/bin
export PATH LC_ALL=C
[[ $# == 3 && $(id -u) == 0 && $(uname -s) == Linux ]] || exit 64
input=$1 REPLAY_WORK=$2 CAPSTONE_SENSOR=$3
[[ $REPLAY_WORK =~ ^/var/tmp/capstone-replay-20261014/history-replay-[A-Za-z0-9]+/(actual|synthetic)$ ]]
[[ $CAPSTONE_SENSOR =~ ^[A-Za-z0-9_.:-]{1,80}$ ]]
[[ -d $REPLAY_WORK && ! -L $REPLAY_WORK && $(stat -c '%u:%a' "$REPLAY_WORK") == 0:700 ]]
[[ -f $input && ! -L $input && $(stat -c %u "$input") == 0 && $(stat -c %s "$input") -le 2097152 ]]
export REPLAY_WORK CAPSTONE_SENSOR
mkdir -m 700 "$REPLAY_WORK/data"
# v0.59.0 journald Record is HashMap<String,String>, with special byte-array decoding.
# These batches have strings only. Refuse broader records rather than simulate that decoding.
jq -e -s 'length>0 and length<=2000 and all(.[]; type=="object" and (has("message")|not) and all(.[];type=="string"))' "$input" >/dev/null
for file in nftables.vrl correlation.vrl; do
  [[ -f $REPLAY_WORK/$file && ! -L $REPLAY_WORK/$file ]]
done
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# remap.file is loaded before Vector expands environment variables: render only our fixed safe path.
sed 's|${REPLAY_WORK}|'"$REPLAY_WORK"'|g' "$script_dir/replay.toml" > "$REPLAY_WORK/replay.toml"
timeout --signal=TERM --kill-after=3s 20s /usr/local/bin/vector validate --no-environment "$REPLAY_WORK/replay.toml" > "$REPLAY_WORK/validate.log" 2>&1
# stdin EOF closes this isolated topology; the file sink stays separate from Vector internal stdout logs.
timeout --signal=TERM --kill-after=3s 30s nice -n 10 /usr/local/bin/vector --config "$REPLAY_WORK/replay.toml" --log-format json < "$input" > "$REPLAY_WORK/vector.log" 2> "$REPLAY_WORK/vector.stderr"
[[ $(stat -c %s "$REPLAY_WORK/result.jsonl") -le 2097152 ]]
jq -e -s 'all(.[]; .replay_stage=="selector" or .replay_stage=="normalized" or .replay_stage=="mapping_failed" or .replay_stage=="normalization_failed" or .replay_stage=="correlation_failed")' "$REPLAY_WORK/result.jsonl" >/dev/null
