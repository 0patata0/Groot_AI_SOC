#!/bin/bash
# Installed at /usr/local/sbin/capstone-vector-history-auto. No user paths or cursor arguments.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
exec 2>/dev/null
refuse() { printf '{"outcome":"deferred","reason":"%s","raw_payload_exported":false}\n' "$1"; exit 65; }
[[ $# == 1 && $1 =~ ^(run|inspect)$ ]] || refuse invalid_arguments
[[ $(id -u) == 0 && $(uname -s) == Linux && $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || refuse wrong_operator_host
base=/usr/local/lib/capstone-vector-history-auto
for directory in /usr /usr/local /usr/local/lib "$base" "$base/history"; do
    [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || refuse unsafe_runtime_directory
    mode=$(stat -c %a "$directory")
    (( (8#$mode & 0022)==0 )) || refuse writable_runtime_directory
done
files=(auto-worker.sh auto-lib.sh state.jq runtime.sha256 history/history-lib.sh history/history-run.sh
       history/continuation-lib.sh history/continue-run.sh history/validate-records.jq)
for file in "${files[@]}"; do
    [[ -f $base/$file && ! -L $base/$file && $(stat -c %u:%g:%h "$base/$file") == 0:0:1 ]] || refuse unsafe_runtime_file
    mode=$(stat -c %a "$base/$file")
    (( (8#$mode & 0022)==0 )) || refuse writable_runtime_file
done
[[ $(wc -l < "$base/runtime.sha256") == 8 && $(stat -c %s "$base/runtime.sha256") -lt 2048 ]] || refuse runtime_manifest_invalid
expected=$(printf '%s\n' auto-lib.sh auto-worker.sh state.jq history/continue-run.sh history/continuation-lib.sh history/history-lib.sh history/history-run.sh history/validate-records.jq | sort)
actual=$(awk 'NF!=2 || length($1)!=64 || $1!~/^[0-9a-f]+$/ {exit 1} {print $2}' "$base/runtime.sha256" | sort) || refuse runtime_manifest_invalid
[[ $actual == "$expected" ]] || refuse runtime_manifest_invalid
(cd "$base" && sha256sum --status -c runtime.sha256) || refuse runtime_source_changed
cutoff=$(date +%s%6N)
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/timeout --kill-after=3s 90s \
  /bin/bash "$base/auto-worker.sh" "$1" /var/lib/capstone-vector-history-auto \
  /usr/bin/journalctl /proc/sys/kernel/random/boot_id "$base/history" "$cutoff"
