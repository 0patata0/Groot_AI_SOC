#!/bin/bash
# Operator-only continuation: no arbitrary source path, cursor or executable input.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $(uname -s) == Linux && $EUID == 0 && $# == 3 ]] || exit 64
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 65
[[ $1 =~ ^[0-9a-f]{64}$ && $2 =~ ^[0-9a-f]{64}$ && $3 =~ ^[0-9a-f]{64}$ ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
[[ $(stat -c %u "$directory") == 0 ]]
(( (8#$(stat -c %a "$directory") & 0022) == 0 ))
for file in history-lib.sh validate-records.jq continuation-lib.sh continue-run.sh; do
    path=$directory/$file
    [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %h "$path") == 1 ]]
    (( (8#$(stat -c %a "$path") & 0022) == 0 ))
done
parent=/var/lib/capstone-vector-history/batch-$1
[[ -f $parent/manifest.json && ! -L $parent && ! -L $parent/manifest.json ]]
[[ $(stat -c '%u:%a' "$parent") == 0:700 && $(stat -c '%u:%a:%h' "$parent/manifest.json") == 0:400:1 ]]
(( $(stat -c %s "$parent/manifest.json") <= 65536 ))
[[ $(sha256sum "$parent/manifest.json" | cut -d ' ' -f1) == "$3" ]]
boot=$(jq -er '.boot_id|select(type=="string" and test("^[0-9a-f]{32}$"))' "$parent/manifest.json")
until=$(jq -er '.until_epoch_us|select(type=="string" and test("^[1-9][0-9]{0,15}$"))' "$parent/manifest.json")
[[ $boot != "$(tr -d '-' </proc/sys/kernel/random/boot_id)" && $until -le $(date +%s%6N) ]]
/bin/bash "$directory/continue-run.sh" /var/lib/capstone-vector-history /usr/bin/journalctl "$1" "$2" "$3"
