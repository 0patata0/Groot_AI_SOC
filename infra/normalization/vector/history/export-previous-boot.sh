#!/bin/bash
# Operator-only one-shot preservation. No upload, replay, checkpoint or service mutation.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $(uname -s) == Linux && $EUID == 0 && $# == 2 ]] || exit 64
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 65
[[ $1 =~ ^[a-f0-9]{32}$ && $2 =~ ^[1-9][0-9]{0,15}$ ]] || exit 64
[[ $1 != "$(tr -d '-' < /proc/sys/kernel/random/boot_id)" ]] || exit 65
[[ $2 -le $(date +%s%6N) ]] || exit 65
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
[[ $(stat -c %u "$directory") == 0 ]]
(( (8#$(stat -c %a "$directory") & 0022) == 0 ))
# No arbitrary executable/path arguments or environment overrides in this operator entry point.
for source in "$directory/history-lib.sh" "$directory/history-run.sh" "$directory/validate-records.jq"; do
    [[ -f $source && ! -L $source && $(stat -c %u "$source") == 0 && $(stat -c %h "$source") == 1 ]]
    (( (8#$(stat -c %a "$source") & 0022) == 0 ))
done
for tool in jq journalctl timeout head wc sha256sum sync flock stat df awk; do command -v "$tool" >/dev/null; done
source "$directory/history-lib.sh"
history_export /var/lib/capstone-vector-history /usr/bin/journalctl "$1" "$2"
