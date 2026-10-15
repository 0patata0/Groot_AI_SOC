#!/bin/bash
# Operator-only, fixed A -> B upload. Completion is NOT a receiver receipt.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
[[ $EUID == 0 && $(uname -s) == Linux && $# == 3 ]] || exit 64
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 65
for value in "$@"; do [[ $value =~ ^[a-f0-9]{64}$ ]] || exit 64; done
root=/var/lib/capstone-vector-history
[[ -d $root && ! -L $root && $(stat -c %u "$root") == 0 && $(stat -c %a "$root") == 700 ]] || exit 65
[[ -f $root/.lock && ! -L $root/.lock && $(stat -c %u "$root/.lock") == 0 && $(stat -c %h "$root/.lock") == 1 && $(stat -c %a "$root/.lock") == 600 ]] || exit 65
exec 9<>"$root/.lock"
flock -n 9 || exit 75
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
[[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || exit 65
(( (8#$(stat -c %a "$directory") & 0022) == 0 )) || exit 65
[[ -f $directory/send-lib.sh && ! -L $directory/send-lib.sh && $(stat -c %u "$directory/send-lib.sh") == 0 && $(stat -c %h "$directory/send-lib.sh") == 1 ]] || exit 65
(( (8#$(stat -c %a "$directory/send-lib.sh") & 0022) == 0 )) || exit 65
status=0
/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
 CAPSTONE_AUTH_FD_PATH="${CAPSTONE_AUTH_FD_PATH:-}" \
 /bin/bash -c 'set -euo pipefail; source "$1"; shift; hs_send "/var/lib/capstone-vector-history/batch-$1" "$@"' \
 history-sender "$directory/send-lib.sh" "$@" 2>/dev/null || status=$?
if (( status != 0 )); then
    printf '{"status":"failed","stage":"transport_not_acknowledged"}\n' >&2
    exit "$status"
fi
