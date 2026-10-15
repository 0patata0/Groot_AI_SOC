#!/bin/bash
# Internal worker; neither sudoers nor an SSH/MCP command endpoint.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# A fresh worker keeps errexit effective; parser diagnostics can quote raw input.
# Only the fixed rejection below may leave this process on failure.
status=0
/bin/bash -c 'set -euo pipefail; umask 077; source "$1"; shift; ht_receive "$@"' \
    history-receiver "$directory/receive-lib.sh" "$@" 2>/dev/null || status=$?
if (( status != 0 )); then
    printf '{"status":"rejected","stage":"not_acknowledged"}\n' >&2
    exit "$status"
fi
