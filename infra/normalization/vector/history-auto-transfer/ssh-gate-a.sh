#!/bin/dash
# authorized_keys forced command; this account has no other sudo permission.
set -eu
[ "$#" -eq 0 ] || exit 64
[ "${SSH_CONNECTION%% *}" = 10.200.10.10 ] || exit 65
[ -n "${SSH_ORIGINAL_COMMAND:-}" ] || exit 65
exec /usr/bin/sudo -n -- /usr/local/libexec/capstone-history-export "$SSH_ORIGINAL_COMMAND"
