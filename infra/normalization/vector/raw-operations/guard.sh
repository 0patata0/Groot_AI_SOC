#!/bin/bash
# ExecStartPre for BOTH native reader units. Lock-free: coordinator may own the
# shared Vector operation lock while requesting systemctl start. Never wait on
# that lock here. Missing/ambiguous state refuses startup and requires resume.
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 1 && ( $1 == vector || $1 == wazuh ) ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P) || exit 2
[[ $EUID == 0 && $OSTYPE == linux* && $directory == /* && -d $directory && ! -L $directory &&
   $(/usr/bin/stat -c %u "$directory") == 0 && -f $directory/coordinator.sh && ! -L $directory/coordinator.sh &&
   $(/usr/bin/stat -c %u:%h "$directory/coordinator.sh") == 0:1 ]] || exit 2
(( (8#$(/usr/bin/stat -c %a "$directory") & 0022)==0 &&
   (8#$(/usr/bin/stat -c %a "$directory/coordinator.sh") & 0022)==0 )) || exit 2
exec /usr/bin/timeout --signal=TERM --kill-after=2s 110s \
  /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC \
  /bin/bash --noprofile --norc -c '
    set -uo pipefail
    source "$1/coordinator.sh" || exit 2
    if ro_runtime && ro_guard_all "$2"; then ro_json ready reader_start_guard
    else ro_json deferred "$RO_REASON"; exit 2; fi
  ' raw-start-guard "$directory" "$1" 2>/dev/null
