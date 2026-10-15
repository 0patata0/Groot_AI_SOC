#!/bin/bash -p
# Pure read-only rsync sender. No account, key, log or store mutation here.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C
ha_command() {
    local allowed='^[-a-zA-Z0-9_./=,+@%: ]+$'
    [[ $# == 1 && ${#1} -le 4096 && $1 == 'rsync --server --sender '* ]] || return 65
    [[ $1 =~ $allowed ]] || return 65
    [[ $1 != *'..'* && $1 != *'--remove'* && $1 != *'--delete'* && $1 != *'--log-file'* &&
       $1 != *'--only-write-batch'* && $1 != *'--write-batch'* && $1 != *'--backup'* &&
       $1 != *'--temp-dir'* && $1 != *'--partial-dir'* && $1 != *'--inplace'* ]]
}
ha_dir() {
    [[ -d $1 && ! -L $1 && $(stat -c '%u:%g:%a' -- "$1") == 0:0:700 ]]
}
ha_store() {
    local root=$1 listing rows bytes batches
    ha_dir "$root" || return 65
    # pipefail rejects a truncated/unreadable inventory; stdout never receives it.
    listing=$(find "$root" -xdev -printf '%y %s %U %G %m %n\n' | head -n 4097) || return 65
    rows=$(printf '%s\n' "$listing" | wc -l) || return 65
    (( rows <= 4096 )) || return 65
    printf '%s\n' "$listing" | awk '
      NF!=6 || $2!~/^[0-9]+$/ || $3!=0 || $4!=0 {exit 1}
      $1=="d" {if($5!=700)exit 1; next}
      $1=="f" {if(($5!=400 && $5!=600)||$6!=1)exit 1; next}
      {exit 1}' || return 65
    bytes=$(printf '%s\n' "$listing" | awk '{n+=$2} END{printf "%.0f",n}') || return 65
    (( bytes <= 1073741824 )) || return 65
    batches=$(find "$root" -mindepth 1 -maxdepth 1 -type d -name 'batch-*' -printf '.\n' | wc -l) || return 65
    (( batches <= 256 )) || return 65
    # rrsync checks this relative to its initial cwd before entering its root.
    [[ ! -e $root/rrsync.log && ! -L $root/rrsync.log ]]
}
# PUBLIC ENTRY: tests source only the functions above, never this block.
[[ $(uname -s) == Linux && $EUID == 0 && $# == 1 ]] || exit 64
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 65
ha_command "$1" || exit 65
[[ $(sha256sum /usr/bin/rrsync | cut -d ' ' -f1) == cb46c1bf89c25e1193eb16e9201405bc0e39d2c2d03bff42d3cee86ef15e3050 ]] || exit 65
[[ $(sha256sum /usr/bin/rsync | cut -d ' ' -f1) == 6b4fb867cb49d0332b72b234656311c807ab68b0537905fda7a3e7481a139f16 ]] || exit 65
store=/var/lib/capstone-vector-history-auto/store
ha_dir /var/lib/capstone-vector-history-auto
ha_dir "$store"
[[ -f $store/.lock && ! -L $store/.lock && $(stat -c '%u:%g:%a:%h' "$store/.lock") == 0:0:600:1 ]] || exit 65
exec 8<"$store/.lock"
flock -s -n 8 || exit 75
ha_store "$store" || exit 65
cd -- "$store"
# rrsync 3.2.7 -ro disables receiver/remove/delete/log-file and path escapes.
# Its existing distro Python is used; no new daemon or Python collector.
exec /usr/bin/timeout --signal=TERM --kill-after=2s 60s \
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
    SSH_ORIGINAL_COMMAND="$1" /usr/bin/rrsync -ro "$store" 2>/dev/null
