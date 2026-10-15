#!/bin/bash
# Fixed operator-only receiver. No arbitrary path, executable or fault arguments.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $(uname -s) == Linux && $EUID == 0 && $# == 3 ]] || exit 64
[[ $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 65
for value in "$@"; do [[ $value =~ ^[a-f0-9]{64}$ ]] || exit 64; done
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
for parent in "$directory" "$directory/../history"; do
    [[ -d $parent && ! -L $parent && $(stat -c %u "$parent") == 0 ]] || exit 65
    (( (8#$(stat -c %a "$parent") & 0022) == 0 )) || exit 65
done
for source in "$directory/receive-lib.sh" "$directory/receive-run.sh" "$directory/validate-manifest.jq" "$directory/../history/validate-records.jq"; do
    [[ -f $source && ! -L $source && $(stat -c %u "$source") == 0 && $(stat -c %h "$source") == 1 ]] || exit 65
    (( (8#$(stat -c %a "$source") & 0022) == 0 )) || exit 65
done
[[ $(sha256sum "$directory/../history/validate-records.jq" | cut -d ' ' -f1) == 2470fab15dfde40540d60a3e47f4de8a6f5520f46acb231d1067895c770ffaa9 ]] || exit 65
# A clean environment prevents caller-supplied shell functions or test adapters.
exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
    /bin/bash "$directory/receive-run.sh" /var/lib/capstone-history-receipts "$@"
