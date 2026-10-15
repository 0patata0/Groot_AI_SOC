#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C
[[ $(uname -s) == Linux && $EUID == 0 && $# == 1 && $1 == run ]] || exit 64
[[ $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 65
lib=/usr/local/lib/capstone-history-auto-transfer
for p in /usr /usr/local /usr/local/lib "$lib"; do
  [[ -d $p && ! -L $p && $(stat -c %u "$p") == 0 ]] || exit 65
  (( (8#$(stat -c %a "$p") & 0022) == 0 )) || exit 65
done
for f in worker-b.sh transfer-lib.sh ssh-b.sh runtime.sha256; do
  [[ -f $lib/$f && ! -L $lib/$f && $(stat -c '%u:%g:%a:%h' "$lib/$f") == 0:0:400:1 ]] || exit 65
done
# Fixed filenames only; do not accept a checksum file that reads arbitrary paths.
[[ $(wc -l < "$lib/runtime.sha256") == 3 ]]
grep -Eq '^[a-f0-9]{64}  worker-b\.sh$' "$lib/runtime.sha256"
grep -Eq '^[a-f0-9]{64}  transfer-lib\.sh$' "$lib/runtime.sha256"
grep -Eq '^[a-f0-9]{64}  ssh-b\.sh$' "$lib/runtime.sha256"
(cd "$lib" && sha256sum --status -c runtime.sha256) || exit 65
exec /usr/bin/timeout --signal=TERM --kill-after=10s 600s \
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul \
  /bin/bash "$lib/worker-b.sh"
