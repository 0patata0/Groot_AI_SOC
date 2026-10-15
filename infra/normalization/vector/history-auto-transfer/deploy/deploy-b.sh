#!/bin/bash -p
# key -> exchange PUBLIC keys via trusted operator -> install. No auto transfer.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=Asia/Seoul
[[ $(uname -s) == Linux && $EUID == 0 && $# -ge 1 ]] || exit 64
[[ $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 65
[[ ($1 == key && $# == 1) || ($1 == install && $# == 3) ]] || exit 64
HD_SOURCE=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd -P)
parent=$HD_SOURCE/deploy
while [[ $parent != / ]]; do
    [[ -d $parent && ! -L $parent && $(stat -c '%u:%g' "$parent") == 0:0 ]] || exit 65
    mode=$(stat -c %a "$parent")
    if [[ $parent == /tmp || $parent == /var/tmp ]]; then [[ $mode == 1777 ]] || exit 65
    else (( (8#$mode & 0022) == 0 )) || exit 65; fi
    parent=$(dirname "$parent")
done
[[ -f $HD_SOURCE/deploy/common.sh && ! -L $HD_SOURCE/deploy/common.sh && $(stat -c '%u:%g:%a:%h' "$HD_SOURCE/deploy/common.sh") == 0:0:400:1 ]] || exit 65
source "$HD_SOURCE/deploy/common.sh"
HD_PHASE=preflight HD_BACKUP=
trap hd_finish EXIT
hd_sources
config=/etc/capstone-history-transfer
if [[ $1 == key ]]; then
    hd_absent "$config"
    hd_backup b-key
    HD_PHASE=key_generation
    hd_newdir "$config" 700
    hd_command /usr/bin/ssh-keygen -q -t ed25519 -N '' -C capstone-history-pull-b -f "$config/id_ed25519"
    chmod 600 "$config/id_ed25519" "$config/id_ed25519.pub"
    hd_file "$config/id_ed25519" 600 8192
    hd_file "$config/id_ed25519.pub" 600 1024
    sync -- "$config/id_ed25519" "$config/id_ed25519.pub" "$config" /etc
    # Only the public half is included in result/evidence or exported.
    /usr/bin/ssh-keygen -y -f "$config/id_ed25519" | awk '{print $1 " " $2}' > "$HD_BACKUP/public.key"
    [[ $(awk '{print $1 " " $2}' "$config/id_ed25519.pub") == "$(cat "$HD_BACKUP/public.key")" ]]
    chmod 400 "$HD_BACKUP/public.key"; sync -- "$HD_BACKUP/public.key" "$HD_BACKUP"
    jq -cnS --arg at "$(date --iso-8601=seconds)" --arg public "$(cat "$HD_BACKUP/public.key")" \
      --arg sha "$(hd_sha "$HD_BACKUP/public.key")" \
      '{schema_version:1,status:"key_created",at_kst:$at,public_key:$public,public_key_sha256:$sha,private_key_exported:false}' | hd_record result.json
    cat "$HD_BACKUP/result.json"
    exit 0
fi
public=$(hd_public "$2" "$3")
hd_parents "$config"; [[ $(stat -c %a "$config") == 700 ]]
hd_file "$config/id_ed25519" 600 8192
hd_file "$config/id_ed25519.pub" 600 1024
hd_file /var/backups/capstone-history-transfer-20261015/b-key/result.json 400 2048
jq -e '.schema_version==1 and .status=="key_created" and .private_key_exported==false' \
  /var/backups/capstone-history-transfer-20261015/b-key/result.json >/dev/null
[[ $(awk '{print $1 " " $2}' "$config/id_ed25519.pub") == "$(jq -r .public_key /var/backups/capstone-history-transfer-20261015/b-key/result.json)" ]]
[[ $(/usr/bin/ssh-keygen -y -f "$config/id_ed25519" | awk '{print $1 " " $2}') == "$(awk '{print $1 " " $2}' "$config/id_ed25519.pub")" ]]
for path in "$config/known_hosts" /usr/local/lib/capstone-history-auto-transfer \
  /usr/local/sbin/capstone-history-auto-transfer /var/lib/capstone-history-auto-transfer \
  /etc/systemd/system/capstone-history-auto-transfer.service /etc/systemd/system/capstone-history-auto-transfer.timer; do hd_absent "$path"; done
hd_parents /var/lib/capstone-history-receipts
[[ $(stat -c %a /var/lib/capstone-history-receipts) == 700 ]]
hd_file /var/lib/capstone-history-receipts/.lock 600 0
# Own runtime source is trusted/pinned; receiver mode/hash checks are read-only.
source "$HD_SOURCE/transfer-lib.sh"
hd_backup b-install
HD_PHASE=host_pin
printf 'capstone-history-source-a %s\n' "$public" > "$HD_BACKUP/known_hosts"
hd_publish "$HD_BACKUP/known_hosts" "$config/known_hosts" 600
hat_dependencies
HD_PHASE=runtime_install
hd_newdir /usr/local/lib/capstone-history-auto-transfer 755
for name in worker-b.sh transfer-lib.sh ssh-b.sh runtime.sha256; do
    hd_publish "$HD_SOURCE/$name" "/usr/local/lib/capstone-history-auto-transfer/$name" 400
done
hd_publish "$HD_SOURCE/run-b.sh" /usr/local/sbin/capstone-history-auto-transfer 500
hd_newdir /var/lib/capstone-history-auto-transfer 700
hd_newdir /var/lib/capstone-history-auto-transfer/work 700
: > "$HD_BACKUP/empty-lock"
hd_publish "$HD_BACKUP/empty-lock" /var/lib/capstone-history-auto-transfer/.lock 600
HD_PHASE=unit_install
for name in capstone-history-auto-transfer.service capstone-history-auto-transfer.timer; do
    hd_publish "$HD_SOURCE/$name" "/etc/systemd/system/$name" 644
done
hd_command /usr/bin/systemd-analyze verify /etc/systemd/system/capstone-history-auto-transfer.service \
  /etc/systemd/system/capstone-history-auto-transfer.timer > "$HD_BACKUP/unit-verify.log" 2>&1
hd_command /usr/bin/systemctl daemon-reload
[[ $(/usr/bin/systemctl show -p ActiveState --value capstone-history-auto-transfer.timer) == inactive &&
   $(/usr/bin/systemctl show -p UnitFileState --value capstone-history-auto-transfer.timer) == disabled ]]
[[ $(/usr/bin/systemctl show -p ActiveState --value capstone-history-auto-transfer.service) == inactive ]]
chmod 400 "$HD_BACKUP/known_hosts" "$HD_BACKUP/empty-lock" "$HD_BACKUP/unit-verify.log"
sync -- "$HD_BACKUP/known_hosts" "$HD_BACKUP/empty-lock" "$HD_BACKUP/unit-verify.log" "$HD_BACKUP"
hd_sources; hat_dependencies
jq -cnS --arg at "$(date --iso-8601=seconds)" --arg host_sha "$3" \
  --arg manifest_sha "$(hd_sha /usr/local/lib/capstone-history-auto-transfer/runtime.sha256)" \
  '{schema_version:1,status:"pull_installed_timer_disabled",at_kst:$at,host_public_key_input_sha256:$host_sha,
    runtime_manifest_sha256:$manifest_sha,private_key_exported:false,transfer_executed:false,timer_enabled:false,
    receiver_source_changed:false,existing_receipts_changed:false}' | hd_record result.json
cat "$HD_BACKUP/result.json"
