#!/bin/bash -p
# Install the fixed read-only sender. No sshd reload, journal call or raw write.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=Asia/Seoul
[[ $(uname -s) == Linux && $EUID == 0 && $# == 2 ]] || exit 64
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 65
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
public=$(hd_public "$1" "$2")
[[ $(hd_sha /usr/bin/rrsync) == cb46c1bf89c25e1193eb16e9201405bc0e39d2c2d03bff42d3cee86ef15e3050 &&
   $(hd_sha /usr/bin/rsync) == 6b4fb867cb49d0332b72b234656311c807ab68b0537905fda7a3e7481a139f16 ]]
[[ -f /bin/dash && -x /bin/dash ]]
for path in /var/lib/capstone-history-export /etc/sudoers.d/capstone-history-export \
  /usr/local/libexec/capstone-history-export /usr/local/libexec/capstone-history-ssh-gate; do hd_absent "$path"; done
rc=0; getent passwd capstone-hist >/dev/null || rc=$?; [[ $rc == 2 ]]
rc=0; getent group capstone-hist >/dev/null || rc=$?; [[ $rc == 2 ]]
hd_parents /etc/sudoers.d
[[ -d /var/lib/capstone-vector-history-auto/store && ! -L /var/lib/capstone-vector-history-auto/store &&
   $(stat -c '%u:%g:%a' /var/lib/capstone-vector-history-auto/store) == 0:0:700 ]]
hd_file /var/lib/capstone-vector-history-auto/store/.lock 600 0
# Changes below are exclusive and recorded first. Failure never retries/removes
# an uncertain account/key/sudo rule. Existing SSH/server configuration is intact.
hd_backup a-install
HD_PHASE=source_install
hd_dir /usr/local/libexec 755
hd_publish "$HD_SOURCE/export-a.sh" /usr/local/libexec/capstone-history-export 500
hd_publish "$HD_SOURCE/ssh-gate-a.sh" /usr/local/libexec/capstone-history-ssh-gate 755
HD_PHASE=account
hd_command /usr/sbin/useradd --system --user-group --home-dir /var/lib/capstone-history-export --no-create-home --shell /bin/dash capstone-hist
hd_command /usr/sbin/usermod --lock capstone-hist
[[ $(getent passwd capstone-hist | cut -d: -f6-7) == /var/lib/capstone-history-export:/bin/dash ]]
[[ $(passwd -S capstone-hist | awk '{print $2}') == L ]]
hd_newdir /var/lib/capstone-history-export 755
hd_newdir /var/lib/capstone-history-export/.ssh 755
printf 'from="10.200.10.10",restrict,command="/usr/local/libexec/capstone-history-ssh-gate" %s capstone-history-pull-b\n' "$public" > "$HD_BACKUP/authorized_keys"
hd_publish "$HD_BACKUP/authorized_keys" /var/lib/capstone-history-export/.ssh/authorized_keys 644
HD_PHASE=sudoers
printf 'capstone-hist ALL=(root) NOPASSWD: NOSETENV: sha256:%s /usr/local/libexec/capstone-history-export *\n' \
  "$(hd_sha "$HD_SOURCE/export-a.sh")" > "$HD_BACKUP/sudoers"
hd_command /usr/sbin/visudo -cf "$HD_BACKUP/sudoers" >/dev/null
hd_publish "$HD_BACKUP/sudoers" /etc/sudoers.d/capstone-history-export 440
hd_command /usr/sbin/visudo -cf /etc/sudoers >/dev/null
HD_PHASE=native_policy
# Reject a non-rsync request through the exact new account's actual sudo rule.
rc=0
hd_command /usr/sbin/runuser -u capstone-hist -- /usr/bin/sudo -n -- /usr/local/libexec/capstone-history-export 'false' >/dev/null 2>&1 || rc=$?
[[ $rc == 65 ]]
hd_command /usr/sbin/sshd -T -C user=capstone-hist,addr=10.200.10.10,host=capstone-history-source-a > "$HD_BACKUP/sshd-effective.txt"
grep -qx 'pubkeyauthentication yes' "$HD_BACKUP/sshd-effective.txt"
grep -qx 'strictmodes yes' "$HD_BACKUP/sshd-effective.txt"
grep -qx 'authorizedkeyscommand none' "$HD_BACKUP/sshd-effective.txt"
grep -qx 'trustedusercakeys none' "$HD_BACKUP/sshd-effective.txt"
grep -qx 'authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2' "$HD_BACKUP/sshd-effective.txt"
chmod 400 "$HD_BACKUP/authorized_keys" "$HD_BACKUP/sudoers" "$HD_BACKUP/sshd-effective.txt"
sync -- "$HD_BACKUP/authorized_keys" "$HD_BACKUP/sudoers" "$HD_BACKUP/sshd-effective.txt" "$HD_BACKUP"
hd_sources
jq -cnS --arg at "$(date --iso-8601=seconds)" --arg key_sha "$2" \
  --arg exporter "$(hd_sha /usr/local/libexec/capstone-history-export)" \
  '{schema_version:1,status:"sender_installed",at_kst:$at,account:"capstone-hist",password_locked:true,
    public_key_input_sha256:$key_sha,exporter_sha256:$exporter,forced_readonly:true,
    negative_sudo_command_rejected:true,ssh_reload_calls:0,source_batches_changed:false,transfer_executed:false}' | hd_record result.json
cat "$HD_BACKUP/result.json"
