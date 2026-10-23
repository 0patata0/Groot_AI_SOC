#!/bin/sh
# Only a random harmless text-file upload/download/delete over loopback SMB.
set -eu
umask 077
exec 2>/dev/null
[ "$#" -eq 0 ] && [ "$(/usr/sbin/smbd --version)" = 'Version 4.6.3' ] || exit 65
[ "$(/usr/bin/smbclient --version)" = 'Version 4.6.3' ] || exit 65
work=$(mktemp -d /tmp/capstone-smb-verify.XXXXXXXX)
name=capstone-verify-${work##*.}.txt
cleanup(){ timeout 5 /usr/bin/smbclient //127.0.0.1/lab -p 1445 -N -m SMB3 -c "del $name" >/dev/null 2>&1 || true; rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM
printf '%s\n' benign-samba-validation > "$work/source.txt"
timeout 10 /usr/bin/smbclient //127.0.0.1/lab -p 1445 -N -m SMB3 -c "put $work/source.txt $name; get $name $work/result.txt; del $name" > "$work/client.log" 2>&1
cmp -s "$work/source.txt" "$work/result.txt" || exit 65
printf '%s\n' '{"schema":1,"lab":"samba","software_version":"4.6.3","package_version":"source-4.6.3","service_ready":true,"attack_tested":false}'
