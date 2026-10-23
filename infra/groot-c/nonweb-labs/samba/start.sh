#!/bin/sh
set -eu
umask 077
[ "$#" -eq 0 ] && [ "$(id -u)" -eq 0 ] || exit 64
mkdir -p /run/samba /var/lib/samba/private /var/cache/samba /var/log/samba /share
chmod 0755 /run/samba /var/lib/samba /var/cache/samba /var/log/samba
chmod 0700 /var/lib/samba/private
# This anonymous training share is common to all sessions inside this lab.
chmod 01777 /share
chown 65534:65534 /share
/usr/local/samba/bin/testparm -s /etc/samba/smb.conf >/dev/null 2>&1
exec /usr/sbin/smbd -F --no-process-group -s /etc/samba/smb.conf
