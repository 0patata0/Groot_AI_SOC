#!/bin/sh
set -eu
umask 077
[ "$#" -eq 0 ] && [ "$(id -u)" -eq 65534 ] && [ "$(id -g)" -eq 65534 ] || exit 64
[ -d /var/lib/redis ] && [ -w /var/lib/redis ] && [ -w /tmp ] || exit 65
exec /usr/bin/redis-server /etc/redis/lab.conf
