#!/bin/sh
# Ordinary Redis PING and expiring string round-trip; no sandbox escape.
set -eu
umask 077
exec 2>/dev/null
[ "$#" -eq 0 ] || exit 64
version=$(/usr/bin/redis-server --version)
case "$version" in 'Redis server v=5.0.7 '*) ;; *) exit 65;; esac
[ "$(dpkg-query -W -f='${Version}' redis-server)" = '5:5.0.7-2' ] || exit 65
[ "$(dpkg-query -W -f='${Version}' redis-tools)" = '5:5.0.7-2' ] || exit 65
[ "$(timeout 5 redis-cli --raw -h 127.0.0.1 -p 6379 PING)" = PONG ] || exit 65
key=capstone:verify:$$
trap 'timeout 3 redis-cli -h 127.0.0.1 -p 6379 DEL "$key" >/dev/null 2>&1 || true' EXIT HUP INT TERM
[ "$(timeout 5 redis-cli --raw -h 127.0.0.1 -p 6379 SET "$key" benign-validation EX 30 NX)" = OK ] || exit 65
[ "$(timeout 5 redis-cli --raw -h 127.0.0.1 -p 6379 GET "$key")" = benign-validation ] || exit 65
[ "$(timeout 5 redis-cli --raw -h 127.0.0.1 -p 6379 EVAL 'return 1' 0)" = 1 ] || exit 65
printf '%s\n' '{"schema":1,"lab":"redis","software_version":"5.0.7","package_version":"5:5.0.7-2","service_ready":true,"attack_tested":false}'
