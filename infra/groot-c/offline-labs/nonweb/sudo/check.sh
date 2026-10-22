#!/bin/sh
# Fixed, non-exploit inventory check. No malformed sudo arguments or shell escape.
set -eu
export LC_ALL=C
test "$(dpkg --print-architecture)" = amd64
test "$(dpkg-query -W -f='${Status}|${Version}' sudo)" = 'install ok installed|1.8.31-1ubuntu1'
test "$(/usr/bin/sudo --version | head -n 1)" = 'Sudo version 1.8.31'
test "$(stat -c '%u:%g:%a' /usr/bin/sudo)" = '0:0:4755'
printf '%s\n' '{"schema":1,"package":"sudo","version":"1.8.31-1ubuntu1","architecture":"amd64","setuid_binary":true,"attack_tested":false}'
