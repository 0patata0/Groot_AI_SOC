#!/bin/sh
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
unset ENV BASH_ENV CDPATH
exec 2>/dev/null
. /lab/terminal-lib.sh
[ "$#" -eq 1 ] || exit 64
terminal_input "$1" || exit 64
if [ ! -e "$STATE" ] && [ ! -L "$STATE" ]; then exit 0; fi
terminal_identity || exit 65
# Job control creates multiple process groups in one controlling session.
# Authorize the fixed session leader, then snapshot only its UID10001 members.
members=
for entry in /proc/[0-9]*; do
    pid=${entry##*/};row=$(terminal_proc "$pid" 2>/dev/null) || continue
    case "$row" in *" $PID "*) members="$members $pid:${row##* }";; esac
done
terminal_identity || exit 65
# Revalidate each PID immediately before its individual signal. Never signal
# an entire group that may contain an unrelated or recycled process.
for item in $members; do
    pid=${item%%:*};start=${item#*:}
    if terminal_member "$pid" "$PID" "$start"; then /bin/kill -HUP -- "$pid" || true; fi
done
sleep 1
for item in $members; do
    pid=${item%%:*};start=${item#*:}
    if terminal_member "$pid" "$PID" "$start"; then /bin/kill -TERM -- "$pid" || true; fi
done
# Keep the tiny receipt for a retry/inspection. Arbitrary daemonized children
# can leave this session; stopping the lab container is the full boundary.
exit 0
