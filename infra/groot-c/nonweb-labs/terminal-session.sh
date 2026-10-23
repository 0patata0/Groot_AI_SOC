#!/bin/sh
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH HOME=/tmp LC_ALL=C
unset ENV BASH_ENV CDPATH
. /lab/terminal-lib.sh
if [ "$#" -eq 1 ]; then
    terminal_input "$1" || exit 64
    # Docker exec -it already creates the session and controlling terminal.
    # A second setsid would detach it and break interactive job control.
    exec /bin/sh /lab/terminal-session.sh --worker "$TAG"
fi
[ "$#" -eq 2 ] && [ "$1" = --worker ] || exit 64
terminal_input "$2" || exit 64
identity=$(terminal_proc "$$")
read -r PGID SID START <<EOF
$identity
EOF
[ "$PGID" = "$$" ] && [ "$SID" = "$$" ] || exit 65
terminal_foreground || exit 65
mkdir -m 0700 -- "$STATE" || exit 65
printf '%s %s\n' "$$" "$START" > "$STATE/process"
terminal_identity || exit 65
cleanup(){
    trap - EXIT HUP INT TERM
    # Leave the target session before cleaning its leader and job groups.
    /usr/bin/setsid /bin/sh /lab/terminal-close.sh "$TAG" </dev/null >/dev/null 2>&1 &
    wait "$!" || true
}
trap cleanup EXIT HUP INT TERM
cd /tmp
set +e
/usr/bin/timeout --foreground --signal=TERM --kill-after=2s 1800s /bin/sh -i
exit "$?"
