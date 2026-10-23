#!/bin/sh
# Fixed UID terminal helpers. This is not a per-session UID/cgroup sandbox.
terminal_input(){
    [ "$(id -u)" -eq 10001 ] && [ "$(id -g)" -eq 10001 ] || return 1
    [ "${#1}" -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1;; esac
    TAG=$1; STATE=/tmp/terminal-$TAG
}
terminal_dir(){
    [ -d "$STATE" ] && [ ! -L "$STATE" ] && [ "$(stat -c %u:%g:%a "$STATE")" = 10001:10001:700 ]
}
terminal_proc(){
    case "$1" in ''|*[!0-9]*) return 1;; esac
    [ "$1" -gt 1 ] && [ -d "/proc/$1" ] || return 1
    [ "$(awk '/^Uid:/ {print $2":"$3":"$4":"$5}' "/proc/$1/status")" = 10001:10001:10001:10001 ] || return 1
    sed 's/^.*) //' "/proc/$1/stat" | awk 'NF>=20 && $3~/^[0-9]+$/ && $4~/^[0-9]+$/ && $20~/^[0-9]+$/ && $3>0 && $4>0 {print $3" "$4" "$20; ok=1} END {if(!ok)exit 1}'
}
terminal_member(){
    # Re-read UID, session and start time immediately before each signal.
    case "$(terminal_proc "$1" 2>/dev/null || true)" in
        *" $2 $3") return 0;;
        *) return 1;;
    esac
}
terminal_foreground(){
    [ -t 0 ] && [ -t 1 ] || return 1
    sed 's/^.*) //' "/proc/$$/stat" | awk -v pid="$$" 'NF>=20 && $3==pid && $4==pid && $5!=0 && $6==pid {ok=1} END {if(!ok)exit 1}'
}
terminal_identity(){
    terminal_dir || return 1
    [ -f "$STATE/process" ] && [ ! -L "$STATE/process" ] && [ "$(stat -c %u:%g:%a:%h "$STATE/process")" = 10001:10001:600:1 ] || return 1
    [ "$(stat -c %s "$STATE/process")" -le 80 ] || return 1
    read -r PID START EXTRA < "$STATE/process"
    [ -z "${EXTRA:-}" ] || return 1
    case "$PID:$START" in *[!0-9:]*|:*|*:) return 1;; esac
    [ "$(terminal_proc "$PID")" = "$PID $PID $START" ] || return 1
    [ "$(tr '\000' '\n' < "/proc/$PID/cmdline")" = "$(printf '/bin/sh\n/lab/terminal-session.sh\n--worker\n%s' "$TAG")" ]
}
