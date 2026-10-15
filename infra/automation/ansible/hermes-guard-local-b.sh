#!/bin/sh
# Root operator only; fixed local playbook. Never expose this through MCP/sudoers.
set -eu
operation=${1:-}
case "$operation" in syntax|check|apply|watch) ;; *) exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || exit 77
expected=${2:-}
if [ "$operation" = watch ]; then
    [ "$#" -eq 1 ] || exit 64
    expected=$(cat /etc/capstone-hermes-guard/machine-id)
else
    [ "$#" -eq 2 ] || exit 64
fi
case "$expected" in ''|*[!0123456789abcdef]*) exit 64 ;; esac
[ "${#expected}" -eq 32 ] && [ "$(cat /etc/machine-id)" = "$expected" ] || exit 77
project=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project"
umask 077
for dir in /var/lib/capstone-automation /var/lib/capstone-automation/hermes-guard /var/lib/capstone-automation/hermes-guard/tmp /var/lib/capstone-automation/hermes-guard/remote-tmp; do
    [ ! -L "$dir" ] || exit 77
    if [ -e "$dir" ]; then
        [ -d "$dir" ] && [ "$(stat -c '%u' "$dir")" -eq 0 ] || exit 77
        mode=$(stat -c '%a' "$dir")
        [ "$((0$mode & 0022))" -eq 0 ] || exit 77
    else
        mkdir "$dir"
    fi
    chmod 700 "$dir"
done
lock=/var/lib/capstone-automation/hermes-guard/apply.lock
[ ! -L "$lock" ] || exit 77
if [ -e "$lock" ]; then
    [ -f "$lock" ] && [ "$(stat -c '%u' "$lock")" -eq 0 ] || exit 77
fi
exec 9>"$lock"
flock -n 9 || { echo 'hermes_guard_reapply verdict=deployment_busy'; exit 75; }
if [ "$operation" = watch ]; then
    identity=$(/usr/local/bin/docker inspect --format '{{.Id}}' hermes)
    saved=/var/lib/capstone-automation/hermes-guard/last-container-id
    [ ! -L "$saved" ] || exit 77
    if [ -f "$saved" ] && [ "$(cat "$saved")" = "$identity" ]; then
        echo 'hermes_guard_reapply verdict=unchanged_container'
        exit 0
    fi
    echo 'hermes_guard_reapply verdict=container_changed'
fi
export ANSIBLE_CONFIG="$project/ansible.cfg"
export ANSIBLE_NOCOLOR=1
export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/hermes-guard/tmp
export ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/hermes-guard/remote-tmp
controller=/opt/capstone-automation/venv/bin/ansible-playbook
[ -x "$controller" ] || exit 69
case "$operation" in
    syntax) set -- --syntax-check ;;
    check) set -- --check ;;
    apply) set -- --extra-vars capstone_guard_enable_watch=true ;;
    watch) set -- ;;
esac
exec "$controller" -i hermes-local-b.ini hermes-guard-b.yml \
    --extra-vars "capstone_expected_machine_id=$expected" "$@"
