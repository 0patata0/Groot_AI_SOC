#!/bin/sh
# Fixed operator playbooks. Not exposed to the LLM or MCP.
set -eu
[ "$(id -u)" -eq 0 ] || exit 77
[ "$#" -eq 2 ] || { echo 'Usage: run-local.sh a|b syntax|check|apply' >&2; exit 64; }
case "$1" in
    a) expected=096e90b6243e438aa8a7b392be754732 ;;
    b) expected=1e143067c98a44ffba6eaa925dc038d7 ;;
    *) exit 64 ;;
esac
target=$1
case "$2" in syntax|check|apply) operation=$2 ;; *) exit 64 ;; esac
[ "$(cat /etc/machine-id)" = "$expected" ] || { echo 'Machine identity mismatch' >&2; exit 77; }
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
export ANSIBLE_CONFIG="$project_dir/ansible.cfg"
export ANSIBLE_NOCOLOR=1
export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/ansible/tmp
export ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/ansible/remote-tmp
umask 077
for state_dir in /var/lib/capstone-automation /var/lib/capstone-automation/ansible "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_REMOTE_TEMP"; do
    [ ! -L "$state_dir" ] || exit 77
    if [ -e "$state_dir" ]; then
        [ -d "$state_dir" ] && [ "$(stat -c '%u' "$state_dir")" -eq 0 ] || exit 77
        state_mode=$(stat -c '%a' "$state_dir")
        [ "$((0$state_mode & 0022))" -eq 0 ] || exit 77
    else
        mkdir "$state_dir"
    fi
    chmod 700 "$state_dir"
done
lock=/var/lib/capstone-automation/ansible/wazuh-vector.lock
[ ! -L "$lock" ] || exit 77
if [ -e "$lock" ]; then
    [ -f "$lock" ] && [ "$(stat -c '%u' "$lock")" -eq 0 ] || exit 77
fi
exec 9>"$lock"
flock -n 9 || { echo 'Wazuh deployment already running' >&2; exit 75; }
# Serialize with the existing privileged approval worker, not just this playbook.
worker_dir=/var/lib/rule-change
worker_lock=$worker_dir/.lock
[ -d "$worker_dir" ] && [ ! -L "$worker_dir" ] || exit 77
[ "$(stat -c '%u' "$worker_dir")" -eq 0 ] || exit 77
worker_mode=$(stat -c '%a' "$worker_dir")
[ "$((0$worker_mode & 0022))" -eq 0 ] || exit 77
[ -f "$worker_lock" ] && [ ! -L "$worker_lock" ] || exit 77
[ "$(stat -c '%u' "$worker_lock")" -eq 0 ] || exit 77
[ "$(stat -c '%h' "$worker_lock")" -eq 1 ] || exit 77
exec 8>>"$worker_lock"
flock -n 8 || { echo 'Approval worker is applying another change; retry later' >&2; exit 75; }
case "$operation" in
    syntax) set -- --syntax-check ;;
    check) set -- --check ;;
    apply) set -- ;;
esac
exec /opt/capstone-automation/venv/bin/ansible-playbook -i inventory.ini "apply-$target.yml" "$@"
