#!/bin/sh
# Operator-only fixed playbook. This is not an MCP/LLM endpoint.
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 syntax|check|apply EXPECTED_A_MACHINE_ID" >&2
    exit 64
fi
operation=$1
expected_machine_id=$2
case "$expected_machine_id" in
    ''|*[!0123456789abcdef]*) echo 'Expected a 32-character lowercase machine ID' >&2; exit 64 ;;
esac
[ "${#expected_machine_id}" -eq 32 ] || exit 64
case "$operation" in syntax|check|apply) ;; *) exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || { echo 'Run on A as the operator root account' >&2; exit 77; }
[ "$(cat /etc/machine-id)" = "$expected_machine_id" ] || { echo 'Machine identity mismatch' >&2; exit 77; }

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
export ANSIBLE_CONFIG="$project_dir/ansible.cfg"
export ANSIBLE_NOCOLOR=1
export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/ansible/tmp
export ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/ansible/remote-tmp
controller=/opt/capstone-automation/venv/bin/ansible-playbook
[ -x "$controller" ] || { echo 'Operator-managed Ansible controller missing' >&2; exit 69; }
umask 077
for state_dir in /var/lib/capstone-automation /var/lib/capstone-automation/ansible "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_REMOTE_TEMP"; do
    [ ! -L "$state_dir" ] || { echo 'Unexpected state directory symlink' >&2; exit 77; }
    if [ -e "$state_dir" ]; then
        [ -d "$state_dir" ] && [ "$(stat -c '%u' "$state_dir")" -eq 0 ] || exit 77
        state_mode=$(stat -c '%a' "$state_dir")
        [ "$((0$state_mode & 0022))" -eq 0 ] || { echo 'State directory writable by another account' >&2; exit 77; }
    else
        mkdir "$state_dir"
    fi
    chmod 700 "$state_dir"
done
lock_path=/var/lib/capstone-automation/ansible/vector.lock
[ ! -L "$lock_path" ] || exit 77
if [ -e "$lock_path" ]; then
    [ -f "$lock_path" ] && [ "$(stat -c '%u' "$lock_path")" -eq 0 ] || exit 77
fi
exec 9>"$lock_path"
flock -n 9 || { echo 'Another Vector deployment is running' >&2; exit 75; }

case "$operation" in
    syntax) set -- --syntax-check ;;
    check) set -- --check --diff ;;
    apply) set -- ;;
esac
exec "$controller" -i inventory/local-a.ini vector-shadow-a.yml vector-storage-a.yml \
    --extra-vars "capstone_expected_machine_id=$expected_machine_id" "$@"
