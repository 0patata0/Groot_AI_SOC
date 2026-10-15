#!/bin/sh
# Operator-only fixed Ansible entrypoint. Never add this to MCP/sudoers.
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[ "$(id -u)" -eq 0 ] || exit 77
[ "$(cat /etc/machine-id)" = 096e90b6243e438aa8a7b392be754732 ] || exit 77
[ "$#" -eq 1 ] || exit 64
case "$1" in syntax) mode=--syntax-check ;; apply) mode= ;; *) exit 64 ;; esac
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"
[ ! -L "$project_dir" ] && [ "$(stat -c '%u' "$project_dir")" -eq 0 ] || exit 77
project_mode=$(stat -c '%a' "$project_dir")
[ "$((0$project_mode & 0022))" -eq 0 ] || exit 77
for f in apply-a.yml ansible.cfg inventory.ini REQUEST-900-CAPSTONE-SCANNER.conf; do
    [ -f "$f" ] && [ ! -L "$f" ] || exit 77
    [ "$(stat -c '%u:%h' "$f")" = 0:1 ] || exit 77
    source_mode=$(stat -c '%a' "$f")
    [ "$((0$source_mode & 0022))" -eq 0 ] || exit 77
done
umask 077
export ANSIBLE_CONFIG="$project_dir/ansible.cfg"
export ANSIBLE_NOCOLOR=1
export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/ansible/tmp
export ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/ansible/remote-tmp
export PYTHONDONTWRITEBYTECODE=1
for d in /var/lib/rule-change /var/lib/capstone-automation/ansible; do
    [ -d "$d" ] && [ ! -L "$d" ] || exit 77
    [ "$(stat -c '%u' "$d")" -eq 0 ] || exit 77
    permissions=$(stat -c '%a' "$d")
    [ "$((0$permissions & 0022))" -eq 0 ] || exit 77
done
for lock in /var/lib/rule-change/.lock /var/lib/capstone-automation/ansible/vector.lock; do
    [ -f "$lock" ] && [ ! -L "$lock" ] || exit 77
    [ "$(stat -c '%u' "$lock")" -eq 0 ] && [ "$(stat -c '%h' "$lock")" -eq 1 ] || exit 77
done
exec 8>>/var/lib/rule-change/.lock
flock -n 8 || exit 75
exec 9>>/var/lib/capstone-automation/ansible/vector.lock
flock -n 9 || exit 75
if [ -n "$mode" ]; then
    exec /opt/capstone-automation/venv/bin/ansible-playbook -i inventory.ini apply-a.yml "$mode"
fi
exec /opt/capstone-automation/venv/bin/ansible-playbook -i inventory.ini apply-a.yml
