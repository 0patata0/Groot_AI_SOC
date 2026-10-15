#!/bin/bash
# Root operator only; serializes with Vector maintenance, Wazuh deployment and approvals.
set -euo pipefail
[[ $(id -u) == 0 && $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
[[ $# == 1 ]] || exit 64
case $1 in syntax) options=(--syntax-check);; apply) options=();; *) exit 64;; esac
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for lock in /var/lib/capstone-automation/ansible/vector.lock /var/lib/capstone-automation/ansible/wazuh-vector.lock /var/lib/rule-change/.lock; do
    [[ -f $lock && ! -L $lock && $(stat -c '%u' "$lock") == 0 && $(stat -c '%h' "$lock") == 1 ]] || exit 77
done
exec 9>>/var/lib/capstone-automation/ansible/vector.lock
flock -n 9 || exit 75
exec 8>>/var/lib/capstone-automation/ansible/wazuh-vector.lock
flock -n 8 || exit 75
exec 7>>/var/lib/rule-change/.lock
flock -n 7 || exit 75
export ANSIBLE_CONFIG="$base/../ansible.cfg" ANSIBLE_NOCOLOR=1
export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/ansible/tmp
export ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/ansible/remote-tmp
export PYTHONDONTWRITEBYTECODE=1
umask 077
exec /opt/capstone-automation/venv/bin/ansible-playbook -i "$base/../inventory.ini" "$base/apply-a.yml" "${options[@]}"
