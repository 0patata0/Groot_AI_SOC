#!/bin/bash
# Fixed operator entry point. Never exposed through MCP or sudoers for an LLM.
set -euo pipefail
[[ $# == 1 ]] || exit 64
case $1 in syntax) flags=(--syntax-check);; check) flags=(--check);; apply) flags=();; *) exit 64;; esac
[[ $(id -u) == 0 && $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 77
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
for path in "$base" "$base/.." /var/lib/capstone-automation /var/lib/capstone-automation/ansible /var/lib/rule-change; do
    [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 ]] || exit 77
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || exit 77
done
for path in "$base/run-b.sh" "$base/apply-b.yml" "$base/../ansible.cfg" "$base/../inventory.ini"; do
    [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %h "$path") == 1 ]] || exit 77
    mode=$(stat -c %a "$path")
    (( (8#$mode & 0022) == 0 )) || exit 77
done
if [[ $1 != syntax ]]; then
    path=$base/preflight.json
    [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %h "$path") == 1 && $(stat -c %a "$path") == 600 ]] || exit 77
fi
# The same ordering as the existing Wazuh operator wrapper; B has no Vector service.
for lock in /var/lib/capstone-automation/ansible/wazuh-vector.lock /var/lib/rule-change/.lock; do
    [[ -f $lock && ! -L $lock && $(stat -c %u "$lock") == 0 && $(stat -c %h "$lock") == 1 ]] || exit 77
    mode=$(stat -c %a "$lock")
    (( (8#$mode & 0022) == 0 )) || exit 77
done
exec 9>>/var/lib/capstone-automation/ansible/wazuh-vector.lock
flock -n 9 || exit 75
exec 8>>/var/lib/rule-change/.lock
flock -n 8 || exit 75
for path in /var/lib/capstone-automation/ansible/tmp /var/lib/capstone-automation/ansible/remote-tmp; do
    [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %a "$path") == 700 ]] || exit 77
done
umask 077
cd "$base"
# A clean environment prevents inherited Ansible plugins/config/extra options.
exec /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root \
    PYTHONDONTWRITEBYTECODE=1 ANSIBLE_CONFIG="$base/../ansible.cfg" ANSIBLE_NOCOLOR=1 \
    ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/ansible/tmp \
    ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/ansible/remote-tmp \
    /opt/capstone-automation/venv/bin/ansible-playbook -i "$base/../inventory.ini" "$base/apply-b.yml" "${flags[@]}"
