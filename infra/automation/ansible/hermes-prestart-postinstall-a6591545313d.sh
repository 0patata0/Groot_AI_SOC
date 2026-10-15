#!/bin/bash
# One observed install postcondition only. Reads back files; never recopies into candidate or changes lifecycle.
set -euo pipefail
[[ $# == 1 && $1 =~ ^(syntax|apply)$ ]] || exit 64
[[ $(id -u) == 0 && $(cat /etc/machine-id) == 1e143067c98a44ffba6eaa925dc038d7 ]] || exit 77
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
lock=/var/lib/capstone-automation/hermes-guard/apply.lock
for p in /var/lib/capstone-automation /var/lib/capstone-automation/hermes-guard; do
    [[ ! -L $p && -d $p && $(stat -c %u "$p") == 0 ]] || exit 77
    mode=$(stat -c %a "$p"); (( (8#$mode & 0022) == 0 )) || exit 77
done
[[ ! -L $lock && -f $lock && $(stat -c '%u:%g:%a:%h' "$lock") == 0:0:600:1 ]] || exit 77
exec 9<>"$lock"
flock -n 9 || exit 75
export ANSIBLE_CONFIG="$project/ansible.cfg" ANSIBLE_NOCOLOR=1
export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/hermes-guard/tmp
export ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/hermes-guard/remote-tmp
export PYTHONDONTWRITEBYTECODE=1
cd -- "$project"
args=()
[[ $1 != syntax ]] || args+=(--syntax-check)
exec /opt/capstone-automation/venv/bin/ansible-playbook -i hermes-local-b.ini \
    hermes-prestart-postinstall-a6591545313d.yml "${args[@]}"
