#!/bin/bash
# Fixed administrator-only prepare. No Docker create/start/restart or source rebinding.
# Serialize participating operators; this is not exclusion of arbitrary manual root edits.
set -euo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
[[ $# == 1 && $1 =~ ^(syntax|apply)$ ]] || exit 64
[[ $(id -u) == 0 && $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for directory in "$project" "$project/inventory" /var/lib/rule-change /var/lib/capstone-automation /var/lib/capstone-automation/ansible; do
  [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || exit 77
  mode=$(stat -c %a "$directory"); (( (8#$mode & 0022) == 0 )) || exit 77
done
for file in waf-persistence-prepare-a.yml waf-persistence-prepare-local-a.sh ansible.cfg inventory/local-a.ini; do
  [[ -f $project/$file && ! -L $project/$file && $(stat -c '%u:%g:%h' "$project/$file") == 0:0:1 ]] || exit 77
  mode=$(stat -c %a "$project/$file"); (( (8#$mode & 0022) == 0 )) || exit 77
done
# Exact reviewed play SHA; no environment/argument override.
expected_play_sha=b9796bb01608ce42650edb3581de11f1b024051efd76f1ab2191c4384bb296cc
[[ $(sha256sum "$project/waf-persistence-prepare-a.yml" | cut -d ' ' -f 1) == "$expected_play_sha" ]] || exit 77
[[ $(sha256sum "$project/ansible.cfg" | cut -d ' ' -f 1) == 89a4bde4e9ed9d17bb621097a24214ade588b23cee1c779f7544f1455cc1746a ]] || exit 77
[[ $(sha256sum "$project/inventory/local-a.ini" | cut -d ' ' -f 1) == 592adf39e7e0a8b729f66c16a0ca005917d30c6c2ed4bf73df813fb9b1d3acd5 ]] || exit 77
for lock in /var/lib/rule-change/.lock /var/lib/capstone-automation/ansible/vector.lock; do
  [[ -f $lock && ! -L $lock && $(stat -c '%u:%g:%h' "$lock") == 0:0:1 ]] || exit 77
  mode=$(stat -c %a "$lock"); (( (8#$mode & 0022) == 0 )) || exit 77
done
exec 8<>/var/lib/rule-change/.lock
flock -n 8 || exit 75
exec 9<>/var/lib/capstone-automation/ansible/vector.lock
flock -n 9 || exit 75
export ANSIBLE_CONFIG="$project/ansible.cfg" ANSIBLE_NOCOLOR=1
export ANSIBLE_LOCAL_TEMP=/var/lib/capstone-automation/ansible/tmp
export ANSIBLE_REMOTE_TEMP=/var/lib/capstone-automation/ansible/remote-tmp
export PYTHONDONTWRITEBYTECODE=1
for directory in "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_REMOTE_TEMP"; do
  [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 ]] || exit 77
  mode=$(stat -c %a "$directory"); (( (8#$mode & 0022) == 0 )) || exit 77
done
cd -- "$project"
args=(--extra-vars waf_prepare_operator_lock=true)
[[ $1 != syntax ]] || args+=(--syntax-check)
exec /opt/capstone-automation/venv/bin/ansible-playbook -i inventory/local-a.ini \
  waf-persistence-prepare-a.yml "${args[@]}"
