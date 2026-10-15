#!/bin/bash
# Fixed A observer. No env/config evaluation, logger, service or checkpoint writes.
set -euo pipefail
PATH=/usr/bin:/bin; export PATH LC_ALL=C TZ=Asia/Seoul
umask 077
[[ $EUID == 0 && $OSTYPE == linux* && $# == 1 && $1 == check ]] || exit 77
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
library=/etc/capstone-vector/line-length-lib.sh
predicate=/etc/capstone-vector/raw-line-status.jq
for parent in /etc /etc/capstone-vector; do
    [[ -d $parent && ! -L $parent && $(stat -c %u "$parent") == 0 ]] || exit 77
    mode=$(stat -c %a "$parent"); (( (8#$mode & 0022)==0 )) || exit 77
done
for file in "$library" "$predicate"; do
    [[ -f $file && ! -L $file && $(stat -c '%u:%h' "$file") == 0:1 ]] || exit 77
    mode=$(stat -c %a "$file"); (( (8#$mode & 0022)==0 )) || exit 77
done
# shellcheck source=./line-length-lib.sh
source "$library"
suricata=$(ll_scan /home/groot_a/capstone/secstack/logs/suricata/eve.json 998 998 644 1048576 33554432 5)
audit=$(ll_scan /home/groot_a/capstone/secstack/logs/modsec/audit.log 101 101 644 1048576 33554432 5)
access=$(ll_scan /home/groot_a/capstone/secstack/logs/modsec/capstone-access.log 101 101 640 1048576 33554432 5)
result=$(jq -nc --arg at "$(date --iso-8601=seconds)" --argjson suricata "$suricata" --argjson audit "$audit" --argjson access "$access" \
  '{schema_version:1,scope:"periodic_snapshot_tail",observed_at_kst:$at,
    sources:[$suricata+{source:"suricata"},$audit+{source:"waf_audit"},$access+{source:"waf_access"}]}')
statuses=$(jq -c -f "$predicate" <<< "$result")
jq -c --argjson statuses "$statuses" '.+{statuses:$statuses}' <<< "$result"
