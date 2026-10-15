#!/bin/bash
# Manual synthetic health check only. No raw/ready source, packet, or chat writes.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
[[ ( $# == 1 || $# == 2 ) && $1 =~ ^[0-9a-f]{32}$ && $(id -u) == 0 ]] || exit 64
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
run_id=$1
delivery_mode=${2:-paced}
[[ $delivery_mode == paced || $delivery_mode == burst ]] || exit 64
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ -f $project_dir/tests/canary-append-lib.sh && ! -L $project_dir/tests/canary-append-lib.sh ]] || exit 77
source "$project_dir/tests/canary-append-lib.sh"
path=/var/log/capstone-vector/canary/normalized.jsonl
for directory in /var/log/capstone-vector /var/log/capstone-vector/canary; do
    [[ -d $directory && ! -L $directory && $(stat -c %u "$directory") == 0 && $(stat -c %a "$directory") == 700 ]] || exit 77
done
[[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 && $(stat -c %a "$path") == 600 && $(stat -c %h "$path") == 1 ]] || exit 77
[[ $(stat -c %s "$path") -le 10485760 ]] || { echo 'FAIL canary file maintenance required' >&2; exit 1; }
systemctl is-active --quiet wazuh-agent.service
identity=$(stat -c '%d:%i' "$path")
opened=0
while read -r pid; do
    for fd in /proc/"$pid"/fd/[0-9]*; do
        fd_identity=$(stat -Lc '%d:%i' "$fd" 2>/dev/null) || continue
        if [[ $fd_identity == "$identity" ]]; then opened=$((opened+1)); fi
    done
done < <(pgrep -x wazuh-logcollec || true)
[[ $opened == 1 ]] || { echo 'FAIL canary input is not open exactly once' >&2; exit 1; }
exec 9>> "$path"
flock -n 9 || exit 75
[[ $(stat -c '%d:%i' "$path") == "$identity" && $(stat -Lc '%d:%i' /proc/$$/fd/9) == "$identity" ]] || exit 77
if grep -Fq "$run_id" "$path"; then echo 'FAIL canary run ID already used' >&2; exit 1; fi
payload=$(mktemp /var/tmp/capstone-vector-canary.XXXXXX)
trap 'rm -f "$payload"' EXIT HUP INT TERM
stamp=$(TZ=Asia/Seoul date '+%Y-%m-%dT%H:%M:%S.000000+09:00')
for scenario in canary-repeat canary-cross canary-repeat-duplicate canary-historical; do
    key=$(printf '%s:%s' "$run_id" "$scenario" | sha256sum | cut -d ' ' -f1)
    jq -c --arg rid "$run_id" --arg stamp "$stamp" --arg key "$key" --arg scenario "$scenario" '
      .capstone_validation.run_id=$rid
      | .capstone_validation.scenario=$scenario
      | .capstone_norm.correlation_key=$key
      | .capstone_norm.observed_at_kst=$stamp
      | if .capstone_norm.correlation_time_class=="fresh" then .capstone_norm.event_time_kst=$stamp else . end
    ' "$project_dir/fixtures/correlation/$scenario.jsonl" >> "$payload"
done
[[ $(wc -l < "$payload") == 13 ]] || exit 1
bytes=$(wc -c < "$payload")
[[ $bytes -le 32768 ]] || exit 1
# Keep the cross-source precursor (row 6) ahead of its nft follow-up (row 7).
# A burst is not an ordering/receipt contract: the 2026-10-14 burst produced
# the repeat alert but no cross alert, while the same 13 rows passed logtest.
# This pause is only a diagnostic pacing control, never a manager ACK.
[[ $(jq -sr '.[5].capstone_norm.source' "$payload") == suricata ]]
[[ $(jq -sr '.[6].capstone_norm.source' "$payload") == nftables ]]
append_result=$(capstone_canary_append "$path" "$payload" "$delivery_mode" "$identity")
jq -c --arg run_id "$run_id" \
    '. + {run_id:$run_id,expected_manager_alerts:2,expected_indexer_documents:2,
      source:"manual_canary_file",pause_is_not_analysis_ack:true,e2e_verified:false}' <<< "$append_result"
