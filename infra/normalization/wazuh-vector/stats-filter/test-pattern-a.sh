#!/bin/bash
# No synthetic row enters an operational log or Wazuh queue.
set -euo pipefail
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
pattern=$(cat "$base/stats-pattern.txt")
installed_pattern=$(sed -n 's/.*<ignore type="PCRE2">\(.*\)<\/ignore>.*/\1/p' "$base/after.xml")
[[ $pattern == "$installed_pattern" ]] || { echo "FAIL: XML and tested pattern differ" >&2; exit 1; }
positive='{"timestamp":"2026-10-14T04:00:00.000000+0900","event_type":"stats","stats":{"uptime":1}}'
printf '%s\n' "$positive" | grep -Pq -- "$pattern"
for negative in \
  '{"timestamp":"2026-10-14T04:00:00.000000+0900","event_type":"alert","alert":{"signature":"stats"}}' \
  '{"timestamp":"2026-10-14T04:00:00.000000+0900","event_type":"flow","flow":{"pkts_toserver":1}}' \
  '{"timestamp":"2026-10-14T04:00:00.000000+0900","event_type":"http","http":{"url":"/event_type/stats"}}' \
  '{"event_type":"alert","nested":{"event_type":"stats","stats":{}}}' \
  '{"timestamp":"2026-10-14T04:00:00.000000+0900","event_type":"stats-other","stats":{}}' \
  '{"timestamp":"2026-10-14T04:00:00.000000+0900","event_type":"stats","stats":"unexpected"}' \
  'prefix {"timestamp":"2026-10-14T04:00:00.000000+0900","event_type":"stats","stats":{}}'; do
    if printf '%s\n' "$negative" | grep -Pq -- "$pattern"; then
        echo 'FAIL: security or noncanonical event matched stats filter' >&2
        exit 1
    fi
done
echo 'PASS PCRE2: canonical stats matched; seven negative boundaries preserved'
