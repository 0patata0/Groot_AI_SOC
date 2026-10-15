#!/bin/sh
# Only synthetic fixtures enter native logtest. No operational input is written.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker=/usr/local/bin/docker
manager=single-node-wazuh.manager-1
location='(groot-sec) any->/var/log/capstone-vector/ready/normalized.jsonl'
umask 077
output=$(mktemp /var/tmp/capstone-vector-logtest.XXXXXX)
trap 'rm -f "$output"' EXIT HUP INT TERM
for fixture in positive-suricata positive-nftables positive-modsecurity; do
    if ! "$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -U 100200:1:json -l "$location" \
        < "$project_dir/fixtures/$fixture.jsonl" > "$output" 2>&1; then
        echo "FAIL native logtest: $fixture" >&2
        exit 1
    fi
    if grep -Eq '(ERROR|CRITICAL):' "$output"; then
        echo "FAIL native logtest diagnostic: $fixture" >&2
        exit 1
    fi
    echo "PASS $fixture rule=100200 level=1 decoder=json"
done
for fixture in wrong-schema wrong-pipeline wrong-source; do
    "$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -l "$location" \
        < "$project_dir/fixtures/$fixture.jsonl" > "$output" 2>&1
    grep -q "name: 'json'" "$output"
    if grep -Eq "id: '100200'|(ERROR|CRITICAL):" "$output"; then
        echo "FAIL negative logtest: $fixture" >&2
        exit 1
    fi
    echo "PASS $fixture does_not_match_100200"
done
"$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -l /var/log/unrelated.jsonl \
    < "$project_dir/fixtures/positive-suricata.jsonl" > "$output" 2>&1
grep -q "name: 'json'" "$output"
if grep -Eq "id: '100200'|(ERROR|CRITICAL):" "$output"; then
    echo 'FAIL negative logtest: wrong-location' >&2
    exit 1
fi
echo 'PASS wrong-location does_not_match_100200'

for location in '(groot-web) any->/var/log/capstone-vector/ready/normalized.jsonl' '/var/log/capstone-vector/ready/normalized.jsonl'; do
    "$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -l "$location" \
        < "$project_dir/fixtures/positive-suricata.jsonl" > "$output" 2>&1
    if grep -Eq "id: '100200'|(ERROR|CRITICAL):" "$output"; then
        echo 'FAIL normalized transport identity boundary' >&2; exit 1
    fi
    echo 'PASS normalized transport identity rejected'
done
