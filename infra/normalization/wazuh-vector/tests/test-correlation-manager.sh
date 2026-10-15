#!/bin/sh
# Synthetic JSON only. One native session per scenario; never injects live logs.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker=/usr/local/bin/docker
manager=single-node-wazuh.manager-1
umask 077
output=$(mktemp /var/tmp/capstone-vector-correlation-logtest.XXXXXX)
trap 'rm -f "$output"' EXIT HUP INT TERM
count=0
while IFS='|' read -r fixture location_kind expected; do
    case "$fixture" in ''|'#'*) continue ;; esac
    case "$location_kind" in
        ready) location='(groot-sec) any->/var/log/capstone-vector/ready/normalized.jsonl' ;;
        canary) location='(groot-sec) any->/var/log/capstone-vector/canary/normalized.jsonl' ;;
        *) echo 'FAIL invalid test location' >&2; exit 1 ;;
    esac
    "$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -l "$location" \
        < "$project_dir/fixtures/correlation/$fixture.jsonl" > "$output" 2>&1
    if grep -Eq '(ERROR|CRITICAL):' "$output"; then
        echo "FAIL native correlation diagnostic: $fixture" >&2
        exit 1
    fi
    actual=$(sed -n "s/^[[:space:]]*id: '\([0-9][0-9]*\)'.*/\1/p" "$output" | paste -sd ' ' -)
    if [ "$actual" != "$expected" ]; then
        echo "FAIL $fixture expected_ids=[$expected] actual_ids=[$actual]" >&2
        exit 1
    fi
    count=$((count + 1))
    echo "PASS $fixture rule_ids=[$actual]"
done < "$project_dir/fixtures/correlation/expected.tsv"
echo "PASS native_correlation_scenarios=$count"
