#!/bin/sh
# Existing manager native logtest only. Never append a fixture to collected files.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker=/usr/local/bin/docker
manager=single-node-wazuh.manager-1
umask 077
output=$(mktemp /var/tmp/capstone-vector-evidence-logtest.XXXXXX)
trap 'rm -f "$output"' EXIT HUP INT TERM
count=0
while IFS='|' read -r fixture location_kind expected; do
    case "$fixture" in ''|'#'*) continue ;; esac
    case "$location_kind" in
        evidence|ready|canary) location="(groot-sec) any->/var/log/capstone-vector/$location_kind/normalized.jsonl" ;;
        other-agent) location='(groot-web) any->/var/log/capstone-vector/evidence/normalized.jsonl' ;;
        bare) location='/var/log/capstone-vector/evidence/normalized.jsonl' ;;
        unrelated) location='/var/log/unrelated.jsonl' ;;
        *) echo 'FAIL invalid evidence fixture location' >&2; exit 1 ;;
    esac
    "$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -l "$location" \
        < "$project_dir/fixtures/evidence/$fixture.jsonl" > "$output" 2>&1
    grep -q "name: 'json'" "$output"
    if grep -Eq '(ERROR|CRITICAL):' "$output"; then
        echo "FAIL native evidence diagnostic: $fixture" >&2; exit 1
    fi
    actual=$(sed -n "s/^[[:space:]]*id: '\([0-9][0-9]*\)'.*/\1/p" "$output" | paste -sd ' ' -)
    if [ "$expected" = reject ]; then
        case " $actual " in *' 100261 '*|*' 100262 '*)
            echo "FAIL evidence rejection: $fixture" >&2; exit 1 ;; esac
    elif [ "$actual" != "$expected" ] || ! grep -q "level: '3'" "$output"; then
        echo "FAIL evidence fixture=$fixture expected=$expected actual=[$actual]" >&2; exit 1
    fi
    count=$((count + 1))
    echo "PASS evidence fixture=$fixture expectation=$expected"
done < "$project_dir/fixtures/evidence/expected.tsv"
echo "PASS native_evidence_scenarios=$count"
