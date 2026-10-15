#!/bin/sh
# This performs one real apply, then repeats it and requires changed=0.
# Run only after the operator has reviewed the candidate and authorized deploy.
set -eu
[ "$#" -eq 1 ] || { echo "Usage: $0 EXPECTED_A_MACHINE_ID" >&2; exit 64; }
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_log=$(mktemp /var/tmp/capstone-ansible-idempotency.XXXXXX)
trap 'rm -f "$test_log"' EXIT HUP INT TERM
sh "$project_dir/run-vector-local-a.sh" apply "$1"
sh "$project_dir/run-vector-local-a.sh" apply "$1" >"$test_log" 2>&1 || {
    cat "$test_log"
    exit 1
}
cat "$test_log"
awk '/^localhost[[:space:]]*:/ && /changed=0/ && /unreachable=0/ && /failed=0/ {ok=1} END {exit !ok}' "$test_log"
echo 'Second apply: changed=0, unreachable=0, failed=0'
