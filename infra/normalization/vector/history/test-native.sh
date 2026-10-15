#!/bin/bash
# Synthetic fixtures only. Never calls the real journalctl or touches production state.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $(uname -s) == Linux && $# == 0 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/history-lib.sh"
stage=$(mktemp -d /var/tmp/capstone-history-fixture.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
export JOURNAL_FIXTURE="$stage/input.jsonl" JOURNAL_SCENARIO=normal JOURNAL_CALLS="$stage/calls"
boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
until=2000000000000000
cat > "$stage/journalctl-fixture" <<'SH'
#!/bin/bash
set -euo pipefail
printf 'call\n' >> "$JOURNAL_CALLS"
count=0 start=1 cursor=''
for arg in "$@"; do
    case $arg in
      --lines=+*) count=${arg#--lines=+} ;;
      --cursor=s=*) cursor=${arg#--cursor=s=}; start=$cursor ;;
      --until=@2000000000.000000|--boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|--no-pager|--quiet|--all|--output=json|--output-fields=*|_TRANSPORT=kernel) ;;
      *) exit 91 ;;
    esac
done
[[ $count -gt 0 ]]
case $JOURNAL_SCENARIO in
  timeout) head -n 1 "$JOURNAL_FIXTURE"; sleep 5; exit 0 ;;
  producer_failure) head -n 1 "$JOURNAL_FIXTURE"; exit 7 ;;
  sigpipe) head -n 1 "$JOURNAL_FIXTURE"; exit 141 ;;
  overflow) cat "$JOURNAL_FIXTURE"; exit 0 ;;
  cursor_missing) [[ -z $cursor ]] || start=$((start+1)) ;;
  tail_missing) [[ $cursor != 2 ]] || start=3 ;;
esac
awk -v start="$start" -v count="$count" 'NR>=start && NR<start+count' "$JOURNAL_FIXTURE"
SH
chmod 700 "$stage/journalctl-fixture"
fixture() {
    jq -nc --arg boot "$boot" --argjson count "$1" 'range(1;$count+1) |
      {__CURSOR:("s="+(.|tostring)),__REALTIME_TIMESTAMP:("1000000"),
       __MONOTONIC_TIMESTAMP:(.|tostring),_BOOT_ID:$boot,_TRANSPORT:"kernel",MESSAGE:"synthetic_history_marker"}' \
      > "$JOURNAL_FIXTURE"
    JOURNAL_SCENARIO=normal
}
run() {
    local name=$1 expected=$2; shift 2
    local rc=0
    history_export "$stage/$name" "$stage/journalctl-fixture" "$boot" "$until" "$@" > "$stage/$name.result" || rc=$?
    [[ $rc == "$expected" ]] || { printf 'FAIL %s exit=%s expected=%s\n' "$name" "$rc" "$expected"; exit 1; }
    if [[ $rc == 0 ]]; then jq -e '.status=="complete_batch"' "$stage/$name.result" >/dev/null
    elif [[ $rc == 2 ]]; then jq -e '.status=="partial"' "$stage/$name.result" >/dev/null; fi
}
passed=0
ok() { passed=$((passed+1)); }
fixture 2
run short 0
jq -e '.records==2 and .source_range_exhausted==true' "$stage/short.result" >/dev/null; ok
# A real cap has one more record: a completed batch is not the entire source range.
fixture 1001
run capped 0
jq -e '.records==1000 and .source_range_exhausted==false' "$stage/capped.result" >/dev/null; ok
fixture 1000
run exact_cap 0
jq -e '.records==1000 and .source_range_exhausted==true' "$stage/exact_cap.result" >/dev/null; ok
# Existing bytes are verified and no producer is invoked on a duplicate request.
calls_before=$(wc -l < "$JOURNAL_CALLS")
run exact_cap 0
[[ $(wc -l < "$JOURNAL_CALLS") == "$calls_before" ]]; ok
# Changed completed bytes are refused, never overwritten.
final=$(find "$stage/exact_cap" -maxdepth 1 -type d -name 'batch-*')
chmod 600 "$final/kernel.jsonl"; printf 'tamper\n' >> "$final/kernel.jsonl"; chmod 400 "$final/kernel.jsonl"
rc=0
history_export "$stage/exact_cap" "$stage/journalctl-fixture" "$boot" "$until" >/dev/null 2>&1 || rc=$?
[[ $rc != 0 && $(wc -l < "$JOURNAL_CALLS") == "$calls_before" ]]; ok
fixture 2
JOURNAL_SCENARIO=timeout
run timed 2 1000 33554432 500
jq -e '.reason=="timeout" or .reason=="killed_or_timeout"' "$stage/timed.result" >/dev/null; ok
fixture 2
JOURNAL_SCENARIO=producer_failure
run failed 2
jq -e '.reason=="producer_failed"' "$stage/failed.result" >/dev/null; ok
fixture 2
JOURNAL_SCENARIO=sigpipe
run broken_pipe 2
jq -e '.reason=="producer_sigpipe"' "$stage/broken_pipe.result" >/dev/null; ok
fixture 2
JOURNAL_SCENARIO=cursor_missing
run missing_cursor 2
jq -e '.reason=="first_cursor_unavailable"' "$stage/missing_cursor.result" >/dev/null; ok
fixture 3
JOURNAL_SCENARIO=tail_missing
run missing_tail 2 2
jq -e '.reason=="last_cursor_unavailable"' "$stage/missing_tail.result" >/dev/null; ok
printf '{"incomplete":\n' > "$JOURNAL_FIXTURE"; JOURNAL_SCENARIO=normal
run invalid_json 2
jq -e '.reason=="invalid_json_or_metadata"' "$stage/invalid_json.result" >/dev/null; ok
# awk normally appends LF; use raw overflow branch to preserve this broken source.
fixture 1
truncate -s -1 "$JOURNAL_FIXTURE"; JOURNAL_SCENARIO=overflow
run no_lf 2
jq -e '.reason=="missing_final_lf"' "$stage/no_lf.result" >/dev/null; ok
fixture 1
sed -i 's/"kernel"/"stdout"/' "$JOURNAL_FIXTURE"
run wrong_transport 2
jq -e '.reason=="invalid_json_or_metadata"' "$stage/wrong_transport.result" >/dev/null; ok
fixture 1
sed -i "s/$boot/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/" "$JOURNAL_FIXTURE"
run wrong_boot 2
jq -e '.reason=="invalid_json_or_metadata"' "$stage/wrong_boot.result" >/dev/null; ok
fixture 1
sed -i 's/1000000/2000000000000001/' "$JOURNAL_FIXTURE"
run after_cutoff 2
jq -e '.reason=="invalid_json_or_metadata"' "$stage/after_cutoff.result" >/dev/null; ok
fixture 2
sed -i 's/s=2/s=1/' "$JOURNAL_FIXTURE"
run duplicate_cursor 2
jq -e '.reason=="invalid_json_or_metadata"' "$stage/duplicate_cursor.result" >/dev/null; ok
# Entire capture budget includes boundary verification, not just the retained batch.
fixture 2
size=$(stat -c %s "$JOURNAL_FIXTURE")
run proof_budget 2 1000 "$size"
jq -e '.reason=="byte_budget"' "$stage/proof_budget.result" >/dev/null; ok
# A small cap tests both buffered producer exit 0 and larger SIGPIPE producers.
fixture 2; JOURNAL_SCENARIO=overflow
run buffered_overflow 2 1000 50
jq -e '.reason=="byte_budget" and .bytes==50' "$stage/buffered_overflow.result" >/dev/null; ok
head -c 34603008 /dev/zero | tr '\0' x > "$JOURNAL_FIXTURE"
JOURNAL_SCENARIO=overflow
run actual_32m_cap 2
jq -e '.reason=="byte_budget" and .bytes==33554432' "$stage/actual_32m_cap.result" >/dev/null; ok
partial=$(find "$stage/actual_32m_cap" -maxdepth 1 -type d -name 'partial-*')
jq -e '.producer_exit==141 and .consumer_exit==0' "$partial/manifest.json" >/dev/null; ok
# Retry creates a fresh partial attempt, preserving the previous bytes and manifest.
run actual_32m_cap 2
[[ $(find "$stage/actual_32m_cap" -maxdepth 1 -type d -name 'partial-*' | wc -l) == 2 ]]; ok
fixture 0
run empty 2
jq -e '.reason=="empty_range_unproven"' "$stage/empty.result" >/dev/null; ok
# No writable/symlink destination is accepted.
mkdir -m 755 "$stage/public"
rc=0; history_export "$stage/public" "$stage/journalctl-fixture" "$boot" "$until" >/dev/null 2>&1 || rc=$?
[[ $rc != 0 ]]; ok
ln -s "$stage/short" "$stage/symlink"
rc=0; history_export "$stage/symlink" "$stage/journalctl-fixture" "$boot" "$until" >/dev/null 2>&1 || rc=$?
[[ $rc != 0 ]]; ok
# Metadata-only stdout: the raw marker and opaque cursor are not exported.
! grep -qE 'synthetic_history_marker|s=' "$stage"/*.result; ok
jq -nc --argjson tests "$passed" '{suite:"native_previous_boot_synthetic",passed:$tests,failed:0,
  real_journal_read:false,production_execution:false,raw_payload_exported:false,packages_installed:false}'
