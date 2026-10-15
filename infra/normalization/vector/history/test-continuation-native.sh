#!/bin/bash
# A native synthetic test only. This never invokes real journalctl or operational state.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $(uname -s) == Linux && $# == 0 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/history-lib.sh"
source "$directory/continuation-lib.sh"
stage=$(mktemp -d /var/tmp/capstone-history-continuation-fixture.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
export JOURNAL_FIXTURE="$stage/input.jsonl" JOURNAL_SCENARIO=normal JOURNAL_CALLS="$stage/calls"
boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa until=1790000000000000
jq -nc --arg boot "$boot" 'range(1;2502) |
  {__CURSOR:("s="+(.|tostring)),__REALTIME_TIMESTAMP:"1000000",__MONOTONIC_TIMESTAMP:(.|tostring),
   _BOOT_ID:$boot,_TRANSPORT:"kernel",MESSAGE:"synthetic_continuation_marker"}' > "$JOURNAL_FIXTURE"
cat > "$stage/journalctl-fixture" <<'SH'
#!/bin/bash
set -euo pipefail
count=0 start=1 mode=initial cursor=''
for arg in "$@"; do
    case $arg in
      --lines=+*) count=${arg#--lines=+} ;;
      --cursor=s=*) cursor=${arg#--cursor=s=}; start=$cursor; mode=inclusive ;;
      --after-cursor=s=*) cursor=${arg#--after-cursor=s=}; start=$((cursor+1)); mode=after ;;
      --until=@1790000000.000000|--boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|--no-pager|--quiet|--all|--output=json|--output-fields=*|_TRANSPORT=kernel) ;;
      *) exit 91 ;;
    esac
done
[[ $count -gt 0 ]]
printf '%s:%s:%s\n' "$mode" "$start" "$count" >> "$JOURNAL_CALLS"
case $JOURNAL_SCENARIO in
  boundary_missing) [[ $mode != inclusive || $cursor != 1000 ]] || start=1001 ;;
  nearest_before) [[ $mode != inclusive || $cursor != 1000 ]] || start=999 ;;
  late_parent_missing) [[ $mode != inclusive || $cursor != 1000 || $count != 1 ]] || start=1001 ;;
  tail_missing) [[ $mode != inclusive || $cursor != 2000 ]] || start=2001 ;;
  after_skip) [[ $mode != after ]] || start=$((start+1)) ;;
  after_repeat) [[ $mode != after ]] || start=$cursor ;;
  no_next) [[ $mode != inclusive || $cursor != 1000 ]] || count=1 ;;
  malformed) if [[ $mode == after ]]; then printf '{broken\n'; exit 0; fi ;;
  no_lf) if [[ $mode == after ]]; then printf '{}'; exit 0; fi ;;
  timeout) if [[ $mode == after ]]; then sleep 30; exit 0; fi ;;
  producer_failure) if [[ $mode == after ]]; then exit 7; fi ;;
  overflow) if [[ $mode == after ]]; then head -c 34603008 /dev/zero | tr '\0' x; exit 0; fi ;;
esac
awk -v start="$start" -v count="$count" 'NR>=start && NR<start+count' "$JOURNAL_FIXTURE"
SH
chmod 700 "$stage/journalctl-fixture"
history_export "$stage/original" "$stage/journalctl-fixture" "$boot" "$until" > "$stage/first.result"
parent_id=$(jq -r .batch_id "$stage/first.result")
parent_sha=$(jq -r .sha256 "$stage/first.result")
parent_manifest_sha=$(sha256sum "$stage/original/batch-$parent_id/manifest.json" | cut -d ' ' -f1)
passed=0
ok() { passed=$((passed+1)); }
newstore() {
    mkdir -m 700 "$stage/$1"
    cp -a "$stage/original/." "$stage/$1/"
}
run() {
    local name=$1 expected=$2 rc=0
    /bin/bash "$directory/continue-run.sh" "$stage/$name" "$stage/journalctl-fixture" "$parent_id" "$parent_sha" "$parent_manifest_sha" > "$stage/$name.result" || rc=$?
    [[ $rc == "$expected" ]] || { printf 'FAIL %s exit=%s expected=%s\n' "$name" "$rc" "$expected"; exit 1; }
}
newstore complete
run complete 0
child_id=$(jq -r .batch_id "$stage/complete.result")
child=$stage/complete/batch-$child_id
jq -e '.records==1000 and .source_range_exhausted==false and .record_metadata.first_cursor=="s=1001" and .record_metadata.last_cursor=="s=2000" and .continuation_boundary_verified==true' "$child/manifest.json" >/dev/null; ok
# Parent source bytes and manifest are unchanged; the child excludes all parent cursors.
[[ $(sha256sum "$stage/complete/batch-$parent_id/kernel.jsonl" | cut -d ' ' -f1) == "$parent_sha" ]]
[[ $(sha256sum "$stage/complete/batch-$parent_id/manifest.json" | cut -d ' ' -f1) == "$parent_manifest_sha" ]]
jq -se '([.[0:1000][].__CURSOR] - [.[1000:][].__CURSOR])|length==1000' \
  "$stage/complete/batch-$parent_id/kernel.jsonl" "$child/kernel.jsonl" >/dev/null; ok
calls_before=$(wc -l < "$JOURNAL_CALLS")
child_sha=$(sha256sum "$child/kernel.jsonl" | cut -d ' ' -f1)
run complete 0
[[ $(wc -l < "$JOURNAL_CALLS") == "$calls_before" && $(sha256sum "$child/kernel.jsonl" | cut -d ' ' -f1) == "$child_sha" ]]; ok
child_manifest_sha=$(sha256sum "$child/manifest.json" | cut -d ' ' -f1)
/bin/bash "$directory/continue-run.sh" "$stage/complete" "$stage/journalctl-fixture" "$child_id" "$child_sha" "$child_manifest_sha" > "$stage/grandchild.result"
grandchild_id=$(jq -r .batch_id "$stage/grandchild.result")
grandchild=$stage/complete/batch-$grandchild_id
jq -e '.records==501 and .source_range_exhausted==true and .record_metadata.first_cursor=="s=2001" and .record_metadata.last_cursor=="s=2501"' "$grandchild/manifest.json" >/dev/null; ok
rc=0
/bin/bash "$directory/continue-run.sh" "$stage/complete" "$stage/journalctl-fixture" "$grandchild_id" \
  "$(sha256sum "$grandchild/kernel.jsonl" | cut -d ' ' -f1)" "$(sha256sum "$grandchild/manifest.json" | cut -d ' ' -f1)" > "$stage/exhausted.result" || rc=$?
[[ $rc == 65 ]]; jq -e '.reason=="parent_already_exhausted"' "$stage/exhausted.result" >/dev/null; ok
for scenario in boundary_missing nearest_before late_parent_missing tail_missing after_skip after_repeat no_next malformed no_lf producer_failure overflow timeout; do
    newstore "$scenario"; JOURNAL_SCENARIO=$scenario
    run "$scenario" 2
    jq -e '.status=="partial" and .source_range_exhausted==null' "$stage/$scenario.result" >/dev/null
    [[ $(find "$stage/$scenario" -maxdepth 1 -type d -name 'batch-*' | wc -l) == 1 ]]
    ok
done
JOURNAL_SCENARIO=overflow
run overflow 2
[[ $(find "$stage/overflow" -maxdepth 1 -type d -name 'partial-*' | wc -l) == 2 ]]; ok
for scenario in payload_tamper manifest_tamper metadata_tamper id_tamper wrong_manifest_sha; do
    newstore "$scenario"; JOURNAL_SCENARIO=normal
    p=$stage/$scenario/batch-$parent_id
    case $scenario in
      payload_tamper) chmod 600 "$p/kernel.jsonl"; printf 'x' >> "$p/kernel.jsonl"; chmod 400 "$p/kernel.jsonl" ;;
      manifest_tamper) chmod 600 "$p/manifest.json"; printf '\n' >> "$p/manifest.json"; chmod 400 "$p/manifest.json" ;;
      metadata_tamper|id_tamper)
        if [[ $scenario == metadata_tamper ]]; then filter='.record_metadata.last_cursor="s=999"'; else filter='.until_epoch_us="1780000000000000"'; fi
        jq "$filter" "$p/manifest.json" > "$p/changed"; chmod 400 "$p/changed"; mv "$p/changed" "$p/manifest.json"
        ;;
      wrong_manifest_sha) ;;
    esac
    expected_manifest=$parent_manifest_sha
    if [[ $scenario == metadata_tamper || $scenario == id_tamper ]]; then expected_manifest=$(sha256sum "$p/manifest.json" | cut -d ' ' -f1)
    elif [[ $scenario == wrong_manifest_sha ]]; then expected_manifest=$(printf wrong | sha256sum | cut -d ' ' -f1); fi
    calls_before=$(wc -l < "$JOURNAL_CALLS")
    rc=0
    /bin/bash "$directory/continue-run.sh" "$stage/$scenario" "$stage/journalctl-fixture" "$parent_id" "$parent_sha" "$expected_manifest" > "$stage/$scenario.result" || rc=$?
    [[ $rc == 65 && $(wc -l < "$JOURNAL_CALLS") == "$calls_before" ]]; ok
done
! grep -qE 'synthetic_continuation_marker|s=' "$stage"/*.result; ok
jq -nc --argjson tests "$passed" '{suite:"native_previous_boot_continuation_synthetic",passed:$tests,failed:0,
  real_journal_read:false,production_execution:false,raw_payload_exported:false,packages_installed:false}'
