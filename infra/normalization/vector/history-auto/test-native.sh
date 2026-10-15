#!/bin/bash
# Synthetic Linux/native tests only. Never calls journalctl/systemctl or the A wrapper.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $(uname -s) == Linux && $# == 0 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
history=$(CDPATH='' cd -- "$directory/../history" && pwd -P)
stage=$(mktemp -d /var/tmp/capstone-history-auto-fixture.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa current=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
until=1790000000000000
export AUTO_FIXTURE_STAGE=$stage AUTO_FIXTURE_MODE=normal AUTO_FIXTURE_COUNT=1001
printf '%s\n' "$current" > "$stage/boot"
: > "$stage/calls"
cat > "$stage/journal-fixture" <<'SH'
#!/bin/bash
set -euo pipefail
root=$AUTO_FIXTURE_STAGE
current=$(tr -d '\n-' < "$root/boot")
if [[ $1 == --list-boots ]]; then
    case $AUTO_FIXTURE_MODE in
      list_failure) exit 7 ;;
      list_malformed) printf 'unexpected\n'; exit 0 ;;
      list_duplicate) printf '%s\n' '-1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' '-1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "0 $current"; exit 0 ;;
      list_missing_current) printf '%s\n' '-1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; exit 0 ;;
      list_overflow) head -c 65537 /dev/zero | tr '\0' x; exit 0 ;;
      too_many_boots) for n in $(seq 1 65); do printf -- '-%s %032x\n' "$n" "$n"; done; printf '0 %s\n' "$current"; exit 0 ;;
      boot_vacuumed) printf '0 %s\n' "$current"; exit 0 ;;
    esac
    printf '%s\n' '-1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "0 $current"
    exit 0
fi
printf 'capture\n' >> "$root/calls"
start=1 count=0 mode=initial
for arg in "$@"; do
    case $arg in
      --lines=+*) count=${arg#--lines=+} ;;
      --cursor=s=*) start=${arg#--cursor=s=}; mode=inclusive ;;
      --after-cursor=s=*) start=$((${arg#--after-cursor=s=}+1)); mode=after ;;
      --boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|--until=@1790000000.000000|--no-pager|--quiet|--all|--output=json|--output-fields=*|_TRANSPORT=kernel) ;;
      *) exit 91 ;;
    esac
done
[[ $count -gt 0 ]]
case $AUTO_FIXTURE_MODE in
  missing_boundary) [[ $mode != inclusive || $start != 1000 ]] || start=1001 ;;
  nearest_boundary) [[ $mode != inclusive || $start != 1000 ]] || start=999 ;;
  malformed) printf '{broken\n'; exit 0 ;;
  empty) exit 0 ;;
  hanging)
    # Preserve exact identities of the private producer and its timeout parent.
    # exec keeps the producer PID/start ticks, so cleanup can prove termination.
    for pid in "$$" "$PPID"; do
      awk -v pid="$pid" '{sub(/^.*\) /, ""); print pid, $20, $4}' "/proc/$pid/stat"
    done > "$root/hanging-identities"
    exec sleep 6 ;;
  boot_changes)
    printf 'cccccccccccccccccccccccccccccccc\n' > "$root/boot" ;;
esac
jq -nc --argjson start "$start" --argjson count "$count" --argjson total "$AUTO_FIXTURE_COUNT" '
  range($start; ([$start+$count,$total+1]|min)) |
  {__CURSOR:("s="+(.|tostring)),__REALTIME_TIMESTAMP:"1000000",__MONOTONIC_TIMESTAMP:(.|tostring),
   _BOOT_ID:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",_TRANSPORT:"kernel",MESSAGE:"private_synthetic_history_auto"}'
SH
chmod 700 "$stage/journal-fixture"
passed=0
ok() { passed=$((passed+1)); }
newroot() {
    root=$stage/$1
    mkdir -m 700 "$root" "$root/jobs" "$root/store"
    : > "$root/.lock"
    printf '%s\n' "$current" > "$stage/boot"
    AUTO_FIXTURE_MODE=normal AUTO_FIXTURE_COUNT=1001
}
run() {
    local expected=$1 rc=0
    timeout --kill-after=2s 70s /bin/bash "$directory/auto-worker.sh" run "$root" "$stage/journal-fixture" \
      "$stage/boot" "$history" "$until" > "$stage/result.json" || rc=$?
    [[ $rc == "$expected" ]] || { printf 'FAIL case=%s exit=%s expected=%s\n' "${root##*/}" "$rc" "$expected"; exit 1; }
}
job() { jq -e "$1" "$root/jobs/$boot.json" >/dev/null; }
newroot normal
run 0
job '.status=="ready" and .batches==1 and .records==1000 and .attempts==0'; ok
run 0
job '.status=="complete" and .batches==2 and .records==1001'; ok
[[ $(jq -s '[.[].__CURSOR]|length==1001 and (unique|length)==1001' "$root"/store/batch-*/kernel.jsonl) == true ]]; ok
before=$(wc -l < "$stage/calls")
run 0
[[ $(wc -l < "$stage/calls") == "$before" ]]; jq -e '.outcome=="idle"' "$stage/result.json" >/dev/null; ok
/bin/bash "$directory/auto-worker.sh" inspect "$root" "$stage/journal-fixture" "$stage/boot" "$history" "$until" > "$stage/inspect.json"
jq -e '.jobs==1 and .complete==1 and .records==1001' "$stage/inspect.json" >/dev/null; ok
# Current boot change after batch commit refuses the job commit; next run adopts
# exactly that completed deterministic batch without reading journal records again.
newroot changed_boot
AUTO_FIXTURE_MODE=boot_changes
run 65
job '.status=="inflight" and .batches==0 and .attempts==1'; ok
before=$(wc -l < "$stage/calls")
AUTO_FIXTURE_MODE=normal
run 0
job '.status=="ready" and .batches==1 and .records==1000'
[[ $(wc -l < "$stage/calls") == "$before" ]]; ok
# A private source clone injects failure only at the completed-source resync.
# The original exporter still fsyncs normally. Job head must not move on error.
newroot resync_failure
mkdir -m 700 "$stage/failed-resync-code"
cp -- "$directory/auto-worker.sh" "$directory/auto-lib.sh" "$directory/state.jq" "$stage/failed-resync-code/"
cat >> "$stage/failed-resync-code/auto-lib.sh" <<'SH'
sync() {
    local value
    for value in "$@"; do
        [[ $value != "$AUTO_ROOT/store/batch-"* ]] || return 9
    done
    command sync "$@"
}
SH
rc=0
/bin/bash "$stage/failed-resync-code/auto-worker.sh" run "$root" "$stage/journal-fixture" "$stage/boot" "$history" "$until" > "$stage/resync-failed.json" || rc=$?
[[ $rc == 65 ]]
jq -e '.reason=="completed_batch_sync_failed"' "$stage/resync-failed.json" >/dev/null
job '.status=="inflight" and .head==null and .batches==0'
[[ $(find "$root/store" -maxdepth 1 -name 'batch-*' | wc -l) == 1 ]]; ok
before=$(wc -l < "$stage/calls")
run 0
job '.status=="ready" and .batches==1 and .records==1000'
[[ $(wc -l < "$stage/calls") == "$before" ]]; ok
# A true killed process leaves inflight + partial. Restart blocks, retaining bytes.
newroot killed
AUTO_FIXTURE_MODE=hanging
rc=0
timeout --kill-after=1s 5s /bin/bash "$directory/auto-worker.sh" run "$root" "$stage/journal-fixture" "$stage/boot" "$history" "$until" > "$stage/killed.json" || rc=$?
[[ $rc == 124 || $rc == 137 ]]
# The existing capture helper has its own timeout process group. Prove both
# recorded private PIDs have exited (or were reused) before fixture cleanup;
# elapsed time alone is not evidence. No process-name matching or broad signal.
[[ $(wc -l < "$stage/hanging-identities") == 2 ]]
while read -r pid ticks session; do
    [[ $pid =~ ^[0-9]+$ && $ticks =~ ^[0-9]+$ && $session =~ ^[0-9]+$ && $pid -gt 1 ]]
    stopped=false
    for poll in $(seq 1 60); do
        actual=$(awk '{sub(/^.*\) /, ""); print $20, $4}' "/proc/$pid/stat" 2>/dev/null || true)
        if [[ $actual != "$ticks $session" ]]; then stopped=true; break; fi
        sleep 0.1
    done
    [[ $stopped == true ]]
done < "$stage/hanging-identities"
job '.status=="inflight"'; [[ $(find "$root/store" -maxdepth 1 -name 'partial-*' | wc -l) == 1 ]]; ok
AUTO_FIXTURE_MODE=normal
before=$(wc -l < "$stage/calls")
run 2
job '.status=="blocked" and .last_reason=="partial_requires_operator"'
[[ $(wc -l < "$stage/calls") == "$before" && $(find "$root/store" -maxdepth 1 -name 'partial-*' | wc -l) == 1 ]]; ok
for scenario in missing_boundary nearest_boundary; do
    newroot "$scenario"; run 0; AUTO_FIXTURE_MODE=$scenario; run 2
    job '.status=="blocked" and .batches==1 and .records==1000'
    [[ $(find "$root/store" -maxdepth 1 -name 'partial-*' | wc -l) == 1 ]]; ok
done
for scenario in malformed empty; do
    newroot "$scenario"; AUTO_FIXTURE_MODE=$scenario; run 2
    job '.status=="blocked" and .batches==0'
    before=$(wc -l < "$stage/calls"); run 0
    [[ $(wc -l < "$stage/calls") == "$before" ]]; ok
done
for scenario in list_failure list_malformed list_duplicate list_missing_current list_overflow too_many_boots; do
    newroot "$scenario"; AUTO_FIXTURE_MODE=$scenario; run 65
    [[ $(find "$root/jobs" -type f | wc -l) == 0 ]]; ok
done
newroot boot_vacuumed; run 0; AUTO_FIXTURE_MODE=boot_vacuumed; run 2
job '.status=="blocked" and .last_reason=="boot_no_longer_retained"'; ok
newroot concurrent
rc=0
flock "$root/.lock" /bin/bash "$directory/auto-worker.sh" run "$root" "$stage/journal-fixture" "$stage/boot" "$history" "$until" > "$stage/locked.json" || rc=$?
[[ $rc == 75 && $(find "$root/jobs" -type f | wc -l) == 0 ]]; ok
newroot bytes
truncate -s 1073741824 "$root/store/quota-fixture"
before=$(wc -l < "$stage/calls"); run 65
[[ $(wc -l < "$stage/calls") == "$before" ]]; job '.status=="ready"'; ok
newroot partial_quota
for n in $(seq 1 256); do mkdir -m 700 "$root/store/partial-fixture-$n"; done
run 65; [[ $(find "$root/store" -mindepth 1 -maxdepth 1 -type d | wc -l) == 256 ]]; ok
newroot tampered_head; run 0
id=$(jq -r .head.batch_id "$root/jobs/$boot.json")
chmod 600 "$root/store/batch-$id/kernel.jsonl"; printf x >> "$root/store/batch-$id/kernel.jsonl"; chmod 400 "$root/store/batch-$id/kernel.jsonl"
before=$(wc -l < "$stage/calls"); run 2
job '.status=="blocked" and .last_reason=="saved_head_invalid"'
[[ $(wc -l < "$stage/calls") == "$before" ]]; ok
newroot manifest_sha_changed; run 0
id=$(jq -r .head.batch_id "$root/jobs/$boot.json")
# Whitespace changes only the exact manifest digest; JSON/record semantics and
# all payload checks remain valid. This exercises conditional-function errexit.
chmod 600 "$root/store/batch-$id/manifest.json"
printf '\n' >> "$root/store/batch-$id/manifest.json"
chmod 400 "$root/store/batch-$id/manifest.json"
before=$(wc -l < "$stage/calls"); run 2
job '.status=="blocked" and .last_reason=="saved_head_invalid" and .batches==1'
[[ $(wc -l < "$stage/calls") == "$before" ]]; ok
newroot bad_state; run 0
jq '.pending_id="wrong"' "$root/jobs/$boot.json" > "$stage/changed.json"; cp "$stage/changed.json" "$root/jobs/$boot.json"
run 65; ok
newroot unsafe_root; chmod 755 "$root"; run 65; ok
newroot symlink_store; rmdir "$root/store"; ln -s "$stage" "$root/store"; run 65; ok
newroot store_symlink; ln -s /dev/null "$root/store/foreign"; run 65; ok
newroot state_symlink; ln -s "$stage/boot" "$root/jobs/$boot.json"; run 65; ok
! grep -qE 'private_synthetic_history_auto|s=[0-9]+' "$stage"/*.json; ok
jq -nc --argjson passed "$passed" '{suite:"native_history_auto_synthetic",passed:$passed,failed:0,
  real_journal_read:false,production_execution:false,packages_installed:false,raw_payload_exported:false}'
