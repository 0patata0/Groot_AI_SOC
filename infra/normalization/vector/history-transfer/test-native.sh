#!/bin/bash
# Linux-only isolated synthetic files. Never calls the operational wrapper.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
[[ $(uname -s) == Linux ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/receive-lib.sh"
stage=$(mktemp -d /var/tmp/capstone-history-receive-test.XXXXXX)
case_name=initialization
trap 'code=$?; if (( code != 0 )); then printf "test_failed_case=%s exit=%s\n" "$case_name" "$code" >&2; fi; rm -rf -- "$stage"' EXIT
passed=0
cat > "$stage/worker.sh" <<'WORKER'
#!/bin/bash
set -euo pipefail
umask 077
export LC_ALL=C TZ=Asia/Seoul
source "$1/receive-lib.sh"; shift
mode=$1; shift
case "$mode" in
    fail_file_sync)
        ht_sync() { [[ $1 != */receipt.json ]] && /usr/bin/sync -- "$@"; } ;;
    fail_commit_parent_sync)
        ht_sync() {
            if [[ $1 == */batches ]] && compgen -G "$1/*/receipt.json" >/dev/null; then return 73; fi
            /usr/bin/sync -- "$@"
        } ;;
    fail_rename)
        ht_rename() { return 74; } ;;
    noop_rename)
        ht_rename() { mkdir -m 700 -- "$2"; /usr/bin/mv -T -n -- "$1" "$2"; } ;;
    low_capacity)
        df() { printf 'Avail\n1\n'; } ;;
    changing_input)
        dd() {
            /usr/bin/dd "$@"
            local argument
            for argument in "$@"; do
                if [[ $argument == if=*/incoming/*/kernel.jsonl ]]; then printf x >> "${argument#if=}"; break; fi
            done
        } ;;
    lost_response)
        ht_receive "$@" >/dev/null
        exit 79 ;;
    normal) ;;
    *) exit 64 ;;
esac
ht_receive "$@"
WORKER
fixture() {
    local label=$1 policy=${2:-previous-kernel-batch-v1}
    case_name=$label
    store=$stage/$label
    mkdir -m 700 -- "$store" "$store/incoming"
    payload=$stage/$label-payload.jsonl
    for i in 1 2 3; do
        jq -cn --arg i "$i" '{__CURSOR:("s=SYNTHETIC_CURSOR_PRIVATE;i="+$i),
          __REALTIME_TIMESTAMP:("176000000000000"+$i),__MONOTONIC_TIMESTAMP:("10"+$i),
          _BOOT_ID:"11111111111111111111111111111111",_TRANSPORT:"kernel",MESSAGE:"SYNTHETIC_RAW_PRIVATE"}'
    done > "$payload"
    payload_sha=$(ht_sha "$payload")
    manifest=$stage/$label-manifest.json
    jq -Rn --arg boot 11111111111111111111111111111111 --arg until 1760000000001000 \
      --argjson max_records 1000 -f "$directory/../history/validate-records.jq" "$payload" > "$stage/$label-summary.json"
    jq -n --arg policy "$policy" --arg sha "$payload_sha" --argjson bytes "$(stat -c %s "$payload")" \
      --slurpfile summary "$stage/$label-summary.json" \
      '{policy:$policy,batch_id:("0"*64),status:"complete_batch",reason:"verified",
       boot_id:"11111111111111111111111111111111",until_epoch_us:"1760000000001000",
       selection:{transport:"kernel",order:"oldest",max_records:1000,max_bytes:33554432,
         capture_validation_budget_ms:15000,finalization_in_budget:false},
       bytes:$bytes,sha256:$sha,records:3,physical_newlines:3,records_verified:true,
       record_metadata:$summary[0],source_range_exhausted:false,captured_bytes_including_verification:$bytes,
       producer_exit:0,consumer_exit:0,original_ack_boundary_known:false,operational_checkpoint_changed:false,
       reinjected:false,remote_receipt:false} |
       if .policy=="previous-kernel-continuation-v1" then
         .selection.order="after_verified_parent_cursor" |
         .parent={batch_id:("a"*64),payload_sha256:("b"*64),manifest_sha256:("c"*64)} |
         .continuation_boundary_verified=true | .continuation_phase="verified"
       else . end' > "$manifest"
    id=$(ht_batch_id "$manifest")
    jq --arg id "$id" '.batch_id=$id' "$manifest" > "$manifest.tmp"; mv -- "$manifest.tmp" "$manifest"
    manifest_sha=$(ht_sha "$manifest")
    mkdir -m 700 -- "$store/incoming/$id"
    incoming=$store/incoming/$id/$payload_sha-$manifest_sha
    mkdir -m 700 -- "$incoming"
    cp -- "$payload" "$incoming/kernel.jsonl"; cp -- "$manifest" "$incoming/manifest.json"
    final=$store/batches/$id
}
revise_manifest() {
    local filter=$1
    jq "$filter" "$incoming/manifest.json" > "$manifest.tmp"; mv -- "$manifest.tmp" "$manifest"
    manifest_sha=$(ht_sha "$manifest")
    local next=$store/incoming/$id/$payload_sha-$manifest_sha
    mkdir -m 700 -- "$next"; cp -- "$incoming/kernel.jsonl" "$next/kernel.jsonl"; cp -- "$manifest" "$next/manifest.json"
    incoming=$next
}
receive() { /bin/bash "$stage/worker.sh" "$directory" "$1" "$store" "$id" "$payload_sha" "$manifest_sha" > "$stage/out" 2> "$stage/error"; }
ok() {
    receive "${1:-normal}"
    jq -e --arg id "$id" --arg payload "$payload_sha" --arg manifest "$manifest_sha" \
      '.stage=="remote_file_preserved" and .batch_id==$id and .payload_sha256==$payload and
       .manifest_sha256==$manifest and .records==3 and (.receipt_sha256|test("^[a-f0-9]{64}$"))' "$stage/out" >/dev/null
    ! grep -Eq 'SYNTHETIC_(RAW|CURSOR)_PRIVATE|__CURSOR|MESSAGE' "$stage/out"
}
reject() {
    if receive "${1:-normal}"; then printf 'unexpected_success\n' >&2; exit 1; fi
    [[ ! -s $stage/out ]]
}
pass() { passed=$((passed+1)); }

fixture valid_v1; ok
[[ $(stat -c %a "$final") == 700 && $(stat -c %a "$final/kernel.jsonl") == 400 ]]
[[ $(jq -r .remote_receipt "$final/manifest.json") == false ]]
pass
receipt_before=$(cat "$final/receipt.sha256"); stamp_before=$(jq -r .received_at_kst "$final/receipt.json")
ok; [[ $(jq -r .reused "$stage/out") == true && $(cat "$final/receipt.sha256") == "$receipt_before" && $(jq -r .received_at_kst "$final/receipt.json") == "$stamp_before" ]]; pass
# Idempotent receipt lookup does not require the old upload to remain available.
mv -- "$incoming" "$incoming.saved"; ok; pass

fixture continuation previous-kernel-continuation-v1; ok; pass
fixture continuation_boundary previous-kernel-continuation-v1
revise_manifest '.continuation_boundary_verified=false'; reject; pass
fixture wrong_parent_id previous-kernel-continuation-v1
revise_manifest '.parent.batch_id=("d"*64)'; reject; pass

fixture policy; revise_manifest '.policy="unknown"'; reject; pass
fixture record_count; revise_manifest '.records=4 | .physical_newlines=4'; reject; pass
fixture cursor_summary; revise_manifest '.record_metadata.last_cursor="tampered"'; reject; pass
fixture fractional_limit; revise_manifest '.selection.max_records=1.5'; reject; pass
fixture size_limit_type; revise_manifest '.selection.max_bytes="33554432"'; reject; pass
fixture size_limit_range; revise_manifest '.selection.max_bytes=33554433'; reject; pass
fixture changed_selection; revise_manifest '.selection.max_records=999'; reject; pass
fixture bad_size; revise_manifest '.bytes+=1'; reject; pass
fixture partial_source; revise_manifest '.status="partial"'; reject; pass
fixture duplicate_manifest
sed '1s/{/{"policy":"previous-kernel-batch-v1",/' "$incoming/manifest.json" > "$manifest.tmp"
manifest_sha=$(ht_sha "$manifest.tmp")
next=$store/incoming/$id/$payload_sha-$manifest_sha
mkdir -m 700 -- "$next"; cp -- "$incoming/kernel.jsonl" "$next/kernel.jsonl"; cp -- "$manifest.tmp" "$next/manifest.json"
incoming=$next; reject; pass

fixture wrong_payload_hash
payload_sha=$(printf 'f%.0s' {1..64})
next=$store/incoming/$id/$payload_sha-$manifest_sha; mv -- "$incoming" "$next"; incoming=$next
reject; pass
fixture wrong_manifest_hash
manifest_sha=$(printf 'f%.0s' {1..64})
next=$store/incoming/$id/$payload_sha-$manifest_sha; mv -- "$incoming" "$next"; incoming=$next
reject; pass
fixture truncated_transfer
truncate -s 20 "$incoming/kernel.jsonl"; reject; pass
fixture missing_payload
rm -- "$incoming/kernel.jsonl"; reject; pass
fixture source_symlink
rm -- "$incoming/kernel.jsonl"; ln -s "$payload" "$incoming/kernel.jsonl"; reject; pass
fixture source_hardlink
ln "$incoming/kernel.jsonl" "$stage/extra-hardlink"; reject; pass
fixture source_fifo
rm -- "$incoming/kernel.jsonl"; mkfifo -m 600 "$incoming/kernel.jsonl"; reject; pass
fixture source_oversize
truncate -s 33554433 "$incoming/kernel.jsonl"; reject; pass
fixture manifest_oversize
truncate -s 65537 "$incoming/manifest.json"; reject; pass
fixture public_store
chmod 755 "$store"; reject; pass
fixture extra_input
: > "$incoming/extra"; reject; pass
fixture no_capacity; reject low_capacity; [[ ! -e $final ]]; pass
fixture source_changed; reject changing_input; [[ ! -e $final ]]; pass

fixture same_id_conflict; ok
original_receipt=$(cat "$final/receipt.sha256")
revise_manifest '.test_annotation="different trusted manifest bytes"'; reject
[[ $(cat "$final/receipt.sha256") == "$original_receipt" ]]; pass
fixture same_id_payload_conflict; ok
original_receipt=$(cat "$final/receipt.sha256")
sed 's/SYNTHETIC_RAW_PRIVATE/SYNTHETIC_RAW_CHANGED/' "$payload" > "$payload.tmp"; mv -- "$payload.tmp" "$payload"
payload_sha=$(ht_sha "$payload")
jq --arg sha "$payload_sha" --argjson bytes "$(stat -c %s "$payload")" \
  '.sha256=$sha | .bytes=$bytes | .captured_bytes_including_verification=$bytes' "$manifest" > "$manifest.tmp"
manifest_sha=$(ht_sha "$manifest.tmp")
next=$store/incoming/$id/$payload_sha-$manifest_sha
mkdir -m 700 -- "$next"; cp -- "$payload" "$next/kernel.jsonl"; cp -- "$manifest.tmp" "$next/manifest.json"
reject; [[ $(cat "$final/receipt.sha256") == "$original_receipt" ]]; pass

fixture fail_file; reject fail_file_sync
[[ ! -e $final && -n $(find "$store/partial" -mindepth 1 -maxdepth 1 -type d -print -quit) ]]; pass
fixture fail_rename; reject fail_rename
[[ ! -e $final ]]; pass
fixture noop_rename; reject noop_rename
[[ -d $final && ! -f $final/receipt.json && -n $(find "$store/partial" -mindepth 1 -maxdepth 1 -type d -print -quit) ]]; pass
fixture fail_after_rename; reject fail_commit_parent_sync
[[ -f $final/receipt.json ]]; receipt_before=$(cat "$final/receipt.sha256")
ok; [[ $(cat "$final/receipt.sha256") == "$receipt_before" && $(jq -r .reused "$stage/out") == true ]]; pass
fixture response_lost; reject lost_response
receipt_before=$(cat "$final/receipt.sha256"); ok
[[ $(cat "$final/receipt.sha256") == "$receipt_before" && $(jq -r .reused "$stage/out") == true ]]; pass
fixture retry_sync_failure; ok; reject fail_file_sync; pass

fixture final_payload_tamper; ok
chmod 600 "$final/kernel.jsonl"; printf 'x' >> "$final/kernel.jsonl"; chmod 400 "$final/kernel.jsonl"; reject; pass
fixture final_manifest_tamper; ok
chmod 600 "$final/manifest.json"; printf ' ' >> "$final/manifest.json"; chmod 400 "$final/manifest.json"; reject; pass
fixture final_receipt_tamper; ok
chmod 600 "$final/receipt.json"; printf ' ' >> "$final/receipt.json"; chmod 400 "$final/receipt.json"; reject; pass

# Exercise the production internal worker's fixed error output without invoking
# the machine-bound public entry or touching any operational path.
fixture raw_parser_diagnostic
printf 'SYNTHETIC_RAW_PRIVATE_INVALID\n%.0s' {1..3} > "$payload"
payload_sha=$(ht_sha "$payload")
jq --arg sha "$payload_sha" --argjson bytes "$(stat -c %s "$payload")" \
  '.sha256=$sha | .bytes=$bytes | .captured_bytes_including_verification=$bytes' "$manifest" > "$manifest.tmp"
manifest_sha=$(ht_sha "$manifest.tmp")
next=$store/incoming/$id/$payload_sha-$manifest_sha
mkdir -m 700 -- "$next"; cp -- "$payload" "$next/kernel.jsonl"; cp -- "$manifest.tmp" "$next/manifest.json"
if /bin/bash "$directory/receive-run.sh" "$store" "$id" "$payload_sha" "$manifest_sha" > "$stage/out" 2> "$stage/error"; then exit 1; fi
[[ ! -s $stage/out && $(cat "$stage/error") == '{"status":"rejected","stage":"not_acknowledged"}' ]]; pass

printf '{"suite":"native_history_receiver_synthetic","passed":%s,"failed":0,"operational_receiver_called":false,"raw_payload_exported":false}\n' "$passed"
