#!/bin/bash
# Root/Linux synthetic fixtures only. Never invokes the machine-bound entry,
# an SSH command, an operational upload, or an operational receiver directory.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
[[ $(uname -s) == Linux && $EUID == 0 && $# == 0 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/receive-lib.sh"
stage=$(mktemp -d /var/tmp/capstone-history-promote-test.XXXXXX)
current_case=initialization
cleanup_test() {
    local status=$?
    if (( status != 0 )); then
        printf '{"suite":"native_history_upload_promotion_synthetic","failed_case":"%s","exit":%s}\n' "$current_case" "$status" >&2
        if [[ -f $stage/error ]]; then sed -n '/^PROMOTE_TEST_FAILURE_LINE=[0-9][0-9]*$/p' "$stage/error" >&2; fi
    fi
    rm -rf -- "$stage"
    exit "$status"
}
trap cleanup_test EXIT
passed=0
cat > "$stage/worker.sh" <<'WORKER'
#!/bin/bash
set -eEuo pipefail
umask 077
export LC_ALL=C TZ=Asia/Seoul
trap 'printf "PROMOTE_TEST_FAILURE_LINE=%s\n" "$LINENO" >&2' ERR
source "$1/receive-lib.sh"
source "$1/promote-upload.sh"
shift
mode=$1; shift
case "$mode" in
  normal) ;;
  fail_copy) promote_copy() { printf 'SYNTHETIC_PARTIAL' > "$2"; return 74; } ;;
  race_file)
    promote_copy() {
      /usr/bin/dd if="$1" of="$2" iflag=nofollow,nonblock,count_bytes count="$3" status=none
      printf 'SYNTHETIC_RACE' >> "$1"
    } ;;
  race_directory)
    promote_copy() {
      /usr/bin/dd if="$1" of="$2" iflag=nofollow,nonblock,count_bytes count="$3" status=none
      if [[ $1 == ./kernel.jsonl ]]; then mv -- "$PWD" "$PWD.moved"; mkdir -m 700 -- "$PWD"; chown 1000:1000 -- "$PWD"; fi
    } ;;
  fail_file_sync) ht_sync() { [[ $1 != */manifest.json ]] && /usr/bin/sync -- "$@"; } ;;
  fail_rename) ht_rename() { return 74; } ;;
  noop_rename) ht_rename() { mkdir -m 700 -- "$2"; /usr/bin/mv -T -n -- "$1" "$2"; } ;;
  fail_publish_sync)
    ht_sync() {
      if [[ $1 == */incoming/* && -d $1 ]] && compgen -G "$1/*/manifest.json" >/dev/null; then return 73; fi
      /usr/bin/sync -- "$@"
    } ;;
  response_lost) promote_transaction "$@" >/dev/null; exit 79 ;;
  lock_held)
    mkdir -m 700 -- "$1"
    : > "$1/.lock"
    exec 8<>"$1/.lock"
    flock -n 8
    ;;
  low_space) df() { printf 'Avail\n1\n'; } ;;
  *) exit 64 ;;
esac
promote_transaction "$@"
WORKER

fixture() {
    local name=$1
    current_case=$name
    store=$stage/$name-store
    upload=$stage/$name-upload
    mkdir -m 700 -- "$upload"
    payload=$stage/$name-payload.jsonl
    for i in 1 2 3; do
      jq -cn --arg i "$i" '{__CURSOR:("s=SYNTHETIC_CURSOR_PRIVATE;i="+$i),
        __REALTIME_TIMESTAMP:("176000000000000"+$i),__MONOTONIC_TIMESTAMP:("10"+$i),
        _BOOT_ID:"11111111111111111111111111111111",_TRANSPORT:"kernel",MESSAGE:"SYNTHETIC_RAW_PRIVATE"}'
    done > "$payload"
    payload_sha=$(ht_sha "$payload")
    manifest=$stage/$name-manifest.json
    jq -Rn --arg boot 11111111111111111111111111111111 --arg until 1760000000001000 \
      --argjson max_records 1000 -f "$directory/../history/validate-records.jq" "$payload" > "$stage/$name-summary.json"
    jq -n --arg sha "$payload_sha" --argjson bytes "$(stat -c %s "$payload")" \
      --slurpfile summary "$stage/$name-summary.json" \
      '{policy:"previous-kernel-batch-v1",batch_id:("0"*64),status:"complete_batch",reason:"verified",
        boot_id:"11111111111111111111111111111111",until_epoch_us:"1760000000001000",
        selection:{transport:"kernel",order:"oldest",max_records:1000,max_bytes:33554432,
          capture_validation_budget_ms:15000,finalization_in_budget:false},
        bytes:$bytes,sha256:$sha,records:3,physical_newlines:3,records_verified:true,
        record_metadata:$summary[0],source_range_exhausted:false,captured_bytes_including_verification:$bytes,
        producer_exit:0,consumer_exit:0,original_ack_boundary_known:false,operational_checkpoint_changed:false,
        reinjected:false,remote_receipt:false}' > "$manifest"
    id=$(ht_batch_id "$manifest")
    jq --arg id "$id" '.batch_id=$id' "$manifest" > "$manifest.tmp"; mv -- "$manifest.tmp" "$manifest"
    manifest_sha=$(ht_sha "$manifest")
    mkdir -m 700 -- "$upload/$id"
    source=$upload/$id/$payload_sha-$manifest_sha
    mkdir -m 700 -- "$source"
    cp -- "$payload" "$source/kernel.jsonl"; cp -- "$manifest" "$source/manifest.json"
    chown -R 1000:1000 -- "$upload"
    destination=$store/incoming/$id/$payload_sha-$manifest_sha
}
revise_manifest() {
    jq "$1" "$source/manifest.json" > "$manifest.tmp"
    manifest_sha=$(ht_sha "$manifest.tmp")
    local next=$upload/$id/$payload_sha-$manifest_sha
    mkdir -m 700 -- "$next"
    cp -- "$source/kernel.jsonl" "$next/kernel.jsonl"; cp -- "$manifest.tmp" "$next/manifest.json"
    chown -R 1000:1000 -- "$next"
    source=$next
    destination=$store/incoming/$id/$payload_sha-$manifest_sha
}
run() { /bin/bash "$stage/worker.sh" "$directory" "$1" "$store" "$upload" "$id" "$payload_sha" "$manifest_sha" > "$stage/out" 2> "$stage/error"; }
ok() {
    run "${1:-normal}"
    jq -e --arg id "$id" --arg p "$payload_sha" --arg m "$manifest_sha" \
      '.status=="promoted_input" and .batch_id==$id and .payload_sha256==$p and .manifest_sha256==$m and .remote_receipt==false' \
      "$stage/out" >/dev/null
    ! grep -Eq 'SYNTHETIC_(RAW|CURSOR)_PRIVATE|__CURSOR|MESSAGE' "$stage/out"
    [[ $(stat -c '%u:%a' "$destination") == 0:700 &&
       $(stat -c '%u:%a:%h' "$destination/kernel.jsonl") == 0:400:1 &&
       $(stat -c '%u:%a:%h' "$destination/manifest.json") == 0:400:1 ]]
    [[ $(ht_sha "$destination/kernel.jsonl") == "$payload_sha" && $(ht_sha "$destination/manifest.json") == "$manifest_sha" ]]
}
reject() {
    if run "${1:-normal}"; then printf 'unexpected_success\n' >&2; exit 1; fi
    [[ ! -s $stage/out ]]
    if [[ -d $store/partial ]]; then [[ -z $(find "$store/partial" -mindepth 1 -maxdepth 1 -name 'promote-*' -print -quit) ]]; fi
}
pass() { passed=$((passed+1)); }

fixture valid; ok
[[ $(ht_sha "$source/kernel.jsonl") == "$payload_sha" && $(ht_sha "$source/manifest.json") == "$manifest_sha" ]]
[[ $(stat -c '%u:%a' "$source/kernel.jsonl") == 1000:600 ]]; pass
identity=$(stat -c '%d:%i:%Y:%Z' "$destination/kernel.jsonl")
ok; [[ $(jq -r .reused "$stage/out") == true && $(stat -c '%d:%i:%Y:%Z' "$destination/kernel.jsonl") == "$identity" ]]; pass
mv -- "$upload" "$upload.saved"; ok; pass

fixture raw_tamper; printf 'SYNTHETIC_CHANGED' >> "$source/kernel.jsonl"; reject; pass
fixture manifest_tamper; printf ' ' >> "$source/manifest.json"; reject; pass
fixture partial_manifest; revise_manifest '.status="partial"'; reject; pass
fixture inconsistent_manifest; revise_manifest '.records=4 | .physical_newlines=4'; reject; pass
fixture wrong_selection; revise_manifest '.selection.max_records=999'; reject; pass
fixture root_source; chown 0:0 "$source/kernel.jsonl"; reject; pass
fixture public_file; chmod 644 "$source/kernel.jsonl"; reject; pass
fixture public_directory; chmod 755 "$source"; reject; pass
fixture user_symlink; rm "$source/kernel.jsonl"; ln -s "$payload" "$source/kernel.jsonl"; reject; pass
fixture directory_symlink; mv "$source" "$source.real"; ln -s "$source.real" "$source"; reject; pass
fixture hardlink; ln "$source/kernel.jsonl" "$stage/extra-hardlink"; reject; pass
fixture fifo; rm "$source/kernel.jsonl"; mkfifo -m 600 "$source/kernel.jsonl"; chown 1000:1000 "$source/kernel.jsonl"; reject; pass
fixture oversized; truncate -s 33554433 "$source/kernel.jsonl"; reject; pass
fixture manifest_oversized; truncate -s 65537 "$source/manifest.json"; reject; pass
fixture extra_file; : > "$source/extra"; reject; pass
fixture unsafe_store; mkdir -m 755 "$store"; reject; pass
fixture lock_link; mkdir -m 700 "$store"; ln -s "$manifest" "$store/.lock"; reject; pass
fixture held_lock; reject lock_held; pass
fixture low_space; reject low_space; [[ ! -e $destination ]]; pass

for mode in fail_copy race_file race_directory fail_file_sync fail_rename; do
    fixture "$mode"; reject "$mode"; [[ ! -e $destination ]]; pass
done
fixture noop; reject noop_rename; [[ -d $destination && ! -e $destination/kernel.jsonl ]]; pass
fixture post_publish_failure; reject fail_publish_sync
[[ -f $destination/kernel.jsonl ]]; identity=$(stat -c '%d:%i' "$destination/kernel.jsonl")
ok; [[ $(jq -r .reused "$stage/out") == true && $(stat -c '%d:%i' "$destination/kernel.jsonl") == "$identity" ]]; pass
fixture dropped_response; reject response_lost
ok; [[ $(jq -r .reused "$stage/out") == true ]]; pass
fixture destination_tamper; ok
chmod 600 "$destination/kernel.jsonl"; printf 'x' >> "$destination/kernel.jsonl"; chmod 400 "$destination/kernel.jsonl"
tampered=$(ht_sha "$destination/kernel.jsonl"); reject
[[ $(ht_sha "$destination/kernel.jsonl") == "$tampered" ]]; pass
fixture destination_extra; ok; : > "$destination/extra"; reject; [[ -f $destination/extra ]]; pass
fixture retry_sync_failure; ok; reject fail_file_sync; [[ -f $destination/kernel.jsonl ]]; pass

printf '{"suite":"native_history_upload_promotion_synthetic","passed":%s,"failed":0,"public_wrapper_called":false,"operational_paths_used":false,"source_user_uid":1000,"raw_payload_exported":false}\n' "$passed"
