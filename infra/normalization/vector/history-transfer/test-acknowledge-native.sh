#!/bin/bash
# Synthetic A receipts only; never invokes the public wrapper or operational paths.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C TZ=Asia/Seoul
[[ $(uname -s) == Linux && $# == 0 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
stage=$(mktemp -d /var/tmp/capstone-receipt-ack-fixture.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mkdir -m 700 "$stage/original" "$stage/original/batch-$id"
printf '{"synthetic_receipt_test":true}\n' > "$stage/original/batch-$id/kernel.jsonl"
payload_sha=$(sha256sum "$stage/original/batch-$id/kernel.jsonl" | cut -d ' ' -f1)
size=$(stat -c %s "$stage/original/batch-$id/kernel.jsonl")
jq -nc --arg id "$id" --arg sha "$payload_sha" --argjson bytes "$size" \
  '{batch_id:$id,sha256:$sha,bytes:$bytes,records:1,status:"complete_batch",policy:"previous-kernel-batch-v1"}' > "$stage/original/batch-$id/manifest.json"
manifest_sha=$(sha256sum "$stage/original/batch-$id/manifest.json" | cut -d ' ' -f1)
chmod 400 "$stage/original/batch-$id/"*.json*
jq -ncS --arg id "$id" --arg payload "$payload_sha" --arg manifest "$manifest_sha" --argjson bytes "$size" \
  '{schema_version:"1",stage:"remote_file_preserved",receiver_machine_id:"1e143067c98a44ffba6eaa925dc038d7",
    source_machine_id:"096e90b6243e438aa8a7b392be754732",store_id:"capstone-history-receipts-v1",
    batch_id:$id,payload_sha256:$payload,manifest_sha256:$manifest,bytes:$bytes,records:1,
    source_policy:"previous-kernel-batch-v1",received_at_kst:"2026-10-14T10:44:00+09:00"}' > "$stage/receipt.json"
receipt_sha=$(sha256sum "$stage/receipt.json" | cut -d ' ' -f1)
jq -cS --arg sha "$receipt_sha" '.+{receipt_sha256:$sha,reused:false}' "$stage/receipt.json" > "$stage/response.json"
cat > "$stage/worker.sh" <<'SH'
#!/bin/bash
set -euo pipefail
source "$1"
shift
hook=$1; shift
case $hook in
  pre_sync)
    ack_sync() {
        for path in "$@"; do [[ $path != */.pending-*/receipt.json ]] || return 1; done
        /usr/bin/sync -- "$@"
    } ;;
  post_sync)
    ack_sync() {
        for path in "$@"; do [[ $path != */receipts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/receipt.json ]] || return 1; done
        /usr/bin/sync -- "$@"
    } ;;
  none) ;;
  *) exit 91 ;;
esac
acknowledge_core "$@"
SH
newstore() { mkdir -m 700 "$stage/$1"; cp -a "$stage/original/." "$stage/$1/"; }
run() {
    local name=$1 expected=$2 input=${3:-$stage/response.json} hook=${4:-none} rc=0
    /bin/bash "$stage/worker.sh" "$directory/acknowledge-receipt.sh" "$hook" "$stage/$name" "$id" "$payload_sha" "$manifest_sha" \
      < "$input" > "$stage/$name.result" 2> "$stage/$name.error" || rc=$?
    if [[ $expected == ok ]]; then [[ $rc == 0 ]]
    else [[ $rc != 0 && ! -s $stage/$name.result ]]; fi
}
rehash() {
    jq -cS 'del(.receipt_sha256,.reused)' "$1" > "$stage/rehash.json"
    local sha; sha=$(sha256sum "$stage/rehash.json" | cut -d ' ' -f1)
    jq -cS --arg sha "$sha" '.receipt_sha256=$sha' "$1" > "$stage/changed-response.json"
    mv "$stage/changed-response.json" "$1"
}
passed=0
ok() { passed=$((passed+1)); }
newstore success; run success ok
final=$stage/success/receipts/$id
cmp -s "$stage/receipt.json" "$final/receipt.json"
[[ $(stat -c '%a:%h' "$final/receipt.json") == 400:1 && $(stat -c %a "$final") == 700 ]]
[[ $(sha256sum "$stage/success/batch-$id/manifest.json" | cut -d ' ' -f1) == "$manifest_sha" ]]
jq -e '.reused==false and .wazuh_analysis_receipt==false and .indexer_receipt==false' "$stage/success.result" >/dev/null; ok
jq '.reused=true' "$stage/response.json" > "$stage/reused.json"
run success ok "$stage/reused.json"
jq -e .reused "$stage/success.result" >/dev/null; ok
jq '.' "$stage/response.json" > "$stage/pretty.json"
run success ok "$stage/pretty.json"; ok
jq '.received_at_kst="2026-10-14T10:44:01+09:00"' "$stage/response.json" > "$stage/conflict.json"
rehash "$stage/conflict.json"
run success fail "$stage/conflict.json"
[[ $(sha256sum "$final/receipt.json" | cut -d ' ' -f1) == "$receipt_sha" ]]; ok
for case in bad_sha wrong_receiver wrong_source wrong_store wrong_records invalid_date; do
    newstore "$case"
    case $case in
      bad_sha) filter='.receipt_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' ;;
      wrong_receiver) filter='.receiver_machine_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' ;;
      wrong_source) filter='.source_machine_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' ;;
      wrong_store) filter='.store_id="wrong-store"' ;;
      wrong_records) filter='.records=2' ;;
      invalid_date) filter='.received_at_kst="2026-99-14T10:44:00+09:00"' ;;
    esac
    jq "$filter" "$stage/response.json" > "$stage/$case.json"
    [[ $case == bad_sha ]] || rehash "$stage/$case.json"
    run "$case" fail "$stage/$case.json"
    [[ ! -e $stage/$case/receipts/$id ]]; ok
done
for case in duplicate multiple nested_duplicate oversized truncated; do
    newstore "$case"
    case $case in
      duplicate) sed 's/^{/{"reused":true,/' "$stage/response.json" > "$stage/$case.json" ;;
      multiple) cat "$stage/response.json" "$stage/response.json" > "$stage/$case.json" ;;
      nested_duplicate) sed 's/^{/{"reused":{"unexpected":1},/' "$stage/response.json" > "$stage/$case.json" ;;
      oversized) head -c 65537 /dev/zero | tr '\0' ' ' > "$stage/$case.json" ;;
      truncated) printf '{"schema_version":' > "$stage/$case.json" ;;
    esac
    run "$case" fail "$stage/$case.json"
    [[ ! -e $stage/$case/receipts/$id ]]; ok
done
for case in payload_tamper manifest_tamper; do
    newstore "$case"
    file=kernel.jsonl; [[ $case != manifest_tamper ]] || file=manifest.json
    chmod 600 "$stage/$case/batch-$id/$file"
    printf '\n' >> "$stage/$case/batch-$id/$file"
    chmod 400 "$stage/$case/batch-$id/$file"
    run "$case" fail
    [[ ! -e $stage/$case/receipts/$id ]]; ok
done
newstore symlink
ln -s "$stage/success/receipts" "$stage/symlink/receipts"
run symlink fail; ok
newstore pre_sync
run pre_sync fail "$stage/response.json" pre_sync
[[ ! -e $stage/pre_sync/receipts/$id ]]; ok
newstore post_sync
run post_sync fail "$stage/response.json" post_sync
[[ -d $stage/post_sync/receipts/$id ]]
run post_sync ok
jq -e .reused "$stage/post_sync.result" >/dev/null; ok
! grep -q 'synthetic_receipt_test' "$stage"/*.result; ok
[[ $(find "$stage" -type d -name '.pending-*' | wc -l) == 0 ]]
jq -nc --argjson passed "$passed" '{suite:"native_A_receipt_ack_synthetic",passed:$passed,failed:0,
  operational_wrapper_executed:false,actual_receipt_written:false,production_data_used:false,
  packages_installed:false,pending_fixture_directories:0}'
