#!/bin/bash
# Linux root synthetic-only fixture. No SSH, real key, account or live store.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul
[[ $(uname -s) == Linux && $EUID == 0 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
receiver=$directory/../history-transfer
stage=$(mktemp -d /var/tmp/capstone-history-pull-test.XXXXXXXX)
case_name=setup passed=0
trap 'rc=$?; if ((rc)); then printf "{\"status\":\"failed\",\"case\":\"%s\",\"exit\":%s}\n" "$case_name" "$rc"; fi; rm -rf -- "$stage"' EXIT
ok() { passed=$((passed+1)); }
rejected() { local rc=0; "$@" >/dev/null 2>&1 || rc=$?; ((rc!=0)); }
# Test the real function definitions without executing either operational entry.
sed '/^# PUBLIC ENTRY:/,$d' "$directory/export-a.sh" > "$stage/export-functions.sh"
source "$stage/export-functions.sh"
case_name=sender; ha_command 'rsync --server --sender -re.iLsfxCIvu --max-size=65536 . ./'; ok
for command in 'rsync --server -r . ./' 'rsync --server --sender -r . ../' 'rsync --server --sender -r --remove-source-files . ./' 'rsync --server --sender -r --delete . ./' 'rsync --server --sender -r --log-file=x . ./' 'rsync --server --sender -r . ./;id' $'rsync --server --sender -r . ./\nid' 'rsync --server --sender -r --only-write-batch=/tmp/x . ./' 'rsync --server --sender -r --temp-dir=/tmp . ./' 'rsync --server --sender -r --backup-dir=/tmp . ./'; do
    case_name=reject_sender; rejected ha_command "$command"; ok
done
case_name=export_store
mkdir -m 700 "$stage/export"; : > "$stage/export/.lock"; chmod 600 "$stage/export/.lock"
ha_store "$stage/export"; ok
ln -s /dev/null "$stage/export/link"; rejected ha_store "$stage/export"; rm "$stage/export/link"; ok
ln "$stage/export/.lock" "$stage/export/hard"; rejected ha_store "$stage/export"; rm "$stage/export/hard"; ok
mkfifo "$stage/export/fifo"; rejected ha_store "$stage/export"; rm "$stage/export/fifo"; ok
: > "$stage/export/rrsync.log"; rejected ha_store "$stage/export"; rm "$stage/export/rrsync.log"; ok

mkdir -m 700 "$stage/history-transfer" "$stage/history" "$stage/lib"
for name in receive-batch.sh receive-run.sh receive-lib.sh validate-manifest.jq; do cp "$receiver/$name" "$stage/history-transfer/$name"; done
cp "$receiver/../history/validate-records.jq" "$stage/history/validate-records.jq"
[[ $(sha256sum "$stage/history/validate-records.jq" | cut -d ' ' -f1) == 2470fab15dfde40540d60a3e47f4de8a6f5520f46acb231d1067895c770ffaa9 ]]
source "$stage/history-transfer/receive-lib.sh"
source "$directory/transfer-lib.sh"
HAT_RECEIVER=$stage/history-transfer
# Installed rsync builds its real remote argv, but the transport is a private
# recorder that exits without opening any socket. This closes the CLI contract.
mkdir -m 700 "$stage/transport" "$stage/no-network"
cat > "$stage/transport/ssh-b.sh" <<RECORDER
#!/bin/bash
printf '%s\\n' "\$@" > '$stage/transport/argv'
exit 47
RECORDER
HAT_LIB=$stage/transport
case_name=rsync_manifest_argv
rejected hat_fetch_manifests "$stage/no-network"
mapfile -t arguments < "$stage/transport/argv"
[[ ${arguments[0]} == 10.200.10.1 && ${arguments[1]} == rsync && ${arguments[2]} == --server && ${arguments[3]} == --sender ]]
ha_command "$(printf '%s ' "${arguments[@]:1}")"; ok
case_name=rsync_batch_argv
rejected hat_fetch_batch "$(printf 'a%.0s' {1..64})" "$stage/no-network" 65536
mapfile -t arguments < "$stage/transport/argv"
[[ ${arguments[0]} == 10.200.10.1 && ${arguments[1]} == rsync && ${arguments[2]} == --server && ${arguments[3]} == --sender ]]
ha_command "$(printf '%s ' "${arguments[@]:1}")"; ok
# Reuse the immutable receiver fixture generator, not its operational wrapper.
[[ $(sha256sum "$receiver/test-native.sh" | cut -d ' ' -f1) == 9e5fdfcb8c171a78ec7a696b55966df0f2a67d218c2408511692cd6993da753a ]]
awk '/^fixture\(\) \{/{on=1} /^revise_manifest\(\)/{on=0} on{print}' "$receiver/test-native.sh" > "$stage/generator.sh"
source "$stage/generator.sh"
directory_saved=$directory; directory=$stage/history-transfer
fixture valid
directory=$directory_saved
cp "$incoming/manifest.json" "$stage/manifest.json"
case_name=manifest_valid; hat_manifest "$stage/manifest.json" "$id"; ok
for filter in '.policy="unknown"' '.bytes=33554433' '.records=1001' '.batch_id=("a"*64)' '.selection.max_records="1000"' '.status="partial"'; do
    case_name=manifest_invalid
    jq "$filter" "$incoming/manifest.json" > "$stage/bad.json"
    rejected hat_manifest "$stage/bad.json" "$id"; ok
done
case_name=manifest_multidoc
cat "$incoming/manifest.json" "$incoming/manifest.json" > "$stage/bad.json"
rejected hat_manifest "$stage/bad.json" "$id"; ok
case_name=manifest_duplicate
sed '1s/{/{"policy":"unknown",/' "$incoming/manifest.json" > "$stage/bad.json"
rejected hat_manifest "$stage/bad.json" "$id"; ok
case_name=manifest_symlink
ln -s "$incoming/manifest.json" "$stage/link.json"; rejected hat_manifest "$stage/link.json" "$id"; ok

# Private-copy worker integration. Changes are only fixed paths/MID in this
# temporary receiver wrapper, one source path in worker, and test-only transport
# and dependency hooks appended to an exact copy of the candidate library.
mkdir -m 700 "$stage/source" "$stage/source/batch-$id" "$stage/target" "$stage/target/work" "$stage/receipts"
cp "$incoming/kernel.jsonl" "$incoming/manifest.json" "$stage/source/batch-$id/"
: > "$stage/target/.lock"; : > "$stage/receipts/.lock"
sed -e "s@/var/lib/capstone-history-receipts@$stage/receipts@g" \
    -e "s@1e143067c98a44ffba6eaa925dc038d7@$(cat /etc/machine-id)@g" \
    "$receiver/receive-batch.sh" > "$stage/history-transfer/receive-batch.sh"
cp "$directory/transfer-lib.sh" "$stage/lib/transfer-lib.sh"
cat >> "$stage/lib/transfer-lib.sh" <<HOOKS
HAT_LIB=$stage/lib
HAT_ROOT=$stage/target
HAT_RECEIPTS=$stage/receipts
HAT_RECEIVER=$stage/history-transfer
hat_dependencies() { :; }
hat_parents() { :; } # private fixture lives under /var/tmp; public paths unchanged.
hat_fetch_manifests() {
 mkdir -m 700 "\$1/batch-$id"
 cp '$stage/source/batch-$id/manifest.json' "\$1/batch-$id/manifest.json"
}
hat_fetch_batch() {
 [[ \$1 == '$id' ]]
 printf 'fetch\n' >> '$stage/fetches'
 cp '$stage/source/batch-$id/kernel.jsonl' '$stage/source/batch-$id/manifest.json' "\$2/"
}
HOOKS
sed "s@source /usr/local/lib/capstone-history-auto-transfer/transfer-lib.sh@source $stage/lib/transfer-lib.sh@" "$directory/worker-b.sh" > "$stage/lib/worker-b.sh"
# Receiver pin checker is unchanged except its fixed machine/store paths above.
chmod 600 "$stage/history/validate-records.jq"
chmod 644 "$stage/history-transfer/"*
run_worker() { /bin/bash "$stage/lib/worker-b.sh" > "$stage/result.json" 2> "$stage/error"; }
case_name=worker_first
run_worker
jq -e '.status=="remote_files_preserved" and .new_receipts==1 and .reused_receipts==0 and .records==3 and .source_changed==false and .source_acknowledged==false and .security_delivery_acknowledged==false' "$stage/result.json" >/dev/null
[[ $(find "$stage/target/work" -mindepth 1 | wc -l) == 0 && $(wc -l < "$stage/fetches") == 1 ]]
receipt=$(cat "$stage/receipts/batches/$id/receipt.sha256")
ok
case_name=worker_retry
run_worker
jq -e '.new_receipts==0 and .reused_receipts==1 and .records==3' "$stage/result.json" >/dev/null
[[ $(cat "$stage/receipts/batches/$id/receipt.sha256") == "$receipt" && $(wc -l < "$stage/fetches") == 1 ]]
ok
case_name=same_id_manifest_conflict
printf '\n' >> "$stage/source/batch-$id/manifest.json"
rejected run_worker
[[ $(cat "$stage/receipts/batches/$id/receipt.sha256") == "$receipt" && $(wc -l < "$stage/fetches") == 1 ]]
jq -e '.status=="deferred" and .phase=="receiver_commit"' "$stage/result.json" >/dev/null
ok
case_name=quota
HAT_ROOT=$stage/target HAT_RECEIPTS=$stage/receipts HAT_QUOTA=1
rejected hat_capacity 0; ok
case_name=metadata_no_raw
! grep -Eq 'SYNTHETIC_RAW|SYNTHETIC_CURSOR|__CURSOR|MESSAGE' "$stage/result.json" "$stage/error" "$stage/target/status.json"
ok
printf '{"status":"passed","cases":%s,"operational_paths_used":false,"ssh_calls":0,"source_changes":false}\n' "$passed"
