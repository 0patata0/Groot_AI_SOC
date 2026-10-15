#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul
ulimit -f 65536
source /usr/local/lib/capstone-history-auto-transfer/transfer-lib.sh
phase=preflight work= count=0 fresh=0 reused=0 records=0 bytes=0 completed=false
finish() {
    local code=$?
    trap - EXIT TERM INT
    if (( code != 0 )); then
        # Preserve uncertain B attempts for inspection. No input retransmission.
        local result
        result=$(jq -cnS --arg phase "$phase" --argjson code "$code" --arg at "$(date --iso-8601=seconds)" \
          '{schema_version:1,status:"deferred",phase:$phase,exit_code:$code,observed_at_kst:$at,
            automatic_input_retry:false,source_changed:false,security_delivery_acknowledged:false}')
        if [[ -n $work && -d $work && ! -L $work ]]; then
            printf '%s\n' "$result" > "$work/failure.json"
            sync -- "$work/failure.json" "$work" || :
        fi
        printf '%s\n' "$result"
    fi
    exit "$code"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
# No raw, cursor, parser error, remote command or SSH credentials leave the worker.
exec 2>/dev/null
hat_parents "$HAT_ROOT"; hat_dir "$HAT_ROOT"; hat_dir "$HAT_ROOT/work"
hat_parents "$HAT_RECEIPTS"; hat_dir "$HAT_RECEIPTS"
hat_file "$HAT_ROOT/.lock" 600 0
hat_file "$HAT_RECEIPTS/.lock" 600 0
exec 8<>"$HAT_ROOT/.lock"; flock -n 8
hat_dependencies
hat_capacity 17039360
work=$(mktemp -d "$HAT_ROOT/work/run-XXXXXXXX")
mkdir -m 700 "$work/catalog"
phase=manifest_pull
hat_fetch_manifests "$work/catalog"
shopt -s nullglob dotglob
batches=("$work/catalog"/*)
(( ${#batches[@]} <= 256 ))
: > "$work/receipts.jsonl"
for batch in "${batches[@]}"; do
    phase=manifest_validation
    hat_dir "$batch"
    name=${batch##*/}; [[ $name =~ ^batch-([a-f0-9]{64})$ ]]; id=${BASH_REMATCH[1]}
    entries=("$batch"/*); [[ ${#entries[@]} == 1 && ${entries[0]} == "$batch/manifest.json" ]]
    hat_manifest "$batch/manifest.json" "$id"
    psha=$(jq -r .sha256 "$batch/manifest.json")
    msha=$(hat_sha "$batch/manifest.json")
    size=$(jq -r .bytes "$batch/manifest.json")
    record_count=$(jq -r .records "$batch/manifest.json")
    final=$HAT_RECEIPTS/batches/$id
    promoted=existing
    if [[ ! -e $final && ! -L $final ]]; then
        phase=capacity
        # fetch + root incoming + receiver partial/final + fixed overhead.
        hat_capacity "$((3 * (size + 65536) + 1048576))"
        phase=batch_pull
        mkdir -m 700 "$work/payload"
        maximum=$size; (( maximum >= 65536 )) || maximum=65536
        hat_fetch_batch "$id" "$work/payload" "$maximum"
        phase=receiver_incoming
        promoted=$(/bin/bash -c 'set -euo pipefail; umask 077; source "$1/transfer-lib.sh"; shift; hat_promote "$@"' \
          history-promote "$HAT_LIB" "$work/payload" "$id" "$psha" "$msha")
        [[ $promoted == existing || $promoted == created ]]
    fi
    phase=receiver_commit
    /usr/bin/timeout --signal=TERM --kill-after=2s 60s \
      /bin/bash "$HAT_RECEIVER/receive-batch.sh" "$id" "$psha" "$msha" > "$work/receipt.json"
    hat_receipt "$work/receipt.json" "$id" "$psha" "$msha"
    [[ $(jq -r .bytes "$work/receipt.json") == "$size" && $(jq -r .records "$work/receipt.json") == "$record_count" ]]
    cat "$work/receipt.json" >> "$work/receipts.jsonl"
    count=$((count+1)); records=$((records+record_count)); bytes=$((bytes+size))
    if [[ $(jq -r .reused "$work/receipt.json") == true ]]; then reused=$((reused+1)); else fresh=$((fresh+1)); fi
    # Acknowledged root incoming was created by THIS attempt. Never remove a
    # pre-existing/manual incoming directory, a final receipt, or anything on A.
    if [[ $promoted == created ]]; then
        phase=incoming_cleanup
        exec 9<>"$HAT_RECEIPTS/.lock"; flock -n 9
        target=$HAT_RECEIPTS/incoming/$id/$psha-$msha
        hat_dir "$target"
        hat_file "$target/kernel.jsonl" 400 33554432
        hat_file "$target/manifest.json" 400 65536
        [[ $(hat_sha "$target/kernel.jsonl") == "$psha" && $(hat_sha "$target/manifest.json") == "$msha" ]]
        rm -- "$target/kernel.jsonl" "$target/manifest.json"
        rmdir -- "$target"; sync -- "$HAT_RECEIPTS/incoming/$id"
        flock -u 9; exec 9>&-
    fi
    if [[ -d $work/payload ]]; then
        rm -- "$work/payload/kernel.jsonl" "$work/payload/manifest.json"; rmdir -- "$work/payload"
    fi
done
phase=finalize
hat_dependencies; hat_capacity 0
[[ $count == "${#batches[@]}" ]]
catalog_sha=$(hat_sha "$work/receipts.jsonl")
jq -cnS --arg at "$(date --iso-8601=seconds)" --arg sha "$catalog_sha" \
  --argjson batches "$count" --argjson fresh "$fresh" --argjson reused "$reused" \
  --argjson records "$records" --argjson bytes "$bytes" \
  '{schema_version:1,policy:"capstone-history-auto-transfer-v1",status:"remote_files_preserved",
    observed_at_kst:$at,source_machine_id:"096e90b6243e438aa8a7b392be754732",receiver_machine_id:"1e143067c98a44ffba6eaa925dc038d7",
    discovered_batches:$batches,verified_receipts:$batches,new_receipts:$fresh,reused_receipts:$reused,records:$records,bytes:$bytes,
    receipt_catalog_sha256:$sha,source_changed:false,source_acknowledged:false,security_delivery_acknowledged:false,
    scope:"completed_batch_manifest_snapshot",automatic_input_retry:false}' > "$work/status.json"
hat_publish "$work/receipts.jsonl" "$HAT_ROOT/latest-batches.jsonl"
hat_publish "$work/status.json" "$HAT_ROOT/status.json"
phase=work_cleanup
hat_cleanup_work "$work"; work=
cat "$HAT_ROOT/status.json"
completed=true
