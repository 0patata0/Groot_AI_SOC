#!/bin/bash
# Private root/Linux fixtures only. No live wrapper, Docker, service or raw input.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 77
here=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
predicate=$here/../collection/line-length/raw-line-status.jq
[[ $(sha256sum "$predicate" | cut -d' ' -f1) == a7e624a8d95877adf1c1ef997de7c3c56c59bf045e87c5a66bb762b582d445ca &&
   $(sha256sum "$here/line-length-lib-v2.sh" | cut -d' ' -f1) == 848acb15609d859d0643aebd02dd71554245ea5771cb80b6b9a4dec4b61dcf10 ]]
source "$here/raw-line-scan-v2.sh"
source "$here/state-lib.sh"
source "$here/line-length-lib-v2.sh"
sources_before=$(sha256sum "$here/raw-line-scan-v2.sh" "$here/state-lib.sh" "$here/state.jq" "$here/line-length-lib-v2.sh" "$predicate")
stage=$(mktemp -d /var/tmp/capstone-raw-state-test.XXXXXXXX)
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-raw-state-test\.[A-Za-z0-9]{8}$ && -d $stage &&
       ! -L $stage && $(stat -c %u:%g:%a "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
passed=0; checks='[]'
run_case() {
    local name=$1 rc; shift
    # A conditional subshell would suppress errexit throughout its functions.
    set +e
    ( set -e; "$@" ) > "$stage/stdout" 2> "$stage/stderr"
    rc=$?
    set -e
    if (( rc == 0 )); then
        passed=$((passed+1)); checks=$(jq -c --arg name "$name" '.+[$name]' <<< "$checks")
    else printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1; fi
}

fixture() {
    engine=$1; phase=$2; writer=${3:-pending}; reader=${4:-current}
    rm -rf -- "$stage/state" "$stage/source" "$stage/config"
    mkdir -m 700 "$stage/state" "$stage/source" "$stage/config"
    root=$stage/state; base=$stage/source; managed=$base/capstone-managed
    mkdir -m 711 "$managed"
    raw_state_prepare "$root" "$engine" >/dev/null
    cfg=$stage/config/vector.toml; env=$stage/config/vector.env; wazuh=$stage/config/ossec.conf
    printf 'fixture-vector\n' > "$cfg"; printf 'fixture-env\n' > "$env"; printf 'fixture-agent\n' > "$wazuh"
    chmod 600 "$cfg" "$env" "$wazuh"
    current=$managed/generation-0000000004.jsonl; pending=$managed/generation-0000000005.jsonl
    uid=101; alias=$base/audit.log
    if [[ $engine == suricata ]]; then uid=998; alias=$base/eve.json; fi
    printf 'old-seven\n' > "$current"
    chown "$uid:$uid" "$current"; chmod 644 "$current"
    if [[ $phase == active ]]; then
        writer=current; reader=current
    else
        printf 'new\n' > "$pending"; chown "$uid:$uid" "$pending"; chmod 644 "$pending"
    fi
    ln -- "${!reader}" "$alias"
    engine_sha=$(printf 'e%.0s' {1..64})
    old_writer_sha=$engine_sha; next_writer_sha=$engine_sha
    if [[ $engine == suricata ]]; then
        ln -- "${!writer}" "$managed/active.jsonl"
    else
        old_writer_sha=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${current##*/}" | sha256sum | cut -d' ' -f1)
        next_writer_sha=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${pending##*/}" | sha256sum | cut -d' ' -f1)
        printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${!writer##*/}" > "$managed/audit-path.conf"
        chmod 444 "$managed/audit-path.conf"
    fi
    if [[ $phase != active && $phase != switch_pending ]]; then chown 0:0 "$current"; chmod 400 "$current"; fi
    local current_gen pending_gen=null oldproof=null drainproof=null publishproof=null bytes oldsha oldsha1
    current_gen=$(jq -nc --argjson dev "$(stat -c %d "$current")" --argjson ino "$(stat -c %i "$current")" --arg sha "$old_writer_sha" \
      '{number:4,basename:"generation-0000000004.jsonl",device:$dev,inode:$ino,writer_config_sha256:$sha}')
    if [[ $phase != active ]]; then
        pending_gen=$(jq -nc --argjson dev "$(stat -c %d "$pending")" --argjson ino "$(stat -c %i "$pending")" --arg sha "$next_writer_sha" \
          '{number:5,basename:"generation-0000000005.jsonl",device:$dev,inode:$ino,writer_config_sha256:$sha}')
    fi
    if [[ $phase != active && $phase != switch_pending ]]; then
        bytes=$(stat -c %s "$current"); oldsha=$(rls_sha "$current"); oldsha1=$(sha1sum "$current" | cut -d' ' -f1)
        oldproof=$(jq -nc --argjson current "$current_gen" --argjson bytes "$bytes" --arg sha "$oldsha" \
          '{boot_id:("a"*32),bytes:$bytes,device:$current.device,inode:$current.inode,sha256:$sha,writer_fd_zero:true,writer_pid:100,writer_start_ticks:10}')
    fi
    if [[ $phase == readers_drained || $phase == publish_pending ]]; then
        drainproof=$(jq -nc --argjson bytes "$bytes" --arg sha1 "$oldsha1" \
          '{vector_checkpoint_sha256:("b"*64),vector_offset:$bytes,vector_stopped:true,wazuh_checkpoint_sha256:("c"*64),wazuh_offset:$bytes,wazuh_sha1:$sha1}')
    fi
    if [[ $phase == publish_pending ]]; then
        publishproof=$(jq -nc --argjson bytes "$bytes" --arg sha1 "$oldsha1" \
          '{decision:"different_prefix",new_prefix_sha1:("d"*40),old_offset:$bytes,old_sha1:$sha1,source_bytes:4,wazuh_checkpoint_sha256:("c"*64)}')
    fi
    jq -ncS --arg engine "$engine" --arg phase "$phase" --arg engine_sha "$engine_sha" \
      --arg cfg "$(rls_sha "$cfg")" --arg env "$(rls_sha "$env")" --arg wazuh "$(rls_sha "$wazuh")" \
      --argjson current "$current_gen" --argjson pending "$pending_gen" --argjson closed "$oldproof" \
      --argjson drained "$drainproof" --argjson publication "$publishproof" \
      '{schema_version:1,policy:"capstone-raw-operations-v1",engine:$engine,machine_id:"096e90b6243e438aa8a7b392be754732",
        boot_id:("a"*32),revision:7,phase:$phase,source_pins:{container_id:("f"*64),engine_config_sha256:$engine_sha,
          producer_format_sha256:("d"*64),vector_config_sha256:$cfg,vector_env_sha256:$env,wazuh_config_sha256:$wazuh},
        current:$current,pending:$pending,proof:{old_closed:$closed,readers_drained:$drained,publish_guard:$publication}}' \
      > "$root/$engine/state.json"
    chmod 600 "$root/$engine/state.json"
}
scan_engine() { rls_engine "$root" "$engine" "$base" "$cfg" "$env" "$wazuh"; }
snapshot() { rls_snapshot "$root" "$engine" "$base" "$cfg" "$env" "$wazuh"; }
statuses() {
    local selected=$1 healthy envelope
    healthy=$(ll_emit within_scanned_range range_within_limit false true true true 0 0 0 0 0 1048576 33554432 5)
    envelope=$(jq -nc --argjson selected "$selected" --argjson healthy "$healthy" \
      '{schema_version:1,scope:"periodic_snapshot_tail",selection:[$selected.selection],
        sources:[($selected.row+{source:"suricata"}),($healthy+{source:"waf_audit"}),($healthy+{source:"waf_access"})]}')
    jq -c -f "$predicate" <<< "$envelope"
}
phase_case() {
    fixture "$1" "$2" "$3" "$4"
    local result writer_number=5 reader_number=4 count=2
    [[ $writer != current ]] || writer_number=4
    [[ $reader != pending ]] || reader_number=5
    [[ $phase != active ]] || count=1
    result=$(scan_engine)
    jq -e --argjson writer "$writer_number" --argjson reader "$reader_number" --argjson count "$count" \
      '.row.verdict=="within_scanned_range" and .selection.metadata_verified and .selection.reason=="writer_snapshot" and
       .selection.writer_generation==$writer and .selection.reader_generation==$reader and
       (.selection.scanned_generations|length)==$count and .selection.selected_generation==$writer' <<< "$result" >/dev/null
    [[ $(statuses "$result") == '[]' ]]
}
for engine_name in suricata modsecurity; do
    run_case "$engine_name-active" phase_case "$engine_name" active current current
    run_case "$engine_name-before-switch" phase_case "$engine_name" switch_pending current current
    run_case "$engine_name-after-switch" phase_case "$engine_name" switch_pending pending current
    for phase_name in old_closed readers_drained publish_pending; do
        run_case "$engine_name-$phase_name" phase_case "$engine_name" "$phase_name" pending current
    done
    run_case "$engine_name-published-alias" phase_case "$engine_name" publish_pending pending pending
done

sealed_before_cas() {
    fixture "$1" switch_pending pending current
    chown 0:0 "$current"; chmod 400 "$current"
    local result; result=$(scan_engine)
    jq -e '.selection.metadata_verified and .row.verdict=="within_scanned_range" and .selection.selected_generation==5' <<< "$result" >/dev/null
}
run_case suricata-sealed-before-cas sealed_before_cas suricata
run_case waf-sealed-before-cas sealed_before_cas modsecurity

rejection_case() {
    local variant=$1 result
    fixture modsecurity switch_pending pending current
    case $variant in
      extra_link) ln "$pending" "$base/unexpected" ;;
      wrong_alias) rm "$alias"; printf 'unrelated\n' > "$alias" ;;
      symlink_alias) rm "$alias"; ln -s "$current" "$alias" ;;
      wrong_pointer) printf 'wrong\n' > "$managed/audit-path.conf" ;;
      pointer_permissions) chmod 644 "$managed/audit-path.conf" ;;
      sealed_writer) chown 0:0 "$pending"; chmod 400 "$pending" ;;
      publish_residual) ln "$pending" "$managed/.publish-link" ;;
      pointer_residual) printf 'candidate\n' > "$managed/.audit-path.next" ;;
      config_drift) printf 'drift\n' >> "$cfg" ;;
      env_drift) printf 'drift\n' >> "$env" ;;
      agent_drift) printf 'drift\n' >> "$wazuh" ;;
      noncanonical_state) printf '\n' >> "$root/$engine/state.json" ;;
      missing_pending) rm "$pending" ;;
      managed_mode) chmod 777 "$managed" ;;
      *) return 1 ;;
    esac
    result=$(scan_engine)
    jq -e '.row.verdict=="inconclusive" and (.selection.metadata_verified|not) and .selection.scanned_generations==[]' <<< "$result" >/dev/null
    [[ $(statuses "$result") == '["collection_raw_line_scan_unavailable"]' ]]
}
for variant in extra_link wrong_alias symlink_alias wrong_pointer pointer_permissions sealed_writer publish_residual pointer_residual config_drift env_drift agent_drift noncanonical_state missing_pending managed_mode; do
    run_case "reject-$variant" rejection_case "$variant"
done

selection_case() {
    local variant=$1 plan rows result old_size new_size
    fixture suricata switch_pending pending current
    case $variant in
      old_positive|positive_inconclusive|positive_metadata_changed)
        head -c 1048577 /dev/zero | tr '\000' A > "$current" ;;
      writer_positive) head -c 1048578 /dev/zero | tr '\000' B > "$pending" ;;
    esac
    plan=$(snapshot)
    if [[ $variant == positive_inconclusive || $variant == inconclusive ]]; then chmod 600 "$pending"; fi
    rows=$(rls_scan_lanes "$plan")
    if [[ $variant == positive_metadata_changed ]]; then result=$(rls_select suricata "$plan" "$rows" false)
    else result=$(rls_select suricata "$plan" "$rows" true); fi
    case $variant in
      old_positive)
        jq -e '.row.verdict=="oversize" and .row.snapshot_bytes==1048577 and .selection.selected_generation==4' <<< "$result" >/dev/null
        [[ $(statuses "$result") == '["collection_raw_line_oversize_seen"]' ]] ;;
      writer_positive)
        jq -e '.row.verdict=="oversize" and .row.snapshot_bytes==1048578 and .selection.selected_generation==5' <<< "$result" >/dev/null
        [[ $(statuses "$result") == '["collection_raw_line_oversize_seen"]' ]] ;;
      positive_inconclusive|positive_metadata_changed)
        jq -e '.row.verdict=="inconclusive" and .row.observed_positive and .row.snapshot_bytes==1048577 and
          .row.max_line_bytes==1048577 and (.row.complete_snapshot_range|not) and .selection.selected_generation==4' <<< "$result" >/dev/null
        [[ $(statuses "$result") == '["collection_raw_line_oversize_seen","collection_raw_line_scan_unavailable"]' ]] ;;
      inconclusive)
        jq -e '.row.verdict=="inconclusive" and .selection.selected_generation==5 and .selection.reason=="inconclusive_priority"' <<< "$result" >/dev/null
        [[ $(statuses "$result") == '["collection_raw_line_scan_unavailable"]' ]] ;;
      writer_range_only)
        jq -e '.row.snapshot_bytes==4 and .row.scanned_bytes==4 and .row.max_line_bytes==3 and
          .selection.selected_generation==5 and .selection.scanned_generations==[4,5]' <<< "$result" >/dev/null ;;
    esac
}
for variant in old_positive writer_positive positive_inconclusive positive_metadata_changed inconclusive writer_range_only; do
    run_case "$variant" selection_case "$variant"
done

changed_after_scan() {
    fixture suricata switch_pending pending current
    head -c 1048577 /dev/zero | tr '\000' A > "$current"
    eval "$(declare -f rls_scan_lanes | sed '1s/rls_scan_lanes/real_scan_lanes/')"
    rls_scan_lanes() { local result; result=$(real_scan_lanes "$1") || return 1; chmod 600 "$pending"; printf '%s\n' "$result"; }
    local result; result=$(scan_engine)
    jq -e '.selection.reason=="metadata_changed" and .row.observed_positive and .row.verdict=="inconclusive"' <<< "$result" >/dev/null
    [[ $(statuses "$result") == '["collection_raw_line_oversize_seen","collection_raw_line_scan_unavailable"]' ]]
}
run_case postscan-change-preserves-positive changed_after_scan

three_source_envelope() {
    local suri waf access result
    fixture suricata active current current; suri=$(scan_engine)
    fixture modsecurity active current current; waf=$(scan_engine)
    printf 'auxiliary\n' > "$base/access.log"; chown 101:101 "$base/access.log"; chmod 640 "$base/access.log"
    access=$(ll_scan "$base/access.log" 101 101 640 1048576 33554432 5 1)
    RLS_PREDICATE=$predicate
    result=$(rls_envelope "$suri" "$waf" "$access")
    (( ${#result} < 16384 ))
    jq -e '.statuses==[] and [.sources[].source]==["suricata","waf_audit","waf_access"] and
      (.selection|length)==2 and (.observed_at_kst|endswith("+09:00"))' <<< "$result" >/dev/null
    [[ $(jq -c -f "$predicate" <<< "$result") == '[]' ]]
}
run_case three-source-envelope-compatible three_source_envelope

parallel_timeout() {
    fixture suricata switch_pending pending current
    local plan start elapsed rows
    plan=$(snapshot)
    # Private synthetic replacement for the worker only. No production path
    # permits this selection. Both direct timeout groups must be reaped <=8s.
    _LL_SELF=$stage/slow-fixture.sh
    printf '#!/bin/bash\ntrap "" TERM\nexec /bin/sleep 20\n' > "$_LL_SELF"
    start=$SECONDS
    rows=$(rls_scan_lanes "$plan")
    elapsed=$((SECONDS-start))
    jq -e 'length==2 and all(.[];.row.verdict=="inconclusive" and .row.reason=="scan_timeout")' <<< "$rows" >/dev/null
    (( elapsed >= 5 && elapsed <= 8 ))
}
run_case two-workers-bounded-parallel-timeout parallel_timeout

[[ $(sha256sum "$here/raw-line-scan-v2.sh" "$here/state-lib.sh" "$here/state.jq" "$here/line-length-lib-v2.sh" "$predicate") == "$sources_before" ]]
cleanup; trap - EXIT
jq -nc --argjson tests "$passed" --argjson checks "$checks" --arg sources "$sources_before" \
  '{status:"passed",native_tests:$tests,checks:$checks,synthetic_only:true,live_wrapper_executed:false,
    services_changed:false,raw_payload_exported:false,source_sha256_unchanged:true,source_hashes:$sources,
    original_predicate_unchanged:true,fixture_removed:true,maximum_parallel_workers:2,
    scanner_rows:3,range_union_performed:false,selection_persisted_by_existing_maintenance:false}'
