#!/bin/bash
# Native, root-only synthetic fixtures. Never calls the fixed live wrapper.
set -euo pipefail
PATH=/usr/bin:/bin; export PATH LC_ALL=C TZ=Asia/Seoul
umask 077
[[ $EUID == 0 && $OSTYPE == linux* && $# == 0 ]] || exit 77
here=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
library=$here/line-length-lib.sh
predicate=$here/raw-line-status.jq
source "$library"
fixture_root=/var/tmp/capstone-sequential-20261014/step2
[[ -d $fixture_root && ! -L $fixture_root && $(stat -c '%u:%a' "$fixture_root") == 0:700 ]] || exit 77
stage=$(mktemp -d "$fixture_root/line-length-fixture.XXXXXXXX")
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-sequential-20261014/step2/line-length-fixture\.[A-Za-z0-9]{8}$ &&
       -d $stage && ! -L $stage && $(stat -c %u "$stage") == 0 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
initial_sha=$(sha256sum "$library" "$predicate")
passed=0
input=$stage/input.log
emit() { head -c "$1" /dev/zero | tr '\000' A; }
check() {
    local expression=$1
    jq -e "$expression" <<< "$result" >/dev/null || { printf 'native_fixture_failed=%s\n' "$case_id" >&2; exit 1; }
    passed=$((passed+1))
}
scan() { result=$(ll_scan "$input" 0 0 600 1048576 33554432 5); }

case_id=empty; : > "$input"; scan
check '.verdict=="within_scanned_range" and .scanned_bytes==0 and .max_line_bytes==0 and .full_file_scan'
for size in 1048575 1048576 1048577; do
    for ending in eof newline; do
        case_id=boundary_${size}_${ending}; emit "$size" > "$input"
        if [[ $ending == newline ]]; then printf '\n' >> "$input"; fi
        scan
        if ((size>1048576)); then
            check ".verdict==\"oversize\" and .observed_positive and .max_line_bytes==$size and .complete_snapshot_range and .full_file_scan"
        else
            check ".verdict==\"within_scanned_range\" and (.observed_positive|not) and .max_line_bytes==$size and .full_file_scan"
        fi
    done
done
case_id=byte_semantics
printf '\000\t\r\303\251\344\270\255\n\000\t\r\303\251\344\270\255' > "$input"; scan
check '.scanned_bytes==17 and .max_line_bytes==8 and .verdict=="within_scanned_range"'
case_id=oversize_after_newline
printf 'short\n' > "$input"; emit 1048577 >> "$input"; scan
check '.max_line_bytes==1048577 and .verdict=="oversize"'

case_id=large_eof_positive
head -c 33554432 /dev/zero | tr '\000' '\n' > "$input"; emit 1048577 >> "$input"; scan
check '.range_start==1048577 and .scanned_bytes==33554432 and .max_line_bytes==1048577 and .verdict=="oversize" and (.full_file_scan|not)'
case_id=large_first_fragment_positive
emit 33554433 > "$input"; printf '\nend\n' >> "$input"; scan
check '.range_start==6 and .scanned_bytes==33554432 and .max_line_bytes==33554427 and .verdict=="oversize" and .leading_fragment_possible'
case_id=positive_only_outside_tail
emit 1048577 > "$input"; printf '\n' >> "$input"; head -c 33554432 /dev/zero | tr '\000' '\n' >> "$input"; scan
check '.range_start==1048578 and .scanned_bytes==33554432 and .max_line_bytes==0 and .verdict=="within_scanned_range" and (.full_file_scan|not)'

case_id=owner_mismatch
result=$(ll_scan "$input" 998 998 600 1048576 33554432 5)
check '.verdict=="inconclusive" and .reason=="metadata_mismatch"'
case_id=mode_mismatch
result=$(ll_scan "$input" 0 0 640 1048576 33554432 5)
check '.verdict=="inconclusive" and .reason=="metadata_mismatch"'
case_id=file_symlink
ln -s input.log "$stage/link.log"
result=$(ll_scan "$stage/link.log" 0 0 600 1048576 33554432 5)
check '.verdict=="inconclusive" and .reason=="source_unavailable"'
case_id=ancestor_symlink
mkdir "$stage/real"; printf 'ok\n' > "$stage/real/input.log"; ln -s real "$stage/linked"
result=$(ll_scan "$stage/linked/input.log" 0 0 600 1048576 33554432 5)
check '.verdict=="inconclusive" and .reason=="source_unavailable"'
case_id=fifo
mkfifo "$stage/fifo"
result=$(ll_scan "$stage/fifo" 0 0 600 1048576 33554432 5)
check '.verdict=="inconclusive" and .reason=="source_unavailable"'
case_id=missing
result=$(ll_scan "$stage/missing" 0 0 600 1048576 33554432 5)
check '.verdict=="inconclusive" and .reason=="source_unavailable"'

# Test-only instrumentation: pause a private copy inside the worker, proving
# the real GNU timeout path. The deployed source and live wrapper are unchanged.
case_id=bounded_timeout
sed 's/local owner_pid=$BASHPID/local owner_pid=$BASHPID; \/usr\/bin\/sleep 2/' "$library" > "$stage/slow-lib.sh"
original_self=$_LL_SELF; _LL_SELF=$stage/slow-lib.sh
result=$(ll_scan "$input" 0 0 600 1048576 33554432 1); _LL_SELF=$original_self
check '.verdict=="inconclusive" and .reason=="scan_timeout"'

# Deterministic read/change boundary: in a subprocess only, wrap the stat
# helper so the real fixture is changed immediately after the second stat.
# All reading, dd, tr, wc and the post-change oracle remain the real code.
for mutation in append truncate regrow rename; do
    case_id=changed_${mutation}; emit 1048577 > "$input"; printf '0\n' > "$stage/calls"
    result=$(
      ll_file_stat() {
        /usr/bin/stat -c '%d|%i|%s|%u|%g|%a|%h|%f|%y|%z' -- "$1"
        n=$(cat "$stage/calls"); printf '%s\n' "$((n+1))" > "$stage/calls"
        if [[ $n == 1 ]]; then
            if [[ $mutation == append ]]; then
                printf 'X' >> "$input"
            elif [[ $mutation == truncate ]]; then
                truncate -s 0 "$input"
            elif [[ $mutation == regrow ]]; then
                truncate -s 0 "$input"; emit 1048577 > "$input"
            else
                mv -- "$input" "$stage/replaced.log"; emit 1048577 > "$input"
            fi
        fi
      }
      ll_worker "$input" 0 0 600 1048576 33554432 5
    )
    if [[ $mutation == append ]]; then
        check '.verdict=="inconclusive" and .reason=="file_changed" and .observed_positive and (.file_stable|not)'
        changed_positive=$result
    else
        check '.verdict=="inconclusive" and .reason=="file_changed" and (.complete_snapshot_range|not)'
    fi
done

case_id=pipeline_failure
emit 1048577 > "$input"
sed 's@/usr/bin/tr -c .* | /usr/bin/wc -c -L@/bin/false | /usr/bin/wc -c -L@' "$library" > "$stage/failing-lib.sh"
grep -q '/bin/false' "$stage/failing-lib.sh"
original_self=$_LL_SELF; _LL_SELF=$stage/failing-lib.sh
result=$(ll_scan "$input" 0 0 600 1048576 33554432 5); _LL_SELF=$original_self
check '.verdict=="inconclusive" and .reason=="scan_error" and .file_stable and (.complete_snapshot_range|not)'

# Predicate checks: statuses cannot be forged by suppressing a positive row or
# claiming a partial/changed range was a complete negative observation.
printf 'ok\n' > "$input"; scan; good=$result
envelope=$(jq -nc --argjson row "$good" '{schema_version:1,scope:"periodic_snapshot_tail",sources:[$row+{source:"suricata"},$row+{source:"waf_audit"},$row+{source:"waf_access"}]}')
case_id=predicate_valid; result=$(jq -c -f "$predicate" <<< "$envelope"); check '.==[]'
case_id=predicate_positive_changed
mixed=$(jq -c --argjson changed "$changed_positive" '.sources[0]=$changed+{source:"suricata"}' <<< "$envelope")
result=$(jq -c -f "$predicate" <<< "$mixed")
check '.==["collection_raw_line_oversize_seen","collection_raw_line_scan_unavailable"]'
for mutation in '.sources+= [.sources[0]]' '.sources[0].source="waf_audit"' '.sources[0].scanned_bytes=-1' '.sources[0].observed_positive=true' '.sources[0].unexpected="payload"' '.sources[0].full_file_scan=false'; do
    case_id=predicate_bad_metadata
    result=$(jq -c "$mutation" <<< "$envelope" | jq -c -f "$predicate")
    check '.==["collection_raw_line_scan_unavailable"]'
done
case_id=predicate_invalid_json
if printf '{' | jq -c -f "$predicate" >/dev/null 2>&1; then exit 1; fi
passed=$((passed+1))
case_id=predicate_multiple_documents
result=$(printf '%s\n%s\n' "$envelope" "$envelope" | jq -c -f "$predicate")
check '.==["collection_raw_line_scan_unavailable"]'
[[ $(sha256sum "$library" "$predicate") == "$initial_sha" ]]
jq -nc --argjson tests "$passed" '{status:"passed",native_tests:$tests,synthetic_only:true,
  live_wrapper_executed:false,production_sources_opened:false,production_paths_changed:false,
  original_library_and_predicate_unchanged:true,raw_payload_exported:false}'
