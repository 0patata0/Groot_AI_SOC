#!/bin/bash
# Existing stage2 native suite plus exact 1..3-link fixtures. No live wrapper.
set -euo pipefail
PATH=/usr/bin:/bin; export PATH LC_ALL=C TZ=Asia/Seoul
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 77
here=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
old=$here/../collection/line-length
library=$here/line-length-lib-v2.sh
original_library_sha=028ac32906a2a7964d46c01a81f42f23e975b25bc6b99593ef97c4bb3676b447
original_tests_sha=a68d83c790bf5064ec6eb25f6cc4b34a088ad933a0e42025d1bf89850190c16d
original_predicate_sha=a7e624a8d95877adf1c1ef997de7c3c56c59bf045e87c5a66bb762b582d445ca
candidate_sha=848acb15609d859d0643aebd02dd71554245ea5771cb80b6b9a4dec4b61dcf10
[[ $(sha256sum "$old/line-length-lib.sh" | cut -d' ' -f1) == "$original_library_sha" &&
   $(sha256sum "$old/test-native.sh" | cut -d' ' -f1) == "$original_tests_sha" &&
   $(sha256sum "$old/raw-line-status.jq" | cut -d' ' -f1) == "$original_predicate_sha" &&
   $(sha256sum "$library" | cut -d' ' -f1) == "$candidate_sha" ]]
original_before=$(sha256sum "$old/line-length-lib.sh" "$old/test-native.sh" "$old/raw-line-status.jq" "$library")
fixture_root=/var/tmp/capstone-sequential-20261014/step3
[[ -d $fixture_root && ! -L $fixture_root && $(stat -c '%u:%a' "$fixture_root") == 0:700 ]] || exit 77
stage=$(mktemp -d "$fixture_root/line-length-v2-fixture.XXXXXXXX")
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-sequential-20261014/step3/line-length-v2-fixture\.[A-Za-z0-9]{8}$ &&
       -d $stage && ! -L $stage && $(stat -c %u "$stage") == 0 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
# Only two pinned private fixture path strings change in the test copy; the
# original stage2 source and all 34 case bodies remain unchanged. Do not recreate
# the already-closed step2 task directory.
mkdir -m 700 "$stage/legacy-suite"
cp -- "$library" "$stage/legacy-suite/line-length-lib.sh"
cp -- "$old/raw-line-status.jq" "$stage/legacy-suite/"
old_fixture=/var/tmp/capstone-sequential-20261014/step2
[[ $(grep -oF "$old_fixture" "$old/test-native.sh" | wc -l) == 2 ]]
sed "s@$old_fixture@$fixture_root@g" "$old/test-native.sh" > "$stage/legacy-suite/test-native.sh"
[[ $(grep -oF "$fixture_root" "$stage/legacy-suite/test-native.sh" | wc -l) == 2 ]]
! grep -qF "$old_fixture" "$stage/legacy-suite/test-native.sh"
legacy_fixture_sha=$(sha256sum "$stage/legacy-suite/test-native.sh" | cut -d' ' -f1)
[[ $(sha256sum "$stage/legacy-suite/line-length-lib.sh" | cut -d' ' -f1) == "$candidate_sha" ]]
/bin/bash "$stage/legacy-suite/test-native.sh" > "$stage/legacy-result.json"
jq -se 'length==1 and .[0].status=="passed" and .[0].native_tests==34 and
  .[0].synthetic_only and (.[0].live_wrapper_executed|not) and (.[0].raw_payload_exported|not)' \
  "$stage/legacy-result.json" >/dev/null
source "$library"
input=$stage/input.log
printf 'short\n' > "$input"
passed=0
check() {
    jq -e "$1" <<< "$result" >/dev/null || { printf 'failed_case=%s\n' "$case_name" >&2; exit 1; }
    passed=$((passed+1))
}
scan() { result=$(ll_scan "$input" 0 0 600 1048576 33554432 5 "$@"); }
case_name=single_default; scan
check '.verdict=="within_scanned_range" and .max_line_bytes==5 and .file_stable'
case_name=single_explicit; scan 1
check '.verdict=="within_scanned_range" and .full_file_scan'
ln -- "$input" "$stage/link-two"
case_name=two_exact; scan 2
check '.verdict=="within_scanned_range" and .max_line_bytes==5 and .file_stable'
for expected in default 1 3; do
    case_name=two_reject_$expected
    if [[ $expected == default ]]; then scan; else scan "$expected"; fi
    check '.verdict=="inconclusive" and .reason=="metadata_mismatch"'
done
ln -- "$input" "$stage/link-three"
case_name=three_exact; scan 3
check '.verdict=="within_scanned_range" and .max_line_bytes==5 and .file_stable'
for expected in default 1 2; do
    case_name=three_reject_$expected
    if [[ $expected == default ]]; then scan; else scan "$expected"; fi
    check '.verdict=="inconclusive" and .reason=="metadata_mismatch"'
done
ln -- "$input" "$stage/link-four"
case_name=four_links_reject; scan 3
check '.verdict=="inconclusive" and .reason=="metadata_mismatch"'
rm -- "$stage/link-four"
case_name=three_link_positive_eof
head -c 1048577 /dev/zero | tr '\000' A > "$input"; scan 3
check '.verdict=="oversize" and .max_line_bytes==1048577 and .observed_positive and .file_stable'
for bad in 0 4 01 1.0 bad -1 ''; do
    case_name=invalid_expected_argument; rc=0
    result=$(ll_scan "$input" 0 0 600 1048576 33554432 5 "$bad") || rc=$?
    [[ $rc == 64 && -z $result ]]; passed=$((passed+1))
done
rm -- "$stage/link-two" "$stage/link-three"
for expected in 2 3; do
    case_name=single_reject_$expected; scan "$expected"
    check '.verdict=="inconclusive" and .reason=="metadata_mismatch"'
done
case_name=worker_legacy_argument_count
result=$(/bin/bash "$library" --worker "$input" 0 0 600 1048576 33554432 5)
check '.verdict=="oversize" and .file_stable'
case_name=worker_reject_invalid_expected; rc=0
result=$(/bin/bash "$library" --worker "$input" 0 0 600 1048576 33554432 5 4) || rc=$?
[[ $rc == 64 && -z $result ]]; passed=$((passed+1))
for change in add remove; do
    case_name=link_count_changes_$change
    ln -- "$input" "$stage/link-two"
    printf '0\n' > "$stage/stat-calls"
    result=$(
      ll_file_stat() {
        /usr/bin/stat -c '%d|%i|%s|%u|%g|%a|%h|%f|%y|%z' -- "$1"
        n=$(cat "$stage/stat-calls"); printf '%s\n' "$((n+1))" > "$stage/stat-calls"
        if [[ $n == 1 ]]; then
            if [[ $change == add ]]; then ln -- "$input" "$stage/link-three"
            else rm -- "$stage/link-two"; fi
        fi
      }
      ll_worker "$input" 0 0 600 1048576 33554432 5 2
    )
    check '.verdict=="inconclusive" and .reason=="file_changed" and .observed_positive and (.file_stable|not)'
    rm -f -- "$stage/link-two" "$stage/link-three"
done
[[ $(sha256sum "$old/line-length-lib.sh" "$old/test-native.sh" "$old/raw-line-status.jq" "$library") == "$original_before" ]]
cleanup
trap - EXIT
jq -nc --argjson extra "$passed" --arg source_sha "$candidate_sha" \
  --arg original_test_sha "$original_tests_sha" --arg fixture_test_sha "$legacy_fixture_sha" \
  '{status:"passed",suite:"native_line_length_exact_links_v2",legacy_tests:34,link_count_tests:$extra,
    native_tests:(34+$extra),candidate_sha256:$source_sha,legacy_suite_cases_unchanged:true,
    legacy_fixture_only_path_replacements:2,legacy_test_original_sha256:$original_test_sha,
    legacy_test_fixture_sha256:$fixture_test_sha,
    original_stage2_sources_unchanged:true,synthetic_only:true,live_wrapper_executed:false,
    production_sources_opened:false,production_paths_changed:false,fixture_removed:true,raw_payload_exported:false}'
