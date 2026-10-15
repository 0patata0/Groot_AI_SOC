#!/bin/bash
# Pure policy mode is portable; full mode uses GNU tools in a private Linux root fixture.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=Asia/Seoul
umask 077
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
MODE=${1:-native}
[[ $# -le 1 && ($MODE == native || $MODE == --policy-only) ]] || exit 64
if [[ $MODE == native ]]; then
    [[ $EUID == 0 && $(uname -s) == Linux ]] || exit 77
    ROOT=$(mktemp -d /var/tmp/capstone-storage-native.XXXXXXXX)
else ROOT=$(mktemp -d "${TMPDIR:-/tmp}/capstone-storage-policy.XXXXXXXX"); fi
trap 'rm -rf -- "$ROOT"' EXIT
PASSED=0
run_case() {
    local name=$1 rc; shift
    set +e
    (set -e; "$@") > "$ROOT/case.log" 2>&1
    rc=$?
    set -e
    if (( rc!=0 )); then printf 'FAIL %s rc=%s\n' "$name" "$rc"; cat "$ROOT/case.log"; exit 1; fi
    PASSED=$((PASSED+1)); printf 'PASS %s\n' "$name"
}
base() { printf '%s\n' '{"used_percent":18,"available_bytes":50000000000,"raw_bytes":72000000,"backup_bytes":21000000,"history_bytes":6700000,"raw_archive_review_due_count":0,"backup_review_due_count":0,"scan_status":"complete"}'; }
policy() { jq -cSe --arg machine 096e90b6243e438aa8a7b392be754732 --arg host a --arg observed 2026-10-15T00:00:00Z -f "$HERE/policy.jq"; }
status() { base | jq -c "$1" | policy | jq -e --arg expected "$2" 'length==18 and .status==$expected and .automatic_deletion==false and .checkpoint_changed==false' >/dev/null; }
invalid() { local rc; set +e; base | jq -c "$1" | policy >/dev/null 2>&1; rc=$?; set -e; (( rc!=0 )); }
run_case healthy status . ok
run_case warning_disk_boundary status '.used_percent=80' warning
run_case critical_disk_boundary status '.used_percent=90' critical
run_case free_exact_2gib status '.available_bytes=2147483648' ok
run_case free_below_2gib status '.available_bytes=2147483647' critical
run_case raw_warning_boundary status '.raw_bytes=4294967296' warning
run_case raw_critical_boundary status '.raw_bytes=5368709120' critical
run_case backup_warning_boundary status '.backup_bytes=1073741824' warning
run_case backup_critical_boundary status '.backup_bytes=2147483648' critical
run_case unknown_not_healthy status '.scan_status="unavailable"|.raw_bytes=null' unavailable
run_case unknown_over_warning status '.used_percent=80|.scan_status="unavailable"|.history_bytes=null' unavailable
run_case known_critical_over_unknown status '.used_percent=90|.scan_status="unavailable"|.history_bytes=null' critical
run_case missing_metric_refused invalid 'del(.raw_bytes)'
run_case complete_null_refused invalid '.raw_bytes=null'
run_case numeric_string_refused invalid '.used_percent="18"'
run_case extra_field_refused invalid '.eligible_for_deletion=true'
if [[ $MODE == --policy-only ]]; then
    printf '{"policy_only":true,"passed":%s,"native_filesystem_executed":false}\n' "$PASSED"
    exit 0
fi
source "$HERE/monitor-lib.sh"
source "$HERE/monitor.sh"
WORK=$ROOT/work; mkdir "$WORK"
expect_fail() { local rc=0; "$@" >/dev/null 2>&1 || rc=$?; (( rc!=0 )); }
tree_ok() { mkdir "$ROOT/tree"; dd if=/dev/zero of="$ROOT/tree/data" bs=1 count=4096 status=none; [[ $(st_tree "$WORK" "$ROOT/tree") -ge 4096 ]]; }
tree_symlink() { ln -s "$ROOT/tree" "$ROOT/tree/link"; expect_fail st_tree "$WORK" "$ROOT/tree"; rm "$ROOT/tree/link"; }
tree_missing() { expect_fail st_tree "$WORK" "$ROOT/missing"; }
disk_ok() { local text available used; text=$(st_disk "$ROOT"); read -r available used <<< "$text"; st_uint "$available"; [[ $used =~ ^[0-9]+$ ]] && (( used<=100 )); }
backup_ok() { mkdir "$ROOT/backups" "$ROOT/backups/capstone-saved" "$ROOT/backups/other"; [[ $(st_backup_list "$ROOT/backups") == "$ROOT/backups/capstone-saved" ]]; }
backup_symlink() { ln -s "$ROOT/tree" "$ROOT/backups/capstone-link"; expect_fail st_backup_list "$ROOT/backups"; rm "$ROOT/backups/capstone-link"; }
raw_setup() {
    mkdir "$ROOT/managed"
    jq -ncS '{schema_version:1,policy:"capstone-raw-operations-v1",engine:"suricata",machine_id:"096e90b6243e438aa8a7b392be754732",phase:"switch_pending",revision:3,current:{number:2},pending:{number:3}}' > "$ROOT/state.json"
    chmod 600 "$ROOT/state.json"
    local n
    for n in 0 1 2 3; do
        printf -v name 'generation-%010d.jsonl' "$n"
        printf 'synthetic\n' > "$ROOT/managed/$name"
        chmod 400 "$ROOT/managed/$name"
        touch -m -d '40 days ago' "$ROOT/managed/$name"
    done
    chmod 644 "$ROOT/managed/generation-0000000001.jsonl"
}
raw_review() { raw_setup; [[ $(st_raw_review "$ROOT/managed" "$ROOT/state.json" suricata "$(($(date +%s)-30*86400))" "$WORK/review") == 1 ]]; jq -se 'length==1 and .[0].generation==0 and .[0].delete_authorized==false' "$WORK/review" >/dev/null; }
raw_hardlink() { ln "$ROOT/managed/generation-0000000000.jsonl" "$ROOT/old-link"; [[ $(st_raw_review "$ROOT/managed" "$ROOT/state.json" suricata "$(($(date +%s)-30*86400))" "$WORK/review") == 0 ]]; rm "$ROOT/old-link"; }
raw_bad_state() { cp "$ROOT/state.json" "$ROOT/state.save"; printf '{}\n' > "$ROOT/state.json"; expect_fail st_raw_review "$ROOT/managed" "$ROOT/state.json" suricata 9999999999 "$WORK/review"; cat "$ROOT/state.save" "$ROOT/state.save" > "$ROOT/state.json"; expect_fail st_raw_review "$ROOT/managed" "$ROOT/state.json" suricata 9999999999 "$WORK/review"; mv "$ROOT/state.save" "$ROOT/state.json"; }
collect_setup() { SM_ROOT=$ROOT/source; mkdir -p "$SM_ROOT"; cp "$HERE/policy.jq" "$SM_ROOT/policy.jq"; }
collect_timeout() {
    collect_setup; SM_TIMEOUT=1s
    printf '#!/bin/bash\nsleep 5\n' > "$SM_ROOT/monitor-lib.sh"
    local before=$SECONDS; sm_collect a 096e90b6243e438aa8a7b392be754732 "$WORK"
    (( SECONDS-before<5 )); jq -e '.status=="unavailable" and .raw_bytes==null' "$WORK/result.json" >/dev/null
}
collect_malformed() { collect_setup; printf '#!/bin/bash\nprintf "{}\\n{}\\n" > "$2/measurements.json"\nprintf "{}\\n" > "$2/inventory.json"\n' > "$SM_ROOT/monitor-lib.sh"; sm_collect a 096e90b6243e438aa8a7b392be754732 "$WORK"; jq -e '.status=="unavailable"' "$WORK/result.json" >/dev/null; }
collect_valid() {
    collect_setup
    { printf '#!/bin/bash\n'; printf "printf '%%s\\n' '%s' > \"\$2/measurements.json\"\n" "$(base)"; printf "printf '%%s\\n' '%s' > \"\$2/inventory.json\"\n" '{"schema_version":1,"automatic_deletion":false,"checkpoint_changed":false,"archive_authorized":false,"referenced_backups_always_protected":true}'; } > "$SM_ROOT/monitor-lib.sh"
    sm_collect a 096e90b6243e438aa8a7b392be754732 "$WORK"
    jq -e '.status=="ok" and length==18' "$WORK/result.json" >/dev/null
}
fixture_publish_dir() {
    # Exercise actual atomic publisher under the private fixture root; the
    # production ancestor check intentionally rejects world-writable /var/tmp.
    sm_dir() {
        local p=$1 mode
        [[ $p == "$ROOT"/* ]] || return 1
        while :; do
            [[ -d $p && ! -L $p && $(stat -c %u:%g "$p") == 0:0 ]] || return 1
            mode=$(stat -c %a "$p") || return 1
            (( (8#$mode & 0022)==0 )) || return 1
            [[ $p == "$ROOT" ]] && break
            p=${p%/*}
        done
    }
}
publish_ok() { fixture_publish_dir; SM_STATE=$ROOT/state; mkdir "$SM_STATE"; chmod 700 "$SM_STATE"; printf '{"sample":1}\n' > "$WORK/publish"; sm_publish "$WORK/publish" status.json; [[ $(stat -c %u:%g:%a:%h "$SM_STATE/status.json") == 0:0:600:1 ]]; }
publish_link() { fixture_publish_dir; SM_STATE=$ROOT/state; ln "$SM_STATE/status.json" "$ROOT/state-link"; printf '{"sample":2}\n' > "$WORK/publish"; expect_fail sm_publish "$WORK/publish" status.json; [[ $(cat "$SM_STATE/status.json") == '{"sample":1}' ]]; rm "$ROOT/state-link"; }
run_case native_du_apparent_bytes tree_ok
run_case symlink_scan_unavailable tree_symlink
run_case missing_scan_unavailable tree_missing
run_case native_df_parse disk_ok
run_case backup_fixed_directory_selection backup_ok
run_case backup_symlink_refused backup_symlink
run_case aged_raw_review_not_current_pending_unsealed raw_review
run_case linked_raw_not_review_eligible raw_hardlink
run_case malformed_state_refused raw_bad_state
run_case timeout_becomes_unavailable collect_timeout
run_case malformed_worker_becomes_unavailable collect_malformed
run_case complete_worker_exact18 collect_valid
run_case native_atomic_status_publish publish_ok
run_case status_hardlink_refused publish_link
rm -rf -- "$ROOT"; trap - EXIT
printf '{"passed":%s,"native_filesystem_executed":true,"operational_paths_accessed":false,"raw_or_checkpoint_changed":false,"fixture_removed":true}\n' "$PASSED"
