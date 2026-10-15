#!/bin/bash
# Existing Bash/jq/coreutils, root-owned synthetic metadata only. No services,
# Docker, real deployment state, checkpoints, source logs or network access.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/migration-start-guard.sh"
stage=$(mktemp -d /var/tmp/capstone-raw-migration-test.XXXXXXXX)
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-raw-migration-test\.[A-Za-z0-9]{8}$ && -d $stage && ! -L $stage &&
      $(stat -c %u:%g:%a "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
passed=0
run_case() {
    local name=$1 rc; shift
    set +e
    ( set -e; setup; "$@" ) > "$stage/stdout" 2> "$stage/stderr"
    rc=$?
    set -e
    if (( rc==0 )); then passed=$((passed+1))
    else printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1; fi
    rm -rf -- "$stage/state" "$stage/runtime" "$stage/calls" "$stage/changed" "$stage/saved"
}
setup() {
    MSG_ROOT=$stage/state MSG_GUARD=$stage/runtime/guard.sh
    MSG_FILE=$MSG_ROOT/start-barrier.json
    mkdir -m 700 "$MSG_ROOT" "$stage/runtime" || return 1
    printf '#!/bin/bash\nexit 0\n' > "$MSG_GUARD" || return 1
    chmod 500 "$MSG_GUARD" || return 1
    : > "$stage/calls"
    msg_host() { return 0; }
    msg_delegate() { printf '%s\n' "$1" >> "$stage/calls"; return 0; }
    marker blocked
}
marker() {
    local phase=$1 digest
    digest=$(msg_hash "$MSG_GUARD") || return 1
    jq -ncS --arg phase "$phase" --arg digest "$digest" \
      '{schema_version:1,policy:"capstone-raw-migration-start-v1",machine_id:"096e90b6243e438aa8a7b392be754732",
        phase:$phase,plan_sha256:("a"*64),armed_boot_id:("b"*32),armed_ledger_sha256:("c"*64),
        release:(if $phase=="blocked" then null else {boot_id:("d"*32),ledger_sha256:("e"*64),
          runtime_guard_sha256:$digest,suricata_state_sha256:("f"*64),modsecurity_state_sha256:("0"*64),
          readers_verified:["vector","wazuh"]} end)}' > "$MSG_FILE" || return 1
    chmod 600 "$MSG_FILE" || return 1
    sync -- "$MSG_FILE" "$MSG_ROOT"
}
expect_denied() {
    local rc=0
    msg_entry vector || rc=$?
    [[ $rc == 75 && ! -s $stage/calls ]]
}
inspect_blocked() {
    msg_entry inspect > "$stage/observed" || return 1
    jq -e '.phase=="blocked" and .reader_start_authorized==false and .read_only==true' "$stage/observed" >/dev/null &&
      [[ ! -s $stage/calls ]]
}
run_case blocked_denies_start expect_denied
run_case inspect_blocked_read_only inspect_blocked
released() {
    marker released && msg_entry "$1" && [[ $(cat "$stage/calls") == "$1" ]]
}
run_case released_vector_delegates released vector
run_case released_wazuh_delegates released wazuh
delegate_rejection() {
    marker released || return 1
    msg_delegate() { printf '%s\n' "$1" >> "$stage/calls"; return 2; }
    local rc=0; msg_entry vector || rc=$?
    [[ $rc == 2 && $(cat "$stage/calls") == vector ]]
}
run_case normal_guard_rejection_propagates delegate_rejection
invalid() {
    local mode=$1
    marker released || return 1
    case $mode in
      missing) rm "$MSG_FILE" ;;
      fifo) rm "$MSG_FILE"; mkfifo -m 600 "$MSG_FILE" ;;
      symlink) mv "$MSG_FILE" "$stage/saved"; ln -s "$stage/saved" "$MSG_FILE" ;;
      hardlink) ln "$MSG_FILE" "$stage/saved" ;;
      mode) chmod 640 "$MSG_FILE" ;;
      owner) chown 1:1 "$MSG_FILE" ;;
      parent_mode) chmod 770 "$MSG_ROOT" ;;
      parent_symlink) mv "$MSG_ROOT" "$stage/saved"; ln -s "$stage/saved" "$MSG_ROOT" ;;
      duplicate) sed 's/"schema_version":1/"schema_version":1,"schema_version":1/' "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" > "$MSG_FILE" ;;
      multiple) cat "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" >> "$MSG_FILE" ;;
      pretty) jq . "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" > "$MSG_FILE" ;;
      newline) printf '\n' >> "$MSG_FILE" ;;
      unknown) jq -cS '.extra=true' "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" > "$MSG_FILE" ;;
      machine) jq -cS '.machine_id=("e"*32)' "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" > "$MSG_FILE" ;;
      proof_missing) jq -cS '.release=null' "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" > "$MSG_FILE" ;;
      readers) jq -cS '.release.readers_verified=["vector"]' "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" > "$MSG_FILE" ;;
      bad_hash) jq -cS '.release.runtime_guard_sha256=("z"*64)' "$MSG_FILE" > "$stage/changed"; cat "$stage/changed" > "$MSG_FILE" ;;
      too_large) dd if=/dev/zero bs=4097 count=1 status=none > "$MSG_FILE" ;;
      guard_hash) printf '#changed\n' >> "$MSG_GUARD" ;;
      guard_writable) chmod 770 "$MSG_GUARD" ;;
      guard_symlink) mv "$MSG_GUARD" "$stage/saved"; ln -s "$stage/saved" "$MSG_GUARD" ;;
      guard_missing) rm "$MSG_GUARD" ;;
      guard_parent_writable) chmod 777 "$stage/runtime" ;;
      *) return 1 ;;
    esac
    expect_denied
}
for mode in missing fifo symlink hardlink mode owner parent_mode parent_symlink duplicate multiple pretty newline unknown machine proof_missing readers bad_hash too_large guard_hash guard_writable guard_symlink guard_missing guard_parent_writable; do
    run_case "${mode}_refused" invalid "$mode"
done
old_boot_blocked() {
    jq -cS '.armed_boot_id=("0"*32)' "$MSG_FILE" > "$stage/changed" || return 1
    cat "$stage/changed" > "$MSG_FILE" || return 1
    expect_denied
}
run_case blocked_record_survives_boot_identity_change old_boot_blocked
changed_during_guard() {
    marker released || return 1
    eval "$(declare -f msg_runtime_guard | sed '1s/msg_runtime_guard/real_runtime_guard/')"
    msg_runtime_guard() { real_runtime_guard && marker blocked; }
    expect_denied
}
run_case rearmed_during_guard_validation_refused changed_during_guard
invalid_argument() {
    local rc=0; msg_entry unknown || rc=$?
    [[ $rc == 64 && ! -s $stage/calls ]]
}
run_case unknown_reader_refused invalid_argument
cleanup && [[ ! -e $stage ]]
trap - EXIT
printf '{"status":"passed","cases":%s,"synthetic_only":true,"operating_state_accessed":false,"systemd_or_docker_called":false,"fixture_removed":true}\n' "$passed"
