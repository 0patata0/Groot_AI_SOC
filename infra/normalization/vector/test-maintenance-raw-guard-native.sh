#!/bin/bash
# Synthetic root-private prepare/guard fixture. No Docker, real systemd, inputs,
# checkpoints, services, operating-process signals or operational files are accessed.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 77
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
base=$here/capstone-vector-maintenance.sh
candidate=$here/capstone-vector-maintenance-raw-guard.sh
migration_guard=$here/raw-operations/migration-start-guard.sh
[[ $(sha256sum "$migration_guard" | cut -d' ' -f1) == b848a6e20b368e2568bf05c1ac91dc4c9c4c043771fb83a916e38d2b540d2bf4 ]]
[[ $(sha256sum "$base" | cut -d' ' -f1) == 8413fb43747a9ddb98f8a8ed1d6df2cf67dd695698b8a81d429c13e3fcdf8f95 ]]
stage=$(mktemp -d /var/tmp/capstone-maintenance-raw-guard-test.XXXXXXXX)
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-maintenance-raw-guard-test\.[A-Za-z0-9]{8}$ && -d $stage && ! -L $stage &&
       $(stat -c %u:%g:%a "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
# Strip exactly the new block and one call: the original body stays byte-identical.
awk '/^# BEGIN managed raw pre-stop guard\./{skip=1;next} /^# END managed raw pre-stop guard\./{skip=0;getline;next} !skip && $0!="        raw_rotation_ready || exit 75"{print}' "$candidate" > "$stage/restored"
cmp -s "$base" "$stage/restored"
[[ $(grep -cF '        raw_rotation_ready || exit 75' "$candidate") == 1 ]]
[[ $(grep -cF '115s' "$candidate") == 1 ]]
# Only fixed fixture paths, command PATH and timeout/wait bounds are changed in
# this copy. The actual new guard function and original prepare case execute.
sed -e "s@/usr/local/lib/capstone-raw-operations@$stage/runtime@g" \
    -e "s@/usr/local/lib/capstone-raw-migration@$stage/migration-runtime@g" \
    -e "s@/var/lib/capstone-raw-migration@$stage/migration-state@g" \
    -e "s@/var/log/capstone-vector@$stage/log@g" \
    -e "s@/var/lib/capstone-vector-maintenance@$stage/state@g" \
    -e "s@/etc/machine-id@$stage/machine-id@g" \
    -e "s@/var/ossec/queue/logcollector/file_status.json@$stage/checkpoint.json@g" \
    -e "s@^PATH=/usr/sbin:/usr/bin:/sbin:/bin\$@PATH=$stage/bin:/usr/sbin:/usr/bin:/sbin:/bin@" \
    -e 's/115s/1s/' -e 's/for attempt in {1\.\.90}/for attempt in {1..2}/' \
    "$candidate" > "$stage/candidate.sh"
bash -n "$stage/candidate.sh"
passed=0
run_case() {
    local name=$1 rc; shift
    set +e
    (set -e; reader_pid=''; trap stop_reader EXIT; setup; "$@") > "$stage/stdout" 2> "$stage/stderr"
    rc=$?
    set -e
    if (( rc != 0 )); then printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1; fi
    passed=$((passed+1))
    rm -rf -- "$stage/runtime" "$stage/migration-runtime" "$stage/migration-state" "$stage/state" "$stage/log" "$stage/bin" "$stage/calls" "$stage/reader.pid" "$stage/guard-mode" "$stage/checkpoint.json" "$stage/link" "$stage/saved" "$stage/changed"
}
stop_reader() {
    if [[ ${reader_pid:-} =~ ^[1-9][0-9]*$ ]]; then
        kill -TERM "$reader_pid" 2>/dev/null || true
        wait "$reader_pid" 2>/dev/null || true
    fi
}
setup() {
    mkdir -m 700 "$stage/runtime" "$stage/migration-runtime" "$stage/migration-state" "$stage/state" "$stage/log" "$stage/bin"
    mkdir -m 700 "$stage/log/ready" "$stage/log/evidence" "$stage/log/quarantine" "$stage/log/telemetry"
    printf '096e90b6243e438aa8a7b392be754732\n' > "$stage/machine-id"
    : > "$stage/calls"; printf 'pass\n' > "$stage/guard-mode"
    for file in ready/normalized.jsonl evidence/normalized.jsonl quarantine/quarantine.jsonl telemetry/health.jsonl; do
        : > "$stage/log/$file"
    done
    for file in coordinator.sh state-lib.sh state.jq checkpoint-gates.sh checkpoint-gates.jq writer-gates.sh; do
        printf 'synthetic fixed metadata\n' > "$stage/runtime/$file"; chmod 400 "$stage/runtime/$file"
    done
    cat > "$stage/runtime/guard.sh" <<EOF
#!/bin/bash
set -euo pipefail
[[ \$# == 1 && \$1 == vector ]] || exit 64
mode=\$(cat '$stage/guard-mode')
expected='{"schema_version":1,"status":"ready","reason":"reader_start_guard","engine":"modsecurity","raw_deleted":false,"checkpoint_rewritten":false,"delivery_acknowledged":false}'
case \$mode in
pass) printf '%s\\n' "\$expected" ;;
deny) printf '%s\\n' "\$expected"; exit 2 ;;
timeout) sleep 30 ;;
pipe_descendant) (sleep 30)& exit 0 ;;
malformed) printf '{' ;;
duplicate) printf '%s\\n' "\$expected" | sed 's/"schema_version":1/"schema_version":1,"schema_version":1/' ;;
multiple) printf '%s\\n%s\\n' "\$expected" "\$expected" ;;
nul) printf '%s\\n\\0' "\$expected" ;;
extra_lf) printf '%s\\n\\n' "\$expected" ;;
wrong_engine) printf '%s\\n' "\${expected/modsecurity/suricata}" ;;
wrong_reason) printf '%s\\n' "\${expected/reader_start_guard/read_only_guard}" ;;
wrong_status) printf '%s\\n' "\${expected/ready/deferred}" ;;
ack_true) printf '%s\\n' "\$expected" | sed 's/"delivery_acknowledged":false/"delivery_acknowledged":true/' ;;
string_false) printf '%s\\n' "\$expected" | sed 's/"raw_deleted":false/"raw_deleted":"false"/' ;;
extra_field) printf '%s\\n' "\$expected" | sed 's/}/,"extra":0}/' ;;
oversize) head -c 4097 /dev/zero | tr '\\000' x ;;
runtime_changed) printf 'changed\\n' >> '$stage/runtime/coordinator.sh'; printf '%s\\n' "\$expected" ;;
*) exit 64 ;;
esac
EOF
    chmod 500 "$stage/runtime/guard.sh"
    sed -e "s@/usr/local/lib/capstone-raw-operations@$stage/runtime@g" \
        -e "s@/var/lib/capstone-raw-migration@$stage/migration-state@g" \
        -e "s@/etc/machine-id@$stage/machine-id@g" "$migration_guard" > "$stage/migration-runtime/migration-start-guard.sh"
    chmod 400 "$stage/migration-runtime/migration-start-guard.sh"
    jq -ncS --arg sha "$(sha256sum "$stage/runtime/guard.sh" | cut -d' ' -f1)" \
      '{schema_version:1,policy:"capstone-raw-migration-start-v1",machine_id:"096e90b6243e438aa8a7b392be754732",
      phase:"released",plan_sha256:("a"*64),armed_boot_id:("b"*32),armed_ledger_sha256:("c"*64),
      release:{boot_id:("b"*32),ledger_sha256:("d"*64),runtime_guard_sha256:$sha,
      suricata_state_sha256:("e"*64),modsecurity_state_sha256:("f"*64),readers_verified:["vector","wazuh"]}}' > "$stage/migration-state/start-barrier.json"
    chmod 600 "$stage/migration-state/start-barrier.json"
    cat > "$stage/bin/systemctl" <<EOF
#!/bin/bash
set -euo pipefail
case "\$*" in
'is-active --quiet capstone-vector.service'|'is-active --quiet wazuh-agent.service') exit 0 ;;
'stop capstone-vector.service') printf 'stop\\n' >> '$stage/calls' ;;
'show capstone-vector.service -p MainPID --value') printf '0\\n' ;;
*) exit 64 ;;
esac
EOF
    cat > "$stage/bin/pgrep" <<EOF
#!/bin/bash
[[ \$* == '-x wazuh-logcollec' ]] || exit 64
cat '$stage/reader.pid'
EOF
    cat > "$stage/bin/logger" <<EOF
#!/bin/bash
printf 'report\\n' >> '$stage/calls'
EOF
    chmod 500 "$stage/bin/"*
    # Direct unreaped child, private empty reader FDs. No live Wazuh PID lookup.
    /bin/bash -c 'exec 3<"$1" 4<"$2"; cat <&3 >/dev/null; cat <&4 >/dev/null; exec sleep 30' raw-private-reader \
        "$stage/log/ready/normalized.jsonl" "$stage/log/evidence/normalized.jsonl" & reader_pid=$!
    printf '%s\n' "$reader_pid" > "$stage/reader.pid"
    local attempt
    for attempt in {1..100}; do [[ -e /proc/$reader_pid/fd/3 && -e /proc/$reader_pid/fd/4 ]] && break; sleep 0.01; done
    [[ -e /proc/$reader_pid/fd/3 && -e /proc/$reader_pid/fd/4 ]]
}
invoke() {
    local rc=0
    CAPSTONE_VECTOR_MAINTENANCE=active /bin/bash "$stage/candidate.sh" prepare || rc=$?
    [[ $rc == "$1" ]] || return 1
    [[ $(find "$stage/state" -maxdepth 1 -name '.raw-start-check.*' | wc -l) == 0 ]] || return 1
}
denied() {
    printf '%s\n' "$1" > "$stage/guard-mode"
    invoke 75 && [[ ! -s $stage/calls && ! -e $stage/state/resume.pending ]]
}
for mode in deny timeout pipe_descendant malformed duplicate multiple nul extra_lf wrong_engine wrong_reason wrong_status ack_true string_false extra_field oversize runtime_changed; do
    run_case "guard_$mode" denied "$mode"
done
invalid_runtime() {
    case $1 in
      missing_runtime) rm -rf "$stage/runtime" ;;
      missing_guard) rm "$stage/runtime/guard.sh" ;;
      guard_symlink) mv "$stage/runtime/guard.sh" "$stage/saved"; ln -s "$stage/saved" "$stage/runtime/guard.sh" ;;
      guard_hardlink) ln "$stage/runtime/guard.sh" "$stage/link" ;;
      guard_fifo) rm "$stage/runtime/guard.sh"; mkfifo -m 600 "$stage/runtime/guard.sh" ;;
      guard_owner) chown 1:1 "$stage/runtime/guard.sh" ;;
      guard_group_writable) chmod 520 "$stage/runtime/guard.sh" ;;
      runtime_writable) chmod 770 "$stage/runtime" ;;
      library_missing) rm "$stage/runtime/checkpoint-gates.jq" ;;
      library_symlink) mv "$stage/runtime/state-lib.sh" "$stage/saved"; ln -s "$stage/saved" "$stage/runtime/state-lib.sh" ;;
      migration_guard_missing) rm "$stage/migration-runtime/migration-start-guard.sh" ;;
      barrier_missing) rm "$stage/migration-state/start-barrier.json" ;;
      barrier_blocked) jq -cS '.phase="blocked"|.release=null' "$stage/migration-state/start-barrier.json" > "$stage/changed"; cat "$stage/changed" > "$stage/migration-state/start-barrier.json" ;;
      barrier_hash_mismatch) jq -cS '.release.runtime_guard_sha256=("0"*64)' "$stage/migration-state/start-barrier.json" > "$stage/changed"; cat "$stage/changed" > "$stage/migration-state/start-barrier.json" ;;
      barrier_writable) chmod 620 "$stage/migration-state/start-barrier.json" ;;
      barrier_symlink) mv "$stage/migration-state/start-barrier.json" "$stage/saved"; ln -s "$stage/saved" "$stage/migration-state/start-barrier.json" ;;
      barrier_duplicate) sed 's/"schema_version":1/"schema_version":1,"schema_version":1/' "$stage/migration-state/start-barrier.json" > "$stage/changed"; cat "$stage/changed" > "$stage/migration-state/start-barrier.json" ;;
    esac
    invoke 75 && [[ ! -s $stage/calls && ! -e $stage/state/resume.pending ]]
}
for mode in missing_runtime missing_guard guard_symlink guard_hardlink guard_fifo guard_owner guard_group_writable runtime_writable library_missing library_symlink migration_guard_missing barrier_missing barrier_blocked barrier_hash_mismatch barrier_writable barrier_symlink barrier_duplicate; do
    run_case "$mode" invalid_runtime "$mode"
done
pass_empty() {
    invoke 0 && [[ $(cat "$stage/state/resume.pending") == pending && $(grep -cx stop "$stage/calls") == 1 &&
        $(grep -cx report "$stage/calls") == 1 && -f $stage/state/ready-before.sha256 && -f $stage/state/evidence-before.sha256 ]]
}
run_case pass_preserves_empty_fd_eof_and_prepare pass_empty
pass_nonempty() {
    stop_reader; reader_pid=''
    printf '{"fixture":1}\n' > "$stage/log/ready/normalized.jsonl"
    printf '{"fixture":2}\n' > "$stage/log/evidence/normalized.jsonl"
    /bin/bash -c 'exec 3<"$1" 4<"$2"; cat <&3 >/dev/null; cat <&4 >/dev/null; exec sleep 30' raw-private-reader \
        "$stage/log/ready/normalized.jsonl" "$stage/log/evidence/normalized.jsonl" & reader_pid=$!
    printf '%s\n' "$reader_pid" > "$stage/reader.pid"
    local attempt ready_size evidence_size
    ready_size=$(stat -c %s "$stage/log/ready/normalized.jsonl")
    evidence_size=$(stat -c %s "$stage/log/evidence/normalized.jsonl")
    for attempt in {1..100}; do
        if [[ -e /proc/$reader_pid/fd/3 && -e /proc/$reader_pid/fd/4 &&
           $(awk '$1=="pos:"{print $2}' /proc/$reader_pid/fdinfo/3) == "$ready_size" &&
           $(awk '$1=="pos:"{print $2}' /proc/$reader_pid/fdinfo/4) == "$evidence_size" ]]; then break; fi
        sleep 0.01
    done
    [[ -e /proc/$reader_pid/fd/3 && -e /proc/$reader_pid/fd/4 ]]
    jq -nc --arg r "$stage/log/ready/normalized.jsonl" --arg e "$stage/log/evidence/normalized.jsonl" \
       --arg rs "$(stat -c %s "$stage/log/ready/normalized.jsonl")" --arg es "$(stat -c %s "$stage/log/evidence/normalized.jsonl")" \
       --arg rh "$(sha1sum "$stage/log/ready/normalized.jsonl" | cut -d' ' -f1)" --arg eh "$(sha1sum "$stage/log/evidence/normalized.jsonl" | cut -d' ' -f1)" \
       '{files:[{path:$r,offset:$rs,hash:$rh},{path:$e,offset:$es,hash:$eh}]}' > "$stage/checkpoint.json"
    pass_empty
}
run_case pass_preserves_nonempty_logical_sha_eof pass_nonempty
pass_guard_eof_denied() {
    stop_reader; reader_pid=''; printf '0\n' > "$stage/reader.pid"
    invoke 1 && [[ $(cat "$stage/state/resume.pending") == pending && $(grep -cx stop "$stage/calls") == 1 &&
       ! -f $stage/state/ready-before.sha256 ]]
}
run_case pass_does_not_bypass_original_eof_guard pass_guard_eof_denied
[[ $passed == 36 ]]
base_sha=$(sha256sum "$base" | cut -d' ' -f1); candidate_sha=$(sha256sum "$candidate" | cut -d' ' -f1)
fixture_sha=$(sha256sum "$stage/candidate.sh" | cut -d' ' -f1)
cleanup; trap - EXIT
jq -nc --arg original "$base_sha" --arg candidate "$candidate_sha" --arg fixture "$fixture_sha" --argjson count "$passed" \
 '{status:"passed",native_tests:$count,original_sha256:$original,candidate_sha256:$candidate,private_copy_sha256:$fixture,
 original_body_unchanged_except_guard:true,actual_prepare_branch_executed:true,private_reader_fd_and_checkpoint_fixture:true,
 guard_timeout_seconds_in_fixture:1,production_guard_timeout_seconds:115,systemd_or_docker_called:false,
 operational_files_touched:false,fixture_removed:true}'
