#!/bin/bash
# ONE disposable systemd service testing the actual migration barrier.
# Released delegates to a private synthetic guard. No real reader unit, raw
# input, checkpoint, Docker, package, reboot or persistent unit is accessed.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* &&
   $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
stage=$(mktemp -d /var/tmp/capstone-raw-migration-test.XXXXXXXX)
token=${stage##*.}
[[ $token =~ ^[A-Za-z0-9]{8}$ ]] || exit 77
unit=capstone-migration-barrier-test-$token.service
description="Capstone private migration startup barrier $token"
created=false cleaned=false main_pid=0 main_ticks=0
owned() {
    local load transient desc
    load=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p LoadState "$unit") || return 1
    [[ $load != not-found ]] || return 3
    transient=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p Transient "$unit") || return 1
    desc=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p Description "$unit") || return 1
    [[ $transient == yes && $desc == "$description" ]]
}
cleanup() {
    local rc=0 state ticks
    if [[ $created == true ]]; then
        if owned; then
            timeout --signal=TERM --kill-after=1s 8s systemctl stop "$unit" >/dev/null 2>&1 || return 1
            timeout --signal=TERM --kill-after=1s 5s systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        else rc=$?; [[ $rc == 3 ]] || return 1; fi
    fi
    if (( main_pid>1 )) && [[ -e /proc/$main_pid/stat ]]; then
        ticks=$(awk '{sub(/^.*\) /, ""); print $20}' "/proc/$main_pid/stat") || return 1
        [[ $ticks != "$main_ticks" ]] || return 1
    fi
    [[ $stage =~ ^/var/tmp/capstone-raw-migration-test\.[A-Za-z0-9]{8}$ &&
       -d $stage && ! -L $stage && $(stat -c %u:%g:%a "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage" || return 1
    cleaned=true
}
finish() {
    local original=$?
    trap - EXIT
    if ! cleanup; then
        printf '{"status":"failed","reason":"private_unit_cleanup_not_verified","unit":"%s","retained_path":"%s"}\n' "$unit" "$stage"
        exit 1
    fi
    if (( original!=0 )); then
        printf '{"status":"failed","reason":"private_lifecycle_assertion_failed","unit":"%s","cleanup_verified":true}\n' "$unit"
    fi
    exit "$original"
}
trap finish EXIT
trap 'exit 143' TERM HUP
trap 'exit 130' INT
[[ $(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p LoadState "$unit") == not-found ]]
mkdir -m 700 "$stage/state" "$stage/runtime"
cp -- "$here/migration-start-guard.sh" "$stage/source.sh"
chmod 500 "$stage/source.sh"
source_sha=$(sha256sum "$stage/source.sh" | cut -d' ' -f1)
cat > "$stage/runtime/guard.sh" <<'FINAL'
#!/bin/bash
set -euo pipefail
[[ $# == 1 && $1 == vector ]] || exit 64
base=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
[[ $base =~ ^/var/tmp/capstone-raw-migration-test\.[A-Za-z0-9]{8}$ && $(stat -c %u:%g:%a "$base") == 0:0:700 ]]
printf '%s\n' "$1" >> "$base/delegations"
FINAL
chmod 500 "$stage/runtime/guard.sh"
runtime_sha=$(sha256sum "$stage/runtime/guard.sh" | cut -d' ' -f1)
cat > "$stage/probe-guard.sh" <<'GUARD'
#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
umask 077
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
[[ $EUID == 0 && $directory =~ ^/var/tmp/capstone-raw-migration-test\.[A-Za-z0-9]{8}$ &&
   $(stat -c %u:%g:%a "$directory") == 0:0:700 ]]
awk '{print $1}' /proc/uptime >> "$directory/attempts"
source "$directory/source.sh"
MSG_ROOT=$directory/state MSG_FILE=$directory/state/start-barrier.json MSG_GUARD=$directory/runtime/guard.sh
msg_entry vector
GUARD
chmod 500 "$stage/probe-guard.sh"
: > "$stage/attempts"; : > "$stage/delegations"
jq -ncS '{schema_version:1,policy:"capstone-raw-migration-start-v1",machine_id:"096e90b6243e438aa8a7b392be754732",
  phase:"blocked",plan_sha256:("a"*64),armed_boot_id:("b"*32),armed_ledger_sha256:("c"*64),release:null}' > "$stage/state/start-barrier.json"
chmod 600 "$stage/state/start-barrier.json"
sync -- "$stage/state/start-barrier.json" "$stage/state" "$stage/source.sh" "$stage/probe-guard.sh" "$stage/runtime/guard.sh" "$stage"
# --no-block avoids treating the intentionally failing first start job as an
# unhandled setup error. Use the real proposed 30-second retry interval.
created=true
timeout --signal=TERM --kill-after=1s 10s systemd-run --quiet --no-block --unit="$unit" \
  --description="$description" --property=Type=simple --property=User=root --property=Group=root \
  --property="ExecStartPre=+/bin/bash $stage/probe-guard.sh" \
  --property=Restart=on-failure --property=RestartSec=30s \
  --property=StartLimitIntervalSec=120s --property=StartLimitBurst=10 \
  --property=TimeoutStartSec=10s --property=TimeoutStopSec=5s \
  --property=ProtectSystem=strict --property=ProtectHome=read-only \
  --property=PrivateTmp=yes --property=NoNewPrivileges=yes \
  --property=CapabilityBoundingSet=CAP_DAC_READ_SEARCH \
  --property=RestrictAddressFamilies=AF_UNIX /bin/sleep 300 >/dev/null
owned
deadline=$((SECONDS+10))
while true; do
    attempts=$(wc -l < "$stage/attempts")
    result=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p Result "$unit")
    pid=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p MainPID "$unit")
    if [[ $attempts == 1 && $result == exit-code && $pid == 0 ]]; then break; fi
    (( SECONDS<deadline )); sleep .2
done
[[ ! -s $stage/delegations ]]
# Synthetic handoff only. Real release requires both actual raw guards and
# source/state evidence; no operating state is altered to make this test pass.
jq -cS --arg digest "$runtime_sha" '.phase="released"|.release={boot_id:("d"*32),ledger_sha256:("e"*64),
 runtime_guard_sha256:$digest,suricata_state_sha256:("f"*64),modsecurity_state_sha256:("0"*64),
 readers_verified:["vector","wazuh"]}' "$stage/state/start-barrier.json" > "$stage/state/next.json"
chmod 600 "$stage/state/next.json"; sync -- "$stage/state/next.json"
mv -T "$stage/state/next.json" "$stage/state/start-barrier.json"; sync -- "$stage/state"
deadline=$((SECONDS+45))
while ! timeout --signal=TERM --kill-after=1s 5s systemctl is-active --quiet "$unit"; do
    owned
    (( SECONDS<deadline )); sleep .5
done
[[ $(wc -l < "$stage/attempts") == 2 && $(cat "$stage/delegations") == vector ]]
[[ $(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p NRestarts "$unit") == 1 ]]
main_pid=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p MainPID "$unit")
[[ $main_pid =~ ^[1-9][0-9]{0,9}$ && $main_pid -gt 1 ]]
main_ticks=$(awk '{sub(/^.*\) /, ""); print $20}' "/proc/$main_pid/stat")
[[ $main_ticks =~ ^[1-9][0-9]*$ ]]
retry_seconds=$(awk 'NR==1{first=$1}NR==2{printf "%.2f",$1-first}' "$stage/attempts")
awk -v interval="$retry_seconds" 'BEGIN{exit !(interval>=29 && interval<45)}'
attempts_sha=$(sha256sum "$stage/attempts" | cut -d ' ' -f1)
owned
timeout --signal=TERM --kill-after=1s 8s systemctl stop "$unit"
# Verify administrator stop remains stopped beyond the exact RestartSec.
deadline=$((SECONDS+35))
while (( SECONDS<deadline )); do
    load=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p LoadState "$unit")
    if [[ $load != not-found ]]; then
        owned
        state=$(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p ActiveState "$unit")
        [[ $state == inactive ]]
        [[ $(timeout --signal=TERM --kill-after=1s 5s systemctl show --value -p MainPID "$unit") == 0 ]]
    fi
    [[ $(sha256sum "$stage/attempts" | cut -d ' ' -f1) == "$attempts_sha" && $(cat "$stage/delegations") == vector ]]
    sleep 1
done
[[ $(sha256sum "$stage/source.sh" | cut -d' ' -f1) == "$source_sha" &&
   $(sha256sum "$stage/runtime/guard.sh" | cut -d' ' -f1) == "$runtime_sha" ]]
cleanup
trap - EXIT
jq -nc --arg unit "$unit" --argjson interval "$retry_seconds" --arg sha "$attempts_sha" --arg source "$source_sha" \
  '{status:"passed",unit:$unit,native_systemd_transient_unit:true,guard_failures:1,automatic_retries:1,
    barrier_source_sha256:$source,synthetic_release_proof:true,normal_guard_is_fixture:true,normal_guard_delegations:1,
    successful_starts:1,guard_attempts:2,retry_interval_seconds:$interval,configured_restart_seconds:30,
    manual_stop_observation_seconds:35,manual_stop_remained_stopped:true,guard_attempts_sha256:$sha,
    uses_privileged_fixed_prestart_prefix:true,production_service_commands:false,operational_source_access:false,
    new_packages:false,persistent_unit_created:false,reboot_tested:false,fixture_removed:true,private_process_reaped:true}'
