#!/bin/bash
# One-off systemd v255 lifecycle test. Creates ONE uniquely named transient
# test service; never addresses the real Vector/Wazuh/Docker units. No reboot,
# daemon-reload, package installation, persistent unit or source-log access.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* &&
   $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
base=/var/tmp/capstone-sequential-20261014/step3
[[ -d $base && ! -L $base && $(stat -c %u:%g:%a "$base") == 0:0:700 ]] || exit 77
stage=$(mktemp -d "$base/reader-start-retry.XXXXXXXX")
token=${stage##*.}
[[ $token =~ ^[A-Za-z0-9]{8}$ ]] || exit 77
unit=capstone-raw-reader-retry-test-$token.service
description="Capstone private reader start retry $token"
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
    [[ $stage =~ ^/var/tmp/capstone-sequential-20261014/step3/reader-start-retry\.[A-Za-z0-9]{8}$ &&
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
cat > "$stage/probe-guard.sh" <<'GUARD'
#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C
umask 077
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
[[ $EUID == 0 && $directory =~ ^/var/tmp/capstone-sequential-20261014/step3/reader-start-retry\.[A-Za-z0-9]{8}$ &&
   $(stat -c %u:%g:%a "$directory") == 0:0:700 ]]
# /proc/uptime is monotonic; these are synthetic invocation timestamps only.
awk '{print $1}' /proc/uptime >> "$directory/attempts"
[[ -f $directory/allow && ! -L $directory/allow && $(stat -c %u:%g:%a:%h "$directory/allow") == 0:0:400:1 ]] || exit 9
GUARD
chmod 500 "$stage/probe-guard.sh"
: > "$stage/attempts"
sync -- "$stage/probe-guard.sh" "$stage/attempts" "$stage"
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
# Only this synthetic guard condition changes. No real source or deployment
# state is repaired to force a successful result.
: > "$stage/allow"; chmod 400 "$stage/allow"; sync -- "$stage/allow" "$stage"
deadline=$((SECONDS+45))
while ! timeout --signal=TERM --kill-after=1s 5s systemctl is-active --quiet "$unit"; do
    owned
    (( SECONDS<deadline )); sleep .5
done
[[ $(wc -l < "$stage/attempts") == 2 ]]
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
    [[ $(sha256sum "$stage/attempts" | cut -d ' ' -f1) == "$attempts_sha" ]]
    sleep 1
done
cleanup
trap - EXIT
jq -nc --arg unit "$unit" --argjson interval "$retry_seconds" --arg sha "$attempts_sha" \
  '{status:"passed",unit:$unit,native_systemd_transient_unit:true,guard_failures:1,automatic_retries:1,
    successful_starts:1,guard_attempts:2,retry_interval_seconds:$interval,configured_restart_seconds:30,
    manual_stop_observation_seconds:35,manual_stop_remained_stopped:true,guard_attempts_sha256:$sha,
    uses_privileged_fixed_prestart_prefix:true,production_service_commands:false,operational_source_access:false,
    new_packages:false,persistent_unit_created:false,reboot_tested:false,fixture_removed:true,private_process_reaped:true}'
