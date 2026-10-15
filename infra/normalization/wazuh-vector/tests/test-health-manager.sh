#!/bin/sh
# Native synthetic logtest only: no logger, journal, alert queue, or network input.
set -eu
docker=/usr/local/bin/docker
manager=${CAPSTONE_WAZUH_MANAGER:-single-node-wazuh.manager-1}
if [ "$manager" != single-node-wazuh.manager-1 ]; then
    [ "${#manager}" -eq 64 ] || exit 64
    case "$manager" in *[!0-9a-f]*) exit 64 ;; esac
fi
[ "$#" -le 1 ] || exit 64
mode=${1:-full}
case "$mode" in full|--baseline) ;; *) exit 64 ;; esac
umask 077
output=$(mktemp /var/tmp/capstone-vector-health-logtest.XXXXXX)
trap 'rm -f "$output"' EXIT HUP INT TERM
pairs='disk_space_low:100241 disk_space_critical:100242 vector_not_active:100243 rotation_failed_pending_recovery:100244 reader_not_at_current_eof:100245 rotated_current_reader_ready:100240 collection_telemetry_missing:100246 collection_telemetry_stale:100247 collection_telemetry_invalid:100248 collection_error_seen:100249 collection_loss_signal_seen:100250 collection_buffer_pressure:100251 unknown_collection_status:100240 collection_error_seen_extra:100240'
if [ "$mode" != --baseline ]; then
    pairs="$pairs collection_raw_line_oversize_seen:100252 collection_raw_line_scan_unavailable:100253 collection_raw_line_oversize_seen_extra:100240 collection_raw_line_scan_unavailable_extra:100240"
fi
for pair in $pairs; do
    status=$(printf '%s' "$pair" | cut -d: -f1)
    expected=$(printf '%s' "$pair" | cut -d: -f2)
    printf 'Oct 14 10:00:00 groot-sec capstone-vector-storage[12345]: status=%s\n' "$status" \
        | "$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -l '(groot-sec) any->journald' > "$output" 2>&1
    actual=$(sed -n "s/^[[:space:]]*id: '\([0-9][0-9]*\)'.*/\1/p" "$output" | paste -sd ' ' -)
    if grep -Eq '(ERROR|CRITICAL):' "$output" || [ "$actual" != "$expected" ]; then
        echo "FAIL health $status expected_id=$expected actual_id=[$actual]" >&2
        exit 1
    fi
    case "$expected" in
        100252|100253)
            level=$(sed -n "s/^[[:space:]]*level: '\([0-9][0-9]*\)'.*/\1/p" "$output" | paste -sd ' ' -)
            [ "$level" = 3 ] || { echo "FAIL health unexpected_level rule=$expected" >&2; exit 1; }
            ;;
    esac
    echo "PASS native_health_status=$status rule=$actual"
done
negative_statuses=disk_space_critical
if [ "$mode" != --baseline ]; then
    negative_statuses="$negative_statuses collection_raw_line_oversize_seen collection_raw_line_scan_unavailable"
fi
for status in $negative_statuses; do
for test in wrong-program wrong-location wrong-agent bare-location; do
    program=capstone-vector-storage
    location='(groot-sec) any->journald'
    case "$test" in wrong-program) program=unrelated ;; wrong-location) location=/var/log/unrelated.log ;; wrong-agent) location='(groot-web) any->journald' ;; bare-location) location=journald ;; esac
    printf 'Oct 14 10:00:00 groot-sec %s[12345]: status=%s\n' "$program" "$status" \
        | "$docker" exec -i "$manager" /var/ossec/bin/wazuh-logtest -l "$location" > "$output" 2>&1
    if grep -Eq "id: '1002(4[0-9]|5[0-3])'|(ERROR|CRITICAL):" "$output"; then
        echo "FAIL health status=$status negative=$test" >&2
        exit 1
    fi
    echo "PASS native_health_status=$status negative=$test"
done
done
