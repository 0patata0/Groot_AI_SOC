#!/bin/bash
# Isolated native OpenSSL certificates + simulated TLS transport. No socket/server.
# Usage: bash test-monitor.sh ABS_MONITOR_SOURCE EXISTING_PRIVATE_TEMP_PARENT
set -euo pipefail
umask 077
[[ $# == 2 && $1 == /* && -f $1 && $2 == /* && -d $2 && ! -L $2 ]] || exit 64
source_file=$1
fixture=$(mktemp -d "$2/certificate-monitor-fixture.XXXXXXXX")
trap 'rc=$?; if (( rc!=0 )); then printf "FAIL %s rc=%s\n" "${current_case:-setup}" "$rc" >&2; fi; rm -rf -- "$fixture"' EXIT
if [[ $(uname -s) == Darwin ]]; then
    real_openssl=/opt/homebrew/opt/openssl@3/bin/openssl
    native_stat=/opt/homebrew/bin/gstat native_dd=/opt/homebrew/bin/gdd
    native_date=/opt/homebrew/bin/gdate native_timeout=/opt/homebrew/bin/gtimeout
else
    real_openssl=/usr/bin/openssl native_stat=/usr/bin/stat native_dd=/usr/bin/dd
    native_date=/usr/bin/date native_timeout=/usr/bin/timeout
fi
for file in "$real_openssl" "$native_stat" "$native_dd" "$native_date" "$native_timeout"; do [[ -x $file ]]; done
# On non-root Mac only the expected ownership tuple is substituted in a private
# copy. Linux root runs the original root:root ownership check unchanged.
expected_uid=$(id -u); expected_gid=$("$native_stat" -c %g "$fixture")
sed "s/== 0:0:644:1/== $expected_uid:$expected_gid:644:1/" "$source_file" > "$fixture/monitor.sh"
source "$fixture/monitor.sh"
stat() { "$native_stat" "$@"; }
dd() { "$native_dd" "$@"; }
CM_DATE=$native_date CM_TIMEOUT=$native_timeout CM_OPENSSL=$fixture/openssl
CM_CERT=$fixture/current.pem
export FIXTURE_REAL_OPENSSL=$real_openssl FIXTURE_TLS_CERT=$fixture/cert31.pem
export FIXTURE_TLS_MODE=ok FIXTURE_CURRENT=$CM_CERT FIXTURE_CALLS=$fixture/calls
cat > "$fixture/openssl" <<'SH'
#!/bin/bash
set -euo pipefail
if [[ $1 == s_client ]]; then
    [[ "$*" == 's_client -connect 127.0.0.1:443 -servername chat.grootlab.duckdns.org -verify_return_error -verify_hostname chat.grootlab.duckdns.org -purpose sslserver -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -no_ign_eof' ]] || exit 90
    printf '%s\n' TLS_OPTIONS_EXACT >> "$FIXTURE_CALLS"
    case "$FIXTURE_TLS_MODE" in
      fail) exit 1 ;; timeout) exit 124 ;; invalid) printf 'not PEM\n'; exit 0 ;;
      changed) printf '\n' >> "$FIXTURE_CURRENT" ;;
      ok) ;; *) exit 91 ;;
    esac
    cat "$FIXTURE_TLS_CERT"; exit 0
fi
if [[ " $* " == *' -checkend '* ]]; then printf '%s\n' "${@: -1}" >> "$FIXTURE_CALLS"; fi
exec "$FIXTURE_REAL_OPENSSL" "$@"
SH
chmod 700 "$fixture/openssl"
"$real_openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$fixture/key.pem" >/dev/null 2>&1
for days in 31 30 15 14 8 7; do
    "$real_openssl" req -new -x509 -key "$fixture/key.pem" -days "$days" \
      -subj /CN=chat.grootlab.duckdns.org -addext subjectAltName=DNS:chat.grootlab.duckdns.org \
      -out "$fixture/cert$days.pem" >/dev/null 2>&1
done
"$real_openssl" req -new -x509 -key "$fixture/key.pem" -days 31 -subj /CN=elsewhere.invalid \
  -addext subjectAltName=DNS:elsewhere.invalid -out "$fixture/wrong.pem" >/dev/null 2>&1
"$real_openssl" req -new -x509 -key "$fixture/key.pem" -days 31 -subj /CN=chat.grootlab.duckdns.org \
  -out "$fixture/no-san.pem" >/dev/null 2>&1
"$real_openssl" req -new -key "$fixture/key.pem" -subj /CN=chat.grootlab.duckdns.org \
  -out "$fixture/request.pem" >/dev/null 2>&1
: > "$fixture/index"; printf '1000\n' > "$fixture/serial"
cat > "$fixture/ca.cnf" <<CFG
[ca]
default_ca=private
[private]
database=$fixture/index
serial=$fixture/serial
new_certs_dir=$fixture
private_key=$fixture/key.pem
certificate=$fixture/cert31.pem
default_md=sha256
policy=policy
x509_extensions=ext
[policy]
commonName=supplied
[ext]
subjectAltName=DNS:chat.grootlab.duckdns.org
CFG
now=$("$native_date" -u +%s)
for spec in expired:-172800:-86400 future:86400:2678400; do
    name=${spec%%:*}; rest=${spec#*:}; first=${rest%%:*}; last=${rest#*:}
    "$real_openssl" ca -batch -selfsign -config "$fixture/ca.cnf" -in "$fixture/request.pem" \
      -out "$fixture/$name.pem" -startdate "$("$native_date" -u -d "@$((now+first))" +%Y%m%d%H%M%SZ)" \
      -enddate "$("$native_date" -u -d "@$((now+last))" +%Y%m%d%H%M%SZ)" >/dev/null 2>&1
    # The next independent certificate may reuse this synthetic subject.
    : > "$fixture/index"
done
passed=0
run_case() {
    local label=$1 source=$2 expiry=$3 probe=$4 reason=$5 mode=${6:-ok} served=${7:-cert31.pem}
    current_case=$label
    rm -f "$CM_CERT"; cp "$fixture/$source" "$CM_CERT"; chmod 644 "$CM_CERT"
    : > "$FIXTURE_CALLS"
    export FIXTURE_TLS_MODE=$mode FIXTURE_TLS_CERT=$fixture/$served
    mkdir "$fixture/work"
    cm_probe "$fixture/work" > "$fixture/result.json"
    jq -e --arg expiry "$expiry" --arg probe "$probe" --arg reason "$reason" \
      '.schema_version==1 and .expiry_status==$expiry and .probe_status==$probe and .reason==$reason and .automatic_renewal==false and
       (.observed_at_kst|test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\+09:00$")) and
       (if .not_after_epoch==null then .not_after_kst==null else (.not_after_kst|endswith("+09:00")) end)' \
      "$fixture/result.json" >/dev/null || {
        printf 'FAIL %s metadata=' "$label" >&2
        jq -c '{expiry_status,probe_status,reason}' "$fixture/result.json" >&2
        return 1
    }
    [[ $("$native_date" -d "$(jq -r .observed_at_kst "$fixture/result.json")" +%s) == \
       "$("$native_date" -d "$(jq -r .observed_at_utc "$fixture/result.json")" +%s)" ]]
    if [[ $(jq -r .not_after_epoch "$fixture/result.json") != null ]]; then
        [[ $("$native_date" -d "$(jq -r .not_after_kst "$fixture/result.json")" +%s) == \
           "$(jq -r .not_after_epoch "$fixture/result.json")" ]]
    fi
    rm -rf "$fixture/work"
    passed=$((passed+1)); printf 'PASS %s\n' "$label"
}
for spec in '31:ok' '30:within_30_days' '15:within_30_days' '14:within_14_days' '8:within_14_days' '7:within_7_days'; do
    days=${spec%%:*}; status=${spec#*:}
    run_case "expiry_$days" "cert$days.pem" "$status" verified verified ok "cert$days.pem"
done
run_case expired_retained_on_tls_failure expired.pem expired unavailable tls_verification_failed fail
run_case future_certificate future.pem unknown unavailable not_yet_valid
run_case wrong_hostname wrong.pem unknown unavailable hostname_invalid
run_case cn_without_san no-san.pem unknown unavailable hostname_invalid
printf 'not a certificate\n' > "$fixture/invalid.pem"
run_case malformed invalid.pem unknown unavailable certificate_invalid
run_case tls_failure cert31.pem ok unavailable tls_verification_failed fail
run_case tls_timeout cert31.pem ok unavailable tls_timeout timeout
run_case malformed_tls_output cert31.pem ok unavailable served_certificate_invalid invalid
run_case mismatch cert31.pem ok mismatch served_certificate_mismatch ok cert30.pem
run_case changed_during_probe cert31.pem ok unavailable certificate_changed changed
for mode in missing symlink oversized badmode; do
    current_case=$mode
    rm -f "$CM_CERT"
    case "$mode" in
        missing) ;;
        symlink) ln -s "$fixture/cert31.pem" "$CM_CERT" ;;
        oversized) dd if=/dev/zero of="$CM_CERT" bs=65537 count=1 status=none; chmod 644 "$CM_CERT" ;;
        badmode) cp "$fixture/cert31.pem" "$CM_CERT"; chmod 666 "$CM_CERT" ;;
    esac
    mkdir "$fixture/work"; cm_probe "$fixture/work" > "$fixture/result.json"
    jq -e '.expiry_status=="unknown" and .probe_status=="unavailable" and .reason=="certificate_unavailable"' "$fixture/result.json" >/dev/null
    rm -rf "$fixture/work"; passed=$((passed+1)); printf 'PASS %s\n' "$mode"
done
run_case native_checkend_arguments cert31.pem ok verified verified
printf '0\n604800\n1209600\n2592000\nTLS_OPTIONS_EXACT\n' > "$fixture/expected-calls"
cmp "$FIXTURE_CALLS" "$fixture/expected-calls"
"$real_openssl" verify -CAfile "$fixture/cert31.pem" -verify_hostname chat.grootlab.duckdns.org "$fixture/cert31.pem" >/dev/null
if "$real_openssl" verify -CAfile "$fixture/cert31.pem" -verify_hostname elsewhere.invalid "$fixture/cert31.pem" >/dev/null 2>&1; then exit 1; fi
passed=$((passed+1)); printf 'PASS native_CA_hostname_boundary\n'
# Root/Linux-only publication: real flock/fsync/rename, private paths, fake logger.
# macOS cannot prove Linux /proc, root ownership or GNU mv -T semantics.
if [[ $(uname -s) == Linux && $EUID == 0 ]]; then
    CM_STATE=$fixture/state; mkdir -m 700 "$CM_STATE"
    cp "$fixture/cert31.pem" "$CM_CERT"; chmod 644 "$CM_CERT"
    export FIXTURE_TLS_MODE=ok FIXTURE_TLS_CERT=$fixture/cert31.pem
    logger() { [[ "$*" == --tag\ capstone-cert-monitor\ --priority\ daemon.notice\ --\ * ]]; printf '%s\n' "$*" >> "$fixture/journal-mock"; }
    (cm_entry run) > "$fixture/run-output"
    [[ $(stat -c %u:%g:%a:%h "$CM_STATE/status.json") == 0:0:600:1 ]]
    cmp "$fixture/run-output" "$CM_STATE/status.json"
    first=$(stat -c %i "$CM_STATE/status.json")
    (cm_entry run) > "$fixture/run-output"
    [[ $(stat -c %i "$CM_STATE/status.json") != "$first" && $(wc -l < "$fixture/journal-mock") == 2 ]]
    passed=$((passed+1)); printf 'PASS native_atomic_publication\n'
    first=$(stat -c %i "$CM_STATE/status.json")
    (cm_entry check) > "$fixture/check-output"
    [[ $(stat -c %i "$CM_STATE/status.json") == "$first" && $(wc -l < "$fixture/journal-mock") == 2 ]]
    passed=$((passed+1)); printf 'PASS check_no_status_or_journal_write\n'
    [[ $(find "$CM_STATE" -maxdepth 1 -type d -name '.probe.*' | wc -l) == 0 ]]
    passed=$((passed+1)); printf 'PASS private_probe_cleanup\n'
    rm "$CM_STATE/status.json"; ln -s "$fixture/cert31.pem" "$CM_STATE/status.json"
    set +e
    (set -e; cm_entry run) > "$fixture/refused-output" 2>/dev/null
    rc=$?
    set -e
    [[ $rc == 77 && $(wc -l < "$fixture/journal-mock") == 2 ]]
    passed=$((passed+1)); printf 'PASS unsafe_status_target_refused\n'
fi
printf '{"suite":"certificate_monitor_private","passed":%s,"network_connections":0,"operating_access":false,"tls_transport_simulated":true}\n' "$passed"
