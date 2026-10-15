#!/bin/bash
# Fixed A/chat certificate observation. No private key, Docker, HTTP, or renewal.
CM_DOMAIN=chat.grootlab.duckdns.org
CM_CERT=/home/groot_a/capstone/chatproxy/tls/chatduck.crt
CM_STATE=/var/lib/capstone-cert-monitor
CM_SELF=/usr/local/sbin/capstone-cert-monitor
CM_OPENSSL=/usr/bin/openssl
CM_TIMEOUT=/usr/bin/timeout
CM_DATE=/usr/bin/date

cm_meta() {
    [[ -f $1 && ! -L $1 && $(stat -c '%u:%g:%a:%h' -- "$1") == 0:0:644:1 &&
       $(stat -c %s -- "$1") -gt 0 && $(stat -c %s -- "$1") -le 65536 ]] || return 1
    stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' -- "$1"
}
cm_path() {
    local p=${CM_CERT%/*}
    while [[ $p != / ]]; do
        [[ -d $p && ! -L $p ]] || return 1
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
cm_fingerprint() {
    local value
    value=$("$CM_OPENSSL" x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null) || return 1
    value=${value#*=}; value=${value//:/}; value=$(printf '%s' "$value" | tr 'A-F' 'a-f')
    [[ $value =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$value"
}
cm_emit() {
    local at utc kst expiry_kst=''
    at=$("$CM_DATE" -u +%s) || return 1
    utc=$("$CM_DATE" -u -d "@$at" +%Y-%m-%dT%H:%M:%SZ) || return 1
    kst=$(TZ=Asia/Seoul "$CM_DATE" -d "@$at" +%Y-%m-%dT%H:%M:%S%:z) || return 1
    if [[ $CM_END != null ]]; then
        expiry_kst=$(TZ=Asia/Seoul "$CM_DATE" -d "@$CM_END" +%Y-%m-%dT%H:%M:%S%:z) || return 1
    fi
    jq -ncS --arg domain "$CM_DOMAIN" --arg expiry "$CM_EXPIRY" --arg probe "$CM_PROBE" \
      --arg reason "$CM_REASON" --arg fingerprint "$CM_FP" --arg served "$CM_SERVED" \
      --arg at "$utc" --arg kst "$kst" --arg expiry_kst "$expiry_kst" --argjson end "$CM_END" --argjson seconds "$CM_SECONDS" \
      '{schema_version:1,domain:$domain,observed_at_utc:$at,observed_at_kst:$kst,expiry_status:$expiry,probe_status:$probe,reason:$reason,
        not_after_epoch:$end,not_after_kst:($expiry_kst|if .=="" then null else . end),seconds_remaining:$seconds,certificate_sha256:($fingerprint|if .=="" then null else . end),
        served_certificate_sha256:($served|if .=="" then null else . end),automatic_renewal:false}'
}
cm_probe() {
    # Private scratch is supplied only by the fixed wrapper or isolated fixture.
    local scratch=$1 before after start end now expected status rc hostcheck
    CM_EXPIRY=unknown CM_PROBE=unavailable CM_REASON=certificate_unavailable
    CM_FP='' CM_SERVED='' CM_END=null CM_SECONDS=null
    if ! cm_path || ! before=$(cm_meta "$CM_CERT"); then cm_emit; return; fi
    # GNU dd never follows a final symlink or blocks on a substituted FIFO.
    if ! dd if="$CM_CERT" of="$scratch/certificate.pem" iflag=nofollow,nonblock,count_bytes count=65537 status=none 2>/dev/null ||
       ! after=$(cm_meta "$CM_CERT") || [[ $before != "$after" ]] ||
       [[ $(stat -c %s "$scratch/certificate.pem") -gt 65536 ]]; then
        CM_REASON=certificate_changed; cm_emit; return
    fi
    if ! CM_FP=$(cm_fingerprint "$scratch/certificate.pem") ||
       ! start=$("$CM_OPENSSL" x509 -in "$scratch/certificate.pem" -noout -startdate 2>/dev/null) ||
       ! end=$("$CM_OPENSSL" x509 -in "$scratch/certificate.pem" -noout -enddate 2>/dev/null) ||
       ! start=$("$CM_DATE" -u -d "${start#notBefore=}" +%s 2>/dev/null) ||
       ! end=$("$CM_DATE" -u -d "${end#notAfter=}" +%s 2>/dev/null) ||
       ! now=$("$CM_DATE" -u +%s) || [[ ! $start =~ ^[0-9]+$ || ! $end =~ ^[0-9]+$ || ! $now =~ ^[0-9]+$ ]]; then
        CM_REASON=certificate_invalid; CM_FP=''; cm_emit; return
    fi
    CM_END=$end CM_SECONDS=$((end-now))
    # OpenSSL3.0 may return 0 for a hostname mismatch: require its exact success
    # text too. A DNS SAN is mandatory; legacy CN-only matches are rejected.
    if ! "$CM_OPENSSL" x509 -in "$scratch/certificate.pem" -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:' ||
       ! hostcheck=$("$CM_OPENSSL" x509 -in "$scratch/certificate.pem" -noout -checkhost "$CM_DOMAIN" 2>/dev/null) ||
       [[ $hostcheck != "Hostname $CM_DOMAIN does match certificate" ]]; then
        CM_REASON=hostname_invalid; cm_emit; return
    fi
    if (( start>now )); then CM_REASON=not_yet_valid; cm_emit; return; fi
    CM_EXPIRY=ok
    for expected in '0:expired' '604800:within_7_days' '1209600:within_14_days' '2592000:within_30_days'; do
        status=${expected#*:}; expected=${expected%%:*}; rc=0
        "$CM_OPENSSL" x509 -in "$scratch/certificate.pem" -noout -checkend "$expected" >/dev/null 2>&1 || rc=$?
        if (( rc==1 )); then CM_EXPIRY=$status; break; fi
        if (( rc!=0 )); then CM_EXPIRY=unknown; CM_REASON=checkend_failed; cm_emit; return; fi
    done
    # A verified local TLS handshake; no HTTP/application request or chat message.
    rc=0
    "$CM_TIMEOUT" --signal=TERM --kill-after=1s 10s "$CM_OPENSSL" s_client \
      -connect 127.0.0.1:443 -servername "$CM_DOMAIN" -verify_return_error -verify_hostname "$CM_DOMAIN" \
      -purpose sslserver -CAfile /etc/ssl/certs/ca-certificates.crt -showcerts -no_ign_eof \
      </dev/null > "$scratch/served.pem" 2> "$scratch/tls.stderr" || rc=$?
    if (( rc!=0 )); then
        CM_REASON=tls_verification_failed
        [[ $rc != 124 && $rc != 137 ]] || CM_REASON=tls_timeout
    elif ! CM_SERVED=$(cm_fingerprint "$scratch/served.pem"); then CM_REASON=served_certificate_invalid
    elif [[ $CM_SERVED != "$CM_FP" ]]; then CM_PROBE=mismatch; CM_REASON=served_certificate_mismatch
    else CM_PROBE=verified; CM_REASON=verified; fi
    if ! after=$(cm_meta "$CM_CERT") || [[ $before != "$after" ]]; then
        CM_PROBE=unavailable; CM_REASON=certificate_changed
    fi
    cm_emit
}
cm_entry() {
    set -euo pipefail
    umask 077
    # A 128KiB per-file limit also bounds native TLS diagnostics/certificate data.
    ulimit -f 128
    local operation=$1 scratch output p lockmeta
    [[ -d $CM_STATE && ! -L $CM_STATE && $(stat -c '%u:%g:%a' "$CM_STATE") == 0:0:700 ]] || return 77
    for p in /var /var/lib; do
        [[ -d $p && ! -L $p && $(stat -c %u:%g "$p") == 0:0 ]] || return 77
        (( (8#$(stat -c %a "$p") & 0022)==0 )) || return 77
    done
    if [[ -e $CM_STATE/.lock || -L $CM_STATE/.lock ]]; then
        [[ -f $CM_STATE/.lock && ! -L $CM_STATE/.lock && $(stat -c %u:%g:%a:%h "$CM_STATE/.lock") == 0:0:600:1 ]] || return 77
    fi
    exec 9<>"$CM_STATE/.lock"; flock -n 9 || return 75
    lockmeta=$(stat -c %d:%i "$CM_STATE/.lock")
    [[ $(stat -Lc %d:%i /proc/self/fd/9) == "$lockmeta" ]] || return 77
    if [[ -e $CM_STATE/status.json || -L $CM_STATE/status.json ]]; then
        [[ -f $CM_STATE/status.json && ! -L $CM_STATE/status.json && $(stat -c %u:%g:%a:%h "$CM_STATE/status.json") == 0:0:600:1 ]] || return 77
    fi
    scratch=$(mktemp -d "$CM_STATE/.probe.XXXXXXXX")
    CM_SCRATCH=$scratch
    trap '[[ -z ${CM_SCRATCH:-} ]] || rm -rf -- "$CM_SCRATCH"' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
    cm_probe "$scratch" > "$scratch/result.json"
    jq -se 'length==1 and .[0].schema_version==1 and .[0].domain=="chat.grootlab.duckdns.org"' "$scratch/result.json" >/dev/null
    if [[ $operation == run ]]; then
        chmod 600 "$scratch/result.json"; sync -- "$scratch/result.json"
        mv -T -- "$scratch/result.json" "$CM_STATE/status.json"; sync -- "$CM_STATE/status.json" "$CM_STATE"
        output=$(cat "$CM_STATE/status.json")
        logger --tag capstone-cert-monitor --priority daemon.notice -- "$output"
    else output=$(cat "$scratch/result.json"); fi
    printf '%s\n' "$output"
    # Observation failure is explicit in both JSON and the oneshot result.
    jq -e '.probe_status=="verified"' <<< "$output" >/dev/null || return 2
}
cm_main() {
    [[ $# == 1 && ($1 == run || $1 == check) && $EUID == 0 &&
       $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || return 77
    [[ ${BASH_SOURCE[0]} == "$CM_SELF" && -f $CM_SELF && ! -L $CM_SELF &&
       $(stat -c %u:%g:%a:%h "$CM_SELF") == 0:0:500:1 ]] || return 77
    local p
    for p in /usr /usr/local /usr/local/sbin; do
        [[ -d $p && ! -L $p && $(stat -c %u:%g "$p") == 0:0 ]] || return 77
        (( (8#$(stat -c %a "$p") & 0022)==0 )) || return 77
    done
    exec /usr/bin/timeout --signal=TERM --kill-after=1s 29s /usr/bin/env -i \
      PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC OPENSSL_CONF=/etc/ssl/openssl.cnf \
      /bin/bash --noprofile --norc -c 'source /usr/local/sbin/capstone-cert-monitor; cm_entry "$1"' monitor "$1"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -euo pipefail
    cm_main "$@"
fi
