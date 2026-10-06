#!/usr/bin/env bash
# Install an already-issued fullchain and key for the DuckDNS
# Mattermost name on Groot_A. ACME issuance/renewal happens elsewhere.
# Usage (on A): sudo bash deploy_chatduck_cert_A.sh /path/fullchain.pem /path/privkey.pem
set -euo pipefail
umask 077

DOMAIN=chat.grootlab.duckdns.org
CHATPROXY_DIR=/home/groot_a/capstone/chatproxy
TLS_DIR=$CHATPROXY_DIR/tls
CERT_DST=$TLS_DIR/chatduck.crt
KEY_DST=$TLS_DIR/chatduck.key
CONTAINER=chatproxy

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
  printf 'Usage: %s [--check-only] fullchain.pem privkey.pem\n' "$0" >&2
  exit 2
}

CHECK_ONLY=0
if [[ ${1:-} == --check-only ]]; then CHECK_ONLY=1; shift; fi
[[ $# -eq 2 ]] || usage
for cmd in openssl realpath sha256sum awk grep; do
  command -v "$cmd" >/dev/null || die "missing command: $cmd"
done
[[ -f $1 && -r $1 && -f $2 && -r $2 ]] || die 'certificate and key must be readable regular files'
FULLCHAIN=$(realpath -- "$1")
PRIVATE_KEY=$(realpath -- "$2")
[[ $FULLCHAIN != "$PRIVATE_KEY" ]] || die 'certificate and key must be different files'

# -checkhost accepts either the exact SAN or a valid wildcard SAN. Requiring a
# DNS SAN first prevents a legacy CN-only certificate from being accepted.
openssl x509 -in "$FULLCHAIN" -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:' \
  || die 'certificate has no DNS subjectAltName'
openssl x509 -in "$FULLCHAIN" -noout -checkhost "$DOMAIN" >/dev/null 2>&1 \
  || die "certificate SAN does not cover $DOMAIN"
openssl x509 -in "$FULLCHAIN" -noout -checkend 86400 >/dev/null 2>&1 \
  || die 'certificate expires within 24 hours'
PEM_COUNT=$(grep -c '^-----BEGIN CERTIFICATE-----$' "$FULLCHAIN" || true)
[[ $PEM_COUNT -ge 2 ]] || die 'provide fullchain.pem, including at least one intermediate certificate'

# A passphrase-free private key is required for unattended nginx reloads. Only
# public-key digests are compared; private-key material is never printed.
CERT_PUB_HASH=$(openssl x509 -in "$FULLCHAIN" -pubkey -noout 2>/dev/null \
  | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}') \
  || die 'cannot read certificate public key'
KEY_PUB_HASH=$(openssl pkey -in "$PRIVATE_KEY" -passin pass: -pubout -outform DER 2>/dev/null \
  | sha256sum | awk '{print $1}') || die 'cannot read unencrypted private key'
[[ $CERT_PUB_HASH == "$KEY_PUB_HASH" ]] || die 'certificate and private key do not match'

# The A host must trust the issuer before we install it. The post-reload curl
# check independently verifies the chain actually served to clients.
openssl verify -purpose sslserver -verify_hostname "$DOMAIN" \
  -untrusted "$FULLCHAIN" "$FULLCHAIN" >/dev/null 2>&1 \
  || die 'certificate chain is not trusted by this host'
printf 'Certificate, SAN, validity, key and issuer chain: OK\n'
if [[ $CHECK_ONLY -eq 1 ]]; then exit 0; fi

[[ $(id -u) -eq 0 ]] || die 'run as root on Groot_A'
for cmd in docker curl mktemp install mv timeout sleep; do
  command -v "$cmd" >/dev/null || die "missing command: $cmd"
done
[[ -d $TLS_DIR && ! -L $TLS_DIR ]] || die "missing or symlinked TLS directory: $TLS_DIR"
[[ -f $CERT_DST && ! -L $CERT_DST && -f $KEY_DST && ! -L $KEY_DST ]] \
  || die 'existing chatduck certificate and key must be regular files'
[[ $FULLCHAIN != "$CERT_DST" && $FULLCHAIN != "$KEY_DST" \
  && $PRIVATE_KEY != "$CERT_DST" && $PRIVATE_KEY != "$KEY_DST" ]] \
  || die 'source paths must differ from installed chatduck paths'
[[ $(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null) == true ]] \
  || die 'chatproxy container is not running'
MOUNT_SRC=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/nginx/tls"}}{{.Source}}{{end}}{{end}}' "$CONTAINER")
[[ -n $MOUNT_SRC && $(realpath -- "$MOUNT_SRC") == $(realpath -- "$TLS_DIR") ]] \
  || die 'chatproxy TLS mount differs from expected host directory'
NGINX_CONFIG=$(docker exec "$CONTAINER" nginx -T 2>/dev/null) \
  || die 'cannot inspect live nginx configuration'
grep -Fq "server_name $DOMAIN;" <<<"$NGINX_CONFIG" \
  || die 'DuckDNS chat server block missing from live nginx config'
grep -Fq '/etc/nginx/tls/chatduck.crt;' <<<"$NGINX_CONFIG" \
  || die 'DuckDNS chat certificate path missing from live nginx config'
grep -Fq '/etc/nginx/tls/chatduck.key;' <<<"$NGINX_CONFIG" \
  || die 'DuckDNS chat key path missing from live nginx config'
docker exec "$CONTAINER" nginx -t >/dev/null 2>&1 || die 'current nginx configuration is invalid'

BACKUP_DIR=''
NEW_CERT=''
NEW_KEY=''
CHANGED=0
SUCCESS=0
cleanup() {
  local result=$?
  trap - EXIT HUP INT TERM
  set +e
  [[ -z $NEW_CERT ]] || rm -f -- "$NEW_CERT"
  [[ -z $NEW_KEY ]] || rm -f -- "$NEW_KEY"
  if [[ $SUCCESS -eq 0 && $CHANGED -eq 1 ]]; then
    printf 'Deployment failed; restoring previous chatduck certificate and key...\n' >&2
    local restore_cert restore_key
    restore_cert=$(mktemp "$TLS_DIR/.chatduck.crt.rollback.XXXXXX")
    restore_key=$(mktemp "$TLS_DIR/.chatduck.key.rollback.XXXXXX")
    install -m 0644 "$BACKUP_DIR/chatduck.crt" "$restore_cert"
    install -m 0600 "$BACKUP_DIR/chatduck.key" "$restore_key"
    mv -f -- "$restore_cert" "$CERT_DST"
    mv -f -- "$restore_key" "$KEY_DST"
    if docker exec "$CONTAINER" nginx -t >/dev/null 2>&1 \
      && docker exec "$CONTAINER" nginx -s reload >/dev/null 2>&1; then
      printf 'Previous certificate restored and nginx reloaded.\n' >&2
    else
      printf 'WARNING: rollback reload failed; inspect chatproxy immediately.\n' >&2
    fi
  fi
  if [[ $CHANGED -eq 0 && -n $BACKUP_DIR ]]; then
    rm -f -- "$BACKUP_DIR/chatduck.crt" "$BACKUP_DIR/chatduck.key"
    rmdir -- "$BACKUP_DIR" 2>/dev/null || true
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

BACKUP_DIR=$(mktemp -d "$TLS_DIR/.chatduck-backup.$(date +%Y%m%d-%H%M%S).XXXXXX")
install -m 0600 "$CERT_DST" "$BACKUP_DIR/chatduck.crt"
install -m 0600 "$KEY_DST" "$BACKUP_DIR/chatduck.key"
NEW_CERT=$(mktemp "$TLS_DIR/.chatduck.crt.new.XXXXXX")
NEW_KEY=$(mktemp "$TLS_DIR/.chatduck.key.new.XXXXXX")
install -m 0644 "$FULLCHAIN" "$NEW_CERT"
install -m 0600 "$PRIVATE_KEY" "$NEW_KEY"

# Each rename is atomic on the TLS filesystem. nginx keeps serving its previous
# in-memory certificate until both files pass nginx -t and we reload it.
CHANGED=1
mv -f -- "$NEW_CERT" "$CERT_DST"
NEW_CERT=''
mv -f -- "$NEW_KEY" "$KEY_DST"
NEW_KEY=''
docker exec "$CONTAINER" nginx -t >/dev/null 2>&1 || die 'nginx -t failed with new certificate'
docker exec "$CONTAINER" nginx -s reload >/dev/null 2>&1 || die 'nginx reload failed'

EXPECTED_FP=$(openssl x509 -in "$FULLCHAIN" -noout -fingerprint -sha256 | awk -F= '{print $2}')
SERVED_FP=''
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  SERVED_CERT=$(timeout 5 openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" -showcerts </dev/null 2>/dev/null) || true
  if [[ -n $SERVED_CERT ]]; then
    SERVED_FP=$(openssl x509 -noout -fingerprint -sha256 <<<"$SERVED_CERT" 2>/dev/null | awk -F= '{print $2}') || true
  fi
  [[ -n $SERVED_FP && $SERVED_FP == "$EXPECTED_FP" ]] && break
  sleep 1
done
[[ -n $SERVED_FP && $SERVED_FP == "$EXPECTED_FP" ]] \
  || die 'live SNI certificate does not match the installed certificate after reload'
curl --noproxy '*' --silent --show-error --fail --max-time 10 \
  --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/v4/system/ping" \
  | grep -Eq '"status"[[:space:]]*:[[:space:]]*"OK"' \
  || die 'trusted HTTPS Mattermost ping failed'

SUCCESS=1
printf 'Installed trusted certificate for %s; SNI and Mattermost ping verified.\n' "$DOMAIN"
printf 'Restricted backup retained at %s\n' "$BACKUP_DIR"
