#!/usr/bin/env bash
set -euo pipefail
umask 077
stage=${1:?stage}; role=${2:?role}; action=${3:?action}
[[ $# == 3 && $stage =~ ^/var/tmp/capstone-bootstrap-[0-9a-f]{24}$ ]] || exit 64
[[ $role == security || $role == siem || $role == service ]] || exit 64
case "$role:$action" in
  *:check|*:apply|*:verify|security:soc-check|siem:soc-check|siem:soc-prepare|siem:soc-export|security:soc-receive|security:soc-apply|siem:soc-activate|security:soc-verify|siem:soc-verify|security:log-activate|siem:log-monitor|security:log-verify|siem:log-verify|siem:dashboard-check|siem:dashboard-apply|siem:dashboard-verify|*:diag-check|*:diag-verify|siem:diag-prepare|siem:diag-export|security:diag-apply|service:diag-apply|siem:diag-activate|siem:tls-install|siem:tls-export|siem:tls-verify|security:tls-trust|siem:host-check|service:host-check|siem:host-apply|service:host-apply|siem:host-verify|service:host-verify) ;;
  *) exit 64 ;;
esac
[[ $(id -u) == 0 && -d $stage && ! -L $stage ]] || exit 77
for path in "$stage" "$stage/site.env" "$stage/source.tar" "$stage/source"; do
  [[ ! -L $path && $(stat -c %u "$path") == 0 ]] || { echo 'unsafe staging ownership' >&2; exit 77; }
done
source "$stage/site.env"
export TZ=Asia/Seoul
[[ $CAPSTONE_ROOT == /opt/capstone && $CAPSTONE_RELEASE =~ ^[0-9a-f]{64}$ ]] || exit 64
actual=$(sha256sum "$stage/source.tar"); actual=${actual%% *}
[[ $actual == "$CAPSTONE_RELEASE" ]] || { echo 'payload checksum mismatch' >&2; exit 65; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Ubuntu 24.04 amd64 required' >&2; exit 69; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 required' >&2; exit 69; }
for tool in bash python3 docker systemctl flock curl openssl jq tar sha256sum; do
  command -v "$tool" >/dev/null || { printf 'missing package command: %s (README)\n' "$tool" >&2; exit 69; }
done
systemctl is-system-running >/dev/null 2>&1 || [[ $(systemctl is-system-running) == degraded ]] || { echo 'running systemd required' >&2; exit 69; }
docker info >/dev/null 2>&1 || { echo 'Docker daemon unavailable' >&2; exit 69; }
docker compose version >/dev/null || exit 69
export CAPSTONE_SOURCE=$stage/source
case "$action" in
  soc-*|log-*|dashboard-*|diag-*|host-*|tls-*)
    # Extensions have their own bounded, idempotent receipts. They may not
    # convert an unrelated deployment or run concurrently with another apply.
    case "$action" in
      *-check|*-verify|soc-export|diag-export|tls-export) ;;
      *) exec 9>/run/lock/capstone-bootstrap.lock
         flock -n 9 || { echo 'another deployment holds the host lock' >&2; exit 75; } ;;
    esac
    if [[ $action != *-check ]]; then
      [[ -f $CAPSTONE_ROOT/role && ! -L $CAPSTONE_ROOT/role && $(cat "$CAPSTONE_ROOT/role") == "$role" ]] || exit 78
    fi
    case "$action" in
      soc-check) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_management.py" check --role "$role" ;;
      soc-prepare) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_management.py" prepare-siem ;;
      soc-export) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_management.py" export-siem ;;
      soc-receive) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_management.py" receive-security ;;
      soc-apply) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_management.py" apply-security ;;
      soc-activate) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_management.py" activate-siem ;;
      soc-verify) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_management.py" verify --role "$role" ;;
      log-*) exec python3 -B "$CAPSTONE_SOURCE/deployment/log_pipeline.py" "${action#log-}" "$role" ;;
      dashboard-check) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_dashboard.py" check --source-root "$CAPSTONE_SOURCE" ;;
      dashboard-*) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_dashboard.py" "${action#dashboard-}" --source-root "$CAPSTONE_SOURCE" --url "https://$SIEM_HOST" --ca-file "$CAPSTONE_ROOT/siem/tls/root-ca.pem" --credentials-file /opt/capstone-prereqs/siem.json --receipt "$CAPSTONE_ROOT/siem/soc-dashboard.json" ;;
      diag-check|diag-verify) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_diagnostics.py" "${action#diag-}" --role "$role" ;;
      diag-prepare) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_diagnostics.py" prepare-siem --role siem ;;
      diag-export) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_diagnostics.py" export-key --role siem ;;
      diag-apply) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_diagnostics.py" apply-reader --role "$role" ;;
      diag-activate) exec python3 -B "$CAPSTONE_SOURCE/deployment/soc_diagnostics.py" activate-siem --role siem ;;
      tls-*) exec python3 -B "$CAPSTONE_SOURCE/deployment/internal_tls.py" "${action#tls-}" ;;
      host-check) exec python3 -B "$CAPSTONE_SOURCE/deployment/host_security.py" check --role "$role" ;;
      host-apply) exec python3 -B "$CAPSTONE_SOURCE/deployment/host_security.py" install --role "$role" ;;
      host-verify) exec python3 -B /opt/capstone-host-security/host_security.py verify ;;
    esac
    exit 64 ;;
esac
if [[ $action == apply ]]; then
  exec 9>/run/lock/capstone-bootstrap.lock
  flock -n 9 || { echo 'another deployment holds the host lock' >&2; exit 75; }
  [[ ! -L $CAPSTONE_ROOT ]] || exit 77
  if [[ -e $CAPSTONE_ROOT/role && $(cat "$CAPSTONE_ROOT/role") != "$role" ]]; then
    echo 'host already assigned to a different role' >&2; exit 78
  fi
  # Check before creating persistent deployment state.
  bash "$CAPSTONE_SOURCE/deployment/roles/$role.sh" check
  install -d -m 0700 "$CAPSTONE_ROOT/releases"
  release=$CAPSTONE_ROOT/releases/$CAPSTONE_RELEASE
  if [[ ! -d $release ]]; then
    mkdir -m 0700 "$release"
    tar --no-same-owner -xf "$stage/source.tar" -C "$release"
    chmod -R go-w "$release"
  fi
  export CAPSTONE_SOURCE=$release
  printf '%s\n' "$role" > "$CAPSTONE_ROOT/role"
fi
printf '[%s] %s\n' "$role" "$action"
bash "$CAPSTONE_SOURCE/deployment/roles/$role.sh" "$action"
